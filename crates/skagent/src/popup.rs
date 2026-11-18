//! skagent's own popup (`--popup`, e.g. `skagent-pinentry`): one window that
//! takes the user through a request (selection, PIN, touch, result), speaking
//! the protocol in `skagent-popup`.
//!
//! - **One request at a time.** A request takes a [`PopupSession`] first and
//!   holds it to the end. Others wait for it, and the popup shows which
//!   (`queue` messages).
//! - **Started on demand, reused.** The first session starts the popup. A
//!   session that ends while others wait leaves it running for the next
//!   request; the last one closes its stdin, and the popup exits.
//! - **Fail closed.** A popup that doesn't start, exits or sends garbage
//!   cancels the request it serves.
//!
//! Lines from the popup are read one byte at a time into locked memory, like
//! pinentry's: they can hold the PIN.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use skagent_popup::style::Style;
use skagent_popup::{
    Intent, MAX_INTENT_LINE, Message, Queued, State, VERSION, encode_message, parse_intent,
};
use skagent_secret::SecretBuffer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{OwnedMutexGuard, mpsc, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::prompt::{PROMPT_TIMEOUT, checked_pin, prompt_command};

/// Longest wait for a starting popup to say it's ready. Generous: a GPU
/// popup initializes its renderer first.
pub const START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a closed popup may take to exit before it is killed. Covers
/// showing a final state for a moment.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Intents buffered between the reader and the session.
const INTENT_QUEUE: usize = 16;

/// The request was cancelled in the popup (✕ or Esc).
#[derive(Debug, Clone, Copy)]
pub struct CancelledInPopup;

impl fmt::Display for CancelledInPopup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cancelled in the popup")
    }
}

impl std::error::Error for CancelledInPopup {}

/// Whether `error` comes from the user cancelling in the popup.
#[must_use]
pub fn cancelled_in_popup(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(<dyn std::error::Error>::is::<CancelledInPopup>)
}

/// The popup program and the one session that uses it at a time.
#[derive(Debug)]
pub struct Popup {
    program: PathBuf,
    /// How it looks, sent first to every started popup.
    style: Style,
    /// The running popup, owned by the current session.
    current: Arc<tokio::sync::Mutex<Option<Running>>>,
    /// Requests waiting for a session, oldest first, with their numbers.
    waiting: watch::Sender<Vec<(u64, Queued)>>,
    /// The next state's sequence number.
    seq: AtomicU64,
    /// The next waiting request's number.
    arrivals: AtomicU64,
}

impl Popup {
    /// Shows prompts with `program`, looking like `style`.
    #[must_use]
    pub fn new(program: PathBuf, style: Style) -> Self {
        Self {
            program,
            style,
            current: Arc::default(),
            waiting: watch::channel(Vec::new()).0,
            seq: AtomicU64::new(1),
            arrivals: AtomicU64::new(0),
        }
    }

    /// The popup program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Waits until the popup is free for a new request, for at most
    /// `timeout`. Meanwhile the popup shows `queued` among the waiting
    /// requests.
    ///
    /// # Errors
    ///
    /// Returns an error if other requests keep it busy for longer.
    pub async fn session(
        self: &Arc<Self>,
        timeout: Duration,
        queued: Queued,
    ) -> Result<PopupSession> {
        let guard = {
            let number = self.arrivals.fetch_add(1, Ordering::SeqCst);
            let _waiting = Waiting::start(&self.waiting, number, queued);
            tokio::time::timeout(timeout, Arc::clone(&self.current).lock_owned())
                .await
                .map_err(|_elapsed| {
                    anyhow!(
                        "the popup is busy with other requests; gave up waiting after {} s",
                        timeout.as_secs()
                    )
                })?
        };
        Ok(PopupSession {
            first_seq: self.seq.load(Ordering::SeqCst),
            popup: Arc::clone(self),
            guard,
        })
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// The requests waiting right now, oldest first.
    fn waiting(&self) -> Vec<Queued> {
        queued(&self.waiting.borrow())
    }
}

fn queued(waiting: &[(u64, Queued)]) -> Vec<Queued> {
    waiting.iter().map(|(_, queued)| queued.clone()).collect()
}

/// Lists a request as waiting until dropped.
struct Waiting<'a> {
    waiting: &'a watch::Sender<Vec<(u64, Queued)>>,
    number: u64,
}

impl<'a> Waiting<'a> {
    fn start(waiting: &'a watch::Sender<Vec<(u64, Queued)>>, number: u64, queued: Queued) -> Self {
        waiting.send_modify(|list| list.push((number, queued)));
        Self { waiting, number }
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let number = self.number;
        self.waiting
            .send_modify(|list| list.retain(|(waiting, _)| *waiting != number));
    }
}

/// One request's use of the popup. Dropping it hands the popup to the next
/// waiting request, or closes it.
#[derive(Debug)]
pub struct PopupSession {
    popup: Arc<Popup>,
    guard: OwnedMutexGuard<Option<Running>>,
    /// States of this request have this sequence number or a higher one;
    /// answers to earlier ones are stale.
    first_seq: u64,
}

impl PopupSession {
    /// Starts the popup unless it is running already.
    ///
    /// # Errors
    ///
    /// Returns an error if the popup can't be started or doesn't say it's
    /// ready in time.
    pub async fn start(&mut self) -> Result<()> {
        if self.guard.is_none() {
            let running = Running::start(&self.popup)
                .await
                .with_context(|| format!("starting the popup {}", self.popup.program.display()))?;
            *self.guard = Some(running);
        }
        Ok(())
    }

    /// Shows `state` and returns its sequence number. Doesn't wait for the
    /// popup.
    ///
    /// # Errors
    ///
    /// Returns an error if the popup isn't running or exited.
    pub fn show(&mut self, state: State) -> Result<u64> {
        self.shower()?.show(state)
    }

    /// A handle that shows states without borrowing the session, e.g. from a
    /// callback.
    ///
    /// # Errors
    ///
    /// Returns an error if the popup isn't running.
    pub fn shower(&self) -> Result<Shower> {
        let running = self.guard.as_ref().context("the popup isn't running")?;
        Ok(Shower {
            popup: Arc::clone(&self.popup),
            lines: running.lines.downgrade(),
        })
    }

    /// Shows `state`, which asks for a PIN, and waits for the answer, for
    /// at most [`PROMPT_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns [`CancelledInPopup`] if the user cancelled, or an error if the
    /// popup exited, the answer isn't a valid FIDO PIN or nobody answered.
    pub async fn ask_pin(&mut self, state: State) -> Result<SecretBuffer> {
        let seq = self.show(state)?;
        let first_seq = self.first_seq;
        let intents = &mut self
            .guard
            .as_mut()
            .context("the popup isn't running")?
            .intents;
        let answer = async {
            loop {
                match intents.recv().await {
                    Some(Intent::Pin { seq: answered, pin }) if answered == seq => {
                        return checked_pin(pin.expose());
                    }
                    Some(Intent::Cancel { seq: cancelled }) if cancelled >= first_seq => {
                        return Err(anyhow::Error::new(CancelledInPopup));
                    }
                    // Answers to replaced states; a stale PIN is dropped (zeroized).
                    Some(_) => {}
                    None => bail!("the popup exited"),
                }
            }
        };
        tokio::time::timeout(PROMPT_TIMEOUT, answer)
            .await
            .map_err(|_elapsed| {
                anyhow!("no PIN was entered within {} s", PROMPT_TIMEOUT.as_secs())
            })?
    }

    /// Shows `state`, which offers to try again, and waits for the answer,
    /// for at most [`PROMPT_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns [`CancelledInPopup`] if the user cancelled, or an error if the
    /// popup exited or nobody answered.
    pub async fn ask_retry(&mut self, state: State) -> Result<()> {
        let seq = self.show(state)?;
        let first_seq = self.first_seq;
        let intents = &mut self
            .guard
            .as_mut()
            .context("the popup isn't running")?
            .intents;
        let answer = async {
            loop {
                match intents.recv().await {
                    Some(Intent::Retry { seq: retried }) if retried == seq => return Ok(()),
                    Some(Intent::Cancel { seq: cancelled }) if cancelled >= first_seq => {
                        return Err(anyhow::Error::new(CancelledInPopup));
                    }
                    Some(_) => {}
                    None => bail!("the popup exited"),
                }
            }
        };
        tokio::time::timeout(PROMPT_TIMEOUT, answer)
            .await
            .map_err(|_elapsed| {
                anyhow!(
                    "nobody chose to try again within {} s",
                    PROMPT_TIMEOUT.as_secs()
                )
            })?
    }

    /// Completes when the user cancels this request in the popup, or the
    /// popup exits. Cancel-safe.
    pub async fn cancelled(&mut self) {
        let first_seq = self.first_seq;
        let Some(running) = self.guard.as_mut() else {
            return std::future::pending().await;
        };
        loop {
            match running.intents.recv().await {
                Some(Intent::Cancel { seq }) if seq >= first_seq => return,
                Some(_) => {}
                None => return,
            }
        }
    }
}

impl Drop for PopupSession {
    fn drop(&mut self) {
        // A request that starts waiting after this check starts a new popup.
        if self.popup.waiting.borrow().is_empty()
            && let Some(running) = self.guard.take()
        {
            running.close();
        }
    }
}

/// Shows states on a session's popup without borrowing the session.
#[derive(Debug, Clone)]
pub struct Shower {
    popup: Arc<Popup>,
    lines: mpsc::WeakUnboundedSender<Vec<u8>>,
}

impl Shower {
    /// Shows `state` and returns its sequence number.
    ///
    /// # Errors
    ///
    /// Returns an error if the popup exited.
    pub fn show(&self, state: State) -> Result<u64> {
        let seq = self.popup.next_seq();
        let line = encode_message(&Message::Show {
            seq,
            waiting: self.popup.waiting(),
            state: Box::new(state),
        })?;
        self.lines
            .upgrade()
            .context("the popup exited")?
            .send(line)
            .map_err(|_closed| anyhow!("the popup exited"))?;
        Ok(seq)
    }
}

/// A running popup process.
#[derive(Debug)]
struct Running {
    child: Child,
    /// Lines for the popup's stdin. Dropping the last sender closes it.
    lines: mpsc::UnboundedSender<Vec<u8>>,
    /// What the popup sent. Closed when its stdout is.
    intents: mpsc::Receiver<Intent>,
    /// Forwards changes of the waiting count.
    queue: JoinHandle<()>,
}

impl Running {
    async fn start(popup: &Popup) -> Result<Self> {
        let mut child = prompt_command(&popup.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning the popup")?;
        let stdin = child.stdin.take().context("the popup has no stdin")?;
        let stdout = child.stdout.take().context("the popup has no stdout")?;

        let (lines, pending) = mpsc::unbounded_channel();
        drop(tokio::spawn(write_lines(stdin, pending)));
        let (intents_sender, mut intents) = mpsc::channel(INTENT_QUEUE);
        drop(tokio::spawn(read_intents(stdout, intents_sender)));

        let ready = tokio::time::timeout(START_TIMEOUT, intents.recv())
            .await
            .map_err(|_elapsed| {
                anyhow!(
                    "the popup didn't say it's ready within {} s",
                    START_TIMEOUT.as_secs()
                )
            })?;
        match ready {
            Some(Intent::Ready { version }) => ensure!(
                version == VERSION,
                "the popup speaks protocol version {version}, skagent {VERSION}"
            ),
            Some(_) => bail!("the popup didn't start with READY"),
            None => bail!("the popup exited before it was ready"),
        }

        let style = encode_message(&Message::Style {
            style: Box::new(popup.style.clone()),
        })?;
        lines
            .send(style)
            .map_err(|_closed| anyhow!("the popup exited before it got its style"))?;

        let queue = tokio::spawn(forward_queue(popup.waiting.subscribe(), lines.downgrade()));
        tracing::debug!(popup = %popup.program.display(), "started the popup");
        Ok(Self {
            child,
            lines,
            intents,
            queue,
        })
    }

    /// Closes the popup's stdin and lets it exit, killing it if it takes too
    /// long.
    fn close(self) {
        let Self {
            mut child,
            lines,
            intents,
            queue,
        } = self;
        queue.abort();
        drop(lines);
        drop(intents);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn(async move {
                if tokio::time::timeout(CLOSE_TIMEOUT, child.wait())
                    .await
                    .is_err()
                {
                    tracing::warn!("the popup didn't exit after its last request, killing it");
                }
                // kill_on_drop: gone by now either way.
                drop(child);
            })),
            // Shutting down: kill_on_drop ends it.
            Err(_no_runtime) => drop(child),
        }
    }
}

/// Writes queued lines to the popup's stdin until the last sender is
/// dropped, then closes it.
async fn write_lines(mut stdin: ChildStdin, mut pending: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(line) = pending.recv().await {
        if let Err(error) = stdin.write_all(&line).await {
            tracing::debug!(%error, "writing to the popup failed");
            return;
        }
    }
}

/// Reads the popup's lines into locked memory and passes them on as
/// intents. Ends at EOF, on an error or on a malformed line, which closes
/// the intent channel.
async fn read_intents(mut stdout: ChildStdout, intents: mpsc::Sender<Intent>) {
    let mut line = match SecretBuffer::with_capacity(MAX_INTENT_LINE) {
        Ok(line) => line,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "can't read from the popup");
            return;
        }
    };
    loop {
        line.clear();
        match read_line(&mut stdout, &mut line).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "reading from the popup failed");
                return;
            }
        }
        let intent = match parse_intent(line.expose()) {
            Ok(intent) => intent,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "the popup sent a malformed line");
                return;
            }
        };
        if intents.send(intent).await.is_err() {
            return;
        }
    }
}

/// Reads one line, without its newline, into `line`. `Ok(false)` at EOF.
async fn read_line(stdout: &mut ChildStdout, line: &mut SecretBuffer) -> Result<bool> {
    loop {
        let mut byte = Zeroizing::new([0_u8; 1]);
        let count = stdout
            .read(&mut *byte)
            .await
            .context("reading from the popup")?;
        if count == 0 {
            return Ok(false);
        }
        if *byte == *b"\n" {
            return Ok(true);
        }
        line.extend_from_slice(&*byte)
            .map_err(|_| anyhow!("the popup sent a line longer than {MAX_INTENT_LINE} bytes"))?;
    }
}

/// Tells the popup whenever the waiting requests change.
async fn forward_queue(
    mut waiting: watch::Receiver<Vec<(u64, Queued)>>,
    lines: mpsc::WeakUnboundedSender<Vec<u8>>,
) {
    while waiting.changed().await.is_ok() {
        let list = queued(&waiting.borrow_and_update());
        let Ok(line) = encode_message(&Message::Queue { waiting: list }) else {
            return;
        };
        let Some(lines) = lines.upgrade() else {
            return;
        };
        if lines.send(line).is_err() {
            return;
        }
    }
}
