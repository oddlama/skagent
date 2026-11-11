//! Asking the user for the PIN: through pinentry (default) or an askpass
//! program, like OpenSSH's ssh-agent uses. Either way the answer goes
//! straight into locked memory and is checked to be a valid FIDO PIN.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
pub use skagent_fido::{PIN_MAX_BYTES, PIN_MIN_BYTES};
use skagent_secret::SecretBuffer;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use zeroize::Zeroize as _;

use crate::pinentry::{Dialog, Pinentry};

/// At or below this many retries left, prompts warn about them.
pub const LOW_RETRIES: u32 = 3;

/// Longest a PIN prompt may stay open. The request holds its security key
/// (and shared access to all keys) while the prompt is open, so an abandoned
/// dialog would otherwise block touch selection, and through the
/// writer-preferring lock every other signature, indefinitely.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// What the user is asked about.
#[derive(Debug, Clone, Copy)]
pub struct PinRequest<'a> {
    /// The key as the user knows it, e.g. `alice@example.com yubikey:1 (SHA256:...)`.
    pub key: &'a str,
    /// PIN attempts the device has left, if known.
    pub retries: Option<u32>,
    /// What went wrong last time, e.g. a wrong PIN.
    pub error: Option<&'a str>,
    /// Whether a touch follows the PIN: yes for signatures, no for loading
    /// resident keys (credential management needs no touch).
    pub then_touch: bool,
    /// What the signature is for, e.g. `log in as "git" to …`.
    pub purpose: Option<&'a str>,
}

impl PinRequest<'_> {
    fn retries_warning(&self) -> Option<String> {
        self.retries
            .filter(|&retries| retries <= LOW_RETRIES)
            .map(|retries| format!("{retries} PIN attempts left before the key locks"))
    }

    /// One-line prompt for askpass programs.
    #[must_use]
    pub fn askpass_text(&self) -> String {
        let mut text = String::new();
        if let Some(error) = self.error {
            text.push_str(error);
            text.push_str(". ");
        }
        text.push_str("Enter PIN for ");
        text.push_str(self.key);
        if let Some(purpose) = self.purpose {
            text.push_str(" to ");
            text.push_str(purpose);
        }
        if self.then_touch {
            text.push_str(", then touch the key");
        }
        if let Some(warning) = self.retries_warning() {
            text.push_str(" (");
            text.push_str(&warning);
            text.push(')');
        }
        text
    }

    /// Description for the pinentry dialog.
    #[must_use]
    pub fn pinentry_description(&self) -> String {
        let mut text = format!("Enter the PIN of the security key holding\n{}", self.key);
        if let Some(purpose) = self.purpose {
            text.push_str("\n\nRequest: ");
            text.push_str(purpose);
            text.push('.');
        }
        if self.then_touch {
            text.push_str("\n\nThen touch the key when it blinks.");
        }
        if let Some(warning) = self.retries_warning() {
            text.push_str("\n\n");
            text.push_str(&warning);
            text.push('.');
        }
        text
    }
}

/// How PINs are asked for.
#[derive(Debug, Clone)]
pub enum PinPrompt {
    /// A pinentry program (Assuan).
    Pinentry(Pinentry),
    /// An askpass program.
    Askpass(Askpass),
}

impl PinPrompt {
    /// Asks the user for the PIN described by `request`, for at most
    /// [`PROMPT_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt fails, is cancelled or times out, or
    /// the answer isn't a valid FIDO PIN.
    pub async fn ask(&self, request: &PinRequest<'_>) -> Result<SecretBuffer> {
        self.ask_within(request, PROMPT_TIMEOUT).await
    }

    /// [`PinPrompt::ask`] with an explicit time limit. On timeout the prompt
    /// program is killed (`kill_on_drop`), which closes its dialog.
    ///
    /// # Errors
    ///
    /// Like [`PinPrompt::ask`].
    pub async fn ask_within(
        &self,
        request: &PinRequest<'_>,
        timeout: Duration,
    ) -> Result<SecretBuffer> {
        tokio::time::timeout(timeout, self.ask_unbounded(request))
            .await
            .map_err(|_elapsed| {
                anyhow!(
                    "no PIN was entered within {} s, the prompt was closed",
                    timeout.as_secs()
                )
            })?
    }

    async fn ask_unbounded(&self, request: &PinRequest<'_>) -> Result<SecretBuffer> {
        match self {
            Self::Askpass(askpass) => askpass.ask_pin(&request.askpass_text()).await,
            Self::Pinentry(pinentry) => {
                let description = request.pinentry_description();
                let answer = pinentry
                    .get_pin(&Dialog {
                        title: "skagent",
                        description: &description,
                        prompt: "PIN:",
                        error: request.error,
                    })
                    .await?;
                checked_pin(answer.expose())
            }
        }
    }
}

/// Room for the longest PIN plus a `\r\n`.
const ANSWER_CAPACITY: usize = PIN_MAX_BYTES + 2;

/// Runs askpass programs.
#[derive(Debug, Clone)]
pub struct Askpass {
    program: PathBuf,
}

impl Askpass {
    /// Uses `program` for prompts.
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    /// The askpass program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Asks for a FIDO PIN with `prompt`.
    ///
    /// # Errors
    ///
    /// Returns an error if the program can't run, is cancelled (non-zero
    /// exit) or answers with something that isn't a valid PIN.
    pub async fn ask_pin(&self, prompt: &str) -> Result<SecretBuffer> {
        let mut child = prompt_command(&self.program)
            .arg(prompt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("starting askpass program {}", self.program.display()))?;
        let mut stdout = child.stdout.take().with_context(|| {
            format!(
                "reading the answer of askpass program {}",
                self.program.display()
            )
        })?;

        let mut answer = SecretBuffer::with_capacity(ANSWER_CAPACITY)?;
        let mut chunk = [0_u8; 64];
        let read = read_into(&mut stdout, &mut chunk, &mut answer).await;
        chunk.zeroize();
        read.with_context(|| {
            format!(
                "reading the answer of askpass program {}",
                self.program.display()
            )
        })?;

        let status = child
            .wait()
            .await
            .with_context(|| format!("waiting for askpass program {}", self.program.display()))?;
        if !status.success() {
            bail!(
                "the PIN prompt was cancelled ({} exited with {status})",
                self.program.display()
            );
        }
        pin_from_answer(&answer)
    }
}

async fn read_into(
    stdout: &mut tokio::process::ChildStdout,
    chunk: &mut [u8; 64],
    answer: &mut SecretBuffer,
) -> Result<()> {
    loop {
        let count = stdout.read(chunk).await.context("reading from the pipe")?;
        if count == 0 {
            return Ok(());
        }
        let Some(bytes) = chunk.get(..count) else {
            bail!("read returned more bytes than the buffer holds");
        };
        answer
            .extend_from_slice(bytes)
            .context("the answer is longer than any valid PIN")?;
    }
}

/// Turns an askpass answer into a PIN: strips one trailing `\n` or `\r\n`
/// and checks the length (4 to 63 bytes).
///
/// # Errors
///
/// Returns an error if the PIN is too short or too long. The message never
/// contains the PIN.
pub fn pin_from_answer(answer: &SecretBuffer) -> Result<SecretBuffer> {
    let bytes = answer.expose();
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    checked_pin(bytes)
}

/// Checks that `bytes` is a valid FIDO PIN (4 to 63 bytes) and copies it
/// into locked memory.
///
/// # Errors
///
/// Returns an error if the length is off. The message never contains the PIN.
pub fn checked_pin(bytes: &[u8]) -> Result<SecretBuffer> {
    if bytes.len() < PIN_MIN_BYTES || bytes.len() > PIN_MAX_BYTES {
        bail!(
            "a FIDO PIN has {PIN_MIN_BYTES} to {PIN_MAX_BYTES} bytes, the answer had {}",
            bytes.len()
        );
    }
    SecretBuffer::from_slice(bytes).context("storing the PIN in locked memory")
}

/// A command for a prompt program (pinentry, askpass): it gets stdio and the
/// agent's environment, nothing else of the agent's, and is killed when the
/// request is dropped (a client that disconnects takes its prompt along).
pub(crate) fn prompt_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        // systemd's socket activation variables are the agent's.
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .kill_on_drop(true);
    // Neither the agent socket nor an open security key.
    skagent_fds::inherit_stdio_only(command.as_std_mut());
    command
}
