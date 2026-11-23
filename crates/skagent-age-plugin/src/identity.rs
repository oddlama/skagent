//! `identity-v1`: unwrapping file keys. The age client hands over the
//! identities and every stanza of the files' headers; the plugin answers
//! with the file keys the agent unwrapped.
//!
//! What the client hands over ([`collect`]) and how a refusal is told
//! ([`error`]) are the protocol's, and shared with the plugin for systems
//! without an agent (`skagent-age-standalone`). Whom to ask in which order
//! isn't: [`run`] asks the agent identity by identity.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use skagent_age::wire::{MAX_STANZAS, Refusal, UnwrapReply, UnwrapRequest};
use skagent_age::{Identity, Stanza};

use crate::agent::Unwrap;
use crate::ipc::{self, Message};

/// How long the agent may take before the age client is told that it waits
/// for the user. A cached PIN and a batch answer faster, and say nothing.
const NOTICE_AFTER: Duration = Duration::from_millis(800);

/// What the age client shows while the agent waits for the user.
const NOTICE: &str =
    "waiting for skagent: it asks for the PIN, then touch the security key when it blinks";

/// The stanzas of one file's header that are of our type.
#[derive(Debug, Default)]
pub struct File {
    /// The file's index, as the age client wrote it.
    pub index: String,
    /// Stanzas of this file seen so far, of any type.
    seen: usize,
    /// The well-formed stanzas of our type, in the header's order.
    pub stanzas: Vec<Stanza>,
    /// Stanzas of our type that are malformed: their position and why.
    pub invalid: Vec<(usize, String)>,
}

impl File {
    /// Whether there is something to unwrap in this file. Tells the age
    /// client what keeps it from being tried: a malformed stanza of ours,
    /// which makes the file's header invalid, or more stanzas than skagent
    /// takes. A file without a stanza of ours is nobody's fault.
    ///
    /// # Errors
    ///
    /// Returns an error if the age client can't be told.
    pub fn check(&self, input: &mut impl BufRead, output: &mut impl Write) -> Result<bool> {
        if !self.invalid.is_empty() {
            for (position, reason) in &self.invalid {
                let about = ["stanza", self.index.as_str(), &position.to_string()];
                error(input, output, &about, reason)?;
            }
            return Ok(false);
        }
        if self.stanzas.len() > MAX_STANZAS {
            let reason = format!(
                "the file has {} stanzas of this recipient type; skagent takes {MAX_STANZAS}",
                self.stanzas.len()
            );
            error(input, output, &["internal"], &reason)?;
            return Ok(false);
        }
        Ok(!self.stanzas.is_empty())
    }
}

/// What phase 1 collected.
#[derive(Debug, Default)]
pub struct Collected {
    /// Each identity, or why it isn't one of ours.
    pub identities: Vec<Result<Identity, String>>,
    /// The files, in the order the age client named them.
    pub files: Vec<File>,
}

/// Phase 1: reads what the age client hands over, up to its `done`.
///
/// # Errors
///
/// Returns an error if the age client breaks the protocol or stops before
/// `done`. An identity or a stanza of ours that is malformed isn't one: it
/// is kept with the reason, to be told in phase 2.
pub fn collect(input: &mut impl BufRead) -> Result<Collected> {
    let mut collected = Collected::default();
    loop {
        let message = ipc::read(input)?.context("the age client stopped before `done`")?;
        match message.tag.as_str() {
            "done" => return Ok(collected),
            "add-identity" => {
                let identity = match message.arguments.as_slice() {
                    [identity] => identity
                        .parse::<Identity>()
                        .map_err(|error| format!("{error:#}")),
                    _ => Err("add-identity takes one identity".to_owned()),
                };
                collected.identities.push(identity);
            }
            "recipient-stanza" => {
                let (index, stanza) = message
                    .arguments
                    .split_first()
                    .context("recipient-stanza without a file index")?;
                if collected
                    .files
                    .last()
                    .is_none_or(|file| file.index != *index)
                {
                    collected.files.push(File {
                        index: index.clone(),
                        ..File::default()
                    });
                }
                let file = collected.files.last_mut().context("no file")?;
                let position = file.seen;
                file.seen = file.seen.saturating_add(1);
                match Stanza::from_header(stanza, &message.body) {
                    Ok(Some(stanza)) => file.stanzas.push(stanza),
                    // Another recipient type: not ours to look at.
                    Ok(None) => {}
                    Err(error) => file.invalid.push((position, format!("{error:#}"))),
                }
            }
            // Commands this version doesn't know are ignored in this phase.
            _ => {}
        }
    }
}

/// Sends an `error` command; the age client answers `ok`. `about`: what the
/// error is about, `["identity", index]`, `["stanza", file, index]` or
/// `["internal"]`.
///
/// # Errors
///
/// Returns an error if the age client can't be told or answers anything
/// else.
pub fn error(
    input: &mut impl BufRead,
    output: &mut impl Write,
    about: &[&str],
    message: &str,
) -> Result<()> {
    ipc::tell(
        input,
        output,
        &Message::with_body("error", about, message.as_bytes()),
    )
}

/// Asks the agent. While it hasn't answered: tells the age client that it
/// waits for the user, once and only if the answer takes a while, and gives
/// up when `client_gone` says nobody waits for the answer any more.
/// `noticed`: whether the client was told already.
fn ask_agent(
    input: &mut impl BufRead,
    output: &mut impl Write,
    agent: &mut impl Unwrap,
    request: &UnwrapRequest,
    (noticed, client_gone): (&mut bool, &mut impl FnMut() -> bool),
) -> Result<UnwrapReply> {
    let started = Instant::now();
    agent.unwrap(request, &mut || {
        if client_gone() {
            bail!("the age client went away");
        }
        if !*noticed && started.elapsed() >= NOTICE_AFTER {
            *noticed = true;
            ipc::show(input, output, NOTICE)?;
        }
        Ok(())
    })
}

/// Whether a refusal ends the whole run: nothing else would go better.
const fn ends_the_run(refusal: Refusal) -> bool {
    match refusal {
        Refusal::Cancelled
        | Refusal::TimedOut
        | Refusal::Locked
        | Refusal::NotAllowed
        | Refusal::Failed => true,
        // Another identity may fit.
        Refusal::NoIdentity | Refusal::AnotherIdentity | Refusal::Ambiguous => false,
    }
}

/// Runs the state machine: reads what the age client collected for us from
/// `input`, asks `agent` for each file, and writes the file keys to
/// `output`. `client_gone` says whether the age client went away, which
/// ends a wait for the agent.
///
/// # Errors
///
/// Returns an error if the age client breaks the protocol or goes away, or
/// the agent can't be asked at all. What the agent refuses is told to the
/// client as an `error` and isn't one here.
pub fn run(
    input: &mut impl BufRead,
    output: &mut impl Write,
    agent: &mut impl Unwrap,
    mut client_gone: impl FnMut() -> bool,
) -> Result<()> {
    let collected = collect(input)?;
    let done = Message::new("done", &[]);

    // An identity that isn't ours means the client and the plugin disagree:
    // nothing is unwrapped then.
    let mut identities = Vec::new();
    let mut refused = false;
    for (position, identity) in collected.identities.into_iter().enumerate() {
        match identity {
            Ok(identity) => identities.push((position, identity)),
            Err(reason) => {
                refused = true;
                error(input, output, &["identity", &position.to_string()], &reason)?;
            }
        }
    }
    if refused {
        return ipc::write(output, &done);
    }

    let mut noticed = false;
    'files: for file in collected.files {
        if !file.check(input, output)? {
            continue;
        }
        for (position, identity) in &identities {
            let request = UnwrapRequest {
                identity: identity.clone(),
                stanzas: file.stanzas.clone(),
            };
            let waiting = (&mut noticed, &mut client_gone);
            match ask_agent(input, output, agent, &request, waiting)? {
                UnwrapReply::FileKey(file_key) => {
                    let command = Message::with_body("file-key", &[&file.index], file_key.expose());
                    ipc::tell(input, output, &command)?;
                    continue 'files;
                }
                // Not for this identity; the next one may fit.
                UnwrapReply::NoMatch => {}
                UnwrapReply::Refused(refusal) => {
                    let about = ["identity", &position.to_string()];
                    error(input, output, &about, refusal.message())?;
                    if ends_the_run(refusal) {
                        break 'files;
                    }
                }
            }
        }
    }
    ipc::write(output, &done)
}
