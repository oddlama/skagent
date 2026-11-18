//! The protocol between skagent and its popup (`skagent-pinentry`).
//!
//! The agent starts the popup and talks to it over the popup's stdin and
//! stdout. The agent decides what to show, the popup only renders it and
//! reports what the user did.
//!
//! - **Popup → agent, first:** `READY <version>` once it can show states.
//! - **Agent → popup:** one JSON object per line, a [`Message`]: the state to
//!   show, or which other requests wait for the popup. Never a secret.
//! - **Popup → agent:** text lines, each an [`Intent`]: `PIN <seq> <data>`,
//!   `CANCEL <seq>` or `RETRY <seq>`. `seq` names the state the user acted on,
//!   so the agent can ignore answers to states it already replaced. The PIN
//!   is percent-escaped like Assuan data (`%`, CR and LF become `%25`, `%0D`
//!   and `%0A`), and the agent reads the line into locked memory.
//! - **The agent closes stdin** when it doesn't need the popup any more. The
//!   popup then exits, after showing a final state such as
//!   [`State::Signed`] for a moment. Until the first state arrives the popup
//!   shows nothing.
//!
//! Text fields come from the agent, which sanitized them: control and
//! invisible formatting characters are already replaced. A popup must still
//! render them as plain text.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use skagent_secret::SecretBuffer;

/// The protocol version in `READY`. Changes that alter the meaning of a
/// message bump it; new optional fields don't.
pub const VERSION: u32 = 1;

/// Longest line the popup may send, without the newline.
pub const MAX_INTENT_LINE: usize = 1000;

/// Longest decoded PIN accepted. The agent checks the FIDO limits itself.
pub const MAX_PIN_BYTES: usize = 256;

/// A message from the agent to the popup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Message {
    /// Show `state`. Replaces whatever was shown before.
    Show {
        /// Names this state in the popup's answers.
        seq: u64,
        /// The other requests waiting for the popup, oldest first.
        waiting: Vec<Queued>,
        /// What to show.
        state: Box<State>,
    },
    /// The requests waiting for the popup changed.
    Queue {
        /// The other requests waiting for the popup, oldest first.
        waiting: Vec<Queued>,
    },
}

/// A request waiting for the popup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queued {
    /// The SSH key it signs with; none for loading resident keys.
    pub key: Option<Key>,
}

/// What the popup shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "kebab-case")]
pub enum State {
    /// The key has never been used and several security keys are plugged
    /// in: each one blinks, and the user touches the one holding the key.
    /// Without a key: choosing the security key to load resident keys from.
    Select {
        /// The SSH key, if this is for a signature.
        key: Option<Key>,
        /// How many security keys blink.
        devices: usize,
        /// How long the selection waits for a touch.
        timeout_ms: u64,
    },
    /// Enter the PIN for a signature. Answered with `PIN` or `CANCEL`.
    Pin {
        /// The SSH key.
        key: Key,
        /// What is signed.
        request: Request,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// Set after a wrong PIN.
        mistake: Option<Mistake>,
    },
    /// Enter the PIN to load the resident keys of a security key. Answered
    /// with `PIN` or `CANCEL`.
    LoadPin {
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// Set after a wrong PIN.
        mistake: Option<Mistake>,
    },
    /// Touch the security key to sign.
    Touch {
        /// The SSH key.
        key: Key,
        /// What is signed.
        request: Request,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// About how long the key waits for the touch.
        timeout_ms: u64,
        /// The key was just selected by touch, so this is the second one.
        again: bool,
    },
    /// Touch the security key once more: skagent pairs with it, once, to
    /// tell it from a device claiming to be it later. Comes right after a
    /// signature or loading succeeded; answered with `CANCEL` to skip it.
    Pair {
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// About how long the key waits for the touch.
        timeout_ms: u64,
    },
    /// Signed. Final.
    Signed {
        /// The SSH key.
        key: Key,
        /// What was signed.
        request: Request,
    },
    /// Resident keys loaded. Final.
    Loaded {
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// The keys loaded, already loaded ones included.
        keys: Vec<Key>,
    },
    /// The YubiKey known to hold the key isn't plugged in, another one is.
    /// Moves on by itself once the right one appears.
    WrongKey {
        /// The SSH key.
        key: Key,
        /// The YubiKey that holds it.
        security_key: Option<SecurityKey>,
        /// The YubiKey that is plugged in instead.
        other: Option<SecurityKey>,
    },
    /// No security key is plugged in. Moves on by itself once one appears.
    NoKey {
        /// The SSH key, unless loading.
        key: Option<Key>,
        /// The YubiKey known to hold the key, if any.
        security_key: Option<SecurityKey>,
    },
    /// Too many wrong PINs in a row: the key accepts no PIN until it was
    /// unplugged and plugged back in. Final.
    Replug {
        /// The SSH key, unless loading.
        key: Option<Key>,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// PIN tries left, if known.
        tries_left: Option<u32>,
    },
    /// No PIN tries left: only a reset, which wipes the key, helps. Final.
    Locked {
        /// The SSH key, unless loading.
        key: Option<Key>,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
    },
    /// The key wants a new PIN before it accepts this one. Final.
    NewPin {
        /// The SSH key, unless loading.
        key: Option<Key>,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
    },
    /// Nobody touched the key in time. Answered with `RETRY` (touch again,
    /// the PIN was kept) or `CANCEL`.
    Timeout {
        /// The SSH key.
        key: Option<Key>,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
    },
    /// Anything else went wrong. Final.
    Failed {
        /// The SSH key, unless loading.
        key: Option<Key>,
        /// The YubiKey, if it reports a serial.
        security_key: Option<SecurityKey>,
        /// What went wrong.
        reason: Failure,
    },
}

impl State {
    /// The state's name on the wire (its `name` field), for logs.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Select { .. } => "select",
            Self::Pin { .. } => "pin",
            Self::LoadPin { .. } => "load-pin",
            Self::Touch { .. } => "touch",
            Self::Pair { .. } => "pair",
            Self::Signed { .. } => "signed",
            Self::Loaded { .. } => "loaded",
            Self::WrongKey { .. } => "wrong-key",
            Self::NoKey { .. } => "no-key",
            Self::Replug { .. } => "replug",
            Self::Locked { .. } => "locked",
            Self::NewPin { .. } => "new-pin",
            Self::Timeout { .. } => "timeout",
            Self::Failed { .. } => "failed",
        }
    }
}

/// An SSH key as the user knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// The configured emoji, if any.
    pub emoji: Option<String>,
    /// The configured label, else the key's comment.
    pub label: String,
    /// `SHA256:…`, as `ssh-add -l` shows it.
    pub fingerprint: String,
}

/// A YubiKey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityKey {
    /// The configured name, else `YubiKey 12 345 678` (its serial).
    pub name: String,
}

/// A wrong PIN was entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mistake {
    /// PIN tries the key has left.
    pub tries_left: u32,
}

/// What a signature is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Request {
    /// Logging in over SSH.
    Login {
        /// The user to log in as.
        user: String,
        /// Where.
        host: Host,
        /// The first host the agent was forwarded to, for forwarded requests.
        via: Option<Host>,
    },
    /// An SSHSIG signature (`ssh-keygen -Y sign`, git commits and tags).
    Sign {
        /// What kind of data, e.g. `git` or `file`.
        namespace: String,
    },
    /// Data of no known kind.
    Unknown,
}

/// A host as far as the agent can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Host {
    /// A host name.
    Named {
        /// E.g. `github.com`.
        name: String,
    },
    /// Only the host key that signed the session is known.
    HostKey {
        /// `SHA256:…`.
        fingerprint: String,
    },
    /// The session isn't bound to a verified host key.
    Unverified,
}

/// Why a request failed, where the agent knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Failure {
    /// The security key was unplugged, replaced or stopped answering.
    Unplugged,
    /// The security key refused the operation.
    Refused,
    /// The security key doesn't hold the SSH key, e.g. another one was
    /// touched, or it was reset since.
    NotOnKey,
    /// The security key has no PIN set.
    NoPin,
    /// The security key wasn't plugged in while the request waited for it.
    NotPluggedIn,
    /// Two plugged-in security keys report the serial of the YubiKey holding
    /// the SSH key: one of them pretends to be it. Neither got the PIN.
    Duplicate,
    /// A device reports the serial of the paired YubiKey but can't prove
    /// skagent's pairing: a fake, or the key was reset. It got no PIN.
    Unrecognized,
    /// Something else; the agent's log says what. Also any reason this
    /// popup doesn't know yet.
    #[serde(other)]
    Other,
}

/// A message from the popup to the agent.
#[derive(Debug)]
pub enum Intent {
    /// The popup speaks protocol `version`.
    Ready {
        /// [`VERSION`] of the popup.
        version: u32,
    },
    /// The user entered `pin` in state `seq`.
    Pin {
        /// The state the PIN was entered in.
        seq: u64,
        /// The PIN, in locked memory.
        pin: SecretBuffer,
    },
    /// The user cancelled in state `seq`.
    Cancel {
        /// The state the user cancelled in.
        seq: u64,
    },
    /// The user asked to try again in state `seq`.
    Retry {
        /// The state the user retried in.
        seq: u64,
    },
}

/// `message` as a line for the popup's stdin.
///
/// # Errors
///
/// Returns an error if the message can't be serialized.
pub fn encode_message(message: &Message) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(message).context("encoding a popup message")?;
    line.push(b'\n');
    Ok(line)
}

/// One line from the agent, without its newline.
///
/// # Errors
///
/// Returns an error if the line isn't a message of this protocol version.
pub fn decode_message(line: &str) -> Result<Message> {
    serde_json::from_str(line).context("decoding a message from the agent")
}

/// One line from the popup, without its newline. A PIN is decoded into
/// locked memory.
///
/// # Errors
///
/// Returns an error if the line is malformed. The message never contains the
/// line's content.
pub fn parse_intent(line: &[u8]) -> Result<Intent> {
    let (verb, rest) = split_word(line);
    match verb {
        b"READY" => Ok(Intent::Ready {
            version: parse_number(rest).context("a READY line without a version")?,
        }),
        b"CANCEL" => Ok(Intent::Cancel {
            seq: parse_number(rest).context("a CANCEL line without a sequence number")?,
        }),
        b"RETRY" => Ok(Intent::Retry {
            seq: parse_number(rest).context("a RETRY line without a sequence number")?,
        }),
        b"PIN" => {
            let (seq, data) = split_word(rest);
            let seq = parse_number(seq).context("a PIN line without a sequence number")?;
            let mut pin = SecretBuffer::with_capacity(MAX_PIN_BYTES)?;
            unescape(data, &mut pin)?;
            ensure!(!pin.is_empty(), "a PIN line without a PIN");
            Ok(Intent::Pin { seq, pin })
        }
        _ => bail!("an unknown line from the popup (contents redacted)"),
    }
}

/// The `READY` line, with its newline.
#[must_use]
pub fn ready_line() -> String {
    format!("READY {VERSION}\n")
}

/// The `CANCEL` line for state `seq`, with its newline.
#[must_use]
pub fn cancel_line(seq: u64) -> String {
    format!("CANCEL {seq}\n")
}

/// The `RETRY` line for state `seq`, with its newline.
#[must_use]
pub fn retry_line(seq: u64) -> String {
    format!("RETRY {seq}\n")
}

/// The `PIN` line for `pin` in state `seq`, with its newline, in locked
/// memory.
///
/// # Errors
///
/// Returns an error if `pin` is empty or too long.
pub fn pin_line(seq: u64, pin: &[u8]) -> Result<SecretBuffer> {
    ensure!(
        !pin.is_empty() && pin.len() <= MAX_PIN_BYTES,
        "a PIN has 1 to {MAX_PIN_BYTES} bytes"
    );
    let head = format!("PIN {seq} ");
    // Every byte may become three, plus the newline.
    let capacity = pin
        .len()
        .checked_mul(3)
        .and_then(|escaped| escaped.checked_add(head.len()))
        .and_then(|line| line.checked_add(1))
        .context("the PIN line is too long")?;
    let mut line = SecretBuffer::with_capacity(capacity)?;
    line.extend_from_slice(head.as_bytes())?;
    for &byte in pin {
        match byte {
            b'%' => line.extend_from_slice(b"%25")?,
            b'\r' => line.extend_from_slice(b"%0D")?,
            b'\n' => line.extend_from_slice(b"%0A")?,
            _ => line.extend_from_slice(&[byte])?,
        }
    }
    line.extend_from_slice(b"\n")?;
    Ok(line)
}

/// The first word of `line` and the rest after one space.
fn split_word(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&byte| byte == b' ') {
        Some(space) => (
            line.get(..space).unwrap_or_default(),
            line.get(space.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (line, &[]),
    }
}

fn parse_number<T: std::str::FromStr>(text: &[u8]) -> Result<T> {
    ensure!(
        !text.is_empty() && text.iter().all(u8::is_ascii_digit),
        "not a number"
    );
    std::str::from_utf8(text)
        .ok()
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(|| anyhow!("a number out of range"))
}

/// Appends the percent-decoded `data` to `out`.
fn unescape(data: &[u8], out: &mut SecretBuffer) -> Result<()> {
    let mut bytes = data.iter();
    while let Some(&byte) = bytes.next() {
        let decoded = if byte == b'%' {
            let (Some(&high), Some(&low)) = (bytes.next(), bytes.next()) else {
                bail!("a truncated percent escape in a PIN line");
            };
            let (Some(high), Some(low)) = (hex_value(high), hex_value(low)) else {
                bail!("an invalid percent escape in a PIN line");
            };
            high.checked_mul(16)
                .and_then(|value| value.checked_add(low))
                .context("a percent escape out of range")?
        } else {
            byte
        };
        out.extend_from_slice(&[decoded])
            .map_err(|_| anyhow!("a PIN longer than {MAX_PIN_BYTES} bytes"))?;
    }
    Ok(())
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit
            .checked_sub(b'a')
            .and_then(|value| value.checked_add(10)),
        b'A'..=b'F' => digit
            .checked_sub(b'A')
            .and_then(|value| value.checked_add(10)),
        _ => None,
    }
}
