//! The messages between the agent and those who ask it about age
//! identities: its plugin and its own command line. They are extensions of
//! the ssh-agent protocol, so agent forwarding carries them.
//!
//! Everything is decoded strictly: a version first, exact lengths, nothing
//! trailing. No message carries a PIN or a long-term secret; a reply to
//! [`UNWRAP_EXTENSION`] carries the file key of one file.

use anyhow::{Context as _, Result, bail, ensure};

use crate::identity::Identity;
use crate::recipient::{RECIPIENT_BYTES, Recipient};
use crate::seed::{FILE_KEY_BYTES, FileKey};
use crate::stanza::{STANZA_BYTES, Stanza};

/// Unwraps the file key of one file: an [`UnwrapRequest`], answered with an
/// [`UnwrapReply`].
pub const UNWRAP_EXTENSION: &str = "age-unwrap@skagent";

/// Creates an age identity on a security key: [`new_request`], answered
/// with a [`NewReply`].
pub const NEW_EXTENSION: &str = "age-new@skagent";

/// Lists the age identities the agent knows: [`simple_request`], answered
/// with a [`ListReply`].
pub const LIST_EXTENSION: &str = "age-list@skagent";

/// The version every message starts with.
const VERSION: u8 = 1;

/// Most stanzas in one [`UnwrapRequest`]. A file for more recipients of this
/// type than that is refused; age's own limit on a header is far higher, but
/// every stanza here costs the agent a decapsulation.
pub const MAX_STANZAS: usize = 64;

/// Most identities in one [`ListReply`].
pub const MAX_LISTED: usize = 256;

/// SSH agent protocol numbers (draft-ietf-sshm-ssh-agent).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

/// Longest reply frame a client reads: far more than any reply here.
pub const MAX_REPLY_BYTES: usize = 512 * 1024;

/// Reads from a message, front to back.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (taken, rest) = self
            .0
            .split_at_checked(length)
            .with_context(|| format!("the message ends {length} bytes early or more"))?;
        self.0 = rest;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().context("no byte")
    }

    fn u32(&mut self) -> Result<usize> {
        let bytes: [u8; 4] = self.take(4)?.try_into().context("no length")?;
        usize::try_from(u32::from_be_bytes(bytes)).context("a length beyond this machine")
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()?;
        self.take(length)
    }

    fn version(&mut self) -> Result<()> {
        let version = self.byte()?;
        ensure!(
            version == VERSION,
            "message version {version}, this skagent speaks version {VERSION}"
        );
        Ok(())
    }

    fn end(self) -> Result<()> {
        ensure!(
            self.0.is_empty(),
            "{} bytes after the end of the message",
            self.0.len()
        );
        Ok(())
    }
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).context("a length that doesn't fit the protocol")?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_u32(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// The details of a request that says nothing but its version.
#[must_use]
pub fn simple_request() -> Vec<u8> {
    vec![VERSION]
}

/// Checks the details of a request that says nothing but its version.
///
/// # Errors
///
/// Returns an error for another version or anything else.
pub fn check_simple_request(details: &[u8]) -> Result<()> {
    let mut reader = Reader(details);
    reader.version()?;
    reader.end()
}

/// The details of a request for a new identity. `another`: also on a
/// security key that holds one already.
#[must_use]
pub fn new_request(another: bool) -> Vec<u8> {
    vec![VERSION, u8::from(another)]
}

/// Whether a request for a new identity asks for `another`.
///
/// # Errors
///
/// Returns an error for anything but one well-formed request.
pub fn decode_new_request(details: &[u8]) -> Result<bool> {
    let mut reader = Reader(details);
    reader.version()?;
    let another = match reader.byte()? {
        0 => false,
        1 => true,
        other => bail!("unknown flags {other} in a request for a new identity"),
    };
    reader.end()?;
    Ok(another)
}

/// Asks for the file key of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapRequest {
    /// The identity to decrypt with.
    pub identity: Identity,
    /// The file's `mlkem768x25519` stanzas, in the header's order. The agent
    /// returns the file key of the first that opens.
    pub stanzas: Vec<Stanza>,
}

impl UnwrapRequest {
    /// The request's details.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no stanzas or more than
    /// [`MAX_STANZAS`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(!self.stanzas.is_empty(), "a request without stanzas");
        ensure!(
            self.stanzas.len() <= MAX_STANZAS,
            "{} stanzas of this recipient type in one file; skagent takes {MAX_STANZAS}",
            self.stanzas.len()
        );
        let mut out = vec![VERSION];
        put_string(&mut out, &self.identity.to_data())?;
        put_u32(&mut out, self.stanzas.len())?;
        for stanza in &self.stanzas {
            out.extend_from_slice(&stanza.to_bytes());
        }
        Ok(out)
    }

    /// A request from its details.
    ///
    /// # Errors
    ///
    /// Returns an error for anything but one well-formed request: another
    /// version, an identity or a stanza this code refuses, no stanzas or
    /// more than [`MAX_STANZAS`], or trailing bytes.
    pub fn decode(details: &[u8]) -> Result<Self> {
        let mut reader = Reader(details);
        reader.version()?;
        let identity = Identity::from_data(reader.string()?)?;
        let count = reader.u32()?;
        ensure!(count >= 1, "a request without stanzas");
        ensure!(
            count <= MAX_STANZAS,
            "{count} stanzas in one request; skagent takes {MAX_STANZAS}"
        );
        let stanzas = (0..count)
            .map(|_| Stanza::from_bytes(reader.take(STANZA_BYTES)?))
            .collect::<Result<Vec<_>>>()?;
        reader.end()?;
        Ok(Self { identity, stanzas })
    }
}

/// Why the agent didn't try, or didn't get to, unwrap. Codes, not text:
/// what the agent knows about this machine stays on it when the request
/// came through a forwarded agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The user cancelled, or the request was revoked (lock, sleep, forget).
    Cancelled,
    /// Nobody typed the PIN or touched the security key in time, or the
    /// security key wasn't plugged in.
    TimedOut,
    /// The agent is locked (`ssh-add -x`).
    Locked,
    /// The agent knows no age identity that fits.
    NoIdentity,
    /// The security key holds another identity than the one named.
    AnotherIdentity,
    /// Several identities are at hand and the request named none.
    Ambiguous,
    /// This connection may not ask: not skagent's plugin, or through a
    /// forwarded agent while that is switched off.
    NotAllowed,
    /// Anything else; the agent's log says what. Also any code this version
    /// doesn't know.
    Failed,
}

impl Refusal {
    const fn code(self) -> u8 {
        match self {
            Self::Cancelled => 1,
            Self::TimedOut => 2,
            Self::Locked => 3,
            Self::NoIdentity => 4,
            Self::AnotherIdentity => 5,
            Self::Ambiguous => 6,
            Self::NotAllowed => 7,
            Self::Failed => 255,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Cancelled,
            2 => Self::TimedOut,
            3 => Self::Locked,
            4 => Self::NoIdentity,
            5 => Self::AnotherIdentity,
            6 => Self::Ambiguous,
            7 => Self::NotAllowed,
            _ => Self::Failed,
        }
    }

    /// What to tell the person who ran age.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "skagent: the request was cancelled",
            Self::TimedOut => {
                "skagent: nobody answered in time (PIN, touch, or plugging in the security key)"
            }
            Self::Locked => "skagent is locked; unlock it with ssh-add -X",
            Self::NoIdentity => {
                "skagent knows no age identity for this: plug in the security key and run \
                 `skagent load`, or create one with `skagent age new`"
            }
            Self::AnotherIdentity => {
                "the security key holds another age identity than the one this identity file names"
            }
            Self::Ambiguous => {
                "skagent knows several age identities; use an identity file from \
                 `skagent age identity` that names one"
            }
            Self::NotAllowed => {
                "skagent doesn't take age requests on this connection (see its log for the reason)"
            }
            Self::Failed => "skagent couldn't decrypt; its log says why",
        }
    }
}

/// What the agent answers to an [`UnwrapRequest`].
#[derive(Debug)]
pub enum UnwrapReply {
    /// The file key.
    FileKey(FileKey),
    /// None of the stanzas is for the identity.
    NoMatch,
    /// The agent didn't unwrap.
    Refused(Refusal),
}

const REPLY_FILE_KEY: u8 = 0;
const REPLY_NO_MATCH: u8 = 1;
const REPLY_REFUSED: u8 = 2;

impl UnwrapReply {
    /// The reply's details. With a file key they are a secret: the caller
    /// hands them on and doesn't keep them.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        match self {
            Self::FileKey(file_key) => {
                out.push(REPLY_FILE_KEY);
                out.extend_from_slice(file_key.expose());
            }
            Self::NoMatch => out.push(REPLY_NO_MATCH),
            Self::Refused(refusal) => {
                out.push(REPLY_REFUSED);
                out.push(refusal.code());
            }
        }
        out
    }

    /// A reply from its details.
    ///
    /// # Errors
    ///
    /// Returns an error for anything but one well-formed reply.
    pub fn decode(details: &[u8]) -> Result<Self> {
        let mut reader = Reader(details);
        reader.version()?;
        let reply = match reader.byte()? {
            REPLY_FILE_KEY => Self::FileKey(FileKey::from_bytes(reader.take(FILE_KEY_BYTES)?)?),
            REPLY_NO_MATCH => Self::NoMatch,
            REPLY_REFUSED => Self::Refused(Refusal::from_code(reader.byte()?)),
            other => bail!("unknown kind of reply {other}"),
        };
        reader.end()?;
        Ok(reply)
    }
}

/// What the agent answers to [`NEW_EXTENSION`]: the new identity's
/// recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReply {
    /// What files for the new identity are encrypted to.
    pub recipient: Recipient,
}

impl NewReply {
    /// The reply's details.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.extend_from_slice(self.recipient.as_bytes());
        out
    }

    /// A reply from its details.
    ///
    /// # Errors
    ///
    /// Returns an error for anything but one well-formed reply.
    pub fn decode(details: &[u8]) -> Result<Self> {
        let mut reader = Reader(details);
        reader.version()?;
        let recipient = Recipient::from_bytes(reader.take(RECIPIENT_BYTES)?)?;
        reader.end()?;
        Ok(Self { recipient })
    }
}

/// What the agent answers to [`LIST_EXTENSION`]: the identities it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListReply {
    /// One entry per identity: its recipient, once the agent derived it on
    /// this machine.
    pub identities: Vec<Option<Recipient>>,
}

impl ListReply {
    /// The reply's details.
    ///
    /// # Errors
    ///
    /// Returns an error for more than [`MAX_LISTED`] identities.
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.identities.len() <= MAX_LISTED,
            "{} identities don't fit one reply",
            self.identities.len()
        );
        let mut out = vec![VERSION];
        put_u32(&mut out, self.identities.len())?;
        for identity in &self.identities {
            match identity {
                Some(recipient) => {
                    out.push(1);
                    out.extend_from_slice(recipient.as_bytes());
                }
                None => out.push(0),
            }
        }
        Ok(out)
    }

    /// A reply from its details.
    ///
    /// # Errors
    ///
    /// Returns an error for anything but one well-formed reply.
    pub fn decode(details: &[u8]) -> Result<Self> {
        let mut reader = Reader(details);
        reader.version()?;
        let count = reader.u32()?;
        ensure!(count <= MAX_LISTED, "{count} identities in one reply");
        let identities = (0..count)
            .map(|_| match reader.byte()? {
                0 => Ok(None),
                1 => Recipient::from_bytes(reader.take(RECIPIENT_BYTES)?).map(Some),
                other => bail!("unknown kind of identity entry {other}"),
            })
            .collect::<Result<Vec<_>>>()?;
        reader.end()?;
        Ok(Self { identities })
    }
}

/// One ssh-agent protocol message that asks for the extension `name` with
/// `details`: the length, `SSH_AGENTC_EXTENSION`, the name, the details.
/// For clients that speak to the agent without an ssh-agent library.
///
/// # Errors
///
/// Returns an error if the message would be too long for the protocol.
pub fn request_frame(name: &str, details: &[u8]) -> Result<Vec<u8>> {
    let mut message = vec![SSH_AGENTC_EXTENSION];
    put_string(&mut message, name.as_bytes())?;
    message.extend_from_slice(details);
    let mut frame = Vec::with_capacity(message.len().saturating_add(4));
    put_u32(&mut frame, message.len())?;
    frame.extend_from_slice(&message);
    Ok(frame)
}

/// The length of the message a 4-byte frame header announces.
///
/// # Errors
///
/// Returns an error for an empty message or one above [`MAX_REPLY_BYTES`].
pub fn reply_length(header: [u8; 4]) -> Result<usize> {
    let length =
        usize::try_from(u32::from_be_bytes(header)).context("a length beyond this machine")?;
    ensure!(length >= 1, "an empty reply");
    ensure!(
        length <= MAX_REPLY_BYTES,
        "a reply of {length} bytes; the agent's are much shorter"
    );
    Ok(length)
}

/// The details of the reply `message` (one frame's content, without its
/// length) to a request for the extension `name`. `None` if the agent
/// answered with a failure: it doesn't know the extension, or refuses it on
/// this connection.
///
/// # Errors
///
/// Returns an error if the message is neither a failure nor a response to
/// that extension.
pub fn reply_details<'a>(name: &str, message: &'a [u8]) -> Result<Option<&'a [u8]>> {
    let mut reader = Reader(message);
    match reader.byte()? {
        SSH_AGENT_FAILURE | SSH_AGENT_EXTENSION_FAILURE => Ok(None),
        SSH_AGENT_EXTENSION_RESPONSE => {
            ensure!(
                reader.string()? == name.as_bytes(),
                "the agent answered another extension than {name}"
            );
            Ok(Some(reader.0))
        }
        other => bail!("the agent answered {name} with a message of type {other}"),
    }
}
