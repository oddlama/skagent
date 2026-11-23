//! `identity-v1` without an agent: from what the age client hands over to
//! the file key, asking the security key itself.
//!
//! The flow goes key first. The age client may name many identities (the
//! lines of everyone who can open a file), and only the key's answers tell
//! which of them it holds. So there is one PIN and one pass over the key's
//! credentials, whatever the number of identities: each credential is
//! derived once, which takes a touch, and its public key is compared with
//! all the recipients named.
//!
//! Nothing outlives the run, and little outlives its step: the PIN is held
//! from the listing to the last derivation and wiped before a person is
//! waited for again, a derived secret and its seed live for one comparison
//! and one file's stanzas.

use std::io::{BufRead, Write};

use anyhow::Result;
use skagent_age::{FileKey, Identity, Recipient, Seed};
use skagent_age_plugin::identity::{self, File};
use skagent_age_plugin::ipc::{self, Message, Secret};
use skagent_fido::{AgeCredential, PIN_MAX_BYTES, PIN_MIN_BYTES};
use skagent_secret::SecretBuffer;

use crate::key::{Failure, Found, SecurityKey};

/// The fewest PIN tries a security key must have left to be asked for its
/// PIN here. The counter is the key's, shared with its SSH credentials and
/// everything else on it, and where this runs (a boot console with another
/// keyboard layout, say) typos are likely: the last tries aren't spent
/// here.
pub const FEWEST_TRIES: u32 = 3;

/// How many answers of a length no PIN has are taken in a row before the
/// run ends. They cost no try, but a prompt that answers by itself would
/// be asked forever.
const LENGTH_MISTAKES: u32 = 3;

/// Said to an identity without data, which names no recipient.
const WITHOUT_DATA: &str = "this plugin asks the security key itself, without skagent, and takes \
                            identities that name their recipient (from `skagent age identity`); \
                            `-j skagent` names none";

/// What ends a run before its last file key.
enum Stop {
    /// Something the age client is told, as an `error`: the run ends in
    /// order.
    Told(String),
    /// The age client can't be talked to, or something that can't happen
    /// did: the plugin fails.
    Broken(anyhow::Error),
}

impl From<anyhow::Error> for Stop {
    fn from(error: anyhow::Error) -> Self {
        Self::Broken(error)
    }
}

/// An error of the security key's that the age client is told.
fn told(error: &anyhow::Error) -> Stop {
    Stop::Told(format!("{error:#}"))
}

/// What a prompt for the PIN says before it asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Notice {
    /// Nothing: the first prompt.
    None,
    /// The PIN before was wrong.
    WrongPin,
    /// The answer before had a length no PIN has. It cost no try.
    WrongLength,
    /// The key wasn't touched in time. The PIN was right, and is typed
    /// again to try once more.
    NotTouched,
}

/// "N tries left".
fn tries_left(tries: u32) -> String {
    if tries == 1 {
        "1 try left".to_owned()
    } else {
        format!("{tries} tries left")
    }
}

/// The prompt for the PIN of the key `name`: one short line, which has to
/// say everything. Behind a boot splash or over SSH into an initrd, nobody
/// sees what the age client prints besides, so the prompt asks for the
/// touch too.
fn prompt(name: &str, tries: u32, notice: Notice) -> String {
    let left = tries_left(tries);
    match notice {
        Notice::None => format!("PIN of {name} ({left}), then touch it"),
        Notice::WrongPin => format!("Wrong PIN. PIN of {name} ({left}), then touch it"),
        Notice::WrongLength => format!(
            "A PIN has {PIN_MIN_BYTES} to {PIN_MAX_BYTES} characters. PIN of {name} ({left}), \
             then touch it"
        ),
        Notice::NotTouched => {
            format!("{name} wasn't touched in time. PIN ({left}) to try again, then touch it")
        }
    }
}

/// Why the key `name` isn't asked for its PIN with `tries` left.
fn too_few_tries(name: &str, tries: u32) -> String {
    if tries == 0 {
        return blocked(name);
    }
    format!(
        "{name} has only {} for its PIN: not asking for it here, where a typo could block the \
         key. Unlock another way; a right PIN where typing is safer sets the counter back",
        tries_left(tries)
    )
}

fn blocked(name: &str) -> String {
    format!("the PIN of {name} is blocked; only a FIDO reset, which wipes the key, helps")
}

/// What the age client is told when the key `name` refused with `failure`.
fn refused(name: &str, failure: Failure) -> String {
    match failure {
        Failure::WrongPin => format!("{name} refused the PIN"),
        Failure::BlockedUntilReplugged => format!(
            "{name} takes no more PINs after three wrong ones in a row: unplug it and plug it \
             back in"
        ),
        Failure::PinBlocked => blocked(name),
        Failure::NotTouched => format!("{name} wasn't touched in time"),
        Failure::Cancelled => format!("the request on {name} was cancelled"),
        Failure::Other(error) => format!("{error:#}"),
    }
}

/// Asks for the PIN of `key` until the key takes one, and returns it with
/// the key's age credentials, which the key lists for a right PIN alone.
///
/// A wrong PIN is asked for again, with the tries left, down to
/// [`FEWEST_TRIES`]: every PIN is typed by a person, none is tried twice. An
/// answer of a length no PIN has never reaches the key.
fn verified_pin<K: SecurityKey>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    key: &mut K,
    mut notice: Notice,
) -> Result<(SecretBuffer, Vec<AgeCredential>), Stop> {
    let not_touched = notice == Notice::NotTouched;
    let mut length_mistakes = 0_u32;
    loop {
        let tries = key.tries_left().map_err(|error| told(&error))?;
        if tries < FEWEST_TRIES {
            return Err(Stop::Told(too_few_tries(key.name(), tries)));
        }
        let asked = prompt(key.name(), tries, notice);
        let pin = match ipc::request_secret(input, output, &asked, PIN_MAX_BYTES)? {
            Secret::Given(pin) if pin.len() >= PIN_MIN_BYTES => pin,
            Secret::Given(_) | Secret::TooLong => {
                length_mistakes = length_mistakes.saturating_add(1);
                if length_mistakes >= LENGTH_MISTAKES {
                    return Err(Stop::Told(format!(
                        "no PIN was given for {}: a PIN has {PIN_MIN_BYTES} to {PIN_MAX_BYTES} \
                         characters",
                        key.name()
                    )));
                }
                notice = Notice::WrongLength;
                continue;
            }
            Secret::Refused if not_touched => {
                return Err(Stop::Told(format!(
                    "{} wasn't touched in time, and no PIN was given to try again",
                    key.name()
                )));
            }
            Secret::Refused => {
                return Err(Stop::Told(format!("no PIN was given for {}", key.name())));
            }
        };
        match key.credentials(&pin) {
            Ok(credentials) => return Ok((pin, credentials)),
            Err(Failure::WrongPin) => notice = Notice::WrongPin,
            Err(failure) => return Err(Stop::Told(refused(key.name(), failure))),
        }
    }
}

/// What one of the key's credentials is for a file.
enum Derived {
    /// The file key: the credential is an identity that was named, and
    /// the file is encrypted to it.
    Opens(FileKey),
    /// The credential is an identity that was named, and none of the file's
    /// stanzas is for it.
    Named,
    /// Nobody named this identity.
    Unnamed,
}

/// Has `key` derive `credential`'s secret, which takes a touch, and tries
/// it on `file` if it is one of the identities `named`.
///
/// A touch that doesn't come isn't the end: the PIN is wiped and asked for
/// again, which says what happened and waits for the person, and the same
/// credential is tried once more. No PIN is held while nobody may be there.
fn derive<K: SecurityKey>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    key: &mut K,
    pin: &mut SecretBuffer,
    credential: &AgeCredential,
    (named, file): (&[Recipient], &File),
) -> Result<Derived, Stop> {
    let seed = loop {
        // For someone at a terminal; the prompt has said it already.
        ipc::show(
            input,
            output,
            &format!("touch {} when it blinks", key.name()),
        )?;
        let again = match key.derive(credential, pin) {
            // The key's answer is wiped once the seed is made of it.
            Ok(answer) => break Seed::from_device_output(&answer)?,
            Err(Failure::NotTouched) => Notice::NotTouched,
            // Not after a listing with this PIN, unless it was changed
            // meanwhile.
            Err(Failure::WrongPin) => Notice::WrongPin,
            Err(failure) => return Err(Stop::Told(refused(key.name(), failure))),
        };
        pin.clear();
        *pin = verified_pin(input, output, key, again)?.0;
    };
    if !named.contains(&seed.recipient()?) {
        return Ok(Derived::Unnamed);
    }
    Ok(seed
        .unwrap(&file.stanzas)?
        .map_or(Derived::Named, Derived::Opens))
}

/// The file key of `file`, from the first of the key's `credentials` that
/// is one of the identities `named` and opens one of the file's stanzas.
fn file_key<K: SecurityKey>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    key: &mut K,
    pin: &mut SecretBuffer,
    credentials: &[AgeCredential],
    (named, file): (&[Recipient], &File),
) -> Result<FileKey, Stop> {
    let mut is_named = false;
    for credential in credentials {
        match derive(input, output, key, pin, credential, (named, file))? {
            Derived::Opens(file_key) => return Ok(file_key),
            // A line that outlived its recipient, or a file and identities
            // that don't belong together: another credential may fit.
            Derived::Named => is_named = true,
            Derived::Unnamed => {}
        }
    }
    Err(Stop::Told(if is_named {
        format!("the file isn't encrypted to the identity on {}", key.name())
    } else {
        format!("none of the identities named is on {}", key.name())
    }))
}

/// Finds the security key, takes its PIN and answers each of `files` with
/// its file key.
fn unwrap_files<K: SecurityKey>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    find: impl FnOnce() -> Result<Found<K>>,
    (named, files): (&[Recipient], &[File]),
) -> Result<(), Stop> {
    let mut key = match find().map_err(|error| told(&error))? {
        Found::One(key) => key,
        Found::None { unusable } if unusable.is_empty() => {
            return Err(Stop::Told("no security key is plugged in".to_owned()));
        }
        Found::None { unusable } => {
            return Err(Stop::Told(format!(
                "no security key that could hold an age identity is plugged in ({})",
                unusable.join("; ")
            )));
        }
        Found::Several(keys) => {
            return Err(Stop::Told(format!(
                "several security keys are plugged in ({}): unplug all but the one to use, so \
                 that its PIN goes to no other",
                keys.join(", ")
            )));
        }
    };
    let (mut pin, credentials) = verified_pin(input, output, &mut key, Notice::None)?;
    if credentials.is_empty() {
        return Err(Stop::Told(format!(
            "{} holds no age identity of skagent's",
            key.name()
        )));
    }
    for file in files {
        let file_key = file_key(
            input,
            output,
            &mut key,
            &mut pin,
            &credentials,
            (named, file),
        )?;
        let command = Message::with_body("file-key", &[&file.index], file_key.expose());
        ipc::tell(input, output, &command)?;
    }
    Ok(())
}

/// Runs the state machine: reads what the age client collected from
/// `input`, and answers each file with its file key on `output`, from the
/// security key `find` gives.
///
/// `find` is only called once there is something to ask a key for: the
/// identities are ours and name their recipients, and a file has stanzas of
/// our type. Nobody is asked for a PIN before that.
///
/// # Errors
///
/// Returns an error if the age client breaks the protocol or goes away.
/// What keeps a file from being opened (no security key, a blocked PIN, no
/// touch, a file for someone else) is told to the client as an `error`, and
/// isn't one here.
pub fn run<K: SecurityKey>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    find: impl FnOnce() -> Result<Found<K>>,
) -> Result<()> {
    let collected = identity::collect(input)?;
    let done = Message::new("done", &[]);

    let mut named = Vec::new();
    // An identity that isn't ours means the client and the plugin disagree:
    // nothing is unwrapped then.
    let mut disagree = false;
    for (position, identity) in collected.identities.into_iter().enumerate() {
        let position = position.to_string();
        let about = ["identity", position.as_str()];
        match identity {
            Ok(Identity::Named(recipient)) => named.push(recipient),
            // Only this line is refused; the others may still fit.
            Ok(Identity::AtHand) => identity::error(input, output, &about, WITHOUT_DATA)?,
            Err(reason) => {
                disagree = true;
                identity::error(input, output, &about, &reason)?;
            }
        }
    }
    if disagree {
        return ipc::write(output, &done);
    }

    let mut files = Vec::new();
    for file in collected.files {
        if file.check(input, output)? {
            files.push(file);
        }
    }
    if named.is_empty() || files.is_empty() {
        return ipc::write(output, &done);
    }

    match unwrap_files(input, output, find, (&named, &files)) {
        Ok(()) => {}
        Err(Stop::Told(reason)) => identity::error(input, output, &["internal"], &reason)?,
        Err(Stop::Broken(error)) => return Err(error),
    }
    ipc::write(output, &done)
}

/// Answers the age client, whatever it asks, that this plugin doesn't run
/// here, and why: reads what the client hands over, up to its `done`, and
/// tells it `reason`.
///
/// # Errors
///
/// Returns an error if the age client breaks the protocol or goes away.
pub fn refuse(input: &mut impl BufRead, output: &mut impl Write, reason: &str) -> Result<()> {
    loop {
        let message = ipc::read(input)?;
        let Some(message) = message else {
            anyhow::bail!("the age client stopped before `done`");
        };
        if message.tag == "done" {
            break;
        }
    }
    identity::error(input, output, &["internal"], reason)?;
    ipc::write(output, &Message::new("done", &[]))
}
