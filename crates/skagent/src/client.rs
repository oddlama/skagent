//! Talking to a running agent, for `skagent forget`, `skagent load` and
//! `skagent age`.

use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age::wire::{self, LIST_EXTENSION, ListReply, NEW_EXTENSION, NewReply};
use skagent_age::{Identity, Recipient};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Unparsed};
use tokio::net::UnixStream;

use crate::agent::{FORGET_PINS_EXTENSION, LOAD_KEYS_EXTENSION};

/// Whether a FIDO security key is connected, for `skagent load
/// --if-connected`. Checked by the client: the agent's refusal reaches it
/// without a reason.
///
/// # Errors
///
/// Returns an error if the devices can't be listed.
pub fn security_key_connected() -> Result<bool> {
    Ok(!skagent_fido::hid_devices()
        .context("listing connected security keys")?
        .is_empty())
}

/// What a load found on the security key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    /// Resident SSH keys, already loaded ones included.
    pub keys: u32,
    /// Age identities.
    pub age_identities: u32,
}

/// Asks the agent to select a device, prompt and load its resident SSH keys
/// and note its age identities. No PIN or credential handle is carried by
/// this request/reply.
///
/// # Errors
/// Refuses an unreachable agent, failed loading or malformed extension reply.
pub async fn load_keys(socket: &Path) -> Result<Loaded> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to the agent at {}", socket.display()))?;
    let reply = Client::new(stream)
        .extension(Extension {
            name: LOAD_KEYS_EXTENSION.to_owned(),
            details: Unparsed::from(Vec::new()),
        })
        .await
        .with_context(|| {
            format!(
                "asking {} to load resident SSH keys; check the agent log for the refusal reason",
                socket.display()
            )
        })?
        .context("the agent returned no resident-loading result")?;
    decode_loaded_count(&reply)
}

/// Validates the loading extension's reply before reporting success: two
/// big-endian counts, the SSH keys and the age identities.
///
/// # Errors
/// Refuses an unexpected extension name or payload length.
pub fn decode_loaded_count(reply: &Extension) -> Result<Loaded> {
    ensure!(
        reply.name == LOAD_KEYS_EXTENSION,
        "unexpected resident-loading reply name"
    );
    let (keys, age_identities) = reply
        .details
        .as_ref()
        .split_first_chunk::<4>()
        .and_then(|(keys, rest)| Some((*keys, <[u8; 4]>::try_from(rest).ok()?)))
        .context("resident-loading reply must contain two u32 counts")?;
    Ok(Loaded {
        keys: u32::from_be_bytes(keys),
        age_identities: u32::from_be_bytes(age_identities),
    })
}

/// Asks the agent at `socket` to drop all cached PINs.
///
/// # Errors
///
/// Returns an error if the agent can't be reached or refuses (e.g. it's not
/// skagent).
pub async fn forget_pins(socket: &Path) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to the agent at {}", socket.display()))?;
    let reply = Client::new(stream)
        .extension(Extension {
            name: FORGET_PINS_EXTENSION.to_owned(),
            details: Unparsed::from(Vec::new()),
        })
        .await
        .with_context(|| {
            format!(
                "asking the agent at {} to forget its PINs (is it skagent?)",
                socket.display()
            )
        })?;
    if reply.is_some() {
        bail!(
            "the agent at {} answered {FORGET_PINS_EXTENSION} with data",
            socket.display()
        );
    }
    Ok(())
}

/// Sends the extension `name` to the agent's socket for age requests and
/// returns the details of its reply.
async fn age_request(socket: &Path, name: &str, details: Vec<u8>) -> Result<Vec<u8>> {
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "connecting to the agent's socket for age requests at {} (is skagent running?)",
            socket.display()
        )
    })?;
    let reply = Client::new(stream)
        .extension(Extension {
            name: name.to_owned(),
            details: Unparsed::from(details),
        })
        .await
        .with_context(|| {
            format!(
                "the agent at {} refused; its log says why",
                socket.display()
            )
        })?
        .context("the agent answered without data")?;
    ensure!(reply.name == name, "the agent answered another request");
    Ok(reply.details.into_bytes())
}

/// Asks the agent to create an age identity on a security key. The agent
/// asks for the PIN, and the key for two touches. `another`: also on a
/// security key that holds an identity already.
///
/// # Errors
///
/// Returns an error if the agent can't be reached, refuses, or answers
/// something else than a recipient.
pub async fn age_new(socket: &Path, another: bool) -> Result<Recipient> {
    let details = age_request(socket, NEW_EXTENSION, wire::new_request(another)).await?;
    Ok(NewReply::decode(&details)?.recipient)
}

/// The age identities the agent knows: the recipient of each, where the
/// agent derived it on this machine already.
///
/// # Errors
///
/// Returns an error if the agent can't be reached, refuses, or answers
/// something else than a list.
pub async fn age_list(socket: &Path) -> Result<Vec<Option<Recipient>>> {
    let details = age_request(socket, LIST_EXTENSION, wire::simple_request()).await?;
    Ok(ListReply::decode(&details)?.identities)
}

/// The content of an identity file for `recipient`: what `age -d -i` takes
/// to decrypt through the agent, and `age -e -i` to encrypt without it. The
/// comment is for people and for tools that read the recipient from it.
#[must_use]
pub fn identity_file(recipient: &Recipient) -> String {
    format!(
        "# skagent age identity: no secret in here, the key is on a security key.\n\
         # Recipient: {recipient}\n\
         {}\n",
        Identity::Named(recipient.clone())
    )
}
