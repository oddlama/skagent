//! Talking to a running agent, for `skagent forget` and `skagent load`.

use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Unparsed};
use tokio::net::UnixStream;

use crate::agent::{FORGET_PINS_EXTENSION, LOAD_KEYS_EXTENSION};

/// Asks the agent to select a device, prompt and load its resident SSH keys.
/// No PIN or credential handle is carried by this request/reply.
///
/// # Errors
/// Refuses an unreachable agent, failed loading or malformed extension reply.
pub async fn load_keys(socket: &Path) -> Result<u32> {
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

/// Validates the loading extension's reply before reporting success.
///
/// # Errors
/// Refuses an unexpected extension name or payload length.
pub fn decode_loaded_count(reply: &Extension) -> Result<u32> {
    ensure!(
        reply.name == LOAD_KEYS_EXTENSION,
        "unexpected resident-loading reply name"
    );
    let bytes: [u8; 4] = reply
        .details
        .as_ref()
        .try_into()
        .context("resident-loading reply must contain a u32 count")?;
    Ok(u32::from_be_bytes(bytes))
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
