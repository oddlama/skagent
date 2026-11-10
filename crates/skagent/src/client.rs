//! Talking to a running agent, for `skagent forget`.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Unparsed};
use tokio::net::UnixStream;

use crate::agent::FORGET_PINS_EXTENSION;

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
