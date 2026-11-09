//! ssh-agent protocol handling.
//!
//! Every message without an explicit handler here is answered with `FAILURE`
//! by `ssh-agent-lib`'s default implementations. That includes signing and
//! adding keys until the identity store and the FIDO layer exist.

use async_trait::async_trait;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Identity;
use tokio::net::UnixStream;

use crate::socket::PeerCheckedListener;

/// Agent state shared by all connections.
#[derive(Debug, Clone, Default)]
pub struct SkAgent {}

impl Agent<PeerCheckedListener> for SkAgent {
    fn new_session(&mut self, _socket: &UnixStream) -> impl Session {
        AgentSession {}
    }
}

/// One client connection.
#[derive(Debug)]
pub struct AgentSession {}

#[async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(Vec::new())
    }
}
