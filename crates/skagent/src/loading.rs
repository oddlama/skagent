//! Resident loading stays inside the agent: no PIN crosses the agent socket.

use std::time::Instant;

use skagent_secret::SecretBuffer;

use crate::identities::SkIdentity;
use crate::routing::RoutedDevice;
use crate::signer::SigningTicket;

/// A successful authenticated enumeration, not yet committed to agent state.
/// Keeps the device locked until identity insertion and cache priming finish.
pub(crate) struct PreparedLoad {
    pub identities: Vec<SkIdentity>,
    pub pin: SecretBuffer,
    pub routed: RoutedDevice,
    pub retries: u32,
    pub accepted_at: Instant,
    pub ticket: SigningTicket,
}
