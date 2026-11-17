//! Resident loading stays inside the agent: no PIN crosses the agent socket.

use std::time::Instant;

use skagent_popup::{SecurityKey, State};
use skagent_secret::SecretBuffer;

use crate::identities::SkIdentity;
use crate::popup::PopupSession;
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
    /// The popup this load was shown in, if any; dropping it lets the popup
    /// close.
    pub popup: Option<PopupSession>,
    /// The YubiKey loaded from, as the popup shows it.
    pub security_key: Option<SecurityKey>,
}

impl PreparedLoad {
    /// Shows in the popup that `count` keys were loaded.
    pub fn show_loaded(&mut self, count: u32) {
        if let Some(session) = self.popup.as_mut() {
            let state = State::Loaded {
                security_key: self.security_key.clone(),
                count,
            };
            if let Err(error) = session.show(state) {
                tracing::debug!(error = %format!("{error:#}"), "showing the result in the popup failed");
            }
        }
    }
}
