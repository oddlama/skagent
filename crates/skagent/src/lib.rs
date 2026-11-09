//! skagent: an ssh-agent for FIDO2 (`sk-ssh-ed25519@openssh.com`) keys that
//! caches the FIDO2 PIN for a bounded time while the authenticator still
//! requires a touch for every signature.
//!
//! See `docs/design.md` for the architecture and the caching rules.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod agent;
pub mod cli;
pub mod hardening;
pub mod logging;
pub mod output;
pub mod serve;
pub mod socket;
