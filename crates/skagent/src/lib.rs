//! skagent: an ssh-agent for FIDO2 (`sk-ssh-ed25519@openssh.com`) keys that
//! caches the FIDO2 PIN for a bounded time while the authenticator still
//! requires a touch for every signature.
//!
//! See `docs/design.md` for the architecture and the caching rules.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod agent;
pub mod cancel;
pub mod cli;
pub mod client;
pub mod destination;
pub mod device;
pub mod hardening;
pub mod identities;
mod loading;
pub mod logging;
pub mod logind;
pub mod output;
pub mod pin_cache;
pub mod pinentry;
pub mod prompt;
pub mod routing;
pub mod serve;
pub mod signer;
pub mod socket;
