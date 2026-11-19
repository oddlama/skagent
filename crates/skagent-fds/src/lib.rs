//! File descriptors the agent gets from elsewhere, or must keep to itself:
//! the listening sockets systemd passes in (socket activation), the ones
//! spawned programs must not get, and a pidfd of whoever connected.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Adopting a passed descriptor, a pre-exec hook and a socket option rustix
// doesn't have need `unsafe`. Only `activation.rs`, `children.rs` and
// `peer.rs` may use it (the workspace denies it everywhere else), every
// block holds one operation and carries a SAFETY comment (clippy enforces
// both).
#[allow(unsafe_code)]
mod activation;
#[allow(unsafe_code)]
mod children;
#[allow(unsafe_code)]
mod peer;

pub use activation::{
    MAX_PASSED_SOCKETS, Passed, activated_listeners, check_listener, passed_names, passed_sockets,
};
pub use children::inherit_stdio_only;
pub use peer::{has_exited, peer_pidfd};
