//! File descriptors crossing `exec`: the listening socket systemd passes in
//! (socket activation), and the ones spawned programs must not get.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Adopting a passed descriptor and a pre-exec hook need `unsafe`. Only
// `activation.rs` and `children.rs` may use it (the workspace denies it
// everywhere else), every block holds one operation and carries a SAFETY
// comment (clippy enforces both).
#[allow(unsafe_code)]
mod activation;
#[allow(unsafe_code)]
mod children;

pub use activation::{activated_listener, check_listener, passed_sockets};
pub use children::inherit_stdio_only;
