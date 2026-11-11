//! File descriptors crossing `exec`: the listening socket systemd passes in
//! (socket activation), and the ones spawned programs must not get.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Adopting a passed descriptor and a pre-exec hook need `unsafe`. It is
// confined to `activation.rs` and `children.rs`, and every block there
// carries a SAFETY comment.
#![allow(unsafe_code)]

mod activation;
mod children;

pub use activation::{activated_listener, check_listener, passed_sockets};
pub use children::inherit_stdio_only;
