//! File descriptors crossing `exec`: the listening socket systemd passes in
//! (socket activation).
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Adopting a passed descriptor needs `unsafe`. It is confined to
// `activation.rs`, and every block there carries a SAFETY comment.
#![allow(unsafe_code)]

mod activation;

pub use activation::{activated_listener, check_listener, passed_sockets};
