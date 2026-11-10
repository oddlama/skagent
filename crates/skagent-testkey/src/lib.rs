//! A virtual FIDO2 security key on Linux uhid, for skagent's VM tests.
//!
//! Behaves like a YubiKey for what skagent cares about: EdDSA credentials,
//! resident keys, credProtect, a real client PIN with 8 retries, no built-in
//! user verification, and a touch for every credential creation and every
//! assertion that asks for user presence. Credentials live in memory only.
//!
//! Links soft-fido2, which is AGPL-3.0. This crate is test-only and must
//! never become a dependency of skagent itself.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod callbacks;
pub mod ctap;
pub mod touch;
