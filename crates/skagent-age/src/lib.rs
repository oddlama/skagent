//! age's post-quantum recipient for a key that is derived from a security
//! key (`docs/age.md`).
//!
//! Files are encrypted to age's native `mlkem768x25519` recipient
//! (`age1pq1…`), so nothing here defines a file format. This crate holds
//! what skagent and its plugin share to use it:
//!
//! - [`Recipient`] and [`Identity`]: the strings.
//! - [`Stanza`]: what a file header carries for one recipient, validated the
//!   way the age specification asks.
//! - [`Seed`]: the private side. It is derived from what a security key
//!   returns for [`batch_salt`], gives the recipient, and unwraps stanzas
//!   to the [`FileKey`].
//! - [`Recipient::wrap`]: the public side, for encrypting to an identity.
//! - [`wire`]: the messages between the agent and its plugin.
//!
//! Underneath are X-Wing (ML-KEM-768 and X25519, combined with SHA3-256) as
//! written down in [filippo.io/hpke-pq](https://filippo.io/hpke-pq), and the
//! base mode of HPKE (RFC 9180) with HKDF-SHA256 and ChaCha20Poly1305.
//!
//! No I/O, no randomness of its own and no `unsafe`. Secrets that outlive a
//! call are [`skagent_secret::SecretBuffer`]s; intermediate values are wiped
//! where this crate owns them. What `libcrux-ml-kem` and `x25519-dalek` keep
//! on the stack while they run isn't.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod encoding;
mod hpke;
mod identity;
mod recipient;
mod seed;
mod stanza;
pub mod wire;
mod xwing;

pub use identity::{Identity, PLUGIN_NAME};
pub use recipient::{RECIPIENT_BYTES, Recipient, WRAP_RANDOM_BYTES};
pub use seed::{
    BATCH_SALT_LABEL, DEVICE_OUTPUT_BYTES, FILE_KEY_BYTES, FileKey, SEED_BYTES, Seed, batch_salt,
};
pub use stanza::{BODY_BYTES, ENC_BYTES, STANZA_BYTES, STANZA_TYPE, Stanza};

/// The label a plugin reports for stanzas of this recipient type. age and
/// rage refuse to put them into one file with recipients that don't carry
/// it, which keeps a file from being only as strong as a classic recipient.
pub const POSTQUANTUM_LABEL: &str = "postquantum";
