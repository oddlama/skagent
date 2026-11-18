//! Telling a security key from a device that claims to be it.
//!
//! The first time a PIN the user typed works on a security key and the key
//! signs with an SSH key it holds, skagent trusts it (trust on first use):
//! it finds its own pairing credential there (credential management with the
//! PIN, no touch), or creates one (a touch). The key's binding keeps that
//! credential's id and public key. Later, before a typed PIN goes to a device
//! that isn't the plug-in that last signed, the device has to sign a random
//! challenge with it, silently. A device that can't is refused, so a fake
//! claiming the YubiKey's serial never gets the PIN.
//!
//! One pairing credential protects every SSH key on its security key, and
//! it's discoverable: on another machine the first PIN finds it without a
//! touch.

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use signature::Verifier as _;
use skagent_fido::{PAIRING_RP_ID, PairingCredential, Statement};
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_agent_lib::ssh_key::{Algorithm, Signature};

/// What a device's answer to a pairing challenge showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// It holds the pairing credential: it's the paired key.
    Proven,
    /// It doesn't hold it, or signed wrongly: it isn't the paired key.
    Disproven,
    /// It couldn't be asked (busy, an error): ask again later.
    Unknown,
}

/// A fresh random challenge.
///
/// # Errors
///
/// Returns an error if the kernel's random source fails.
pub fn challenge() -> Result<[u8; 32]> {
    let mut challenge = [0_u8; 32];
    let mut filled = 0;
    while let Some(rest) = challenge.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        let read = rustix::rand::getrandom(rest, rustix::rand::GetRandomFlags::empty())
            .context("reading random bytes for a pairing challenge")?;
        filled = filled.saturating_add(read);
    }
    Ok(challenge)
}

/// Whether `statement` is `pairing`'s signature over `challenge`: Ed25519
/// over the authenticator data (relying party hash, flags, counter) and the
/// challenge, as FIDO assertions are signed. Authenticator data with
/// extensions doesn't verify: none were asked for.
#[must_use]
pub fn verify(pairing: &PairingCredential, challenge: &[u8; 32], statement: &Statement) -> bool {
    let Ok(signature) = Signature::new(Algorithm::Ed25519, statement.signature.clone()) else {
        return false;
    };
    // Relying party hash, flags, counter, challenge.
    let mut message = Vec::with_capacity(69);
    message.extend_from_slice(&Sha256::digest(PAIRING_RP_ID.as_bytes()));
    message.push(statement.flags);
    message.extend_from_slice(&statement.counter.to_be_bytes());
    message.extend_from_slice(challenge);
    KeyData::Ed25519(Ed25519PublicKey(pairing.public_key))
        .verify(&message, &signature)
        .is_ok()
}
