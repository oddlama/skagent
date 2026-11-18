//! skagent's own credential on a security key: one per key, discoverable,
//! Ed25519, usable without user verification by its id (credProtect 2). The
//! agent stores its id and public key once it trusts the key, then has the
//! key sign a random challenge before it sends a PIN there: a device that
//! merely claims to be that key can't.
//!
//! The relying party `skagent:pairing` isn't `ssh:…`, so OpenSSH's tools and
//! `skagent load` leave the credential alone.

use std::ffi::CStr;

use anyhow::{Context as _, Result, bail};
use skagent_secret::SecretBuffer;

use crate::error::ErrorKind;
use crate::{AssertRequest, Device, Statement, nul_terminated_pin, raw};

/// The pairing credential's relying party.
pub const PAIRING_RP_ID: &str = "skagent:pairing";
const PAIRING_RP_ID_C: &CStr = c"skagent:pairing";
const PAIRING_RP_NAME: &CStr = c"skagent";
/// The same user every time: creating the credential again replaces the
/// key's old one instead of adding another.
const PAIRING_USER_ID: &[u8] = b"skagent";
const PAIRING_USER_NAME: &CStr = c"skagent pairing";

/// skagent's pairing credential on one security key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCredential {
    /// Credential id.
    pub id: Vec<u8>,
    /// Ed25519 public key.
    pub public_key: [u8; 32],
}

impl Device {
    /// skagent's pairing credential on this key, if there is one. Credential
    /// management with `pin`; no touch.
    ///
    /// # Errors
    ///
    /// Returns an error if the key has no credential management, refuses the
    /// PIN, or the listing fails. Only `Ok(None)` means there is none.
    pub fn find_pairing(&mut self, pin: &SecretBuffer) -> Result<Option<PairingCredential>> {
        if !self.inner.supports_credman() {
            bail!(
                "security key {} has no credential management to find its pairing",
                self.path
            );
        }
        let terminated = nul_terminated_pin(pin)?;
        let pin = CStr::from_bytes_with_nul(terminated.expose())
            .context("the PIN contains a NUL byte")?;
        let keys = match self.inner.resident_keys(PAIRING_RP_ID_C, pin) {
            Ok(keys) => keys,
            Err(error) if error.kind() == ErrorKind::NoCredentials => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("looking for skagent's pairing on {}", self.path));
            }
        };
        let mut pairings = keys
            .into_iter()
            .map(|key| pairing(key.key_handle, &key.public_key))
            .collect::<Result<Vec<_>>>()?;
        pairings.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(pairings.into_iter().next())
    }

    /// Creates skagent's pairing credential on this key, replacing an older
    /// one. Needs `pin` (it's discoverable) and a touch.
    ///
    /// # Errors
    ///
    /// Returns an error with a [`crate::FidoError`] inside if the key refuses or
    /// nobody touches it.
    pub fn create_pairing(&mut self, pin: &SecretBuffer) -> Result<PairingCredential> {
        let terminated = nul_terminated_pin(pin)?;
        let pin = CStr::from_bytes_with_nul(terminated.expose())
            .context("the PIN contains a NUL byte")?;
        let mut credential = raw::Credential::new()?;
        credential.set_type_eddsa()?;
        credential.set_rp(PAIRING_RP_ID_C, PAIRING_RP_NAME)?;
        credential.set_user(PAIRING_USER_ID, PAIRING_USER_NAME)?;
        // Nothing to attest to anyone: trust comes from the first use.
        credential.set_clientdata_hash(&[0; 32])?;
        credential.set_resident(raw::Opt::True)?;
        credential.set_protection_uv_optional_with_id()?;
        self.inner
            .make_cred(&mut credential, Some(pin))
            .with_context(|| format!("creating skagent's pairing on {}", self.path))?;
        pairing(credential.id()?, &credential.public_key()?)
    }

    /// Has the key sign `challenge` with `pairing`, silently: no touch, no
    /// PIN. The caller verifies the signature.
    ///
    /// # Errors
    ///
    /// Returns an error with a [`crate::FidoError`] inside if the key refuses,
    /// e.g. because it doesn't hold the credential.
    pub fn sign_challenge(
        &mut self,
        pairing: &PairingCredential,
        challenge: [u8; 32],
    ) -> Result<Statement> {
        self.assert(
            &AssertRequest {
                rp_id: PAIRING_RP_ID,
                client_data_hash: challenge,
                key_handle: &pairing.id,
                user_presence: false,
            },
            None,
        )
    }
}

fn pairing(id: Vec<u8>, public_key: &[u8]) -> Result<PairingCredential> {
    let public_key = public_key
        .try_into()
        .context("skagent's pairing must have a 32-byte Ed25519 public key")?;
    Ok(PairingCredential { id, public_key })
}
