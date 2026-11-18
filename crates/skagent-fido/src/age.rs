//! The credential an age identity is derived from. FIDO2 has no decryption;
//! the hmac-secret extension gives a secret that never changes, and the
//! agent derives the identity's private key from it (`docs/age.md`).
//!
//! One credential per identity: discoverable, so a load finds it on any
//! machine; credProtect 3, so the key denies it exists without the PIN; and
//! with hmac-secret. Deriving always asks for a touch. Security keys refuse
//! the extension without one, and nothing here ever asks for that.
//!
//! The relying party `skagent:age` isn't `ssh:…`, so OpenSSH's tools and the
//! SSH side of `skagent load` leave these credentials alone, and it is no web
//! origin, so no browser can use them.

use std::ffi::CStr;
use std::fmt;

use anyhow::{Context as _, Result, bail, ensure};
use libfido2_sys as sys;
use skagent_secret::SecretBuffer;

use crate::error::ErrorKind;
use crate::{Device, Statement, nul_terminated_pin, raw};

/// The relying party of age credentials.
pub const AGE_RP_ID: &str = "skagent:age";
const AGE_RP_ID_C: &CStr = c"skagent:age";
const AGE_RP_NAME: &CStr = c"skagent";
const AGE_USER_NAME: &CStr = c"skagent age";

/// Bytes of a user id, which tells the credentials of one key apart.
pub const AGE_USER_ID_BYTES: usize = 16;

/// Bytes a derivation returns: one HMAC-SHA-256 output.
pub const DERIVED_SECRET_BYTES: usize = 32;

/// The extensions a security key has to list to hold an age credential.
const NEEDED_EXTENSIONS: [&str; 2] = ["credProtect", "hmac-secret"];

/// An age credential on one security key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AgeCredential {
    id: Vec<u8>,
}

impl AgeCredential {
    /// A credential by its id, e.g. one remembered from an earlier listing.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is empty or longer than 1024 bytes.
    pub fn new(id: Vec<u8>) -> Result<Self> {
        ensure!(
            !id.is_empty() && id.len() <= 1024,
            "an age credential id must have 1 to 1024 bytes"
        );
        Ok(Self { id })
    }

    /// The credential id.
    #[must_use]
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl fmt::Debug for AgeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgeCredential")
            .field("id", &"<redacted>")
            .finish()
    }
}

impl Device {
    /// Checks that this key can hold an age credential: it lists the
    /// credProtect and hmac-secret extensions and has credential management.
    ///
    /// # Errors
    ///
    /// Returns an error that names what is missing, or one with a
    /// [`crate::FidoError`] inside if the key can't be asked.
    pub fn check_age_support(&mut self) -> Result<()> {
        let listed = self
            .inner
            .extensions()
            .with_context(|| format!("reading the extensions of {}", self.path))?;
        for needed in NEEDED_EXTENSIONS {
            if !listed.iter().any(|extension| extension == needed) {
                bail!(
                    "security key {} doesn't support {needed}, which an age identity needs",
                    self.path
                );
            }
        }
        if !self.inner.supports_credman() {
            bail!(
                "security key {} has no credential management, which an age identity needs",
                self.path
            );
        }
        Ok(())
    }

    /// The age credentials on this key, ordered by id. Credential management
    /// with `pin`; no touch. Credentials of the relying party that could be
    /// used without the PIN aren't ours and are left out.
    ///
    /// # Errors
    ///
    /// Returns an error if the key has no credential management, refuses the
    /// PIN, or the listing fails.
    pub fn age_credentials(&mut self, pin: &SecretBuffer) -> Result<Vec<AgeCredential>> {
        if !self.inner.supports_credman() {
            bail!(
                "security key {} has no credential management to list age credentials",
                self.path
            );
        }
        let terminated = nul_terminated_pin(pin)?;
        let pin = CStr::from_bytes_with_nul(terminated.expose())
            .context("the PIN contains a NUL byte")?;
        let keys = match self.inner.resident_keys(AGE_RP_ID_C, pin) {
            Ok(keys) => keys,
            Err(error) if error.kind() == ErrorKind::NoCredentials => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("listing age credentials on {}", self.path));
            }
        };
        let mut credentials = keys
            .into_iter()
            .filter(|key| key.protection == sys::FIDO_CRED_PROT_UV_REQUIRED)
            .map(|key| AgeCredential::new(key.key_handle))
            .collect::<Result<Vec<_>>>()?;
        credentials.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(credentials)
    }

    /// Creates an age credential on this key. Needs `pin` and a touch. A
    /// fresh `user_id` adds a credential; one that the key already has under
    /// this relying party would replace that credential and destroy the
    /// identity derived from it, so callers pass random bytes.
    ///
    /// The new credential is looked up again before it is returned, so the
    /// key is known to have stored it with credProtect 3.
    ///
    /// # Errors
    ///
    /// Returns an error if the key can't hold age credentials, refuses, or
    /// nobody touches it; see [`crate::error_kind`].
    pub fn create_age_credential(
        &mut self,
        user_id: &[u8; AGE_USER_ID_BYTES],
        pin: &SecretBuffer,
    ) -> Result<AgeCredential> {
        self.check_age_support()?;
        let terminated = nul_terminated_pin(pin)?;
        let c_pin = CStr::from_bytes_with_nul(terminated.expose())
            .context("the PIN contains a NUL byte")?;
        let mut credential = raw::Credential::new()?;
        credential.set_type_eddsa()?;
        credential.set_rp(AGE_RP_ID_C, AGE_RP_NAME)?;
        credential.set_user(user_id, AGE_USER_NAME)?;
        // Nothing to attest to anyone, and the credential never signs for us.
        credential.set_clientdata_hash(&[0; 32])?;
        credential.set_resident(raw::Opt::True)?;
        credential.set_protection_uv_required()?;
        credential.enable_hmac_secret()?;
        self.inner
            .make_cred(&mut credential, Some(c_pin))
            .with_context(|| format!("creating an age credential on {}", self.path))?;
        let created = AgeCredential::new(credential.id()?)?;
        if !self.age_credentials(pin)?.contains(&created) {
            bail!(
                "security key {} created an age credential, but doesn't list it as protected by \
                 the PIN; it is not used",
                self.path
            );
        }
        Ok(created)
    }

    /// Derives the secret of `credential` for `salt`: the key computes an
    /// HMAC-SHA-256 over the salt with a secret it keeps with the credential.
    /// The same salt gives the same secret, every time. Needs `pin` and a
    /// touch; blocks until touched or until the operation times out.
    ///
    /// # Errors
    ///
    /// Returns an error with a [`crate::FidoError`] inside if the key
    /// refuses, e.g. because it doesn't hold the credential; see
    /// [`crate::error_kind`]. An answer the key gave without a touch or
    /// without verifying the PIN is refused too.
    pub fn derive(
        &mut self,
        credential: &AgeCredential,
        salt: &[u8; 32],
        pin: &SecretBuffer,
    ) -> Result<SecretBuffer> {
        let terminated = nul_terminated_pin(pin)?;
        let pin = CStr::from_bytes_with_nul(terminated.expose())
            .context("the PIN contains a NUL byte")?;

        let mut assertion = raw::Assertion::new()?;
        assertion.set_rp(&AGE_RP_ID_C.to_owned())?;
        // The signature isn't used: what counts comes back encrypted.
        assertion.set_clientdata_hash(&[0; 32])?;
        assertion.allow_credential(&credential.id)?;
        assertion.set_user_presence(raw::Opt::True)?;
        assertion.set_user_verification(raw::Opt::Omit)?;
        assertion.derive_with(salt)?;

        self.inner
            .get_assert(&mut assertion, Some(pin))
            .with_context(|| format!("deriving an age secret on {}", self.path))?;

        if assertion.count() != 1 {
            bail!(
                "{} returned {} assertions for one allowed credential",
                self.path,
                assertion.count()
            );
        }
        let Some((_, flags, _)) = assertion.statement(0) else {
            bail!("{} returned an assertion without a signature", self.path);
        };
        // Without verification a key may answer with another secret (CTAP 2.1
        // keeps one for either case), and without a touch it shouldn't answer
        // at all.
        ensure!(
            flags & Statement::USER_VERIFIED != 0,
            "{} derived a secret without verifying the PIN; it is not used",
            self.path
        );
        ensure!(
            flags & Statement::USER_PRESENT != 0,
            "{} derived a secret without a touch; it is not used",
            self.path
        );
        let secret = assertion
            .with_hmac_secret(0, SecretBuffer::from_slice)
            .with_context(|| format!("{} returned no secret for the age credential", self.path))?
            .context("keeping the derived secret in locked memory")?;
        ensure!(
            secret.len() == DERIVED_SECRET_BYTES,
            "{} derived a secret of {} bytes instead of {DERIVED_SECRET_BYTES}",
            self.path,
            secret.len()
        );
        Ok(secret)
    }
}
