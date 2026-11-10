//! Validated public metadata of an Ed25519 SSH resident credential.

use std::fmt;

use anyhow::{Context as _, Result, ensure};

/// A resident SSH credential. No private key is exported by the device.
#[derive(Clone, PartialEq, Eq)]
pub struct ResidentCredential {
    application: String,
    public_key: [u8; 32],
    key_handle: Vec<u8>,
    protection: u8,
    user_name: String,
}

impl ResidentCredential {
    /// Validates credential-management metadata before it becomes an identity.
    /// Protection 0 means the authenticator omitted the optional policy field.
    ///
    /// # Errors
    /// Refuses non-SSH RPs, invalid public keys/handles or unknown protection policies.
    pub fn new(
        application: String,
        public_key: &[u8],
        key_handle: Vec<u8>,
        protection: i32,
        user_name: String,
    ) -> Result<Self> {
        ensure!(
            application.starts_with("ssh:") && !application.contains('\0'),
            "resident credential is not an SSH relying party"
        );
        let public_key = public_key
            .try_into()
            .context("resident Ed25519 public key must have 32 bytes")?;
        ensure!(
            !key_handle.is_empty() && key_handle.len() <= 1024,
            "resident credential handle must have 1 to 1024 bytes"
        );
        let protection =
            u8::try_from(protection).context("invalid resident credential protection policy")?;
        ensure!(
            protection <= 3,
            "unknown resident credential protection policy {protection}"
        );
        Ok(Self {
            application,
            public_key,
            key_handle,
            protection,
            user_name,
        })
    }

    /// SSH relying party id, including the `ssh:` prefix.
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Raw Ed25519 public key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Credential id used in subsequent assertions.
    #[must_use]
    pub fn key_handle(&self) -> &[u8] {
        &self.key_handle
    }

    /// Whether the device enforces user verification (credProtect 3).
    #[must_use]
    pub fn requires_pin(&self) -> bool {
        self.protection == 3
    }

    /// Public user name stored at enrollment; the original SSH comment is not stored.
    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

impl fmt::Debug for ResidentCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentCredential")
            .field("application", &self.application)
            .field("protection", &self.protection)
            .field("user_name", &self.user_name)
            .field("key_handle_len", &self.key_handle.len())
            .finish_non_exhaustive()
    }
}
