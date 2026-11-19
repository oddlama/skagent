//! The private side: the seed an identity's key pair expands from, and the
//! file key it unwraps.

use std::fmt;

use anyhow::{Context as _, Result, anyhow, ensure};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use skagent_secret::{Backend, SecretBuffer};
use zeroize::Zeroizing;

use crate::recipient::Recipient;
use crate::stanza::{HPKE_INFO, Stanza};
use crate::{hpke, xwing};

/// Bytes of a seed: an X-Wing private key, what an `AGE-SECRET-KEY-PQ-1…`
/// identity holds.
pub const SEED_BYTES: usize = xwing::SEED_BYTES;

/// Bytes a security key returns for one salt (HMAC-SHA-256).
pub const DEVICE_OUTPUT_BYTES: usize = 32;

/// Bytes of an age file key.
pub const FILE_KEY_BYTES: usize = 16;

/// What the salt of the identity that may be used in batches is the SHA-256
/// of. The salt decides which secret a security key returns, so an identity
/// with another policy (`skagent/age/v1/strict` is reserved for one that is
/// never kept) has an unrelated key.
pub const BATCH_SALT_LABEL: &str = "skagent/age/v1/batch";

/// HKDF's `info` on the way from the security key's answer to the seed. The
/// answer itself is never used as a key, and another scheme can derive its
/// own from it with another `info`.
const SEED_INFO: &[u8] = b"skagent/age/v1/mlkem768x25519";

/// The salt sent to the security key for the identity that may be used in
/// batches: `SHA-256(BATCH_SALT_LABEL)`.
#[must_use]
pub fn batch_salt() -> [u8; 32] {
    Sha256::digest(BATCH_SALT_LABEL.as_bytes()).into()
}

/// The seed of an identity: its whole private key. Lives in locked memory
/// and is wiped when dropped.
pub struct Seed(SecretBuffer);

impl Seed {
    /// The seed for what the security key returned:
    /// `HKDF-SHA-256(ikm = output, salt = "", info = "skagent/age/v1/mlkem768x25519")`.
    ///
    /// # Errors
    ///
    /// Returns an error if `output` isn't [`DEVICE_OUTPUT_BYTES`] long, or
    /// locked memory can't be had.
    pub fn from_device_output(output: &SecretBuffer) -> Result<Self> {
        ensure!(
            output.len() == DEVICE_OUTPUT_BYTES,
            "a security key's answer has {DEVICE_OUTPUT_BYTES} bytes, not {}",
            output.len()
        );
        let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
        Hkdf::<Sha256>::new(None, output.expose())
            .expand(SEED_INFO, &mut *seed)
            .map_err(|error| anyhow!("deriving the seed: {error}"))?;
        Self::from_bytes(&*seed)
    }

    /// A seed from its bytes, e.g. the data of an `AGE-SECRET-KEY-PQ-1…`
    /// identity. The caller wipes `bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` isn't [`SEED_BYTES`] long, or locked
    /// memory can't be had.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == SEED_BYTES,
            "a seed has {SEED_BYTES} bytes, not {}",
            bytes.len()
        );
        SecretBuffer::from_slice(bytes)
            .map(Self)
            .context("keeping the seed in locked memory")
    }

    /// A copy of the seed in memory of `backend`, for a seed that is kept
    /// longer than one decryption.
    ///
    /// # Errors
    ///
    /// Returns an error if that memory can't be had.
    pub fn copy_in(&self, backend: Backend) -> Result<Self> {
        SecretBuffer::from_slice_in(self.0.expose(), backend)
            .map(Self)
            .context("keeping the seed in protected memory")
    }

    fn expand(&self) -> Result<xwing::ExpandedKey> {
        let seed: &[u8; SEED_BYTES] = self
            .0
            .expose()
            .try_into()
            .context("the seed lost its length")?;
        xwing::ExpandedKey::expand(seed)
    }

    /// The recipient that files for this identity are encrypted to.
    ///
    /// # Errors
    ///
    /// Returns an error if the expansion fails, which no seed causes.
    pub fn recipient(&self) -> Result<Recipient> {
        Recipient::from_bytes(&*self.expand()?.public_key()?)
    }

    /// The file key of the first of `stanzas` that is for this identity, or
    /// `None` if none is. All stanzas of one file wrap the same file key, so
    /// stopping at the first keeps one call from opening several files.
    ///
    /// # Errors
    ///
    /// Returns an error if a primitive refuses or locked memory can't be
    /// had. A stanza for someone else is not an error.
    pub fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<FileKey>> {
        let key = self.expand()?;
        for stanza in stanzas {
            let shared_secret = key.decapsulate(stanza.enc())?;
            if let Some(file_key) = hpke::open(&shared_secret, HPKE_INFO, stanza.body())? {
                return FileKey::from_bytes(&file_key).map(Some);
            }
        }
        Ok(None)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Seed(<redacted>)")
    }
}

/// The key of one file's payload. Lives in locked memory and is wiped when
/// dropped.
pub struct FileKey(SecretBuffer);

impl FileKey {
    /// A file key from its bytes. The caller wipes `bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` isn't [`FILE_KEY_BYTES`] long, or locked
    /// memory can't be had.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == FILE_KEY_BYTES,
            "a file key has {FILE_KEY_BYTES} bytes, not {}",
            bytes.len()
        );
        SecretBuffer::from_slice(bytes)
            .map(Self)
            .context("keeping the file key in locked memory")
    }

    /// The file key.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for FileKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileKey(<redacted>)")
    }
}
