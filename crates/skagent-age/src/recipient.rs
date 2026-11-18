//! The recipient: an X-Wing public key, written `age1pq1…`.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

use crate::seed::FileKey;
use crate::stanza::{BODY_BYTES, HPKE_INFO, Stanza};
use crate::{encoding, hpke, xwing};

/// Bytes of a recipient: the ML-KEM-768 encapsulation key (1184), then the
/// X25519 public key (32).
pub const RECIPIENT_BYTES: usize = xwing::PUBLIC_KEY_BYTES;

/// Bytes of randomness one [`Recipient::wrap`] takes.
pub const WRAP_RANDOM_BYTES: usize = xwing::ENCAPSULATION_RANDOM_BYTES;

/// What a recipient string starts with, before Bech32's separator.
const PREFIX: &str = "age1pq";

/// An age post-quantum recipient. Public.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Recipient {
    key: Box<[u8; RECIPIENT_BYTES]>,
}

impl Recipient {
    /// A recipient from its public key.
    ///
    /// # Errors
    ///
    /// Returns an error if `key` isn't [`RECIPIENT_BYTES`] long, its
    /// ML-KEM-768 part isn't a valid encapsulation key, or its X25519 part is
    /// a point of low order.
    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        let key: Box<[u8; RECIPIENT_BYTES]> =
            Box::<[u8]>::from(key).try_into().ok().with_context(|| {
                format!("a recipient has {RECIPIENT_BYTES} bytes, not {}", key.len())
            })?;
        xwing::check_public_key(&key).context("the recipient's public key")?;
        Ok(Self { key })
    }

    /// The public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RECIPIENT_BYTES] {
        &self.key
    }

    /// The start and the end of the recipient string, enough to tell one from
    /// another where 1959 characters don't fit: `age1pq1x34nzs…fzv49zc0k`.
    #[must_use]
    pub fn abbreviated(&self) -> String {
        let full = self.to_string();
        let head: String = full.chars().take(13).collect();
        let tail_start = full.chars().count().saturating_sub(9);
        let tail: String = full.chars().skip(tail_start).collect();
        format!("{head}…{tail}")
    }

    /// Wraps `file_key` for this recipient: the stanza stock age produces
    /// for it. `randomness` must be fresh for every stanza and come from the
    /// system's generator; it is as secret as the file key.
    ///
    /// # Errors
    ///
    /// Returns an error if a primitive refuses, which a valid recipient
    /// doesn't cause.
    pub fn wrap(&self, file_key: &FileKey, randomness: &[u8; WRAP_RANDOM_BYTES]) -> Result<Stanza> {
        let (enc, shared_secret) = xwing::encapsulate(&self.key, randomness)?;
        let body = Zeroizing::new(hpke::seal(&shared_secret, HPKE_INFO, file_key.expose())?);
        let body: [u8; BODY_BYTES] = body.as_slice().try_into().ok().with_context(|| {
            format!(
                "sealing a file key gave {} bytes, not {BODY_BYTES}",
                body.len()
            )
        })?;
        Ok(Stanza::new(enc, body))
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = encoding::encode(PREFIX, &*self.key).map_err(|_| fmt::Error)?;
        formatter.write_str(&encoded)
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Recipient({})", self.abbreviated())
    }
}

impl FromStr for Recipient {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let key = encoding::decode(PREFIX, text)
            .with_context(|| format!("not an age post-quantum recipient ({PREFIX}1…)"))?;
        Self::from_bytes(&key)
    }
}
