//! The `mlkem768x25519` recipient stanza of an age header.

use std::fmt;

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::xwing;

/// The first argument of a stanza of this recipient type.
pub const STANZA_TYPE: &str = "mlkem768x25519";

/// Bytes of the encapsulated key `enc`, the stanza's second argument.
pub const ENC_BYTES: usize = xwing::CIPHERTEXT_BYTES;

/// Bytes of the stanza's body: the 16-byte file key and the 16-byte tag.
pub const BODY_BYTES: usize = 32;

/// Bytes of a stanza as skagent's plugin sends it to the agent: `enc`, then
/// the body.
pub const STANZA_BYTES: usize = ENC_BYTES + BODY_BYTES;

/// HPKE's `info` for this recipient type.
pub(crate) const HPKE_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

/// One `mlkem768x25519` stanza: a file key, wrapped for one recipient.
/// Nothing in it is secret, and it doesn't say whose it is.
#[derive(Clone, PartialEq, Eq)]
pub struct Stanza {
    enc: Box<[u8; ENC_BYTES]>,
    body: [u8; BODY_BYTES],
}

impl Stanza {
    /// A stanza as a header holds it: its arguments, the type first, and its
    /// decoded body. `None` for a stanza of another type, which an identity
    /// has to ignore.
    ///
    /// # Errors
    ///
    /// Returns an error for a stanza of this type that the age specification
    /// rejects: more or fewer than two arguments, an `enc` that isn't the
    /// canonical base64 of 1120 bytes, or a body that isn't 32 bytes (checked
    /// before any decryption, against partitioning oracles). An `enc` whose
    /// X25519 part is a point of low order is rejected too.
    pub fn from_header<A: AsRef<str>>(arguments: &[A], body: &[u8]) -> Result<Option<Self>> {
        let Some((kind, rest)) = arguments.split_first() else {
            bail!("a stanza without a type");
        };
        if kind.as_ref() != STANZA_TYPE {
            return Ok(None);
        }
        let [enc] = rest else {
            bail!(
                "a {STANZA_TYPE} stanza has one argument after its type, not {}",
                rest.len()
            );
        };
        let enc = STANDARD_NO_PAD
            .decode(enc.as_ref())
            .ok()
            .context("the argument of a {STANZA_TYPE} stanza isn't canonical base64")?;
        Self::from_parts(&enc, body).map(Some)
    }

    /// A stanza from its `enc` and its body.
    ///
    /// # Errors
    ///
    /// Returns an error if either has the wrong length, or `enc` has an
    /// X25519 part of low order.
    pub fn from_parts(enc: &[u8], body: &[u8]) -> Result<Self> {
        let enc: Box<[u8; ENC_BYTES]> =
            Box::<[u8]>::from(enc).try_into().ok().with_context(|| {
                format!(
                    "the encapsulated key of a {STANZA_TYPE} stanza has {} bytes, not {ENC_BYTES}",
                    enc.len()
                )
            })?;
        let body: [u8; BODY_BYTES] = body.try_into().ok().with_context(|| {
            format!(
                "the body of a {STANZA_TYPE} stanza has {} bytes, not {BODY_BYTES}",
                body.len()
            )
        })?;
        xwing::check_ciphertext(&enc)
            .with_context(|| format!("the encapsulated key of a {STANZA_TYPE} stanza"))?;
        Ok(Self { enc, body })
    }

    /// A stanza from [`Stanza::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` isn't [`STANZA_BYTES`] long, or holds a
    /// stanza [`Stanza::from_parts`] refuses.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == STANZA_BYTES,
            "a {STANZA_TYPE} stanza takes {STANZA_BYTES} bytes, not {}",
            bytes.len()
        );
        let (enc, body) = bytes
            .split_at_checked(ENC_BYTES)
            .context("a stanza shorter than its encapsulated key")?;
        Self::from_parts(enc, body)
    }

    /// `enc`, then the body: [`STANZA_BYTES`] bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STANZA_BYTES);
        bytes.extend_from_slice(&*self.enc);
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// The stanza's second argument: `enc` in base64, as a header holds it.
    #[must_use]
    pub fn enc_argument(&self) -> String {
        STANDARD_NO_PAD.encode(self.enc.as_slice())
    }

    /// The encapsulated key.
    #[must_use]
    pub fn enc(&self) -> &[u8; ENC_BYTES] {
        &self.enc
    }

    /// The body: the wrapped file key.
    #[must_use]
    pub fn body(&self) -> &[u8; BODY_BYTES] {
        &self.body
    }

    pub(crate) fn new(enc: Box<[u8; ENC_BYTES]>, body: [u8; BODY_BYTES]) -> Self {
        Self { enc, body }
    }
}

impl fmt::Debug for Stanza {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 1152 bytes of ciphertext help nobody in a log.
        formatter
            .debug_struct("Stanza")
            .field("type", &STANZA_TYPE)
            .finish_non_exhaustive()
    }
}
