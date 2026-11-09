//! Locked, guarded, zeroizing memory for small secrets such as FIDO2 PINs.
//!
//! Every [`SecretBuffer`] is its own anonymous memory mapping:
//!
//! ```text
//! [ guard page, PROT_NONE ][ data pages, RW, mlock, DONTDUMP, WIPEONFORK ][ guard page, PROT_NONE ]
//! ```
//!
//! - **`mlock`**: the pages are never written to swap. Each buffer has its own
//!   mapping because `munlock` isn't reference counted: locking pages that
//!   are shared with unrelated heap data would let the first unlock expose
//!   the others.
//! - **`MADV_DONTDUMP`**: left out of core dumps, in addition to the agent's
//!   `RLIMIT_CORE=0`.
//! - **`MADV_WIPEONFORK`**: a forked child (e.g. before `exec`ing pinentry)
//!   sees zeros instead of the secret.
//! - **Guard pages**: an overflow faults instead of silently reading or writing
//!   neighboring memory.
//! - **Zeroization**: volatile writes on [`SecretBuffer::clear`] and on drop.
//!
//! Allocation fails closed. If any step fails, e.g. because `RLIMIT_MEMLOCK`
//! is exhausted, no buffer is returned.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Raw memory mappings need `unsafe`. It is confined to `mapping.rs`, and
// every block there carries a SAFETY comment.
#![allow(unsafe_code)]

mod mapping;

use std::fmt;
use std::ops::Range;

use anyhow::{Result, bail};
use subtle::ConstantTimeEq as _;

use crate::mapping::LockedPages;

/// Fixed-capacity byte buffer for a secret, backed by locked, guarded pages.
///
/// The content is only reachable through [`SecretBuffer::expose`].
/// `Debug` reveals nothing about it, not even its length. The buffer can't
/// be cloned, so every copy of a secret is an explicit, visible operation.
pub struct SecretBuffer {
    pages: LockedPages,
    capacity: usize,
    len: usize,
}

impl SecretBuffer {
    /// Allocates an empty buffer that holds up to `capacity` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `capacity` is zero, or if mapping, protecting,
    /// locking or advising the memory fails.
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            bail!("a secret buffer needs a capacity of at least one byte");
        }
        Ok(Self {
            pages: LockedPages::allocate(capacity)?,
            capacity,
            len: 0,
        })
    }

    /// Allocates a buffer of exactly `bytes.len()` capacity holding a copy of `bytes`.
    ///
    /// The caller is responsible for zeroizing `bytes` afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is empty or the allocation fails.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut buffer = Self::with_capacity(bytes.len())?;
        buffer.extend_from_slice(bytes)?;
        Ok(buffer)
    }

    /// Appends `bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error and leaves the buffer unchanged if the result would
    /// exceed the capacity.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(new_len) = self
            .len
            .checked_add(bytes.len())
            .filter(|&new_len| new_len <= self.capacity)
        else {
            bail!(
                "secret of {} more bytes doesn't fit, capacity is {} bytes",
                bytes.len(),
                self.capacity
            );
        };
        let Some(destination) = self.pages.as_mut_slice().get_mut(self.len..new_len) else {
            bail!(
                "secret buffer range {}..{} is outside its pages",
                self.len,
                new_len
            );
        };
        destination.copy_from_slice(bytes);
        self.len = new_len;
        Ok(())
    }

    /// The stored secret.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.pages.as_slice().get(..self.len).unwrap_or_default()
    }

    /// Number of bytes stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of bytes the buffer holds.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Zeroizes the content and empties the buffer. The memory stays allocated.
    pub fn clear(&mut self) {
        self.pages.zeroize();
        self.len = 0;
    }

    /// Compares the content with `other` in time independent of where they differ.
    ///
    /// The comparison does leak whether the lengths are equal.
    #[must_use]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        bool::from(self.expose().ct_eq(other))
    }

    /// Address range of the locked data pages.
    ///
    /// For diagnostics and tests, e.g. finding the mapping in `/proc/self/smaps`.
    #[must_use]
    pub fn data_pages(&self) -> Range<usize> {
        self.pages.data_range()
    }
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBuffer(<redacted>)")
    }
}
