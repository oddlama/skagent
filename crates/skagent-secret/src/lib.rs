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
//! - **`MADV_DONTDUMP`**: left out of core dumps, in addition to the
//!   process's `RLIMIT_CORE=0` ([`harden_process`]).
//! - **`MADV_WIPEONFORK`**: a forked child (e.g. before `exec`ing pinentry)
//!   sees zeros instead of the secret.
//! - **Guard pages**: an overflow faults instead of silently reading or writing
//!   neighboring memory.
//! - **Zeroization**: volatile writes on [`SecretBuffer::clear`] and on drop.
//!
//! Allocation fails closed. If any step fails, e.g. because `RLIMIT_MEMLOCK`
//! is exhausted, no buffer is returned.
//!
//! [`use_secretmem`] switches a process to `memfd_secret(2)` pages instead:
//! they are also removed from the kernel's direct map, so neither the kernel
//! nor a kernel exploit reading through it sees the secret. Forked children
//! don't get the pages at all (`MADV_DONTFORK`; `MADV_WIPEONFORK` needs
//! private memory). The catch: the kernel refuses to hibernate while any
//! such memory exists, hence opt-in.
//!
//! A single secret that is worth it, and that is gone before the machine
//! sleeps, can live there whatever the process chose:
//! [`SecretBuffer::from_slice_in`] with [`strongest_backend`].
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Raw memory mappings need `unsafe`. Only `mapping.rs` may use it (the
// workspace denies it everywhere else), every block holds one operation and
// carries a SAFETY comment (clippy enforces both).

#[allow(unsafe_code)]
mod mapping;
mod process;

use std::fmt;
use std::ops::Range;
use std::sync::OnceLock;

use anyhow::{Context as _, Result, bail, ensure};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::mapping::LockedPages;
pub use crate::process::{disable_core_dumps, harden_process};

/// Where a process keeps its secret buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Anonymous memory: locked, not dumped, wiped in forked children.
    Locked,
    /// `memfd_secret(2)` memory: also gone from the kernel's direct map,
    /// absent in forked children; blocks hibernation while any exists.
    Secretmem,
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

/// The backend of this process. Fixed by the first buffer, or by
/// [`use_secretmem`] before it.
#[must_use]
pub fn backend() -> Backend {
    *BACKEND.get_or_init(|| Backend::Locked)
}

/// Puts every secret buffer of this process into `memfd_secret(2)` memory.
/// Call it before the first buffer is allocated; calling it again is fine.
///
/// # Errors
///
/// Returns an error if the kernel doesn't provide such memory (probed with a
/// test allocation), or if buffers were allocated in locked memory already.
pub fn use_secretmem() -> Result<()> {
    drop(
        LockedPages::allocate(1, Backend::Secretmem)
            .context("memfd_secret memory isn't available on this system")?,
    );
    let chosen = *BACKEND.get_or_init(|| Backend::Secretmem);
    ensure!(
        chosen == Backend::Secretmem,
        "secret buffers were already allocated in locked memory; choose memfd_secret before the first one"
    );
    Ok(())
}

/// Whether the kernel provides `memfd_secret(2)` memory, probed once.
#[must_use]
pub fn secretmem_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| LockedPages::allocate(1, Backend::Secretmem).is_ok())
}

/// The backend that hides a secret best on this system: `memfd_secret(2)`
/// memory if the kernel provides it, else locked memory.
#[must_use]
pub fn strongest_backend() -> Backend {
    if secretmem_available() {
        Backend::Secretmem
    } else {
        Backend::Locked
    }
}

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
        Self::with_capacity_in(capacity, backend())
    }

    /// [`SecretBuffer::with_capacity`] in memory of `backend`, whatever the
    /// process keeps its other secrets in. Doesn't fix the process's backend.
    ///
    /// # Errors
    ///
    /// Returns an error if `capacity` is zero, or the memory can't be had,
    /// e.g. because the kernel has no `memfd_secret(2)`.
    pub fn with_capacity_in(capacity: usize, backend: Backend) -> Result<Self> {
        if capacity == 0 {
            bail!("a secret buffer needs a capacity of at least one byte");
        }
        Ok(Self {
            pages: LockedPages::allocate(capacity, backend)?,
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

    /// [`SecretBuffer::from_slice`] in memory of `backend`, see
    /// [`SecretBuffer::with_capacity_in`].
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is empty or the allocation fails.
    pub fn from_slice_in(bytes: &[u8], backend: Backend) -> Result<Self> {
        let mut buffer = Self::with_capacity_in(bytes.len(), backend)?;
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

    /// Keeps the first `len` bytes and zeroizes the rest. Does nothing if
    /// `len` isn't shorter than the content.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        if let Some(cut) = self.pages.as_mut_slice().get_mut(len..self.len) {
            cut.zeroize();
        }
        self.len = len;
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
