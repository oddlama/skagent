//! The raw memory mapping behind a `SecretBuffer`. All `unsafe` of the
//! crate lives here.

use std::ffi::c_void;
use std::ops::Range;
use std::ptr::{self, NonNull};

use anyhow::{Context as _, Result, anyhow};
use rustix::mm::{
    Advice, MapFlags, MprotectFlags, ProtFlags, madvise, mlock, mmap_anonymous, mprotect, munlock,
    munmap,
};
use rustix::param::page_size;
use zeroize::Zeroize as _;

/// Locked data pages between two guard pages, owned exclusively.
///
/// Invariants, established by [`LockedPages::allocate`] and kept until drop:
/// - `base..base + total_len` is one anonymous private mapping owned by this value.
/// - `data = base + page`, `data..data + data_len` is readable, writable and locked.
/// - the first and last page of the mapping are `PROT_NONE`.
pub(crate) struct LockedPages {
    base: NonNull<c_void>,
    total_len: usize,
    data: NonNull<u8>,
    data_len: usize,
}

// SAFETY: `LockedPages` exclusively owns its mapping; nothing else holds the
// pointers. Shared access only reads (`as_slice`), mutation requires `&mut`.
// So moving it to or sharing it with another thread is as safe as for a `Vec<u8>`.
unsafe impl Send for LockedPages {}
// SAFETY: see `Send`. `&LockedPages` only allows reads.
unsafe impl Sync for LockedPages {}

impl LockedPages {
    /// Maps, protects, locks and advises pages for at least `capacity` bytes.
    pub(crate) fn allocate(capacity: usize) -> Result<Self> {
        let page = page_size();
        let data_len = capacity.div_ceil(page).checked_mul(page).ok_or_else(|| {
            anyhow!("secret capacity of {capacity} bytes overflows when rounded to pages")
        })?;
        let total_len = page
            .checked_mul(2)
            .and_then(|guards| guards.checked_add(data_len))
            .ok_or_else(|| {
                anyhow!("secret capacity of {capacity} bytes overflows with guard pages")
            })?;

        // SAFETY: a fresh anonymous private mapping at a kernel-chosen address
        // (null hint, no MAP_FIXED) can't alias or replace any existing memory.
        let base = unsafe {
            mmap_anonymous(
                ptr::null_mut(),
                total_len,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
        }
        .with_context(|| format!("mapping {total_len} bytes for a secret buffer"))?;
        let base = NonNull::new(base)
            .ok_or_else(|| anyhow!("mmap returned a null mapping for a secret buffer"))?;
        // From here on the mapping is owned; `Unmap` releases it on any early return.
        let unmap = Unmap { base, total_len };

        // SAFETY: `page < total_len`, so the result stays inside the mapping.
        let data = unsafe { base.cast::<u8>().add(page) };

        // SAFETY: `data..data + data_len` lies inside the mapping we own, and
        // nothing references it yet.
        unsafe {
            mprotect(
                data.as_ptr().cast(),
                data_len,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
        }
        .context("making secret buffer pages readable and writable")?;
        // SAFETY: same range, inside our mapping.
        unsafe { mlock(data.as_ptr().cast(), data_len) }.with_context(|| {
            format!(
                "locking {data_len} bytes of secret memory into RAM (is RLIMIT_MEMLOCK exhausted?)"
            )
        })?;
        // SAFETY: advice on a range inside our mapping; neither advice changes
        // what the memory contains for this process.
        unsafe { madvise(data.as_ptr().cast(), data_len, Advice::LinuxDontDump) }
            .context("excluding secret memory from core dumps (MADV_DONTDUMP)")?;
        // SAFETY: as above.
        unsafe { madvise(data.as_ptr().cast(), data_len, Advice::LinuxWipeOnFork) }
            .context("wiping secret memory in forked children (MADV_WIPEONFORK)")?;

        std::mem::forget(unmap);
        Ok(Self {
            base,
            total_len,
            data,
            data_len,
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: by the type invariants the range is mapped readable, owned
        // by `self` and lives as long as `self`; `&self` excludes writers.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.data_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` makes this the only reference.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len) }
    }

    pub(crate) fn zeroize(&mut self) {
        // Volatile writes the compiler can't elide.
        self.as_mut_slice().zeroize();
    }

    pub(crate) fn data_range(&self) -> Range<usize> {
        let start = self.data.as_ptr().addr();
        start..start.saturating_add(self.data_len)
    }
}

impl Drop for LockedPages {
    fn drop(&mut self) {
        self.zeroize();
        // SAFETY: the range is the locked part of our own mapping. Unlocking
        // can't fail in a way that matters here: the content is already zero
        // and the mapping is released right after.
        let _unlocked = unsafe { munlock(self.data.as_ptr().cast(), self.data_len) };
        drop(Unmap {
            base: self.base,
            total_len: self.total_len,
        });
    }
}

/// Releases a mapping on drop. Used for cleanup on early returns in
/// [`LockedPages::allocate`] and for the final release.
struct Unmap {
    base: NonNull<c_void>,
    total_len: usize,
}

impl Drop for Unmap {
    fn drop(&mut self) {
        // SAFETY: `base..base + total_len` is a mapping we own and nothing
        // references it any more. A failing munmap leaves the (zeroed or never
        // written) pages mapped; there is nothing better to do in a destructor.
        let _unmapped = unsafe { munmap(self.base.as_ptr(), self.total_len) };
    }
}
