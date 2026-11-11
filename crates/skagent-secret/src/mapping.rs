//! The raw memory mapping behind a `SecretBuffer`. All `unsafe` of the
//! crate lives here.

use std::ffi::{c_int, c_void};
use std::ops::Range;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::ptr::{self, NonNull};

use anyhow::{Context as _, Result, anyhow, ensure};
use rustix::mm::{
    Advice, MapFlags, MprotectFlags, ProtFlags, madvise, mlock, mmap, mmap_anonymous, mprotect,
    munlock, munmap,
};
use rustix::param::page_size;
use zeroize::Zeroize as _;

use crate::Backend;

/// Locked data pages between two guard pages, owned exclusively.
///
/// Invariants, established by [`LockedPages::allocate`] and kept until drop:
/// - `base..base + total_len` is a mapping owned by this value: anonymous and
///   private, with the data pages replaced by a `memfd_secret` file mapping
///   for [`Backend::Secretmem`].
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
    pub(crate) fn allocate(capacity: usize, backend: Backend) -> Result<Self> {
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

        match backend {
            // SAFETY: `data..data + data_len` lies inside the mapping we own,
            // and nothing references it yet.
            Backend::Locked => unsafe {
                mprotect(
                    data.as_ptr().cast(),
                    data_len,
                    MprotectFlags::READ | MprotectFlags::WRITE,
                )
            }
            .context("making secret buffer pages readable and writable")?,
            Backend::Secretmem => map_secretmem(data, data_len)?,
        }
        // memfd_secret pages are never swapped: the kernel marks their
        // mapping unevictable (mm/secretmem.c) and charges them against
        // RLIMIT_MEMLOCK when they are mapped. mlock would try to fault them
        // in through get_user_pages, which the kernel refuses for secretmem,
        // and fail with ENOMEM.
        if backend == Backend::Locked {
            // SAFETY: same range, inside our mapping.
            unsafe { mlock(data.as_ptr().cast(), data_len) }.with_context(|| {
                format!(
                    "locking {data_len} bytes of secret memory into RAM (is RLIMIT_MEMLOCK exhausted?)"
                )
            })?;
        }
        // SAFETY: advice on a range inside our mapping; neither advice changes
        // what the memory contains for this process.
        unsafe { madvise(data.as_ptr().cast(), data_len, Advice::LinuxDontDump) }
            .context("excluding secret memory from core dumps (MADV_DONTDUMP)")?;
        let (fork_advice, fork_step) = match backend {
            Backend::Locked => (
                Advice::LinuxWipeOnFork,
                "wiping secret memory in forked children (MADV_WIPEONFORK)",
            ),
            // WIPEONFORK only works on private anonymous memory; a shared
            // mapping is kept from forked children altogether.
            Backend::Secretmem => (
                Advice::LinuxDontFork,
                "keeping secret memory from forked children (MADV_DONTFORK)",
            ),
        };
        // SAFETY: as above.
        unsafe { madvise(data.as_ptr().cast(), data_len, fork_advice) }.context(fork_step)?;

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

/// Replaces `data..data + data_len`, part of a `PROT_NONE` reservation owned
/// by the caller, with readable and writable `memfd_secret(2)` pages: they
/// are also removed from the kernel's direct map.
fn map_secretmem(data: NonNull<u8>, data_len: usize) -> Result<()> {
    // SAFETY: memfd_secret takes a flags integer and returns a new file
    // descriptor or -1; no memory is passed to the kernel.
    let raw = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context(
            "creating memfd_secret memory (needs Linux 5.14 or later; off by default before 6.5)",
        );
    }
    let raw = c_int::try_from(raw).context("memfd_secret returned an out-of-range descriptor")?;
    // SAFETY: `raw` was just returned by the kernel and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let len = u64::try_from(data_len).context("secret buffer size doesn't fit a file size")?;
    rustix::fs::ftruncate(&fd, len).context("sizing memfd_secret memory")?;
    // SAFETY: `data..data + data_len` lies inside the reservation the caller
    // owns and nothing references it yet. MAP_FIXED replaces exactly those
    // pages with the secret file's; the guard pages around them stay.
    let mapped = unsafe {
        mmap(
            data.as_ptr().cast(),
            data_len,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED | MapFlags::FIXED,
            &fd,
            0,
        )
    }
    .context("mapping memfd_secret memory")?;
    ensure!(
        mapped == data.as_ptr().cast::<c_void>(),
        "memfd_secret memory was mapped at another address"
    );
    // The mapping keeps the memory alive; the descriptor isn't needed.
    Ok(())
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
