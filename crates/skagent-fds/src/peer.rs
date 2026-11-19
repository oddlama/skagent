//! A handle on the process at the other end of a unix socket connection.
//!
//! `SO_PEERCRED` gives the peer's pid, a number the kernel hands to another
//! process once this one is gone. `SO_PEERPIDFD` (Linux 6.5) gives a pidfd:
//! it refers to that one process for as long as it is open, so what was read
//! about the pid can be checked to have been about the peer.

use std::io;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

use anyhow::{Context as _, Result, bail, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

/// A pidfd of the process that connected `socket` (or created it, for a
/// socket pair), as the kernel recorded it then. `None` if the kernel
/// doesn't know `SO_PEERPIDFD` (before Linux 6.5).
///
/// # Errors
///
/// Returns an error if `socket` isn't a connected unix socket, or the peer
/// is gone and reaped already.
pub fn peer_pidfd(socket: BorrowedFd<'_>) -> Result<Option<OwnedFd>> {
    let mut pidfd: libc::c_int = -1;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .context("the size of a descriptor doesn't fit socklen_t")?;
    // SAFETY: `socket` is an open descriptor for the duration of the call.
    // The kernel writes at most `length` bytes, the size of the `c_int` the
    // value pointer refers to, and the size it wrote to `length`; both live
    // on this stack frame.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &raw mut length,
        )
    };
    if status != 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            // An older kernel: the option doesn't exist.
            Some(libc::ENOPROTOOPT) => Ok(None),
            _ => Err(error).context("asking for a pidfd of the connection's peer (SO_PEERPIDFD)"),
        };
    }
    ensure!(
        usize::try_from(length).is_ok_and(|length| length == size_of::<libc::c_int>()),
        "SO_PEERPIDFD returned {length} bytes instead of a descriptor"
    );
    if pidfd < 0 {
        bail!("SO_PEERPIDFD returned no descriptor");
    }
    // SAFETY: the kernel just created this descriptor for us and returned its
    // number; nothing else owns it, and it is closed once, by the `OwnedFd`.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    // The kernel creates pidfds close-on-exec; the agent's prompts must not
    // get one whatever it does.
    let flags = fcntl_getfd(&pidfd).context("reading the pidfd's descriptor flags")?;
    fcntl_setfd(&pidfd, flags | FdFlags::CLOEXEC).context("marking the pidfd close-on-exec")?;
    Ok(Some(pidfd))
}

/// Whether the process behind `pidfd` has exited. While it hasn't, its pid
/// names no other process.
///
/// # Errors
///
/// Returns an error if `pidfd` can't be polled.
pub fn has_exited(pidfd: impl AsFd) -> Result<bool> {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    // Zero: don't wait.
    let ready = poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .context("polling a pidfd")?;
    Ok(ready > 0)
}
