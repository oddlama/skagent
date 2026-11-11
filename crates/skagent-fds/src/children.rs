//! Spawned programs get stdin, stdout and stderr, and nothing else.

use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// Makes the child of `command` close every descriptor above stderr when it
/// execs, whether or not it was opened close-on-exec.
///
/// Not every library sets the flag: libfido2 opens `/dev/hidraw*` without
/// it, so a PIN prompt spawned while a security key is open would inherit
/// the device. The child marks the descriptors (`close_range(2)` with
/// `CLOSE_RANGE_CLOEXEC`, Linux 5.11) instead of closing them, so the
/// standard library's own close-on-exec pipe still reports a failed exec.
/// It happens after fork, so threads of this process opening files at the
/// same time can't slip through. On older kernels spawning fails.
pub fn inherit_stdio_only(command: &mut Command) {
    // SAFETY: the hook runs in the forked child before exec, where only
    // async-signal-safe operations are allowed: `mark_inherited_cloexec`
    // makes one raw syscall and, on failure, reads errno. No allocation, no
    // locks.
    unsafe {
        command.pre_exec(mark_inherited_cloexec);
    }
}

/// Marks every descriptor above stderr close-on-exec.
fn mark_inherited_cloexec() -> std::io::Result<()> {
    // SAFETY: close_range with CLOSE_RANGE_CLOEXEC sets a flag on this
    // process's descriptors; no memory is passed to the kernel.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if marked == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
