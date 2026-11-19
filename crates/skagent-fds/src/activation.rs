//! systemd socket activation (`sd_listen_fds(3)`): takes over the listening
//! unix socket systemd passed to this process.
//!
//! The protocol: systemd passes the sockets as file descriptors from 3 on,
//! `LISTEN_FDS` says how many, and `LISTEN_PID` names the process they are
//! meant for. A `LISTEN_PID` of another process (say, our parent) means
//! nothing was passed to us.
//!
//! The variables aren't unset: `std::env::remove_var` isn't thread safe.
//! Programs spawned with them see a `LISTEN_PID` that isn't theirs, which
//! makes them ignore the variables; the agent removes them anyway when it
//! spawns its prompts.

use std::ffi::OsStr;
use std::os::fd::{BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result, anyhow, ensure};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{socket_acceptconn, socket_domain, socket_type};
use rustix::net::{AddressFamily, SocketType};

/// The first passed descriptor (`SD_LISTEN_FDS_START`).
const FIRST_PASSED_FD: RawFd = 3;

/// Set once the passed socket has an owner, so it can't get a second one.
static TAKEN: AtomicBool = AtomicBool::new(false);

/// How many sockets systemd passed to the process `own_pid`, given the
/// values of `LISTEN_PID` and `LISTEN_FDS`. Zero if `LISTEN_PID` is unset or
/// names another process.
///
/// # Errors
///
/// Returns an error if `LISTEN_PID` isn't a process id, or if it names this
/// process and `LISTEN_FDS` is missing or not a count.
pub fn passed_sockets(
    own_pid: u32,
    listen_pid: Option<&OsStr>,
    listen_fds: Option<&OsStr>,
) -> Result<u32> {
    let Some(listen_pid) = listen_pid else {
        return Ok(0);
    };
    let listen_pid: u32 = listen_pid
        .to_str()
        .and_then(|pid| pid.parse().ok())
        .ok_or_else(|| anyhow!("LISTEN_PID={} is not a process id", listen_pid.display()))?;
    if listen_pid != own_pid {
        return Ok(0);
    }
    let listen_fds =
        listen_fds.context("LISTEN_PID names this process, but LISTEN_FDS is unset")?;
    listen_fds
        .to_str()
        .and_then(|count| count.parse().ok())
        .ok_or_else(|| anyhow!("LISTEN_FDS={} is not a count", listen_fds.display()))
}

/// Checks that `fd` is what an ssh-agent can serve on: a listening unix
/// stream socket.
///
/// # Errors
///
/// Returns an error if `fd` isn't a socket, or is one of another family or
/// type, or doesn't listen.
pub fn check_listener(fd: BorrowedFd<'_>) -> Result<()> {
    let family = socket_domain(fd).context("the passed descriptor is not a socket")?;
    ensure!(
        family == AddressFamily::UNIX,
        "the passed socket is not a unix socket"
    );
    let kind = socket_type(fd).context("reading the type of the passed socket")?;
    ensure!(
        kind == SocketType::STREAM,
        "the passed socket is not a stream socket (ListenStream=)"
    );
    let listening = socket_acceptconn(fd).context("reading whether the passed socket listens")?;
    ensure!(listening, "the passed socket doesn't listen");
    Ok(())
}

/// Most sockets the agent takes over: the ssh-agent socket and the one for
/// age requests.
pub const MAX_PASSED_SOCKETS: u32 = 2;

/// A listening socket systemd passed.
#[derive(Debug)]
pub struct Passed {
    /// Its name: `FileDescriptorName=` of the socket unit, else the unit's
    /// name. `None` if systemd named nothing.
    pub name: Option<String>,
    /// The socket: close on exec and non-blocking, ready for an async runtime.
    pub listener: UnixListener,
}

/// The names of `count` passed sockets from the value of `LISTEN_FDNAMES`
/// (`sd_listen_fds_with_names(3)`): one per socket, separated by colons.
///
/// # Errors
///
/// Returns an error if the variable names another number of sockets or
/// isn't UTF-8.
pub fn passed_names(listen_fdnames: Option<&OsStr>, count: u32) -> Result<Vec<Option<String>>> {
    let count = usize::try_from(count).context("more passed sockets than fit this machine")?;
    let Some(names) = listen_fdnames else {
        return Ok(vec![None; count]);
    };
    let names = names
        .to_str()
        .ok_or_else(|| anyhow!("LISTEN_FDNAMES={} is not UTF-8", names.display()))?;
    let names: Vec<Option<String>> = names.split(':').map(|name| Some(name.to_owned())).collect();
    ensure!(
        names.len() == count,
        "LISTEN_FDNAMES names {} sockets, LISTEN_FDS passes {count}",
        names.len()
    );
    Ok(names)
}

/// The listening sockets systemd passed to this process, in the order it
/// passed them, each with its name.
///
/// Call it early, from one place: every descriptor gets exactly one owner, a
/// second call is an error.
///
/// # Errors
///
/// Returns an error if the variables are malformed, if systemd passed more
/// than [`MAX_PASSED_SOCKETS`], if a passed descriptor isn't a listening unix
/// stream socket, or if it can't be configured.
pub fn activated_listeners() -> Result<Vec<Passed>> {
    let count = passed_sockets(
        rustix::process::getpid()
            .as_raw_nonzero()
            .get()
            .unsigned_abs(),
        std::env::var_os("LISTEN_PID").as_deref(),
        std::env::var_os("LISTEN_FDS").as_deref(),
    )?;
    if count == 0 {
        return Ok(Vec::new());
    }
    ensure!(
        count <= MAX_PASSED_SOCKETS,
        "systemd passed {count} sockets; skagent takes its ssh-agent socket and one named \"age\""
    );
    let names = passed_names(std::env::var_os("LISTEN_FDNAMES").as_deref(), count)?;
    ensure!(
        !TAKEN.swap(true, Ordering::SeqCst),
        "the sockets systemd passed were taken over already"
    );

    let mut passed = Vec::new();
    for (offset, name) in (0..).zip(names) {
        let fd = FIRST_PASSED_FD
            .checked_add(offset)
            .context("a passed descriptor number that doesn't exist")?;
        // SAFETY: LISTEN_PID names this process, so systemd passed the
        // descriptors from 3 on, `count` of them, open across exec. They
        // have been open since the process started, so no later open() can
        // have reused a number, and `TAKEN` makes this the only place that
        // claims them.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        check_listener(borrowed)?;
        // Passed descriptors are inheritable; the agent's prompts must not
        // get them.
        let flags = fcntl_getfd(borrowed).context("reading a passed socket's descriptor flags")?;
        fcntl_setfd(borrowed, flags | FdFlags::CLOEXEC)
            .context("marking a passed socket close-on-exec")?;
        // SAFETY: as above; the listener becomes the descriptor's only owner
        // and closes it once.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let listener = UnixListener::from(owned);
        listener
            .set_nonblocking(true)
            .context("making a passed socket non-blocking")?;
        passed.push(Passed { name, listener });
    }
    Ok(passed)
}
