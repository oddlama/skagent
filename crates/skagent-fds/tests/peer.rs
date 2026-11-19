//! The pidfd of a connection's peer.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use anyhow::{Result, ensure};
use rustix::io::{FdFlags, fcntl_getfd};
use skagent_fds::{has_exited, peer_pidfd};

#[test]
fn the_peer_of_a_socket_pair_is_this_process_and_alive() -> Result<()> {
    let (ours, _theirs) = UnixStream::pair()?;
    let Some(pidfd) = peer_pidfd(ours.as_fd())? else {
        // Before Linux 6.5 there is no such option; the agent then refuses
        // what needs it.
        return Ok(());
    };
    ensure!(!has_exited(&pidfd)?, "this process counts as exited");
    ensure!(
        fcntl_getfd(&pidfd)?.contains(FdFlags::CLOEXEC),
        "a spawned prompt would inherit the pidfd"
    );
    Ok(())
}

#[test]
fn something_that_is_no_socket_has_no_peer() -> Result<()> {
    let file = tempfile::tempfile()?;
    ensure!(peer_pidfd(file.as_fd()).is_err());
    Ok(())
}
