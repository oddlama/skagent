//! Socket path resolution, binding rules, peer policy and cleanup.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use rustix::io::Errno;
use skagent::socket::{
    DEFAULT_SOCKET_NAME, age_socket_path, bind, default_socket_path, is_transient_accept_error,
    peer_allowed,
};

#[test]
fn default_socket_path_lives_in_the_runtime_dir() -> Result<()> {
    let path = default_socket_path(Some(OsStr::new("/run/user/1000")))?;
    ensure!(path == Path::new("/run/user/1000").join(DEFAULT_SOCKET_NAME));
    Ok(())
}

#[test]
fn the_socket_for_age_requests_is_named_after_the_ssh_agent_socket() {
    // Several agents with sockets of their own don't meet on one path.
    for (ssh, age) in [
        (
            "/run/user/1000/skagent.sock",
            "/run/user/1000/skagent-age.sock",
        ),
        ("/tmp/agent.sock", "/tmp/agent-age.sock"),
        ("/tmp/a.b.sock", "/tmp/a.b-age.sock"),
        ("/tmp/agent", "/tmp/agent-age"),
        ("agent.sock", "agent-age.sock"),
    ] {
        assert_eq!(age_socket_path(Path::new(ssh)), Path::new(age), "{ssh}");
    }
}

#[test]
fn default_socket_path_needs_an_absolute_runtime_dir() {
    for runtime_dir in [
        None,
        Some(OsStr::new("")),
        Some(OsStr::new("run/user/1000")),
    ] {
        assert!(
            default_socket_path(runtime_dir).is_err(),
            "accepted XDG_RUNTIME_DIR {runtime_dir:?}"
        );
    }
}

#[test]
fn peers_must_be_the_own_user_or_root() {
    assert!(peer_allowed(1000, 1000));
    assert!(peer_allowed(0, 1000));
    assert!(peer_allowed(0, 0));
    assert!(!peer_allowed(1001, 1000));
    assert!(!peer_allowed(1000, 0));
}

#[test]
fn only_resource_and_abort_errors_are_retried() {
    for errno in [
        Errno::MFILE,
        Errno::NFILE,
        Errno::NOBUFS,
        Errno::CONNABORTED,
        Errno::INTR,
    ] {
        let error = io::Error::from_raw_os_error(errno.raw_os_error());
        assert!(
            is_transient_accept_error(&error),
            "{errno:?} is not retried"
        );
    }
    for errno in [Errno::BADF, Errno::INVAL, Errno::NOTSOCK] {
        let error = io::Error::from_raw_os_error(errno.raw_os_error());
        assert!(!is_transient_accept_error(&error), "{errno:?} is retried");
    }
    assert!(!is_transient_accept_error(&io::Error::other(
        "not an os error"
    )));
}

#[tokio::test]
async fn bound_socket_is_private() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    let (_listener, _bound) = bind(&path)?;
    let mode = fs::metadata(&path)
        .context("reading socket mode")?
        .permissions()
        .mode();
    ensure!(mode & 0o777 == 0o600, "socket mode is {:o}", mode & 0o777);
    Ok(())
}

#[tokio::test]
async fn binding_leaves_nothing_but_the_socket() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    let (_listener, _bound) = bind(&path)?;

    let entries = fs::read_dir(dir.path())
        .context("listing temp dir")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()
        .context("reading temp dir entries")?;
    ensure!(
        entries == [OsStr::new("agent.sock")],
        "leftovers: {entries:?}"
    );
    Ok(())
}

#[tokio::test]
async fn stale_socket_is_replaced() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    // A socket file nobody listens on any more, like after a crash.
    drop(std::os::unix::net::UnixListener::bind(&path).context("creating stale socket")?);
    ensure!(path.exists());

    let (_listener, _bound) = bind(&path)?;
    Ok(())
}

#[tokio::test]
async fn live_socket_is_not_replaced() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    let (_listener, _bound) = bind(&path)?;

    let error = match bind(&path) {
        Ok(_) => anyhow::bail!("second bind on a live socket succeeded"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(
        error.contains("already listening"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn non_socket_files_are_never_replaced() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    fs::write(&path, "precious").context("creating regular file")?;

    let error = match bind(&path) {
        Ok(_) => anyhow::bail!("bind replaced a regular file"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(error.contains("not a socket"), "unexpected error: {error}");
    ensure!(fs::read_to_string(&path).context("reading file back")? == "precious");
    Ok(())
}

#[tokio::test]
async fn remove_deletes_the_own_socket() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    let (listener, bound) = bind(&path)?;
    drop(listener);

    bound.remove()?;
    ensure!(!path.exists());
    // Removing again is fine: the file is already gone.
    bound.remove()?;
    Ok(())
}

#[tokio::test]
async fn remove_leaves_a_replaced_socket_alone() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let path = dir.path().join("agent.sock");
    let (listener, bound) = bind(&path)?;
    drop(listener);

    // Another agent's socket moved into place. It was created while ours
    // still existed, so it can't share our inode.
    let other = dir.path().join("other.sock");
    let _other_listener =
        std::os::unix::net::UnixListener::bind(&other).context("creating other socket")?;
    fs::rename(&other, &path).context("replacing the socket")?;

    bound.remove()?;
    ensure!(
        path.exists(),
        "removed a socket that belongs to someone else"
    );
    Ok(())
}
