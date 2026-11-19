//! Which `LISTEN_*` values pass sockets to us, and which descriptors are
//! accepted as the agent socket.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::net::TcpListener;
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};

use anyhow::{Context as _, Result, ensure};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket};
use skagent_fds::{activated_listeners, check_listener, passed_names, passed_sockets};

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

#[test]
fn sockets_are_passed_only_to_the_process_listen_pid_names() -> Result<()> {
    ensure!(passed_sockets(42, None, None)? == 0);
    ensure!(
        passed_sockets(42, None, Some(os("1")))? == 0,
        "LISTEN_FDS alone passes nothing"
    );
    ensure!(
        passed_sockets(42, Some(os("41")), Some(os("1")))? == 0,
        "meant for another process"
    );
    ensure!(passed_sockets(42, Some(os("42")), Some(os("1")))? == 1);
    ensure!(passed_sockets(42, Some(os("42")), Some(os("2")))? == 2);
    Ok(())
}

#[test]
fn malformed_variables_are_errors() -> Result<()> {
    for (pid, fds) in [
        (Some(os("x")), Some(os("1"))),
        (Some(os("")), Some(os("1"))),
        (Some(os("-42")), Some(os("1"))),
        (Some(os("42")), None),
        (Some(os("42")), Some(os("one"))),
        (Some(os("42")), Some(os("-1"))),
    ] {
        ensure!(
            passed_sockets(42, pid, fds).is_err(),
            "accepted {pid:?} {fds:?}"
        );
    }
    Ok(())
}

#[test]
fn a_listening_unix_stream_socket_is_accepted() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let listener = UnixListener::bind(dir.path().join("agent.sock")).context("binding")?;
    check_listener(listener.as_fd())
}

#[test]
fn anything_else_is_refused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let datagram = UnixDatagram::bind(dir.path().join("datagram.sock")).context("binding")?;
    let (connected, _peer) = UnixStream::pair().context("creating a socket pair")?;
    let tcp = TcpListener::bind("127.0.0.1:0").context("binding tcp")?;
    let file = std::fs::File::open("/dev/null").context("opening /dev/null")?;
    // Listens too, but with message boundaries ssh-agent clients don't use.
    let seqpacket = socket(AddressFamily::UNIX, SocketType::SEQPACKET, None).context("socket")?;
    let address = SocketAddrUnix::new(dir.path().join("seqpacket.sock")).context("address")?;
    bind(&seqpacket, &address).context("binding seqpacket")?;
    listen(&seqpacket, 1).context("listening on seqpacket")?;
    for (name, result) in [
        ("datagram", check_listener(datagram.as_fd())),
        ("connected stream", check_listener(connected.as_fd())),
        ("tcp listener", check_listener(tcp.as_fd())),
        ("seqpacket listener", check_listener(seqpacket.as_fd())),
        ("file", check_listener(file.as_fd())),
    ] {
        ensure!(result.is_err(), "accepted a {name}");
    }
    Ok(())
}

#[test]
fn without_systemd_nothing_is_taken() -> Result<()> {
    // The test harness isn't socket activated (LISTEN_PID, if inherited,
    // names another process).
    ensure!(activated_listeners()?.is_empty());
    Ok(())
}

#[test]
fn passed_sockets_are_named_one_by_one() -> Result<()> {
    ensure!(passed_names(None, 2)? == [None, None], "no names");
    ensure!(passed_names(None, 0)?.is_empty());
    ensure!(
        passed_names(Some(os("skagent.socket:age")), 2)?
            == [Some("skagent.socket".to_owned()), Some("age".to_owned())]
    );
    ensure!(passed_names(Some(os("age")), 1)? == [Some("age".to_owned())]);
    // systemd names every socket; another count means the variables don't
    // belong together.
    ensure!(
        passed_names(Some(os("age")), 2).is_err(),
        "one name, two sockets"
    );
    ensure!(
        passed_names(Some(os("a:b:c")), 2).is_err(),
        "three names, two sockets"
    );
    Ok(())
}
