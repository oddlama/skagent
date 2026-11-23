//! The plugin's way to the agent: which socket, and the exchange on it.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age::wire::{Refusal, UNWRAP_EXTENSION, UnwrapReply, UnwrapRequest};
use skagent_age::{FileKey, Identity};
use skagent_age_plugin::agent::{Agent, Unwrap as _, hung_up, local_socket, socket_path};

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

#[test]
fn the_socket_for_age_requests_comes_before_a_forwarded_agent() -> Result<()> {
    let there = |_: &Path| true;
    let missing = |_: &Path| false;
    let runtime = Some(os("/run/user/1000"));
    let forwarded = Some(os("/tmp/ssh"));
    // Named explicitly: taken as is, whether it exists or not.
    ensure!(
        socket_path(Some(os("/tmp/given.sock")), runtime, forwarded, missing)?
            == Path::new("/tmp/given.sock")
    );
    // skagent runs here.
    ensure!(
        socket_path(None, runtime, forwarded, there)?
            == Path::new("/run/user/1000/skagent-age.sock")
    );
    // It doesn't: a remote host, with the agent forwarded.
    ensure!(socket_path(None, runtime, forwarded, missing)? == Path::new("/tmp/ssh"));
    ensure!(socket_path(None, None, forwarded, there)? == Path::new("/tmp/ssh"));
    // Empty values count as unset.
    ensure!(socket_path(Some(os("")), Some(os("")), forwarded, there)? == Path::new("/tmp/ssh"));
    ensure!(socket_path(None, runtime, None, missing).is_err());
    ensure!(socket_path(None, None, Some(os("")), there).is_err());
    Ok(())
}

/// Where an agent runs on this machine, which a forwarded one doesn't.
#[test]
fn an_agent_on_this_machine_is_found_by_its_socket_for_age_requests() {
    let there = |_: &Path| true;
    let missing = |_: &Path| false;
    let runtime = Some(os("/run/user/1000"));
    assert_eq!(
        local_socket(Some(os("/tmp/given.sock")), runtime, missing),
        Some(PathBuf::from("/tmp/given.sock"))
    );
    assert_eq!(
        local_socket(None, runtime, there),
        Some(PathBuf::from("/run/user/1000/skagent-age.sock"))
    );
    // No agent: an initrd, a rescue system.
    assert_eq!(local_socket(None, runtime, missing), None);
    assert_eq!(local_socket(None, None, there), None);
    assert_eq!(local_socket(Some(os("")), Some(os("")), there), None);
}

fn request() -> Result<UnwrapRequest> {
    let (_, recipient) = support::identity(1)?;
    Ok(UnwrapRequest {
        identity: Identity::AtHand,
        stanzas: vec![recipient.wrap(&FileKey::from_bytes(b"0123456789abcdef")?, &[1; 64])?],
    })
}

/// An agent for one connection: reads the request, waits, answers `reply`
/// (a message without its length). Returns the request it read.
fn serve_once(
    listener: UnixListener,
    delay: Duration,
    reply: Vec<u8>,
) -> std::thread::JoinHandle<Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header)?;
        let mut message = vec![0_u8; usize::try_from(u32::from_be_bytes(header))?];
        stream.read_exact(&mut message)?;
        std::thread::sleep(delay);
        stream.write_all(&u32::try_from(reply.len())?.to_be_bytes())?;
        stream.write_all(&reply)?;
        Ok(message)
    })
}

/// An `SSH_AGENT_EXTENSION_RESPONSE` for the unwrap extension.
fn response(reply: &UnwrapReply) -> Result<Vec<u8>> {
    let mut message = vec![29];
    message.extend_from_slice(&u32::try_from(UNWRAP_EXTENSION.len())?.to_be_bytes());
    message.extend_from_slice(UNWRAP_EXTENSION.as_bytes());
    message.extend_from_slice(&reply.encode());
    Ok(message)
}

fn socket(directory: &tempfile::TempDir, name: &str) -> Result<(UnixListener, PathBuf)> {
    let path = directory.path().join(name);
    Ok((UnixListener::bind(&path)?, path))
}

#[test]
fn a_request_is_one_extension_message_and_the_reply_is_decoded() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (listener, path) = socket(&directory, "agent.sock")?;
    let reply = UnwrapReply::FileKey(FileKey::from_bytes(b"YELLOW SUBMARINE")?);
    let server = serve_once(listener, Duration::ZERO, response(&reply)?);

    let request = request()?;
    let answer = Agent::at(path).unwrap(&request, &mut || Ok(()))?;
    let UnwrapReply::FileKey(file_key) = answer else {
        bail!("no file key: {answer:?}");
    };
    ensure!(file_key.expose() == b"YELLOW SUBMARINE");

    let received = server.join().ok().context("the server panicked")??;
    ensure!(received.first() == Some(&27), "not SSH_AGENTC_EXTENSION");
    let name_end = 5 + UNWRAP_EXTENSION.len();
    ensure!(received.get(5..name_end) == Some(UNWRAP_EXTENSION.as_bytes()));
    ensure!(UnwrapRequest::decode(received.get(name_end..).context("no details")?)? == request);
    Ok(())
}

#[test]
fn while_the_agent_takes_its_time_the_caller_is_asked_whether_to_go_on() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (listener, path) = socket(&directory, "agent.sock")?;
    let server = serve_once(
        listener,
        Duration::from_millis(400),
        response(&UnwrapReply::NoMatch)?,
    );
    let mut calls = 0_u32;
    let answer = Agent::at(path).unwrap(&request()?, &mut || {
        calls += 1;
        Ok(())
    })?;
    ensure!(matches!(answer, UnwrapReply::NoMatch));
    ensure!(calls >= 3, "asked {calls} times in 400 ms");
    server.join().ok().context("the server panicked")??;

    // Saying no ends the request, without waiting for the answer.
    let (listener, path) = socket(&directory, "slow.sock")?;
    let server = serve_once(
        listener,
        Duration::from_secs(2),
        response(&UnwrapReply::NoMatch)?,
    );
    let started = std::time::Instant::now();
    let answer = Agent::at(path).unwrap(&request()?, &mut || bail!("the client went away"));
    ensure!(answer.is_err());
    ensure!(
        started.elapsed() < Duration::from_secs(1),
        "waited for the agent anyway"
    );
    // The server's write may hit the closed connection.
    drop(server.join());
    Ok(())
}

#[test]
fn a_failure_means_not_allowed_on_a_forwarded_agent_and_an_error_on_skagents_own() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for failure in [5_u8, 28] {
        let (listener, path) = socket(&directory, &format!("ssh-{failure}.sock"))?;
        let server = serve_once(listener, Duration::ZERO, vec![failure]);
        let answer = Agent::at(path).unwrap(&request()?, &mut || Ok(()))?;
        ensure!(
            matches!(answer, UnwrapReply::Refused(Refusal::NotAllowed)),
            "{failure}: {answer:?}"
        );
        server.join().ok().context("the server panicked")??;
    }
    let own = tempfile::tempdir()?;
    let (listener, path) = socket(&own, "skagent-age.sock")?;
    let server = serve_once(listener, Duration::ZERO, vec![5]);
    ensure!(Agent::at(path).unwrap(&request()?, &mut || Ok(())).is_err());
    server.join().ok().context("the server panicked")??;
    Ok(())
}

#[test]
fn replies_that_are_something_else_are_errors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut another = vec![29];
    another.extend_from_slice(&16_u32.to_be_bytes());
    another.extend_from_slice(b"age-list@skagent");
    let mut truncated = response(&UnwrapReply::FileKey(FileKey::from_bytes(
        b"YELLOW SUBMARINE",
    )?))?;
    truncated.pop();
    for (name, reply) in [
        ("success", vec![6_u8]),
        ("another-extension", another),
        ("truncated", truncated),
    ] {
        let (listener, path) = socket(&directory, &format!("{name}.sock"))?;
        let server = serve_once(listener, Duration::ZERO, reply);
        ensure!(
            Agent::at(path).unwrap(&request()?, &mut || Ok(())).is_err(),
            "{name}"
        );
        server.join().ok().context("the server panicked")??;
    }
    ensure!(
        Agent::at(directory.path().join("nobody.sock"))
            .unwrap(&request()?, &mut || Ok(()))
            .is_err(),
        "no agent"
    );
    Ok(())
}

#[test]
fn a_pipe_hangs_up_when_its_other_end_closes() -> Result<()> {
    let (ours, theirs) = UnixStream::pair()?;
    ensure!(!hung_up(&ours));
    drop(theirs);
    ensure!(hung_up(&ours));
    // A file never hangs up: input redirected from one isn't a client gone.
    ensure!(!hung_up(tempfile::tempfile()?));
    Ok(())
}
