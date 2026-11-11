//! The message size limit on agent connections.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use skagent::frames::{BoundedStream, MAX_MESSAGE_LEN};
use support::RunningAgent;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

fn message(payload: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = u32::try_from(payload.len())?.to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Writes `bytes` one small piece at a time and reads them back through a
/// [`BoundedStream`], so length prefixes are split across reads.
async fn through_bounded(bytes: &[u8]) -> Result<std::io::Result<Vec<u8>>> {
    let (reader, mut writer) = UnixStream::pair().context("creating a socket pair")?;
    let owned = bytes.to_vec();
    let writing = tokio::spawn(async move {
        for piece in owned.chunks(3) {
            if writer.write_all(piece).await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut bounded = BoundedStream::new(reader);
    let mut received = Vec::new();
    let outcome = loop {
        let mut chunk = [0_u8; 5];
        match bounded.read(&mut chunk).await {
            Ok(0) => break Ok(received),
            Ok(count) => received.extend_from_slice(chunk.get(..count).unwrap_or_default()),
            Err(error) => break Err(error),
        }
    };
    writing.await.context("writer task")?;
    Ok(outcome)
}

#[tokio::test]
async fn messages_up_to_the_limit_pass_unchanged() -> Result<()> {
    let mut stream = message(b"\x0b")?;
    stream.extend(message(b"")?);
    stream.extend(message(&[7; 300])?);
    // A prefix announcing exactly the limit is fine (the payload may follow).
    stream.extend(MAX_MESSAGE_LEN.to_be_bytes());
    stream.extend([1, 2, 3]);
    let received = through_bounded(&stream).await??;
    ensure!(received == stream, "the bytes changed on their way through");
    Ok(())
}

#[tokio::test]
async fn a_longer_message_fails_the_read() -> Result<()> {
    let mut stream = message(b"\x0b")?;
    let too_long = MAX_MESSAGE_LEN.checked_add(1).context("limit overflow")?;
    stream.extend(too_long.to_be_bytes());
    stream.extend([0; 16]);
    let error = through_bounded(&stream)
        .await?
        .err()
        .context("a message above the limit was read")?;
    ensure!(error.kind() == std::io::ErrorKind::InvalidData);
    Ok(())
}

#[tokio::test]
async fn the_agent_hangs_up_on_an_oversized_message() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut raw = UnixStream::connect(dir.path().join("agent.sock")).await?;

    // u32::MAX bytes announced; without a limit the agent would keep
    // buffering and wait for the rest.
    raw.write_all(&u32::MAX.to_be_bytes()).await?;
    raw.write_all(&[0; 1024]).await?;
    let mut reply = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut reply))
        .await
        .context("the agent kept the connection open")?;
    ensure!(
        matches!(read, Ok(0) | Err(_)),
        "the agent answered instead of hanging up"
    );

    // Other connections are unaffected.
    let mut client = agent.client().await?;
    ssh_agent_lib::agent::Session::request_identities(&mut client)
        .await
        .context("listing keys on a new connection")?;
    agent.stop().await
}
