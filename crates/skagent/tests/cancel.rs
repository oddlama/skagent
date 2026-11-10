//! Noticing abandoned requests: client hangups and dropped request futures.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use skagent::cancel::{Abandoned, Hangup};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

const SOON: Duration = Duration::from_secs(1);
const NOT_YET: Duration = Duration::from_millis(100);

#[tokio::test]
async fn data_from_the_client_is_no_hangup_and_stays_unread() -> Result<()> {
    let (mut agent_side, mut client) = UnixStream::pair().context("creating a socket pair")?;
    let hangup = Hangup::watch(&agent_side)?;

    client.write_all(b"request").await?;
    ensure!(
        tokio::time::timeout(NOT_YET, hangup.closed())
            .await
            .is_err(),
        "pending data was taken for a hangup"
    );
    // The protocol side still gets every byte.
    let mut received = [0_u8; 7];
    agent_side.read_exact(&mut received).await?;
    ensure!(&received == b"request");

    client.write_all(b"more").await?;
    ensure!(
        tokio::time::timeout(NOT_YET, hangup.closed())
            .await
            .is_err(),
        "a second request was taken for a hangup"
    );
    drop(client);
    tokio::time::timeout(SOON, hangup.closed())
        .await
        .context("the hangup went unnoticed")?;
    Ok(())
}

#[tokio::test]
async fn a_hangup_before_watching_counts_too() -> Result<()> {
    let (agent_side, client) = UnixStream::pair().context("creating a socket pair")?;
    drop(client);
    let hangup = Hangup::watch(&agent_side)?;
    tokio::time::timeout(SOON, hangup.closed())
        .await
        .context("an earlier hangup went unnoticed")?;
    Ok(())
}

#[tokio::test]
async fn work_is_dropped_when_the_client_hangs_up() -> Result<()> {
    let (agent_side, client) = UnixStream::pair().context("creating a socket pair")?;
    let hangup = Hangup::watch(&agent_side)?;
    let abandoned = Abandoned::default();
    let flag = abandoned.flag();
    let work = async move {
        let _abandoned = abandoned;
        std::future::pending::<()>().await;
        Ok(())
    };
    let disconnect = async move {
        tokio::time::sleep(NOT_YET).await;
        drop(client);
    };
    let (outcome, ()) = tokio::time::timeout(
        SOON,
        futures_util_join(Hangup::unless_closed(Some(&hangup), work), disconnect),
    )
    .await
    .context("the request outlived its client")?;
    ensure!(outcome.is_err(), "a cancelled request reported success");
    ensure!(flag.is_set(), "the work wasn't dropped");
    Ok(())
}

#[tokio::test]
async fn finished_work_wins_and_no_watch_means_no_cancel() -> Result<()> {
    let (agent_side, _client) = UnixStream::pair().context("creating a socket pair")?;
    let hangup = Hangup::watch(&agent_side)?;
    let answer = Hangup::unless_closed(Some(&hangup), async { Ok(42) }).await?;
    ensure!(answer == 42);
    let answer = Hangup::unless_closed(None, async { Ok(7) }).await?;
    ensure!(answer == 7);
    Ok(())
}

#[test]
fn abandoned_is_set_on_drop_only() {
    let abandoned = Abandoned::default();
    let flag = abandoned.flag();
    assert!(!flag.is_set());
    drop(abandoned);
    assert!(flag.is_set());
}

/// Runs both futures to completion.
async fn futures_util_join<A, B>(
    first: impl Future<Output = A>,
    second: impl Future<Output = B>,
) -> (A, B) {
    tokio::join!(first, second)
}
