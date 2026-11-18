//! Device and credential locks: independent devices don't block each other.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::CredentialKey;
use skagent::routing::KeyedLocks;

fn work() -> CredentialKey {
    CredentialKey::new("ssh:work", &[1; 32])
}

fn device(inode: u64) -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw1", 1, inode, (100, 0))
}

#[tokio::test]
async fn different_devices_do_not_block_each_other() -> Result<()> {
    let locks = KeyedLocks::default();
    let first = locks.lock(device(1)).await;
    let second = tokio::time::timeout(Duration::from_secs(1), locks.lock(device(2))).await?;
    // The same device queues, while independent devices hold their locks.
    ensure!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock(device(1)))
            .await
            .is_err()
    );
    drop(first);
    let third = tokio::time::timeout(Duration::from_secs(1), locks.lock(device(1))).await?;
    drop((second, third));
    Ok(())
}

#[tokio::test]
async fn a_cancelled_waiter_does_not_bypass_a_live_device_lock() -> Result<()> {
    let locks = KeyedLocks::default();
    let owner = locks.lock(work()).await;
    for _ in 0..2 {
        ensure!(
            tokio::time::timeout(Duration::from_millis(20), locks.lock(work()))
                .await
                .is_err()
        );
    }
    drop(owner);
    drop(tokio::time::timeout(Duration::from_secs(1), locks.lock(work())).await?);
    Ok(())
}

#[tokio::test]
async fn waiting_for_a_busy_key_gives_up() -> Result<()> {
    let locks = KeyedLocks::default();
    let holder = locks.lock(device(1)).await;
    // The outer timeout only keeps a broken implementation from hanging the test.
    let waited = tokio::time::timeout(
        Duration::from_secs(1),
        locks.lock_within(device(1), Duration::from_millis(50)),
    )
    .await
    .context("lock_within ignored its timeout")?;
    let error = match waited {
        Ok(_) => anyhow::bail!("got a lock that is held"),
        Err(error) => error.to_string(),
    };
    ensure!(error.contains("busy"), "{error}");
    drop(holder);
    drop(
        locks
            .lock_within(device(1), Duration::from_millis(50))
            .await?,
    );
    Ok(())
}
