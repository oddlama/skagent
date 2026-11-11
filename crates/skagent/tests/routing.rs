//! Routing is independent of enumeration order and never substitutes devices.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::CredentialKey;
use skagent::routing::{Bindings, KeyedLocks, Resolution};

fn work() -> CredentialKey {
    CredentialKey::new("ssh:work", &[1; 32])
}

fn personal() -> CredentialKey {
    CredentialKey::new("ssh:personal", &[2; 32])
}

fn device(inode: u64) -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw1", 1, inode, (100, 0))
}

#[test]
fn unknown_credentials_need_selection_unless_there_is_only_one_device() -> Result<()> {
    let bindings = Bindings::default();
    ensure!(bindings.resolve(&work(), &[]).is_err());
    ensure!(bindings.resolve(&work(), &[device(1)])? == Resolution::Direct(device(1)));
    ensure!(bindings.resolve(&work(), &[device(1), device(2)])? == Resolution::Touch);
    Ok(())
}

#[test]
fn bindings_override_enumeration_order() -> Result<()> {
    let mut bindings = Bindings::default();
    bindings.bind(work(), device(1));
    bindings.bind(personal(), device(2));
    for candidates in [[device(1), device(2)], [device(2), device(1)]] {
        ensure!(bindings.resolve(&work(), &candidates)? == Resolution::Direct(device(1)));
        ensure!(bindings.resolve(&personal(), &candidates)? == Resolution::Direct(device(2)));
    }
    Ok(())
}

#[test]
fn losing_a_binding_requires_touch_even_with_one_remaining_device() -> Result<()> {
    let mut bindings = Bindings::default();
    bindings.bind(work(), device(1));
    ensure!(bindings.resolve(&work(), &[device(2)])? == Resolution::Touch);
    ensure!(bindings.resolve(&work(), &[device(2), device(3)])? == Resolution::Touch);
    ensure!(bindings.resolve(&work(), &[]).is_err());
    Ok(())
}

#[test]
fn removing_one_binding_leaves_the_other_alone() -> Result<()> {
    let mut bindings = Bindings::default();
    bindings.bind(work(), device(1));
    bindings.bind(personal(), device(2));
    bindings.forget(&work());
    let candidates = [device(1), device(2)];
    ensure!(bindings.resolve(&work(), &candidates)? == Resolution::Touch);
    ensure!(bindings.resolve(&personal(), &candidates)? == Resolution::Direct(device(2)));
    Ok(())
}

#[test]
fn clearing_identities_forgets_all_bindings() -> Result<()> {
    let mut bindings = Bindings::default();
    bindings.bind(work(), device(1));
    bindings.bind(personal(), device(2));
    bindings.clear();
    for key in [work(), personal()] {
        ensure!(bindings.resolve(&key, &[device(1), device(2)])? == Resolution::Touch);
    }
    Ok(())
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
