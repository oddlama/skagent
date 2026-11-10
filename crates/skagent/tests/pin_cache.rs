//! The PIN cache rules, with fabricated devices and explicit time.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::{CachePolicy, CredentialKey, Lookup, Miss, PinCache};
use skagent_secret::SecretBuffer;

const PIN: &[u8] = b"246810";

fn device() -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw3", 0xf302, 1234, (1_700_000_000, 5))
}

fn replugged() -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw3", 0xf302, 1299, (1_700_000_100, 7))
}

fn work() -> CredentialKey {
    CredentialKey::new("ssh:example", &[1; 64])
}

fn personal() -> CredentialKey {
    CredentialKey::new("ssh:", &[2; 64])
}

fn at(start: Instant, seconds: u64) -> Result<Instant> {
    start
        .checked_add(Duration::from_secs(seconds))
        .context("instant overflow in test")
}

fn policy(lifetime: u64, idle: Option<u64>) -> CachePolicy {
    CachePolicy {
        lifetime: Duration::from_secs(lifetime),
        idle_timeout: idle.map(Duration::from_secs),
    }
}

fn cache_with_work_pin(policy: CachePolicy, start: Instant) -> Result<PinCache> {
    let mut cache = PinCache::new(policy);
    cache.store(work(), SecretBuffer::from_slice(PIN)?, device(), 8, start);
    Ok(cache)
}

fn expect_hit(lookup: Lookup) -> Result<()> {
    match lookup {
        Lookup::Hit(pin) => {
            ensure!(pin.expose() == PIN, "wrong PIN handed out");
            Ok(())
        }
        Lookup::Miss(miss) => bail!("expected a hit, got {miss:?}"),
    }
}

fn expect_miss(lookup: &Lookup, expected: Miss) -> Result<()> {
    match lookup {
        Lookup::Hit(_) => bail!("expected {expected:?}, got a hit"),
        Lookup::Miss(miss) => {
            ensure!(*miss == expected, "expected {expected:?}, got {miss:?}");
            Ok(())
        }
    }
}

#[test]
fn a_stored_pin_is_handed_out_for_the_same_device_and_counter() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(CachePolicy::default(), start)?;
    expect_hit(cache.lookup(&work(), &device(), 8, at(start, 60)?)?)?;
    expect_hit(cache.lookup(&work(), &device(), 8, at(start, 120)?)?)?;
    expect_miss(
        &cache.lookup(&personal(), &device(), 8, start)?,
        Miss::NotCached,
    )
}

#[test]
fn another_device_or_a_replug_drops_the_pin() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(CachePolicy::default(), start)?;
    expect_miss(
        &cache.lookup(&work(), &replugged(), 8, start)?,
        Miss::DeviceChanged,
    )?;
    // Gone for good, not just refused for that device.
    expect_miss(
        &cache.lookup(&work(), &device(), 8, start)?,
        Miss::NotCached,
    )
}

#[test]
fn a_changed_retry_counter_drops_the_pin() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(CachePolicy::default(), start)?;
    expect_miss(
        &cache.lookup(&work(), &device(), 7, start)?,
        Miss::RetriesChanged {
            stored: 8,
            current: 7,
        },
    )?;
    ensure!(cache.is_empty());
    Ok(())
}

#[test]
fn the_lifetime_is_hard_and_not_extended_by_use() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(policy(3600, None), start)?;
    cache.mark_used(&work(), at(start, 3000)?);
    expect_hit(cache.lookup(&work(), &device(), 8, at(start, 3599)?)?)?;
    expect_miss(
        &cache.lookup(&work(), &device(), 8, at(start, 3600)?)?,
        Miss::Expired,
    )
}

#[test]
fn the_idle_timeout_counts_from_the_last_use() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(policy(3600, Some(600)), start)?;
    cache.mark_used(&work(), at(start, 500)?);
    expect_hit(cache.lookup(&work(), &device(), 8, at(start, 1099)?)?)?;
    expect_miss(
        &cache.lookup(&work(), &device(), 8, at(start, 1100)?)?,
        Miss::Idle,
    )
}

#[test]
fn a_zero_lifetime_disables_caching() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(policy(0, None), start)?;
    ensure!(cache.is_empty(), "stored a PIN with caching disabled");
    expect_miss(
        &cache.lookup(&work(), &device(), 8, start)?,
        Miss::NotCached,
    )
}

#[test]
fn entries_are_independent() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(CachePolicy::default(), start)?;
    cache.store(
        personal(),
        SecretBuffer::from_slice(b"13579")?,
        replugged(),
        8,
        start,
    );

    ensure!(cache.evict(&personal()));
    ensure!(!cache.evict(&personal()), "evicted twice");
    expect_hit(cache.lookup(&work(), &device(), 8, start)?)?;
    ensure!(cache.clear() == 1);
    ensure!(cache.is_empty());
    Ok(())
}

#[test]
fn expire_drops_only_ended_entries() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(policy(100, None), start)?;
    cache.store(
        personal(),
        SecretBuffer::from_slice(b"13579")?,
        replugged(),
        8,
        at(start, 50)?,
    );
    ensure!(cache.expire(at(start, 99)?) == 0);
    ensure!(cache.expire(at(start, 100)?) == 1);
    ensure!(cache.len() == 1);
    ensure!(cache.expire(at(start, 150)?) == 1);
    ensure!(cache.is_empty());
    Ok(())
}

#[test]
fn storing_again_restarts_the_lifetime() -> Result<()> {
    let start = Instant::now();
    let mut cache = cache_with_work_pin(policy(100, None), start)?;
    cache.store(
        work(),
        SecretBuffer::from_slice(PIN)?,
        device(),
        8,
        at(start, 90)?,
    );
    expect_hit(cache.lookup(&work(), &device(), 8, at(start, 150)?)?)
}

#[test]
fn debug_output_shows_no_pin_or_key_handle() -> Result<()> {
    let start = Instant::now();
    let cache = cache_with_work_pin(CachePolicy::default(), start)?;
    let debug = format!("{cache:?}");
    ensure!(!debug.contains("246810"), "PIN in debug output: {debug}");
    ensure!(debug.contains("key_handle_len: 64"), "{debug}");
    Ok(())
}

#[test]
fn device_identity_of_a_non_device_fails() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let file = dir.path().join("not-a-device");
    std::fs::write(&file, "x").context("writing file")?;
    let path = file.to_str().context("temp path is not UTF-8")?;
    ensure!(
        DeviceIdentity::of(path).is_err(),
        "regular file accepted as device"
    );
    ensure!(DeviceIdentity::of("/dev/does-not-exist").is_err());
    Ok(())
}
