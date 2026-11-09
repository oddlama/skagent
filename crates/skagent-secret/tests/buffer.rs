//! Behavior of `SecretBuffer` as a container.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_secret::SecretBuffer;

#[test]
fn stores_and_exposes_the_secret() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"123456")?;
    ensure!(buffer.expose() == b"123456");
    ensure!(buffer.len() == 6 && buffer.capacity() == 6 && !buffer.is_empty());
    Ok(())
}

#[test]
fn appends_up_to_the_capacity() -> Result<()> {
    let mut buffer = SecretBuffer::with_capacity(8)?;
    ensure!(buffer.is_empty());
    buffer.extend_from_slice(b"1234")?;
    buffer.extend_from_slice(b"5678")?;
    ensure!(buffer.expose() == b"12345678");
    Ok(())
}

#[test]
fn rejects_overflow_and_keeps_the_content() -> Result<()> {
    let mut buffer = SecretBuffer::with_capacity(4)?;
    buffer.extend_from_slice(b"123")?;
    ensure!(
        buffer.extend_from_slice(b"45").is_err(),
        "overflow accepted"
    );
    ensure!(buffer.expose() == b"123");
    Ok(())
}

#[test]
fn zero_capacity_and_empty_secrets_are_rejected() {
    assert!(SecretBuffer::with_capacity(0).is_err());
    assert!(SecretBuffer::from_slice(b"").is_err());
}

#[test]
fn clear_empties_the_buffer() -> Result<()> {
    let mut buffer = SecretBuffer::from_slice(b"123456")?;
    buffer.clear();
    ensure!(buffer.is_empty() && buffer.expose().is_empty());
    buffer.extend_from_slice(b"abc")?;
    ensure!(buffer.expose() == b"abc");
    Ok(())
}

#[test]
fn debug_reveals_nothing() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"hunter2-pin")?;
    let debug = format!("{buffer:?}");
    ensure!(debug == "SecretBuffer(<redacted>)", "debug output: {debug}");
    Ok(())
}

#[test]
fn constant_time_eq_compares_content_and_length() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"123456")?;
    ensure!(buffer.constant_time_eq(b"123456"));
    ensure!(!buffer.constant_time_eq(b"123457"));
    ensure!(!buffer.constant_time_eq(b"12345"));
    ensure!(!buffer.constant_time_eq(b"1234567"));
    Ok(())
}

#[test]
fn large_secrets_span_multiple_pages() -> Result<()> {
    let secret = vec![0x5a_u8; 10_000];
    let buffer = SecretBuffer::from_slice(&secret)?;
    ensure!(buffer.expose() == secret.as_slice());
    let pages = buffer.data_pages();
    ensure!(pages.end.saturating_sub(pages.start) >= 10_000);
    Ok(())
}
