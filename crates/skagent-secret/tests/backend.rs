//! The first buffer fixes where a process keeps its secrets.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_secret::{
    Backend, SecretBuffer, backend, secretmem_available, strongest_backend, use_secretmem,
};

#[test]
fn memfd_secret_can_only_be_chosen_before_the_first_buffer() -> Result<()> {
    let _locked = SecretBuffer::from_slice(b"246810")?;
    ensure!(backend() == Backend::Locked);
    ensure!(
        use_secretmem().is_err(),
        "switched backends with a buffer allocated"
    );
    ensure!(backend() == Backend::Locked);
    Ok(())
}

/// Where the kernel puts the mapping at `address`: the header line of its
/// entry in `/proc/self/smaps`.
fn mapping_of(address: usize) -> Result<String> {
    let smaps = std::fs::read_to_string("/proc/self/smaps")?;
    smaps
        .lines()
        .find(|line| {
            line.split_once(' ')
                .and_then(|(range, _)| range.split_once('-'))
                .and_then(|(start, end)| {
                    let start = usize::from_str_radix(start, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    Some(start <= address && address < end)
                })
                .unwrap_or(false)
        })
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("no mapping at {address:x}"))
}

#[test]
fn one_secret_can_live_in_memfd_secret_memory_while_the_others_dont() -> Result<()> {
    let locked = SecretBuffer::from_slice(b"246810")?;
    ensure!(backend() == Backend::Locked);
    if !secretmem_available() {
        // An older kernel: the strongest there is, is what everything uses.
        ensure!(strongest_backend() == Backend::Locked);
        ensure!(SecretBuffer::from_slice_in(b"seed", Backend::Secretmem).is_err());
        return Ok(());
    }
    ensure!(strongest_backend() == Backend::Secretmem);
    let hidden = SecretBuffer::from_slice_in(b"an identity's seed", strongest_backend())?;
    ensure!(hidden.expose() == b"an identity's seed");
    ensure!(mapping_of(hidden.data_pages().start)?.contains("secretmem"));
    // The process's own choice stands, for the buffers before and after.
    ensure!(backend() == Backend::Locked);
    let after = SecretBuffer::from_slice(b"135790")?;
    for buffer in [&locked, &after] {
        ensure!(!mapping_of(buffer.data_pages().start)?.contains("secretmem"));
    }
    ensure!(SecretBuffer::with_capacity_in(0, Backend::Secretmem).is_err());
    Ok(())
}
