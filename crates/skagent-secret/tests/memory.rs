//! What the kernel says about a `SecretBuffer`'s memory, read from `/proc/self/smaps`.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ops::Range;

use anyhow::{Context as _, Result, anyhow, ensure};
use skagent_secret::SecretBuffer;

/// One mapping from `/proc/self/smaps`.
#[derive(Debug)]
struct Vma {
    range: Range<usize>,
    permissions: String,
    flags: Vec<String>,
    locked_kb: u64,
}

fn parse_hex(text: &str) -> Result<usize> {
    usize::from_str_radix(text, 16).with_context(|| format!("parsing address {text:?}"))
}

fn read_smaps() -> Result<Vec<Vma>> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").context("reading /proc/self/smaps")?;
    let mut vmas: Vec<Vma> = Vec::new();
    for line in smaps.lines() {
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        if let Some((start, end)) = first
            .split_once('-')
            .filter(|(start, _)| !start.ends_with(':'))
        {
            let permissions = fields.next().unwrap_or_default().to_owned();
            vmas.push(Vma {
                range: parse_hex(start)?..parse_hex(end)?,
                permissions,
                flags: Vec::new(),
                locked_kb: 0,
            });
        } else if let Some(current) = vmas.last_mut() {
            match first {
                "VmFlags:" => current.flags = fields.map(str::to_owned).collect(),
                "Locked:" => {
                    current.locked_kb = fields
                        .next()
                        .unwrap_or_default()
                        .parse()
                        .with_context(|| format!("parsing Locked line {line:?}"))?;
                }
                _ => {}
            }
        }
    }
    Ok(vmas)
}

fn vma_containing(vmas: &[Vma], address: usize) -> Result<&Vma> {
    vmas.iter()
        .find(|vma| vma.range.contains(&address))
        .ok_or_else(|| anyhow!("no mapping contains {address:#x}"))
}

#[test]
fn data_pages_are_locked_not_dumped_and_wiped_on_fork() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"123456")?;
    let pages = buffer.data_pages();
    let vmas = read_smaps()?;
    let vma = vma_containing(&vmas, pages.start)?;

    ensure!(vma.permissions.starts_with("rw"), "data pages: {vma:?}");
    for flag in ["lo", "dd", "wf"] {
        ensure!(
            vma.flags.iter().any(|f| f == flag),
            "flag {flag} missing: {vma:?}"
        );
    }
    ensure!(vma.locked_kb > 0, "nothing locked: {vma:?}");
    Ok(())
}

#[test]
fn data_pages_are_surrounded_by_guard_pages() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"123456")?;
    let pages = buffer.data_pages();
    let vmas = read_smaps()?;

    let before = vma_containing(&vmas, pages.start.saturating_sub(1))?;
    let after = vma_containing(&vmas, pages.end)?;
    for guard in [before, after] {
        ensure!(
            guard.permissions.starts_with("---"),
            "not a guard page: {guard:?}"
        );
    }
    Ok(())
}

#[test]
fn memory_is_released_on_drop() -> Result<()> {
    let buffer = SecretBuffer::from_slice(b"123456")?;
    let start = buffer.data_pages().start;
    drop(buffer);

    // The address may be reused by a later mapping, but not by a locked,
    // wipe-on-fork one of ours with the same layout. Check it isn't ours any more.
    let vmas = read_smaps()?;
    if let Some(vma) = vmas.iter().find(|vma| vma.range.contains(&start)) {
        ensure!(
            !(vma.flags.iter().any(|f| f == "wf") && vma.range.start == start),
            "secret mapping still present after drop: {vma:?}"
        );
    }
    Ok(())
}
