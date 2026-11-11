//! Buffers in `memfd_secret(2)` memory, as the kernel reports them.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use skagent_secret::{Backend, SecretBuffer, backend, use_secretmem};

/// The `/proc/self/smaps` block of the mapping containing `address`: its
/// header line (ending in the mapped file) and its `VmFlags`.
fn mapping_of(address: usize) -> Result<(String, Vec<String>)> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").context("reading /proc/self/smaps")?;
    let mut current: Option<String> = None;
    for line in smaps.lines() {
        let first = line.split_whitespace().next().unwrap_or_default();
        if let Some((start, end)) = first
            .split_once('-')
            .filter(|(start, _)| !start.ends_with(':'))
        {
            let start = usize::from_str_radix(start, 16).context("parsing a start address")?;
            let end = usize::from_str_radix(end, 16).context("parsing an end address")?;
            current = (start..end).contains(&address).then(|| line.to_owned());
        } else if let (Some(header), Some(flags)) = (&current, line.strip_prefix("VmFlags:")) {
            return Ok((
                header.clone(),
                flags.split_whitespace().map(str::to_owned).collect(),
            ));
        }
    }
    anyhow::bail!("no mapping contains {address:#x}")
}

#[test]
fn secretmem_buffers_are_kept_from_dumps_and_children() -> Result<()> {
    use_secretmem()?;
    use_secretmem().context("choosing it twice must be fine")?;
    ensure!(backend() == Backend::Secretmem);

    let mut buffer = SecretBuffer::from_slice(b"246810")?;
    ensure!(buffer.expose() == b"246810");
    let (header, flags) = mapping_of(buffer.data_pages().start)?;
    ensure!(
        header.contains("secretmem"),
        "not memfd_secret memory: {header}"
    );
    // Never swapped by construction: the kernel keeps secretmem unevictable,
    // which smaps doesn't show. Not dumped, not inherited by children:
    for flag in ["dd", "dc"] {
        ensure!(
            flags.iter().any(|f| f == flag),
            "flag {flag} missing: {flags:?}"
        );
    }
    buffer.clear();
    ensure!(buffer.expose().is_empty());
    Ok(())
}
