//! The first buffer fixes where a process keeps its secrets.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_secret::{Backend, SecretBuffer, backend, use_secretmem};

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
