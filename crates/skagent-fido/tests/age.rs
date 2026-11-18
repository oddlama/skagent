//! Age credential ids: validation and redaction. Everything else about them
//! needs a security key and is covered by the VM tests.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_fido::{AGE_RP_ID, AgeCredential};

#[test]
fn ids_are_bounded_and_hidden_in_debug() -> Result<()> {
    let credential = AgeCredential::new(b"sensitive-handle".to_vec())?;
    ensure!(credential.id() == b"sensitive-handle");
    let shown = format!("{credential:?}");
    ensure!(!shown.contains("sensitive"), "{shown}");
    ensure!(!shown.contains("115"), "the id's bytes in {shown}");

    ensure!(AgeCredential::new(vec![1; 1024]).is_ok());
    for length in [0, 1025] {
        ensure!(
            AgeCredential::new(vec![1; length]).is_err(),
            "{length} bytes accepted"
        );
    }
    Ok(())
}

#[test]
fn the_relying_party_is_neither_ssh_nor_a_web_origin() {
    // OpenSSH's tools and the SSH side of a load look at `ssh:` only, and a
    // relying party id with a colon can't be a web origin's.
    assert!(!AGE_RP_ID.starts_with("ssh:"));
    assert!(AGE_RP_ID.contains(':'));
}
