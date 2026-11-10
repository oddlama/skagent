//! Resident credential metadata validation and redaction.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_fido::ResidentCredential;

#[test]
fn ssh_metadata_preserves_protection_and_hides_handles_in_debug() -> Result<()> {
    for protection in 0..=3 {
        let key = ResidentCredential::new(
            "ssh:work".to_owned(),
            &[42; 32],
            b"sensitive-handle".to_vec(),
            protection,
            "alice".to_owned(),
        )?;
        ensure!(key.requires_pin() == (protection == 3));
        ensure!(key.public_key() == &[42; 32]);
        ensure!(key.key_handle() == b"sensitive-handle");
        ensure!(!format!("{key:?}").contains("sensitive-handle"));
    }
    Ok(())
}

#[test]
fn invalid_metadata_is_refused() {
    for application in ["", "example.com", "ssh", "ssh:\0bad"] {
        assert!(
            ResidentCredential::new(application.to_owned(), &[42; 32], vec![1], 3, String::new())
                .is_err()
        );
    }
    for length in [0, 31, 33] {
        assert!(
            ResidentCredential::new(
                "ssh:".to_owned(),
                &vec![42; length],
                vec![1],
                3,
                String::new()
            )
            .is_err()
        );
    }
    for length in [0, 1025] {
        assert!(
            ResidentCredential::new(
                "ssh:".to_owned(),
                &[42; 32],
                vec![1; length],
                3,
                String::new()
            )
            .is_err()
        );
    }
    for protection in [-1, 4, 256] {
        assert!(
            ResidentCredential::new(
                "ssh:".to_owned(),
                &[42; 32],
                vec![1],
                protection,
                String::new()
            )
            .is_err()
        );
    }
}
