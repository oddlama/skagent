//! The OpenSSH encoding of signatures from the security key.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent::signer::ssh_signature;
use skagent_fido::Statement;
use ssh_agent_lib::ssh_key::Algorithm;

#[test]
fn signature_is_followed_by_flags_and_big_endian_counter() -> Result<()> {
    let signature = ssh_signature(&Statement {
        signature: vec![0xaa; 64],
        flags: 0x05,
        counter: 0x0102_0304,
    })?;
    ensure!(signature.algorithm() == Algorithm::SkEd25519);
    let mut expected = vec![0xaa; 64];
    expected.extend_from_slice(&[0x05, 0x01, 0x02, 0x03, 0x04]);
    ensure!(
        signature.as_bytes() == expected.as_slice(),
        "{:?}",
        signature.as_bytes()
    );
    Ok(())
}

#[test]
fn signatures_of_the_wrong_length_are_refused() {
    for length in [0, 63, 65, 72] {
        let result = ssh_signature(&Statement {
            signature: vec![0; length],
            flags: 0x05,
            counter: 1,
        });
        assert!(result.is_err(), "{length}-byte signature accepted");
    }
}
