//! The OpenSSH encoding of signatures from the security key, and checking
//! them against the identity before they leave the agent.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use signature::Signer as _;
use skagent::identities::SkIdentity;
use skagent::signer::{ssh_signature, verified_signature};
use skagent_fido::Statement;
use ssh_agent_lib::ssh_key::sha2::{Digest as _, Sha256};
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use support::{rfc8032_keypair, rfc8032_sk_public, sk_credential_with, sk_public};

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

const FLAGS: u8 = 0x05;
const COUNTER: u32 = 7;

/// What an authenticator holding the RFC 8032 key returns for `data`: an
/// Ed25519 signature over SHA-256(application) ‖ flags ‖ counter ‖
/// SHA-256(data).
fn statement_for(data: &[u8]) -> Result<Statement> {
    let mut signed = Sha256::digest("ssh:example").to_vec();
    signed.push(FLAGS);
    signed.extend_from_slice(&COUNTER.to_be_bytes());
    signed.extend_from_slice(&Sha256::digest(data));
    let signature: Signature = rfc8032_keypair()
        .try_sign(&signed)
        .context("signing like the authenticator")?;
    Ok(Statement {
        signature: signature.as_bytes().to_vec(),
        flags: FLAGS,
        counter: COUNTER,
    })
}

fn identity(public: ssh_agent_lib::ssh_key::public::SkEd25519) -> Result<SkIdentity> {
    SkIdentity::from_credential(sk_credential_with(public, 1, "key")?, None)
}

#[test]
fn the_identitys_own_signature_is_returned() -> Result<()> {
    let statement = statement_for(b"data")?;
    let signature = verified_signature(&identity(rfc8032_sk_public())?, b"data", &statement)?;
    ensure!(signature == ssh_signature(&statement)?);
    Ok(())
}

#[test]
fn a_signature_for_another_public_key_is_refused() -> Result<()> {
    // An identity whose key handle belongs to the RFC 8032 key, but which
    // claims another public key: the device signs, the agent must not hand
    // that signature out (or cache the PIN that produced it).
    let impostor = identity(sk_public(2))?;
    ensure!(verified_signature(&impostor, b"data", &statement_for(b"data")?).is_err());
    Ok(())
}

#[test]
fn a_signature_over_other_data_is_refused() -> Result<()> {
    let real = identity(rfc8032_sk_public())?;
    ensure!(verified_signature(&real, b"other", &statement_for(b"data")?).is_err());
    Ok(())
}
