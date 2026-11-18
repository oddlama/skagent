//! The pairing challenge: only the paired key's signature over this
//! challenge, as a FIDO assertion signs it, counts.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use skagent::pairing::{challenge, verify};
use skagent_fido::{PAIRING_RP_ID, PairingCredential, Statement};

const CHALLENGE: [u8; 32] = [5; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pairing(key: &SigningKey) -> PairingCredential {
    PairingCredential {
        id: vec![1; 16],
        public_key: key.verifying_key().to_bytes(),
    }
}

/// What a security key holding `key` answers: a signature over its
/// authenticator data (relying party hash, flags, counter) and the challenge.
fn answer(key: &SigningKey, rp_id: &str, challenge: &[u8; 32]) -> Statement {
    let (flags, counter) = (0x00, 7_u32);
    let mut message = Sha256::digest(rp_id.as_bytes()).to_vec();
    message.push(flags);
    message.extend_from_slice(&counter.to_be_bytes());
    message.extend_from_slice(challenge);
    Statement {
        signature: key.sign(&message).to_bytes().to_vec(),
        flags,
        counter,
    }
}

#[test]
fn the_paired_keys_answer_verifies() {
    let paired = key(3);
    let statement = answer(&paired, PAIRING_RP_ID, &CHALLENGE);
    assert!(verify(&pairing(&paired), &CHALLENGE, &statement));
}

#[test]
fn nothing_else_verifies() {
    let paired = key(3);
    let statement = answer(&paired, PAIRING_RP_ID, &CHALLENGE);
    // Another key, an old challenge, another relying party.
    assert!(!verify(&pairing(&key(4)), &CHALLENGE, &statement));
    assert!(!verify(&pairing(&paired), &[6; 32], &statement));
    let elsewhere = answer(&paired, "ssh:", &CHALLENGE);
    assert!(!verify(&pairing(&paired), &CHALLENGE, &elsewhere));
    // Flags or counter that weren't signed.
    let tampered = Statement {
        counter: 8,
        ..statement.clone()
    };
    assert!(!verify(&pairing(&paired), &CHALLENGE, &tampered));
    let tampered = Statement {
        flags: 0x01,
        ..statement.clone()
    };
    assert!(!verify(&pairing(&paired), &CHALLENGE, &tampered));
    let garbage = Statement {
        signature: vec![0; 10],
        ..statement
    };
    assert!(!verify(&pairing(&paired), &CHALLENGE, &garbage));
}

#[test]
fn challenges_are_fresh() -> Result<()> {
    let (first, second) = (challenge()?, challenge()?);
    ensure!(first != second && first != [0; 32]);
    Ok(())
}
