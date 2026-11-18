//! From a security key's answer to the seed. These values decide every
//! identity's recipient: changing one would orphan every encrypted file.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Result, ensure};
use skagent_age::{
    BATCH_SALT_LABEL, DEVICE_OUTPUT_BYTES, FILE_KEY_BYTES, FileKey, SEED_BYTES, Seed, batch_salt,
};
use skagent_secret::SecretBuffer;

#[test]
fn the_salt_is_the_sha256_of_its_label() -> Result<()> {
    // `printf %s skagent/age/v1/batch | sha256sum`
    ensure!(BATCH_SALT_LABEL == "skagent/age/v1/batch");
    ensure!(
        batch_salt().as_slice()
            == support::hex("4a5556e0bb188d92a3b8b0b8c5bc380097fc9b6af977a3606d7d1c8949b30dc8")?
    );
    Ok(())
}

#[test]
fn the_seed_is_derived_not_the_answer_itself() -> Result<()> {
    let answer = SecretBuffer::from_slice(&[5; DEVICE_OUTPUT_BYTES])?;
    let derived = Seed::from_device_output(&answer)?.recipient()?;
    ensure!(
        derived == Seed::from_device_output(&answer)?.recipient()?,
        "not deterministic"
    );
    ensure!(
        derived != Seed::from_bytes(answer.expose())?.recipient()?,
        "the answer is the seed"
    );

    let other = SecretBuffer::from_slice(&[6; DEVICE_OUTPUT_BYTES])?;
    ensure!(derived != Seed::from_device_output(&other)?.recipient()?);
    Ok(())
}

#[test]
fn answers_seeds_and_file_keys_have_one_size_each() -> Result<()> {
    for length in [1, 16, 31, 33, 64] {
        let answer = SecretBuffer::from_slice(&vec![5; length])?;
        ensure!(
            Seed::from_device_output(&answer).is_err(),
            "answer of {length}"
        );
        ensure!(
            Seed::from_bytes(&vec![5; length]).is_err(),
            "seed of {length}"
        );
    }
    ensure!(Seed::from_bytes(&[]).is_err());
    ensure!(Seed::from_bytes(&[5; SEED_BYTES]).is_ok());

    for length in [0, 15, 17, 25, 32] {
        ensure!(
            FileKey::from_bytes(&vec![5; length]).is_err(),
            "file key of {length}"
        );
    }
    ensure!(FileKey::from_bytes(&[5; FILE_KEY_BYTES])?.expose() == [5; FILE_KEY_BYTES]);
    Ok(())
}
