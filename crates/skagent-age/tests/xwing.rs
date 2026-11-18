//! X-Wing against the test vectors of draft-connolly-cfrg-xwing-kem-10,
//! through the public interface: a seed's recipient is the vector's public
//! key, and wrapping with the vector's randomness gives its ciphertext.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::collections::HashMap;

use anyhow::{Context as _, Result, ensure};
use skagent_age::{ENC_BYTES, FileKey, RECIPIENT_BYTES, Recipient, Seed, WRAP_RANDOM_BYTES};

struct Vector {
    seed: Vec<u8>,
    public_key: Vec<u8>,
    randomness: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn vectors() -> Result<Vec<Vector>> {
    let text = support::text("xwing-draft-10.txt")?;
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let fields: HashMap<&str, &str> = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            let field =
                |name: &str| support::hex(fields.get(name).with_context(|| format!("no {name}"))?);
            Ok(Vector {
                seed: field("seed")?,
                public_key: field("pk")?,
                randomness: field("eseed")?,
                ciphertext: field("ct")?,
            })
        })
        .collect()
}

#[test]
fn a_seed_expands_to_the_drafts_public_key() -> Result<()> {
    let vectors = vectors()?;
    ensure!(vectors.len() == 3, "{} vectors", vectors.len());
    for vector in &vectors {
        ensure!(vector.public_key.len() == RECIPIENT_BYTES);
        let recipient = Seed::from_bytes(&vector.seed)?.recipient()?;
        ensure!(recipient.as_bytes().as_slice() == vector.public_key);
    }
    Ok(())
}

#[test]
fn wrapping_with_the_drafts_randomness_gives_its_ciphertext() -> Result<()> {
    let file_key = FileKey::from_bytes(b"YELLOW SUBMARINE")?;
    for vector in vectors()? {
        ensure!(vector.ciphertext.len() == ENC_BYTES);
        let randomness: [u8; WRAP_RANDOM_BYTES] = vector
            .randomness
            .as_slice()
            .try_into()
            .context("the draft's randomness")?;
        let recipient = Recipient::from_bytes(&vector.public_key)?;
        let stanza = recipient.wrap(&file_key, &randomness)?;
        ensure!(stanza.enc().as_slice() == vector.ciphertext);

        // Both sides arrived at the same shared secret: the seed opens it.
        let opened = Seed::from_bytes(&vector.seed)?
            .unwrap(&[stanza])?
            .context("the seed doesn't open what was wrapped for its recipient")?;
        ensure!(opened.expose() == file_key.expose());
    }
    Ok(())
}
