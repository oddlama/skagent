//! age's own test vectors for the `mlkem768x25519` recipient (C2SP/CCTV),
//! and a file stock age wrote for a recipient derived the way a security
//! key's answer is.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age::{FileKey, Seed, Stanza};
use skagent_secret::SecretBuffer;

/// What a vector says about decrypting its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Success,
    NoMatch,
    HeaderFailure,
}

struct Vector {
    expect: Expect,
    file_key: Vec<u8>,
    seed: Seed,
    file: Vec<u8>,
}

/// Reads a CCTV test file: `key: value` lines, an empty line, the age file.
fn vector(name: &str) -> Result<Vector> {
    let content = support::data(&format!("cctv/{name}"))?;
    let split = content
        .windows(2)
        .position(|window| window == b"\n\n")
        .context("no empty line after the test's header")?;
    let (header, file) = content.split_at_checked(split).context("split")?;
    let file = file.get(2..).context("no age file")?.to_vec();
    let header = std::str::from_utf8(header).context("the test's header isn't UTF-8")?;

    let mut expect = None;
    let mut file_key = None;
    let mut seed = None;
    for line in header.lines() {
        let (key, value) = line.split_once(": ").context("not a `key: value` line")?;
        match key {
            "expect" => {
                expect = Some(match value {
                    "success" => Expect::Success,
                    "no match" => Expect::NoMatch,
                    "header failure" => Expect::HeaderFailure,
                    other => bail!("{name}: unexpected `expect: {other}`"),
                });
            }
            "file key" => file_key = Some(support::hex(value)?),
            "identity" if value.starts_with("AGE-SECRET-KEY-PQ-1") => {
                seed = Some(support::native_seed(value)?);
            }
            _ => {}
        }
    }
    Ok(Vector {
        expect: expect.context("no `expect`")?,
        file_key: file_key.context("no `file key`")?,
        seed: seed.context("no post-quantum identity")?,
        file,
    })
}

/// What decrypting does with our code: reads the header, keeps the stanzas
/// that are ours, and unwraps with the identity.
fn unwrap(vector: &Vector) -> Result<Option<FileKey>> {
    let mut stanzas = Vec::new();
    for stanza in support::read_header(&vector.file)? {
        if let Some(stanza) = Stanza::from_header(&stanza.arguments, &stanza.body)? {
            stanzas.push(stanza);
        }
    }
    vector.seed.unwrap(&stanzas)
}

#[test]
fn files_for_the_identity_give_their_file_key() -> Result<()> {
    for name in ["hybrid", "hybrid_and_x25519", "hybrid_grease"] {
        let vector = vector(name)?;
        ensure!(vector.expect == Expect::Success, "{name}");
        let file_key = unwrap(&vector)?.with_context(|| format!("{name}: no match"))?;
        ensure!(
            file_key.expose() == vector.file_key,
            "{name}: wrong file key"
        );
    }
    Ok(())
}

#[test]
fn files_that_dont_authenticate_are_no_match_and_no_error() -> Result<()> {
    for name in [
        "hybrid_bad_tag",
        "hybrid_currupted_enc_mlkem",
        "hybrid_currupted_enc_x25519",
        "hybrid_no_match",
        // The type is case-sensitive: `MLKEM768X25519` is another type.
        "hybrid_uppercase",
    ] {
        let vector = vector(name)?;
        ensure!(vector.expect == Expect::NoMatch, "{name}");
        ensure!(unwrap(&vector)?.is_none(), "{name}: a file key came out");
    }
    Ok(())
}

#[test]
fn malformed_stanzas_are_refused() -> Result<()> {
    for name in [
        "hybrid_extra_argument",
        // The X25519 part of `enc` is the identity or another low-order point.
        "hybrid_identity",
        "hybrid_low_order",
        // 25 bytes of file key: the body's length is checked before decrypting.
        "hybrid_long_file_key",
        "hybrid_long_share",
        "hybrid_short_share",
        "hybrid_not_canonical_enc",
        "hybrid_not_canonical_body",
    ] {
        let vector = vector(name)?;
        ensure!(vector.expect == Expect::HeaderFailure, "{name}");
        ensure!(unwrap(&vector).is_err(), "{name}: accepted");
    }
    Ok(())
}

#[test]
fn a_stanza_of_another_type_is_ignored_whatever_it_holds() -> Result<()> {
    // An X25519 stanza with an `enc` of our size. It fails the header for an
    // X25519 identity; ours has to ignore stanzas of other types.
    let vector = vector("hybrid_x25519_arg")?;
    ensure!(vector.expect == Expect::HeaderFailure);
    ensure!(unwrap(&vector)?.is_none());
    Ok(())
}

#[test]
fn stock_age_encrypts_to_what_a_security_keys_answer_derives() -> Result<()> {
    // The answer `00 01 … 1f`; `tests/data/README.md` says how the recipient
    // and the file were made without this crate.
    let answer: Vec<u8> = (0..32).collect();
    let seed = Seed::from_device_output(&SecretBuffer::from_slice(&answer)?)?;
    let expected = support::text("derived-recipient.txt")?;
    ensure!(
        seed.recipient()?.to_string() == expected.trim_end(),
        "the derivation changed: every identity would get another recipient"
    );

    let mut stanzas = Vec::new();
    for stanza in support::read_header(&support::data("stock-age-to-derived.age")?)? {
        stanzas.extend(Stanza::from_header(&stanza.arguments, &stanza.body)?);
    }
    ensure!(stanzas.len() == 1, "{} stanzas", stanzas.len());
    let file_key = seed
        .unwrap(&stanzas)?
        .context("stock age's stanza didn't open")?;
    ensure!(file_key.expose().len() == 16);

    // Another answer is another identity.
    let other = Seed::from_device_output(&SecretBuffer::from_slice(&[7; 32])?)?;
    ensure!(other.unwrap(&stanzas)?.is_none());
    Ok(())
}
