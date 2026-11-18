//! Shared helpers for the integration tests: the fixtures in `tests/data`
//! and a strict reader for age headers. Every test file is its own crate and
//! uses only part of this module.
#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use skagent_age::{Recipient, Seed};

/// A file of `tests/data`.
pub fn data(name: &str) -> Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

/// A text file of `tests/data`.
pub fn text(name: &str) -> Result<String> {
    String::from_utf8(data(name)?).with_context(|| format!("{name} isn't UTF-8"))
}

/// Decodes hexadecimal digits.
pub fn hex(digits: &str) -> Result<Vec<u8>> {
    ensure!(
        digits.len().is_multiple_of(2),
        "an odd number of hex digits"
    );
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).context("hex digits aren't ASCII")?;
            u8::from_str_radix(pair, 16).with_context(|| format!("{pair:?} isn't hex"))
        })
        .collect()
}

/// The seed inside a native `AGE-SECRET-KEY-PQ-1…` identity.
pub fn native_seed(identity: &str) -> Result<Seed> {
    let (prefix, seed) =
        bech32::decode(identity).map_err(|error| anyhow!("decoding {identity}: {error}"))?;
    ensure!(
        prefix.as_str() == "AGE-SECRET-KEY-PQ-",
        "{identity} is no native post-quantum identity"
    );
    Seed::from_bytes(&seed)
}

/// The example of the age specification: its identity's seed, and the
/// recipient the specification gives for it.
pub fn spec_example() -> Result<(Seed, String)> {
    let example = text("spec-example.txt")?;
    let mut lines = example.lines();
    let identity = lines.next().context("no identity line")?;
    let recipient = lines.next().context("no recipient line")?;
    Ok((native_seed(identity)?, recipient.to_owned()))
}

/// The recipient of the specification's example.
pub fn spec_recipient() -> Result<Recipient> {
    spec_example()?.1.parse()
}

/// One recipient stanza of a header: its arguments and its decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderStanza {
    pub arguments: Vec<String>,
    pub body: Vec<u8>,
}

/// Reads the recipient stanzas of an age file, as strictly as the
/// specification's grammar: the version line, stanzas whose body lines are
/// 64 columns except the last, canonical unpadded base64, and the line that
/// starts the MAC. What follows the header isn't looked at.
pub fn read_header(file: &[u8]) -> Result<Vec<HeaderStanza>> {
    let mut lines = file.split(|&byte| byte == b'\n').map(|line| {
        std::str::from_utf8(line)
            .ok()
            .filter(|line| line.bytes().all(|byte| (0x20..0x7f).contains(&byte)))
            .context("a header line isn't printable ASCII")
    });
    let mut next = || lines.next().context("the header ends early")?;

    ensure!(next()? == "age-encryption.org/v1", "no version line");
    let mut stanzas = Vec::new();
    let mut line = next()?;
    loop {
        if line.starts_with("---") {
            ensure!(!stanzas.is_empty(), "a header without stanzas");
            return Ok(stanzas);
        }
        let Some(arguments) = line.strip_prefix("-> ") else {
            bail!("expected a stanza, found {line:?}");
        };
        let arguments: Vec<String> = arguments.split(' ').map(str::to_owned).collect();
        ensure!(
            arguments
                .iter()
                .all(|argument| !argument.is_empty() && argument.bytes().all(|byte| byte > 0x20)),
            "an empty or malformed argument in {line:?}"
        );
        let mut encoded = String::new();
        loop {
            let body_line = next()?;
            ensure!(body_line.len() <= 64, "a body line of more than 64 columns");
            encoded.push_str(body_line);
            if body_line.len() < 64 {
                break;
            }
        }
        let body = STANDARD_NO_PAD
            .decode(&encoded)
            .ok()
            .context("a stanza body isn't canonical base64")?;
        stanzas.push(HeaderStanza { arguments, body });
        line = next()?;
    }
}
