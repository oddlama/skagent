//! Bech32 as age uses it: the original checksum (not Bech32m), without
//! BIP-173's limit of 90 characters. A recipient has almost 2000.

use anyhow::{Context as _, Result, anyhow, bail};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Checksum, Hrp};

/// The Bech32 checksum over strings of any length we produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LongBech32 {}

impl Checksum for LongBech32 {
    type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
    /// Far above a recipient's 1959 characters. The checksum only detects
    /// errors reliably in short strings; age accepts that, and so do we.
    const CODE_LENGTH: usize = 8192;
    const CHECKSUM_LENGTH: usize = <Bech32 as Checksum>::CHECKSUM_LENGTH;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = <Bech32 as Checksum>::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = <Bech32 as Checksum>::TARGET_RESIDUE;
}

/// Whether `prefix` is written in capitals, like age's identities.
fn is_upper(prefix: &str) -> bool {
    !prefix
        .chars()
        .any(|character| character.is_ascii_lowercase())
}

/// Encodes `data` after `prefix`, in the case of `prefix`.
pub(crate) fn encode(prefix: &str, data: &[u8]) -> Result<String> {
    let hrp = Hrp::parse(prefix).map_err(|error| anyhow!("Bech32 prefix {prefix:?}: {error}"))?;
    let encoded = if is_upper(prefix) {
        bech32::encode_upper::<LongBech32>(hrp, data)
    } else {
        bech32::encode_lower::<LongBech32>(hrp, data)
    };
    encoded.map_err(|error| anyhow!("encoding {} bytes as Bech32: {error}", data.len()))
}

/// Decodes `text`, which must start with exactly `prefix` (age's prefixes
/// are case-sensitive: `age1pq` is a recipient, `AGE1PQ` is nothing).
pub(crate) fn decode(prefix: &str, text: &str) -> Result<Vec<u8>> {
    let Some(rest) = text.strip_prefix(prefix) else {
        bail!("doesn't start with {prefix}1");
    };
    if !rest.starts_with('1') {
        bail!("doesn't start with {prefix}1");
    }
    let checked = CheckedHrpstring::new::<LongBech32>(text)
        .map_err(|error| anyhow!("not valid Bech32: {error}"))?;
    let data: Vec<u8> = checked.byte_iter().collect();
    // Encoding again with `prefix` must give the same string. That refuses a
    // second spelling of the same data (Bech32 pads the last character, and
    // the decoder drops leftover bits), and a string whose real prefix is
    // longer: Bech32's separator is the last `1`, not the first.
    let canonical = encode(prefix, &data).context("encoding again")?;
    if canonical != text {
        bail!("not in canonical form");
    }
    Ok(data)
}
