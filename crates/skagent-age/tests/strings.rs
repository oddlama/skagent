//! Recipient and identity strings.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, anyhow, ensure};
use bech32::primitives::iter::Fe32IterExt as _;
use bech32::{Bech32, Fe32, Hrp};
use skagent_age::{Identity, PLUGIN_NAME, RECIPIENT_BYTES, Recipient};

#[test]
fn the_specifications_example_identity_has_its_recipient() -> Result<()> {
    let (seed, expected) = support::spec_example()?;
    let recipient = seed.recipient()?;
    ensure!(recipient.to_string() == expected);
    ensure!(expected.len() == 1959);

    let parsed: Recipient = expected.parse()?;
    ensure!(parsed == recipient);
    ensure!(parsed.as_bytes().len() == RECIPIENT_BYTES);
    ensure!(Recipient::from_bytes(parsed.as_bytes())? == recipient);
    Ok(())
}

#[test]
fn a_recipient_is_shown_by_its_ends() -> Result<()> {
    let (_, full) = support::spec_example()?;
    let recipient: Recipient = full.parse()?;
    let short = recipient.abbreviated();
    ensure!(short == "age1pq1x34nzs…fzv49zc0k", "{short}");
    let debug = format!("{recipient:?}");
    ensure!(debug == format!("Recipient({short})"), "{debug}");
    Ok(())
}

#[test]
fn only_canonical_lowercase_recipient_strings_parse() -> Result<()> {
    let (_, good) = support::spec_example()?;

    // age's prefixes are case-sensitive, and Bech32 forbids mixed case.
    let upper = good.to_uppercase();
    ensure!(upper.parse::<Recipient>().is_err(), "uppercase");
    let mixed = good.replacen("age1pq1x", "age1pq1X", 1);
    ensure!(mixed.parse::<Recipient>().is_err(), "mixed case");

    // One character changed: the checksum.
    let last = good.chars().last().context("empty")?;
    let replacement = if last == 'q' { 'p' } else { 'q' };
    let mut damaged: String = good.chars().take(good.len().saturating_sub(1)).collect();
    damaged.push(replacement);
    ensure!(damaged.parse::<Recipient>().is_err(), "bad checksum");

    for other in [
        "",
        "age1pq",
        "age1pq1",
        // A classic recipient, and another plugin's.
        "age1dnljckavy0lz98s672faeh6rg62yu7qpgrx254yy7dxcnkaluvmq2erktc",
        "age1yubikey1qgf2k486ctg6rs66mlm6wudwcwg6r5h5jme2cr3ympluyjl84dgk",
    ] {
        ensure!(other.parse::<Recipient>().is_err(), "{other:?} accepted");
    }
    Ok(())
}

#[test]
fn recipients_of_the_wrong_size_or_with_a_bad_key_are_refused() -> Result<()> {
    let good = support::spec_recipient()?;
    let bytes = good.as_bytes().as_slice();
    ensure!(Recipient::from_bytes(bytes.get(1..).context("slice")?).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    ensure!(Recipient::from_bytes(&longer).is_err());

    // The X25519 part (the last 32 bytes) as the point of order one: every
    // sender would share the same, all-zero secret with it.
    let mut low_order = bytes.to_vec();
    let start = low_order.len().checked_sub(32).context("short")?;
    low_order.get_mut(start..).context("tail")?.fill(0);
    ensure!(Recipient::from_bytes(&low_order).is_err(), "low order");

    // An ML-KEM encapsulation key holds numbers below 3329 in 12 bits each;
    // all ones isn't one, so it doesn't decode to itself.
    let mut not_reduced = bytes.to_vec();
    not_reduced.get_mut(..2).context("head")?.fill(0xff);
    ensure!(Recipient::from_bytes(&not_reduced).is_err(), "not reduced");
    Ok(())
}

#[test]
fn the_identity_without_data_is_what_age_sends_for_dash_j() -> Result<()> {
    // `age -d -j skagent` hands this string to the plugin (age 1.3.2).
    const FROM_AGE: &str = "AGE-PLUGIN-SKAGENT-1W3SFA8";
    ensure!(Identity::AtHand.to_string() == FROM_AGE);
    ensure!(FROM_AGE.parse::<Identity>()? == Identity::AtHand);
    ensure!(Identity::from_data(&[])? == Identity::AtHand);
    ensure!(Identity::AtHand.recipient().is_none());
    ensure!(FROM_AGE.starts_with(&format!("AGE-PLUGIN-{}-1", PLUGIN_NAME.to_uppercase())));
    Ok(())
}

#[test]
fn a_named_identity_carries_its_recipient() -> Result<()> {
    let recipient = support::spec_recipient()?;
    let identity = Identity::Named(recipient.clone());
    let text = identity.to_string();
    ensure!(text.starts_with("AGE-PLUGIN-SKAGENT-1"));
    ensure!(
        text == text.to_uppercase(),
        "identities are written in capitals"
    );
    ensure!(text.parse::<Identity>()? == identity);
    ensure!(identity.recipient() == Some(&recipient));

    let data = identity.to_data();
    ensure!(data.len() == RECIPIENT_BYTES.saturating_add(1));
    ensure!(data.first() == Some(&1), "version");
    ensure!(Identity::from_data(&data)? == identity);
    Ok(())
}

#[test]
fn identities_this_code_doesnt_know_are_refused() -> Result<()> {
    let recipient = support::spec_recipient()?;
    let mut data = Identity::Named(recipient).to_data();

    // A later version, with whatever it carries.
    *data.first_mut().context("empty")? = 2;
    let error = Identity::from_data(&data)
        .err()
        .context("version 2 accepted")?;
    ensure!(format!("{error:#}").contains("newer"), "{error:#}");
    ensure!(Identity::from_data(&[0]).is_err(), "version 0");

    // The right version with a recipient cut short.
    *data.first_mut().context("empty")? = 1;
    data.pop();
    ensure!(Identity::from_data(&data).is_err(), "truncated");
    ensure!(Identity::from_data(&[1]).is_err(), "no recipient");

    for other in [
        "",
        "AGE-PLUGIN-SKAGENT-1",
        "age-plugin-skagent-1w3sfa8",
        "AGE-PLUGIN-YUBIKEY-16CFWSQYZC6JFAUGPQESMC",
        "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR",
    ] {
        ensure!(other.parse::<Identity>().is_err(), "{other:?} accepted");
    }
    Ok(())
}

#[test]
fn a_string_has_one_spelling() -> Result<()> {
    // Bech32 writes five bits per character. A decoder that drops leftover
    // bits reads `Q` (five zero bits) as no bytes at all, so this string
    // would be a second spelling of the identity without data.
    let prefix = Hrp::parse("AGE-PLUGIN-SKAGENT-").map_err(|error| anyhow!("{error}"))?;
    let padded: String = [Fe32::Q]
        .into_iter()
        .with_checksum::<Bech32>(&prefix)
        .chars()
        .collect::<String>()
        .to_uppercase();
    ensure!(padded.starts_with("AGE-PLUGIN-SKAGENT-1Q"), "{padded}");
    ensure!(padded.parse::<Identity>().is_err(), "{padded} accepted");
    Ok(())
}

#[test]
fn the_prefix_ends_at_the_last_separator() -> Result<()> {
    // Bech32's separator is the last `1`. This string starts like an identity
    // of ours, but its prefix is longer, and it holds no data: taking it for
    // ours would read it as the identity at hand.
    let longer = Hrp::parse("AGE-PLUGIN-SKAGENT-1QQ").map_err(|error| anyhow!("{error}"))?;
    let other = bech32::encode_upper::<Bech32>(longer, &[]).map_err(|error| anyhow!("{error}"))?;
    ensure!(other.starts_with("AGE-PLUGIN-SKAGENT-1QQ1"), "{other}");
    ensure!(other.parse::<Identity>().is_err(), "{other} accepted");
    Ok(())
}
