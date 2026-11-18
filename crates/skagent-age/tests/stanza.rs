//! Stanzas: what is accepted from a header, the form sent to the agent, and
//! wrapping and unwrapping.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use skagent_age::{
    BODY_BYTES, ENC_BYTES, FILE_KEY_BYTES, FileKey, POSTQUANTUM_LABEL, STANZA_BYTES, STANZA_TYPE,
    Seed, Stanza, WRAP_RANDOM_BYTES,
};

/// A stanza for the specification's example identity.
fn wrapped(file_key: &[u8; FILE_KEY_BYTES], randomness: u8) -> Result<Stanza> {
    support::spec_recipient()?.wrap(
        &FileKey::from_bytes(file_key)?,
        &[randomness; WRAP_RANDOM_BYTES],
    )
}

fn arguments(stanza: &Stanza) -> Vec<String> {
    vec![STANZA_TYPE.to_owned(), stanza.enc_argument()]
}

#[test]
fn the_names_are_ages() {
    assert_eq!(STANZA_TYPE, "mlkem768x25519");
    assert_eq!(POSTQUANTUM_LABEL, "postquantum");
    assert_eq!((ENC_BYTES, BODY_BYTES, STANZA_BYTES), (1120, 32, 1152));
}

#[test]
fn a_wrapped_file_key_comes_back_for_its_identity_only() -> Result<()> {
    let (seed, _) = support::spec_example()?;
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let stanzas = [stanza];
    let file_key = seed.unwrap(&stanzas)?.context("no match")?;
    ensure!(file_key.expose() == b"0123456789abcdef");

    let stranger = Seed::from_bytes(&[9; 32])?;
    ensure!(stranger.unwrap(&stanzas)?.is_none());
    ensure!(seed.unwrap(&[])?.is_none(), "no stanzas");
    Ok(())
}

#[test]
fn randomness_changes_the_stanza_not_the_file_key() -> Result<()> {
    let (seed, _) = support::spec_example()?;
    let first = wrapped(b"0123456789abcdef", 1)?;
    let second = wrapped(b"0123456789abcdef", 2)?;
    ensure!(first != second);
    ensure!(first.enc() != second.enc() && first.body() != second.body());
    for stanza in [first, second] {
        let file_key = seed.unwrap(&[stanza])?.context("no match")?;
        ensure!(file_key.expose() == b"0123456789abcdef");
    }
    Ok(())
}

#[test]
fn one_call_gives_one_file_key_the_first_that_opens() -> Result<()> {
    // Stanzas of two files in one request: a requester gets the first file's
    // key and nothing of the second.
    let (seed, _) = support::spec_example()?;
    let stranger = Seed::from_bytes(&[9; 32])?
        .recipient()?
        .wrap(&FileKey::from_bytes(b"someone else's!!")?, &[3; 64])?;
    let first_file = wrapped(b"first file's key", 1)?;
    let second_file = wrapped(b"second file key!", 2)?;

    let file_key = seed
        .unwrap(&[stranger.clone(), first_file.clone(), second_file.clone()])?
        .context("no match")?;
    ensure!(file_key.expose() == b"first file's key");
    let file_key = seed
        .unwrap(&[second_file, stranger, first_file])?
        .context("no match")?;
    ensure!(file_key.expose() == b"second file key!");
    Ok(())
}

#[test]
fn a_header_stanza_round_trips() -> Result<()> {
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let read = Stanza::from_header(&arguments(&stanza), stanza.body())?.context("ignored")?;
    ensure!(read == stanza);
    ensure!(stanza.enc_argument().len() == 1494, "1120 bytes in base64");
    ensure!(!stanza.enc_argument().ends_with('='), "unpadded");
    Ok(())
}

#[test]
fn stanzas_of_other_types_are_ignored_not_refused() -> Result<()> {
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let enc = stanza.enc_argument();
    for kind in [
        "X25519",
        "MLKEM768X25519",
        "mlkem768p256tag",
        "scrypt",
        "grease",
    ] {
        // Even with our arguments, or with none, or with a body of any size.
        ensure!(Stanza::from_header(&[kind, enc.as_str()], stanza.body())?.is_none());
        ensure!(Stanza::from_header(&[kind], &[])?.is_none());
        ensure!(Stanza::from_header(&[kind, "a", "b", "c"], &[1; 100])?.is_none());
    }
    ensure!(Stanza::from_header::<&str>(&[], &[]).is_err(), "no type");
    Ok(())
}

#[test]
fn malformed_stanzas_of_our_type_are_refused() -> Result<()> {
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let enc = stanza.enc_argument();
    let body = stanza.body().as_slice();
    let refused = |arguments: &[&str], body: &[u8]| Stanza::from_header(arguments, body).is_err();

    ensure!(refused(&[STANZA_TYPE], body), "no enc");
    ensure!(
        refused(&[STANZA_TYPE, &enc, "extra"], body),
        "extra argument"
    );
    ensure!(refused(&[STANZA_TYPE, &enc, &enc], body), "enc twice");

    // The body: 16 bytes of file key and a tag, checked before decrypting.
    for length in [0, 16, 31, 33, 41, 64] {
        ensure!(
            refused(&[STANZA_TYPE, &enc], &vec![0; length]),
            "body of {length}"
        );
    }

    // `enc`: canonical unpadded base64 of exactly 1120 bytes.
    let shorter: String = enc.chars().take(enc.len().saturating_sub(4)).collect();
    ensure!(refused(&[STANZA_TYPE, &shorter], body), "short enc");
    ensure!(
        refused(&[STANZA_TYPE, &format!("{enc}AAAA")], body),
        "long enc"
    );
    ensure!(refused(&[STANZA_TYPE, &format!("{enc}=")], body), "padded");
    ensure!(
        refused(&[STANZA_TYPE, &enc.replace('A', "!")], body),
        "not base64"
    );
    ensure!(refused(&[STANZA_TYPE, ""], body), "empty enc");
    // 1120 bytes end in a character that carries two bits; the other four
    // must be zero. `B` instead of the canonical character sets one of them.
    let last = enc.chars().last().context("empty")?;
    let position = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .find(last)
        .context("not base64")?;
    ensure!(
        position % 16 == 0,
        "the canonical last character has four zero bits"
    );
    let mut trailing: String = enc.chars().take(enc.len().saturating_sub(1)).collect();
    trailing.push(if last == 'A' { 'B' } else { 'R' });
    ensure!(refused(&[STANZA_TYPE, &trailing], body), "trailing bits");
    Ok(())
}

#[test]
fn a_low_order_share_is_refused_wherever_a_stanza_comes_from() -> Result<()> {
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    // The X25519 share is the last 32 bytes of `enc`. Zero is the point of
    // order one, and one a point of order four.
    for point in [0_u8, 1] {
        let mut enc = stanza.enc().to_vec();
        let start = enc.len().checked_sub(32).context("short")?;
        let share = enc.get_mut(start..).context("tail")?;
        share.fill(0);
        *share.first_mut().context("empty")? = point;
        ensure!(
            Stanza::from_parts(&enc, stanza.body()).is_err(),
            "from_parts {point}"
        );
        let mut bytes = enc.clone();
        bytes.extend_from_slice(stanza.body());
        ensure!(Stanza::from_bytes(&bytes).is_err(), "from_bytes {point}");
    }
    Ok(())
}

#[test]
fn the_form_sent_to_the_agent_round_trips_and_has_one_size() -> Result<()> {
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let bytes = stanza.to_bytes();
    ensure!(bytes.len() == STANZA_BYTES);
    ensure!(bytes.get(..ENC_BYTES) == Some(stanza.enc().as_slice()));
    ensure!(bytes.get(ENC_BYTES..) == Some(stanza.body().as_slice()));
    ensure!(Stanza::from_bytes(&bytes)? == stanza);

    ensure!(
        Stanza::from_bytes(bytes.get(1..).context("slice")?).is_err(),
        "short"
    );
    let mut longer = bytes.clone();
    longer.push(0);
    ensure!(Stanza::from_bytes(&longer).is_err(), "long");
    ensure!(Stanza::from_bytes(&[]).is_err(), "empty");
    Ok(())
}

#[test]
fn debug_output_shows_no_key_material() -> Result<()> {
    let (seed, _) = support::spec_example()?;
    let file_key = FileKey::from_bytes(b"0123456789abcdef")?;
    ensure!(format!("{seed:?}") == "Seed(<redacted>)");
    ensure!(format!("{file_key:?}") == "FileKey(<redacted>)");
    let stanza = wrapped(b"0123456789abcdef", 1)?;
    let shown = format!("{stanza:?}");
    ensure!(shown.len() < 80, "{shown}");
    Ok(())
}
