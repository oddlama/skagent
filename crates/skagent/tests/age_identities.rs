//! What the agent knows about age identities: which one a request is for,
//! and what is remembered across restarts.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use skagent::age::{AgeIdentities, AgeIdentity, NotChosen, default_age_path};
use skagent_age::{Recipient, Seed};
use skagent_fido::AgeCredential;

fn credential(byte: u8) -> Result<AgeCredential> {
    AgeCredential::new(vec![byte; 32])
}

fn recipient(byte: u8) -> Result<Recipient> {
    Seed::from_bytes(&[byte; 32])?.recipient()
}

/// Whether `identity` is the one with `credential(byte)`.
fn is(identity: &AgeIdentity, byte: u8) -> bool {
    identity.credential().id() == [byte; 32]
}

#[test]
fn found_credentials_become_identities_once() -> Result<()> {
    let mut known = AgeIdentities::default();
    ensure!(known.found(&[credential(1)?, credential(2)?]) == 2);
    ensure!(
        known.found(&[credential(2)?, credential(3)?]) == 1,
        "counted a known one"
    );
    ensure!(known.found(&[]) == 0);
    let order: Vec<_> = known
        .all()
        .iter()
        .filter_map(|identity| identity.credential().id().first().copied())
        .collect();
    ensure!(order == [1, 2, 3], "{order:?}");
    ensure!(
        known
            .all()
            .iter()
            .all(|identity| identity.recipient().is_none())
    );
    Ok(())
}

#[test]
fn a_derivation_tells_the_recipient_and_makes_an_identity_known() -> Result<()> {
    let mut known = AgeIdentities::default();
    known.found(&[credential(1)?]);
    known.derived(&credential(1)?, &recipient(1)?);
    known.derived(&credential(2)?, &recipient(2)?);
    ensure!(known.all().len() == 2);
    for (identity, byte) in known.all().iter().zip([1, 2]) {
        ensure!(is(identity, byte) && identity.recipient() == Some(&recipient(byte)?));
    }
    // The key of an identity is its credential under the age relying party.
    let key = format!("{:?}", known.all().first().context("empty")?.key());
    ensure!(key.contains("skagent:age"), "{key}");
    Ok(())
}

#[test]
fn a_request_without_a_name_takes_the_only_identity_or_the_one_at_hand() -> Result<()> {
    let mut known = AgeIdentities::default();
    ensure!(known.choose(None, |_| true) == Err(NotChosen::NoIdentity));

    known.found(&[credential(1)?]);
    // The only one: nobody is asked what is plugged in.
    let chosen = known.choose(None, |_| false).map_err(anyhow::Error::new)?;
    ensure!(is(&chosen, 1));

    known.derived(&credential(2)?, &recipient(2)?);
    ensure!(
        known.choose(None, |_| false) == Err(NotChosen::Ambiguous),
        "none at hand"
    );
    ensure!(
        known.choose(None, |_| true) == Err(NotChosen::Ambiguous),
        "both at hand"
    );
    let chosen = known
        .choose(None, |identity| is(identity, 2))
        .map_err(anyhow::Error::new)?;
    ensure!(is(&chosen, 2));
    Ok(())
}

#[test]
fn a_named_request_takes_its_identity_or_one_that_could_be_it() -> Result<()> {
    let mut known = AgeIdentities::default();
    known.derived(&credential(1)?, &recipient(1)?);
    known.derived(&credential(2)?, &recipient(2)?);

    // Known by its recipient: that one, whatever is plugged in.
    let chosen = known
        .choose(Some(&recipient(2)?), |_| false)
        .map_err(anyhow::Error::new)?;
    ensure!(is(&chosen, 2));
    // Another recipient, and every identity's recipient is known: none fits.
    ensure!(known.choose(Some(&recipient(9)?), |_| true) == Err(NotChosen::NoIdentity));

    // An identity found but never used could be the one named.
    known.found(&[credential(3)?]);
    let chosen = known
        .choose(Some(&recipient(9)?), |_| false)
        .map_err(anyhow::Error::new)?;
    ensure!(is(&chosen, 3));
    // Two of them: the one at hand, else nobody knows.
    known.found(&[credential(4)?]);
    ensure!(known.choose(Some(&recipient(9)?), |_| false) == Err(NotChosen::Ambiguous));
    let chosen = known
        .choose(Some(&recipient(9)?), |identity| is(identity, 4))
        .map_err(anyhow::Error::new)?;
    ensure!(is(&chosen, 4));
    // An identity with a known recipient is never a candidate for another's.
    ensure!(
        known.choose(Some(&recipient(9)?), |identity| is(identity, 1)) == Err(NotChosen::Ambiguous)
    );
    Ok(())
}

#[test]
fn identities_are_remembered_in_a_private_file() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("state").join("age.toml");
    {
        let mut known = AgeIdentities::remembered_in(file.clone());
        ensure!(known.all().is_empty());
        known.found(&[credential(1)?, credential(2)?]);
        known.derived(&credential(2)?, &recipient(2)?);
    }
    let mode = std::fs::metadata(&file)?.permissions().mode() & 0o777;
    ensure!(mode == 0o600, "mode {mode:o}");
    let text = std::fs::read_to_string(&file)?;
    ensure!(text.starts_with("# skagent"), "{text}");
    ensure!(text.matches("[[identity]]").count() == 2, "{text}");
    ensure!(
        text.contains(&format!("credential = \"{}\"", "01".repeat(32))),
        "{text}"
    );
    ensure!(text.matches("recipient = \"age1pq1").count() == 1, "{text}");

    let known = AgeIdentities::remembered_in(file);
    ensure!(known.all().len() == 2);
    let first = known.all().first().context("empty")?;
    let second = known.all().get(1).context("one")?;
    ensure!(is(first, 1) && first.recipient().is_none());
    ensure!(is(second, 2) && second.recipient() == Some(&recipient(2)?));
    Ok(())
}

#[test]
fn a_file_that_cant_be_used_is_ignored_and_replaced() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let good = format!("[[identity]]\ncredential = \"{}\"\n", "01".repeat(32));
    let cases = [
        ("not TOML", "[[identity".to_owned()),
        ("an unknown key", format!("{good}secret = \"x\"\n")),
        ("an unknown table", format!("{good}\n[[other]]\nx = 1\n")),
        (
            "a credential that isn't hex",
            "[[identity]]\ncredential = \"zz\"\n".to_owned(),
        ),
        (
            "an empty credential",
            "[[identity]]\ncredential = \"\"\n".to_owned(),
        ),
        ("a credential twice", format!("{good}\n{good}")),
        (
            "a recipient that isn't one",
            format!("{good}recipient = \"age1pq1qqqq\"\n"),
        ),
    ];
    for (what, content) in cases {
        let file = directory.path().join("age.toml");
        std::fs::write(&file, content)?;
        let mut known = AgeIdentities::remembered_in(file.clone());
        ensure!(known.all().is_empty(), "{what} was used");
        known.found(&[credential(5)?]);
        let known = AgeIdentities::remembered_in(file);
        ensure!(known.all().len() == 1, "{what} wasn't replaced");
    }
    Ok(())
}

#[test]
fn the_file_lives_in_the_state_directory() -> Result<()> {
    ensure!(
        default_age_path(Some(OsStr::new("/state")), Some(OsStr::new("/home/alice")))?
            == Path::new("/state/skagent/age.toml")
    );
    ensure!(
        default_age_path(None, Some(OsStr::new("/home/alice")))?
            == Path::new("/home/alice/.local/state/skagent/age.toml")
    );
    ensure!(default_age_path(None, None).is_err());
    Ok(())
}
