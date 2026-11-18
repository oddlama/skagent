//! Key acceptance, constraint rules and the identity store, with explicit time.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent::identities::{
    AcceptedConstraints, BUILT_IN_SK_PROVIDER, IdentityStore, Origin, SK_PROVIDER_CONSTRAINT,
    SkIdentity, evaluate_constraints,
};
use ssh_agent_lib::proto::{Extension, KeyConstraint, Unparsed};
use support::{
    SK_FLAGS_UP_UV, ed25519_credential, sk_credential, sk_credential_with, sk_key_data, sk_public,
};

fn extension(name: &str, details: &[u8]) -> KeyConstraint {
    KeyConstraint::Extension(Extension {
        name: name.to_owned(),
        details: Unparsed::from(details.to_vec()),
    })
}

fn later(start: Instant, seconds: u64) -> Result<Instant> {
    start
        .checked_add(Duration::from_secs(seconds))
        .context("instant overflow in test")
}

fn identity(seed: u8, comment: &str, expires_at: Option<Instant>) -> Result<SkIdentity> {
    SkIdentity::from_credential(sk_credential(seed, comment)?, expires_at)
}

#[test]
fn what_ssh_add_sends_for_sk_keys_is_accepted() -> Result<()> {
    let accepted = evaluate_constraints(&[
        KeyConstraint::Lifetime(3600),
        extension(SK_PROVIDER_CONSTRAINT, BUILT_IN_SK_PROVIDER),
    ])?;
    ensure!(
        accepted
            == AcceptedConstraints {
                lifetime: Some(Duration::from_secs(3600)),
                destinations: Vec::new(),
            }
    );
    ensure!(evaluate_constraints(&[])? == AcceptedConstraints::default());
    Ok(())
}

#[test]
fn constraints_that_cannot_be_honored_refuse_the_key() {
    let refused = [
        ("confirm", vec![KeyConstraint::Confirm]),
        ("zero lifetime", vec![KeyConstraint::Lifetime(0)]),
        (
            "duplicate lifetime",
            vec![KeyConstraint::Lifetime(10), KeyConstraint::Lifetime(20)],
        ),
        (
            "external provider",
            vec![extension(
                SK_PROVIDER_CONSTRAINT,
                b"/usr/lib/libsk-other.so",
            )],
        ),
        (
            "duplicate provider",
            vec![
                extension(SK_PROVIDER_CONSTRAINT, BUILT_IN_SK_PROVIDER),
                extension(SK_PROVIDER_CONSTRAINT, BUILT_IN_SK_PROVIDER),
            ],
        ),
        (
            "destination restriction without destinations",
            vec![extension("restrict-destination-v00@openssh.com", b"")],
        ),
        (
            "unknown extension",
            vec![extension("whatever@example.com", b"")],
        ),
    ];
    for (case, constraints) in refused {
        assert!(
            evaluate_constraints(&constraints).is_err(),
            "accepted: {case}"
        );
    }
}

#[test]
fn sk_keys_are_taken_apart() -> Result<()> {
    let identity = identity(9, "alice yubikey:1", None)?;
    ensure!(identity.matches(&sk_key_data(9)));
    ensure!(!identity.matches(&sk_key_data(8)));
    ensure!(identity.application() == "ssh:example");
    ensure!(identity.flags() == SK_FLAGS_UP_UV);
    ensure!(identity.key_handle() == [9; 64].as_slice());
    ensure!(identity.comment() == "alice yubikey:1");
    ensure!(identity.fingerprint().starts_with("SHA256:"));
    Ok(())
}

#[test]
fn other_key_types_are_refused() -> Result<()> {
    let error = match SkIdentity::from_credential(ed25519_credential(), None) {
        Ok(identity) => anyhow::bail!("accepted a plain ed25519 key: {identity:?}"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(error.contains("ssh-ed25519"), "unexpected error: {error}");
    Ok(())
}

#[test]
fn debug_shows_no_key_handle_bytes() -> Result<()> {
    let debug = format!("{:?}", identity(0xab, "c", None)?);
    ensure!(debug.contains("key_handle_len: 64"), "{debug}");
    // 0xab = 171, as `Vec<u8>`'s Debug would print it.
    ensure!(
        !debug.contains("171"),
        "key handle bytes in debug output: {debug}"
    );
    Ok(())
}

#[test]
fn store_keeps_insertion_order_and_replaces_duplicates() -> Result<()> {
    let now = Instant::now();
    let mut store = IdentityStore::default();
    ensure!(!store.add(identity(1, "first", None)?, Origin::Local));
    ensure!(!store.add(identity(2, "second", None)?, Origin::Local));
    ensure!(
        store.add(identity(1, "first, renamed", None)?, Origin::Local),
        "duplicate not reported"
    );

    let comments: Vec<&str> = store
        .identities(now)
        .iter()
        .map(SkIdentity::comment)
        .collect();
    ensure!(comments == ["first, renamed", "second"], "{comments:?}");
    Ok(())
}

#[test]
fn store_removes_single_and_all_keys() -> Result<()> {
    let now = Instant::now();
    let mut store = IdentityStore::default();
    store.add(identity(1, "first", None)?, Origin::Local);
    store.add(identity(2, "second", None)?, Origin::Local);

    ensure!(
        store
            .remove(&sk_key_data(1), now)
            .is_some_and(|removed| removed.comment() == "first")
    );
    ensure!(
        store.remove(&sk_key_data(1), now).is_none(),
        "removed twice"
    );
    ensure!(store.find(&sk_key_data(2), now).is_some());
    ensure!(store.clear() == 1);
    ensure!(store.identities(now).is_empty());
    Ok(())
}

#[test]
fn keys_expire_at_their_lifetime() -> Result<()> {
    let start = Instant::now();
    let mut store = IdentityStore::default();
    store.add(
        identity(1, "short", Some(later(start, 10)?))?,
        Origin::Local,
    );
    store.add(identity(2, "forever", None)?, Origin::Local);

    ensure!(store.find(&sk_key_data(1), later(start, 9)?).is_some());
    ensure!(
        store.find(&sk_key_data(1), later(start, 10)?).is_none(),
        "alive at expiry"
    );
    let left: Vec<&str> = store
        .identities(later(start, 10)?)
        .iter()
        .map(SkIdentity::comment)
        .collect();
    ensure!(left == ["forever"], "{left:?}");
    Ok(())
}

#[test]
fn re_adding_resets_the_lifetime() -> Result<()> {
    let start = Instant::now();
    let mut store = IdentityStore::default();
    store.add(identity(1, "k", Some(later(start, 10)?))?, Origin::Local);
    store.add(identity(1, "k", None)?, Origin::Local);
    ensure!(store.find(&sk_key_data(1), later(start, 3600)?).is_some());
    Ok(())
}

#[test]
fn take_expired_hands_out_exactly_the_ended_identities() -> Result<()> {
    let start = Instant::now();
    let mut store = IdentityStore::default();
    store.add(
        identity(1, "short", Some(later(start, 10)?))?,
        Origin::Local,
    );
    store.add(identity(2, "forever", None)?, Origin::Local);
    store.add(
        identity(3, "long", Some(later(start, 100)?))?,
        Origin::Local,
    );

    ensure!(store.take_expired(later(start, 9)?).is_empty());
    let expired = store.take_expired(later(start, 10)?);
    ensure!(
        expired.iter().map(SkIdentity::comment).collect::<Vec<_>>() == ["short"],
        "{expired:?}"
    );
    let remaining: Vec<_> = store
        .identities(later(start, 10)?)
        .iter()
        .map(|identity| identity.comment().to_owned())
        .collect();
    ensure!(remaining == ["forever", "long"], "{remaining:?}");
    ensure!(
        store.take_expired(later(start, 10)?).is_empty(),
        "taken twice"
    );
    Ok(())
}

/// Another public key for the credential (application and key handle) of
/// `handle_seed`'s key, like a key added with a leaked key handle.
fn impostor(public_seed: u8, handle_seed: u8) -> Result<SkIdentity> {
    SkIdentity::from_credential(
        sk_credential_with(sk_public(public_seed), handle_seed, "impostor")?,
        None,
    )
}

#[test]
fn another_public_key_for_a_loaded_credential_is_detected() -> Result<()> {
    let mut store = IdentityStore::default();
    store.add(identity(1, "real", None)?, Origin::Local);

    let shared = store.sharing_credential(&impostor(2, 1)?);
    ensure!(
        shared.is_some_and(|existing| existing.comment() == "real"),
        "a second public key for the same credential went unnoticed"
    );
    ensure!(
        store
            .sharing_credential(&identity(1, "replacement", None)?)
            .is_none(),
        "replacing a key with itself counts as sharing"
    );
    ensure!(
        store
            .sharing_credential(&identity(2, "other", None)?)
            .is_none(),
        "an unrelated key counts as sharing"
    );
    Ok(())
}

#[test]
fn resident_imports_refuse_a_credential_loaded_under_another_key() -> Result<()> {
    let mut store = IdentityStore::default();
    store.add(impostor(2, 1)?, Origin::Local);
    let now = Instant::now();
    ensure!(
        store
            .resident_imports(&[identity(1, "resident", None)?], now)
            .is_err(),
        "a resident key was imported next to another key using its credential"
    );
    Ok(())
}

/// The comments of the keys a store remembered in `file` offers, in order.
fn offered_after_restart(file: &std::path::Path) -> Vec<String> {
    let mut restarted = IdentityStore::remembered_in(file.to_path_buf());
    restarted
        .identities(Instant::now())
        .iter()
        .map(|identity| identity.comment().to_owned())
        .collect()
}

#[test]
fn keys_added_here_are_offered_again_after_a_restart() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("skagent").join("keys.toml");
    let start = Instant::now();
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(identity(1, "work", None)?, Origin::Local);
    store.add(identity(2, "personal", None)?, Origin::Local);
    // A lifetime ends; such a key mustn't outlive it in a file.
    store.add(
        identity(3, "short", Some(later(start, 600)?))?,
        Origin::Local,
    );
    ensure!(offered_after_restart(&file) == ["work", "personal"]);

    let restarted = IdentityStore::remembered_in(file.clone());
    drop(restarted);
    let mode = std::fs::metadata(&file)
        .context("inspecting the file")?
        .permissions()
        .mode()
        & 0o777;
    ensure!(mode == 0o600, "file mode {mode:o}");
    Ok(())
}

#[test]
fn a_forwarded_agent_neither_adds_nor_changes_remembered_keys() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(identity(1, "work", None)?, Origin::Local);
    store.add(identity(1, "renamed remotely", None)?, Origin::Forwarded);
    store.add(identity(2, "planted", None)?, Origin::Forwarded);
    ensure!(offered_after_restart(&file) == ["work"]);
    Ok(())
}

#[test]
fn adding_a_key_again_with_a_lifetime_forgets_it() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(identity(1, "work", None)?, Origin::Local);
    store.add(
        identity(1, "work", Some(later(Instant::now(), 600)?))?,
        Origin::Local,
    );
    ensure!(offered_after_restart(&file).is_empty());
    Ok(())
}

#[test]
fn removed_keys_are_forgotten() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(identity(1, "work", None)?, Origin::Local);
    store.add(identity(2, "personal", None)?, Origin::Local);
    store.add(identity(3, "other", None)?, Origin::Local);
    let work = identity(1, "work", None)?.key_data();
    ensure!(store.remove(&work, Instant::now()).is_some());
    ensure!(offered_after_restart(&file) == ["personal", "other"]);
    store.clear();
    ensure!(offered_after_restart(&file).is_empty());
    Ok(())
}

#[test]
fn remembered_keys_keep_their_handle_flags_and_any_comment() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    let comment = "a \"quoted\" \\ comment\nover lines\twith a bell \u{7} and ü";
    let original = identity(1, comment, None)?;
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(original.clone(), Origin::Local);
    let mut restarted = IdentityStore::remembered_in(file);
    let restored = restarted.identities(Instant::now());
    ensure!(restored == [original], "{restored:?}");
    Ok(())
}

#[test]
fn an_unreadable_keys_file_is_ignored_and_replaced() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    for broken in [
        "not toml [",
        "[[key]]\npublic-key = \"ssh-ed25519 AAAA\"\nflags = 5\nkey-handle = \"00\"\n",
        "[[key]]\nunknown = 1\n",
    ] {
        std::fs::write(&file, broken).context("writing a broken file")?;
        let mut store = IdentityStore::remembered_in(file.clone());
        ensure!(store.identities(Instant::now()).is_empty());
        store.add(identity(1, "work", None)?, Origin::Local);
        ensure!(offered_after_restart(&file) == ["work"]);
    }
    Ok(())
}

#[test]
fn remembered_keys_sharing_a_credential_are_refused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("keys.toml");
    // Written by a store, then the impostor's entry appended by hand.
    let mut store = IdentityStore::remembered_in(file.clone());
    store.add(identity(1, "real", None)?, Origin::Local);
    let other = dir.path().join("other.toml");
    let mut other_store = IdentityStore::remembered_in(other.clone());
    other_store.add(impostor(2, 1)?, Origin::Local);
    let text = std::fs::read_to_string(&file).context("reading")?
        + &std::fs::read_to_string(&other).context("reading")?;
    std::fs::write(&file, text).context("writing")?;
    ensure!(offered_after_restart(&file).is_empty());
    Ok(())
}
