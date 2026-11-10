//! Key acceptance, constraint rules and the identity store, with explicit time.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent::identities::{
    AcceptedConstraints, BUILT_IN_SK_PROVIDER, IdentityStore, SK_PROVIDER_CONSTRAINT, SkIdentity,
    evaluate_constraints,
};
use ssh_agent_lib::proto::{Extension, KeyConstraint, Unparsed};
use support::{SK_FLAGS_UP_UV, ed25519_credential, sk_credential, sk_key_data};

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
                lifetime: Some(Duration::from_secs(3600))
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
            "destination constraint",
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
    ensure!(!store.add(identity(1, "first", None)?));
    ensure!(!store.add(identity(2, "second", None)?));
    ensure!(
        store.add(identity(1, "first, renamed", None)?),
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
    store.add(identity(1, "first", None)?);
    store.add(identity(2, "second", None)?);

    ensure!(store.remove(&sk_key_data(1), now));
    ensure!(!store.remove(&sk_key_data(1), now), "removed twice");
    ensure!(store.find(&sk_key_data(2), now).is_some());
    ensure!(store.clear() == 1);
    ensure!(store.identities(now).is_empty());
    Ok(())
}

#[test]
fn keys_expire_at_their_lifetime() -> Result<()> {
    let start = Instant::now();
    let mut store = IdentityStore::default();
    store.add(identity(1, "short", Some(later(start, 10)?))?);
    store.add(identity(2, "forever", None)?);

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
    store.add(identity(1, "k", Some(later(start, 10)?))?);
    store.add(identity(1, "k", None)?);
    ensure!(store.find(&sk_key_data(1), later(start, 3600)?).is_some());
    Ok(())
}
