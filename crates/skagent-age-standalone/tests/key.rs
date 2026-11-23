//! Which of the plugged-in security keys is asked, and what they are called.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use skagent_age_standalone::device::name;
use skagent_age_standalone::key::{Found, select};

fn usable(name: &str) -> (String, Result<u8, String>) {
    (name.to_owned(), Ok(0))
}

fn unusable(name: &str, why: &str) -> (String, Result<u8, String>) {
    (name.to_owned(), Err(why.to_owned()))
}

#[test]
fn the_only_key_that_could_hold_an_identity_is_the_one() {
    assert!(matches!(select(vec![usable("YubiKey 1")]), Found::One(0)));
    // A U2F token or a key without a PIN next to it doesn't get in the way.
    let devices = vec![
        unusable("U2F token", "it doesn't support CTAP2"),
        usable("YubiKey 1"),
        unusable("Other key", "it has no PIN"),
    ];
    assert!(matches!(select(devices), Found::One(0)));
}

#[test]
fn several_keys_that_could_are_named_and_none_is_taken() {
    let devices = vec![
        usable("YubiKey 1"),
        unusable("U2F token", "it doesn't support CTAP2"),
        usable("YubiKey 2"),
    ];
    let found = select(devices);
    assert!(
        matches!(&found, Found::Several(names) if names == &["YubiKey 1", "YubiKey 2"]),
        "{found:?}"
    );
}

#[test]
fn what_cant_hold_an_identity_is_named_with_why() {
    let nothing: Vec<(String, Result<u8, String>)> = Vec::new();
    assert!(matches!(select(nothing), Found::None { unusable } if unusable.is_empty()));
    let devices = vec![
        unusable("U2F token", "it doesn't support CTAP2"),
        unusable("Other key", "it has no PIN"),
    ];
    let found = select(devices);
    let expected = [
        "U2F token: it doesn't support CTAP2",
        "Other key: it has no PIN",
    ];
    assert!(
        matches!(&found, Found::None { unusable } if unusable == &expected),
        "{found:?}"
    );
}

/// The name goes into a prompt that may be shown on a boot console.
#[test]
fn a_key_is_called_by_its_serial_or_its_product_in_plain_ascii() {
    assert_eq!(
        name(Some(12_345_678), "YubiKey OTP+FIDO+CCID"),
        "YubiKey 12345678"
    );
    assert_eq!(
        name(None, "Security Key by Yubico"),
        "Security Key by Yubico"
    );
    assert_eq!(name(None, "  Nitro\u{00a0}key\t 3\n"), "Nitrokey 3");
    assert_eq!(name(None, "Schlüssel\u{1b}[31m"), "Schlssel[31m");
    assert_eq!(name(None, ""), "the security key");
    assert_eq!(name(None, "\u{7f}\u{0}"), "the security key");
    assert_eq!(name(None, &"x".repeat(100)).len(), 40);
}
