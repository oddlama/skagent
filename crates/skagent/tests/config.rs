//! The configuration file: names for SSH keys and YubiKeys.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use skagent::config::{Config, default_config_path, grouped_digits};

const FINGERPRINT: &str = "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ";

#[test]
fn keys_and_security_keys_are_read() -> Result<()> {
    let config = Config::parse(&format!(
        r#"
[keys."{FINGERPRINT}"]
emoji = "🦊"
label = "github-work"

[security-keys.12345678]
name = "Desk 5C NFC"

[security-keys."23456789"]
name = "Keychain 5 Nano"
"#
    ))?;
    let key = config.key(FINGERPRINT).context("key missing")?;
    ensure!(key.emoji.as_deref() == Some("🦊"));
    ensure!(config.label(FINGERPRINT) == Some("github-work"));
    ensure!(config.security_key_name(12_345_678) == Some("Desk 5C NFC"));
    ensure!(config.security_key_name(23_456_789) == Some("Keychain 5 Nano"));
    ensure!(config.security_key_name(1).is_none());
    Ok(())
}

#[test]
fn everything_is_optional() -> Result<()> {
    ensure!(Config::parse("")? == Config::default());
    let only_emoji = Config::parse(&format!("[keys.\"{FINGERPRINT}\"]\nemoji = \"🔑\""))?;
    ensure!(only_emoji.label(FINGERPRINT).is_none());
    Ok(())
}

/// Silently ignoring a typo would leave the user wondering why nothing
/// changed, so anything unknown or malformed is refused with a reason.
#[test]
fn unknown_or_malformed_settings_are_refused() {
    let refused = [
        "[unknown]\nx = 1",
        &format!("[keys.\"{FINGERPRINT}\"]\nlable = \"typo\""),
        "[keys.\"SHA256:short\"]\nlabel = \"x\"",
        "[keys.\"MD5:aa:bb\"]\nlabel = \"x\"",
        "[security-keys.\"12ab\"]\nname = \"x\"",
        "[security-keys.99999999999]\nname = \"x\"",
        "[security-keys.1]\nname = \"\"",
        "[security-keys.1]\nname = \"line\\nbreak\"",
        &format!("[keys.\"{FINGERPRINT}\"]\nlabel = \"{}\"", "x".repeat(65)),
        &format!("[keys.\"{FINGERPRINT}\"]\nemoji = \"{}\"", "🦊".repeat(17)),
        "[security-keys.1]\nname = \"x\"\nemoji = \"🦊\"",
    ];
    for text in refused {
        assert!(Config::parse(text).is_err(), "accepted: {text}");
    }
}

#[test]
fn a_missing_default_file_is_fine_but_a_given_one_must_exist() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("config.toml");
    ensure!(Config::load(&missing, false)? == Config::default());
    ensure!(Config::load(&missing, true).is_err());

    std::fs::write(&missing, "[security-keys.7]\nname = \"spare\"\n")?;
    ensure!(Config::load(&missing, true)?.security_key_name(7) == Some("spare"));
    std::fs::write(&missing, "not toml [")?;
    let error = Config::load(&missing, false)
        .err()
        .context("a broken file was accepted")?;
    ensure!(format!("{error:#}").contains("config.toml"), "{error:#}");
    Ok(())
}

#[test]
fn the_default_path_follows_xdg() -> Result<()> {
    let path = |xdg: Option<&str>, home: Option<&str>| {
        default_config_path(xdg.map(OsStr::new), home.map(OsStr::new))
    };
    ensure!(
        path(Some("/x/config"), Some("/home/a"))? == Path::new("/x/config/skagent/config.toml")
    );
    ensure!(path(None, Some("/home/a"))? == Path::new("/home/a/.config/skagent/config.toml"));
    ensure!(
        path(Some("relative"), Some("/home/a"))?
            == Path::new("/home/a/.config/skagent/config.toml")
    );
    ensure!(path(None, None).is_err());
    Ok(())
}

#[test]
fn yubikeys_are_named_by_config_or_their_last_four_digits() -> Result<()> {
    let config = Config::parse("[security-keys.12345678]\nname = \"Desk 5C NFC\"")?;
    ensure!(config.yubikey_name(12_345_678) == "Desk 5C NFC");
    ensure!(config.yubikey_name(23_456_789) == "YubiKey 23 456 789");
    ensure!(config.yubikey_name(42) == "YubiKey 42");
    Ok(())
}

#[test]
fn serials_read_in_groups_of_three() -> Result<()> {
    for (number, grouped) in [
        (0, "0"),
        (42, "42"),
        (999, "999"),
        (1_000, "1 000"),
        (123_456, "123 456"),
        (1_234_567, "1 234 567"),
        (12_345_678, "12 345 678"),
        (u32::MAX, "4 294 967 295"),
    ] {
        ensure!(
            grouped_digits(number) == grouped,
            "{number}: {}",
            grouped_digits(number)
        );
    }
    Ok(())
}
