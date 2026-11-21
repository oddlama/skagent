//! The configuration file: how the user names their SSH keys and YubiKeys.
//!
//! ```toml
//! [keys."SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ"]
//! emoji = "🦊"
//! label = "github-work"
//!
//! [security-keys.12345678]
//! name = "Desk 5C NFC"
//!
//! [popup]
//! renderer = "gpu"
//! appearance = "dark"
//! scale = 1.25
//!
//! [popup.dark]
//! accent = "#88c0d0"
//! ```
//!
//! Everything is optional, and nothing in it is secret. Unknown settings are
//! refused, so a typo can't silently do nothing. The exception is `[popup]`
//! (see `skagent_popup::style`): how the popup looks is cosmetic, so a
//! setting there that can't be used is skipped with a warning instead of
//! stopping the agent. What it draws with isn't cosmetic, and is treated the
//! same: an unusable `renderer` leaves the default, the CPU, which loads no
//! GPU driver. home-manager generates the file from `services.skagent.keys`,
//! `services.skagent.securityKeys` and `services.skagent.popup`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use serde::Deserialize;
use skagent_popup::style::Style;

/// File name below `$XDG_CONFIG_HOME/skagent`.
pub const DEFAULT_CONFIG_NAME: &str = "config.toml";

/// Longest label or YubiKey name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// Longest emoji, in characters. Emoji sequences (families, flags, skin tones)
/// are made of several characters.
pub const MAX_EMOJI_CHARS: usize = 16;

/// Length of the base64 part of an SSH SHA-256 fingerprint.
const FINGERPRINT_BASE64_CHARS: usize = 43;

/// The parsed configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    keys: BTreeMap<String, KeyConfig>,
    security_keys: BTreeMap<u32, SecurityKeyConfig>,
    style: Style,
    warnings: Vec<String>,
}

/// How an SSH key is shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Shown in the popup's avatar.
    pub emoji: Option<String>,
    /// Shown instead of the key's comment.
    pub label: Option<String>,
}

/// How a YubiKey is shown.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityKeyConfig {
    /// E.g. `Desk 5C NFC`.
    pub name: String,
}

/// The file as written, before validation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawConfig {
    #[serde(default)]
    keys: BTreeMap<String, KeyConfig>,
    #[serde(default)]
    security_keys: BTreeMap<String, SecurityKeyConfig>,
    /// Checked setting by setting, see the module documentation.
    #[serde(default)]
    popup: toml::Table,
}

impl Config {
    /// Parses and validates the contents of a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first setting that is malformed, unknown
    /// or out of range.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text).context("parsing the configuration")?;
        for (fingerprint, key) in &raw.keys {
            check_fingerprint(fingerprint)?;
            if let Some(emoji) = &key.emoji {
                check_text(emoji, MAX_EMOJI_CHARS)
                    .with_context(|| format!("the emoji of key {fingerprint}"))?;
            }
            if let Some(label) = &key.label {
                check_text(label, MAX_NAME_CHARS)
                    .with_context(|| format!("the label of key {fingerprint}"))?;
            }
        }
        let mut security_keys = BTreeMap::new();
        for (serial, security_key) in raw.security_keys {
            let parsed = parse_serial(&serial)?;
            check_text(&security_key.name, MAX_NAME_CHARS)
                .with_context(|| format!("the name of security key {serial}"))?;
            if security_keys.insert(parsed, security_key).is_some() {
                bail!("security key {parsed} is configured twice");
            }
        }
        let (style, warnings) = Style::from_table(&raw.popup);
        Ok(Self {
            keys: raw.keys,
            security_keys,
            style,
            warnings,
        })
    }

    /// How the popup looks.
    #[must_use]
    pub const fn style(&self) -> &Style {
        &self.style
    }

    /// The settings that were skipped, one line each: `popup.dark.acent: no
    /// such colour …`.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Reads `path`. With `required` false a missing file is an empty
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file can't be read (or is missing and
    /// `required`), or doesn't parse.
    pub fn load(path: &Path, required: bool) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound && !required => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading the configuration {}", path.display()));
            }
        };
        Self::parse(&text).with_context(|| format!("in the configuration {}", path.display()))
    }

    /// How the key with `fingerprint` (`SHA256:…`) is shown, if configured.
    #[must_use]
    pub fn key(&self, fingerprint: &str) -> Option<&KeyConfig> {
        self.keys.get(fingerprint)
    }

    /// The label of the key with `fingerprint`, if configured.
    #[must_use]
    pub fn label(&self, fingerprint: &str) -> Option<&str> {
        self.key(fingerprint)?.label.as_deref()
    }

    /// How the YubiKey with `serial` is named: its configured name, else
    /// `YubiKey 12 345 678`, the serial as `ykman list --serials` shows it,
    /// in groups of three digits.
    #[must_use]
    pub fn yubikey_name(&self, serial: u32) -> String {
        self.security_key_name(serial).map_or_else(
            || format!("YubiKey {}", grouped_digits(serial)),
            ToOwned::to_owned,
        )
    }

    /// The name of the YubiKey with `serial`, if configured.
    #[must_use]
    pub fn security_key_name(&self, serial: u32) -> Option<&str> {
        self.security_keys
            .get(&serial)
            .map(|security_key| security_key.name.as_str())
    }
}

/// `12345678` as `12 345 678`: groups of three digits from the right, to read
/// a serial at a glance.
#[must_use]
pub fn grouped_digits(number: u32) -> String {
    let digits = number.to_string();
    let mut grouped = String::with_capacity(digits.len().saturating_mul(2));
    for (index, digit) in digits.chars().enumerate() {
        let left = digits.len().saturating_sub(index);
        if index > 0 && left.is_multiple_of(3) {
            grouped.push(' ');
        }
        grouped.push(digit);
    }
    grouped
}

/// Where the configuration is read from without `--config`:
/// `$XDG_CONFIG_HOME/skagent/config.toml`, else `$HOME/.config/…`.
///
/// # Errors
///
/// Returns an error if neither variable gives an absolute path.
pub fn default_config_path(
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf> {
    let absolute = |value: Option<&OsStr>| {
        value
            .map(Path::new)
            .filter(|path| path.is_absolute())
            .map(Path::to_path_buf)
    };
    let base = absolute(xdg_config_home)
        .or_else(|| absolute(home).map(|home| home.join(".config")))
        .context("neither XDG_CONFIG_HOME nor HOME is an absolute path; pass --config")?;
    Ok(base.join("skagent").join(DEFAULT_CONFIG_NAME))
}

fn check_fingerprint(fingerprint: &str) -> Result<()> {
    let base64 = fingerprint
        .strip_prefix("SHA256:")
        .with_context(|| format!("key {fingerprint:?} is not a SHA256:… fingerprint"))?;
    ensure!(
        base64.len() == FINGERPRINT_BASE64_CHARS
            && base64
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'),
        "key {fingerprint:?} is not a SHA256:… fingerprint as `ssh-add -l` shows it"
    );
    Ok(())
}

fn parse_serial(serial: &str) -> Result<u32> {
    ensure!(
        !serial.is_empty() && serial.bytes().all(|byte| byte.is_ascii_digit()),
        "security key {serial:?} is not a serial number"
    );
    serial
        .parse()
        .with_context(|| format!("security key serial {serial} is out of range"))
}

fn check_text(text: &str, max_chars: usize) -> Result<()> {
    ensure!(!text.trim().is_empty(), "is empty");
    ensure!(
        text.chars().count() <= max_chars,
        "is longer than {max_chars} characters"
    );
    ensure!(
        !text.chars().any(char::is_control),
        "contains control characters"
    );
    Ok(())
}
