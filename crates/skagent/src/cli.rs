//! Command line interface.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::pin_cache::{KeyPinPolicy, KeySelector};

/// ssh-agent for FIDO2 (sk) keys: caches the PIN, still requires a touch per signature.
#[derive(Debug, Parser)]
#[command(name = "skagent", version, about)]
pub struct Cli {
    /// Log filter in `tracing` env-filter syntax, e.g. `info` or `skagent=debug`.
    ///
    /// Debug and trace output of the ssh-agent protocol library is always
    /// suppressed, because it contains key handles and lock passphrases.
    #[arg(long, env = "SKAGENT_LOG", default_value = "info", global = true)]
    pub log: String,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve the ssh-agent protocol on a unix socket until SIGINT or SIGTERM.
    Serve(ServeArgs),
    /// Drop all cached PINs of a running agent; the keys stay loaded. Meant
    /// for screen lockers, e.g. `swayidle lock 'skagent forget; swaylock'`.
    Forget(SocketArgs),
    /// Load resident Ed25519 SSH keys from one security key. With multiple
    /// devices, touch the one to load. The running agent asks for its PIN.
    Load(SocketArgs),
}

/// Where the agent socket is.
#[derive(Debug, Args)]
pub struct SocketArgs {
    /// Path of the agent socket. Defaults to `$XDG_RUNTIME_DIR/skagent.sock`.
    #[arg(long, env = "SKAGENT_SOCKET")]
    pub socket: Option<PathBuf>,
}

/// Arguments of `skagent serve`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Where to listen.
    #[command(flatten)]
    pub socket: SocketArgs,

    /// pinentry program that asks for PINs (the default prompt).
    #[arg(long, default_value = "pinentry", conflicts_with = "askpass")]
    pub pinentry: PathBuf,

    /// Ask for PINs with this askpass program instead of pinentry, like
    /// OpenSSH's `SSH_ASKPASS`: it gets the prompt as its argument and prints
    /// the PIN.
    #[arg(long)]
    pub askpass: Option<PathBuf>,

    /// How long a PIN stays cached after it was entered, e.g. `8h`, `30m`,
    /// `90s`. Using the PIN doesn't extend it. `0` disables caching.
    #[arg(long, value_parser = parse_duration, default_value = "8h")]
    pub pin_lifetime: Duration,

    /// Also drop a cached PIN that wasn't used for this long, e.g. `1h`.
    #[arg(long, value_parser = parse_duration)]
    pub pin_idle: Option<Duration>,

    /// Cache the PINs of some keys differently, e.g.
    /// `application=ssh:personal,lifetime=1h,idle=15m` or
    /// `fingerprint=SHA256:...,lifetime=0`. One selector (`application` or
    /// `fingerprint`, as `ssh-add -l` shows it) and `lifetime` and/or `idle`;
    /// `0` means no caching or no idle timeout. Repeatable, the first rule
    /// matching a key wins.
    #[arg(long = "pin-policy", value_name = "RULE", value_parser = parse_pin_policy)]
    pub pin_policies: Vec<KeyPinPolicy>,

    /// Don't show a desktop notification while a security key waits for a
    /// touch (`org.freedesktop.Notifications` on the session bus).
    #[arg(long)]
    pub no_touch_notification: bool,
}

/// Parses a `--pin-policy` rule: comma-separated `name=value` settings.
///
/// # Errors
///
/// Returns a message for clap if the rule has no or two selectors, no
/// override, an unknown setting or a bad duration.
pub fn parse_pin_policy(text: &str) -> Result<KeyPinPolicy, String> {
    let mut selector = None;
    let mut lifetime = None;
    let mut idle = None;
    for setting in text.split(',') {
        let (name, value) = setting
            .split_once('=')
            .ok_or_else(|| format!("{setting:?} is not name=value"))?;
        if value.is_empty() {
            return Err(format!("{name}= needs a value"));
        }
        let duplicate = match name {
            "application" => selector
                .replace(KeySelector::Application(value.to_owned()))
                .is_some(),
            "fingerprint" => selector
                .replace(KeySelector::Fingerprint(value.to_owned()))
                .is_some(),
            "lifetime" => lifetime.replace(parse_duration(value)?).is_some(),
            "idle" => idle.replace(parse_duration(value)?).is_some(),
            _ => {
                return Err(format!(
                    "unknown setting {name:?}, use application, fingerprint, lifetime or idle"
                ));
            }
        };
        if duplicate {
            return Err(format!(
                "{name}= is given twice, or both application= and fingerprint="
            ));
        }
    }
    let selector = selector.ok_or("the rule needs application= or fingerprint=")?;
    if lifetime.is_none() && idle.is_none() {
        return Err("the rule needs lifetime= and/or idle=".to_owned());
    }
    Ok(KeyPinPolicy {
        selector,
        lifetime,
        idle,
    })
}

/// Parses `0` or a whole number with a unit: `s`, `m` or `h`.
///
/// # Errors
///
/// Returns a message for clap if `text` isn't such a duration.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let invalid = || format!("{text:?} is not a duration like 90s, 30m or 8h");
    let unit = text.chars().last().ok_or_else(invalid)?;
    let number: u64 = text
        .strip_suffix(unit)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let seconds = match unit {
        's' => Some(number),
        'm' => number.checked_mul(60),
        'h' => number.checked_mul(3600),
        _ => None,
    }
    .ok_or_else(invalid)?;
    Ok(Duration::from_secs(seconds))
}
