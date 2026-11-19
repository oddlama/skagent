//! Command line interface.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    Load(LoadArgs),
    /// Check the configuration file: fails if `serve` would refuse it or
    /// skip any of its settings, and says which.
    CheckConfig(CheckConfigArgs),
    /// age identities: keys on security keys that decrypt age files. Files
    /// are encrypted to an identity's recipient with stock age, and decrypted
    /// through `age-plugin-skagent`, which asks the running agent.
    Age(AgeArgs),
    /// Run a command whose age decryptions take one touch together: the
    /// first file its processes decrypt through `age-plugin-skagent` takes
    /// the PIN and a touch, the following ones neither, until the command
    /// is done or the time is up. E.g. `skagent batch -- agenix rekey`.
    Batch(BatchArgs),
}

/// Arguments of `skagent batch`.
#[derive(Debug, Args)]
pub struct BatchArgs {
    /// Where the agent listens for age requests.
    #[command(flatten)]
    pub socket: AgeSocketArgs,

    /// How long the batch lasts at most, e.g. `5m`. Never longer than the
    /// agent allows (`skagent serve --batch-lifetime`), which is also what
    /// it lasts without this.
    #[arg(long = "for", value_name = "DURATION", value_parser = parse_batch_duration)]
    pub lasting: Option<Duration>,

    /// The command to run, with its arguments.
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<OsString>,
}

/// Arguments of `skagent age`.
#[derive(Debug, Args)]
pub struct AgeArgs {
    /// What to do.
    #[command(subcommand)]
    pub command: AgeCommand,
}

/// `skagent age` subcommands.
#[derive(Debug, Subcommand)]
pub enum AgeCommand {
    /// Create an age identity on a security key and print its recipient.
    /// The running agent asks for the PIN; the key then wants two touches,
    /// one to create the credential and one to read the recipient.
    New {
        /// Where the agent listens for age requests.
        #[command(flatten)]
        socket: AgeSocketArgs,

        /// Also on a security key that holds an age identity already.
        #[arg(long)]
        another: bool,
    },
    /// Print the recipients of the age identities the agent knows.
    List(AgeSocketArgs),
    /// Print an identity file for `age -d -i`. It holds no secret: it names
    /// the identity by its recipient, which makes it usable for encrypting
    /// too.
    Identity {
        /// Where the agent listens for age requests. Not needed with a
        /// recipient.
        #[command(flatten)]
        socket: AgeSocketArgs,

        /// The identity's recipient (`age1pq1…`). Without it: the one
        /// identity the agent knows.
        recipient: Option<String>,
    },
}

/// Where the agent's socket for age requests is.
#[derive(Debug, Args)]
pub struct AgeSocketArgs {
    /// Path of the socket for age requests. Defaults to
    /// `$XDG_RUNTIME_DIR/skagent-age.sock`.
    #[arg(long, env = "SKAGENT_AGE_SOCKET")]
    pub age_socket: Option<PathBuf>,
}

/// Arguments of `skagent check-config`.
#[derive(Debug, Args)]
pub struct CheckConfigArgs {
    /// The file to check. Defaults to `$XDG_CONFIG_HOME/skagent/config.toml`;
    /// a file given here must exist.
    #[arg(long, env = "SKAGENT_CONFIG")]
    pub config: Option<PathBuf>,
}

/// Arguments of `skagent load`.
#[derive(Debug, Args)]
pub struct LoadArgs {
    /// Where the agent is.
    #[command(flatten)]
    pub socket: SocketArgs,

    /// Succeed without loading anything if no security key is connected,
    /// e.g. when loading at login.
    #[arg(long)]
    pub if_connected: bool,
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

    /// Where to listen for age requests (`skagent age`, `age-plugin-skagent`).
    /// Defaults to the ssh-agent socket's path with `-age` in its name:
    /// `$XDG_RUNTIME_DIR/skagent-age.sock`.
    #[arg(long, env = "SKAGENT_AGE_SOCKET")]
    pub age_socket: Option<PathBuf>,

    /// Configuration file: emoji and labels for SSH keys, names for YubiKeys.
    /// Defaults to `$XDG_CONFIG_HOME/skagent/config.toml`, which may be
    /// missing; a file given here must exist.
    #[arg(long, env = "SKAGENT_CONFIG")]
    pub config: Option<PathBuf>,

    /// pinentry program that asks for PINs (the default prompt).
    #[arg(long, default_value = "pinentry", conflicts_with = "askpass")]
    pub pinentry: PathBuf,

    /// Ask for PINs with this askpass program instead of pinentry, like
    /// OpenSSH's `SSH_ASKPASS`: it gets the prompt as its argument and prints
    /// the PIN.
    #[arg(long)]
    pub askpass: Option<PathBuf>,

    /// Show prompts in skagent's own popup program (e.g. `skagent-pinentry`)
    /// instead: device selection, PIN, touch and the result in one window,
    /// one request at a time. Replaces the touch notifications.
    #[arg(long, conflicts_with_all = ["askpass", "pinentry"])]
    pub popup: Option<PathBuf>,

    /// How long a PIN stays cached after it was entered, e.g. `8h`, `30m`,
    /// `90s`. Using the PIN doesn't extend it. `0` disables caching.
    #[arg(long, value_parser = parse_duration, default_value = "8h")]
    pub pin_lifetime: Duration,

    /// Also drop a cached PIN that wasn't used for this long, e.g. `1h`.
    /// `0` means no idle timeout, the default.
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

    /// Where cached PINs and other secrets live. `memfd-secret` uses
    /// `memfd_secret(2)` memory, which is also removed from the kernel's direct
    /// map; the system can't hibernate while any exists.
    #[arg(long, value_enum, default_value_t = SecretMemory::Locked)]
    pub secret_memory: SecretMemory,

    /// Don't show a desktop notification while a security key waits for a
    /// touch (`org.freedesktop.Notifications` on the session bus).
    #[arg(long)]
    pub no_touch_notification: bool,

    /// How long a request waits for its security key to be plugged in, e.g.
    /// `15s` or `1m`, asking for it by name once skagent knows which YubiKey
    /// holds the key. The client hanging up (Ctrl-C) ends the wait too. `0`
    /// fails right away.
    #[arg(long, value_parser = parse_duration, default_value = "15s")]
    pub plug_in_timeout: Duration,

    /// The longest a batch of decryptions (`skagent batch`) lasts, e.g.
    /// `10m`. The key of an age identity stays in the agent's memory for
    /// that long at most, and files are decrypted without a touch. `0`
    /// turns batches off.
    #[arg(long, value_parser = parse_duration, default_value = "10m")]
    pub batch_lifetime: Duration,

    /// Don't pair with security keys on first use. Pairing takes one more
    /// touch, once per security key, and lets skagent tell the key from a
    /// device claiming to be it before a PIN goes there. Pairings made
    /// before are still checked.
    #[arg(long)]
    pub no_pairing: bool,
}

/// Where secrets live (`--secret-memory`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SecretMemory {
    /// Locked anonymous memory, not dumped, wiped in forked children.
    Locked,
    /// `memfd_secret(2)` memory.
    #[value(name = "memfd-secret")]
    MemfdSecret,
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

/// Parses how long a batch lasts: a duration above zero, in seconds that
/// fit the request.
///
/// # Errors
///
/// Returns a message for clap if `text` isn't such a duration.
pub fn parse_batch_duration(text: &str) -> Result<Duration, String> {
    let duration = parse_duration(text)?;
    if duration.is_zero() {
        return Err("a batch lasts longer than 0; leave --for out for as long as allowed".into());
    }
    if u32::try_from(duration.as_secs()).is_err() {
        return Err(format!("{text:?} is too long"));
    }
    Ok(duration)
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
