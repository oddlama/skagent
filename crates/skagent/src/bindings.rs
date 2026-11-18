//! Which security key holds which credential.
//!
//! A binding records the plug-in a credential last signed on and, for a
//! YubiKey, its serial. The plug-in tells the device apart only until it is
//! unplugged; the serial survives replugs and agent restarts. So a replugged
//! YubiKey is used without a selection touch, and a request whose YubiKey
//! isn't plugged in can ask for it by name and wait.
//!
//! Serial bindings are remembered in a file, under a digest of the
//! credential rather than its key handle. Nothing in it is secret; losing it
//! only means selecting by touch once more.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;

use crate::device::DeviceIdentity;
use crate::pin_cache::CredentialKey;

/// The file's name in `$XDG_STATE_HOME/skagent`.
pub const DEFAULT_BINDINGS_NAME: &str = "bindings.toml";

const HEADER: &str = "\
# Which YubiKey holds which of skagent's SSH keys, by serial, learned from
# signatures and loading. skagent rewrites this file; deleting it only means
# selecting a key by touch once more. Credentials are SHA-256 digests.
";

/// Where a credential was last used.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    /// The plug-in, unless remembered from an earlier run.
    device: Option<DeviceIdentity>,
    /// The YubiKey's serial, if it reports one.
    serial: Option<u32>,
}

/// A routing decision made without touching a device or reading a PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The bound plug-in or YubiKey, or the only device on first use.
    Direct(DeviceIdentity),
    /// Several candidates, or the device of a binding without a serial is
    /// gone: the user selects by touch.
    Touch,
    /// The security key isn't plugged in: wait for it.
    Wait(Missing),
    /// Several connected devices report the serial of the YubiKey holding
    /// the credential. At most one of them is that YubiKey, so none gets the
    /// PIN.
    Ambiguous {
        /// The serial claimed more than once.
        serial: u32,
    },
}

/// What a request waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Nothing is plugged in.
    Nothing {
        /// The YubiKey holding the credential, if known.
        serial: Option<u32>,
    },
    /// Other security keys are plugged in, not the YubiKey holding the
    /// credential.
    Elsewhere {
        /// The YubiKey holding the credential.
        serial: u32,
        /// One of the others, if it reports a serial.
        other: Option<u32>,
    },
}

impl Missing {
    /// The YubiKey waited for, if known.
    #[must_use]
    pub fn serial(self) -> Option<u32> {
        match self {
            Self::Nothing { serial } => serial,
            Self::Elsewhere { serial, .. } => Some(serial),
        }
    }
}

/// A request gave up waiting for its security key to be plugged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotPluggedIn {
    /// The YubiKey it waited for, if known.
    pub serial: Option<u32>,
}

impl fmt::Display for NotPluggedIn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.serial {
            Some(serial) => write!(
                formatter,
                "the YubiKey with serial {serial} wasn't plugged in"
            ),
            None => formatter.write_str("no security key was plugged in"),
        }
    }
}

impl std::error::Error for NotPluggedIn {}

/// Several security keys reported the serial of the one holding a
/// credential; the request was refused rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialClaimedTwice {
    /// The serial.
    pub serial: u32,
}

impl fmt::Display for SerialClaimedTwice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "several security keys report serial {}, so one of them pretends to be that YubiKey; \
             not sending the PIN to any",
            self.serial
        )
    }
}

impl std::error::Error for SerialClaimedTwice {}

/// Credential-to-device associations, independent of cached PINs.
#[derive(Debug, Default)]
pub struct Bindings {
    entries: HashMap<[u8; 32], Binding>,
    /// Where serial bindings are remembered, if anywhere.
    file: Option<PathBuf>,
}

impl Bindings {
    /// The serial bindings remembered in `file`, remembering further ones
    /// there. A missing file holds none; one that can't be read is ignored
    /// with a warning, and replaced on the next change.
    #[must_use]
    pub fn remembered_in(file: PathBuf) -> Self {
        let entries = read_remembered(&file).unwrap_or_else(|error| {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "ignoring the remembered bindings"
            );
            HashMap::new()
        });
        tracing::debug!(
            file = %file.display(),
            remembered = entries.len(),
            "read the remembered bindings"
        );
        Self {
            entries,
            file: Some(file),
        }
    }

    /// Binds a credential after a successful assertion or PIN-authenticated
    /// enumeration on `device`. A credential lives on one device only, so a
    /// serial known from before stays when this time it couldn't be read.
    pub fn bind(&mut self, key: &CredentialKey, device: DeviceIdentity, serial: Option<u32>) {
        let digest = key.digest();
        let before = self.serial_of(&digest);
        let serial = serial.or(before);
        self.entries.insert(
            digest,
            Binding {
                device: Some(device),
                serial,
            },
        );
        if serial != before {
            self.save();
        }
    }

    /// Removes an identity's binding, not merely its PIN.
    pub fn forget(&mut self, key: &CredentialKey) {
        let removed = self.entries.remove(&key.digest());
        if removed.is_some_and(|binding| binding.serial.is_some()) {
            self.save();
        }
    }

    /// Removes all associations when the agent unloads all identities.
    pub fn clear(&mut self) {
        let remembered = self
            .entries
            .values()
            .any(|binding| binding.serial.is_some());
        self.entries.clear();
        if remembered {
            self.save();
        }
    }

    /// Whether resolving `key` needs the serials of `devices`: its YubiKey
    /// is known, but its plug-in isn't among them.
    #[must_use]
    pub fn needs_serials(&self, key: Option<&CredentialKey>, devices: &[DeviceIdentity]) -> bool {
        key.and_then(|key| self.entries.get(&key.digest()))
            .is_some_and(|binding| {
                binding.serial.is_some()
                    && !binding
                        .device
                        .as_ref()
                        .is_some_and(|device| devices.contains(device))
            })
    }

    /// Chooses among the connected `devices` for `key` (`None`: loading,
    /// from any device). `serial_of` tells a device's serial, if known.
    ///
    /// Never another device in place of a known one: a lost binding needs a
    /// touch, unless its YubiKey is recognized by its serial; a YubiKey that
    /// isn't plugged in is waited for; a serial reported twice is refused.
    /// The only device is used for a credential seen for the first time.
    #[must_use]
    pub fn resolve(
        &self,
        key: Option<&CredentialKey>,
        devices: &[DeviceIdentity],
        serial_of: impl Fn(&DeviceIdentity) -> Option<u32>,
    ) -> Resolution {
        let Some(binding) = key.and_then(|key| self.entries.get(&key.digest())) else {
            return match devices {
                [] => Resolution::Wait(Missing::Nothing { serial: None }),
                [only] => Resolution::Direct(only.clone()),
                _ => Resolution::Touch,
            };
        };
        if let Some(device) = binding
            .device
            .as_ref()
            .filter(|device| devices.contains(device))
        {
            return Resolution::Direct(device.clone());
        }
        let Some(serial) = binding.serial else {
            return if devices.is_empty() {
                Resolution::Wait(Missing::Nothing { serial: None })
            } else {
                Resolution::Touch
            };
        };
        let mut claiming = devices
            .iter()
            .filter(|device| serial_of(device) == Some(serial));
        match (claiming.next(), claiming.next()) {
            (Some(device), None) => return Resolution::Direct(device.clone()),
            (Some(_), Some(_)) => return Resolution::Ambiguous { serial },
            (None, _) => {}
        }
        Resolution::Wait(if devices.is_empty() {
            Missing::Nothing {
                serial: Some(serial),
            }
        } else {
            Missing::Elsewhere {
                serial,
                other: devices.iter().find_map(&serial_of),
            }
        })
    }

    fn serial_of(&self, digest: &[u8; 32]) -> Option<u32> {
        self.entries.get(digest).and_then(|binding| binding.serial)
    }

    /// Writes the serial bindings down, if there is a file. A failure only
    /// costs the memory across restarts, with a warning.
    fn save(&self) {
        let Some(file) = &self.file else {
            return;
        };
        if let Err(error) = write_remembered(file, &self.entries) {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "can't remember which YubiKey holds which key"
            );
        }
    }
}

/// Where bindings are remembered: `$XDG_STATE_HOME/skagent/bindings.toml`,
/// else `$HOME/.local/state/…`.
///
/// # Errors
///
/// Returns an error if neither variable gives an absolute path.
pub fn default_bindings_path(
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf> {
    let absolute = |value: Option<&OsStr>| {
        value
            .map(Path::new)
            .filter(|path| path.is_absolute())
            .map(Path::to_path_buf)
    };
    let base = absolute(xdg_state_home)
        .or_else(|| absolute(home).map(|home| home.join(".local").join("state")))
        .context("neither XDG_STATE_HOME nor HOME is an absolute path")?;
    Ok(base.join("skagent").join(DEFAULT_BINDINGS_NAME))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberedFile {
    #[serde(default)]
    binding: Vec<Remembered>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Remembered {
    credential: String,
    serial: u32,
}

fn read_remembered(file: &Path) -> Result<HashMap<[u8; 32], Binding>> {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", file.display()));
        }
    };
    let parsed: RememberedFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    parsed
        .binding
        .into_iter()
        .map(|remembered| {
            Ok((
                parse_digest(&remembered.credential)?,
                Binding {
                    device: None,
                    serial: Some(remembered.serial),
                },
            ))
        })
        .collect()
}

/// Replaces `file` with the serial bindings: written to a new, private file
/// first, then renamed over the old one, so a crash leaves either.
fn write_remembered(file: &Path, entries: &HashMap<[u8; 32], Binding>) -> Result<()> {
    let directory = file
        .parent()
        .with_context(|| format!("{} has no parent directory", file.display()))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let mut remembered: Vec<(String, u32)> = entries
        .iter()
        .filter_map(|(digest, binding)| binding.serial.map(|serial| (hex(digest), serial)))
        .collect();
    remembered.sort();
    let mut text = HEADER.to_owned();
    for (credential, serial) in remembered {
        writeln!(
            text,
            "\n[[binding]]\ncredential = \"{credential}\"\nserial = {serial}"
        )
        .context("formatting the remembered bindings")?;
    }
    let new = file.with_extension("toml.new");
    match fs::remove_file(&new) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("removing {}", new.display()));
        }
        _ => {}
    }
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&new)
        .with_context(|| format!("creating {}", new.display()))?;
    out.write_all(text.as_bytes())
        .and_then(|()| out.sync_all())
        .with_context(|| format!("writing {}", new.display()))?;
    fs::rename(&new, file)
        .with_context(|| format!("renaming {} to {}", new.display(), file.display()))
}

fn hex(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            // Writing to a String can't fail.
            let _ = write!(text, "{byte:02x}");
            text
        })
}

fn parse_digest(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "credential {text:?} is not a SHA-256 digest in hex"
    );
    let mut digest = [0_u8; 32];
    for (byte, pair) in digest.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).context("credential digest")?;
        *byte = u8::from_str_radix(pair, 16).context("credential digest")?;
    }
    Ok(digest)
}
