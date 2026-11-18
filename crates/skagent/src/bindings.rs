//! Which security key holds which credential.
//!
//! A binding records the plug-in a credential last signed on and, where
//! known, the YubiKey's serial and skagent's pairing credential on the key
//! (`pairing.rs`). The plug-in tells the device apart only until it is
//! unplugged. The pairing survives replugs and agent restarts and can't be
//! faked: the device that answers its challenge is the key. The serial
//! survives too, but any device can claim it; it names the key and, for keys
//! paired before, tells a fake that claims it.
//!
//! Bindings with a serial or a pairing are remembered in a file, under a
//! digest of the credential rather than its key handle. Nothing in it is
//! secret; losing it only means selecting by touch once more.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use skagent_fido::PairingCredential;

use crate::device::DeviceIdentity;
use crate::pairing::Proof;
use crate::pin_cache::CredentialKey;
use crate::state_files::{self, hex, parse_fixed, parse_hex};

/// The file's name in `$XDG_STATE_HOME/skagent`.
pub const DEFAULT_BINDINGS_NAME: &str = "bindings.toml";

const HEADER: &str = "\
# Which security key holds which of skagent's SSH keys, learned from
# signatures and loading: the YubiKey's serial, and skagent's pairing
# credential on the key, which it has to prove before it gets a PIN.
# skagent rewrites this file; deleting it only means selecting a key by touch
# once more. Credentials are SHA-256 digests.
";

/// Where a credential was last used.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    /// The plug-in, unless remembered from an earlier run.
    device: Option<DeviceIdentity>,
    /// The YubiKey's serial, if it reports one.
    serial: Option<u32>,
    /// skagent's pairing credential on the key, once paired.
    pairing: Option<PairingCredential>,
}

impl Binding {
    fn remembered(&self) -> bool {
        self.serial.is_some() || self.pairing.is_some()
    }
}

/// A routing decision made without touching a device or reading a PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The bound plug-in, the paired key, the YubiKey with the bound serial
    /// (unpaired), or the only device on first use.
    Direct(DeviceIdentity),
    /// Several candidates, or the device of an unpaired binding without a
    /// serial is gone: the user selects by touch.
    Touch,
    /// The security key isn't plugged in: wait for it.
    Wait(Missing),
    /// Several connected devices claim to be the key holding the credential
    /// (its serial, or even its pairing). At most one of them is, so none
    /// gets the PIN.
    Ambiguous {
        /// The serial claimed, if known.
        serial: Option<u32>,
    },
    /// A device reports the serial of the paired key but can't prove the
    /// pairing: a fake, or the key was reset.
    Unrecognized {
        /// The serial.
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
    /// Other security keys are plugged in, not the one holding the
    /// credential.
    Elsewhere {
        /// The YubiKey holding the credential, if known.
        serial: Option<u32>,
        /// One of the others, if it reports a serial.
        other: Option<u32>,
    },
}

impl Missing {
    /// The YubiKey waited for, if known.
    #[must_use]
    pub fn serial(self) -> Option<u32> {
        match self {
            Self::Nothing { serial } | Self::Elsewhere { serial, .. } => serial,
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

/// Several security keys claimed to be the one holding a credential; the
/// request was refused rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialClaimedTwice {
    /// The serial claimed, if known.
    pub serial: Option<u32>,
}

impl fmt::Display for SerialClaimedTwice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.serial {
            Some(serial) => write!(
                formatter,
                "several security keys report serial {serial}, so one of them pretends to be that \
                 YubiKey; not sending the PIN to any"
            ),
            None => formatter.write_str(
                "several security keys claim to be the one holding the key; not sending the PIN \
                 to any",
            ),
        }
    }
}

impl std::error::Error for SerialClaimedTwice {}

/// A device claimed the serial of a paired key but couldn't prove the
/// pairing; the request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unrecognized {
    /// The serial it claimed.
    pub serial: u32,
}

impl fmt::Display for Unrecognized {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the security key reporting serial {} can't prove skagent's pairing: it isn't the \
             YubiKey skagent paired (a fake, or it was reset); not sending the PIN",
            self.serial
        )
    }
}

impl std::error::Error for Unrecognized {}

/// Credential-to-device associations, independent of cached PINs.
#[derive(Debug, Default)]
pub struct Bindings {
    entries: HashMap<[u8; 32], Binding>,
    /// Where bindings with a serial or a pairing are remembered, if anywhere.
    file: Option<PathBuf>,
}

impl Bindings {
    /// The bindings remembered in `file`, remembering further ones there. A
    /// missing file holds none; one that can't be read is ignored with a
    /// warning, and replaced on the next change.
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
    /// serial or pairing known from before stays when this time there is
    /// none.
    pub fn bind(
        &mut self,
        key: &CredentialKey,
        device: DeviceIdentity,
        serial: Option<u32>,
        pairing: Option<PairingCredential>,
    ) {
        let digest = key.digest();
        let before = self.entries.get(&digest).cloned();
        let binding = Binding {
            device: Some(device),
            serial: serial.or(before.as_ref().and_then(|before| before.serial)),
            pairing: pairing.or_else(|| before.as_ref().and_then(|before| before.pairing.clone())),
        };
        let changed = before.is_none_or(|before| {
            before.serial != binding.serial || before.pairing != binding.pairing
        });
        self.entries.insert(digest, binding);
        if changed {
            self.save();
        }
    }

    /// Removes an identity's binding, not merely its PIN.
    pub fn forget(&mut self, key: &CredentialKey) {
        let removed = self.entries.remove(&key.digest());
        if removed.is_some_and(|binding| binding.remembered()) {
            self.save();
        }
    }

    /// Removes all associations when the agent unloads all identities.
    pub fn clear(&mut self) {
        let remembered = self.entries.values().any(Binding::remembered);
        self.entries.clear();
        if remembered {
            self.save();
        }
    }

    /// The pairing of `key`'s security key, once paired.
    #[must_use]
    pub fn pairing_of(&self, key: &CredentialKey) -> Option<&PairingCredential> {
        self.entries
            .get(&key.digest())
            .and_then(|binding| binding.pairing.as_ref())
    }

    /// Whether resolving `key` needs the serials of `devices`: its YubiKey
    /// is known, but its plug-in isn't among them.
    #[must_use]
    pub fn needs_serials(&self, key: Option<&CredentialKey>, devices: &[DeviceIdentity]) -> bool {
        self.away(key, devices)
            .is_some_and(|binding| binding.serial.is_some())
    }

    /// The pairing the devices must prove to resolve `key`: it is paired,
    /// but its plug-in isn't among `devices`.
    #[must_use]
    pub fn needs_proof(
        &self,
        key: Option<&CredentialKey>,
        devices: &[DeviceIdentity],
    ) -> Option<&PairingCredential> {
        self.away(key, devices)
            .and_then(|binding| binding.pairing.as_ref())
    }

    /// `key`'s binding, if its plug-in isn't among `devices`.
    fn away(&self, key: Option<&CredentialKey>, devices: &[DeviceIdentity]) -> Option<&Binding> {
        key.and_then(|key| self.entries.get(&key.digest()))
            .filter(|binding| {
                !binding
                    .device
                    .as_ref()
                    .is_some_and(|device| devices.contains(device))
            })
    }

    /// Chooses among the connected `devices` for `key` (`None`: loading,
    /// from any device). `serial_of` tells a device's serial, if known;
    /// `proof_of`, what it answered to the challenge of `key`'s pairing.
    ///
    /// Never another device in place of a known one: a paired key is the
    /// device that proves the pairing, and a device claiming its serial
    /// without the proof is refused; an unpaired YubiKey is recognized by its
    /// serial, unless two devices claim it; a lost binding without either
    /// needs a touch; a key that isn't plugged in is waited for. The only
    /// device is used for a credential seen for the first time.
    #[must_use]
    pub fn resolve(
        &self,
        key: Option<&CredentialKey>,
        devices: &[DeviceIdentity],
        serial_of: impl Fn(&DeviceIdentity) -> Option<u32>,
        proof_of: impl Fn(&DeviceIdentity) -> Proof,
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
        let serial = binding.serial;
        if binding.pairing.is_some() {
            let mut proven = devices
                .iter()
                .filter(|device| proof_of(device) == Proof::Proven);
            match (proven.next(), proven.next()) {
                (Some(device), None) => return Resolution::Direct(device.clone()),
                (Some(_), Some(_)) => return Resolution::Ambiguous { serial },
                (None, _) => {}
            }
            if let Some(serial) = serial {
                let fake = devices.iter().any(|device| {
                    serial_of(device) == Some(serial) && proof_of(device) == Proof::Disproven
                });
                if fake {
                    return Resolution::Unrecognized { serial };
                }
            }
            return Resolution::Wait(missing(serial, devices, &serial_of));
        }
        let Some(serial) = serial else {
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
            (Some(device), None) => Resolution::Direct(device.clone()),
            (Some(_), Some(_)) => Resolution::Ambiguous {
                serial: Some(serial),
            },
            (None, _) => Resolution::Wait(missing(Some(serial), devices, &serial_of)),
        }
    }

    /// Writes the bindings with a serial or a pairing down, if there is a
    /// file. A failure only costs the memory across restarts, with a warning.
    fn save(&self) {
        let Some(file) = &self.file else {
            return;
        };
        if let Err(error) = write_remembered(file, &self.entries) {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "can't remember which security key holds which key"
            );
        }
    }
}

/// What a request for the key with `serial` waits for among `devices`.
fn missing(
    serial: Option<u32>,
    devices: &[DeviceIdentity],
    serial_of: impl Fn(&DeviceIdentity) -> Option<u32>,
) -> Missing {
    if devices.is_empty() {
        Missing::Nothing { serial }
    } else {
        Missing::Elsewhere {
            serial,
            other: devices.iter().find_map(serial_of),
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
    state_files::state_path(DEFAULT_BINDINGS_NAME, xdg_state_home, home)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberedFile {
    #[serde(default)]
    binding: Vec<Remembered>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Remembered {
    credential: String,
    serial: Option<u32>,
    pairing_id: Option<String>,
    pairing_key: Option<String>,
}

fn read_remembered(file: &Path) -> Result<HashMap<[u8; 32], Binding>> {
    let Some(text) = state_files::read(file)? else {
        return Ok(HashMap::new());
    };
    let parsed: RememberedFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    parsed
        .binding
        .into_iter()
        .map(|remembered| {
            let pairing = match (remembered.pairing_id, remembered.pairing_key) {
                (Some(id), Some(public_key)) => Some(PairingCredential {
                    id: parse_hex(&id, 1024).context("pairing id")?,
                    public_key: parse_fixed(&public_key).context("pairing key")?,
                }),
                (None, None) => None,
                _ => anyhow::bail!("a pairing needs both pairing-id and pairing-key"),
            };
            ensure!(
                remembered.serial.is_some() || pairing.is_some(),
                "a remembered binding without a serial or a pairing"
            );
            Ok((
                parse_fixed(&remembered.credential).context("credential digest")?,
                Binding {
                    device: None,
                    serial: remembered.serial,
                    pairing,
                },
            ))
        })
        .collect()
}

/// Replaces `file` with the bindings worth remembering.
fn write_remembered(file: &Path, entries: &HashMap<[u8; 32], Binding>) -> Result<()> {
    let mut remembered: Vec<(String, &Binding)> = entries
        .iter()
        .filter(|(_, binding)| binding.remembered())
        .map(|(digest, binding)| (hex(digest), binding))
        .collect();
    remembered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut text = HEADER.to_owned();
    for (credential, binding) in remembered {
        write!(text, "\n[[binding]]\ncredential = \"{credential}\"\n")
            .context("formatting the remembered bindings")?;
        if let Some(serial) = binding.serial {
            writeln!(text, "serial = {serial}").context("formatting the remembered bindings")?;
        }
        if let Some(pairing) = &binding.pairing {
            writeln!(
                text,
                "pairing-id = \"{}\"\npairing-key = \"{}\"",
                hex(&pairing.id),
                hex(&pairing.public_key)
            )
            .context("formatting the remembered bindings")?;
        }
    }
    state_files::write(file, &text)
}
