//! age identities: credentials on security keys whose secret decrypts age
//! files (`docs/age.md`). This is what the agent knows about them and
//! remembers across restarts; the way to a security key's answer is
//! [`crate::signer`]'s.
//!
//! An identity is its credential. Its recipient, the public half, is only
//! known once the agent derived the key on this machine: a security key
//! doesn't give it without a touch.
//!
//! Known identities are remembered in `$XDG_STATE_HOME/skagent/age.toml`:
//! the credential's id and the recipient. Nothing in it is secret. With the
//! id alone the security key still denies that the credential exists; it
//! takes the PIN and a touch to use it.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use skagent_age::Recipient;
use skagent_fido::{AGE_RP_ID, AgeCredential};

use crate::pin_cache::CredentialKey;
use crate::state_files::{self, hex, parse_hex};

/// The file's name in `$XDG_STATE_HOME/skagent`.
pub const DEFAULT_AGE_NAME: &str = "age.toml";

const HEADER: &str = "\
# skagent: the age identities it found on security keys, and their recipients
# once it derived them. Nothing here is secret; using an identity takes its
# security key, the PIN and a touch. Written by skagent, don't edit.
";

/// Most identities kept. A security key holds 25 to 100 credentials of all
/// kinds.
pub const MAX_IDENTITIES: usize = 256;

/// One age identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeIdentity {
    credential: AgeCredential,
    recipient: Option<Recipient>,
}

impl AgeIdentity {
    /// The credential on the security key.
    #[must_use]
    pub fn credential(&self) -> &AgeCredential {
        &self.credential
    }

    /// What files for this identity are encrypted to, once known.
    #[must_use]
    pub fn recipient(&self) -> Option<&Recipient> {
        self.recipient.as_ref()
    }

    /// The credential as routing, the PIN cache and the bindings know it.
    #[must_use]
    pub fn key(&self) -> CredentialKey {
        CredentialKey::new(AGE_RP_ID, self.credential.id())
    }
}

/// Why no identity was chosen for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotChosen {
    /// No identity fits: none is known, or none that could be the one named.
    NoIdentity,
    /// Several fit, and nothing says which.
    Ambiguous,
}

impl std::fmt::Display for NotChosen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NoIdentity => {
                "no age identity fits the request; `skagent load` finds the ones on a security key"
            }
            Self::Ambiguous => {
                "several age identities fit the request and it names none; use an identity file \
                 from `skagent age identity`"
            }
        })
    }
}

impl std::error::Error for NotChosen {}

/// The age identities the agent knows.
#[derive(Debug, Default)]
pub struct AgeIdentities {
    known: Vec<AgeIdentity>,
    /// Where they are remembered, if anywhere.
    file: Option<PathBuf>,
}

impl AgeIdentities {
    /// The identities remembered in `file`, and remembered there from now
    /// on. A file that can't be read is ignored, with a warning, and
    /// replaced by the next change.
    #[must_use]
    pub fn remembered_in(file: PathBuf) -> Self {
        let known = read_remembered(&file).unwrap_or_else(|error| {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "ignoring the remembered age identities"
            );
            Vec::new()
        });
        Self {
            known,
            file: Some(file),
        }
    }

    /// The known identities, in the order they were found.
    #[must_use]
    pub fn all(&self) -> &[AgeIdentity] {
        &self.known
    }

    /// Takes note of `credentials` found on a security key. Returns how many
    /// weren't known.
    pub fn found(&mut self, credentials: &[AgeCredential]) -> usize {
        let mut new = 0_usize;
        for credential in credentials {
            if self.position(credential).is_none() && self.known.len() < MAX_IDENTITIES {
                self.known.push(AgeIdentity {
                    credential: credential.clone(),
                    recipient: None,
                });
                new = new.saturating_add(1);
            }
        }
        if new > 0 {
            self.save();
        }
        new
    }

    /// Takes note of the recipient the agent derived for `credential`, which
    /// becomes known if it wasn't.
    pub fn derived(&mut self, credential: &AgeCredential, recipient: &Recipient) {
        match self.position(credential) {
            Some(position) => {
                let Some(identity) = self.known.get_mut(position) else {
                    return;
                };
                if identity.recipient.as_ref() == Some(recipient) {
                    return;
                }
                identity.recipient = Some(recipient.clone());
            }
            None if self.known.len() < MAX_IDENTITIES => self.known.push(AgeIdentity {
                credential: credential.clone(),
                recipient: Some(recipient.clone()),
            }),
            None => return,
        }
        self.save();
    }

    /// The identity a request is for. `named`: the recipient its identity
    /// string carries, if any. `at_hand` says whether an identity's
    /// security key is plugged in, and is only asked when more than one
    /// identity fits.
    ///
    /// An identity whose recipient isn't known yet could be the one named;
    /// the derivation tells. Of several such, the first one at hand is
    /// chosen (else the first): once the caller knows its recipient
    /// ([`AgeIdentities::derived`]) and it wasn't the one, the next choice
    /// is another.
    ///
    /// # Errors
    ///
    /// Returns [`NotChosen`] if no identity fits, or the request names none
    /// and it isn't exactly one that is at hand: which one a file is for
    /// only shows by trying, with a touch each, every time.
    pub fn choose(
        &self,
        named: Option<&Recipient>,
        at_hand: impl Fn(&AgeIdentity) -> bool,
    ) -> Result<AgeIdentity, NotChosen> {
        if let Some(named) = named
            && let Some(exact) = self
                .known
                .iter()
                .find(|identity| identity.recipient.as_ref() == Some(named))
        {
            return Ok(exact.clone());
        }
        let candidates: Vec<&AgeIdentity> = self
            .known
            .iter()
            .filter(|identity| named.is_none() || identity.recipient.is_none())
            .collect();
        match candidates.as_slice() {
            [] => Err(NotChosen::NoIdentity),
            [only] => Ok((*only).clone()),
            several => {
                let mut present = several.iter().filter(|identity| at_hand(identity));
                match (present.next(), present.next(), named, several.first()) {
                    (Some(only), None, _, _) => Ok((*only).clone()),
                    (Some(first), Some(_), Some(_), _) | (None, _, Some(_), Some(first)) => {
                        Ok((*first).clone())
                    }
                    _ => Err(NotChosen::Ambiguous),
                }
            }
        }
    }

    fn position(&self, credential: &AgeCredential) -> Option<usize> {
        self.known
            .iter()
            .position(|identity| identity.credential == *credential)
    }

    /// Writes the identities down, if there is a file. A failure only costs
    /// the memory across restarts, with a warning.
    fn save(&self) {
        let Some(file) = &self.file else {
            return;
        };
        if let Err(error) = write_remembered(file, &self.known) {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "can't remember the age identities"
            );
        }
    }
}

/// Where age identities are remembered: `$XDG_STATE_HOME/skagent/age.toml`,
/// else `$HOME/.local/state/…`.
///
/// # Errors
///
/// Returns an error if neither variable gives an absolute path.
pub fn default_age_path(xdg_state_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    state_files::state_path(DEFAULT_AGE_NAME, xdg_state_home, home)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberedFile {
    #[serde(default)]
    identity: Vec<Remembered>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Remembered {
    credential: String,
    recipient: Option<String>,
}

fn read_remembered(file: &Path) -> Result<Vec<AgeIdentity>> {
    let Some(text) = state_files::read(file)? else {
        return Ok(Vec::new());
    };
    let parsed: RememberedFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    anyhow::ensure!(
        parsed.identity.len() <= MAX_IDENTITIES,
        "{} holds more than {MAX_IDENTITIES} identities",
        file.display()
    );
    let mut known: Vec<AgeIdentity> = Vec::new();
    for remembered in parsed.identity {
        let credential =
            AgeCredential::new(parse_hex(&remembered.credential, 1024).context("credential id")?)?;
        anyhow::ensure!(
            known
                .iter()
                .all(|identity| identity.credential != credential),
            "{} lists a credential twice",
            file.display()
        );
        let recipient = remembered
            .recipient
            .map(|recipient| recipient.parse::<Recipient>())
            .transpose()
            .context("recipient")?;
        known.push(AgeIdentity {
            credential,
            recipient,
        });
    }
    Ok(known)
}

/// Replaces `file` with `known`.
fn write_remembered(file: &Path, known: &[AgeIdentity]) -> Result<()> {
    let mut text = HEADER.to_owned();
    for identity in known {
        write!(
            text,
            "\n[[identity]]\ncredential = \"{}\"\n",
            hex(identity.credential.id())
        )
        .context("formatting the remembered age identities")?;
        if let Some(recipient) = &identity.recipient {
            writeln!(text, "recipient = \"{recipient}\"")
                .context("formatting the remembered age identities")?;
        }
    }
    state_files::write(file, &text)
}
