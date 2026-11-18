//! The keys the agent holds: `sk-ssh-ed25519@openssh.com` keys only, each
//! with an optional expiry.
//!
//! Keys added on this machine without a lifetime or destination constraints
//! (`ssh-add`, `skagent load`) are remembered in a file and offered again
//! after a restart; signing still needs the security key, and the PIN.
//! Nothing in it is secret: public keys, comments and key handles, as stub
//! files hold them.
//!
//! Time is always passed in as `now`, so expiry is deterministic in tests.

use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use serde::Deserialize;
use skagent_fido::ResidentCredential;
use ssh_agent_lib::proto::{
    Extension, Identity, KeyConstraint, PrivateCredential, PublicCredential,
};
use ssh_agent_lib::ssh_key::private::KeypairData;
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use ssh_agent_lib::ssh_key::{HashAlg, PublicKey};

use crate::destination::{
    DestinationConstraint, RESTRICT_DESTINATION_CONSTRAINT, parse_destination_constraints,
};
use crate::display::{self, MAX_NAME_CHARS};
use crate::state_files::{self, hex, parse_hex, toml_string};

/// The file's name in `$XDG_STATE_HOME/skagent`.
pub const DEFAULT_KEYS_NAME: &str = "keys.toml";

/// Most keys remembered; a longer file is refused as a whole.
const MAX_REMEMBERED_KEYS: usize = 256;

/// Longest key handle and comment read back, in bytes.
const MAX_KEY_HANDLE_BYTES: usize = 1024;
const MAX_COMMENT_BYTES: usize = 4096;

const KEYS_HEADER: &str = "\
# The keys skagent offers again after a restart: those added on this machine
# without a lifetime or destination constraints (ssh-add, skagent load).
# Signing still needs the security key and its PIN. skagent rewrites this
# file; `ssh-add -d` and `ssh-add -D` remove keys from it.
";

/// Where a key was added from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// This machine. Without a lifetime or destination constraints, the key
    /// is remembered across restarts.
    Local,
    /// Another machine, through a forwarded agent. Never remembered, and it
    /// doesn't change what is.
    Forwarded,
}

/// OpenSSH sk key flag: the key needs a touch for every signature.
pub const SK_USER_PRESENCE_REQUIRED: u8 = 0x01;
/// OpenSSH sk key flag: the key needs user verification (PIN) for every
/// signature (`verify-required`).
pub const SK_USER_VERIFICATION_REQUIRED: u8 = 0x04;

/// Extension constraint `ssh-add` attaches to sk keys, naming the security
/// key middleware that should drive the device.
pub const SK_PROVIDER_CONSTRAINT: &str = "sk-provider@openssh.com";

/// Middleware name for OpenSSH's built-in libfido2 support, the only one
/// skagent implements.
pub const BUILT_IN_SK_PROVIDER: &[u8] = b"internal";

/// What the constraints of an `ADD_IDENTITY_CONSTRAINED` request amount to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AcceptedConstraints {
    /// Remove the key after this long (`ssh-add -t`).
    pub lifetime: Option<Duration>,
    /// Where the key may be used (`ssh-add -h`); empty means anywhere.
    pub destinations: Vec<DestinationConstraint>,
}

/// Checks key constraints. Anything skagent doesn't implement refuses the
/// whole key: silently ignoring a constraint would hand out a key with fewer
/// restrictions than the user asked for.
///
/// # Errors
///
/// Returns an error naming the first constraint that can't be honored.
pub fn evaluate_constraints(constraints: &[KeyConstraint]) -> Result<AcceptedConstraints> {
    let mut lifetime = None;
    let mut provider_seen = false;
    let mut destinations: Option<Vec<DestinationConstraint>> = None;
    for constraint in constraints {
        match constraint {
            KeyConstraint::Lifetime(0) => bail!("a key lifetime of 0 seconds is not valid"),
            KeyConstraint::Lifetime(seconds) => {
                if lifetime
                    .replace(Duration::from_secs(u64::from(*seconds)))
                    .is_some()
                {
                    bail!("the lifetime constraint is given more than once");
                }
            }
            KeyConstraint::Confirm => bail!(
                "confirmation constraints (ssh-add -c) are not supported; \
                 the touch on the security key already confirms every signature"
            ),
            KeyConstraint::Extension(Extension { name, details })
                if name == SK_PROVIDER_CONSTRAINT =>
            {
                if provider_seen {
                    bail!("the {SK_PROVIDER_CONSTRAINT} constraint is given more than once");
                }
                provider_seen = true;
                if details.as_ref() != BUILT_IN_SK_PROVIDER {
                    bail!(
                        "security key provider \"{}\" is not supported, only the built-in one",
                        display::shown(&String::from_utf8_lossy(details.as_ref()), MAX_NAME_CHARS)
                    );
                }
            }
            KeyConstraint::Extension(Extension { name, details })
                if name == RESTRICT_DESTINATION_CONSTRAINT =>
            {
                let parsed = parse_destination_constraints(details.as_ref())
                    .context("refusing a key with unusable destination constraints")?;
                if destinations.replace(parsed).is_some() {
                    bail!(
                        "the {RESTRICT_DESTINATION_CONSTRAINT} constraint is given more than once"
                    );
                }
            }
            KeyConstraint::Extension(Extension { name, .. }) => {
                bail!(
                    "key constraint \"{}\" is not supported",
                    display::shown(name, MAX_NAME_CHARS)
                );
            }
        }
    }
    Ok(AcceptedConstraints {
        lifetime,
        destinations: destinations.unwrap_or_default(),
    })
}

/// An sk key the agent can sign with.
///
/// The key handle isn't a secret for `verify-required` keys (the PIN is
/// still needed), but it is never logged: `Debug` shows its length only.
#[derive(Clone, PartialEq, Eq)]
pub struct SkIdentity {
    public: SkEd25519,
    flags: u8,
    key_handle: Vec<u8>,
    comment: String,
    expires_at: Option<Instant>,
    /// Where the key may be used; empty means anywhere.
    destinations: Vec<DestinationConstraint>,
}

impl SkIdentity {
    /// Builds a public agent identity from authenticated resident metadata.
    /// The original SSH comment isn't on the authenticator: use RP and user.
    #[must_use]
    pub fn from_resident(credential: &ResidentCredential) -> Self {
        let flags = SK_USER_PRESENCE_REQUIRED
            | if credential.requires_pin() {
                SK_USER_VERIFICATION_REQUIRED
            } else {
                0
            };
        Self {
            public: SkEd25519::new(
                Ed25519PublicKey(*credential.public_key()),
                credential.application(),
            ),
            flags,
            key_handle: credential.key_handle().to_vec(),
            comment: format!("{} {}", credential.application(), credential.user_name())
                .trim_end()
                .to_owned(),
            expires_at: None,
            destinations: Vec::new(),
        }
    }

    /// Takes an sk key out of an `ADD_IDENTITY` credential.
    ///
    /// # Errors
    ///
    /// Returns an error for every other key type and for certificates.
    pub fn from_credential(
        credential: PrivateCredential,
        expires_at: Option<Instant>,
    ) -> Result<Self> {
        match credential {
            PrivateCredential::Key {
                privkey: KeypairData::SkEd25519(keypair),
                comment,
            } => Ok(Self {
                public: keypair.public().clone(),
                flags: keypair.flags(),
                key_handle: keypair.key_handle().to_vec(),
                comment,
                expires_at,
                destinations: Vec::new(),
            }),
            PrivateCredential::Key { privkey, .. } => {
                let algorithm = privkey.algorithm().map_or_else(
                    |_| "an unknown key type".to_owned(),
                    |algorithm| algorithm.to_string(),
                );
                bail!("only sk-ssh-ed25519@openssh.com keys are accepted, not {algorithm}")
            }
            PrivateCredential::Cert { algorithm, .. } => {
                bail!("certificates are not supported ({algorithm})")
            }
        }
    }

    /// The public key as it appears on the wire.
    #[must_use]
    pub fn key_data(&self) -> KeyData {
        KeyData::SkEd25519(self.public.clone())
    }

    /// The `REQUEST_IDENTITIES` entry for this key.
    #[must_use]
    pub fn identity(&self) -> Identity {
        Identity {
            credential: PublicCredential::Key(self.key_data()),
            comment: self.comment.clone(),
        }
    }

    /// Whether `key` is this identity's public key.
    #[must_use]
    pub fn matches(&self, key: &KeyData) -> bool {
        matches!(key, KeyData::SkEd25519(public) if *public == self.public)
    }

    /// FIDO relying party id, e.g. `ssh:example`.
    #[must_use]
    pub fn application(&self) -> &str {
        self.public.application()
    }

    /// The credential id that tells the authenticator which key to use.
    #[must_use]
    pub fn key_handle(&self) -> &[u8] {
        &self.key_handle
    }

    /// OpenSSH sk flags, e.g. user presence and verification required.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether signing needs the PIN (`verify-required`).
    #[must_use]
    pub fn requires_pin(&self) -> bool {
        self.flags & SK_USER_VERIFICATION_REQUIRED != 0
    }

    /// The key comment.
    #[must_use]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// `SHA256:...` fingerprint, as `ssh-add -l` shows it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key_data().fingerprint(HashAlg::Sha256).to_string()
    }

    /// When the key leaves the agent, if it has a lifetime.
    #[must_use]
    pub fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    /// The same identity, restricted to `destinations` (`ssh-add -h`).
    #[must_use]
    pub fn with_destinations(mut self, destinations: Vec<DestinationConstraint>) -> Self {
        self.destinations = destinations;
        self
    }

    /// Where the key may be used; empty means anywhere.
    #[must_use]
    pub fn destinations(&self) -> &[DestinationConstraint] {
        &self.destinations
    }
}

impl fmt::Debug for SkIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkIdentity")
            .field("fingerprint", &self.fingerprint())
            .field("application", &self.application())
            .field("comment", &self.comment)
            .field("flags", &self.flags)
            .field("key_handle_len", &self.key_handle.len())
            .field("expires_at", &self.expires_at)
            .field("destinations", &self.destinations.len())
            // public key and key handle are represented by fingerprint and length
            .finish_non_exhaustive()
    }
}

/// The agent's identities, in the order they were added.
#[derive(Debug, Default)]
pub struct IdentityStore {
    identities: Vec<SkIdentity>,
    /// The identities remembered across restarts, as written to `file`.
    remembered: Vec<SkIdentity>,
    /// Where they are remembered, if anywhere.
    file: Option<PathBuf>,
}

impl IdentityStore {
    /// The identities remembered in `file`, remembering further ones there.
    /// A missing file holds none; one that can't be read is ignored with a
    /// warning, and replaced on the next change.
    #[must_use]
    pub fn remembered_in(file: PathBuf) -> Self {
        let remembered = read_keys(&file).unwrap_or_else(|error| {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "ignoring the remembered keys"
            );
            Vec::new()
        });
        if !remembered.is_empty() {
            tracing::info!(
                file = %file.display(),
                keys = remembered.len(),
                "offering the keys remembered from before"
            );
        }
        Self {
            identities: remembered.clone(),
            remembered,
            file: Some(file),
        }
    }

    /// Adds `identity`, or replaces the entry with the same public key (new
    /// comment, flags, key handle and expiry), like OpenSSH's agent. Added
    /// on this machine, it's remembered across restarts if it has no
    /// lifetime and no destination constraints, and forgotten otherwise.
    ///
    /// Returns whether an existing entry was replaced.
    pub fn add(&mut self, identity: SkIdentity, origin: Origin) -> bool {
        if origin == Origin::Local {
            self.remember(&identity);
        }
        if let Some(existing) = self
            .identities
            .iter_mut()
            .find(|existing| existing.public == identity.public)
        {
            *existing = identity;
            true
        } else {
            self.identities.push(identity);
            false
        }
    }

    /// A loaded identity with another public key but `identity`'s credential
    /// (application and key handle). PIN cache entries and device bindings
    /// belong to the credential, so the two keys would share them: a key
    /// added through a forwarded agent with a leaked key handle could sign
    /// with the PIN cached for, and outside the destination constraints of,
    /// the real key.
    #[must_use]
    pub fn sharing_credential(&self, identity: &SkIdentity) -> Option<&SkIdentity> {
        self.identities.iter().find(|existing| {
            existing.public != identity.public
                && existing.application() == identity.application()
                && existing.key_handle == identity.key_handle
        })
    }

    /// Plans a resident import without overwriting an existing identity's
    /// lifetime, comment or flags. Conflicting handles/policies are refused.
    ///
    /// # Errors
    /// Refuses a resident key whose public key matches different stored metadata.
    pub fn resident_imports(
        &mut self,
        loaded: &[SkIdentity],
        now: Instant,
    ) -> Result<Vec<SkIdentity>> {
        self.expire(now);
        loaded.iter().map(|identity| {
            if let Some(other) = self.sharing_credential(identity) {
                bail!(
                    "resident key {} uses the credential of the loaded key {}; remove that key before reloading",
                    identity.fingerprint(),
                    other.fingerprint()
                );
            }
            let Some(existing) = self.identities.iter().find(|existing| existing.public == identity.public) else {
                return Ok(identity.clone());
            };
            ensure!(existing.key_handle == identity.key_handle && existing.requires_pin() == identity.requires_pin(),
                "resident key {} conflicts with a loaded identity; remove it explicitly before reloading", identity.fingerprint());
            Ok(existing.clone())
        }).collect()
    }

    /// Removes the identity with public key `key` and returns it. It isn't
    /// remembered any more either.
    pub fn remove(&mut self, key: &KeyData, now: Instant) -> Option<SkIdentity> {
        self.expire(now);
        let index = self
            .identities
            .iter()
            .position(|identity| identity.matches(key))?;
        let removed = self.identities.remove(index);
        let remembered = self.remembered.len();
        self.remembered.retain(|identity| !identity.matches(key));
        if self.remembered.len() != remembered {
            self.save();
        }
        Some(removed)
    }

    /// Removes all identities, remembered ones included. Returns how many
    /// there were.
    pub fn clear(&mut self) -> usize {
        let removed = self.identities.len();
        self.identities.clear();
        if !self.remembered.is_empty() {
            self.remembered.clear();
            self.save();
        }
        removed
    }

    /// Remembers `identity` (added on this machine) if it qualifies, or
    /// forgets an older entry with its public key if it doesn't: a key added
    /// again with a lifetime or destinations mustn't come back without them.
    fn remember(&mut self, identity: &SkIdentity) {
        let qualifies = identity.expires_at.is_none() && identity.destinations.is_empty();
        let known = self
            .remembered
            .iter()
            .any(|remembered| remembered.public == identity.public);
        let changed = if qualifies {
            if self.remembered.contains(identity) {
                false
            } else if known {
                for remembered in &mut self.remembered {
                    if remembered.public == identity.public {
                        *remembered = identity.clone();
                    }
                }
                true
            } else {
                self.remembered.push(identity.clone());
                true
            }
        } else if known {
            self.remembered
                .retain(|remembered| remembered.public != identity.public);
            true
        } else {
            false
        };
        if changed {
            self.save();
        }
    }

    /// Writes the remembered identities down, if there is a file. A failure
    /// only costs them across restarts, with a warning.
    fn save(&self) {
        let Some(file) = &self.file else {
            return;
        };
        if let Err(error) = write_keys(file, &self.remembered) {
            tracing::warn!(
                file = %file.display(),
                error = %format!("{error:#}"),
                "can't remember the keys across restarts"
            );
        }
    }

    /// The identities that haven't expired at `now`. Expired ones are dropped.
    pub fn identities(&mut self, now: Instant) -> &[SkIdentity] {
        self.expire(now);
        &self.identities
    }

    /// The identity with public key `key`, unless it has expired at `now`.
    pub fn find(&mut self, key: &KeyData, now: Instant) -> Option<&SkIdentity> {
        self.expire(now);
        self.identities
            .iter()
            .find(|identity| identity.matches(key))
    }

    /// Removes and returns the identities whose lifetime ended at `now`, so
    /// the caller can drop their PINs and device bindings too.
    pub fn take_expired(&mut self, now: Instant) -> Vec<SkIdentity> {
        let (expired, kept) = std::mem::take(&mut self.identities)
            .into_iter()
            .partition(|identity| identity.is_expired(now));
        self.identities = kept;
        expired
    }

    /// Safety net for callers that didn't [`IdentityStore::take_expired`]
    /// with the same `now` first: an expired identity is never handed out.
    fn expire(&mut self, now: Instant) {
        for identity in self.take_expired(now) {
            tracing::warn!(
                fingerprint = %identity.fingerprint(),
                comment = %identity.comment,
                "key lifetime ended, removed without dropping its PIN"
            );
        }
    }
}

/// Where keys are remembered: `$XDG_STATE_HOME/skagent/keys.toml`, else
/// `$HOME/.local/state/…`.
///
/// # Errors
///
/// Returns an error if neither variable gives an absolute path.
pub fn default_keys_path(xdg_state_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    state_files::state_path(DEFAULT_KEYS_NAME, xdg_state_home, home)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    #[serde(default)]
    key: Vec<RememberedKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RememberedKey {
    public_key: String,
    flags: u8,
    key_handle: String,
    #[serde(default)]
    comment: String,
}

fn read_keys(file: &Path) -> Result<Vec<SkIdentity>> {
    let Some(text) = state_files::read(file)? else {
        return Ok(Vec::new());
    };
    let parsed: KeysFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
    ensure!(
        parsed.key.len() <= MAX_REMEMBERED_KEYS,
        "more than {MAX_REMEMBERED_KEYS} keys"
    );
    let mut identities: Vec<SkIdentity> = Vec::with_capacity(parsed.key.len());
    for remembered in parsed.key {
        let public = PublicKey::from_openssh(&remembered.public_key)
            .with_context(|| format!("public key {:?}", remembered.public_key))?;
        let KeyData::SkEd25519(public) = public.key_data().clone() else {
            bail!(
                "{:?} is not an sk-ssh-ed25519@openssh.com key",
                remembered.public_key
            );
        };
        ensure!(
            remembered.comment.len() <= MAX_COMMENT_BYTES,
            "a comment longer than {MAX_COMMENT_BYTES} bytes"
        );
        let identity = SkIdentity {
            public,
            flags: remembered.flags,
            key_handle: parse_hex(&remembered.key_handle, MAX_KEY_HANDLE_BYTES)
                .context("key handle")?,
            comment: remembered.comment,
            expires_at: None,
            destinations: Vec::new(),
        };
        // Like adding: one entry per public key and per credential.
        let clash = identities.iter().find(|other| {
            other.public == identity.public
                || (other.application() == identity.application()
                    && other.key_handle == identity.key_handle)
        });
        if let Some(other) = clash {
            bail!(
                "keys {} and {} share a public key or a credential",
                other.fingerprint(),
                identity.fingerprint()
            );
        }
        identities.push(identity);
    }
    Ok(identities)
}

fn write_keys(file: &Path, identities: &[SkIdentity]) -> Result<()> {
    let mut text = KEYS_HEADER.to_owned();
    for identity in identities {
        let public = PublicKey::new(identity.key_data(), "")
            .to_openssh()
            .context("encoding a public key")?;
        writeln!(
            text,
            "\n[[key]]\npublic-key = {}\nflags = {}\nkey-handle = \"{}\"\ncomment = {}",
            toml_string(&public),
            identity.flags,
            hex(&identity.key_handle),
            toml_string(&identity.comment)
        )
        .context("formatting the remembered keys")?;
    }
    state_files::write(file, &text)
}
