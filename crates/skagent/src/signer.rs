//! Signing with an sk key on its security key, with the PIN cache.
//!
//! One signature at a time: the device can only do one operation anyway, and
//! it keeps two requests for the same key from prompting twice.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::{Digest as _, Sha256};
use skagent_fido::{AssertRequest, Device, ErrorKind, Statement, error_kind, hid_devices};
use skagent_secret::SecretBuffer;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use tokio::sync::Mutex;

use crate::device::DeviceIdentity;
use crate::identities::SkIdentity;
use crate::pin_cache::{CachePolicy, CredentialKey, Lookup, Miss, PinCache};
use crate::prompt::{PinPrompt, PinRequest};

/// OpenSSH sk flag: the key needs a touch for every signature.
pub const SK_USER_PRESENCE_REQUIRED: u8 = 0x01;
/// OpenSSH sk flag: the key needs user verification (PIN) for every signature.
pub const SK_USER_VERIFICATION_REQUIRED: u8 = 0x04;

/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Signs, asking for PINs and caching them.
#[derive(Debug)]
pub struct Signer {
    prompt: Option<PinPrompt>,
    state: Mutex<State>,
    /// Held for a whole signature: prompt, device operation, cache update.
    operation: Mutex<()>,
}

#[derive(Debug)]
struct State {
    cache: PinCache,
    /// Shown with the next prompt for that credential, e.g. "wrong PIN".
    last_failure: HashMap<CredentialKey, String>,
}

/// Where the PIN for one signature came from.
enum PinSource {
    None,
    Cache(SecretBuffer),
    User(SecretBuffer),
}

impl PinSource {
    fn pin(&self) -> Option<&SecretBuffer> {
        match self {
            Self::None => None,
            Self::Cache(pin) | Self::User(pin) => Some(pin),
        }
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new(None, CachePolicy::default())
    }
}

impl Signer {
    /// A signer that asks through `prompt` and caches with `policy`. Without
    /// a prompt, keys that need a PIN can't sign.
    #[must_use]
    pub fn new(prompt: Option<PinPrompt>, policy: CachePolicy) -> Self {
        Self {
            prompt,
            state: Mutex::new(State {
                cache: PinCache::new(policy),
                last_failure: HashMap::new(),
            }),
            operation: Mutex::new(()),
        }
    }

    /// Drops all cached PINs. Returns how many there were.
    pub async fn forget_all(&self) -> usize {
        self.state.lock().await.cache.clear()
    }

    /// Drops the cached PIN of `identity`. Returns whether there was one.
    pub async fn forget(&self, identity: &SkIdentity) -> bool {
        self.state
            .lock()
            .await
            .cache
            .evict(&credential_key(identity))
    }

    /// Drops PINs whose lifetime or idle timeout ended. Returns how many.
    pub async fn expire(&self, now: Instant) -> usize {
        self.state.lock().await.cache.expire(now)
    }

    /// Number of cached PINs.
    pub async fn cached(&self) -> usize {
        self.state.lock().await.cache.len()
    }

    /// Signs `data` with `identity`.
    ///
    /// Needs exactly one connected security key. Uses the cached PIN if the
    /// cache rules allow it, otherwise asks the user.
    ///
    /// # Errors
    ///
    /// Returns an error if no unique device is connected, the PIN prompt fails,
    /// or the device refuses (wrong PIN, no touch, unknown credential).
    pub async fn sign(&self, identity: &SkIdentity, data: &[u8]) -> Result<Signature> {
        let _operation = self.operation.lock().await;
        let key = credential_key(identity);
        let path = only_device().await?;
        let device = DeviceIdentity::of(&path)?;

        let source = if identity.flags() & SK_USER_VERIFICATION_REQUIRED == 0 {
            PinSource::None
        } else {
            self.pin_for(identity, &key, &device).await?
        };

        let request = OwnedAssertRequest {
            rp_id: identity.application().to_owned(),
            client_data_hash: Sha256::digest(data).into(),
            key_handle: identity.key_handle().to_vec(),
            user_presence: identity.flags() & SK_USER_PRESENCE_REQUIRED != 0,
        };
        let (source, outcome) = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                let outcome = assert_on(&path, &request, source.pin());
                (source, outcome)
            })
            .await
            .context("the signing thread panicked or was cancelled")?
        };

        match outcome {
            Ok((statement, retries_after)) => {
                self.remember(&key, source, &device, retries_after).await;
                ssh_signature(&statement)
            }
            Err(error) => {
                self.record_failure(identity, &key, &source, &error).await;
                Err(error.context(format!("signing with {}", describe(identity))))
            }
        }
    }

    /// The PIN to use: cached if allowed, otherwise asked for.
    async fn pin_for(
        &self,
        identity: &SkIdentity,
        key: &CredentialKey,
        device: &DeviceIdentity,
    ) -> Result<PinSource> {
        let path = device.path().to_owned();
        let retries = tokio::task::spawn_blocking(move || Device::open(&path)?.pin_retries())
            .await
            .context("the device thread panicked or was cancelled")??;

        let (lookup, last_failure) = {
            let mut state = self.state.lock().await;
            if retries == 0 {
                state.cache.evict(key);
                bail!(
                    "the PIN of the security key at {} is blocked; only a FIDO reset (which wipes the key) helps",
                    device.path()
                );
            }
            let lookup = state.cache.lookup(key, device, retries, Instant::now())?;
            (lookup, state.last_failure.get(key).cloned())
        };
        let miss = match lookup {
            Lookup::Hit(pin) => {
                tracing::debug!(key = %describe(identity), "using the cached PIN");
                return Ok(PinSource::Cache(pin));
            }
            Lookup::Miss(miss) => miss,
        };
        if miss != Miss::NotCached {
            tracing::info!(key = %describe(identity), reason = %miss, "asking for the PIN again");
        }

        let prompt = self.prompt.as_ref().ok_or_else(|| {
            anyhow!(
                "{} needs a PIN, but no PIN prompt is configured (--prompt, --pinentry, --askpass)",
                describe(identity)
            )
        })?;
        let pin = prompt
            .ask(&PinRequest {
                key: &describe(identity),
                retries: Some(retries),
                error: last_failure.as_deref(),
            })
            .await?;
        Ok(PinSource::User(pin))
    }

    /// After a successful signature: cache a typed PIN, or note the use of a
    /// cached one. Only if the device node is still the one the PIN went to.
    async fn remember(
        &self,
        key: &CredentialKey,
        source: PinSource,
        device: &DeviceIdentity,
        retries_after: Option<u32>,
    ) {
        let mut state = self.state.lock().await;
        state.last_failure.remove(key);
        let still_same_device = DeviceIdentity::of(device.path()).is_ok_and(|now| now == *device);
        match source {
            PinSource::None => {}
            PinSource::Cache(_) if still_same_device => state.cache.mark_used(key, Instant::now()),
            PinSource::User(pin) if still_same_device => {
                if let Some(retries) = retries_after {
                    state
                        .cache
                        .store(key.clone(), pin, device.clone(), retries, Instant::now());
                } else {
                    tracing::warn!(
                        "not caching the PIN: the retry counter couldn't be read after signing"
                    );
                }
            }
            PinSource::Cache(_) | PinSource::User(_) => {
                state.cache.evict(key);
                tracing::warn!(
                    device = device.path(),
                    "the security key changed during the signature, not caching its PIN"
                );
            }
        }
    }

    async fn record_failure(
        &self,
        identity: &SkIdentity,
        key: &CredentialKey,
        source: &PinSource,
        error: &anyhow::Error,
    ) {
        let Some(kind) = error_kind(error) else {
            return;
        };
        let mut state = self.state.lock().await;
        if kind.invalidates_pin() {
            state.cache.evict(key);
        }
        let note = match kind {
            ErrorKind::PinInvalid => "The previous PIN was wrong",
            ErrorKind::PinAuthBlocked => "Too many wrong PINs: unplug the key and plug it back in",
            ErrorKind::PinPolicyViolation => {
                "The key wants a new PIN first: change it with `ykman fido access change-pin`"
            }
            _ => return,
        };
        if matches!(source, PinSource::Cache(_)) {
            // The retry guard should make this impossible, unless the PIN was
            // changed elsewhere without a failed attempt in between.
            tracing::warn!(key = %describe(identity), "the device rejected the cached PIN, dropped it");
        }
        state.last_failure.insert(key.clone(), note.to_owned());
    }
}

fn credential_key(identity: &SkIdentity) -> CredentialKey {
    CredentialKey::new(identity.application(), identity.key_handle())
}

/// The key as the user knows it: comment and fingerprint.
fn describe(identity: &SkIdentity) -> String {
    format!("{} ({})", identity.comment(), identity.fingerprint())
}

async fn only_device() -> Result<String> {
    let devices = tokio::task::spawn_blocking(hid_devices)
        .await
        .context("the device listing thread panicked or was cancelled")??;
    match devices.as_slice() {
        [] => bail!("no FIDO security key is connected"),
        [device] => Ok(device.path.clone()),
        several => bail!(
            "{} FIDO security keys are connected ({}); skagent can't pick one yet, leave only the key that holds this credential",
            several.len(),
            several
                .iter()
                .map(|device| format!("{} {}", device.path, device.product))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

struct OwnedAssertRequest {
    rp_id: String,
    client_data_hash: [u8; 32],
    key_handle: Vec<u8>,
    user_presence: bool,
}

/// Signs on the device at `path`. With a PIN, also returns the retry counter
/// right after, for the cache.
fn assert_on(
    path: &str,
    request: &OwnedAssertRequest,
    pin: Option<&SecretBuffer>,
) -> Result<(Statement, Option<u32>)> {
    let mut device = Device::open(path)?;
    let result = device.assert(
        &AssertRequest {
            rp_id: &request.rp_id,
            client_data_hash: request.client_data_hash,
            key_handle: &request.key_handle,
            user_presence: request.user_presence,
        },
        pin,
    );
    match result {
        Ok(statement) => {
            let retries = pin.and_then(|_| match device.pin_retries() {
                Ok(retries) => Some(retries),
                Err(error) => {
                    tracing::warn!(device = path, error = %format!("{error:#}"), "reading the retry counter after signing failed");
                    None
                }
            });
            Ok((statement, retries))
        }
        Err(error) => {
            if error_kind(&error) == Some(ErrorKind::PinInvalid) {
                // Reading the counter is free; it tells the user how close they are to a lockout.
                match device.pin_retries() {
                    Ok(retries) => tracing::warn!(device = path, retries, "wrong PIN"),
                    Err(retries_error) => tracing::warn!(
                        device = path,
                        error = %format!("{retries_error:#}"),
                        "wrong PIN, and the retry counter can't be read"
                    ),
                }
            }
            Err(error)
        }
    }
}

/// The `sk-ssh-ed25519@openssh.com` signature: Ed25519 signature, then the
/// authenticator flags and the signature counter, which the server needs to
/// rebuild the signed authenticator data.
///
/// # Errors
///
/// Returns an error if the signature isn't 64 bytes.
pub fn ssh_signature(statement: &Statement) -> Result<Signature> {
    if statement.signature.len() != ED25519_SIGNATURE_BYTES {
        bail!(
            "the security key returned a {}-byte signature, Ed25519 has {ED25519_SIGNATURE_BYTES}",
            statement.signature.len()
        );
    }
    let mut bytes = statement.signature.clone();
    bytes.push(statement.flags);
    bytes.extend_from_slice(&statement.counter.to_be_bytes());
    Signature::new(Algorithm::SkEd25519, bytes).context("encoding the sk-ssh-ed25519 signature")
}
