//! Signing with an sk key on its security key, with the PIN cache.
//!
//! One operation per device and per credential. Bound devices can sign in
//! parallel; touch selection is exclusive across devices.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha2::{Digest as _, Sha256};
use skagent_fido::{AssertRequest, ErrorKind, Statement, error_kind};
use skagent_secret::SecretBuffer;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use tokio::sync::{Mutex, watch};

use crate::device::DeviceIdentity;
use crate::identities::SkIdentity;
use crate::loading::PreparedLoad;
use crate::pin_cache::{CachePolicy, CredentialKey, Lookup, Miss, PinCache};
use crate::prompt::{PinPrompt, PinRequest};
use crate::routing::{RoutedDevice, Router};

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
    router: Router,
    invalidation: watch::Sender<()>,
}

/// Captured while the agent authorizes a request, before it queues for the
/// device. Any eviction invalidates outstanding requests, including prompts.
#[derive(Debug, Clone)]
pub struct SigningTicket(watch::Receiver<()>);

impl SigningTicket {
    /// Refuses a request authorized before an eviction.
    ///
    /// # Errors
    /// Returns an error after removal, lock, forget or watcher failure.
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self
                .0
                .has_changed()
                .context("checking signature authorization")?,
            "signature cancelled by PIN eviction; request a new signature"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct State {
    cache: PinCache,
    /// Shown with the next prompt for that credential, e.g. "wrong PIN".
    last_failure: HashMap<CredentialKey, String>,
    caching_available: bool,
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
                caching_available: true,
            }),
            router: Router::default(),
            invalidation: watch::channel(()).0,
        }
    }

    /// Authorizes a request in the current eviction generation.
    #[must_use]
    pub fn ticket(&self) -> SigningTicket {
        SigningTicket(self.invalidation.subscribe())
    }

    /// Drops all cached PINs and invalidates outstanding signatures.
    pub async fn forget_all(&self) -> usize {
        let mut state = self.state.lock().await;
        self.invalidation.send_replace(());
        state.cache.clear()
    }

    /// Unloads all identity-specific state as well as the cached PINs.
    pub async fn remove_all(&self) -> usize {
        let mut state = self.state.lock().await;
        self.invalidation.send_replace(());
        self.router.clear().await;
        state.last_failure.clear();
        state.cache.clear()
    }

    /// Disables caching while logind cannot be watched. Signing still works,
    /// but asks every time. Changes also invalidate in-flight requests.
    pub async fn set_caching_available(&self, available: bool) {
        let mut state = self.state.lock().await;
        if state.caching_available != available {
            state.caching_available = available;
            self.invalidation.send_replace(());
            state.cache.clear();
        }
    }

    /// Drops the cached PIN of `identity`. Returns whether there was one.
    pub async fn forget(&self, identity: &SkIdentity) -> bool {
        let mut state = self.state.lock().await;
        self.invalidation.send_replace(());
        let key = credential_key(identity);
        self.router.forget(&key).await;
        state.last_failure.remove(&key);
        state.cache.evict(&key)
    }

    /// Drops PINs whose lifetime or idle timeout ended. Returns how many.
    pub async fn expire(&self, now: Instant) -> usize {
        self.state.lock().await.cache.expire(now)
    }

    /// Number of cached PINs.
    pub async fn cached(&self) -> usize {
        self.state.lock().await.cache.len()
    }

    /// Authenticates and lists one selected device, without mutating identities.
    pub(crate) async fn prepare_load(&self, mut ticket: SigningTicket) -> Result<PreparedLoad> {
        let routing_ticket = ticket.clone();
        let mut routed = tokio::select! {
            biased;
            _ = ticket.0.changed() => bail!("resident loading cancelled by PIN eviction"),
            routed = self.router.for_load(routing_ticket) => routed?,
        };
        let (mut routed, retries) = tokio::task::spawn_blocking(move || {
            let retries = routed.device.pin_retries()?;
            Ok::<_, anyhow::Error>((routed, retries))
        })
        .await
        .context("reading PIN retries before resident loading")??;
        ensure!(retries > 0, "the selected security key's PIN is blocked");
        let prompt = self
            .prompt
            .as_ref()
            .context("resident loading needs a PIN prompt (--pinentry or --askpass)")?;
        let label = format!("resident SSH credentials on {}", routed.identity.path());
        let request = PinRequest {
            key: &label,
            retries: Some(retries),
            error: None,
        };
        let pin = tokio::select! {
            biased;
            _ = ticket.0.changed() => bail!("resident PIN prompt cancelled by PIN eviction"),
            pin = prompt.ask(&request) => pin?,
        };
        ticket.check()?;
        let worker_ticket = ticket.clone();
        let (routed, pin, outcome) = tokio::task::spawn_blocking(move || {
            let outcome = (|| {
                worker_ticket.check()?;
                ensure!(
                    DeviceIdentity::of(routed.identity.path())? == routed.identity,
                    "security key changed during the loading prompt"
                );
                let credentials = routed.device.resident_ssh_keys(&pin)?;
                let retries = routed.device.pin_retries()?;
                Ok::<_, anyhow::Error>((credentials, retries))
            })();
            (routed, pin, outcome)
        })
        .await
        .context("enumerating resident credentials in the device thread")?;
        if outcome
            .as_ref()
            .err()
            .and_then(error_kind)
            .is_some_and(ErrorKind::invalidates_pin)
        {
            self.state.lock().await.cache.evict_device(&routed.identity);
        }
        let (credentials, retries) = outcome
            .context("loading resident SSH credentials; the PIN is never retried automatically")?;
        ticket.check()?;
        ensure!(
            DeviceIdentity::of(routed.identity.path())? == routed.identity,
            "security key changed during resident loading"
        );
        Ok(PreparedLoad {
            identities: credentials.iter().map(SkIdentity::from_resident).collect(),
            pin,
            routed,
            retries,
            accepted_at: Instant::now(),
            ticket,
        })
    }

    /// Commits bindings and verified PINs. Caller holds the agent state lock
    /// and inserts the identities immediately afterwards, without awaiting.
    pub(crate) async fn prime_loaded(
        &self,
        loaded: &mut PreparedLoad,
        identities: &[SkIdentity],
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        loaded.ticket.check()?;
        let device = &loaded.routed.identity;
        ensure!(
            DeviceIdentity::of(device.path())? == *device,
            "security key changed before committing resident credentials"
        );
        // Allocate every copy before modifying state. An mlock failure cannot
        // leave a partially primed cache or partially loaded identity list.
        let mut pins = Vec::new();
        if state.caching_available && state.cache.policy().caches() {
            for identity in identities
                .iter()
                .filter(|identity| identity.flags() & SK_USER_VERIFICATION_REQUIRED != 0)
            {
                pins.push((
                    credential_key(identity),
                    SecretBuffer::from_slice(loaded.pin.expose())
                        .context("allocating a resident credential's cached PIN")?,
                ));
            }
        }
        for identity in identities {
            self.router
                .bind(credential_key(identity), device.clone())
                .await;
        }
        loaded.pin.clear();
        for (key, pin) in pins {
            state.last_failure.remove(&key);
            state
                .cache
                .store(key, pin, device.clone(), loaded.retries, loaded.accepted_at);
        }
        Ok(())
    }

    /// Signs `data` with `identity`.
    ///
    /// Uses the credential's bound device, or asks for selection by touch.
    /// Uses a cached PIN only on the device it was verified on.
    ///
    /// # Errors
    ///
    /// Returns an error if device selection or the PIN prompt fails,
    /// or the device refuses (wrong PIN, no touch, unknown credential).
    pub async fn sign(
        &self,
        identity: &SkIdentity,
        data: &[u8],
        mut ticket: SigningTicket,
    ) -> Result<Signature> {
        let key = credential_key(identity);
        let _credential = tokio::select! {
            biased;
            _ = ticket.0.changed() => bail!("queued signature cancelled by PIN eviction"),
            guard = self.router.credentials.lock(key.clone()) => guard,
        };
        ticket.check()?;
        tracing::info!(key = %describe(identity), "resolving the signing device");
        let routing_ticket = ticket.clone();
        let mut routed = tokio::select! {
            biased;
            _ = ticket.0.changed() => bail!("device selection cancelled by PIN eviction"),
            routed = self.router.route(&key, routing_ticket) => routed?,
        };
        let device = routed.identity.clone();
        let needs_pin = identity.flags() & SK_USER_VERIFICATION_REQUIRED != 0;
        let (mut routed, retries) = tokio::task::spawn_blocking(move || {
            let retries = if needs_pin {
                Some(routed.device.pin_retries()?)
            } else {
                None
            };
            Ok::<_, anyhow::Error>((routed, retries))
        })
        .await
        .context("reading the routed security key's PIN retry counter")??;

        let source = if identity.flags() & SK_USER_VERIFICATION_REQUIRED == 0 {
            PinSource::None
        } else {
            tokio::select! {
                biased;
                _ = ticket.0.changed() => bail!("PIN prompt cancelled by PIN eviction"),
                source = self.pin_for(identity, &key, &device, retries.context("missing PIN retry counter")?) => source?,
            }
        };

        let request = OwnedAssertRequest {
            rp_id: identity.application().to_owned(),
            client_data_hash: Sha256::digest(data).into(),
            key_handle: identity.key_handle().to_vec(),
            user_presence: true,
        };
        ticket.check()?;
        let retry_guard = matches!(source, PinSource::Cache(_))
            .then_some(retries)
            .flatten();
        let (source, outcome) = {
            let device = device.clone();
            tokio::task::spawn_blocking(move || {
                let outcome = assert_on(&mut routed, &device, &request, source.pin(), retry_guard);
                (source, outcome)
            })
            .await
            .context("the signing thread panicked or was cancelled")?
        };

        // A blocking libfido2 call cannot yet be cancelled. Wait for it, but
        // never return its signature or repopulate the cache after eviction.
        ticket.check()?;
        match outcome {
            Ok((statement, retries_after)) => {
                let signature = ssh_signature(&statement)?;
                ensure!(
                    statement.flags & SK_USER_PRESENCE_REQUIRED != 0,
                    "the assertion lacks user presence"
                );
                ensure!(
                    source.pin().is_none() || statement.flags & SK_USER_VERIFICATION_REQUIRED != 0,
                    "the assertion lacks user verification"
                );
                self.remember(&key, source, &device, retries_after, &ticket)
                    .await?;
                Ok(signature)
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
        retries: u32,
    ) -> Result<PinSource> {
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
                "{} needs a PIN, but no PIN prompt is configured (--pinentry or --askpass)",
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
        ticket: &SigningTicket,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        ticket.check()?;
        state.last_failure.remove(key);
        let still_same_device = DeviceIdentity::of(device.path()).is_ok_and(|now| now == *device);
        if still_same_device {
            self.router.bind(key.clone(), device.clone()).await;
        }
        if !state.caching_available {
            return Ok(());
        }
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
        Ok(())
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

struct OwnedAssertRequest {
    rp_id: String,
    client_data_hash: [u8; 32],
    key_handle: Vec<u8>,
    user_presence: bool,
}

/// Signs on the device at `path`. With a PIN, also returns the retry counter
/// right after, for the cache.
fn assert_on(
    routed: &mut RoutedDevice,
    expected: &DeviceIdentity,
    request: &OwnedAssertRequest,
    pin: Option<&SecretBuffer>,
    retry_guard: Option<u32>,
) -> Result<(Statement, Option<u32>)> {
    let path = expected.path();
    let device = &mut routed.device;
    ensure!(
        DeviceIdentity::of(path)? == *expected,
        "security key changed before signing at {path}"
    );
    if let Some(expected_retries) = retry_guard {
        ensure!(
            device.pin_retries()? == expected_retries,
            "PIN retry counter changed before signing at {path}"
        );
    }
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
