//! Signing with an sk key on its security key, with the PIN cache.
//!
//! One operation per device and per credential. Bound devices can sign in
//! parallel; touch selection is exclusive across devices.
//!
//! The way from a request to the security key's answer is the same for
//! whatever is asked of a credential: routing, the PIN from the cache or the
//! user, the touch, the checks before anything is returned or cached. A
//! [`Job`] is what differs: a signature with an SSH key here, the secret of
//! an age identity in [`crate::age`].

mod age;
mod batch;

pub(crate) use age::Offer;
pub use age::purpose as decryption_purpose;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha2::{Digest as _, Sha256};
use signature::Verifier as _;
use skagent_fido::{
    AgeCredential, AssertRequest, ErrorKind, PairingCredential, ResidentCredential, Statement,
    error_kind,
};
use skagent_popup::{Failure, Host, Key, Mistake, Queued, Request, SecurityKey, State as Shown};
use skagent_secret::SecretBuffer;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use tokio::sync::{Mutex, watch};

use crate::ancestry::Proc;
use crate::batch::{Batches, Ended as BatchEnded};
use crate::bindings::{
    Bindings, Missing, NotPluggedIn, Presence, SerialClaimedTwice, Unrecognized, present_first,
};
use crate::cancel::{DeviceInterrupt, Ended};
use crate::config::Config;
use crate::destination::{Destination, Purpose};
use crate::device::{DeviceGone, DeviceIdentity};
use crate::display::{self, MAX_COMMENT_CHARS};
use crate::identities::SkIdentity;
use crate::loading::PreparedLoad;
use crate::notify::{Notification, Notifier};
use crate::pin_cache::{
    CachePolicy, CredentialKey, KeyPinPolicy, Lookup, Miss, PinCache, policy_for,
};
use crate::popup::{CancelledInPopup, Popup, PopupSession, cancelled_in_popup};
use crate::prompt::{PinPrompt, PinRequest};
use crate::routing::{OnSelect, OnWait, QUEUE_TIMEOUT, RoutedDevice, Router, SELECTION_TIMEOUT};

/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_BYTES: usize = 64;

/// The longest a batch of decryptions lasts unless `--batch-lifetime` says
/// otherwise.
pub const DEFAULT_BATCH_LIFETIME: Duration = Duration::from_mins(10);

/// Signs, asking for PINs and caching them.
#[derive(Debug)]
pub struct Signer {
    prompt: Option<PinPrompt>,
    state: Mutex<State>,
    router: Router,
    invalidation: watch::Sender<()>,
    /// Shows "touch your security key" while an assertion waits.
    notifier: Option<Arc<Notifier>>,
    /// Shows the batches that decrypt without a touch, with a button to
    /// stop them.
    batch_notifier: Option<Arc<Notifier>>,
    /// The cache policy of keys no rule in `pin_policies` matches.
    default_policy: CachePolicy,
    /// Per-key overrides (`--pin-policy`); the first match wins.
    pin_policies: Vec<KeyPinPolicy>,
    /// Labels and names the user gave keys (`--config`).
    config: Arc<Config>,
    /// skagent's own popup (`--popup`), which replaces the prompt and the
    /// notifications.
    popup: Option<Arc<Popup>>,
    /// Whether to pair with security keys on first use (`--no-pairing`).
    pairing: bool,
    /// Plug-ins pairing failed on or the user declined it for: not asked
    /// again until replugged.
    pairing_skipped: std::sync::Mutex<HashSet<DeviceIdentity>>,
}

/// Captured while the agent authorizes a request, before it queues for the
/// device. Revoked by evictions that cover it: every global one (lock,
/// forget, remove-all, sleep, monitoring changes), and the removal or expiry
/// of its own credential. Revocation cancels prompts and queued work, and a
/// revoked request never returns a signature or refills the cache.
#[derive(Debug, Clone)]
pub struct SigningTicket {
    all: watch::Receiver<()>,
    /// Closed (sender dropped) when this credential's identity is removed.
    credential: Option<watch::Receiver<()>>,
}

impl SigningTicket {
    /// Refuses a request authorized before an eviction that covers it.
    ///
    /// # Errors
    /// Returns an error once the ticket is revoked.
    pub fn check(&self) -> Result<()> {
        // A closed channel is an error, and an error means revoked.
        let revoked = self.all.has_changed().unwrap_or(true)
            || self
                .credential
                .as_ref()
                .is_some_and(|credential| credential.has_changed().unwrap_or(true));
        ensure!(
            !revoked,
            "request cancelled by PIN eviction or key removal; request it again"
        );
        Ok(())
    }

    /// Completes when the ticket is revoked. Cancel-safe.
    ///
    /// Waits on copies of the receivers: `changed()` marks the value seen,
    /// and on the ticket's own receivers that would make a later
    /// [`SigningTicket::check`] pass again after a global revocation.
    pub async fn revoked(&self) {
        let mut all = self.all.clone();
        match self.credential.clone() {
            Some(mut credential) => {
                tokio::select! {
                    _ = all.changed() => {}
                    _ = credential.changed() => {}
                }
            }
            None => {
                let _changed_or_closed = all.changed().await;
            }
        }
    }
}

#[derive(Debug)]
struct State {
    cache: PinCache,
    /// Shown with the next prompt for that credential, e.g. "wrong PIN".
    last_failure: HashMap<CredentialKey, String>,
    caching: Caching,
    /// Per-credential revocation; dropping a sender revokes its tickets.
    revocations: HashMap<CredentialKey, watch::Sender<()>>,
    /// The batches of decryptions, with the seeds they keep: here, so that
    /// whatever evicts PINs ends them under the same lock.
    batches: Batches<Proc>,
}

/// Whether PINs may be cached, which depends on watching logind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caching {
    /// Not watching yet: the agent just started. Requests run uncached.
    Pending,
    /// Lock and sleep events are watched.
    Available,
    /// Watching failed, or the machine is about to sleep.
    Unavailable,
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

/// The security key's part of a [`Job`], run in the device thread with the
/// PIN, if the credential needs one.
pub(crate) type Work<T> =
    Box<dyn FnOnce(&mut skagent_fido::Device, Option<&SecretBuffer>) -> Result<T> + Send>;

/// What one request asks of a credential on a security key.
/// [`Signer::run`] takes it from routing to the result.
pub(crate) trait Job: Sync {
    /// What the security key hands back.
    type Raw: Send + 'static;
    /// What the request yields, once [`Job::accept`] checked it.
    type Done;

    /// The credential on the security key.
    fn credential(&self) -> &CredentialKey;
    /// The key as the popup shows it.
    fn popup_key(&self) -> Key;
    /// What the request is for, as the popup shows it.
    fn popup_request(&self) -> Request;
    /// The key for prompts and logs: its name and what identifies it.
    fn described(&self) -> &str;
    /// The key's name alone, for notifications.
    fn name(&self) -> &str;
    /// What the request is for, for prompts, notifications and logs.
    fn purpose(&self) -> String;
    /// Whether the credential needs the PIN.
    fn needs_pin(&self) -> bool;
    /// How long its PIN is cached.
    fn policy(&self) -> CachePolicy;
    /// What is done with the key, for errors and logs: "signing".
    fn doing(&self) -> &'static str;
    /// The security key's part.
    fn work(&self) -> Work<Self::Raw>;
    /// Checks what the security key `device` returned. Nothing is returned
    /// to the client or cached before this passed. `with_pin`: the request
    /// carried a PIN.
    fn accept(&self, raw: Self::Raw, with_pin: bool, device: &DeviceIdentity)
    -> Result<Self::Done>;
    /// What the popup shows last, after the request succeeded.
    fn done(&self) -> Shown;
}

/// A signature with an SSH key.
struct SignJob<'a> {
    identity: &'a SkIdentity,
    data: &'a [u8],
    purpose: &'a Purpose,
    credential: CredentialKey,
    popup_key: Key,
    described: String,
    name: String,
    policy: CachePolicy,
}

impl Job for SignJob<'_> {
    type Raw = Statement;
    type Done = Signature;

    fn credential(&self) -> &CredentialKey {
        &self.credential
    }

    fn popup_key(&self) -> Key {
        self.popup_key.clone()
    }

    fn popup_request(&self) -> Request {
        popup_request(self.purpose)
    }

    fn described(&self) -> &str {
        &self.described
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn purpose(&self) -> String {
        self.purpose.to_string()
    }

    fn needs_pin(&self) -> bool {
        self.identity.requires_pin()
    }

    fn policy(&self) -> CachePolicy {
        self.policy
    }

    fn doing(&self) -> &'static str {
        "signing"
    }

    fn work(&self) -> Work<Statement> {
        let request = OwnedAssertRequest {
            rp_id: self.identity.application().to_owned(),
            client_data_hash: Sha256::digest(self.data).into(),
            key_handle: self.identity.key_handle().to_vec(),
            user_presence: true,
        };
        Box::new(move |device, pin| {
            device.assert(
                &AssertRequest {
                    rp_id: &request.rp_id,
                    client_data_hash: request.client_data_hash,
                    key_handle: &request.key_handle,
                    user_presence: request.user_presence,
                },
                pin,
            )
        })
    }

    fn accept(
        &self,
        statement: Statement,
        with_pin: bool,
        _device: &DeviceIdentity,
    ) -> Result<Signature> {
        // Neither returned nor cached unless it is the identity's own
        // signature: the device may hold another credential under that
        // handle, or the identity's public key may not be the one the
        // handle belongs to.
        let signature = verified_signature(self.identity, self.data, &statement)?;
        ensure!(
            statement.user_present(),
            "the assertion lacks user presence"
        );
        ensure!(
            !with_pin || statement.user_verified(),
            "the assertion lacks user verification"
        );
        Ok(signature)
    }

    fn done(&self) -> Shown {
        Shown::Signed {
            key: self.popup_key(),
            request: self.popup_request(),
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
    ///
    /// Caching starts disabled ([`Self::caching_pending`]): PINs are only
    /// cached once lock and sleep events are watched and
    /// [`Self::set_caching_available`] says so.
    #[must_use]
    pub fn new(prompt: Option<PinPrompt>, policy: CachePolicy) -> Self {
        Self {
            prompt,
            state: Mutex::new(State {
                cache: PinCache::new(policy),
                last_failure: HashMap::new(),
                caching: Caching::Pending,
                revocations: HashMap::new(),
                batches: Batches::new(Proc, DEFAULT_BATCH_LIFETIME),
            }),
            router: Router::default(),
            invalidation: watch::channel(()).0,
            notifier: None,
            batch_notifier: None,
            default_policy: policy,
            pin_policies: Vec::new(),
            config: Arc::default(),
            popup: None,
            pairing: true,
            pairing_skipped: std::sync::Mutex::default(),
        }
    }

    /// The same signer, pairing with security keys on first use or not.
    /// Pairings made before are checked either way.
    #[must_use]
    pub fn with_pairing(mut self, pairing: bool) -> Self {
        self.pairing = pairing;
        self
    }

    /// The same signer, showing every request in `popup`: one request at a
    /// time, the others wait for it.
    #[must_use]
    pub fn with_popup(mut self, popup: Arc<Popup>) -> Self {
        self.popup = Some(popup);
        self
    }

    /// `identity` as the popup shows it.
    pub(crate) fn popup_key(&self, identity: &SkIdentity) -> Key {
        let fingerprint = identity.fingerprint();
        let configured = self.config.key(&fingerprint);
        Key {
            emoji: configured.and_then(|key| key.emoji.clone()),
            label: display::plain(
                self.label(identity).unwrap_or(identity.comment()),
                MAX_COMMENT_CHARS,
            ),
            fingerprint,
        }
    }

    /// The routed YubiKey as the popup shows it, if it reports a serial.
    fn security_key(&self, routed: &RoutedDevice) -> Option<SecurityKey> {
        routed.serial.map(|serial| SecurityKey {
            name: self.config.yubikey_name(serial),
        })
    }

    /// The same signer, showing keys and YubiKeys with the labels and names
    /// in `config`.
    #[must_use]
    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = config;
        self
    }

    /// The configured label of `identity`, if any.
    fn label(&self, identity: &SkIdentity) -> Option<&str> {
        self.config.label(&identity.fingerprint())
    }

    /// How the routed security key is named in prompts and logs: the
    /// YubiKey's name, or its device path if it reports no serial.
    fn device_name(&self, routed: &RoutedDevice) -> String {
        routed.serial.map_or_else(
            || routed.identity.path().to_owned(),
            |serial| self.config.yubikey_name(serial),
        )
    }

    /// Tells the user which security key to plug in while a request waits
    /// for it: in the popup if there is one, else in a notification. `key`:
    /// the SSH key and its label, unless loading.
    fn on_wait(
        &self,
        session: Option<&PopupSession>,
        key: Option<(Key, String)>,
    ) -> Result<Option<OnWait>> {
        if let Some(session) = session {
            return Ok(Some(wait_in_popup(
                session,
                key.map(|(key, _)| key),
                Arc::clone(&self.config),
            )?));
        }
        Ok(self.notifier.as_ref().map(|notifier| {
            wait_notified(
                Arc::clone(notifier),
                key.map(|(_, label)| label),
                Arc::clone(&self.config),
            )
        }))
    }

    /// Passes routing's outcome on. If routing failed over a known YubiKey
    /// (not plugged in, its serial claimed twice or without the pairing),
    /// the result names it.
    fn waited_for(
        &self,
        routed: Result<RoutedDevice>,
        security_key: &mut Option<SecurityKey>,
    ) -> Result<RoutedDevice> {
        routed.inspect_err(|error| {
            let serial = error.chain().find_map(|cause| {
                cause
                    .downcast_ref::<NotPluggedIn>()
                    .and_then(|missing| missing.serial)
                    .or_else(|| {
                        cause
                            .downcast_ref::<SerialClaimedTwice>()
                            .and_then(|claimed| claimed.serial)
                    })
                    .or_else(|| {
                        cause
                            .downcast_ref::<Unrecognized>()
                            .map(|unrecognized| unrecognized.serial)
                    })
            });
            if let Some(serial) = serial {
                *security_key = Some(SecurityKey {
                    name: self.config.yubikey_name(serial),
                });
            }
        })
    }

    /// [`describe`] with the configured label.
    fn describe(&self, identity: &SkIdentity) -> String {
        describe(identity, self.label(identity))
    }

    /// The same signer, caching the PINs of some keys differently: the first
    /// rule matching a key's application or fingerprint wins.
    #[must_use]
    pub fn with_pin_policies(mut self, rules: Vec<KeyPinPolicy>) -> Self {
        self.pin_policies = rules;
        self
    }

    /// How long the PIN of `identity` is cached.
    #[must_use]
    pub fn policy_for(&self, identity: &SkIdentity) -> CachePolicy {
        policy_for(
            self.default_policy,
            &self.pin_policies,
            identity.application(),
            &identity.fingerprint(),
        )
    }

    /// The same signer, starting from `bindings` (e.g. remembered in a file).
    #[must_use]
    pub fn with_bindings(mut self, bindings: Bindings) -> Self {
        self.router = self.router.with_bindings(bindings);
        self
    }

    /// The same signer, waiting up to `timeout` for a request's security key
    /// to be plugged in. Zero fails such requests right away.
    #[must_use]
    pub fn with_plug_in_timeout(mut self, timeout: Duration) -> Self {
        self.router.plug_in_timeout = timeout;
        self
    }

    /// The same signer, showing desktop notifications while a key waits for
    /// a touch, or to be plugged in.
    #[must_use]
    pub fn with_notifier(mut self, notifier: Arc<Notifier>) -> Self {
        self.router.notifier = Some(Arc::clone(&notifier));
        self.notifier = Some(notifier);
        self
    }

    /// Authorizes a request that isn't about one credential (loading),
    /// revoked by global evictions only.
    #[must_use]
    pub fn ticket(&self) -> SigningTicket {
        SigningTicket {
            all: self.invalidation.subscribe(),
            credential: None,
        }
    }

    /// Authorizes a request for `identity`, also revoked when that identity
    /// is removed or expires.
    pub async fn ticket_for(&self, identity: &SkIdentity) -> SigningTicket {
        self.ticket_for_credential(credential_key(identity)).await
    }

    /// Authorizes a request for the credential `key`, see
    /// [`Signer::ticket_for`].
    async fn ticket_for_credential(&self, key: CredentialKey) -> SigningTicket {
        let mut state = self.state.lock().await;
        state
            .revocations
            .retain(|_, sender| sender.receiver_count() > 0);
        let credential = state
            .revocations
            .entry(key)
            .or_insert_with(|| watch::channel(()).0)
            .subscribe();
        SigningTicket {
            all: self.invalidation.subscribe(),
            credential: Some(credential),
        }
    }

    /// What every eviction of all PINs does, under the state lock: revokes
    /// every ticket, ends every batch (wiping its seeds) and drops every
    /// PIN. Returns how many PINs there were.
    fn evict(&self, state: &mut State) -> usize {
        self.invalidation.send_replace(());
        state.batches.end_all(BatchEnded::PinsEvicted);
        state.cache.clear()
    }

    /// Drops all cached PINs, ends all batches and invalidates outstanding
    /// requests.
    pub async fn forget_all(&self) -> usize {
        let mut state = self.state.lock().await;
        self.evict(&mut state)
    }

    /// Unloads all identity-specific state as well as the cached PINs.
    pub async fn remove_all(&self) -> usize {
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        bindings.clear();
        state.last_failure.clear();
        state.revocations.clear();
        self.evict(&mut state)
    }

    /// Disables caching while logind cannot be watched. Signing still works,
    /// but asks every time. Changes also invalidate in-flight requests, so
    /// none spans a lost connection or a suspend. Except the first change
    /// after [`Self::caching_pending`]: requests that came in before logind
    /// was watched for the first time missed no event.
    pub async fn set_caching_available(&self, available: bool) {
        let mut state = self.state.lock().await;
        let next = if available {
            Caching::Available
        } else {
            Caching::Unavailable
        };
        let revoke = state.caching != next && state.caching != Caching::Pending;
        state.caching = next;
        if revoke {
            self.evict(&mut state);
        }
    }

    /// Disables caching until logind is watched, for agent startup: requests
    /// meanwhile run uncached, and the first [`Self::set_caching_available`]
    /// doesn't revoke them. Leaving another state revokes and evicts like
    /// losing logind.
    pub async fn caching_pending(&self) {
        let mut state = self.state.lock().await;
        if state.caching != Caching::Pending {
            state.caching = Caching::Pending;
            self.evict(&mut state);
        }
    }

    /// Forgets everything about `identity` after its removal or expiry: its
    /// PIN, device binding and last failure, and revokes its in-flight
    /// requests. Other credentials' requests continue. Returns whether a PIN
    /// was cached.
    pub async fn forget(&self, identity: &SkIdentity) -> bool {
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        let key = credential_key(identity);
        // Dropping the sender closes the channel, which revokes.
        state.revocations.remove(&key);
        bindings.forget(&key);
        state.last_failure.remove(&key);
        state.cache.evict(&key)
    }

    /// Drops PINs whose lifetime or idle timeout ended, returning how many,
    /// and PINs of security keys that were unplugged (or replugged) since.
    /// Ends the batches whose time is up, whose tool is gone or whose
    /// security key was unplugged.
    pub async fn expire(&self, now: Instant) -> usize {
        let mut state = self.state.lock().await;
        let expired = state.cache.expire(now);
        let unplugged = state.cache.evict_absent(still_plugged_in);
        if unplugged > 0 {
            tracing::info!(
                unplugged,
                "dropped the cached PINs of unplugged security keys"
            );
        }
        // Whoever watches a batch logs its end.
        state.batches.sweep(now, still_plugged_in);
        expired
    }

    /// Number of cached PINs.
    pub async fn cached(&self) -> usize {
        self.state.lock().await.cache.len()
    }

    /// Authenticates and lists one selected device, without mutating
    /// identities. With a popup, the prepared load keeps its session, to
    /// show the result once the agent committed it.
    pub(crate) async fn prepare_load(&self, ticket: SigningTicket) -> Result<PreparedLoad> {
        let mut session = self.popup_session(&ticket, Queued { key: None }).await?;
        let mut security_key = None;
        let prepared = self
            .prepare_load_on_device(&ticket, session.as_mut(), &mut security_key)
            .await;
        match prepared {
            Ok(mut prepared) => {
                prepared.security_key = security_key;
                prepared.popup = session;
                Ok(prepared)
            }
            Err(error) => {
                if let Some(session) = session.as_mut()
                    && let Some(state) = final_state(&error, &ticket, None, security_key)
                {
                    show_best_effort(session, state);
                }
                Err(error)
            }
        }
    }

    async fn prepare_load_on_device(
        &self,
        ticket: &SigningTicket,
        mut session: Option<&mut PopupSession>,
        security_key: &mut Option<SecurityKey>,
    ) -> Result<PreparedLoad> {
        let on_select = match session.as_deref() {
            Some(session) => Some(select_in_popup(session, None)?),
            None => None,
        };
        let on_wait = self.on_wait(session.as_deref(), None)?;
        let mut routed = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("resident loading cancelled by PIN eviction"),
            () = popup_cancelled(session.as_deref_mut()) => return Err(anyhow::Error::new(CancelledInPopup)),
            routed = self.router.for_load(ticket.clone(), on_select, on_wait) => {
                self.waited_for(routed, security_key)?
            }
        };
        *security_key = self.security_key(&routed);
        let mut wrong_pin = false;
        loop {
            let (back, retries) = read_retries(routed, true).await?;
            routed = back;
            let retries = retries.context("missing PIN retry counter")?;
            if retries == 0 {
                return Err(anyhow::Error::new(TriesLeft(0))
                    .context("the selected security key's PIN is blocked"));
            }
            let mistake = wrong_pin.then_some(Mistake {
                tries_left: retries,
            });
            let device_name = self.device_name(&routed);
            let pin = self
                .load_pin(
                    ticket,
                    session.as_deref_mut(),
                    &device_name,
                    security_key.clone(),
                    mistake,
                    retries,
                )
                .await?;
            ticket.check()?;
            let (back, pin, outcome) = list_resident(routed, pin, ticket.clone()).await?;
            routed = back;
            if outcome
                .as_ref()
                .err()
                .and_then(error_kind)
                .is_some_and(ErrorKind::invalidates_pin)
            {
                self.state.lock().await.cache.evict_device(&routed.identity);
            }
            let (credentials, age, retries) = match outcome {
                Ok(listed) => listed,
                Err(error) => {
                    // In the popup the user just types it again.
                    wrong_pin =
                        session.is_some() && error_kind(&error) == Some(ErrorKind::PinInvalid);
                    if wrong_pin {
                        continue;
                    }
                    return Err(error.context(
                        "loading resident SSH credentials; the PIN is never retried automatically",
                    ));
                }
            };
            ticket.check()?;
            routed
                .identity
                .ensure_present()
                .context("during resident loading")?;
            // The PIN worked and the key holds keys of ours: pair with it,
            // once.
            let (routed, pairing) = if credentials.is_empty() && age.is_empty() {
                (routed, None)
            } else {
                self.pair(None, ticket, session.as_deref_mut(), routed, &pin)
                    .await?
            };
            ticket.check()?;
            return Ok(PreparedLoad {
                identities: credentials.iter().map(SkIdentity::from_resident).collect(),
                age,
                pin,
                pairing,
                routed,
                retries,
                accepted_at: Instant::now(),
                ticket: ticket.clone(),
                popup: None,
                security_key: None,
            });
        }
    }

    /// Asks for the PIN to load resident keys: in the popup, or with the
    /// configured prompt.
    async fn load_pin(
        &self,
        ticket: &SigningTicket,
        session: Option<&mut PopupSession>,
        device_name: &str,
        security_key: Option<SecurityKey>,
        mistake: Option<Mistake>,
        retries: u32,
    ) -> Result<SecretBuffer> {
        if let Some(session) = session {
            let state = Shown::LoadPin {
                security_key,
                mistake,
            };
            return tokio::select! {
                biased;
                () = ticket.revoked() => bail!("resident PIN prompt cancelled by PIN eviction"),
                pin = session.ask_pin(state) => pin,
            };
        }
        let prompt = self
            .prompt
            .as_ref()
            .context("resident loading needs a PIN prompt (--pinentry, --askpass or --popup)")?;
        let label = format!("resident SSH credentials on {device_name}");
        let request = PinRequest {
            key: &label,
            retries: Some(retries),
            error: None,
            then_touch: false,
            purpose: None,
        };
        tokio::select! {
            biased;
            () = ticket.revoked() => bail!("resident PIN prompt cancelled by PIN eviction"),
            pin = prompt.ask(&request) => pin,
        }
    }

    /// Commits bindings and verified PINs. Caller holds the agent state lock
    /// and inserts the identities immediately afterwards, without awaiting.
    pub(crate) async fn prime_loaded(
        &self,
        loaded: &mut PreparedLoad,
        identities: &[SkIdentity],
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        loaded.ticket.check()?;
        let device = &loaded.routed.identity;
        device
            .ensure_present()
            .context("before committing resident credentials")?;
        // Allocate every copy before modifying state. An mlock failure cannot
        // leave a partially primed cache or partially loaded identity list.
        let age_keys: Vec<CredentialKey> = loaded
            .age
            .iter()
            .map(|credential| CredentialKey::new(skagent_fido::AGE_RP_ID, credential.id()))
            .collect();
        let mut pins = Vec::new();
        if state.caching == Caching::Available {
            // An age identity always needs the PIN.
            let policy = self.age_policy();
            if policy.caches() {
                for key in &age_keys {
                    pins.push((
                        key.clone(),
                        SecretBuffer::from_slice(loaded.pin.expose())
                            .context("allocating an age identity's cached PIN")?,
                        policy,
                    ));
                }
            }
            for identity in identities.iter().filter(|identity| identity.requires_pin()) {
                let policy = self.policy_for(identity);
                if !policy.caches() {
                    continue;
                }
                pins.push((
                    credential_key(identity),
                    SecretBuffer::from_slice(loaded.pin.expose())
                        .context("allocating a resident credential's cached PIN")?,
                    policy,
                ));
            }
        }
        for key in identities.iter().map(credential_key).chain(age_keys) {
            bindings.bind(
                &key,
                device.clone(),
                loaded.routed.serial,
                loaded.pairing.clone(),
            );
        }
        loaded.pin.clear();
        for (key, pin, policy) in pins {
            state.last_failure.remove(&key);
            state.cache.store(
                key,
                pin,
                device.clone(),
                loaded.retries,
                loaded.accepted_at,
                policy,
            );
        }
        Ok(())
    }

    /// Signs `data` with `identity`.
    ///
    /// Uses the credential's bound device, or asks for selection by touch.
    /// Uses a cached PIN only on the device it was verified on. With a popup,
    /// the request waits for it first and shows every step there; a wrong
    /// PIN typed in the popup is asked for again.
    ///
    /// # Errors
    ///
    /// Returns an error if device selection or the PIN prompt fails,
    /// or the device refuses (wrong PIN, no touch, unknown credential).
    pub async fn sign(
        &self,
        identity: &SkIdentity,
        data: &[u8],
        ticket: SigningTicket,
        purpose: &Purpose,
    ) -> Result<Signature> {
        let job = SignJob {
            identity,
            data,
            purpose,
            credential: credential_key(identity),
            popup_key: self.popup_key(identity),
            described: self.describe(identity),
            name: shown_name(identity, self.label(identity)),
            policy: self.policy_for(identity),
        };
        self.run(&job, ticket).await
    }

    /// Takes `job` from routing to its result, see [`Signer::sign`].
    ///
    /// # Errors
    ///
    /// Returns an error if device selection or the PIN prompt fails, the
    /// device refuses, or the job doesn't accept what the device returned.
    pub(crate) async fn run<J: Job>(&self, job: &J, ticket: SigningTicket) -> Result<J::Done> {
        let queued = Queued {
            key: Some(job.popup_key()),
        };
        let mut session = self.popup_session(&ticket, queued).await?;
        let mut security_key = None;
        let done = self
            .run_on_device(job, &ticket, session.as_mut(), &mut security_key)
            .await;
        if let Some(session) = session.as_mut() {
            let last = match &done {
                Ok(_) => Some(job.done()),
                Err(error) => final_state(error, &ticket, Some(job.popup_key()), security_key),
            };
            if let Some(state) = last {
                show_best_effort(session, state);
            }
        }
        done
    }

    /// Waits for the popup, if there is one, and starts it.
    async fn popup_session(
        &self,
        ticket: &SigningTicket,
        queued: Queued,
    ) -> Result<Option<PopupSession>> {
        let Some(popup) = &self.popup else {
            return Ok(None);
        };
        let mut session = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("request cancelled by PIN eviction or key removal while waiting for the popup"),
            session = popup.session(QUEUE_TIMEOUT, queued) => session?,
        };
        tokio::select! {
            biased;
            () = ticket.revoked() => bail!("request cancelled by PIN eviction or key removal while starting the popup"),
            started = session.start() => started?,
        }
        Ok(Some(session))
    }

    async fn run_on_device<J: Job>(
        &self,
        job: &J,
        ticket: &SigningTicket,
        mut session: Option<&mut PopupSession>,
        security_key: &mut Option<SecurityKey>,
    ) -> Result<J::Done> {
        let key = job.credential().clone();
        let _credential = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("queued signature cancelled by PIN eviction or key removal"),
            guard = self.router.credentials.lock_within(key.clone(), QUEUE_TIMEOUT) => guard?,
        };
        ticket.check()?;
        tracing::info!(key = %job.described(), "resolving the signing device");
        let on_select = match session.as_deref() {
            Some(session) => Some(select_in_popup(session, Some(job.popup_key()))?),
            None => None,
        };
        let on_wait = self.on_wait(
            session.as_deref(),
            Some((job.popup_key(), job.name().to_owned())),
        )?;
        let mut routed = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("device selection cancelled by PIN eviction or key removal"),
            () = popup_cancelled(session.as_deref_mut()) => return Err(anyhow::Error::new(CancelledInPopup)),
            routed = self.router.route(&key, ticket.clone(), job.described(), on_select, on_wait) => {
                self.waited_for(routed, security_key)?
            }
        };
        *security_key = self.security_key(&routed);
        tracing::info!(
            key = %job.described(),
            security_key = %self.device_name(&routed),
            serial = routed.serial,
            "{} on the security key",
            job.doing()
        );
        let running = Running {
            job,
            ticket,
            device: routed.identity.clone(),
            serial: routed.serial,
            key,
            security_key: security_key.clone(),
        };
        let mut round = Round {
            again: routed.selected_by_touch,
            wrong_pin: false,
            kept: None,
        };
        loop {
            round = match self
                .attempt(&running, session.as_deref_mut(), routed, round)
                .await?
            {
                Attempt::Done(done) => return Ok(done),
                Attempt::WrongPin(back) => {
                    routed = back;
                    Round {
                        again: false,
                        wrong_pin: true,
                        kept: None,
                    }
                }
                Attempt::TimedOut(back, source) => {
                    routed = back;
                    let session = session
                        .as_deref_mut()
                        .context("a touch timed out without a popup")?;
                    let state = Shown::Timeout {
                        key: Some(job.popup_key()),
                        security_key: running.security_key.clone(),
                    };
                    tokio::select! {
                        biased;
                        () = ticket.revoked() => bail!("request cancelled by PIN eviction or key removal after a touch timeout"),
                        retried = session.ask_retry(state) => retried?,
                    }
                    // The PIN was accepted: it isn't asked for again.
                    Round {
                        again: false,
                        wrong_pin: false,
                        kept: Some(source),
                    }
                }
            };
        }
    }

    /// One try at the job on the routed device: PIN (unless cached or kept
    /// from the previous round), touch, result.
    async fn attempt<J: Job>(
        &self,
        running: &Running<'_, J>,
        mut session: Option<&mut PopupSession>,
        routed: RoutedDevice,
        round: Round,
    ) -> Result<Attempt<J::Done>> {
        let (job, ticket) = (running.job, running.ticket);
        let Round {
            again,
            wrong_pin,
            kept,
        } = round;
        let (mut routed, retries) = read_retries(routed, job.needs_pin()).await?;
        let source = match (kept, retries) {
            (Some(kept), _) => kept,
            (None, Some(retries)) => {
                let popup = session.as_deref_mut().map(|session| PopupPin {
                    session,
                    security_key: running.security_key.clone(),
                    mistake: wrong_pin.then_some(Mistake {
                        tries_left: retries,
                    }),
                });
                tokio::select! {
                    biased;
                    () = ticket.revoked() => bail!("PIN prompt cancelled by PIN eviction or key removal"),
                    source = self.pin_for(job, &running.device, retries, popup) => source?,
                }
            }
            (None, None) => PinSource::None,
        };

        // A typed PIN is checked before the touch is asked for, so a wrong
        // one never shows "touch your key" first.
        let (back, source, checked) = check_typed_pin(routed, source).await?;
        routed = back;
        ticket.check()?;
        if let Err(error) = checked {
            return self
                .attempt_failed(running, session.is_some(), routed, source, error)
                .await;
        }

        let work = job.work();
        ticket.check()?;
        let retry_guard = matches!(source, PinSource::Cache(_))
            .then_some(retries)
            .flatten();
        // Revocation, a cancel in the popup or a dropped request cancels the
        // request on the device, which ends the wait for a touch and with
        // it the PIN copy.
        let notification = self.show_touch(running, session.as_deref_mut(), again)?;
        let (interrupt, finished) = DeviceInterrupt::new(routed.device.canceller());
        let worker = {
            let device = running.device.clone();
            let doing = job.doing();
            tokio::task::spawn_blocking(move || {
                let _finished = finished;
                let outcome = work_on(&mut routed, &device, work, source.pin(), retry_guard, doing);
                (routed, source, outcome)
            })
        };
        let ((routed, source, outcome), ended) = interrupt
            .run(worker, ticket, popup_cancelled(session.as_deref_mut()))
            .await?;
        drop(notification);
        if ended == Ended::Stopped {
            return Err(anyhow::Error::new(CancelledInPopup));
        }

        // Revoked meanwhile: never return the result or refill the cache.
        ticket.check()?;
        match outcome {
            Ok((raw, retries_after)) => {
                let done = job
                    .accept(raw, source.pin().is_some(), &running.device)
                    .with_context(|| format!("{} with {}", job.doing(), job.described()))?;
                // The key just proved it holds the credential with a PIN the
                // user typed: the moment to pair with it, once.
                let pairing = match &source {
                    PinSource::User(pin) => {
                        self.pair(Some(&running.key), ticket, session, routed, pin)
                            .await?
                            .1
                    }
                    PinSource::Cache(_) | PinSource::None => None,
                };
                self.remember(running, source, retries_after, job.policy(), pairing)
                    .await?;
                Ok(Attempt::Done(done))
            }
            Err(error) => {
                self.attempt_failed(running, session.is_some(), routed, source, error)
                    .await
            }
        }
    }

    /// After an attempt failed with `error`: notes it, and in the popup
    /// (`in_popup`) asks again after a wrong typed PIN, or offers to try
    /// again after a touch timeout.
    async fn attempt_failed<J: Job>(
        &self,
        running: &Running<'_, J>,
        in_popup: bool,
        routed: RoutedDevice,
        source: PinSource,
        error: anyhow::Error,
    ) -> Result<Attempt<J::Done>> {
        let job = running.job;
        self.record_failure(job.described(), &running.key, &source, &error)
            .await;
        if in_popup {
            match error_kind(&error) {
                // The user just types it again.
                Some(ErrorKind::PinInvalid) if matches!(source, PinSource::User(_)) => {
                    return Ok(Attempt::WrongPin(routed));
                }
                Some(ErrorKind::TouchTimeout) => {
                    tracing::info!(key = %job.described(), "nobody touched the security key in time");
                    return Ok(Attempt::TimedOut(routed, source));
                }
                _ => {}
            }
        }
        Err(error.context(format!("{} with {}", job.doing(), job.described())))
    }

    /// Tells the user to touch the key: in the popup, or with a desktop
    /// notification that lasts until the returned guard is dropped.
    fn show_touch<J: Job>(
        &self,
        running: &Running<'_, J>,
        session: Option<&mut PopupSession>,
        again: bool,
    ) -> Result<Option<Notification>> {
        let job = running.job;
        if let Some(session) = session {
            session.show(Shown::Touch {
                key: job.popup_key(),
                request: job.popup_request(),
                security_key: running.security_key.clone(),
                timeout_ms: u64::try_from(TOUCH_TIMEOUT_HINT.as_millis()).unwrap_or(u64::MAX),
                again,
            })?;
            return Ok(None);
        }
        Ok(self.notifier.as_ref().map(|notifier| {
            notifier.show(
                "Touch your security key",
                &format!("{}: {}", job.name(), job.purpose()),
            )
        }))
    }

    /// `identities`, the ones on a plugged-in security key first, then those
    /// skagent can't place, then those on a security key that isn't plugged
    /// in, otherwise in their order: of two keys a server accepts, ssh then
    /// signs with the one at hand.
    pub async fn present_first(&self, identities: Vec<SkIdentity>) -> Vec<SkIdentity> {
        if identities.len() < 2 {
            return identities;
        }
        let keys: Vec<CredentialKey> = identities.iter().map(credential_key).collect();
        let presence = self.router.presence(&keys).await;
        present_first(identities, &presence)
    }

    /// Where the security key of each of `keys` is right now, see
    /// [`crate::routing::Router::presence`].
    pub(crate) async fn presence(&self, keys: &[CredentialKey]) -> Vec<Presence> {
        self.router.presence(keys).await
    }

    /// Pairs with the security key `routed`, right after a PIN the user
    /// typed worked on it (trust on first use, see `pairing.rs`): finds
    /// skagent's pairing credential there, or creates one, which takes one
    /// more touch. `key`: the SSH key that just signed, skipped if already
    /// paired; `None` when loading. Hands the device back with the pairing.
    ///
    /// Pairing never fails the request: a key it fails on, or that the user
    /// declined it for, isn't asked again until it's replugged.
    ///
    /// # Errors
    ///
    /// Returns an error only if the device thread panicked.
    async fn pair(
        &self,
        key: Option<&CredentialKey>,
        ticket: &SigningTicket,
        mut session: Option<&mut PopupSession>,
        routed: RoutedDevice,
        pin: &SecretBuffer,
    ) -> Result<(RoutedDevice, Option<PairingCredential>)> {
        let paired = match key {
            Some(key) => self.router.bindings().await.pairing_of(key).is_some(),
            None => false,
        };
        if !self.pairing || paired || self.pairing_skipped(&routed.identity) {
            return Ok((routed, None));
        }
        let pin = match SecretBuffer::from_slice(pin.expose()) {
            Ok(pin) => pin,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "not pairing: can't copy the PIN");
                return Ok((routed, None));
            }
        };
        // Looking takes only the PIN: on another machine this is all.
        let (mut routed, pin, found) = tokio::task::spawn_blocking(move || {
            let mut routed = routed;
            let found = routed.device.find_pairing(&pin);
            (routed, pin, found)
        })
        .await
        .context("the pairing thread failed")?;
        match found {
            Ok(Some(pairing)) => {
                tracing::info!(
                    security_key = %self.device_name(&routed),
                    "found skagent's pairing on the security key"
                );
                return Ok((routed, Some(pairing)));
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    security_key = %self.device_name(&routed),
                    error = %format!("{error:#}"),
                    "can't look for skagent's pairing; not pairing with this security key"
                );
                self.skip_pairing(&routed.identity);
                return Ok((routed, None));
            }
        }
        tracing::info!(
            security_key = %self.device_name(&routed),
            "touch the security key once more to pair skagent with it"
        );
        let notification = self.show_pair(session.as_deref_mut(), &routed);
        let (interrupt, finished) = DeviceInterrupt::new(routed.device.canceller());
        let worker = tokio::task::spawn_blocking(move || {
            let _finished = finished;
            let created = routed.device.create_pairing(&pin);
            (routed, created)
        });
        let ((back, created), ended) = interrupt
            .run(worker, ticket, popup_cancelled(session))
            .await?;
        routed = back;
        drop(notification);
        match (created, ended) {
            (Ok(pairing), Ended::Finished) => {
                tracing::info!(
                    security_key = %self.device_name(&routed),
                    "paired with the security key"
                );
                Ok((routed, Some(pairing)))
            }
            // The request's own checks refuse it next.
            (_, Ended::Revoked) => Ok((routed, None)),
            (_, Ended::Stopped) => {
                tracing::info!("pairing declined in the popup");
                self.skip_pairing(&routed.identity);
                Ok((routed, None))
            }
            (Err(error), Ended::Finished) => {
                tracing::warn!(
                    security_key = %self.device_name(&routed),
                    error = %format!("{error:#}"),
                    "pairing with the security key failed"
                );
                self.skip_pairing(&routed.identity);
                Ok((routed, None))
            }
        }
    }

    fn pairing_skipped(&self, device: &DeviceIdentity) -> bool {
        self.pairing_skipped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(device)
    }

    fn skip_pairing(&self, device: &DeviceIdentity) {
        let mut skipped = self
            .pairing_skipped
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Only plug-ins still connected matter; keeps the set small.
        skipped.retain(|skipped| skipped.ensure_present().is_ok());
        skipped.insert(device.clone());
    }

    /// Asks for the pairing touch: in the popup, else in a notification.
    fn show_pair(
        &self,
        session: Option<&mut PopupSession>,
        routed: &RoutedDevice,
    ) -> Option<Notification> {
        if let Some(session) = session {
            show_best_effort(
                session,
                Shown::Pair {
                    security_key: self.security_key(routed),
                    timeout_ms: u64::try_from(TOUCH_TIMEOUT_HINT.as_millis()).unwrap_or(u64::MAX),
                },
            );
            return None;
        }
        self.notifier.as_ref().map(|notifier| {
            notifier.show(
                "Touch your security key once more",
                &format!(
                    "To pair {} with skagent. Only this once.",
                    self.device_name(routed)
                ),
            )
        })
    }

    /// The PIN to use: cached if allowed, otherwise asked for, in the popup
    /// if there is one.
    async fn pin_for<J: Job>(
        &self,
        job: &J,
        device: &DeviceIdentity,
        retries: u32,
        popup: Option<PopupPin<'_>>,
    ) -> Result<PinSource> {
        let key = job.credential();
        let (lookup, last_failure) = {
            let mut state = self.state.lock().await;
            if retries == 0 {
                state.cache.evict(key);
                return Err(anyhow::Error::new(TriesLeft(0)).context(format!(
                    "the PIN of the security key at {} is blocked; only a FIDO reset (which wipes the key) helps",
                    device.path()
                )));
            }
            let lookup = state.cache.lookup(key, device, retries, Instant::now())?;
            (lookup, state.last_failure.get(key).cloned())
        };
        let miss = match lookup {
            Lookup::Hit(pin) => {
                tracing::debug!(key = %job.described(), "using the cached PIN");
                return Ok(PinSource::Cache(pin));
            }
            Lookup::Miss(miss) => miss,
        };
        if miss != Miss::NotCached {
            tracing::info!(key = %job.described(), reason = %miss, "asking for the PIN again");
        }

        if let Some(PopupPin {
            session,
            security_key,
            mistake,
        }) = popup
        {
            let pin = session
                .ask_pin(Shown::Pin {
                    key: job.popup_key(),
                    request: job.popup_request(),
                    security_key,
                    mistake,
                })
                .await?;
            return Ok(PinSource::User(pin));
        }
        let prompt = self.prompt.as_ref().ok_or_else(|| {
            anyhow!(
                "{} needs a PIN, but no PIN prompt is configured (--pinentry, --askpass or --popup)",
                job.described()
            )
        })?;
        let purpose = job.purpose();
        let pin = prompt
            .ask(&PinRequest {
                key: job.described(),
                retries: Some(retries),
                error: last_failure.as_deref(),
                then_touch: true,
                purpose: Some(&purpose),
            })
            .await?;
        Ok(PinSource::User(pin))
    }

    /// After a successful signature: cache a typed PIN, or note the use of a
    /// cached one. Only if the device node is still the one the PIN went to.
    async fn remember<J: Job>(
        &self,
        running: &Running<'_, J>,
        source: PinSource,
        retries_after: Option<u32>,
        policy: CachePolicy,
        pairing: Option<PairingCredential>,
    ) -> Result<()> {
        let (key, device) = (&running.key, &running.device);
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        running.ticket.check()?;
        state.last_failure.remove(key);
        let still_same_device = still_plugged_in(device);
        if still_same_device {
            bindings.bind(key, device.clone(), running.serial, pairing);
        }
        if state.caching != Caching::Available {
            return Ok(());
        }
        match source {
            PinSource::None => {}
            PinSource::Cache(_) if still_same_device => state.cache.mark_used(key, Instant::now()),
            PinSource::User(pin) if still_same_device => {
                if let Some(retries) = retries_after {
                    state.cache.store(
                        key.clone(),
                        pin,
                        device.clone(),
                        retries,
                        Instant::now(),
                        policy,
                    );
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
        described: &str,
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
            tracing::warn!(key = %described, "the device rejected the cached PIN, dropped it");
        }
        state.last_failure.insert(key.clone(), note.to_owned());
    }
}

/// Whether `device` is still the plug-in it was.
fn still_plugged_in(device: &DeviceIdentity) -> bool {
    DeviceIdentity::of(device.path()).is_ok_and(|current| current == *device)
}

/// About how long a YubiKey waits for a touch, for the popup's countdown.
/// To be measured on hardware (`docs/pinentry.md`).
const TOUCH_TIMEOUT_HINT: Duration = Duration::from_secs(15);

/// PIN tries the security key has left, attached to PIN errors.
#[derive(Debug, Clone, Copy)]
struct TriesLeft(u32);

impl fmt::Display for TriesLeft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} PIN tries left", self.0)
    }
}

impl std::error::Error for TriesLeft {}

/// One request, as it goes through its attempts.
struct Running<'a, J: Job> {
    job: &'a J,
    ticket: &'a SigningTicket,
    key: CredentialKey,
    /// The routed device's plug-in.
    device: DeviceIdentity,
    /// Its YubiKey serial, if it reports one.
    serial: Option<u32>,
    security_key: Option<SecurityKey>,
}

/// How an attempt ended, short of an error.
enum Attempt<T> {
    Done(T),
    /// The user typed a wrong PIN in the popup: ask again on this device.
    WrongPin(RoutedDevice),
    /// Nobody touched the key in time: the popup offers to try again with
    /// the same PIN.
    TimedOut(RoutedDevice, PinSource),
}

/// What an attempt starts with.
struct Round {
    /// The device was just selected by touch: this is the second touch.
    again: bool,
    /// The previous attempt's PIN was wrong.
    wrong_pin: bool,
    /// The PIN from the previous attempt, which timed out after accepting it.
    kept: Option<PinSource>,
}

/// Reads the routed device's PIN retry counter if `needs_pin`, in the
/// device thread.
async fn read_retries(
    mut routed: RoutedDevice,
    needs_pin: bool,
) -> Result<(RoutedDevice, Option<u32>)> {
    tokio::task::spawn_blocking(move || {
        let retries = if needs_pin {
            Some(routed.device.pin_retries()?)
        } else {
            None
        };
        Ok::<_, anyhow::Error>((routed, retries))
    })
    .await
    .context("reading the routed security key's PIN retry counter")?
}

/// Checks a PIN the user just typed on the routed device, where that works
/// without a touch. Only PIN errors fail the check: otherwise the assertion
/// checks the PIN anyway. The device and the PIN source come back either way.
async fn check_typed_pin(
    mut routed: RoutedDevice,
    source: PinSource,
) -> Result<(RoutedDevice, PinSource, Result<()>)> {
    tokio::task::spawn_blocking(move || {
        let checked = match &source {
            PinSource::User(pin) => check_pin_on(&mut routed, pin),
            PinSource::None | PinSource::Cache(_) => Ok(()),
        };
        (routed, source, checked)
    })
    .await
    .context("checking the PIN in the device thread")
}

fn check_pin_on(routed: &mut RoutedDevice, pin: &SecretBuffer) -> Result<()> {
    let path = routed.identity.path();
    routed
        .identity
        .ensure_present()
        .context("before checking the PIN")?;
    match with_tries_left(&mut routed.device, |device| device.check_pin(pin)) {
        Ok(_) => Ok(()),
        Err(error) if error_kind(&error).is_some_and(ErrorKind::invalidates_pin) => {
            if error_kind(&error) == Some(ErrorKind::PinInvalid) {
                tracing::warn!(device = path, "wrong PIN");
            }
            Err(error)
        }
        Err(error) => {
            tracing::debug!(
                device = path,
                error = %format!("{error:#}"),
                "can't check the PIN before the touch, the assertion will"
            );
            Ok(())
        }
    }
}

/// What listing resident credentials yields: the SSH credentials, the age
/// credentials and the retry counter right after.
type Listing = Result<(Vec<ResidentCredential>, Vec<AgeCredential>, u32)>;

/// Lists the resident SSH credentials and the age credentials of the routed
/// device with `pin`, in the device thread. The device and the PIN come back
/// either way.
async fn list_resident(
    mut routed: RoutedDevice,
    pin: SecretBuffer,
    ticket: SigningTicket,
) -> Result<(RoutedDevice, SecretBuffer, Listing)> {
    tokio::task::spawn_blocking(move || {
        let outcome = (|| {
            ticket.check()?;
            routed
                .identity
                .ensure_present()
                .context("during the loading prompt")?;
            let credentials =
                with_tries_left(&mut routed.device, |device| device.resident_ssh_keys(&pin))?;
            let age = with_tries_left(&mut routed.device, |device| device.age_credentials(&pin))?;
            let retries = routed.device.pin_retries()?;
            Ok((credentials, age, retries))
        })();
        (routed, pin, outcome)
    })
    .await
    .context("enumerating resident credentials in the device thread")
}

/// Asks for the PIN in the popup.
struct PopupPin<'a> {
    session: &'a mut PopupSession,
    security_key: Option<SecurityKey>,
    mistake: Option<Mistake>,
}

/// Completes when the user cancels in the popup; never without one.
async fn popup_cancelled(session: Option<&mut PopupSession>) {
    match session {
        Some(session) => session.cancelled().await,
        None => std::future::pending().await,
    }
}

/// Shows the selection in the popup once the router starts one.
fn select_in_popup(session: &PopupSession, key: Option<Key>) -> Result<OnSelect> {
    let shower = session.shower()?;
    let timeout_ms = u64::try_from(SELECTION_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    Ok(Box::new(move |devices| {
        if let Err(error) = shower.show(Shown::Select {
            key,
            devices,
            timeout_ms,
        }) {
            tracing::debug!(error = %format!("{error:#}"), "showing the selection in the popup failed");
        }
    }))
}

/// Shows which security key to plug in, in the popup. `key`: the SSH key,
/// unless loading.
fn wait_in_popup(session: &PopupSession, key: Option<Key>, config: Arc<Config>) -> Result<OnWait> {
    let shower = session.shower()?;
    Ok(Box::new(move |missing| {
        let name = |serial: u32| SecurityKey {
            name: config.yubikey_name(serial),
        };
        let state = match (missing, key.clone()) {
            (Missing::Elsewhere { serial, other }, Some(key)) => Shown::WrongKey {
                key,
                security_key: serial.map(name),
                other: other.map(name),
            },
            (missing, key) => Shown::NoKey {
                key,
                security_key: missing.serial().map(name),
            },
        };
        if let Err(error) = shower.show(state) {
            tracing::debug!(error = %format!("{error:#}"), "showing the wait in the popup failed");
        }
    }))
}

/// Shows which security key to plug in, in a desktop notification that
/// closes once the request stops waiting. `label`: the SSH key's, unless
/// loading.
fn wait_notified(notifier: Arc<Notifier>, label: Option<String>, config: Arc<Config>) -> OnWait {
    let mut shown: Option<Notification> = None;
    Box::new(move |missing| {
        let summary = missing.serial().map_or_else(
            || "Plug in your security key".to_owned(),
            |serial| format!("Plug in {}", config.yubikey_name(serial)),
        );
        let body = match (missing, &label) {
            (Missing::Elsewhere { other, .. }, Some(label)) => format!(
                "{} doesn't hold {label}.",
                other.map_or_else(
                    || "The security key plugged in".to_owned(),
                    |other| config.yubikey_name(other)
                )
            ),
            (Missing::Nothing { serial: Some(_) }, Some(label)) => format!("It holds {label}."),
            (_, Some(label)) => format!("The one holding {label}."),
            (_, None) => "To load its SSH keys into skagent.".to_owned(),
        };
        // Replacing the guard closes the previous notification.
        drop(shown.replace(notifier.show(&summary, &body)));
    })
}

/// Shows a final state; the request's outcome doesn't depend on it.
fn show_best_effort(session: &mut PopupSession, state: Shown) {
    if let Err(error) = session.show(state) {
        tracing::debug!(error = %format!("{error:#}"), "showing the result in the popup failed");
    }
}

/// What the popup shows after a request failed with `error`: nothing if it
/// was revoked or cancelled in the popup (it closes or moves on).
fn final_state(
    error: &anyhow::Error,
    ticket: &SigningTicket,
    key: Option<Key>,
    security_key: Option<SecurityKey>,
) -> Option<Shown> {
    if ticket.check().is_err() || cancelled_in_popup(error) {
        return None;
    }
    let tries_left = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<TriesLeft>())
        .map(|tries| tries.0);
    Some(match (error_kind(error), tries_left) {
        (Some(ErrorKind::PinBlocked), _) | (_, Some(0)) => Shown::Locked { key, security_key },
        (Some(ErrorKind::PinAuthBlocked), tries_left) => Shown::Replug {
            key,
            security_key,
            tries_left,
        },
        (Some(ErrorKind::PinPolicyViolation), _) => Shown::NewPin { key, security_key },
        (Some(ErrorKind::TouchTimeout), _) => Shown::Timeout { key, security_key },
        (kind, _) => Shown::Failed {
            key,
            security_key,
            reason: failure(error, kind),
        },
    })
}

/// Why a request failed, as far as the popup can tell the user.
fn failure(error: &anyhow::Error, kind: Option<ErrorKind>) -> Failure {
    let gone = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<DeviceGone>());
    if gone.is_some() {
        return Failure::Unplugged;
    }
    let missing = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NotPluggedIn>());
    if missing.is_some() {
        return Failure::NotPluggedIn;
    }
    let claimed = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SerialClaimedTwice>());
    if claimed.is_some() {
        return Failure::Duplicate;
    }
    let unrecognized = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Unrecognized>());
    if unrecognized.is_some() {
        return Failure::Unrecognized;
    }
    match kind {
        Some(ErrorKind::Transport) => Failure::Unplugged,
        Some(ErrorKind::OperationDenied) => Failure::Refused,
        Some(ErrorKind::NoCredentials) => Failure::NotOnKey,
        Some(ErrorKind::PinNotSet) => Failure::NoPin,
        _ => Failure::Other,
    }
}

/// What a signature is for, as the popup shows it.
fn popup_request(purpose: &Purpose) -> Request {
    let host = |destination: &Destination| match destination {
        Destination::Named(name) => Host::Named { name: name.clone() },
        Destination::HostKey(fingerprint) => Host::HostKey {
            fingerprint: fingerprint.clone(),
        },
        Destination::Unverified => Host::Unverified,
    };
    match purpose {
        Purpose::Login {
            user,
            destination,
            forwarded_to,
        } => Request::Login {
            user: user.clone(),
            host: host(destination),
            via: forwarded_to.as_ref().map(host),
        },
        Purpose::SignData { namespace } => Request::Sign {
            namespace: namespace.clone(),
        },
        Purpose::Unknown => Request::Unknown,
    }
}

/// Runs `operation` on `device`; if it fails because of the PIN, the error
/// says how many tries are left (reading the counter is free).
fn with_tries_left<T>(
    device: &mut skagent_fido::Device,
    operation: impl FnOnce(&mut skagent_fido::Device) -> Result<T>,
) -> Result<T> {
    operation(device).map_err(|error| {
        if error_kind(&error).is_some_and(ErrorKind::invalidates_pin)
            && let Ok(retries) = device.pin_retries()
        {
            return error.context(TriesLeft(retries));
        }
        error
    })
}

fn credential_key(identity: &SkIdentity) -> CredentialKey {
    CredentialKey::new(identity.application(), identity.key_handle())
}

/// The key as the user knows it, for prompts, notifications and logs: its
/// configured `label`, else its comment, and the fingerprint. A forwarded
/// agent may have added the key, so the text is made safe to show
/// ([`display::shown`]).
#[must_use]
pub fn describe(identity: &SkIdentity, label: Option<&str>) -> String {
    format!(
        "{} ({})",
        shown_name(identity, label),
        identity.fingerprint()
    )
}

/// The configured `label` of `identity`, else its comment, safe to show.
fn shown_name(identity: &SkIdentity, label: Option<&str>) -> String {
    display::shown(label.unwrap_or(identity.comment()), MAX_COMMENT_CHARS)
}

struct OwnedAssertRequest {
    rp_id: String,
    client_data_hash: [u8; 32],
    key_handle: Vec<u8>,
    user_presence: bool,
}

/// Runs `work` on the device at `path`. With a PIN, also returns the retry
/// counter right after, for the cache. `doing`: what the work is, for errors.
fn work_on<T>(
    routed: &mut RoutedDevice,
    expected: &DeviceIdentity,
    work: Work<T>,
    pin: Option<&SecretBuffer>,
    retry_guard: Option<u32>,
    doing: &'static str,
) -> Result<(T, Option<u32>)> {
    let path = expected.path();
    let device = &mut routed.device;
    expected
        .ensure_present()
        .with_context(|| format!("before {doing}"))?;
    if let Some(expected_retries) = retry_guard {
        ensure!(
            device.pin_retries()? == expected_retries,
            "PIN retry counter changed before {doing} at {path}"
        );
    }
    match work(device, pin) {
        Ok(raw) => {
            let retries = pin.and_then(|_| match device.pin_retries() {
                Ok(retries) => Some(retries),
                Err(error) => {
                    tracing::warn!(device = path, error = %format!("{error:#}"), "reading the retry counter after {doing} failed");
                    None
                }
            });
            Ok((raw, retries))
        }
        Err(error) => {
            if error_kind(&error).is_some_and(ErrorKind::invalidates_pin) {
                // Reading the counter is free; it tells the user how close
                // they are to a lockout.
                match device.pin_retries() {
                    Ok(retries) => {
                        if error_kind(&error) == Some(ErrorKind::PinInvalid) {
                            tracing::warn!(device = path, retries, "wrong PIN");
                        }
                        return Err(error.context(TriesLeft(retries)));
                    }
                    Err(retries_error) => tracing::warn!(
                        device = path,
                        error = %format!("{retries_error:#}"),
                        "the PIN was refused, and the retry counter can't be read"
                    ),
                }
            }
            Err(error)
        }
    }
}

/// [`ssh_signature`] of `statement`, checked like a server would check it:
/// against `identity`'s public key and application, over `data`.
///
/// # Errors
///
/// Returns an error if the signature is malformed or doesn't verify.
pub fn verified_signature(
    identity: &SkIdentity,
    data: &[u8],
    statement: &Statement,
) -> Result<Signature> {
    let signature = ssh_signature(statement)?;
    identity
        .key_data()
        .verify(data, &signature)
        .map_err(|_invalid| {
            anyhow!(
                "the security key's signature doesn't verify with the public key of {}; \
                 the key handle belongs to another key",
                identity.fingerprint()
            )
        })?;
    Ok(signature)
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
