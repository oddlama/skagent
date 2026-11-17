//! Signing with an sk key on its security key, with the PIN cache.
//!
//! One operation per device and per credential. Bound devices can sign in
//! parallel; touch selection is exclusive across devices.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha2::{Digest as _, Sha256};
use signature::Verifier as _;
use skagent_fido::{AssertRequest, ErrorKind, ResidentCredential, Statement, error_kind};
use skagent_popup::{Failure, Host, Key, Mistake, Request, SecurityKey, State as Shown};
use skagent_secret::SecretBuffer;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};
use tokio::sync::{Mutex, watch};

use crate::cancel::{DeviceInterrupt, Ended};
use crate::config::Config;
use crate::destination::{Destination, Purpose};
use crate::device::DeviceIdentity;
use crate::display::{self, MAX_COMMENT_CHARS};
use crate::identities::SkIdentity;
use crate::loading::PreparedLoad;
use crate::notify::{Notification, Notifier};
use crate::pin_cache::{
    CachePolicy, CredentialKey, KeyPinPolicy, Lookup, Miss, PinCache, policy_for,
};
use crate::popup::{CancelledInPopup, Popup, PopupSession, cancelled_in_popup};
use crate::prompt::{PinPrompt, PinRequest};
use crate::routing::{OnSelect, QUEUE_TIMEOUT, RoutedDevice, Router};

/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Signs, asking for PINs and caching them.
#[derive(Debug)]
pub struct Signer {
    prompt: Option<PinPrompt>,
    state: Mutex<State>,
    router: Router,
    invalidation: watch::Sender<()>,
    /// Shows "touch your security key" while an assertion waits.
    notifier: Option<Arc<Notifier>>,
    /// The cache policy of keys no rule in `pin_policies` matches.
    default_policy: CachePolicy,
    /// Per-key overrides (`--pin-policy`); the first match wins.
    pin_policies: Vec<KeyPinPolicy>,
    /// Labels and names the user gave keys (`--config`).
    config: Arc<Config>,
    /// skagent's own popup (`--popup`), which replaces the prompt and the
    /// notifications.
    popup: Option<Arc<Popup>>,
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
            }),
            router: Router::default(),
            invalidation: watch::channel(()).0,
            notifier: None,
            default_policy: policy,
            pin_policies: Vec::new(),
            config: Arc::default(),
            popup: None,
        }
    }

    /// The same signer, showing every request in `popup`: one request at a
    /// time, the others wait for it.
    #[must_use]
    pub fn with_popup(mut self, popup: Arc<Popup>) -> Self {
        self.popup = Some(popup);
        self
    }

    /// `identity` as the popup shows it.
    fn popup_key(&self, identity: &SkIdentity) -> Key {
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

    /// The same signer, showing desktop notifications while a key waits for
    /// a touch.
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
        let mut state = self.state.lock().await;
        state
            .revocations
            .retain(|_, sender| sender.receiver_count() > 0);
        let credential = state
            .revocations
            .entry(credential_key(identity))
            .or_insert_with(|| watch::channel(()).0)
            .subscribe();
        SigningTicket {
            all: self.invalidation.subscribe(),
            credential: Some(credential),
        }
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
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        self.invalidation.send_replace(());
        bindings.clear();
        state.last_failure.clear();
        state.revocations.clear();
        state.cache.clear()
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
            self.invalidation.send_replace(());
            state.cache.clear();
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
            self.invalidation.send_replace(());
            state.cache.clear();
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
    pub async fn expire(&self, now: Instant) -> usize {
        let mut state = self.state.lock().await;
        let expired = state.cache.expire(now);
        let unplugged = state.cache.evict_absent(|device| {
            DeviceIdentity::of(device.path()).is_ok_and(|current| current == *device)
        });
        if unplugged > 0 {
            tracing::info!(
                unplugged,
                "dropped the cached PINs of unplugged security keys"
            );
        }
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
        let mut session = self.popup_session(&ticket).await?;
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
        let mut routed = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("resident loading cancelled by PIN eviction"),
            () = popup_cancelled(session.as_deref_mut()) => return Err(anyhow::Error::new(CancelledInPopup)),
            routed = self.router.for_load(ticket.clone(), on_select) => routed?,
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
            let (credentials, retries) = match outcome {
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
            ensure!(
                DeviceIdentity::of(routed.identity.path())? == routed.identity,
                "security key changed during resident loading"
            );
            return Ok(PreparedLoad {
                identities: credentials.iter().map(SkIdentity::from_resident).collect(),
                pin,
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
        ensure!(
            DeviceIdentity::of(device.path())? == *device,
            "security key changed before committing resident credentials"
        );
        // Allocate every copy before modifying state. An mlock failure cannot
        // leave a partially primed cache or partially loaded identity list.
        let mut pins = Vec::new();
        if state.caching == Caching::Available {
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
        for identity in identities {
            bindings.bind(credential_key(identity), device.clone());
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
        let mut session = self.popup_session(&ticket).await?;
        let mut security_key = None;
        let signed = self
            .sign_on_device(
                identity,
                data,
                &ticket,
                purpose,
                session.as_mut(),
                &mut security_key,
            )
            .await;
        if let Some(session) = session.as_mut() {
            let key = self.popup_key(identity);
            let last = match &signed {
                Ok(_) => Some(Shown::Signed {
                    key,
                    request: popup_request(purpose),
                }),
                Err(error) => final_state(error, &ticket, Some(key), security_key),
            };
            if let Some(state) = last {
                show_best_effort(session, state);
            }
        }
        signed
    }

    /// Waits for the popup, if there is one, and starts it.
    async fn popup_session(&self, ticket: &SigningTicket) -> Result<Option<PopupSession>> {
        let Some(popup) = &self.popup else {
            return Ok(None);
        };
        let mut session = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("request cancelled by PIN eviction or key removal while waiting for the popup"),
            session = popup.session(QUEUE_TIMEOUT) => session?,
        };
        tokio::select! {
            biased;
            () = ticket.revoked() => bail!("request cancelled by PIN eviction or key removal while starting the popup"),
            started = session.start() => started?,
        }
        Ok(Some(session))
    }

    async fn sign_on_device(
        &self,
        identity: &SkIdentity,
        data: &[u8],
        ticket: &SigningTicket,
        purpose: &Purpose,
        mut session: Option<&mut PopupSession>,
        security_key: &mut Option<SecurityKey>,
    ) -> Result<Signature> {
        let key = credential_key(identity);
        let _credential = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("queued signature cancelled by PIN eviction or key removal"),
            guard = self.router.credentials.lock_within(key.clone(), QUEUE_TIMEOUT) => guard?,
        };
        ticket.check()?;
        tracing::info!(key = %self.describe(identity), "resolving the signing device");
        let label = self.describe(identity);
        let on_select = match session.as_deref() {
            Some(session) => Some(select_in_popup(session, Some(self.popup_key(identity)))?),
            None => None,
        };
        let mut routed = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("device selection cancelled by PIN eviction or key removal"),
            () = popup_cancelled(session.as_deref_mut()) => return Err(anyhow::Error::new(CancelledInPopup)),
            routed = self.router.route(&key, ticket.clone(), &label, on_select) => routed?,
        };
        *security_key = self.security_key(&routed);
        tracing::info!(
            key = %self.describe(identity),
            security_key = %self.device_name(&routed),
            serial = routed.serial,
            "signing on the security key"
        );
        let signing = Signing {
            identity,
            data,
            ticket,
            purpose,
            device: routed.identity.clone(),
            key,
            security_key: security_key.clone(),
        };
        let mut again = routed.selected_by_touch;
        let mut wrong_pin = false;
        loop {
            match self
                .sign_attempt(&signing, session.as_deref_mut(), routed, again, wrong_pin)
                .await?
            {
                Attempt::Signed(signature) => return Ok(signature),
                Attempt::WrongPin(back) => {
                    routed = back;
                    again = false;
                    wrong_pin = true;
                }
            }
        }
    }

    /// One try at signing on the routed device: PIN (unless cached), touch,
    /// result. `wrong_pin`: the previous try's PIN was wrong.
    async fn sign_attempt(
        &self,
        signing: &Signing<'_>,
        mut session: Option<&mut PopupSession>,
        routed: RoutedDevice,
        again: bool,
        wrong_pin: bool,
    ) -> Result<Attempt> {
        let (identity, ticket) = (signing.identity, signing.ticket);
        let (mut routed, retries) = read_retries(routed, identity.requires_pin()).await?;
        let source = match retries {
            Some(retries) => {
                let popup = session.as_deref_mut().map(|session| PopupPin {
                    session,
                    security_key: signing.security_key.clone(),
                    mistake: wrong_pin.then_some(Mistake {
                        tries_left: retries,
                    }),
                });
                tokio::select! {
                    biased;
                    () = ticket.revoked() => bail!("PIN prompt cancelled by PIN eviction or key removal"),
                    source = self.pin_for(identity, &signing.key, &signing.device, retries, signing.purpose, popup) => source?,
                }
            }
            None => PinSource::None,
        };

        // A typed PIN is checked before the touch is asked for, so a wrong
        // one never shows "touch your key" first.
        let (back, source, checked) = check_typed_pin(routed, source).await?;
        routed = back;
        ticket.check()?;
        if let Err(error) = checked {
            return self
                .attempt_failed(signing, session.is_some(), routed, &source, error)
                .await;
        }

        let request = OwnedAssertRequest {
            rp_id: identity.application().to_owned(),
            client_data_hash: Sha256::digest(signing.data).into(),
            key_handle: identity.key_handle().to_vec(),
            user_presence: true,
        };
        ticket.check()?;
        let retry_guard = matches!(source, PinSource::Cache(_))
            .then_some(retries)
            .flatten();
        // Revocation, a cancel in the popup or a dropped request cancels the
        // assertion on the device, which ends the wait for a touch and with
        // it the PIN copy.
        let notification = self.show_touch(signing, session.as_deref_mut(), again)?;
        let (interrupt, finished) = DeviceInterrupt::new(routed.device.canceller());
        let worker = {
            let device = signing.device.clone();
            tokio::task::spawn_blocking(move || {
                let _finished = finished;
                let outcome = assert_on(&mut routed, &device, &request, source.pin(), retry_guard);
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

        // Revoked meanwhile: never return the signature or refill the cache.
        ticket.check()?;
        match outcome {
            Ok((statement, retries_after)) => {
                // Neither returned nor cached unless it is the identity's own
                // signature: the device may hold another credential under that
                // handle, or the identity's public key may not be the one the
                // handle belongs to.
                let signature = verified_signature(identity, signing.data, &statement)
                    .with_context(|| format!("signing with {}", self.describe(identity)))?;
                ensure!(
                    statement.user_present(),
                    "the assertion lacks user presence"
                );
                ensure!(
                    source.pin().is_none() || statement.user_verified(),
                    "the assertion lacks user verification"
                );
                let policy = self.policy_for(identity);
                self.remember(
                    &signing.key,
                    source,
                    &signing.device,
                    retries_after,
                    ticket,
                    policy,
                )
                .await?;
                Ok(Attempt::Signed(signature))
            }
            Err(error) => {
                self.attempt_failed(signing, session.is_some(), routed, &source, error)
                    .await
            }
        }
    }

    /// After an attempt failed with `error`: notes it, and in the popup
    /// (`in_popup`) asks again after a wrong typed PIN.
    async fn attempt_failed(
        &self,
        signing: &Signing<'_>,
        in_popup: bool,
        routed: RoutedDevice,
        source: &PinSource,
        error: anyhow::Error,
    ) -> Result<Attempt> {
        let identity = signing.identity;
        self.record_failure(identity, &signing.key, source, &error)
            .await;
        // In the popup the user just types it again.
        if in_popup
            && matches!(source, PinSource::User(_))
            && error_kind(&error) == Some(ErrorKind::PinInvalid)
        {
            return Ok(Attempt::WrongPin(routed));
        }
        Err(error.context(format!("signing with {}", self.describe(identity))))
    }

    /// Tells the user to touch the key: in the popup, or with a desktop
    /// notification that lasts until the returned guard is dropped.
    fn show_touch(
        &self,
        signing: &Signing<'_>,
        session: Option<&mut PopupSession>,
        again: bool,
    ) -> Result<Option<Notification>> {
        let identity = signing.identity;
        if let Some(session) = session {
            session.show(Shown::Touch {
                key: self.popup_key(identity),
                request: popup_request(signing.purpose),
                security_key: signing.security_key.clone(),
                timeout_ms: u64::try_from(TOUCH_TIMEOUT_HINT.as_millis()).unwrap_or(u64::MAX),
                again,
            })?;
            return Ok(None);
        }
        Ok(self.notifier.as_ref().map(|notifier| {
            notifier.show(
                "Touch your security key",
                &format!(
                    "{}: {}",
                    shown_name(identity, self.label(identity)),
                    signing.purpose
                ),
            )
        }))
    }

    /// The PIN to use: cached if allowed, otherwise asked for, in the popup
    /// if there is one.
    async fn pin_for(
        &self,
        identity: &SkIdentity,
        key: &CredentialKey,
        device: &DeviceIdentity,
        retries: u32,
        purpose: &Purpose,
        popup: Option<PopupPin<'_>>,
    ) -> Result<PinSource> {
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
                tracing::debug!(key = %self.describe(identity), "using the cached PIN");
                return Ok(PinSource::Cache(pin));
            }
            Lookup::Miss(miss) => miss,
        };
        if miss != Miss::NotCached {
            tracing::info!(key = %self.describe(identity), reason = %miss, "asking for the PIN again");
        }

        if let Some(PopupPin {
            session,
            security_key,
            mistake,
        }) = popup
        {
            let pin = session
                .ask_pin(Shown::Pin {
                    key: self.popup_key(identity),
                    request: popup_request(purpose),
                    security_key,
                    mistake,
                })
                .await?;
            return Ok(PinSource::User(pin));
        }
        let prompt = self.prompt.as_ref().ok_or_else(|| {
            anyhow!(
                "{} needs a PIN, but no PIN prompt is configured (--pinentry, --askpass or --popup)",
                self.describe(identity)
            )
        })?;
        let purpose = purpose.to_string();
        let pin = prompt
            .ask(&PinRequest {
                key: &self.describe(identity),
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
    async fn remember(
        &self,
        key: &CredentialKey,
        source: PinSource,
        device: &DeviceIdentity,
        retries_after: Option<u32>,
        ticket: &SigningTicket,
        policy: CachePolicy,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        ticket.check()?;
        state.last_failure.remove(key);
        let still_same_device = DeviceIdentity::of(device.path()).is_ok_and(|now| now == *device);
        if still_same_device {
            bindings.bind(key.clone(), device.clone());
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
            tracing::warn!(key = %self.describe(identity), "the device rejected the cached PIN, dropped it");
        }
        state.last_failure.insert(key.clone(), note.to_owned());
    }
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

/// One signature request, as it goes through its attempts.
struct Signing<'a> {
    identity: &'a SkIdentity,
    data: &'a [u8],
    ticket: &'a SigningTicket,
    purpose: &'a Purpose,
    key: CredentialKey,
    /// The routed device's plug-in.
    device: DeviceIdentity,
    security_key: Option<SecurityKey>,
}

/// How an attempt ended, short of an error.
enum Attempt {
    Signed(Signature),
    /// The user typed a wrong PIN in the popup: ask again on this device.
    WrongPin(RoutedDevice),
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
    ensure!(
        DeviceIdentity::of(path)? == routed.identity,
        "security key changed before checking the PIN at {path}"
    );
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

/// What listing resident credentials yields: the credentials and the retry
/// counter right after.
type Listing = Result<(Vec<ResidentCredential>, u32)>;

/// Lists the resident SSH credentials of the routed device with `pin`, in
/// the device thread. The device and the PIN come back either way.
async fn list_resident(
    mut routed: RoutedDevice,
    pin: SecretBuffer,
    ticket: SigningTicket,
) -> Result<(RoutedDevice, SecretBuffer, Listing)> {
    tokio::task::spawn_blocking(move || {
        let outcome = (|| {
            ticket.check()?;
            ensure!(
                DeviceIdentity::of(routed.identity.path())? == routed.identity,
                "security key changed during the loading prompt"
            );
            let credentials =
                with_tries_left(&mut routed.device, |device| device.resident_ssh_keys(&pin))?;
            let retries = routed.device.pin_retries()?;
            Ok((credentials, retries))
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
    Ok(Box::new(move |devices| {
        if let Err(error) = shower.show(Shown::Select { key, devices }) {
            tracing::debug!(error = %format!("{error:#}"), "showing the selection in the popup failed");
        }
    }))
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
        (Some(ErrorKind::Transport), _) => Shown::Failed {
            key,
            reason: Failure::Unplugged,
        },
        (Some(ErrorKind::OperationDenied), _) => Shown::Failed {
            key,
            reason: Failure::Refused,
        },
        _ => Shown::Failed {
            key,
            reason: Failure::Other,
        },
    })
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
