//! What age identities ask of their security keys: the secret a decryption
//! derives its key from, and a new credential.
//!
//! Deriving is a [`Job`]: everything a signature goes through on its way to
//! the security key applies to it unchanged. Creating has no credential to
//! route by yet, so it picks the security key like a load does.

use std::time::Instant;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age::batch_salt;
use skagent_fido::{AGE_RP_ID, AGE_USER_ID_BYTES, AgeCredential, DERIVED_SECRET_BYTES};
use skagent_popup::{Host, Key, Mistake, Queued, Request, Requester, State as Shown};
use skagent_secret::SecretBuffer;

use super::{
    Caching, Job, LastWord, Signer, SigningTicket, TOUCH_TIMEOUT_HINT, Work, final_state,
    popup_cancelled, read_retries, select_in_popup, show_best_effort, with_tries_left,
};
use crate::age::AgeIdentity;
use crate::batch::Member;
use crate::cancel::{DeviceInterrupt, Ended};
use crate::device::DeviceIdentity;
use crate::display::{self, MAX_COMMAND_CHARS, MAX_NAME_CHARS};
use crate::pin_cache::{CachePolicy, CredentialKey, policy_for};
use crate::popup::{CancelledInPopup, PopupSession};
use crate::prompt::PinRequest;
use crate::routing::RoutedDevice;

/// How an age identity is called where it has no name of its own.
const IDENTITY_NAME: &str = "age identity";

/// Who asks for a decryption, in a sentence: "decrypt a file for agenix",
/// "decrypt a file for the host with key … (through your forwarded
/// agent)".
#[must_use]
pub fn purpose(by: &Requester) -> String {
    let host = |host: &Host| match host {
        Host::Named { name } => name.clone(),
        Host::HostKey { fingerprint } => format!("the host with key {fingerprint}"),
        Host::Unverified => "an unverified host".to_owned(),
    };
    match by {
        Requester::Program { name: Some(name) } => format!("decrypt a file for {name}"),
        Requester::Program { name: None } => "decrypt a file".to_owned(),
        Requester::Forwarded { host: from, via } => match via {
            Some(via) => format!(
                "decrypt a file for {} (through your agent forwarded to {})",
                host(from),
                host(via)
            ),
            None => format!(
                "decrypt a file for {} (through your forwarded agent)",
                host(from)
            ),
        },
    }
}

/// What the first decryption of a batch asks the user for: the files the
/// batch's command asks for from then on, for a limited time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Offer {
    /// The command, as the popup shows it.
    command: String,
    /// How long the batch still lasts at most.
    seconds: u64,
}

impl Offer {
    /// What a decryption for `member`'s batch offers.
    pub fn of(member: &Member) -> Self {
        Self {
            command: member.command.clone(),
            // Never less than what is granted.
            seconds: member
                .remaining
                .as_secs()
                .saturating_add(u64::from(member.remaining.subsec_nanos() > 0)),
        }
    }

    /// In a sentence: "decrypt the files … asks for …".
    fn purpose(&self) -> String {
        format!(
            "decrypt the files \"{}\" asks for, without another touch, for up to {} (a batch)",
            display::shown(&self.command, MAX_COMMAND_CHARS),
            display::about(self.seconds)
        )
    }
}

/// What a security key answered for an age identity.
pub(crate) struct Derived {
    /// The answer for the batch salt: what the identity's seed is derived
    /// from.
    pub answer: SecretBuffer,
    /// The plug-in of the security key that gave it.
    pub device: DeviceIdentity,
}

/// `identity` as the popup shows it: its recipient cut short where an SSH
/// key has its fingerprint.
fn popup_key(identity: &AgeIdentity) -> Key {
    Key {
        emoji: None,
        label: IDENTITY_NAME.to_owned(),
        fingerprint: identity
            .recipient()
            .map(skagent_age::Recipient::abbreviated)
            .unwrap_or_default(),
    }
}

/// `identity` for prompts and logs.
fn describe(identity: &AgeIdentity) -> String {
    match identity.recipient() {
        Some(recipient) => format!("{IDENTITY_NAME} ({})", recipient.abbreviated()),
        None => format!("{IDENTITY_NAME} (not used on this machine yet)"),
    }
}

/// The secret of an age identity: what its security key answers for the
/// salt of the identity that may be used in batches.
struct DeriveJob {
    key: CredentialKey,
    credential: AgeCredential,
    popup_key: Key,
    by: Requester,
    /// Set if the request starts a batch: then that is what the user is
    /// asked for, not one file.
    batch: Option<Offer>,
    /// The request follows one whose identity turned out to be another:
    /// the user is asked to touch once more.
    again: bool,
    described: String,
    policy: CachePolicy,
}

impl Job for DeriveJob {
    type Raw = SecretBuffer;
    type Done = Derived;

    fn credential(&self) -> &CredentialKey {
        &self.key
    }

    fn popup_key(&self) -> Key {
        self.popup_key.clone()
    }

    fn popup_request(&self) -> Request {
        match &self.batch {
            Some(offer) => Request::Batch {
                command: offer.command.clone(),
                seconds: offer.seconds,
            },
            None => Request::Decrypt {
                by: self.by.clone(),
            },
        }
    }

    fn described(&self) -> &str {
        &self.described
    }

    fn name(&self) -> &str {
        IDENTITY_NAME
    }

    fn purpose(&self) -> String {
        match &self.batch {
            Some(offer) => offer.purpose(),
            None => purpose(&self.by),
        }
    }

    fn needs_pin(&self) -> bool {
        // Always: the credential is unusable without it (credProtect 3).
        true
    }

    fn policy(&self) -> CachePolicy {
        self.policy
    }

    fn doing(&self) -> &'static str {
        "decrypting"
    }

    fn work(&self) -> Work<SecretBuffer> {
        let credential = self.credential.clone();
        let salt = batch_salt();
        Box::new(move |device, pin| {
            let pin = pin.context("an age identity is never used without the PIN")?;
            device.derive(&credential, &salt, pin)
        })
    }

    fn accept(
        &self,
        answer: SecretBuffer,
        with_pin: bool,
        device: &DeviceIdentity,
    ) -> Result<Derived> {
        // The fido layer refused an answer without a touch or without the
        // PIN verified; this is the same rule from this side.
        ensure!(with_pin, "an age identity was used without the PIN");
        ensure!(
            answer.len() == DERIVED_SECRET_BYTES,
            "the security key's answer has {} bytes, not {DERIVED_SECRET_BYTES}",
            answer.len()
        );
        Ok(Derived {
            answer,
            device: device.clone(),
        })
    }

    fn done(&self) -> Shown {
        Shown::Signed {
            key: self.popup_key(),
            request: self.popup_request(),
        }
    }

    fn again(&self) -> bool {
        self.again
    }
}

/// What the two touches of creating an identity have in common.
struct Touches<'a> {
    ticket: &'a SigningTicket,
    key: &'a Key,
    security_key: Option<skagent_popup::SecurityKey>,
}

impl Touches<'_> {
    /// Asks for a touch in the popup (without one, the prompt said that the
    /// key blinks twice) and runs `work` on the device while it waits for
    /// it. Revocation, a cancel in the popup or a dropped request end the
    /// wait. The device and the PIN come back with the result.
    async fn run<T: Send + 'static>(
        &self,
        mut session: Option<&mut PopupSession>,
        again: bool,
        mut routed: RoutedDevice,
        pin: SecretBuffer,
        work: impl FnOnce(&mut skagent_fido::Device, &SecretBuffer) -> Result<T> + Send + 'static,
    ) -> Result<(RoutedDevice, SecretBuffer, T)> {
        if let Some(session) = session.as_deref_mut() {
            show_best_effort(
                session,
                Shown::Touch {
                    key: self.key.clone(),
                    request: Request::Create,
                    security_key: self.security_key.clone(),
                    timeout_ms: u64::try_from(TOUCH_TIMEOUT_HINT.as_millis()).unwrap_or(u64::MAX),
                    again,
                },
            );
        }
        let (interrupt, finished) = DeviceInterrupt::new(routed.device.canceller());
        let worker = tokio::task::spawn_blocking(move || {
            let _finished = finished;
            let outcome = routed
                .identity
                .ensure_present()
                .context("before using the security key")
                .and_then(|()| work(&mut routed.device, &pin));
            (routed, pin, outcome)
        });
        let ((routed, pin, outcome), ended) = interrupt
            .run(worker, self.ticket, popup_cancelled(session))
            .await?;
        if ended == Ended::Stopped {
            return Err(anyhow::Error::new(CancelledInPopup));
        }
        self.ticket.check()?;
        Ok((routed, pin, outcome?))
    }
}

/// A new age identity on a security key, not yet known to the agent: its
/// credential, the security key's answer for it, and what the agent
/// remembers about the security key once it commits.
pub(crate) struct CreatedIdentity {
    pub credential: AgeCredential,
    /// The security key's answer for the batch salt.
    pub answer: SecretBuffer,
    pin: SecretBuffer,
    routed: RoutedDevice,
    retries: u32,
    accepted_at: Instant,
    ticket: SigningTicket,
    popup: Option<PopupSession>,
    popup_key: Key,
}

impl CreatedIdentity {
    /// Shows in the popup that the identity exists.
    pub fn show_created(&mut self) {
        if let Some(session) = self.popup.as_mut() {
            show_best_effort(
                session,
                Shown::Signed {
                    key: self.popup_key.clone(),
                    request: Request::Create,
                },
            );
        }
    }
}

impl Signer {
    /// Authorizes a request for the age identity `identity`, see
    /// [`Signer::ticket_for`].
    pub async fn ticket_for_age(&self, identity: &AgeIdentity) -> SigningTicket {
        self.ticket_for_credential(identity.key()).await
    }

    /// How long the PIN of an age identity is cached: `--pin-policy
    /// application=skagent:age,…` applies, else the default.
    pub(super) fn age_policy(&self) -> CachePolicy {
        policy_for(self.default_policy, &self.pin_policies, AGE_RP_ID, "")
    }

    /// What the security key holding `identity` answers for the salt of the
    /// identity that may be used in batches: 32 bytes that never change, and
    /// from which the identity's private key is derived. Goes the way of a
    /// signature: the security key that holds the credential, the PIN from
    /// the cache or the user, a touch. With `batch`, the request starts
    /// one, and the user is asked for that.
    ///
    /// The popup comes back with the answer: whether a file was decrypted
    /// shows only once the caller unwrapped, and the last word is theirs.
    /// `follows`: the last word of a derivation right before this one,
    /// whose identity wasn't the one asked for. This one goes on in its
    /// popup, and asks to touch once more.
    ///
    /// # Errors
    ///
    /// Returns an error where [`Signer::sign`] does.
    pub(crate) async fn derive(
        &self,
        identity: &AgeIdentity,
        by: Requester,
        batch: Option<Offer>,
        ticket: SigningTicket,
        follows: Option<LastWord>,
    ) -> Result<(Derived, LastWord)> {
        let job = DeriveJob {
            key: identity.key(),
            credential: identity.credential().clone(),
            popup_key: popup_key(identity),
            by,
            batch,
            again: follows.is_some(),
            described: describe(identity),
            policy: self.age_policy(),
        };
        self.run_open(&job, ticket, follows).await
    }

    /// Creates an age identity on a security key: picks the key like a load
    /// does (the one plugged in, or the one touched), asks for its PIN,
    /// creates the credential (a touch) and derives its secret (another
    /// touch). A security key that holds an identity already is refused
    /// unless `another` says to add one. Nothing about the new identity is
    /// remembered before [`Signer::commit_created`].
    ///
    /// # Errors
    ///
    /// Returns an error if selection, the PIN prompt or the security key
    /// fails, or the request is revoked or cancelled.
    pub(crate) async fn create_age_identity(
        &self,
        user_id: [u8; AGE_USER_ID_BYTES],
        another: bool,
        ticket: SigningTicket,
    ) -> Result<CreatedIdentity> {
        let key = Key {
            emoji: None,
            label: format!("New {IDENTITY_NAME}"),
            fingerprint: String::new(),
        };
        let queued = Queued {
            key: Some(key.clone()),
        };
        let mut session = self.popup_session(&ticket, queued).await?;
        let mut security_key = None;
        let created = self
            .create_on_device(
                (user_id, another),
                &ticket,
                &key,
                session.as_mut(),
                &mut security_key,
            )
            .await;
        match created {
            Ok(mut created) => {
                created.popup = session;
                Ok(created)
            }
            Err(error) => {
                if let Some(session) = session.as_mut()
                    && let Some(state) = final_state(
                        &error,
                        &ticket,
                        Some(key),
                        security_key,
                        Some(Request::Create),
                    )
                {
                    show_best_effort(session, state);
                }
                Err(error)
            }
        }
    }

    async fn create_on_device(
        &self,
        (user_id, another): ([u8; AGE_USER_ID_BYTES], bool),
        ticket: &SigningTicket,
        key: &Key,
        mut session: Option<&mut PopupSession>,
        security_key: &mut Option<skagent_popup::SecurityKey>,
    ) -> Result<CreatedIdentity> {
        let on_select = match session.as_deref() {
            Some(session) => Some(select_in_popup(session, Some(key.clone()))?),
            None => None,
        };
        let on_wait = self.on_wait(session.as_deref(), None)?;
        let routed = tokio::select! {
            biased;
            () = ticket.revoked() => bail!("creating an age identity cancelled by PIN eviction"),
            () = popup_cancelled(session.as_deref_mut()) => return Err(anyhow::Error::new(CancelledInPopup)),
            routed = self.router.for_load(ticket.clone(), on_select, on_wait) => {
                self.waited_for(routed, security_key)?
            }
        };
        *security_key = self.security_key(&routed);
        let (routed, retries) = read_retries(routed, true).await?;
        let retries = retries.context("missing PIN retry counter")?;
        ensure!(retries > 0, "the selected security key's PIN is blocked");

        let device_name = self.device_name(&routed);
        let pin = self
            .create_pin(
                ticket,
                session.as_deref_mut(),
                key,
                security_key.clone(),
                &device_name,
                retries,
            )
            .await?;
        ticket.check()?;

        let shown = Touches {
            ticket,
            key,
            security_key: security_key.clone(),
        };
        // The first touch creates the credential.
        let (routed, pin, credential) = shown
            .run(
                session.as_deref_mut(),
                false,
                routed,
                pin,
                move |device, pin| {
                    // Listing takes the PIN and no touch, so a wrong PIN or an
                    // identity that exists already never asks for one.
                    let existing = with_tries_left(device, |device| device.age_credentials(pin))?;
                    ensure!(
                        another || existing.is_empty(),
                        "this security key holds an age identity already; `skagent load` finds it, \
                     and `skagent age new --another` adds one more"
                    );
                    device.create_age_credential(&user_id, pin)
                },
            )
            .await
            .context("creating an age identity")?;
        tracing::info!(
            security_key = %device_name,
            "created an age credential; touch the security key once more to read its recipient"
        );

        // The second touch derives its secret, from which the recipient
        // follows.
        let derived = credential.clone();
        let (routed, pin, (answer, retries)) = shown
            .run(session, true, routed, pin, move |device, pin| {
                let answer = device.derive(&derived, &batch_salt(), pin)?;
                let retries = device.pin_retries()?;
                Ok((answer, retries))
            })
            .await
            .context(
                "deriving the new identity's secret; the credential exists and `skagent load` \
                 finds it",
            )?;
        routed
            .identity
            .ensure_present()
            .context("after creating an age identity")?;
        Ok(CreatedIdentity {
            credential,
            answer,
            pin,
            routed,
            retries,
            accepted_at: Instant::now(),
            ticket: ticket.clone(),
            popup: None,
            popup_key: key.clone(),
        })
    }

    /// Asks for the PIN to create an identity: in the popup, or with the
    /// configured prompt.
    async fn create_pin(
        &self,
        ticket: &SigningTicket,
        session: Option<&mut PopupSession>,
        key: &Key,
        security_key: Option<skagent_popup::SecurityKey>,
        device_name: &str,
        retries: u32,
    ) -> Result<SecretBuffer> {
        if let Some(session) = session {
            let state = Shown::Pin {
                key: key.clone(),
                request: Request::Create,
                security_key,
                mistake: None::<Mistake>,
            };
            return tokio::select! {
                biased;
                () = ticket.revoked() => bail!("PIN prompt cancelled by PIN eviction"),
                pin = session.ask_pin(state) => pin,
            };
        }
        let prompt = self.prompt.as_ref().context(
            "creating an age identity needs a PIN prompt (--pinentry, --askpass or --popup)",
        )?;
        let label = format!("a new age identity on {device_name}");
        let request = PinRequest {
            key: &label,
            retries: Some(retries),
            error: None,
            then_touch: true,
            purpose: Some("create it (the key blinks twice)"),
        };
        tokio::select! {
            biased;
            () = ticket.revoked() => bail!("PIN prompt cancelled by PIN eviction"),
            pin = prompt.ask(&request) => pin,
        }
    }

    /// Remembers what creating `created` showed: which security key holds
    /// the credential, and the PIN it accepted. The caller holds the agent's
    /// state lock and notes the identity right after, without awaiting.
    ///
    /// # Errors
    ///
    /// Returns an error if the request was revoked meanwhile, the security
    /// key is gone, or locked memory for the PIN can't be had.
    pub(crate) async fn commit_created(&self, created: &mut CreatedIdentity) -> Result<()> {
        let key = CredentialKey::new(AGE_RP_ID, created.credential.id());
        let mut state = self.state.lock().await;
        let mut bindings = self.router.bindings().await;
        // No awaits from here on: a cancelled caller can't stop halfway.
        created.ticket.check()?;
        let device = &created.routed.identity;
        device
            .ensure_present()
            .context("before remembering the new age identity")?;
        let policy = self.age_policy();
        let cached = if state.caching == Caching::Available && policy.caches() {
            Some(
                SecretBuffer::from_slice(created.pin.expose())
                    .context("allocating the new identity's cached PIN")?,
            )
        } else {
            None
        };
        bindings.bind(&key, device.clone(), created.routed.serial, None);
        created.pin.clear();
        if let Some(pin) = cached {
            state.cache.store(
                key,
                pin,
                device.clone(),
                created.retries,
                created.accepted_at,
                policy,
            );
        }
        Ok(())
    }

    /// `name`, a program's name from the process list, safe to show.
    #[must_use]
    pub fn shown_program(name: &str) -> String {
        display::plain(name, MAX_NAME_CHARS)
    }
}
