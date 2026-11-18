//! ssh-agent protocol handling.
//!
//! Behavior follows OpenSSH's ssh-agent where it applies:
//! - Only `sk-ssh-ed25519@openssh.com` keys are accepted (see [`crate::identities`]).
//! - A locked agent lists no identities and refuses everything except
//!   `UNLOCK`. Empty lock passphrases are refused.
//! - Each wrong unlock attempt waits 0.1 s longer than the previous one, up
//!   to 10 s. Attempts are serialized across connections, so opening more
//!   connections doesn't speed up guessing.
//!
//! Signing goes to the security key; see [`crate::signer`].
//!
//! Refused requests answer `FAILURE`. The reason is logged at `warn`, never
//! sent to the client: the protocol has no way to carry it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use skagent_secret::SecretBuffer;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::QueryResponse;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Extension, Identity, PublicCredential, RemoveIdentity,
    SignRequest, Unparsed,
};
use ssh_agent_lib::ssh_key::Signature;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroize as _;

use crate::cancel::Hangup;
use crate::destination::{self, Bound, SESSION_BIND_EXTENSION, SessionBindings};
use crate::frames::BoundedStream;
use crate::identities::{
    AcceptedConstraints, IdentityStore, Origin, SkIdentity, evaluate_constraints,
};
use crate::signer::Signer;
use crate::socket::PeerCheckedListener;

/// Agent protocol extension that drops all cached PINs and keeps the keys.
/// `skagent forget` sends it; screen lockers can run that.
pub const FORGET_PINS_EXTENSION: &str = "forget-pins@skagent";

/// No-argument request to load one selected device's resident SSH keys.
/// The reply carries the number loaded as a big-endian u32, never a PIN.
pub const LOAD_KEYS_EXTENSION: &str = "load-resident-keys@skagent";

/// Asks the agent which extensions it supports.
const QUERY_EXTENSION: &str = "query";

/// What `query` answers.
const SUPPORTED_EXTENSIONS: [&str; 4] = [
    QUERY_EXTENSION,
    SESSION_BIND_EXTENSION,
    FORGET_PINS_EXTENSION,
    LOAD_KEYS_EXTENSION,
];

/// Extra wait per consecutive failed unlock attempt.
pub const UNLOCK_DELAY_STEP: Duration = Duration::from_millis(100);

/// Failed attempts after which the wait stops growing (100 × 0.1 s = 10 s).
pub const UNLOCK_DELAY_MAX_STEPS: u32 = 100;

/// Agent state shared by all connections.
#[derive(Debug, Clone, Default)]
pub struct SkAgent {
    shared: Arc<Shared>,
}

impl SkAgent {
    /// An agent that signs with `signer`.
    #[must_use]
    pub fn new(signer: Signer) -> Self {
        Self::with_identities(signer, IdentityStore::default())
    }

    /// An agent that signs with `signer` and starts with `identities`, e.g.
    /// the ones remembered from before a restart.
    #[must_use]
    pub fn with_identities(signer: Signer, identities: IdentityStore) -> Self {
        Self {
            shared: Arc::new(Shared {
                signer,
                state: Mutex::new(State {
                    identities,
                    ..State::default()
                }),
                ..Shared::default()
            }),
        }
    }

    /// The signer behind the agent, e.g. to authorize a request in tests.
    #[must_use]
    pub fn signer(&self) -> &Signer {
        &self.shared.signer
    }

    /// Drops all cached PINs, e.g. when the screen locks. Returns how many there were.
    pub async fn forget_pins(&self, reason: &str) -> usize {
        let forgotten = self.shared.signer.forget_all().await;
        tracing::info!(forgotten, reason, "dropped cached PINs");
        forgotten
    }

    /// Allows caching only while lock/sleep monitoring is available.
    pub async fn set_caching_available(&self, available: bool) {
        self.shared.signer.set_caching_available(available).await;
    }

    /// Disables caching until monitoring starts, without revoking the
    /// requests that arrive meanwhile when it does (see
    /// [`Signer::caching_pending`]). Socket activation hands the agent its
    /// first request right at startup.
    pub async fn caching_pending(&self) {
        self.shared.signer.caching_pending().await;
    }

    /// Removes identities whose `ssh-add -t` lifetime ended (with their PINs
    /// and device bindings), and drops cached PINs whose own lifetime or idle
    /// timeout ended.
    pub async fn expire(&self) {
        let (state, _now) = self.shared.state_now().await;
        drop(state);
        let expired = self.shared.signer.expire(Instant::now()).await;
        if expired > 0 {
            tracing::info!(
                expired,
                "cached PINs reached their lifetime or idle timeout"
            );
        }
    }
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    /// Held for the whole unlock attempt, including the penalty wait.
    unlock_attempts: Mutex<()>,
    signer: Signer,
}

impl Shared {
    /// Locks the agent state and removes identities whose lifetime ended at
    /// the returned `now`, dropping their PINs and bindings like `ssh-add -d`.
    /// Callers use the same `now` for every lookup under this lock.
    async fn state_now(&self) -> (MutexGuard<'_, State>, Instant) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        for identity in state.identities.take_expired(now) {
            let pin_dropped = self.signer.forget(&identity).await;
            tracing::info!(
                fingerprint = %identity.fingerprint(),
                comment = %identity.comment(),
                pin_dropped,
                "key lifetime ended, removed from the agent"
            );
        }
        (state, now)
    }
}

#[derive(Debug, Default)]
struct State {
    identities: IdentityStore,
    /// The lock passphrase while the agent is locked.
    lock: Option<SecretBuffer>,
    failed_unlocks: u32,
}

impl Agent<PeerCheckedListener> for SkAgent {
    fn new_session(&mut self, socket: &BoundedStream<UnixStream>) -> impl Session {
        let hangup = Hangup::watch(socket.get_ref())
            .map_err(|error| {
                tracing::warn!(
                    %error,
                    "can't watch the connection, requests of a client that disconnects run to the end"
                );
            })
            .ok();
        AgentSession {
            shared: Arc::clone(&self.shared),
            hangup,
            bindings: SessionBindings::default(),
        }
    }
}

/// One client connection.
#[derive(Debug)]
pub struct AgentSession {
    shared: Arc<Shared>,
    /// Lets long requests (signing, loading) stop when the client is gone.
    hangup: Option<Hangup>,
    /// The SSH sessions ssh bound this connection to (`session-bind`).
    bindings: SessionBindings,
}

/// Logs why a request is refused and turns it into a protocol `FAILURE`.
fn refuse(request: &str, reason: &anyhow::Error) -> AgentError {
    tracing::warn!(reason = %format!("{reason:#}"), "refused {request}");
    AgentError::Failure
}

impl AgentSession {
    async fn add(&self, identity: AddIdentity, constraints: AcceptedConstraints) -> Result<()> {
        let AcceptedConstraints {
            lifetime,
            destinations,
        } = constraints;
        let (mut state, now) = self.shared.state_now().await;
        let expires_at = lifetime
            .map(|lifetime| {
                now.checked_add(lifetime)
                    .ok_or_else(|| anyhow!("key lifetime of {} s is too large", lifetime.as_secs()))
            })
            .transpose()?;
        let identity = SkIdentity::from_credential(identity.credential, expires_at)?
            .with_destinations(destinations);

        if state.lock.is_some() {
            bail!("the agent is locked");
        }
        // Like OpenSSH: a key this connection can't see can't be replaced
        // through it either, e.g. to drop its destination constraints.
        if let Some(existing) = state.identities.find(&identity.key_data(), now) {
            self.visible(existing)?;
        }
        if let Some(other) = state.identities.sharing_credential(&identity) {
            bail!(
                "the key's credential (application and key handle) belongs to the loaded key {}",
                other.fingerprint()
            );
        }
        let (fingerprint, comment) = (identity.fingerprint(), identity.comment().to_owned());
        let destination_constraints = identity.destinations().len();
        let unknown_host_keys: usize = identity
            .destinations()
            .iter()
            .map(destination::DestinationConstraint::skipped_host_keys)
            .sum();
        // A forwarded agent's keys aren't this machine's to keep.
        let origin = if self.bindings.is_remote() {
            Origin::Forwarded
        } else {
            Origin::Local
        };
        let replaced = state.identities.add(identity, origin);
        tracing::info!(
            %fingerprint,
            %comment,
            lifetime_seconds = lifetime.map(|lifetime| lifetime.as_secs()),
            destination_constraints,
            replaced,
            "added key"
        );
        if unknown_host_keys > 0 {
            tracing::info!(
                %fingerprint,
                unknown_host_keys,
                "left host keys of types skagent doesn't know out of the key's destination constraints; \
                 sessions to hosts with only such keys can't use it"
            );
        }
        Ok(())
    }

    /// Whether `identity` exists for this connection: its destination
    /// constraints allow the hops the connection is bound to.
    fn visible(&self, identity: &SkIdentity) -> Result<()> {
        destination::permitted(identity.destinations(), &self.bindings, None)
            .map(|_| ())
            .context("the key is not in the agent (as seen from this connection)")
    }

    async fn remove(&self, credential: &PublicCredential) -> Result<()> {
        let PublicCredential::Key(key) = credential else {
            bail!("certificates are never held by this agent");
        };
        let (mut state, now) = self.shared.state_now().await;
        if state.lock.is_some() {
            bail!("the agent is locked");
        }
        let existing = state
            .identities
            .find(key, now)
            .ok_or_else(|| anyhow!("the key is not in the agent"))?;
        self.visible(existing)?;
        let removed = state
            .identities
            .remove(key, now)
            .ok_or_else(|| anyhow!("the key is not in the agent"))?;
        let pin_dropped = self.shared.signer.forget(&removed).await;
        drop(state);
        tracing::info!(
            fingerprint = %removed.fingerprint(),
            comment = %removed.comment(),
            pin_dropped,
            "removed key"
        );
        Ok(())
    }

    async fn sign_with(&self, request: &SignRequest) -> Result<Signature> {
        let PublicCredential::Key(key) = &request.credential else {
            bail!("certificates are never held by this agent");
        };
        // Copied out, so the state isn't locked while the device waits for a touch.
        let (identity, ticket) = {
            let (mut state, now) = self.shared.state_now().await;
            if state.lock.is_some() {
                bail!("the agent is locked");
            }
            let identity = state
                .identities
                .find(key, now)
                .ok_or_else(|| anyhow!("the key is not in the agent"))?
                .clone();
            let ticket = self.shared.signer.ticket_for(&identity).await;
            (identity, ticket)
        };
        // Destination constraints and the websafe rule, before the device.
        let purpose = destination::authorize_signature(
            &identity.key_data(),
            identity.application(),
            identity.destinations(),
            &self.bindings,
            &request.data,
        )?;
        // Only the device work is cut short when the client leaves; finding
        // the identity above (which reaps expired ones) always completes.
        let signature = Hangup::unless_closed(
            self.hangup.as_ref(),
            self.shared
                .signer
                .sign(&identity, &request.data, ticket, &purpose),
        )
        .await?;
        tracing::info!(
            fingerprint = %identity.fingerprint(),
            comment = %identity.comment(),
            %purpose,
            "signed"
        );
        Ok(signature)
    }

    async fn load_resident(&self, details: &[u8]) -> Result<Extension> {
        ensure!(
            details.is_empty(),
            "resident loading takes no extension arguments"
        );
        // Through a forwarded agent, another machine could make a PIN prompt
        // pop up here; only `skagent load` on this machine may.
        ensure!(
            !self.bindings.is_remote(),
            "resident keys are only loaded on request from this machine, not through a forwarded agent"
        );
        let ticket = {
            let (state, _now) = self.shared.state_now().await;
            ensure!(state.lock.is_none(), "the agent is locked");
            self.shared.signer.ticket()
        };
        // Selection, prompt and enumeration end when the client leaves. The
        // commit below always runs to the end once it started.
        let mut loaded = Hangup::unless_closed(
            self.hangup.as_ref(),
            self.shared.signer.prepare_load(ticket),
        )
        .await?;
        let (mut state, now) = self.shared.state_now().await;
        ensure!(
            state.lock.is_none(),
            "the agent was locked during resident loading"
        );
        loaded.ticket.check()?;
        let imports = state.identities.resident_imports(&loaded.identities, now)?;
        let count = u32::try_from(imports.len())
            .context("too many resident identities for the loading reply")?;
        self.shared
            .signer
            .prime_loaded(&mut loaded, &imports)
            .await?;
        let shown = imports
            .iter()
            .map(|identity| self.shared.signer.popup_key(identity))
            .collect();
        // No awaits from cache commit through identity insertion.
        for identity in imports {
            tracing::info!(fingerprint = %identity.fingerprint(), comment = %identity.comment(), "loaded resident SSH key");
            // Loading is refused through a forwarded agent.
            state.identities.add(identity, Origin::Local);
        }
        loaded.show_loaded(shown);
        Ok(Extension {
            name: LOAD_KEYS_EXTENSION.to_owned(),
            details: Unparsed::from(count.to_be_bytes().to_vec()),
        })
    }

    async fn lock_with(&self, mut passphrase: String) -> Result<()> {
        let stored = Self::store_passphrase(passphrase.as_bytes());
        passphrase.zeroize();
        let stored = stored?;

        let (mut state, _now) = self.shared.state_now().await;
        if state.lock.is_some() {
            bail!("the agent is already locked");
        }
        state.lock = Some(stored);
        let forgotten = self.shared.signer.forget_all().await;
        drop(state);
        tracing::info!(forgotten_pins = forgotten, "agent locked");
        Ok(())
    }

    async fn unlock_with(&self, mut passphrase: String) -> Result<()> {
        // Serializes all attempts, including their penalty wait.
        let _attempt = self.shared.unlock_attempts.lock().await;

        let penalty = {
            let (mut state, _now) = self.shared.state_now().await;
            let Some(stored) = &state.lock else {
                passphrase.zeroize();
                bail!("the agent is not locked");
            };
            let matches = !passphrase.is_empty() && stored.constant_time_eq(passphrase.as_bytes());
            passphrase.zeroize();
            if matches {
                state.lock = None;
                state.failed_unlocks = 0;
                tracing::info!("agent unlocked");
                return Ok(());
            }
            state.failed_unlocks = state
                .failed_unlocks
                .saturating_add(1)
                .min(UNLOCK_DELAY_MAX_STEPS);
            UNLOCK_DELAY_STEP.saturating_mul(state.failed_unlocks)
        };
        tokio::time::sleep(penalty).await;
        bail!(
            "wrong passphrase (waited {:.1} s before answering)",
            penalty.as_secs_f64()
        )
    }

    fn store_passphrase(passphrase: &[u8]) -> Result<SecretBuffer> {
        if passphrase.is_empty() {
            bail!("an empty lock passphrase is not allowed");
        }
        SecretBuffer::from_slice(passphrase).context("storing the lock passphrase in locked memory")
    }
}

#[async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let (mut state, now) = self.shared.state_now().await;
        if state.lock.is_some() {
            return Ok(Vec::new());
        }
        Ok(state
            .identities
            .identities(now)
            .iter()
            .filter(|identity| self.visible(identity).is_ok())
            .map(SkIdentity::identity)
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.sign_with(&request)
            .await
            .map_err(|reason| refuse("signature request", &reason))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        self.add(identity, AcceptedConstraints::default())
            .await
            .map_err(|reason| refuse("adding a key", &reason))
    }

    async fn add_identity_constrained(
        &mut self,
        request: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        let added = match evaluate_constraints(&request.constraints) {
            Ok(accepted) => self.add(request.identity, accepted).await,
            Err(reason) => Err(reason),
        };
        added.map_err(|reason| refuse("adding a key", &reason))
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        self.remove(&identity.credential)
            .await
            .map_err(|reason| refuse("removing a key", &reason))
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        let (mut state, _now) = self.shared.state_now().await;
        if state.lock.is_some() {
            return Err(refuse("removing all keys", &anyhow!("the agent is locked")));
        }
        let removed = state.identities.clear();
        let forgotten = self.shared.signer.remove_all().await;
        drop(state);
        tracing::info!(removed, forgotten_pins = forgotten, "removed all keys");
        Ok(())
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        // Processed while locked too, like OpenSSH: binding a new forwarded
        // connection must work before the agent is unlocked.
        if extension.name == SESSION_BIND_EXTENSION {
            return match self.bindings.bind(extension.details.as_ref()) {
                Ok(Bound::New { forwarding }) => {
                    tracing::debug!(
                        hops = self.bindings.len(),
                        forwarding,
                        "bound the connection to an SSH session"
                    );
                    Ok(None)
                }
                Ok(Bound::AlreadyBound) => Ok(None),
                Err(reason) => {
                    // Destination-constrained keys stay off this connection.
                    tracing::warn!(
                        reason = %format!("{reason:#}"),
                        "refused to bind a connection to its SSH session"
                    );
                    Err(AgentError::ExtensionFailure)
                }
            };
        }
        if extension.name == QUERY_EXTENSION {
            return Extension::new_message(QueryResponse {
                extensions: SUPPORTED_EXTENSIONS
                    .iter()
                    .map(|&name| name.to_owned())
                    .collect(),
            })
            .map(Some)
            .map_err(|error| refuse("answering a query", &anyhow!("{error}")));
        }
        if extension.name == FORGET_PINS_EXTENSION {
            // Through a forwarded agent, another machine could evict the
            // PINs right before asking for a signature, and so make a PIN
            // prompt appear here when it chooses.
            if self.bindings.is_remote() {
                return Err(refuse(
                    "forgetting PINs",
                    &anyhow!("only on request from this machine, not through an SSH connection"),
                ));
            }
            let forgotten = self.shared.signer.forget_all().await;
            tracing::info!(forgotten, reason = "forget request", "dropped cached PINs");
            return Ok(None);
        }
        if extension.name == LOAD_KEYS_EXTENSION {
            return self
                .load_resident(extension.details.as_ref())
                .await
                .map(Some)
                .map_err(|reason| refuse("loading resident keys", &reason));
        }
        tracing::debug!(name = %extension.name, "unsupported extension");
        Err(AgentError::Failure)
    }

    async fn lock(&mut self, passphrase: String) -> Result<(), AgentError> {
        self.lock_with(passphrase)
            .await
            .map_err(|reason| refuse("locking the agent", &reason))
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        self.unlock_with(passphrase)
            .await
            .map_err(|reason| refuse("unlocking the agent", &reason))
    }
}
