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
//!
//! Requests about age identities (`docs/age.md`) come in on a socket of
//! their own, from skagent's plugin and its command line only
//! ([`crate::peer`]). That socket answers nothing else, and the ssh-agent
//! socket answers none of them, unless `--age-forwarding` lets it decrypt:
//! then whatever asks there counts as another machine, gets one file key
//! per touch, and nothing from a batch.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use skagent_age::wire::{
    self, BATCH_EXTENSION, BatchReply, BatchRequest, LIST_EXTENSION, ListReply, NEW_EXTENSION,
    NewReply, Refusal, UNWRAP_EXTENSION, UnwrapReply, UnwrapRequest,
};
use skagent_age::{FileKey, Recipient, Seed};
use skagent_fido::{AGE_USER_ID_BYTES, ErrorKind, error_kind};
use skagent_popup::{Failure, Host, Requester};
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
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard};
use zeroize::Zeroize as _;

use crate::age::{AgeIdentities, AgeIdentity, MAX_IDENTITIES, NotChosen};
use crate::batch::{BatchId, Member, Served};
use crate::bindings::{NotPluggedIn, Presence};
use crate::cancel::Hangup;
use crate::destination::{self, Bound, Destination, SESSION_BIND_EXTENSION, SessionBindings};
use crate::display::{self, MAX_COMMAND_CHARS};
use crate::frames::BoundedStream;
use crate::identities::{
    AcceptedConstraints, IdentityStore, Origin, SkIdentity, evaluate_constraints,
};
use crate::peer::{OwnPrograms, Peer, Program};
use crate::popup::cancelled_in_popup;
use crate::signer::{Derived, LastWord, Offer, Signer, SigningTicket, decryption_purpose};
use crate::socket::PeerCheckedListener;

/// Agent protocol extension that drops all cached PINs and keeps the keys.
/// `skagent forget` sends it; screen lockers can run that.
pub const FORGET_PINS_EXTENSION: &str = "forget-pins@skagent";

/// No-argument request to load one selected device's resident SSH keys.
/// The reply carries the number loaded as a big-endian u32, never a PIN.
pub const LOAD_KEYS_EXTENSION: &str = "load-resident-keys@skagent";

/// Asks the agent which extensions it supports.
const QUERY_EXTENSION: &str = "query";

/// What `query` answers on the ssh-agent socket.
const SUPPORTED_EXTENSIONS: [&str; 4] = [
    QUERY_EXTENSION,
    SESSION_BIND_EXTENSION,
    FORGET_PINS_EXTENSION,
    LOAD_KEYS_EXTENSION,
];

/// What `query` answers on the socket for age requests.
const AGE_EXTENSIONS: [&str; 5] = [
    QUERY_EXTENSION,
    UNWRAP_EXTENSION,
    NEW_EXTENSION,
    LIST_EXTENSION,
    BATCH_EXTENSION,
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
        Self::with_stores(signer, identities, AgeIdentities::default(), None)
    }

    /// An agent that also starts with the age identities `age`. `own`: its
    /// executables, whose requests the socket for age requests takes;
    /// without them it takes none.
    #[must_use]
    pub fn with_stores(
        signer: Signer,
        identities: IdentityStore,
        age: AgeIdentities,
        own: Option<OwnPrograms>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                signer,
                own,
                state: Mutex::new(State {
                    identities,
                    age,
                    ..State::default()
                }),
                ..Shared::default()
            }),
        }
    }

    /// The agent as the socket for age requests serves it: connections there
    /// are answered about age identities, and nothing else.
    #[must_use]
    pub fn age_socket(&self) -> AgeSocket {
        AgeSocket(self.clone())
    }

    /// The signer behind the agent, e.g. to authorize a request in tests.
    #[must_use]
    pub fn signer(&self) -> &Signer {
        &self.shared.signer
    }

    /// Whether the ssh-agent socket decrypts age files (`--age-forwarding`):
    /// for other machines, through a forwarded agent. Off unless allowed.
    pub fn allow_age_forwarding(&self, allowed: bool) {
        self.shared.age_forwarding.store(allowed, Ordering::SeqCst);
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
    /// The agent's own executables, to recognize its plugin and its command
    /// line on the socket for age requests.
    own: Option<OwnPrograms>,
    /// Whether the ssh-agent socket decrypts age files (`--age-forwarding`).
    age_forwarding: AtomicBool,
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
    /// The age identities found on security keys.
    age: AgeIdentities,
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
            channel: Channel::Ssh,
            batch: None,
        }
    }
}

/// [`SkAgent`] on its socket for age requests, see [`SkAgent::age_socket`].
#[derive(Debug, Clone)]
pub struct AgeSocket(SkAgent);

impl Agent<PeerCheckedListener> for AgeSocket {
    fn new_session(&mut self, socket: &BoundedStream<UnixStream>) -> impl Session {
        let shared = Arc::clone(&self.0.shared);
        let hangup = Hangup::watch(socket.get_ref())
            .map_err(|error| {
                tracing::warn!(
                    %error,
                    "can't watch the connection, requests of a client that disconnects run to the end"
                );
            })
            .ok();
        // Whoever it is gets a session; one that isn't ours is answered
        // with refusals, and the log says why.
        let channel = match &shared.own {
            None => Channel::AgeRefused,
            Some(own) => match Peer::inspect(socket.get_ref(), own) {
                Ok(peer) if peer.program() == Program::Other => {
                    tracing::warn!(
                        pid = peer.pid(),
                        plugin = %own.plugin_path().display(),
                        "refusing a connection for age requests: its program is neither \
                         skagent's plugin nor skagent itself (after an update, restart the agent)"
                    );
                    Channel::AgeRefused
                }
                Ok(peer) => Channel::Age(peer),
                Err(error) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "refusing a connection for age requests: can't tell who it is"
                    );
                    Channel::AgeRefused
                }
            },
        };
        AgentSession {
            shared,
            hangup,
            bindings: SessionBindings::default(),
            channel,
            batch: None,
        }
    }
}

/// Which socket a connection came in on.
#[derive(Debug)]
enum Channel {
    /// The ssh-agent socket.
    Ssh,
    /// The socket for age requests, from one of skagent's programs.
    Age(Peer),
    /// The socket for age requests, from anything else, or after the
    /// connection did what one of skagent's programs never does.
    AgeRefused,
}

/// One client connection.
#[derive(Debug)]
pub struct AgentSession {
    shared: Arc<Shared>,
    /// Lets long requests (signing, loading) stop when the client is gone.
    hangup: Option<Hangup>,
    /// The SSH sessions ssh bound this connection to (`session-bind`).
    bindings: SessionBindings,
    /// The socket it came in on.
    channel: Channel,
    /// The batch this connection asked for (`skagent batch`), which lasts
    /// as long as the connection at most.
    batch: Option<OpenBatch>,
}

/// A connection's batch. Dropped with the connection, which closes the
/// batch and wipes what it kept.
#[derive(Debug)]
struct OpenBatch {
    id: BatchId,
    shared: Arc<Shared>,
}

impl Drop for OpenBatch {
    fn drop(&mut self) {
        let (id, shared) = (self.id, Arc::clone(&self.shared));
        // Without a runtime the agent is shutting down, and every batch
        // goes with its state.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                if let Some((files, ended)) = shared.signer.close_batch(id).await {
                    tracing::info!(
                        batch = %id,
                        files,
                        ended_before = ended.map(|reason| reason.to_string()),
                        "closed the batch: its command is done"
                    );
                }
            }));
        }
    }
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
        let age_count = u32::try_from(loaded.age.len())
            .context("too many age identities for the loading reply")?;
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
        let new_identities = state.age.found(&loaded.age);
        if age_count > 0 {
            tracing::info!(
                found = age_count,
                new = new_identities,
                "found age identities on the security key"
            );
        }
        loaded.show_loaded(shown);
        // Two counts: the SSH keys, and the age identities on the key.
        let mut reply = count.to_be_bytes().to_vec();
        reply.extend_from_slice(&age_count.to_be_bytes());
        Ok(Extension {
            name: LOAD_KEYS_EXTENSION.to_owned(),
            details: Unparsed::from(reply),
        })
    }

    /// Refuses what the socket for age requests doesn't answer: everything
    /// of the ssh-agent protocol itself.
    fn on_ssh_socket(&self, request: &str) -> Result<(), AgentError> {
        match self.channel {
            Channel::Ssh => Ok(()),
            Channel::Age(_) | Channel::AgeRefused => Err(refuse(
                request,
                &anyhow!("the socket for age requests answers nothing else"),
            )),
        }
    }

    /// The peer on the socket for age requests, if it runs `program`.
    fn age_peer(&self, program: Program) -> Result<&Peer> {
        match &self.channel {
            Channel::Age(peer) if peer.program() == program => Ok(peer),
            Channel::Age(_) => bail!("not asked by the program that may ask this"),
            Channel::AgeRefused => bail!("the connection was refused, see above"),
            Channel::Ssh => bail!(
                "age requests are only answered on the socket for them, not on the ssh-agent \
                 socket"
            ),
        }
    }

    /// Answers `age-unwrap@skagent`. Only a malformed request is an error;
    /// everything else is a reply that says what happened.
    async fn age_unwrap(&self, details: &[u8]) -> Result<Extension> {
        let reply = match self.age_peer(Program::Plugin) {
            Ok(peer) => {
                let request =
                    UnwrapRequest::decode(details).context("decoding the request to unwrap")?;
                let by = Requester::Program {
                    name: peer.started_by().map(|name| Signer::shown_program(&name)),
                };
                // Without a pidfd nobody is proven anybody's descendant.
                let member = match peer.pidfd() {
                    Some(pinned) => self.shared.signer.batch_of(peer.pid(), pinned).await,
                    None => None,
                };
                self.unwrap(&request, by, member).await
            }
            Err(reason) => {
                tracing::warn!(reason = %format!("{reason:#}"), "refused to decrypt");
                UnwrapReply::Refused(Refusal::NotAllowed)
            }
        };
        Ok(Extension {
            name: UNWRAP_EXTENSION.to_owned(),
            details: Unparsed::from(reply.encode()),
        })
    }

    /// Answers `age-unwrap@skagent` on the ssh-agent socket: for another
    /// machine, as far as anyone can tell. One file key for a touch, never
    /// from a batch.
    async fn forwarded_unwrap(&self, details: &[u8]) -> Result<Extension> {
        let request = UnwrapRequest::decode(details).context("decoding the request to unwrap")?;
        let host = |destination: Destination| match destination {
            Destination::Named(name) => Host::Named { name },
            Destination::HostKey(fingerprint) => Host::HostKey { fingerprint },
            Destination::Unverified => Host::Unverified,
        };
        let (from, via) = self.bindings.forwarded_to();
        let by = Requester::Forwarded {
            host: host(from),
            via: via.map(host),
        };
        let reply = self.unwrap(&request, by, None).await;
        Ok(Extension {
            name: UNWRAP_EXTENSION.to_owned(),
            details: Unparsed::from(reply.encode()),
        })
    }

    /// Decrypts for `request`: chooses the identity, has its security key
    /// derive the secret, and unwraps. For a `member` of a batch, the seed
    /// the batch keeps does it, once the first request derived it. What
    /// went wrong becomes a reply.
    async fn unwrap(
        &self,
        request: &UnwrapRequest,
        by: Requester,
        member: Option<Member>,
    ) -> UnwrapReply {
        let named = request.identity.recipient();
        // A member's turn is held to the end: the members that asked
        // meanwhile then find the seed this request left for the batch,
        // instead of asking for touches of their own.
        let mut turn = None;
        // Of several identities that weren't used on this machine yet, only
        // the security key's answer tells which one a request names. They
        // are tried in turn, a touch each, and each is known from then on.
        // `another`: the popup of the one tried before, which it wasn't.
        let mut another: Option<LastWord> = None;
        for _tried in 0..=MAX_IDENTITIES {
            let (identity, ticket) = match self.choose_identity(named).await {
                Ok(chosen) => chosen,
                Err(refusal) => {
                    let Some(last_word) = another else {
                        return UnwrapReply::Refused(refusal);
                    };
                    // Nothing is left that could be the one named.
                    last_word.failed(Failure::AnotherIdentity);
                    return UnwrapReply::Refused(Refusal::AnotherIdentity);
                }
            };
            if let Some(member) = &member {
                let served = if turn.is_none() {
                    match self.turn_in_batch(member, &identity, request).await {
                        Ok(taken) => {
                            turn = Some(taken);
                            None
                        }
                        Err(reply) => Some(reply),
                    }
                } else {
                    self.unwrap_in_batch(member, &identity, request).await
                };
                if let Some(reply) = served {
                    if let Some(last_word) = another {
                        match &reply {
                            UnwrapReply::FileKey(_) => last_word.done(),
                            UnwrapReply::NoMatch => last_word.failed(Failure::NotForIdentity),
                            UnwrapReply::Refused(_) => last_word.failed(Failure::Other),
                        }
                    }
                    return reply;
                }
            }
            let unwrapped = self
                .unwrap_with(
                    &identity,
                    &ticket,
                    request,
                    by.clone(),
                    member.as_ref(),
                    another.take(),
                )
                .await;
            match unwrapped {
                Ok(Unwrapped::Reply(reply)) => return reply,
                Ok(Unwrapped::Another(last_word)) => another = Some(last_word),
                Err(error) => {
                    let refusal = refusal_of(&error, &ticket);
                    tracing::warn!(
                        reason = %format!("{error:#}"),
                        ?refusal,
                        "refused to decrypt"
                    );
                    return UnwrapReply::Refused(refusal);
                }
            }
        }
        // Every try makes one identity known, so there are never this many.
        tracing::warn!("refused to decrypt: tried more identities than there are");
        UnwrapReply::Refused(Refusal::Failed)
    }

    /// The age identity a request is for, and the ticket that authorizes
    /// it, taken under the state lock like a signature's.
    async fn choose_identity(
        &self,
        named: Option<&Recipient>,
    ) -> Result<(AgeIdentity, SigningTicket), Refusal> {
        let refused = |not_chosen: NotChosen| {
            tracing::warn!(reason = %not_chosen, "refused to decrypt");
            match not_chosen {
                NotChosen::NoIdentity => Refusal::NoIdentity,
                NotChosen::Ambiguous => Refusal::Ambiguous,
            }
        };
        let locked = || {
            tracing::warn!(reason = "the agent is locked", "refused to decrypt");
            Refusal::Locked
        };
        let known = {
            let (state, _now) = self.shared.state_now().await;
            if state.lock.is_some() {
                return Err(locked());
            }
            match state.age.choose(named, |_| false) {
                Ok(identity) => {
                    let ticket = self.shared.signer.ticket_for_age(&identity).await;
                    return Ok((identity, ticket));
                }
                Err(NotChosen::NoIdentity) => return Err(refused(NotChosen::NoIdentity)),
                Err(NotChosen::Ambiguous) => state.age.all().to_vec(),
            }
        };
        // Several fit. Which security keys are plugged in may ask the
        // devices, so not under the state lock.
        let keys: Vec<_> = known.iter().map(AgeIdentity::key).collect();
        let presence = self.shared.signer.presence(&keys).await;
        let present: Vec<&AgeIdentity> = known
            .iter()
            .zip(&presence)
            .filter(|(_, presence)| **presence == Presence::Present)
            .map(|(identity, _)| identity)
            .collect();
        let (state, _now) = self.shared.state_now().await;
        if state.lock.is_some() {
            return Err(locked());
        }
        let identity = state
            .age
            .choose(named, |identity| present.contains(&identity))
            .map_err(refused)?;
        let ticket = self.shared.signer.ticket_for_age(&identity).await;
        Ok((identity, ticket))
    }

    /// Answers `request` from the seed `member`'s batch keeps for
    /// `identity`: that is the `Err`, the reply. Without a seed, waits for
    /// the member's turn to derive one, and returns it if there is still
    /// none then.
    async fn turn_in_batch(
        &self,
        member: &Member,
        identity: &AgeIdentity,
        request: &UnwrapRequest,
    ) -> Result<OwnedMutexGuard<()>, UnwrapReply> {
        if let Some(reply) = self.unwrap_in_batch(member, identity, request).await {
            return Err(reply);
        }
        // Another member may be at the security key right now. Only this
        // wait ends when the client leaves.
        let waiting = Arc::clone(&member.turn).lock_owned();
        let turn = Hangup::unless_closed(self.hangup.as_ref(), async { Ok(waiting.await) })
            .await
            .map_err(|error| {
                tracing::warn!(reason = %format!("{error:#}"), "refused to decrypt");
                UnwrapReply::Refused(Refusal::Cancelled)
            })?;
        match self.unwrap_in_batch(member, identity, request).await {
            Some(reply) => Err(reply),
            None => Ok(turn),
        }
    }

    /// What the batch `member` belongs to answers `request` from the seed
    /// it keeps for `identity`, without the security key. `None` if it
    /// keeps none (yet, or any more): then the request is an ordinary one.
    async fn unwrap_in_batch(
        &self,
        member: &Member,
        identity: &AgeIdentity,
        request: &UnwrapRequest,
    ) -> Option<UnwrapReply> {
        let served = self
            .shared
            .signer
            .unwrap_in_batch(
                member.id,
                &identity.key(),
                request.identity.recipient(),
                &request.stanzas,
            )
            .await;
        match served {
            Ok(Served::NotKept) => None,
            Ok(Served::FileKey(file_key)) => {
                tracing::info!(
                    identity = %identity.recipient().map(Recipient::abbreviated).unwrap_or_default(),
                    batch = %member.id,
                    command = %member.command,
                    stanzas = request.stanzas.len(),
                    matched = file_key.is_some(),
                    "decrypted in a batch, without a touch"
                );
                Some(file_key.map_or(UnwrapReply::NoMatch, UnwrapReply::FileKey))
            }
            Ok(Served::AnotherIdentity) => {
                tracing::warn!(
                    batch = %member.id,
                    "refused to decrypt: the batch's identity is another one than the one named"
                );
                Some(UnwrapReply::Refused(Refusal::AnotherIdentity))
            }
            Err(error) => {
                tracing::warn!(
                    reason = %format!("{error:#}"),
                    batch = %member.id,
                    "refused to decrypt"
                );
                Some(UnwrapReply::Refused(Refusal::Failed))
            }
        }
    }

    /// Has `identity`'s security key derive its secret, and unwraps with
    /// it. `follows`: the popup of the identity tried right before, which
    /// wasn't the one named.
    async fn unwrap_with(
        &self,
        identity: &AgeIdentity,
        ticket: &SigningTicket,
        request: &UnwrapRequest,
        by: Requester,
        member: Option<&Member>,
        follows: Option<LastWord>,
    ) -> Result<Unwrapped> {
        let purpose = match member {
            Some(member) => format!(
                "start the batch {} for \"{}\"",
                member.id,
                display::shown(&member.command, MAX_COMMAND_CHARS)
            ),
            None => decryption_purpose(&by),
        };
        // Only the device work is cut short when the client leaves.
        let (derived, last_word) = Hangup::unless_closed(
            self.hangup.as_ref(),
            self.shared
                .signer
                .derive(identity, by, member.map(Offer::of), ticket.clone(), follows),
        )
        .await?;
        // Only now is it known what the touch was good for.
        match self
            .open_with(identity, ticket, request, member, derived, &purpose)
            .await
        {
            Ok(Opened::FileKey(file_key)) => {
                last_word.done();
                Ok(Unwrapped::Reply(UnwrapReply::FileKey(file_key)))
            }
            Ok(Opened::Nothing) => {
                last_word.failed(Failure::NotForIdentity);
                Ok(Unwrapped::Reply(UnwrapReply::NoMatch))
            }
            Ok(Opened::AnotherIdentity) => Ok(Unwrapped::Another(last_word)),
            Err(error) => {
                last_word.failed(Failure::Other);
                Err(error)
            }
        }
    }

    /// What the answer of `identity`'s security key opens of `request`.
    /// The identity's recipient is known from then on.
    async fn open_with(
        &self,
        identity: &AgeIdentity,
        ticket: &SigningTicket,
        request: &UnwrapRequest,
        member: Option<&Member>,
        derived: Derived,
        purpose: &str,
    ) -> Result<Opened> {
        let seed = Seed::from_device_output(&derived.answer)?;
        let device = derived.device;
        drop(derived.answer);
        let recipient = seed.recipient()?;
        {
            let (mut state, _now) = self.shared.state_now().await;
            ensure!(
                state.lock.is_none(),
                "the agent was locked during the decryption"
            );
            ticket.check()?;
            state.age.derived(identity.credential(), &recipient);
        }
        // The identity named is checked before any stanza is tried.
        if let Some(named) = request.identity.recipient()
            && *named != recipient
        {
            tracing::info!(
                named = %named.abbreviated(),
                derived = %recipient.abbreviated(),
                "this age identity of the security key is another one than the one named; it is \
                 known from now on"
            );
            return Ok(Opened::AnotherIdentity);
        }
        let unwrapped = seed.unwrap(&request.stanzas)?;
        if let Some(member) = member {
            // The user agreed to the batch with this request's touch.
            let kept = self
                .shared
                .signer
                .keep_seed(
                    member.id,
                    identity.key(),
                    (&seed, recipient.clone()),
                    device,
                    ticket,
                    unwrapped.is_some(),
                )
                .await?;
            if kept {
                tracing::info!(
                    identity = %recipient.abbreviated(),
                    batch = %member.id,
                    command = %member.command,
                    seconds = member.remaining.as_secs(),
                    memory = ?skagent_secret::strongest_backend(),
                    "the batch started: its command's further decryptions with this identity \
                     need no touch"
                );
            } else {
                tracing::info!(
                    batch = %member.id,
                    "the batch is over, or nothing can be kept right now: further decryptions \
                     take a touch each"
                );
            }
        }
        drop(seed);
        ticket.check()?;
        tracing::info!(
            identity = %recipient.abbreviated(),
            %purpose,
            stanzas = request.stanzas.len(),
            matched = unwrapped.is_some(),
            "decrypted"
        );
        Ok(unwrapped.map_or(Opened::Nothing, Opened::FileKey))
    }

    /// Answers `age-new@skagent`: creates an identity on a security key and
    /// returns its recipient.
    async fn age_new(&self, details: &[u8]) -> Result<Extension> {
        self.age_peer(Program::Agent)?;
        let another = wire::decode_new_request(details)?;
        let ticket = {
            let (state, _now) = self.shared.state_now().await;
            ensure!(state.lock.is_none(), "the agent is locked");
            self.shared.signer.ticket()
        };
        let mut user_id = [0_u8; AGE_USER_ID_BYTES];
        rustix::rand::getrandom(&mut user_id, rustix::rand::GetRandomFlags::empty())
            .ok()
            .filter(|&written| written == user_id.len())
            .context("getting random bytes for the new credential's user id")?;
        // Selection, the prompt and the touches end when the client leaves.
        // The commit below always runs to the end once it started.
        let mut created = Hangup::unless_closed(
            self.hangup.as_ref(),
            self.shared
                .signer
                .create_age_identity(user_id, another, ticket),
        )
        .await?;
        let recipient = Seed::from_device_output(&created.answer)?.recipient()?;
        let (mut state, _now) = self.shared.state_now().await;
        ensure!(
            state.lock.is_none(),
            "the agent was locked while the identity was created; `skagent load` finds it"
        );
        self.shared.signer.commit_created(&mut created).await?;
        // No awaits from the commit through noting the identity.
        state.age.derived(&created.credential, &recipient);
        drop(state);
        created.show_created();
        tracing::info!(recipient = %recipient.abbreviated(), "created an age identity");
        Ok(Extension {
            name: NEW_EXTENSION.to_owned(),
            details: Unparsed::from(NewReply { recipient }.encode()),
        })
    }

    /// Answers `age-batch@skagent`: opens a batch for the command line
    /// tool at the other end. It lasts as long as this connection at most.
    async fn age_batch(&mut self, details: &[u8]) -> Result<Extension> {
        let peer = self.age_peer(Program::Agent)?;
        let request = BatchRequest::decode(details).context("decoding the request for a batch")?;
        ensure!(self.batch.is_none(), "the connection has its batch already");
        // Without a pidfd nothing ties the batch to its tool, and no
        // process could be proven to descend from it.
        let tool = peer
            .pidfd()
            .context(
                "batches need a kernel that pins the peer of a connection (SO_PEERPIDFD, \
                 Linux 6.5)",
            )?
            .try_clone()
            .context("keeping a pidfd of the batch's tool")?;
        let tool_pid = peer.pid();
        let command = display::plain(&request.command, MAX_COMMAND_CHARS);
        let opened = {
            let (state, _now) = self.shared.state_now().await;
            ensure!(state.lock.is_none(), "the agent is locked");
            self.shared
                .signer
                .open_batch(
                    (tool_pid, tool),
                    command,
                    Duration::from_secs(u64::from(request.seconds)),
                )
                .await?
        };
        let seconds = u32::try_from(opened.lasts.as_secs()).unwrap_or(u32::MAX);
        tracing::info!(
            batch = %opened.id,
            command = %opened.command,
            seconds,
            pid = tool_pid,
            "opened a batch: the first decryption its command asks for takes the PIN and a \
             touch, the following ones neither"
        );
        self.batch = Some(OpenBatch {
            id: opened.id,
            shared: Arc::clone(&self.shared),
        });
        let shared = Arc::clone(&self.shared);
        drop(tokio::spawn(async move {
            shared.signer.watch_batch(opened).await;
        }));
        Ok(Extension {
            name: BATCH_EXTENSION.to_owned(),
            details: Unparsed::from(BatchReply { seconds }.encode()),
        })
    }

    /// Answers `age-list@skagent` with the identities the agent knows.
    async fn age_list(&self, details: &[u8]) -> Result<Extension> {
        self.age_peer(Program::Agent)?;
        wire::check_simple_request(details)?;
        let (state, _now) = self.shared.state_now().await;
        ensure!(state.lock.is_none(), "the agent is locked");
        let identities = state
            .age
            .all()
            .iter()
            .map(|identity| identity.recipient().cloned())
            .collect();
        Ok(Extension {
            name: LIST_EXTENSION.to_owned(),
            details: Unparsed::from(ListReply { identities }.encode()?),
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

impl AgentSession {
    /// What the socket for age requests answers to an extension.
    async fn age_extension(
        &mut self,
        extension: &Extension,
    ) -> Result<Option<Extension>, AgentError> {
        let details = extension.details.as_ref();
        let answered = match extension.name.as_str() {
            QUERY_EXTENSION => {
                return Extension::new_message(QueryResponse {
                    extensions: AGE_EXTENSIONS.iter().map(|&name| name.to_owned()).collect(),
                })
                .map(Some)
                .map_err(|error| refuse("answering a query", &anyhow!("{error}")));
            }
            UNWRAP_EXTENSION => self.age_unwrap(details).await,
            NEW_EXTENSION => self.age_new(details).await,
            LIST_EXTENSION => self.age_list(details).await,
            BATCH_EXTENSION => self.age_batch(details).await,
            SESSION_BIND_EXTENSION => {
                // ssh binds the connections it forwards. None of skagent's
                // programs does: this one is relayed, and gets nothing more.
                self.channel = Channel::AgeRefused;
                Err(anyhow!(
                    "the connection is bound to an SSH session, so it is forwarded; the socket \
                     for age requests only answers this machine"
                ))
            }
            other => Err(anyhow!(
                "the socket for age requests doesn't know {other:?}"
            )),
        };
        answered
            .map(Some)
            .map_err(|reason| refuse("an age request", &reason))
    }
}

/// What a security key's answer for an identity opened of a request.
enum Opened {
    /// One of the file's stanzas: the file key.
    FileKey(FileKey),
    /// None of them.
    Nothing,
    /// Nothing was tried: the identity is another one than the one the
    /// request names.
    AnotherIdentity,
}

/// How one identity's part of a decryption ended.
enum Unwrapped {
    /// With an answer for the requester.
    Reply(UnwrapReply),
    /// The security key's answer made it another identity than the one the
    /// request names. Its popup is still open, without a last word.
    Another(LastWord),
}

/// Why a decryption that failed with `error` is refused, as far as the
/// requester is told.
fn refusal_of(error: &anyhow::Error, ticket: &SigningTicket) -> Refusal {
    if cancelled_in_popup(error) || ticket.check().is_err() {
        return Refusal::Cancelled;
    }
    let not_plugged_in = error
        .chain()
        .any(|cause| cause.downcast_ref::<NotPluggedIn>().is_some());
    match error_kind(error) {
        Some(ErrorKind::Cancelled) => Refusal::Cancelled,
        Some(ErrorKind::TouchTimeout) => Refusal::TimedOut,
        _ if not_plugged_in => Refusal::TimedOut,
        _ => Refusal::Failed,
    }
}

#[async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        self.on_ssh_socket("listing keys")?;
        let visible: Vec<SkIdentity> = {
            let (mut state, now) = self.shared.state_now().await;
            if state.lock.is_some() {
                return Ok(Vec::new());
            }
            state
                .identities
                .identities(now)
                .iter()
                .filter(|identity| self.visible(identity).is_ok())
                .cloned()
                .collect()
        };
        // Not under the state lock: placing the keys may ask the devices.
        let ordered = self.shared.signer.present_first(visible).await;
        Ok(ordered.iter().map(SkIdentity::identity).collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.on_ssh_socket("signature request")?;
        self.sign_with(&request)
            .await
            .map_err(|reason| refuse("signature request", &reason))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        self.on_ssh_socket("adding a key")?;
        self.add(identity, AcceptedConstraints::default())
            .await
            .map_err(|reason| refuse("adding a key", &reason))
    }

    async fn add_identity_constrained(
        &mut self,
        request: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.on_ssh_socket("adding a key")?;
        let added = match evaluate_constraints(&request.constraints) {
            Ok(accepted) => self.add(request.identity, accepted).await,
            Err(reason) => Err(reason),
        };
        added.map_err(|reason| refuse("adding a key", &reason))
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        self.on_ssh_socket("removing a key")?;
        self.remove(&identity.credential)
            .await
            .map_err(|reason| refuse("removing a key", &reason))
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.on_ssh_socket("removing all keys")?;
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
        if !matches!(self.channel, Channel::Ssh) {
            return self.age_extension(&extension).await;
        }
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
        let age_forwarding = self.shared.age_forwarding.load(Ordering::SeqCst);
        if extension.name == QUERY_EXTENSION {
            return Extension::new_message(QueryResponse {
                extensions: SUPPORTED_EXTENSIONS
                    .iter()
                    .copied()
                    .chain(age_forwarding.then_some(UNWRAP_EXTENSION))
                    .map(str::to_owned)
                    .collect(),
            })
            .map(Some)
            .map_err(|error| refuse("answering a query", &anyhow!("{error}")));
        }
        // The one age request this socket takes, and only if told to.
        if extension.name == UNWRAP_EXTENSION && age_forwarding {
            return self
                .forwarded_unwrap(extension.details.as_ref())
                .await
                .map(Some)
                .map_err(|reason| refuse("a forwarded age request", &reason));
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
        self.on_ssh_socket("locking the agent")?;
        self.lock_with(passphrase)
            .await
            .map_err(|reason| refuse("locking the agent", &reason))
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        self.on_ssh_socket("unlocking the agent")?;
        self.unlock_with(passphrase)
            .await
            .map_err(|reason| refuse("unlocking the agent", &reason))
    }
}
