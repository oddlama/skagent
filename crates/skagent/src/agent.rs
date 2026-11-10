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

use anyhow::{Context as _, Result, anyhow, bail};
use async_trait::async_trait;
use skagent_secret::SecretBuffer;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Identity, PublicCredential, RemoveIdentity, SignRequest,
};
use ssh_agent_lib::ssh_key::Signature;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use zeroize::Zeroize as _;

use crate::identities::{IdentityStore, SkIdentity, evaluate_constraints};
use crate::prompt::Askpass;
use crate::signer;
use crate::socket::PeerCheckedListener;

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
    /// An agent that asks for PINs through `askpass`. Without one, keys that
    /// need a PIN can't sign.
    #[must_use]
    pub fn new(askpass: Option<Askpass>) -> Self {
        Self {
            shared: Arc::new(Shared {
                askpass,
                ..Shared::default()
            }),
        }
    }
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    /// Held for the whole unlock attempt, including the penalty wait.
    unlock_attempts: Mutex<()>,
    askpass: Option<Askpass>,
}

#[derive(Debug, Default)]
struct State {
    identities: IdentityStore,
    /// The lock passphrase while the agent is locked.
    lock: Option<SecretBuffer>,
    failed_unlocks: u32,
}

impl Agent<PeerCheckedListener> for SkAgent {
    fn new_session(&mut self, _socket: &UnixStream) -> impl Session {
        AgentSession {
            shared: Arc::clone(&self.shared),
        }
    }
}

/// One client connection.
#[derive(Debug)]
pub struct AgentSession {
    shared: Arc<Shared>,
}

/// Logs why a request is refused and turns it into a protocol `FAILURE`.
fn refuse(request: &str, reason: &anyhow::Error) -> AgentError {
    tracing::warn!(reason = %format!("{reason:#}"), "refused {request}");
    AgentError::Failure
}

impl AgentSession {
    async fn add(&self, identity: AddIdentity, lifetime: Option<Duration>) -> Result<()> {
        let now = Instant::now();
        let expires_at = lifetime
            .map(|lifetime| {
                now.checked_add(lifetime)
                    .ok_or_else(|| anyhow!("key lifetime of {} s is too large", lifetime.as_secs()))
            })
            .transpose()?;
        let identity = SkIdentity::from_credential(identity.credential, expires_at)?;

        let mut state = self.shared.state.lock().await;
        if state.lock.is_some() {
            bail!("the agent is locked");
        }
        let (fingerprint, comment) = (identity.fingerprint(), identity.comment().to_owned());
        let replaced = state.identities.add(identity);
        tracing::info!(
            %fingerprint,
            %comment,
            lifetime_seconds = lifetime.map(|lifetime| lifetime.as_secs()),
            replaced,
            "added key"
        );
        Ok(())
    }

    async fn remove(&self, credential: &PublicCredential) -> Result<()> {
        let PublicCredential::Key(key) = credential else {
            bail!("certificates are never held by this agent");
        };
        let mut state = self.shared.state.lock().await;
        if state.lock.is_some() {
            bail!("the agent is locked");
        }
        if !state.identities.remove(key, Instant::now()) {
            bail!("the key is not in the agent");
        }
        tracing::info!(fingerprint = %key.fingerprint(ssh_agent_lib::ssh_key::HashAlg::Sha256), "removed key");
        Ok(())
    }

    async fn sign_with(&self, request: &SignRequest) -> Result<Signature> {
        let PublicCredential::Key(key) = &request.credential else {
            bail!("certificates are never held by this agent");
        };
        // Copied out, so the state isn't locked while the device waits for a touch.
        let identity = {
            let mut state = self.shared.state.lock().await;
            if state.lock.is_some() {
                bail!("the agent is locked");
            }
            state
                .identities
                .find(key, Instant::now())
                .ok_or_else(|| anyhow!("the key is not in the agent"))?
                .clone()
        };
        let signature =
            signer::sign(&identity, &request.data, self.shared.askpass.as_ref()).await?;
        tracing::info!(
            fingerprint = %identity.fingerprint(),
            comment = %identity.comment(),
            "signed"
        );
        Ok(signature)
    }

    async fn lock_with(&self, mut passphrase: String) -> Result<()> {
        let stored = Self::store_passphrase(passphrase.as_bytes());
        passphrase.zeroize();
        let stored = stored?;

        let mut state = self.shared.state.lock().await;
        if state.lock.is_some() {
            bail!("the agent is already locked");
        }
        state.lock = Some(stored);
        tracing::info!("agent locked");
        Ok(())
    }

    async fn unlock_with(&self, mut passphrase: String) -> Result<()> {
        // Serializes all attempts, including their penalty wait.
        let _attempt = self.shared.unlock_attempts.lock().await;

        let penalty = {
            let mut state = self.shared.state.lock().await;
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
        let mut state = self.shared.state.lock().await;
        if state.lock.is_some() {
            return Ok(Vec::new());
        }
        Ok(state
            .identities
            .identities(Instant::now())
            .iter()
            .map(SkIdentity::identity)
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.sign_with(&request)
            .await
            .map_err(|reason| refuse("signature request", &reason))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        self.add(identity, None)
            .await
            .map_err(|reason| refuse("adding a key", &reason))
    }

    async fn add_identity_constrained(
        &mut self,
        request: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        let added = match evaluate_constraints(&request.constraints) {
            Ok(accepted) => self.add(request.identity, accepted.lifetime).await,
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
        let mut state = self.shared.state.lock().await;
        if state.lock.is_some() {
            return Err(refuse("removing all keys", &anyhow!("the agent is locked")));
        }
        let removed = state.identities.clear();
        tracing::info!(removed, "removed all keys");
        Ok(())
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
