//! Shared helpers for the integration tests. Every test file is its own
//! crate and uses only part of this module.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use skagent::serve::serve_until;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{AddIdentity, PrivateCredential};
use ssh_agent_lib::ssh_key::private::{
    Ed25519Keypair, Ed25519PrivateKey, KeypairData, SkEd25519 as SkEd25519Keypair,
};
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Upper bound for the agent to start and to stop.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// OpenSSH sk flags: user presence required (0x01) | user verification required (0x04).
pub const SK_FLAGS_UP_UV: u8 = 0x05;

/// An agent served from a background task, stopped explicitly.
pub struct RunningAgent {
    socket: PathBuf,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

impl RunningAgent {
    pub async fn start(socket: &Path) -> Result<Self> {
        let (shutdown, shutdown_received) = oneshot::channel::<()>();
        let path = socket.to_owned();
        let task = tokio::spawn(async move {
            serve_until(&path, async move {
                shutdown_received
                    .await
                    .context("shutdown sender dropped before signalling")
            })
            .await
        });
        tokio::time::timeout(TIMEOUT, async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .with_context(|| format!("agent socket {} did not appear", socket.display()))?;
        Ok(Self {
            socket: socket.to_owned(),
            shutdown,
            task,
        })
    }

    pub async fn client(&self) -> Result<Client<UnixStream>> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connecting to {}", self.socket.display()))?;
        Ok(Client::new(stream))
    }

    pub async fn stop(self) -> Result<()> {
        self.shutdown
            .send(())
            .map_err(|()| anyhow!("agent task ended before shutdown"))?;
        tokio::time::timeout(TIMEOUT, self.task)
            .await
            .context("agent did not stop in time")?
            .context("agent task panicked or was cancelled")?
    }
}

/// Public half of a fake sk key. `seed` makes keys distinct.
pub fn sk_public(seed: u8) -> SkEd25519 {
    SkEd25519::new(Ed25519PublicKey([seed; 32]), "ssh:example")
}

/// Wire form of [`sk_public`].
pub fn sk_key_data(seed: u8) -> KeyData {
    KeyData::SkEd25519(sk_public(seed))
}

/// What `ssh-add` sends for an sk key: public key, flags, key handle, comment.
pub fn sk_credential(seed: u8, comment: &str) -> Result<PrivateCredential> {
    let keypair = SkEd25519Keypair::new(sk_public(seed), SK_FLAGS_UP_UV, vec![seed; 64])
        .context("building fake sk keypair")?;
    Ok(PrivateCredential::Key {
        privkey: KeypairData::SkEd25519(keypair),
        comment: comment.to_owned(),
    })
}

/// [`sk_credential`] wrapped as an `ADD_IDENTITY` request.
pub fn add_sk(seed: u8, comment: &str) -> Result<AddIdentity> {
    Ok(AddIdentity {
        credential: sk_credential(seed, comment)?,
    })
}

/// RFC 8032 section 7.1, test 1: a consistent ed25519 keypair. A mismatched
/// one fails to decode, and ssh-agent-lib drops the connection instead of
/// answering, which would test the library instead of skagent.
const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// A plain ed25519 key, which skagent must refuse.
pub fn ed25519_credential() -> PrivateCredential {
    PrivateCredential::Key {
        privkey: KeypairData::Ed25519(Ed25519Keypair {
            public: Ed25519PublicKey(RFC8032_PUBLIC),
            private: Ed25519PrivateKey::from_bytes(&RFC8032_SECRET),
        }),
        comment: "plain ed25519".to_owned(),
    }
}
