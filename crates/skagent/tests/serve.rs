//! The served agent, exercised over a real unix socket with an ssh-agent client.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, ensure};
use skagent::serve::serve_until;
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::SignRequest;
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Upper bound for the agent to start and to stop.
const TIMEOUT: Duration = Duration::from_secs(5);

struct RunningAgent {
    socket: PathBuf,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

impl RunningAgent {
    async fn start(socket: &Path) -> Result<Self> {
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

    async fn client(&self) -> Result<Client<UnixStream>> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connecting to {}", self.socket.display()))?;
        Ok(Client::new(stream))
    }

    async fn stop(self) -> Result<()> {
        self.shutdown
            .send(())
            .map_err(|()| anyhow!("agent task ended before shutdown"))?;
        tokio::time::timeout(TIMEOUT, self.task)
            .await
            .context("agent did not stop in time")?
            .context("agent task panicked or was cancelled")?
    }
}

fn sk_key() -> KeyData {
    KeyData::SkEd25519(SkEd25519::new(Ed25519PublicKey([7; 32]), "ssh:example"))
}

#[tokio::test]
async fn new_agent_has_no_identities() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;

    let identities = agent
        .client()
        .await?
        .request_identities()
        .await
        .context("requesting identities")?;
    ensure!(
        identities.is_empty(),
        "unexpected identities: {identities:?}"
    );

    agent.stop().await
}

#[tokio::test]
async fn signing_is_refused_without_identities() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;

    let result = agent
        .client()
        .await?
        .sign(SignRequest {
            credential: sk_key().into(),
            data: b"session data".to_vec(),
            flags: 0,
        })
        .await;
    ensure!(
        result.is_err(),
        "agent signed without any identity: {result:?}"
    );

    agent.stop().await
}

#[tokio::test]
async fn connection_survives_a_refused_request() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;

    let refused = client
        .sign(SignRequest {
            credential: sk_key().into(),
            data: Vec::new(),
            flags: 0,
        })
        .await;
    ensure!(refused.is_err());
    let identities = client
        .request_identities()
        .await
        .context("requesting identities after a refusal")?;
    ensure!(identities.is_empty());

    agent.stop().await
}

#[tokio::test]
async fn shutdown_removes_the_socket() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let socket = dir.path().join("agent.sock");
    let agent = RunningAgent::start(&socket).await?;

    agent.stop().await?;
    ensure!(!socket.exists(), "socket left behind after shutdown");
    Ok(())
}

#[tokio::test]
async fn second_agent_on_the_same_socket_is_refused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let socket = dir.path().join("agent.sock");
    let agent = RunningAgent::start(&socket).await?;

    let second = serve_until(&socket, async { Ok(()) }).await;
    let error = match second {
        Ok(()) => anyhow::bail!("second agent started on a live socket"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(
        error.contains("already listening"),
        "unexpected error: {error}"
    );
    // The refused second agent must not have removed the first one's socket.
    ensure!(socket.exists(), "socket of the running agent disappeared");

    agent.stop().await
}
