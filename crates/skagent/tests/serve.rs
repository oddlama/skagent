//! Lifecycle of the served agent over a real unix socket.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use skagent::agent::SkAgent;
use skagent::client;
use skagent::serve::{Listening, serve_until};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::proto::SignRequest;
use support::{RunningAgent, sk_key_data};

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
            credential: sk_key_data(7).into(),
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
            credential: sk_key_data(7).into(),
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

    let second = serve_until(Listening::Bind(socket.clone()), SkAgent::default(), async {
        Ok(())
    })
    .await;
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

#[tokio::test]
async fn an_activated_socket_is_served_and_left_in_place() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let socket = dir.path().join("agent.sock");
    // What systemd would pass: bound and listening before the agent starts.
    let passed = std::os::unix::net::UnixListener::bind(&socket).context("binding")?;
    passed
        .set_nonblocking(true)
        .context("making it non-blocking")?;
    ensure!(skagent::serve::activated_path(&passed)? == socket);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve_until(
        Listening::Activated(passed),
        SkAgent::default(),
        async move { stopped.await.context("stop sender dropped") },
    ));
    client::forget_pins(&socket)
        .await
        .context("talking to the agent on the passed socket")?;
    stop.send(()).map_err(|()| anyhow::anyhow!("agent gone"))?;
    served.await.context("joining the agent")??;
    ensure!(socket.exists(), "the agent removed the socket systemd owns");
    Ok(())
}
