//! Adding, listing, removing keys and locking, over the real protocol.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent::agent::UNLOCK_DELAY_STEP;
use skagent::identities::{BUILT_IN_SK_PROVIDER, SK_PROVIDER_CONSTRAINT};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, Extension, KeyConstraint, RemoveIdentity, Unparsed,
};
use support::{RunningAgent, add_sk, ed25519_credential, sk_key_data};
use tokio::net::UnixStream;

async fn comments(client: &mut Client<UnixStream>) -> Result<Vec<String>> {
    Ok(client
        .request_identities()
        .await
        .context("requesting identities")?
        .into_iter()
        .map(|identity| identity.comment)
        .collect())
}

fn sk_provider(provider: &[u8]) -> KeyConstraint {
    KeyConstraint::Extension(Extension {
        name: SK_PROVIDER_CONSTRAINT.to_owned(),
        details: Unparsed::from(provider.to_vec()),
    })
}

#[tokio::test]
async fn sk_keys_are_added_listed_and_removed() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;

    client
        .add_identity(add_sk(1, "work")?)
        .await
        .context("adding work key")?;
    client
        .add_identity_constrained(AddIdentityConstrained {
            identity: add_sk(2, "personal")?,
            constraints: vec![
                KeyConstraint::Lifetime(3600),
                sk_provider(BUILT_IN_SK_PROVIDER),
            ],
        })
        .await
        .context("adding personal key with ssh-add's constraints")?;
    ensure!(comments(&mut client).await? == ["work", "personal"]);

    // Other connections see the same keys.
    let mut other = agent.client().await?;
    ensure!(comments(&mut other).await? == ["work", "personal"]);

    other
        .remove_identity(RemoveIdentity {
            credential: sk_key_data(1).into(),
        })
        .await
        .context("removing work key")?;
    ensure!(comments(&mut client).await? == ["personal"]);
    let removed_twice = other
        .remove_identity(RemoveIdentity {
            credential: sk_key_data(1).into(),
        })
        .await;
    ensure!(removed_twice.is_err(), "removing a missing key succeeded");

    client
        .remove_all_identities()
        .await
        .context("removing all keys")?;
    ensure!(comments(&mut client).await?.is_empty());

    agent.stop().await
}

#[tokio::test]
async fn non_sk_keys_and_unsupported_constraints_are_refused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;

    let plain = client
        .add_identity(AddIdentity {
            credential: ed25519_credential(),
        })
        .await;
    ensure!(plain.is_err(), "plain ed25519 key accepted");

    for constraint in [KeyConstraint::Confirm, sk_provider(b"/opt/libsk-other.so")] {
        let refused = client
            .add_identity_constrained(AddIdentityConstrained {
                identity: add_sk(3, "constrained")?,
                constraints: vec![constraint.clone()],
            })
            .await;
        ensure!(refused.is_err(), "accepted with {constraint:?}");
    }

    ensure!(
        comments(&mut client).await?.is_empty(),
        "a refused key was stored"
    );
    agent.stop().await
}

#[tokio::test]
async fn adding_the_same_key_again_replaces_it() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;

    client
        .add_identity(add_sk(1, "old comment")?)
        .await
        .context("first add")?;
    client
        .add_identity(add_sk(1, "new comment")?)
        .await
        .context("second add")?;
    ensure!(comments(&mut client).await? == ["new comment"]);

    agent.stop().await
}

#[tokio::test]
async fn a_locked_agent_hides_and_protects_its_keys() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;
    client
        .add_identity(add_sk(1, "work")?)
        .await
        .context("adding key")?;

    ensure!(
        client.lock(String::new()).await.is_err(),
        "locked with an empty passphrase"
    );
    client
        .lock("correct horse".to_owned())
        .await
        .context("locking")?;
    ensure!(
        client.lock("again".to_owned()).await.is_err(),
        "locked twice"
    );

    ensure!(
        comments(&mut client).await?.is_empty(),
        "keys listed while locked"
    );
    ensure!(
        client.add_identity(add_sk(2, "new")?).await.is_err(),
        "added while locked"
    );
    ensure!(
        client.remove_all_identities().await.is_err(),
        "removed while locked"
    );

    client
        .unlock("correct horse".to_owned())
        .await
        .context("unlocking")?;
    ensure!(
        comments(&mut client).await? == ["work"],
        "keys lost by locking"
    );
    ensure!(
        client.unlock("correct horse".to_owned()).await.is_err(),
        "unlocked twice"
    );

    agent.stop().await
}

#[tokio::test]
async fn wrong_unlocks_are_refused_with_a_growing_delay() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;
    client.lock("secret".to_owned()).await.context("locking")?;

    for attempt in 1..=2_u32 {
        let started = Instant::now();
        ensure!(
            client.unlock("guess".to_owned()).await.is_err(),
            "wrong passphrase accepted"
        );
        let expected: Duration = UNLOCK_DELAY_STEP.saturating_mul(attempt);
        ensure!(
            started.elapsed() >= expected,
            "attempt {attempt} answered after {:?}, expected at least {expected:?}",
            started.elapsed()
        );
    }
    // A prefix of the passphrase is wrong too.
    ensure!(client.unlock("secre".to_owned()).await.is_err());

    client
        .unlock("secret".to_owned())
        .await
        .context("unlocking")?;
    // The delay counter is reset by a successful unlock.
    client
        .lock("secret".to_owned())
        .await
        .context("locking again")?;
    let started = Instant::now();
    ensure!(client.unlock("guess".to_owned()).await.is_err());
    ensure!(
        started.elapsed() < UNLOCK_DELAY_STEP.saturating_mul(2),
        "delay was not reset after unlocking: {:?}",
        started.elapsed()
    );

    agent.stop().await
}
