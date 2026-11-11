//! Session binding and destination constraints over the real protocol.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use signature::Signer as _;
use skagent::agent::LOAD_KEYS_EXTENSION;
use skagent::destination::{RESTRICT_DESTINATION_CONSTRAINT, SESSION_BIND_EXTENSION};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::extension::{
    DestinationConstraint, HostTuple, KeySpec, QueryResponse, RestrictDestination, SessionBind,
};
use ssh_agent_lib::proto::{
    AddIdentityConstrained, Extension, KeyConstraint, RemoveIdentity, Unparsed,
};
use ssh_agent_lib::ssh_encoding::Encode as _;
use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
use ssh_agent_lib::ssh_key::public::KeyData;
use support::{RunningAgent, add_sk, sk_key_data};
use tokio::net::UnixStream;

fn host_key(seed: u8) -> (Ed25519Keypair, KeyData) {
    let keypair = Ed25519Keypair::from_seed(&[seed; 32]);
    let key = KeyData::Ed25519(keypair.public);
    (keypair, key)
}

fn bind_request(seed: u8, session_id: &[u8], forwarding: bool) -> Result<Extension> {
    let (keypair, key) = host_key(seed);
    let bind = SessionBind {
        host_key: key,
        session_id: session_id.to_vec(),
        signature: keypair.try_sign(session_id)?,
        is_forwarding: forwarding,
    };
    let mut details = Vec::new();
    bind.encode(&mut details).context("encoding session-bind")?;
    Ok(Extension {
        name: SESSION_BIND_EXTENSION.to_owned(),
        details: Unparsed::from(details),
    })
}

/// `ssh-add -h jump`, where jump has the host key of `seed`.
fn only_to(seed: u8) -> Result<KeyConstraint> {
    let (_, key) = host_key(seed);
    let constraint = RestrictDestination {
        constraints: vec![DestinationConstraint {
            from: HostTuple {
                username: String::new(),
                hostname: String::new(),
                keys: Vec::new(),
            },
            to: HostTuple {
                username: String::new(),
                hostname: "jump".to_owned(),
                keys: vec![KeySpec {
                    keyblob: key,
                    is_ca: false,
                }],
            },
        }],
    };
    let mut details = Vec::new();
    constraint
        .encode(&mut details)
        .context("encoding the constraint")?;
    Ok(KeyConstraint::Extension(Extension {
        name: RESTRICT_DESTINATION_CONSTRAINT.to_owned(),
        details: Unparsed::from(details),
    }))
}

async fn listed(client: &mut Client<UnixStream>) -> Result<usize> {
    Ok(client.request_identities().await.context("listing")?.len())
}

#[tokio::test]
async fn bindings_are_verified_and_query_lists_the_extensions() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut client = agent.client().await?;

    ensure!(
        client
            .extension(bind_request(1, b"session", false)?)
            .await?
            .is_none()
    );
    let mut other = agent.client().await?;
    other.extension(bind_request(1, b"s", true)?).await?;
    ensure!(
        other.extension(bind_request(2, b"s", true)?).await.is_err(),
        "a session ID bound to two host keys"
    );

    let reply = client
        .extension(Extension {
            name: "query".to_owned(),
            details: Unparsed::from(Vec::new()),
        })
        .await?
        .context("query answered nothing")?;
    let supported = reply.details.parse::<QueryResponse>()?.extensions;
    for name in [
        "query",
        SESSION_BIND_EXTENSION,
        LOAD_KEYS_EXTENSION,
        "forget-pins@skagent",
    ] {
        ensure!(
            supported.iter().any(|extension| extension == name),
            "{name} missing: {supported:?}"
        );
    }
    agent.stop().await
}

#[tokio::test]
async fn constrained_keys_exist_only_where_their_destinations_allow() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let agent = RunningAgent::start(&dir.path().join("agent.sock")).await?;
    let mut local = agent.client().await?;
    local
        .add_identity_constrained(AddIdentityConstrained {
            identity: add_sk(5, "jump only")?,
            constraints: vec![only_to(1)?],
        })
        .await?;
    local.add_identity(add_sk(6, "anywhere")?).await?;
    ensure!(
        listed(&mut local).await? == 2,
        "a local connection sees every key"
    );

    // A connection bound to jump sees both.
    let mut on_jump = agent.client().await?;
    on_jump.extension(bind_request(1, b"s1", false)?).await?;
    ensure!(listed(&mut on_jump).await? == 2);

    // One bound to another host only sees the unconstrained key, and can
    // neither remove nor replace the constrained one.
    let mut elsewhere = agent.client().await?;
    elsewhere.extension(bind_request(2, b"s2", false)?).await?;
    ensure!(listed(&mut elsewhere).await? == 1);
    let removed = elsewhere
        .remove_identity(RemoveIdentity {
            credential: ssh_agent_lib::proto::PublicCredential::Key(sk_key_data(5)),
        })
        .await;
    ensure!(removed.is_err(), "removed a key it can't see");
    let replaced = elsewhere
        .add_identity(add_sk(5, "unconstrained now")?)
        .await;
    ensure!(
        replaced.is_err(),
        "dropped the constraints of a key it can't see"
    );

    // A failed bind hides constrained keys for good.
    let mut failed = agent.client().await?;
    let mut garbage = bind_request(1, b"s3", false)?;
    garbage.details = Unparsed::from(vec![1, 2, 3]);
    ensure!(failed.extension(garbage).await.is_err());
    ensure!(listed(&mut failed).await? == 1);

    ensure!(
        listed(&mut local).await? == 2,
        "the refused changes changed something"
    );
    local
        .remove_identity(RemoveIdentity {
            credential: ssh_agent_lib::proto::PublicCredential::Key(sk_key_data(5)),
        })
        .await?;
    agent.stop().await
}
