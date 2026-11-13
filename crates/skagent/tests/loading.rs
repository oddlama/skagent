//! Resident conversion, constraint preservation and extension validation.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use clap::Parser as _;
use skagent::agent::LOAD_KEYS_EXTENSION;
use skagent::cli::{Cli, Command};
use skagent::client::decode_loaded_count;
use skagent::identities::{IdentityStore, SkIdentity};
use skagent_fido::ResidentCredential;
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::proto::{Extension, Unparsed};

fn resident(protection: i32, handle: u8) -> Result<SkIdentity> {
    Ok(SkIdentity::from_resident(&ResidentCredential::new(
        "ssh:example".to_owned(),
        &[2; 32],
        vec![handle; 64],
        protection,
        "alice".to_owned(),
    )?))
}

#[test]
fn conversion_preserves_uv_and_builds_a_public_comment() -> Result<()> {
    for protection in 0..=3 {
        let identity = resident(protection, 2)?;
        ensure!(identity.flags() == if protection == 3 { 5 } else { 1 });
        ensure!(identity.application() == "ssh:example");
        ensure!(identity.comment() == "ssh:example alice");
        ensure!(identity.key_handle() == [2; 64]);
        ensure!(identity.expires_at().is_none());
    }
    Ok(())
}

#[test]
fn reload_preserves_existing_lifetime_and_comment() -> Result<()> {
    let now = Instant::now();
    let expiry = now
        .checked_add(Duration::from_secs(100))
        .context("expiry overflow")?;
    let existing =
        SkIdentity::from_credential(support::sk_credential(2, "custom comment")?, Some(expiry))?;
    let mut store = IdentityStore::default();
    store.add(existing.clone());
    let imports = store.resident_imports(&[resident(3, 2)?], now)?;
    ensure!(imports == [existing]);
    ensure!(
        store.resident_imports(&[resident(3, 9)?], now).is_err(),
        "conflicting handle accepted"
    );
    ensure!(
        store.resident_imports(&[resident(1, 2)?], now).is_err(),
        "conflicting verification policy accepted"
    );
    Ok(())
}

#[test]
fn reply_count_is_strictly_validated() -> Result<()> {
    let reply = Extension {
        name: LOAD_KEYS_EXTENSION.to_owned(),
        details: Unparsed::from(258_u32.to_be_bytes().to_vec()),
    };
    ensure!(decode_loaded_count(&reply)? == 258);
    for length in [0, 3, 5] {
        let reply = Extension {
            name: LOAD_KEYS_EXTENSION.to_owned(),
            details: Unparsed::from(vec![0; length]),
        };
        ensure!(decode_loaded_count(&reply).is_err());
    }
    let reply = Extension {
        name: "wrong-extension".to_owned(),
        details: Unparsed::from(vec![0; 4]),
    };
    ensure!(decode_loaded_count(&reply).is_err());
    Ok(())
}

#[test]
fn load_takes_a_socket_and_if_connected_but_never_a_pin() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "load", "--socket", "/run/example.sock"])?;
    ensure!(matches!(cli.command, Command::Load(ref args) if !args.if_connected));
    ensure!(Cli::try_parse_from(["skagent", "load", "--pin", "246810"]).is_err());
    let cli = Cli::try_parse_from(["skagent", "load", "--if-connected"])?;
    ensure!(matches!(cli.command, Command::Load(ref args) if args.if_connected));
    Ok(())
}

#[tokio::test]
async fn locked_and_malformed_load_requests_are_refused_before_hardware_access() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("agent.sock");
    let agent = support::RunningAgent::start(&socket).await?;
    let mut client = agent.client().await?;
    ensure!(
        client
            .extension(Extension {
                name: LOAD_KEYS_EXTENSION.to_owned(),
                details: Unparsed::from(vec![1])
            })
            .await
            .is_err()
    );
    client.lock("test passphrase".to_owned()).await?;
    ensure!(skagent::client::load_keys(&socket).await.is_err());
    client.unlock("test passphrase".to_owned()).await?;
    ensure!(client.request_identities().await?.is_empty());
    agent.stop().await
}
