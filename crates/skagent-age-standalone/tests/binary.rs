//! The plugin's binary, run as the age client runs it: what it does before
//! any security key is asked.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use anyhow::{Context as _, Result, ensure};
use skagent_age::{Identity, STANZA_TYPE, Seed, Stanza};
use skagent_age_plugin::ipc::{self, Message};
use skagent_secret::SecretBuffer;
use support::{FILE_KEY, add_identity, done, head, ok, recipient, stanza, text};

/// Runs the plugin with `arguments`, `client` on its standard input and
/// `environment` for all it knows of the machine.
fn run(arguments: &[&str], client: &[Message], environment: &[(&str, &Path)]) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_skagent-age-standalone"));
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command.spawn().context("starting the plugin")?;
    let mut sent = Vec::new();
    for message in client {
        ipc::write(&mut sent, message)?;
    }
    child
        .stdin
        .take()
        .context("no standard input")?
        .write_all(&sent)
        .context("writing to the plugin")?;
    child.wait_with_output().context("waiting for the plugin")
}

fn written(output: &Output) -> Result<Vec<Message>> {
    ensure!(
        output.status.success(),
        "the plugin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    support::output(&output.stdout)
}

/// One file for the identity whose key answers with ones, and the answers
/// to what the plugin may say.
fn decrypting() -> Result<Vec<Message>> {
    let to = recipient(1)?;
    Ok(vec![
        add_identity(&Identity::Named(to.clone())),
        stanza(&to, "0", 1)?,
        done(),
        ok(),
        ok(),
    ])
}

fn encrypting() -> Result<Vec<Message>> {
    Ok(vec![
        add_identity(&Identity::Named(recipient(1)?)),
        Message::with_body("wrap-file-key", &[], FILE_KEY),
        done(),
        ok(),
        ok(),
    ])
}

#[test]
fn run_by_hand_it_says_what_it_is() -> Result<()> {
    for arguments in [
        &[][..],
        &["--help"],
        &["identity-v1"],
        &["--age-plugin=x", "y"],
    ] {
        let output = run(arguments, &[], &[])?;
        let said = String::from_utf8_lossy(&output.stdout);
        ensure!(output.status.success(), "{arguments:?}");
        ensure!(
            said.contains("standalone") && said.contains("where skagent itself doesn't run"),
            "{arguments:?}: {said}"
        );
    }
    // A state machine of a later age.
    let output = run(&["--age-plugin=identity-v2"], &[], &[])?;
    ensure!(!output.status.success());
    ensure!(String::from_utf8_lossy(&output.stderr).contains("identity-v2"));
    Ok(())
}

/// Where an agent runs, its own plugin answers: this one says so, whatever
/// it is asked, and looks for no security key.
#[test]
fn next_to_an_agent_it_refuses_and_says_which_plugin_to_use() -> Result<()> {
    let runtime = tempfile::tempdir().context("creating a runtime directory")?;
    std::fs::write(runtime.path().join("skagent-age.sock"), b"")?;
    let elsewhere = tempfile::tempdir().context("creating a directory")?;
    let named = elsewhere.path().join("agent.sock");
    let found = [
        [("XDG_RUNTIME_DIR", runtime.path())],
        [("SKAGENT_AGE_SOCKET", named.as_path())],
    ];
    for environment in &found {
        for (state_machine, client) in [
            ("--age-plugin=identity-v1", decrypting()?),
            ("--age-plugin=recipient-v1", encrypting()?),
        ] {
            let said = written(&run(&[state_machine], &client, environment)?)?;
            ensure!(
                said.iter().map(head).collect::<Vec<_>>() == ["error internal", "done"],
                "{state_machine} with {environment:?}"
            );
            let why = said.first().map(text).unwrap_or_default();
            ensure!(
                why.contains("skagent runs here") && why.contains("has to be the one in PATH"),
                "{why}"
            );
        }
    }
    Ok(())
}

/// Encrypting to an identity needs neither an agent nor a security key.
#[test]
fn it_encrypts_to_an_identity_like_the_regular_plugin() -> Result<()> {
    let runtime = tempfile::tempdir().context("creating a runtime directory")?;
    let environment = [("XDG_RUNTIME_DIR", runtime.path())];
    let said = written(&run(
        &["--age-plugin=recipient-v1"],
        &encrypting()?,
        &environment,
    )?)?;
    ensure!(
        said.iter()
            .map(|message| message.tag.as_str())
            .collect::<Vec<_>>()
            == ["recipient-stanza", "done"],
        "{:?}",
        said.iter().map(head).collect::<Vec<_>>()
    );
    let wrapped = said.first().context("no stanza")?;
    ensure!(wrapped.arguments.get(1).map(String::as_str) == Some(STANZA_TYPE));
    let arguments = wrapped.arguments.get(1..).context("no stanza")?;
    let wrapped = Stanza::from_header(arguments, &wrapped.body)?.context("not our type")?;
    let seed = Seed::from_device_output(&SecretBuffer::from_slice(&[1; 32])?)?;
    let file_key = seed
        .unwrap(&[wrapped])?
        .context("the identity can't open it")?;
    ensure!(file_key.expose() == FILE_KEY);
    Ok(())
}

/// libfido2 would write every message to and from the security key to
/// stderr, which is the age client's: the plugin asks no key then, and
/// nobody for a PIN.
#[test]
fn with_fido_debug_set_no_security_key_is_asked() -> Result<()> {
    let runtime = tempfile::tempdir().context("creating a runtime directory")?;
    let environment = [
        ("XDG_RUNTIME_DIR", runtime.path()),
        ("FIDO_DEBUG", Path::new("1")),
    ];
    let said = written(&run(
        &["--age-plugin=identity-v1"],
        &decrypting()?,
        &environment,
    )?)?;
    ensure!(
        said.iter().map(head).collect::<Vec<_>>() == ["error internal", "done"],
        "{:?}",
        said.iter().map(head).collect::<Vec<_>>()
    );
    let why = said.first().map(text).unwrap_or_default();
    ensure!(why.contains("FIDO_DEBUG is set"), "{why}");
    Ok(())
}
