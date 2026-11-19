//! `recipient-v1`: encrypting to an identity, without the agent.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use skagent_age::{Identity, STANZA_TYPE, Stanza};
use skagent_age_plugin::ipc::Message;
use skagent_age_plugin::recipient;
use support::{done, head, input, ok, output};

/// Randomness for tests: every buffer gets the next byte value.
fn counting() -> impl FnMut(&mut [u8]) -> Result<()> {
    let mut next = 0_u8;
    move |buffer| {
        next = next.wrapping_add(1);
        buffer.fill(next);
        Ok(())
    }
}

fn run(client: &[Message]) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    recipient::run(&mut input(client)?, &mut out, counting())?;
    output(&out)
}

fn add_identity(identity: &Identity) -> Message {
    Message::new("add-identity", &[&identity.to_string()])
}

fn wrap(file_key: &[u8]) -> Message {
    Message::with_body("wrap-file-key", &[], file_key)
}

/// The stanza inside a `recipient-stanza FILE …` command.
fn stanza(message: &Message) -> Result<Stanza> {
    let arguments = message.arguments.get(1..).context("no stanza")?;
    Stanza::from_header(arguments, &message.body)?.context("not our type")
}

#[test]
fn a_file_key_is_wrapped_for_the_recipient_the_identity_names() -> Result<()> {
    let (seed, recipient) = support::identity(1)?;
    let client = [
        add_identity(&Identity::Named(recipient)),
        wrap(b"YELLOW SUBMARINE"),
        Message::new("extension-labels", &[]),
        done(),
        ok(),
        ok(),
    ];
    let written = run(&client)?;
    ensure!(written.len() == 3, "{}", written.len());
    ensure!(head(written.first().context("empty")?) == "labels postquantum");
    let wrapped = written.get(1).context("no stanza")?;
    ensure!(wrapped.tag == "recipient-stanza");
    ensure!(wrapped.arguments.first().map(String::as_str) == Some("0"));
    ensure!(wrapped.arguments.get(1).map(String::as_str) == Some(STANZA_TYPE));
    let file_key = seed
        .unwrap(&[stanza(wrapped)?])?
        .context("the identity can't open it")?;
    ensure!(file_key.expose() == b"YELLOW SUBMARINE");
    ensure!(head(written.last().context("empty")?) == "done");
    Ok(())
}

#[test]
fn labels_are_only_sent_to_a_client_that_asked() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let client = [
        add_identity(&Identity::Named(recipient)),
        wrap(b"YELLOW SUBMARINE"),
        done(),
        ok(),
    ];
    let written = run(&client)?;
    ensure!(
        written
            .iter()
            .map(|message| message.tag.as_str())
            .collect::<Vec<_>>()
            == ["recipient-stanza", "done"]
    );
    Ok(())
}

#[test]
fn every_file_key_is_wrapped_for_every_identity_with_fresh_randomness() -> Result<()> {
    let (first_seed, first) = support::identity(1)?;
    let (second_seed, second) = support::identity(2)?;
    let client = [
        add_identity(&Identity::Named(first)),
        wrap(b"the first file!!"),
        add_identity(&Identity::Named(second)),
        wrap(b"the second file!"),
        done(),
        ok(),
        ok(),
        ok(),
        ok(),
    ];
    let written = run(&client)?;
    let stanzas: Vec<_> = written
        .iter()
        .filter(|message| message.tag == "recipient-stanza")
        .collect();
    let files: Vec<_> = stanzas
        .iter()
        .filter_map(|message| message.arguments.first().cloned())
        .collect();
    ensure!(files == ["0", "0", "1", "1"], "{files:?}");
    let mut encapsulated = Vec::new();
    for (message, (seed, expected)) in stanzas.iter().zip([
        (&first_seed, b"the first file!!"),
        (&second_seed, b"the first file!!"),
        (&first_seed, b"the second file!"),
        (&second_seed, b"the second file!"),
    ]) {
        let stanza = stanza(message)?;
        let file_key = seed
            .unwrap(std::slice::from_ref(&stanza))?
            .context("not for it")?;
        ensure!(file_key.expose() == expected);
        encapsulated.push(stanza.enc_argument());
    }
    encapsulated.sort();
    encapsulated.dedup();
    ensure!(encapsulated.len() == 4, "randomness was reused");
    Ok(())
}

#[test]
fn what_cant_be_wrapped_to_is_an_error_and_then_nothing_is_wrapped() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let good = add_identity(&Identity::Named(recipient));
    let cases: [(&str, Vec<Message>, &str); 5] = [
        (
            "the identity without a recipient",
            vec![add_identity(&Identity::AtHand), wrap(b"YELLOW SUBMARINE")],
            "error identity 0",
        ),
        (
            "another plugin's identity",
            vec![
                good.clone(),
                Message::new(
                    "add-identity",
                    &["AGE-PLUGIN-YUBIKEY-16CFWSQYZC6JFAUGPQESMC"],
                ),
                wrap(b"YELLOW SUBMARINE"),
            ],
            "error identity 1",
        ),
        (
            "a recipient: we have no recipient type",
            vec![
                good.clone(),
                Message::new("add-recipient", &["age1skagent1qqqq"]),
                wrap(b"YELLOW SUBMARINE"),
            ],
            "error recipient 0",
        ),
        (
            "a file key of 17 bytes",
            vec![good.clone(), wrap(b"YELLOW SUBMARINES")],
            "error internal",
        ),
        (
            "a file key of no bytes",
            vec![good.clone(), wrap(b"")],
            "error internal",
        ),
    ];
    for (what, mut client, expected) in cases {
        client.extend([Message::new("extension-labels", &[]), done(), ok(), ok()]);
        let written = run(&client)?;
        ensure!(
            written.iter().map(head).collect::<Vec<_>>() == [expected, "done"],
            "{what}: {:?}",
            written.iter().map(head).collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn a_client_that_doesnt_answer_ok_is_an_error() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let client = [
        add_identity(&Identity::Named(recipient)),
        wrap(b"YELLOW SUBMARINE"),
        done(),
        Message::new("fail", &[]),
    ];
    ensure!(run(&client).is_err());
    Ok(())
}

#[test]
fn failing_randomness_wraps_nothing() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let client = [
        add_identity(&Identity::Named(recipient)),
        wrap(b"YELLOW SUBMARINE"),
        done(),
        ok(),
    ];
    let mut out = Vec::new();
    let result = recipient::run(&mut input(&client)?, &mut out, |_| {
        anyhow::bail!("no randomness")
    });
    ensure!(result.is_err());
    ensure!(output(&out)?.is_empty());
    Ok(())
}
