//! `identity-v1`: what the plugin asks the agent, and what it tells the age
//! client.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use skagent_age::wire::{Refusal, UnwrapReply};
use skagent_age::{FileKey, Identity, Recipient, STANZA_TYPE, Stanza};
use skagent_age_plugin::identity;
use skagent_age_plugin::ipc::Message;
use support::{Scripted, ScriptedAgent, done, file_key, head, input, ok, output};

/// `add-identity` as the age client sends it.
fn add_identity(identity: &Identity) -> Message {
    Message::new("add-identity", &[&identity.to_string()])
}

/// A stanza of ours for `recipient`, and `recipient-stanza FILE …` for it.
fn stanza(recipient: &Recipient, file: &str, randomness: u8) -> Result<(Stanza, Message)> {
    let stanza = recipient.wrap(
        &FileKey::from_bytes(b"0123456789abcdef")?,
        &[randomness; 64],
    )?;
    let message = Message::with_body(
        "recipient-stanza",
        &[file, STANZA_TYPE, &stanza.enc_argument()],
        stanza.body(),
    );
    Ok((stanza, message))
}

/// Runs the plugin on what the age client sends, with `agent`.
fn run(client: &[Message], agent: &mut ScriptedAgent) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    identity::run(&mut input(client)?, &mut out, agent, || false)?;
    output(&out)
}

#[test]
fn the_file_key_the_agent_unwraps_goes_to_the_client() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (sent, message) = stanza(&recipient, "0", 1)?;
    let named = Identity::Named(recipient);
    let mut agent = ScriptedAgent::answering(vec![Scripted::Reply(file_key(b"YELLOW SUBMARINE")?)]);
    let written = run(&[add_identity(&named), message, done(), ok()], &mut agent)?;

    ensure!(agent.asked.len() == 1);
    let asked = agent.asked.first().context("not asked")?;
    ensure!(asked.identity == named && asked.stanzas == [sent]);
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["file-key 0", "done"]);
    ensure!(*written.first().context("empty")?.body == *b"YELLOW SUBMARINE");
    Ok(())
}

#[test]
fn stanzas_of_other_types_never_reach_the_agent() -> Result<()> {
    let client = [
        add_identity(&Identity::AtHand),
        Message::with_body("recipient-stanza", &["0", "X25519", "abc"], &[7; 32]),
        Message::with_body("recipient-stanza", &["0", "grease", "x", "y"], &[1, 2, 3]),
        // Unknown commands are ignored in this phase.
        Message::with_body("grease-cafe", &["93", "71"], &[9]),
        done(),
    ];
    let mut agent = ScriptedAgent::default();
    let written = run(&client, &mut agent)?;
    ensure!(agent.asked.is_empty());
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["done"]);
    Ok(())
}

#[test]
fn a_file_that_isnt_for_the_identity_gets_no_answer_and_no_error() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, message) = stanza(&recipient, "0", 1)?;
    let mut agent = ScriptedAgent::answering(vec![Scripted::Reply(UnwrapReply::NoMatch)]);
    let written = run(
        &[add_identity(&Identity::AtHand), message, done()],
        &mut agent,
    )?;
    ensure!(agent.asked.len() == 1);
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["done"]);
    Ok(())
}

#[test]
fn each_file_is_one_request_with_all_its_stanzas() -> Result<()> {
    let (_, first) = support::identity(1)?;
    let (_, second) = support::identity(2)?;
    let (a, message_a) = stanza(&first, "0", 1)?;
    let (b, message_b) = stanza(&second, "0", 2)?;
    let (c, message_c) = stanza(&first, "1", 3)?;
    let client = [
        add_identity(&Identity::AtHand),
        message_a,
        Message::with_body("recipient-stanza", &["0", "X25519", "abc"], &[7; 32]),
        message_b,
        message_c,
        done(),
        ok(),
        ok(),
    ];
    let mut agent = ScriptedAgent::answering(vec![
        Scripted::Reply(file_key(b"the first file!!")?),
        Scripted::Reply(file_key(b"the second file!")?),
    ]);
    let written = run(&client, &mut agent)?;
    let stanzas: Vec<_> = agent
        .asked
        .iter()
        .map(|request| request.stanzas.clone())
        .collect();
    ensure!(stanzas == [vec![a, b], vec![c]]);
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["file-key 0", "file-key 1", "done"]);
    Ok(())
}

#[test]
fn identities_are_tried_in_order_until_one_fits() -> Result<()> {
    let (_, first) = support::identity(1)?;
    let (_, second) = support::identity(2)?;
    let (_, message) = stanza(&second, "0", 1)?;
    let identities = [Identity::Named(first), Identity::Named(second)];
    let mut client: Vec<Message> = identities.iter().map(add_identity).collect();
    client.extend([message, done(), ok()]);
    let mut agent = ScriptedAgent::answering(vec![
        Scripted::Reply(UnwrapReply::NoMatch),
        Scripted::Reply(file_key(b"YELLOW SUBMARINE")?),
    ]);
    let written = run(&client, &mut agent)?;
    let asked: Vec<_> = agent
        .asked
        .iter()
        .map(|request| request.identity.clone())
        .collect();
    ensure!(asked == identities);
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["file-key 0", "done"]);
    Ok(())
}

/// With an identity that names no recipient (`-j skagent`), which is
/// nobody else's line.
#[test]
fn a_refusal_is_told_and_ends_the_run_unless_another_identity_may_fit() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, file_0) = stanza(&recipient, "0", 1)?;
    let (_, file_1) = stanza(&recipient, "1", 2)?;
    for (refusal, ends) in [
        (Refusal::Cancelled, true),
        (Refusal::TimedOut, true),
        (Refusal::Locked, true),
        (Refusal::NotAllowed, true),
        (Refusal::Failed, true),
        (Refusal::NoIdentity, false),
        (Refusal::AnotherIdentity, false),
        (Refusal::Ambiguous, false),
    ] {
        let client = [
            add_identity(&Identity::AtHand),
            file_0.clone(),
            file_1.clone(),
            done(),
            ok(),
            ok(),
        ];
        let mut agent = ScriptedAgent::answering(vec![
            Scripted::Reply(UnwrapReply::Refused(refusal)),
            Scripted::Reply(UnwrapReply::Refused(refusal)),
        ]);
        let written = run(&client, &mut agent)?;
        let expected = if ends { 1 } else { 2 };
        ensure!(
            agent.asked.len() == expected,
            "{refusal:?}: asked {}",
            agent.asked.len()
        );
        let errors: Vec<_> = written
            .iter()
            .filter(|message| message.tag == "error")
            .collect();
        ensure!(errors.len() == expected, "{refusal:?}");
        for error in errors {
            ensure!(error.arguments == ["identity", "0"], "{refusal:?}");
            ensure!(*error.body == *refusal.message().as_bytes(), "{refusal:?}");
        }
        ensure!(
            written.last().map(head).as_deref() == Some("done"),
            "{refusal:?}"
        );
        ensure!(!written.iter().any(|message| message.tag == "file-key"));
    }
    Ok(())
}

/// age and rage run the plugin once for each line of an identity file and
/// stop at an `error`. A line that names somebody else's key gets none, so
/// the agent's own line after it has its turn.
#[test]
fn an_identity_that_isnt_the_agents_is_answered_with_nothing() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, message) = stanza(&recipient, "0", 1)?;
    let named = Identity::Named(recipient);
    for refusal in [Refusal::NoIdentity, Refusal::AnotherIdentity] {
        // A run of its own, as the clients start it.
        let client = [add_identity(&named), message.clone(), done()];
        let mut agent =
            ScriptedAgent::answering(vec![Scripted::Reply(UnwrapReply::Refused(refusal))]);
        let written = run(&client, &mut agent)?;
        ensure!(
            written.iter().map(head).collect::<Vec<_>>() == ["done"],
            "{refusal:?}: {:?}",
            written.iter().map(head).collect::<Vec<_>>()
        );

        // And in one run with the next line, which the agent has a key for.
        let client = [
            add_identity(&named),
            add_identity(&named),
            message.clone(),
            done(),
            ok(),
        ];
        let mut agent = ScriptedAgent::answering(vec![
            Scripted::Reply(UnwrapReply::Refused(refusal)),
            Scripted::Reply(file_key(b"YELLOW SUBMARINE")?),
        ]);
        let written = run(&client, &mut agent)?;
        ensure!(
            written.iter().map(head).collect::<Vec<_>>() == ["file-key 0", "done"],
            "{refusal:?}"
        );
    }
    // Everything else the agent refuses is told, also for such an identity.
    for refusal in [
        Refusal::Cancelled,
        Refusal::TimedOut,
        Refusal::Locked,
        Refusal::NotAllowed,
        Refusal::Failed,
        Refusal::Ambiguous,
    ] {
        let client = [add_identity(&named), message.clone(), done(), ok()];
        let mut agent =
            ScriptedAgent::answering(vec![Scripted::Reply(UnwrapReply::Refused(refusal))]);
        let written = run(&client, &mut agent)?;
        ensure!(
            written.iter().map(head).collect::<Vec<_>>() == ["error identity 0", "done"],
            "{refusal:?}"
        );
    }
    Ok(())
}

#[test]
fn a_malformed_stanza_of_ours_fails_its_file_and_no_other() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (good, good_message) = stanza(&recipient, "0", 1)?;
    let (_, later_message) = stanza(&recipient, "1", 2)?;
    let enc = good.enc_argument();
    let client = [
        add_identity(&Identity::AtHand),
        Message::with_body("recipient-stanza", &["0", "X25519", "abc"], &[7; 32]),
        good_message,
        // A third argument, and in the next one a body of the wrong length.
        Message::with_body(
            "recipient-stanza",
            &["0", STANZA_TYPE, &enc, "extra"],
            good.body(),
        ),
        Message::with_body("recipient-stanza", &["0", STANZA_TYPE, &enc], &[0; 41]),
        later_message,
        done(),
        ok(),
        ok(),
        ok(),
    ];
    let mut agent = ScriptedAgent::answering(vec![Scripted::Reply(file_key(b"YELLOW SUBMARINE")?)]);
    let written = run(&client, &mut agent)?;
    // Positions count every stanza of the file, the X25519 one included.
    ensure!(
        written.iter().map(head).collect::<Vec<_>>()
            == ["error stanza 0 2", "error stanza 0 3", "file-key 1", "done"]
    );
    ensure!(
        agent.asked.len() == 1,
        "the file with the malformed stanzas was asked for"
    );
    Ok(())
}

#[test]
fn an_identity_that_isnt_ours_stops_everything() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, message) = stanza(&recipient, "0", 1)?;
    let client = [
        add_identity(&Identity::AtHand),
        Message::new(
            "add-identity",
            &["AGE-PLUGIN-YUBIKEY-16CFWSQYZC6JFAUGPQESMC"],
        ),
        message,
        done(),
        ok(),
    ];
    let mut agent = ScriptedAgent::default();
    let written = run(&client, &mut agent)?;
    ensure!(
        agent.asked.is_empty(),
        "unwrapped although an identity was refused"
    );
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["error identity 1", "done"]);
    Ok(())
}

#[test]
fn the_client_hears_about_the_wait_once_and_only_if_it_takes_long() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, file_0) = stanza(&recipient, "0", 1)?;
    let (_, file_1) = stanza(&recipient, "1", 2)?;
    let client = [
        add_identity(&Identity::AtHand),
        file_0,
        file_1,
        done(),
        // To `msg`, then to the two file keys.
        ok(),
        ok(),
        ok(),
    ];
    let mut agent = ScriptedAgent::answering(vec![
        Scripted::Slow(4, file_key(b"the first file!!")?),
        Scripted::Slow(4, file_key(b"the second file!")?),
    ]);
    let written = run(&client, &mut agent)?;
    ensure!(
        written.iter().map(head).collect::<Vec<_>>() == ["msg", "file-key 0", "file-key 1", "done"]
    );
    let notice = String::from_utf8(written.first().context("empty")?.body.to_vec())?;
    ensure!(
        notice.contains("PIN") && notice.contains("touch"),
        "{notice}"
    );

    // An answer that is there right away says nothing.
    let (_, quick) = stanza(&recipient, "0", 3)?;
    let mut agent =
        ScriptedAgent::answering(vec![Scripted::Slow(1, file_key(b"YELLOW SUBMARINE")?)]);
    let written = run(
        &[add_identity(&Identity::AtHand), quick, done(), ok()],
        &mut agent,
    )?;
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["file-key 0", "done"]);
    Ok(())
}

#[test]
fn nobody_is_waited_for_once_the_client_is_gone() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, message) = stanza(&recipient, "0", 1)?;
    let mut agent = ScriptedAgent::answering(vec![Scripted::Slow(1, UnwrapReply::NoMatch)]);
    let mut out = Vec::new();
    let result = identity::run(
        &mut input(&[add_identity(&Identity::AtHand), message, done()])?,
        &mut out,
        &mut agent,
        || true,
    );
    ensure!(
        result.is_err(),
        "kept waiting for an agent nobody listens to"
    );
    ensure!(output(&out)?.is_empty());
    Ok(())
}

#[test]
fn an_agent_that_cant_be_reached_and_a_client_that_stops_early_are_errors() -> Result<()> {
    let (_, recipient) = support::identity(1)?;
    let (_, message) = stanza(&recipient, "0", 1)?;
    let mut agent = ScriptedAgent::answering(vec![Scripted::Unreachable]);
    let client = [add_identity(&Identity::AtHand), message.clone(), done()];
    ensure!(run(&client, &mut agent).is_err(), "no agent");

    // No `done`, and no answer to the file key.
    let mut agent = ScriptedAgent::default();
    ensure!(
        run(
            &[add_identity(&Identity::AtHand), message.clone()],
            &mut agent
        )
        .is_err()
    );
    let mut agent = ScriptedAgent::answering(vec![Scripted::Reply(file_key(b"YELLOW SUBMARINE")?)]);
    let client = [add_identity(&Identity::AtHand), message, done()];
    ensure!(run(&client, &mut agent).is_err(), "no answer to file-key");
    Ok(())
}
