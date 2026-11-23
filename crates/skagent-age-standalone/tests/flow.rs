//! `identity-v1` without an agent: what the security key is asked, in which
//! order, and what the age client is told.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use anyhow::{Context as _, Result, ensure};
use skagent_age::Identity;
use skagent_age_plugin::ipc::Message;
use skagent_age_standalone::flow::{self, FEWEST_TRIES};
use skagent_age_standalone::key::Found;
use support::{
    FILE_KEY, FakeKey, Model, PIN, add_identity, done, fail, head, input, ok, output, recipient,
    stanza, text, typed,
};

/// What a run wrote, and whether it looked for a security key.
struct Ran {
    written: Vec<Message>,
    looked: bool,
}

impl Ran {
    fn heads(&self) -> Vec<String> {
        self.written.iter().map(head).collect()
    }

    /// The bodies of the messages with `tag`, as text.
    fn said(&self, tag: &str) -> Vec<String> {
        self.written
            .iter()
            .filter(|message| message.tag == tag)
            .map(text)
            .collect()
    }

    /// The one `error` of the run.
    fn error(&self) -> Result<String> {
        let errors = self.said("error");
        ensure!(errors.len() == 1, "{errors:?}");
        errors.into_iter().next().context("no error")
    }
}

/// Runs the plugin on what the age client sends, with `found` for the
/// plugged-in security keys.
fn run_with(client: &[Message], found: Found<FakeKey>) -> Result<Ran> {
    let mut out = Vec::new();
    let looked = Cell::new(false);
    flow::run(&mut input(client)?, &mut out, || {
        looked.set(true);
        Ok(found)
    })?;
    Ok(Ran {
        written: output(&out)?,
        looked: looked.get(),
    })
}

/// Runs the plugin with the one security key `model`.
fn run(client: &[Message], model: &Rc<RefCell<Model>>) -> Result<Ran> {
    run_with(client, Found::One(FakeKey::of(model)))
}

/// What the age client hands over for one file encrypted to the identities
/// `to`, with the identity lines `named`.
fn file_for(named: &[u8], to: &[u8]) -> Result<Vec<Message>> {
    let mut client = Vec::new();
    for answer in named {
        client.push(add_identity(&Identity::Named(recipient(*answer)?)));
    }
    for (position, answer) in to.iter().enumerate() {
        let randomness = u8::try_from(position)?.saturating_add(1);
        client.push(stanza(&recipient(*answer)?, "0", randomness)?);
    }
    client.push(done());
    Ok(client)
}

fn with(mut client: Vec<Message>, answers: &[Message]) -> Vec<Message> {
    client.extend_from_slice(answers);
    client
}

fn asked(model: &Rc<RefCell<Model>>) -> Vec<String> {
    model.borrow().asked.clone()
}

#[test]
fn one_pin_and_one_touch_open_a_file() -> Result<()> {
    let model = Model::holding(&[1]);
    let client = with(file_for(&[1], &[1])?, &[typed(PIN), ok(), ok()]);
    let ran = run(&client, &model)?;

    ensure!(
        ran.heads() == ["request-secret", "msg", "file-key 0", "done"],
        "{:?}",
        ran.heads()
    );
    // The prompt is all a person may see: the key, the tries, the touch.
    ensure!(
        ran.said("request-secret") == ["PIN of YubiKey 12345678 (8 tries left), then touch it"]
    );
    ensure!(ran.said("msg") == ["touch YubiKey 12345678 when it blinks"]);
    let file_key = ran.written.get(2).context("no file key")?;
    ensure!(*file_key.body == *FILE_KEY);
    ensure!(asked(&model) == ["tries", "list", "derive 1"]);
    Ok(())
}

/// The lines of everyone a file is for: only the key's answer tells which
/// of them it holds, and it is asked once.
#[test]
fn the_key_is_asked_once_however_many_identities_are_named() -> Result<()> {
    let model = Model::holding(&[3]);
    let client = with(file_for(&[1, 2, 3], &[1, 2, 3])?, &[typed(PIN), ok(), ok()]);
    let ran = run(&client, &model)?;

    ensure!(
        ran.heads() == ["request-secret", "msg", "file-key 0", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(asked(&model) == ["tries", "list", "derive 3"]);
    Ok(())
}

#[test]
fn a_wrong_pin_is_asked_for_again_with_the_tries_left() -> Result<()> {
    let model = Model::holding(&[1]);
    let client = with(
        file_for(&[1], &[1])?,
        &[typed(b"000000"), typed(b"111111"), typed(PIN), ok(), ok()],
    );
    let ran = run(&client, &model)?;

    ensure!(
        ran.said("request-secret")
            == [
                "PIN of YubiKey 12345678 (8 tries left), then touch it",
                "Wrong PIN. PIN of YubiKey 12345678 (7 tries left), then touch it",
                "Wrong PIN. PIN of YubiKey 12345678 (6 tries left), then touch it",
            ],
        "{:?}",
        ran.said("request-secret")
    );
    ensure!(
        ran.heads()
            .ends_with(&["file-key 0".to_owned(), "done".to_owned()])
    );
    // The tries are read before every prompt, and no PIN is tried twice.
    ensure!(
        asked(&model)
            == [
                "tries", "list", "tries", "list", "tries", "list", "derive 1"
            ]
    );
    Ok(())
}

/// The counter is the key's, for everything on it: the last tries aren't
/// spent where typos are likely.
#[test]
fn the_last_tries_arent_spent_here() -> Result<()> {
    let model = Model::holding(&[1]);
    model.borrow_mut().tries = FEWEST_TRIES.saturating_sub(1);
    let ran = run(&with(file_for(&[1], &[1])?, &[ok()]), &model)?;
    ensure!(
        ran.heads() == ["error internal", "done"],
        "{:?}",
        ran.heads()
    );
    let error = ran.error()?;
    ensure!(
        error.contains("YubiKey 12345678 has only 2 tries left") && error.contains("not asking"),
        "{error}"
    );
    ensure!(asked(&model) == ["tries"], "the key was asked for more");

    // With one try more it asks, once: the wrong PIN leaves too few.
    let model = Model::holding(&[1]);
    model.borrow_mut().tries = FEWEST_TRIES;
    let client = with(file_for(&[1], &[1])?, &[typed(b"000000"), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["request-secret", "error internal", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(model.borrow().tries == 2);

    // A blocked PIN is said to be one.
    let model = Model::holding(&[1]);
    model.borrow_mut().tries = 0;
    let ran = run(&with(file_for(&[1], &[1])?, &[ok()]), &model)?;
    let error = ran.error()?;
    ensure!(
        error.contains("the PIN of YubiKey 12345678 is blocked"),
        "{error}"
    );
    Ok(())
}

/// An answer that can't be a PIN costs no try: the key never sees it.
#[test]
fn an_answer_of_a_length_no_pin_has_never_reaches_the_key() -> Result<()> {
    let model = Model::holding(&[1]);
    let client = with(
        file_for(&[1], &[1])?,
        &[typed(b"123"), typed(&[b'7'; 64]), typed(PIN), ok(), ok()],
    );
    let ran = run(&client, &model)?;
    let prompts = ran.said("request-secret");
    ensure!(prompts.len() == 3, "{prompts:?}");
    for prompt in prompts.iter().skip(1) {
        ensure!(
            prompt
                == "A PIN has 4 to 63 characters. PIN of YubiKey 12345678 (8 tries left), then touch it",
            "{prompt}"
        );
    }
    ensure!(
        ran.heads()
            .ends_with(&["file-key 0".to_owned(), "done".to_owned()])
    );
    ensure!(model.borrow().tries == 8);
    ensure!(asked(&model) == ["tries", "tries", "tries", "list", "derive 1"]);

    // A prompt that keeps answering nothing isn't asked forever.
    let model = Model::holding(&[1]);
    let nothing = [typed(b""), typed(b""), typed(b""), ok()];
    let ran = run(&with(file_for(&[1], &[1])?, &nothing), &model)?;
    ensure!(
        ran.heads()
            == [
                "request-secret",
                "request-secret",
                "request-secret",
                "error internal",
                "done"
            ],
        "{:?}",
        ran.heads()
    );
    let error = ran.error()?;
    ensure!(error.contains("no PIN was given"), "{error}");
    ensure!(!asked(&model).contains(&"list".to_owned()));
    Ok(())
}

#[test]
fn three_wrong_pins_in_a_row_block_the_key_until_it_is_replugged() -> Result<()> {
    let model = Model::holding(&[1]);
    let wrong = [typed(b"000000"), typed(b"111111"), typed(b"222222"), ok()];
    let ran = run(&with(file_for(&[1], &[1])?, &wrong), &model)?;
    ensure!(ran.said("request-secret").len() == 3);
    let error = ran.error()?;
    ensure!(
        error.contains("takes no more PINs") && error.contains("unplug it and plug it back in"),
        "{error}"
    );
    // Not the same as a PIN that is blocked for good.
    ensure!(!error.contains("FIDO reset"), "{error}");
    ensure!(model.borrow().tries == 5);
    Ok(())
}

#[test]
fn without_a_pin_the_key_is_asked_nothing() -> Result<()> {
    let model = Model::holding(&[1]);
    // The client has nobody to ask, or the user cancelled.
    let ran = run(&with(file_for(&[1], &[1])?, &[fail(), ok()]), &model)?;
    ensure!(
        ran.heads() == ["request-secret", "error internal", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(ran.error()? == "no PIN was given for YubiKey 12345678");
    ensure!(asked(&model) == ["tries"]);
    Ok(())
}

#[test]
fn a_key_without_an_identity_is_told_from_one_with_another() -> Result<()> {
    let model = Model::holding(&[]);
    let ran = run(&with(file_for(&[1], &[1])?, &[typed(PIN), ok()]), &model)?;
    ensure!(ran.error()? == "YubiKey 12345678 holds no age identity of skagent's");
    ensure!(asked(&model) == ["tries", "list"], "a touch for nothing");

    // Two identities on the key, neither of them named: a touch each to
    // know.
    let model = Model::holding(&[7, 8]);
    let client = with(file_for(&[1, 2], &[1, 2])?, &[typed(PIN), ok(), ok(), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["request-secret", "msg", "msg", "error internal", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(ran.error()? == "none of the identities named is on YubiKey 12345678");
    ensure!(asked(&model) == ["tries", "list", "derive 7", "derive 8"]);
    Ok(())
}

/// A key with two identities, the second of which the file is for.
#[test]
fn the_keys_credentials_are_tried_in_turn_a_touch_each() -> Result<()> {
    let model = Model::holding(&[1, 2]);
    let client = with(file_for(&[2], &[2])?, &[typed(PIN), ok(), ok(), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["request-secret", "msg", "msg", "file-key 0", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(asked(&model) == ["tries", "list", "derive 1", "derive 2"]);
    Ok(())
}

/// An identity line whose recipient the file isn't encrypted to (any more).
#[test]
fn an_identity_that_is_named_and_opens_nothing_isnt_the_end() -> Result<()> {
    // Both of the key's identities are named, the file is for the second.
    let model = Model::holding(&[1, 2]);
    let client = with(file_for(&[1, 2], &[2, 9])?, &[typed(PIN), ok(), ok(), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["request-secret", "msg", "msg", "file-key 0", "done"],
        "{:?}",
        ran.heads()
    );

    // Nothing opens: not the same failure as a key nobody named.
    let model = Model::holding(&[1]);
    let client = with(file_for(&[1, 2], &[2, 9])?, &[typed(PIN), ok(), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["request-secret", "msg", "error internal", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(ran.error()? == "the file isn't encrypted to the identity on YubiKey 12345678");
    Ok(())
}

/// The PIN isn't held while nobody may be there: it is typed again, and the
/// same credential is tried once more.
#[test]
fn a_missed_touch_asks_for_the_pin_again_and_tries_the_same_credential() -> Result<()> {
    let model = Model::holding(&[1, 2]);
    model.borrow_mut().untouched = 1;
    let client = with(
        file_for(&[1], &[1])?,
        &[typed(PIN), ok(), typed(PIN), ok(), ok()],
    );
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads()
            == [
                "request-secret",
                "msg",
                "request-secret",
                "msg",
                "file-key 0",
                "done"
            ],
        "{:?}",
        ran.heads()
    );
    ensure!(
        ran.said("request-secret").get(1).map(String::as_str)
            == Some(
                "YubiKey 12345678 wasn't touched in time. PIN (8 tries left) to try again, then \
                 touch it"
            ),
        "{:?}",
        ran.said("request-secret")
    );
    ensure!(
        asked(&model) == ["tries", "list", "derive 1", "tries", "list", "derive 1"],
        "{:?}",
        asked(&model)
    );
    Ok(())
}

#[test]
fn a_missed_touch_and_no_pin_to_try_again_end_the_run() -> Result<()> {
    let model = Model::holding(&[1]);
    model.borrow_mut().untouched = 1;
    let client = with(file_for(&[1], &[1])?, &[typed(PIN), ok(), fail(), ok()]);
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads()
            == [
                "request-secret",
                "msg",
                "request-secret",
                "error internal",
                "done"
            ],
        "{:?}",
        ran.heads()
    );
    ensure!(
        ran.error()?
            == "YubiKey 12345678 wasn't touched in time, and no PIN was given to try again"
    );

    // A wrong PIN at that prompt is a wrong PIN: asked again, and the touch
    // after the right one opens the file.
    let model = Model::holding(&[1]);
    model.borrow_mut().untouched = 1;
    let client = with(
        file_for(&[1], &[1])?,
        &[typed(PIN), ok(), typed(b"000000"), typed(PIN), ok(), ok()],
    );
    let ran = run(&client, &model)?;
    let prompts = ran.said("request-secret");
    ensure!(
        prompts.get(2).map(String::as_str)
            == Some("Wrong PIN. PIN of YubiKey 12345678 (7 tries left), then touch it"),
        "{prompts:?}"
    );
    ensure!(
        ran.heads()
            .ends_with(&["file-key 0".to_owned(), "done".to_owned()])
    );
    Ok(())
}

/// `-j skagent`: which identity that is, only an agent can tell.
#[test]
fn an_identity_without_data_is_refused_and_the_others_still_count() -> Result<()> {
    let model = Model::holding(&[1]);
    let mut client = vec![add_identity(&Identity::AtHand)];
    client.extend(file_for(&[1], &[1])?);
    // `ok` to the error, the PIN, `ok` to the touch and to the file key.
    let ran = run(&with(client, &[ok(), typed(PIN), ok(), ok()]), &model)?;
    ensure!(
        ran.heads()
            == [
                "error identity 0",
                "request-secret",
                "msg",
                "file-key 0",
                "done"
            ],
        "{:?}",
        ran.heads()
    );
    ensure!(
        ran.error()?
            .contains("identities that name their recipient")
    );

    // Alone, it leaves nothing to ask a key for.
    let mut client = vec![add_identity(&Identity::AtHand)];
    client.extend(file_for(&[], &[1])?);
    let ran = run(&with(client, &[ok()]), &model)?;
    ensure!(
        ran.heads() == ["error identity 0", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(!ran.looked, "looked for a security key with nothing to ask");
    Ok(())
}

#[test]
fn an_identity_that_isnt_ours_stops_everything() -> Result<()> {
    let model = Model::holding(&[1]);
    let mut client = vec![Message::new(
        "add-identity",
        &["AGE-PLUGIN-YUBIKEY-16CFWSQYZC6JFAUGPQESMC"],
    )];
    client.extend(file_for(&[1], &[1])?);
    let ran = run(&with(client, &[ok()]), &model)?;
    ensure!(
        ran.heads() == ["error identity 0", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(!ran.looked && asked(&model).is_empty());
    Ok(())
}

/// Nobody is asked for a PIN for a file that has nothing for this plugin.
#[test]
fn a_file_without_a_stanza_of_ours_asks_for_nothing() -> Result<()> {
    let model = Model::holding(&[1]);
    let client = [
        add_identity(&Identity::Named(recipient(1)?)),
        Message::with_body("recipient-stanza", &["0", "X25519", "abc"], &[0; 32]),
        done(),
    ];
    let ran = run(&client, &model)?;
    ensure!(ran.heads() == ["done"], "{:?}", ran.heads());
    ensure!(!ran.looked && asked(&model).is_empty());

    // A stanza of ours that is malformed makes its file's header invalid.
    let client = [
        add_identity(&Identity::Named(recipient(1)?)),
        Message::with_body(
            "recipient-stanza",
            &["0", "mlkem768x25519", "abc"],
            &[0; 32],
        ),
        done(),
        ok(),
    ];
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads() == ["error stanza 0 0", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(!ran.looked && asked(&model).is_empty());
    Ok(())
}

#[test]
fn no_pin_is_asked_for_without_exactly_one_security_key() -> Result<()> {
    let client = with(file_for(&[1], &[1])?, &[ok()]);

    let ran = run_with(
        &client,
        Found::None {
            unusable: Vec::new(),
        },
    )?;
    ensure!(
        ran.heads() == ["error internal", "done"],
        "{:?}",
        ran.heads()
    );
    ensure!(ran.error()? == "no security key is plugged in");

    // What is plugged in and can't hold an identity is named with why.
    let unusable = vec!["U2F token: no CTAP2".to_owned()];
    let ran = run_with(&client, Found::None { unusable })?;
    ensure!(
        ran.error()?
            == "no security key that could hold an age identity is plugged in (U2F token: no \
                CTAP2)"
    );

    // The PIN would go to one of them on a guess.
    let names = vec!["YubiKey 1".to_owned(), "YubiKey 2".to_owned()];
    let ran = run_with(&client, Found::Several(names))?;
    ensure!(
        ran.heads() == ["error internal", "done"],
        "{:?}",
        ran.heads()
    );
    let error = ran.error()?;
    ensure!(
        error.contains("several security keys are plugged in (YubiKey 1, YubiKey 2)")
            && error.contains("unplug all but the one to use"),
        "{error}"
    );
    Ok(())
}

/// The age clients send one file at a time; the protocol allows more.
#[test]
fn each_file_takes_its_own_touch_and_one_pin_does_for_all() -> Result<()> {
    let model = Model::holding(&[1]);
    let to = recipient(1)?;
    let client = [
        add_identity(&Identity::Named(to.clone())),
        stanza(&to, "0", 1)?,
        stanza(&to, "1", 2)?,
        done(),
        typed(PIN),
        ok(),
        ok(),
        ok(),
        ok(),
    ];
    let ran = run(&client, &model)?;
    ensure!(
        ran.heads()
            == [
                "request-secret",
                "msg",
                "file-key 0",
                "msg",
                "file-key 1",
                "done"
            ],
        "{:?}",
        ran.heads()
    );
    ensure!(asked(&model) == ["tries", "list", "derive 1", "derive 1"]);
    Ok(())
}

#[test]
fn a_client_that_stops_early_is_an_error() -> Result<()> {
    let model = Model::holding(&[1]);
    // No `done`.
    let mut client = file_for(&[1], &[1])?;
    client.pop();
    ensure!(run(&client, &model).is_err());
    // Gone instead of answering the prompt.
    ensure!(run(&file_for(&[1], &[1])?, &model).is_err());
    Ok(())
}

/// Where an agent runs, the plugin answers every request with why it
/// doesn't.
#[test]
fn refusing_reads_what_the_client_hands_over_and_says_why() -> Result<()> {
    let client = with(file_for(&[1], &[1])?, &[ok()]);
    let mut out = Vec::new();
    flow::refuse(&mut input(&client)?, &mut out, "skagent runs here")?;
    let written = output(&out)?;
    ensure!(written.iter().map(head).collect::<Vec<_>>() == ["error internal", "done"]);
    ensure!(written.first().map(text).as_deref() == Some("skagent runs here"));
    // Also what encrypting hands over.
    let client = [
        Message::new("add-identity", &["AGE-PLUGIN-SKAGENT-1XYZ"]),
        Message::with_body("wrap-file-key", &[], FILE_KEY),
        done(),
        ok(),
    ];
    let mut out = Vec::new();
    flow::refuse(&mut input(&client)?, &mut out, "skagent runs here")?;
    ensure!(output(&out)?.iter().map(head).collect::<Vec<_>>() == ["error internal", "done"]);
    ensure!(flow::refuse(&mut input(&[])?, &mut Vec::new(), "x").is_err());
    Ok(())
}
