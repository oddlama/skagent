//! The plugin protocol's messages on the wire.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::io::Cursor;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age_plugin::ipc::{self, Message, Secret};

fn written(message: &Message) -> Result<String> {
    let mut bytes = Vec::new();
    ipc::write(&mut bytes, message)?;
    String::from_utf8(bytes).context("not UTF-8")
}

fn read(text: &str) -> Result<Option<Message>> {
    ipc::read(&mut Cursor::new(text.as_bytes()))
}

#[test]
fn a_message_is_written_like_a_stanza_of_an_age_header() -> Result<()> {
    ensure!(written(&Message::new("done", &[]))? == "-> done\n\n");
    ensure!(
        written(&Message::with_body("file-key", &["0"], b"YELLOW SUBMARINE"))?
            == "-> file-key 0\nWUVMTE9XIFNVQk1BUklORQ\n"
    );
    // 48 bytes fill a line of 64 columns exactly: an empty line ends the body.
    let full = written(&Message::with_body("msg", &[], &[0; 48]))?;
    ensure!(full == format!("-> msg\n{}\n\n", "A".repeat(64)), "{full}");
    let longer = written(&Message::with_body("msg", &[], &[0; 49]))?;
    ensure!(
        longer == format!("-> msg\n{}\nAA\n", "A".repeat(64)),
        "{longer}"
    );
    Ok(())
}

#[test]
fn messages_round_trip_whatever_their_length() -> Result<()> {
    let mut bytes = Vec::new();
    let lengths = [0_usize, 1, 16, 32, 47, 48, 49, 96, 100, 1120];
    for length in lengths {
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(length).collect();
        ipc::write(
            &mut bytes,
            &Message::with_body("recipient-stanza", &["3", "mlkem768x25519", "abc+/"], &body),
        )?;
    }
    let read = support::output(&bytes)?;
    ensure!(read.len() == lengths.len());
    for (message, length) in read.iter().zip(lengths) {
        ensure!(message.tag == "recipient-stanza");
        ensure!(message.arguments == ["3", "mlkem768x25519", "abc+/"]);
        ensure!(message.body.len() == length, "{length}");
    }
    Ok(())
}

#[test]
fn the_end_of_the_input_is_no_message() -> Result<()> {
    ensure!(read("")?.is_none());
    let mut both = Cursor::new(b"-> ok\n\n".to_vec());
    ensure!(ipc::read(&mut both)?.is_some());
    ensure!(ipc::read(&mut both)?.is_none());
    Ok(())
}

#[test]
fn what_isnt_a_stanza_is_refused() {
    let full_line = "A".repeat(64);
    let cases = [
        ("no arrow", "ok\n\n".to_owned()),
        ("no space after the arrow", "->ok\n\n".to_owned()),
        ("no tag", "-> \n\n".to_owned()),
        ("an empty argument", "-> ok  x\n\n".to_owned()),
        ("ends in the first line", "-> ok".to_owned()),
        ("ends before the body", "-> ok\n".to_owned()),
        ("ends after a full line", format!("-> msg\n{full_line}\n")),
        (
            "a body line of 65 columns",
            format!("-> msg\n{full_line}A\n\n"),
        ),
        ("padded base64", "-> msg\nQQ==\n".to_owned()),
        ("not base64", "-> msg\n!!!!\n".to_owned()),
        // `QR` decodes to one byte and leaves bits set that mean nothing.
        ("trailing bits", "-> msg\nQR\n".to_owned()),
        ("a control character", "-> ok\t\n\n".to_owned()),
        ("not ASCII", "-> ök\n\n".to_owned()),
        ("a carriage return", "-> ok\r\n\r\n".to_owned()),
    ];
    for (what, text) in cases {
        assert!(read(&text).is_err(), "{what} accepted");
    }
}

#[test]
fn very_long_lines_and_bodies_are_refused() {
    let long_line = format!("-> ok {}\n\n", "a".repeat(70_000));
    assert!(read(&long_line).is_err(), "a line of 70 kB");
    let lines = format!("{}\n", "A".repeat(64)).repeat(3000);
    assert!(
        read(&format!("-> msg\n{lines}\n")).is_err(),
        "a body of 190 kB"
    );
}

#[test]
fn only_words_can_be_written() -> Result<()> {
    let mut sink = Vec::new();
    for arguments in [&["two words"][..], &[""], &["line\nbreak"], &["tab\t"]] {
        ensure!(
            ipc::write(&mut sink, &Message::new("ok", arguments)).is_err(),
            "{arguments:?}"
        );
    }
    ensure!(ipc::write(&mut sink, &Message::new("", &[])).is_err());
    ensure!(sink.is_empty(), "something was written anyway");
    Ok(())
}

#[test]
fn telling_expects_ok_and_asking_takes_any_answer() -> Result<()> {
    let command = Message::new("labels", &["postquantum"]);
    let mut out = Vec::new();
    ipc::tell(&mut Cursor::new(b"-> ok\n\n".to_vec()), &mut out, &command)?;
    ensure!(out == b"-> labels postquantum\n\n");

    ensure!(
        ipc::tell(
            &mut Cursor::new(b"-> fail\n\n".to_vec()),
            &mut Vec::new(),
            &command
        )
        .is_err()
    );
    ensure!(ipc::tell(&mut Cursor::new(Vec::new()), &mut Vec::new(), &command).is_err());
    let answer = ipc::ask(
        &mut Cursor::new(b"-> fail\n\n".to_vec()),
        &mut Vec::new(),
        &command,
    )?;
    ensure!(answer.tag == "fail");
    Ok(())
}

/// What the client answers to `request-secret` for `secret`: `ok` with the
/// secret as its body.
fn answer(secret: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ipc::write(&mut bytes, &Message::with_body("ok", &[], secret))?;
    Ok(bytes)
}

fn request(client: Vec<u8>, max_bytes: usize) -> Result<(Secret, Vec<Message>, Cursor<Vec<u8>>)> {
    let mut input = Cursor::new(client);
    let mut out = Vec::new();
    let secret = ipc::request_secret(&mut input, &mut out, "PIN of the key", max_bytes)?;
    Ok((secret, support::output(&out)?, input))
}

#[test]
fn a_secret_is_asked_for_with_its_prompt_and_comes_back_whole() -> Result<()> {
    // Shorter than a line, a line exactly, and more than one.
    for length in [0_usize, 1, 4, 6, 47, 48, 49, 63, 96, 100] {
        let typed: Vec<u8> = (b'0'..=b'9').cycle().take(length).collect();
        let (secret, asked, _) = request(answer(&typed)?, 128)?;
        let Secret::Given(secret) = secret else {
            bail!("{length} bytes: {secret:?}");
        };
        ensure!(secret.expose() == typed, "{length} bytes");
        let [asked] = asked.as_slice() else {
            bail!("asked {} times", asked.len());
        };
        ensure!(asked.tag == "request-secret" && asked.arguments.is_empty());
        ensure!(*asked.body == *b"PIN of the key");
    }
    Ok(())
}

#[test]
fn a_secret_that_is_too_long_is_read_to_its_end_and_dropped() -> Result<()> {
    // The next message is read from where the secret ended.
    let mut client = answer(&[b'7'; 200])?;
    client.extend_from_slice(b"-> ok\n\n");
    let (secret, _, mut input) = request(client, 63)?;
    ensure!(matches!(secret, Secret::TooLong), "{secret:?}");
    let next = ipc::read(&mut input)?.context("the next message")?;
    ensure!(next.tag == "ok" && next.body.is_empty());
    // One byte too many is too many.
    let (secret, _, _) = request(answer(&[b'7'; 64])?, 63)?;
    ensure!(matches!(secret, Secret::TooLong), "{secret:?}");
    let (secret, _, _) = request(answer(&[b'7'; 63])?, 63)?;
    ensure!(matches!(secret, Secret::Given(_)), "{secret:?}");
    Ok(())
}

#[test]
fn a_client_that_cant_ask_or_a_user_who_cancels_gives_no_secret() -> Result<()> {
    let (secret, _, mut input) = request(b"-> fail\n\n-> ok\n\n".to_vec(), 63)?;
    ensure!(matches!(secret, Secret::Refused), "{secret:?}");
    ensure!(ipc::read(&mut input)?.is_some(), "the next message");
    Ok(())
}

#[test]
fn an_answer_that_isnt_a_secret_is_refused_without_repeating_it() {
    let full_line = "A".repeat(64);
    let cases = [
        ("nothing", String::new()),
        ("another answer", "-> done\n\n".to_owned()),
        ("ends before the body", "-> ok\n".to_owned()),
        ("ends after a full line", format!("-> ok\n{full_line}\n")),
        ("a line of 65 columns", format!("-> ok\n{full_line}A\n\n")),
        ("padded base64", "-> ok\nU0VDUkVUMQ==\n".to_owned()),
        ("not base64", "-> ok\nSECRET!!\n".to_owned()),
        ("trailing bits", "-> ok\nU0VDUkVUMR\n".to_owned()),
    ];
    for (what, text) in cases {
        let result = request(text.into_bytes(), 63);
        assert!(result.is_err(), "{what} accepted");
        let said = result
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert!(
            !said.contains("SECRET") && !said.contains("U0VDUkVU"),
            "{what}: {said}"
        );
    }
}

#[test]
fn a_message_for_the_user_takes_ok_and_fail() -> Result<()> {
    for reply in ["-> ok\n\n", "-> fail\n\n"] {
        let mut out = Vec::new();
        ipc::show(
            &mut Cursor::new(reply.as_bytes().to_vec()),
            &mut out,
            "touch the key",
        )?;
        let shown = support::output(&out)?;
        let [shown] = shown.as_slice() else {
            bail!("{} messages", shown.len());
        };
        ensure!(shown.tag == "msg" && *shown.body == *b"touch the key");
    }
    ensure!(ipc::show(&mut Cursor::new(Vec::new()), &mut Vec::new(), "x").is_err());
    Ok(())
}
