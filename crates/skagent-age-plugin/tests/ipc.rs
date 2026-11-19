//! The plugin protocol's messages on the wire.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::io::Cursor;

use anyhow::{Context as _, Result, ensure};
use skagent_age_plugin::ipc::{self, Message};

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
