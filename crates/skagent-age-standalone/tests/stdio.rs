//! The reader the age client's lines come through keeps nothing of them.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::{BufRead as _, Cursor, Read as _};

use anyhow::{Result, ensure};
use skagent_age_plugin::ipc::{self, Message, Secret};
use skagent_age_standalone::stdio::ClientInput;

fn holds(input: &ClientInput<Cursor<Vec<u8>>>, needle: &[u8]) -> bool {
    input
        .buffer()
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn what_was_consumed_is_wiped() -> Result<()> {
    let mut input = ClientInput::new(Cursor::new(b"first line\nsecond line\n".to_vec()));
    ensure!(input.fill_buf()? == b"first line\nsecond line\n");
    ensure!(holds(&input, b"first line"));
    input.consume(11);
    ensure!(!holds(&input, b"first") && holds(&input, b"second line"));
    ensure!(input.fill_buf()? == b"second line\n");
    // Reading consumes too.
    let mut rest = Vec::new();
    input.read_to_end(&mut rest)?;
    ensure!(rest == b"second line\n");
    ensure!(input.buffer().iter().all(|&byte| byte == 0));
    // More than there is consumes what there is.
    let mut input = ClientInput::new(Cursor::new(b"abc".to_vec()));
    input.fill_buf()?;
    input.consume(100);
    ensure!(input.fill_buf()?.is_empty());
    Ok(())
}

#[test]
fn input_longer_than_the_buffer_comes_through_whole() -> Result<()> {
    let sent: Vec<u8> = (0..=u8::MAX).cycle().take(20_000).collect();
    let mut input = ClientInput::new(Cursor::new(sent.clone()));
    let mut read = Vec::new();
    input.read_to_end(&mut read)?;
    ensure!(read == sent);
    Ok(())
}

/// A PIN on its way from the age client into locked memory: once it is
/// there, the reader has none of it, neither as typed nor as sent.
#[test]
fn a_pin_that_was_read_is_nowhere_in_the_reader() -> Result<()> {
    let pin = b"correct horse battery staple, and more than one line of it";
    let mut sent = Vec::new();
    ipc::write(&mut sent, &Message::with_body("ok", &[], pin))?;
    ipc::write(&mut sent, &Message::new("ok", &[]))?;
    let encoded = sent.get(6..30).map(<[u8]>::to_vec).unwrap_or_default();
    ensure!(encoded.len() == 24);

    let mut input = ClientInput::new(Cursor::new(sent));
    let secret = ipc::request_secret(&mut input, &mut Vec::new(), "PIN", 63)?;
    let Secret::Given(secret) = secret else {
        anyhow::bail!("{secret:?}");
    };
    ensure!(secret.expose() == pin);
    ensure!(!holds(&input, &encoded), "the PIN's base64 is still there");
    ensure!(!holds(&input, b"correct horse"));
    // What follows is still to be read.
    ensure!(ipc::read(&mut input)?.is_some());
    Ok(())
}
