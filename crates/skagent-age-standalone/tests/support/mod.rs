//! Shared helpers for the integration tests: the age client's side of the
//! plugin protocol, and a security key that isn't one. Every test file is
//! its own crate and uses only part of this module.
#![allow(dead_code)]

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use anyhow::{Context as _, Result};
use skagent_age::{FileKey, Identity, Recipient, STANZA_TYPE, Seed};
use skagent_age_plugin::ipc::{self, Message};
use skagent_age_standalone::key::{Failure, SecurityKey};
use skagent_fido::AgeCredential;
use skagent_secret::SecretBuffer;

/// The PIN of the keys in these tests.
pub const PIN: &[u8] = b"246810";

/// The file key every stanza in these tests wraps.
pub const FILE_KEY: &[u8; 16] = b"YELLOW SUBMARINE";

/// What the age client sends: `messages` one after the other.
pub fn input(messages: &[Message]) -> Result<Cursor<Vec<u8>>> {
    let mut bytes = Vec::new();
    for message in messages {
        ipc::write(&mut bytes, message)?;
    }
    Ok(Cursor::new(bytes))
}

/// The messages the plugin wrote.
pub fn output(bytes: &[u8]) -> Result<Vec<Message>> {
    let mut reader = Cursor::new(bytes);
    let mut messages = Vec::new();
    while let Some(message) = ipc::read(&mut reader)? {
        messages.push(message);
    }
    Ok(messages)
}

/// A message's tag and arguments, as one string.
pub fn head(message: &Message) -> String {
    std::iter::once(message.tag.as_str())
        .chain(message.arguments.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A message's body as text.
pub fn text(message: &Message) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

pub fn ok() -> Message {
    Message::new("ok", &[])
}

pub fn fail() -> Message {
    Message::new("fail", &[])
}

pub fn done() -> Message {
    Message::new("done", &[])
}

/// What the age client answers when the user typed `secret`.
pub fn typed(secret: &[u8]) -> Message {
    Message::with_body("ok", &[], secret)
}

/// `add-identity` as the age client sends it.
pub fn add_identity(identity: &Identity) -> Message {
    Message::new("add-identity", &[&identity.to_string()])
}

/// The recipient of the identity whose credential makes a security key
/// answer with 32 bytes of `answer`.
pub fn recipient(answer: u8) -> Result<Recipient> {
    Seed::from_device_output(&SecretBuffer::from_slice(&[answer; 32])?)?.recipient()
}

/// `recipient-stanza FILE …` for a stanza that wraps [`FILE_KEY`] for
/// `recipient`.
pub fn stanza(recipient: &Recipient, file: &str, randomness: u8) -> Result<Message> {
    let stanza = recipient.wrap(&FileKey::from_bytes(FILE_KEY)?, &[randomness; 64])?;
    Ok(Message::with_body(
        "recipient-stanza",
        &[file, STANZA_TYPE, &stanza.enc_argument()],
        stanza.body(),
    ))
}

/// A security key as its user sees it: a PIN with tries, age credentials,
/// and whether somebody touches it.
#[derive(Debug)]
pub struct Model {
    pub pin: Vec<u8>,
    pub tries: u32,
    pub wrong_in_a_row: u32,
    /// Each credential by the byte its answer is made of, see [`recipient`].
    pub identities: Vec<u8>,
    /// How many of the next derivations nobody touches the key for.
    pub untouched: u32,
    /// What the key was asked for: `tries`, `list`, `derive N`.
    pub asked: Vec<String>,
    /// How often a PIN reached the key, right or wrong.
    pub pins: usize,
}

impl Model {
    /// A key with the PIN [`PIN`], all 8 tries, and `identities`.
    pub fn holding(identities: &[u8]) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            pin: PIN.to_vec(),
            tries: 8,
            wrong_in_a_row: 0,
            identities: identities.to_vec(),
            untouched: 0,
            asked: Vec::new(),
            pins: 0,
        }))
    }

    /// What a key does with a PIN: a wrong one costs a try, three wrong
    /// ones in a row block it until it is replugged, a right one sets the
    /// counter back.
    fn check(&mut self, pin: &SecretBuffer) -> Result<(), Failure> {
        self.pins = self.pins.saturating_add(1);
        if self.tries == 0 {
            return Err(Failure::PinBlocked);
        }
        if self.wrong_in_a_row >= 3 {
            return Err(Failure::BlockedUntilReplugged);
        }
        if pin.expose() == self.pin {
            self.tries = 8;
            self.wrong_in_a_row = 0;
            return Ok(());
        }
        self.tries = self.tries.saturating_sub(1);
        self.wrong_in_a_row = self.wrong_in_a_row.saturating_add(1);
        Err(if self.tries == 0 {
            Failure::PinBlocked
        } else if self.wrong_in_a_row >= 3 {
            Failure::BlockedUntilReplugged
        } else {
            Failure::WrongPin
        })
    }
}

/// The credential whose answer is made of `answer`.
fn credential(answer: u8) -> Result<AgeCredential, Failure> {
    AgeCredential::new(vec![answer]).map_err(Failure::Other)
}

/// A [`Model`] as the flow asks it.
#[derive(Debug)]
pub struct FakeKey {
    pub name: String,
    pub model: Rc<RefCell<Model>>,
}

impl FakeKey {
    pub fn of(model: &Rc<RefCell<Model>>) -> Self {
        Self {
            name: "YubiKey 12345678".to_owned(),
            model: Rc::clone(model),
        }
    }
}

impl SecurityKey for FakeKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn tries_left(&mut self) -> Result<u32> {
        let mut model = self.model.borrow_mut();
        model.asked.push("tries".to_owned());
        Ok(model.tries)
    }

    fn credentials(&mut self, pin: &SecretBuffer) -> Result<Vec<AgeCredential>, Failure> {
        let mut model = self.model.borrow_mut();
        model.asked.push("list".to_owned());
        model.check(pin)?;
        model.identities.iter().copied().map(credential).collect()
    }

    fn derive(
        &mut self,
        credential: &AgeCredential,
        pin: &SecretBuffer,
    ) -> Result<SecretBuffer, Failure> {
        let mut model = self.model.borrow_mut();
        let answer = credential
            .id()
            .first()
            .copied()
            .context("a credential without an id")
            .map_err(Failure::Other)?;
        model.asked.push(format!("derive {answer}"));
        model.check(pin)?;
        if model.untouched > 0 {
            model.untouched = model.untouched.saturating_sub(1);
            return Err(Failure::NotTouched);
        }
        SecretBuffer::from_slice(&[answer; 32]).map_err(Failure::Other)
    }
}
