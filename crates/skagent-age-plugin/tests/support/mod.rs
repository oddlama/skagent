//! Shared helpers for the integration tests: the age client's side of the
//! plugin protocol, and an agent that answers from a script. Every test file
//! is its own crate and uses only part of this module.
#![allow(dead_code)]

use std::io::Cursor;

use anyhow::{Context as _, Result, bail};
use skagent_age::wire::{UnwrapReply, UnwrapRequest};
use skagent_age::{FileKey, Recipient, Seed};
use skagent_age_plugin::agent::Unwrap;
use skagent_age_plugin::ipc::{self, Message};

/// A seed whose bytes are all `byte`, and its recipient.
pub fn identity(byte: u8) -> Result<(Seed, Recipient)> {
    let seed = Seed::from_bytes(&[byte; 32])?;
    let recipient = seed.recipient()?;
    Ok((seed, recipient))
}

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

pub fn ok() -> Message {
    Message::new("ok", &[])
}

pub fn done() -> Message {
    Message::new("done", &[])
}

/// What an agent in a test answers to one request.
pub enum Scripted {
    Reply(UnwrapReply),
    /// Calls `waiting` this many times, 300 ms apart, then answers.
    Slow(u32, UnwrapReply),
    /// The agent can't be reached.
    Unreachable,
}

/// An agent that answers from a script and keeps what it was asked.
#[derive(Default)]
pub struct ScriptedAgent {
    pub script: Vec<Scripted>,
    pub asked: Vec<UnwrapRequest>,
}

impl ScriptedAgent {
    pub fn answering(script: Vec<Scripted>) -> Self {
        Self {
            script,
            asked: Vec::new(),
        }
    }
}

impl Unwrap for ScriptedAgent {
    fn unwrap(
        &mut self,
        request: &UnwrapRequest,
        waiting: &mut dyn FnMut() -> Result<()>,
    ) -> Result<UnwrapReply> {
        self.asked.push(request.clone());
        if self.script.is_empty() {
            bail!("the agent was asked more often than the test expects");
        }
        match self.script.remove(0) {
            Scripted::Reply(reply) => Ok(reply),
            Scripted::Slow(times, reply) => {
                for _ in 0..times {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    waiting()?;
                }
                Ok(reply)
            }
            Scripted::Unreachable => bail!("no agent"),
        }
    }
}

pub fn file_key(text: &[u8; 16]) -> Result<UnwrapReply> {
    Ok(UnwrapReply::FileKey(
        FileKey::from_bytes(text).context("file key")?,
    ))
}
