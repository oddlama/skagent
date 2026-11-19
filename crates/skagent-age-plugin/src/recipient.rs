//! `recipient-v1`: wrapping file keys, for `age -e -i` with an identity of
//! ours. An identity names its recipient, so this needs neither the agent
//! nor the security key: it is what stock age does for the `age1pq1…`
//! recipient, and produces the same stanza.

use std::io::{BufRead, Write};

use anyhow::{Context as _, Result};
use skagent_age::{
    FileKey, Identity, POSTQUANTUM_LABEL, Recipient, STANZA_TYPE, WRAP_RANDOM_BYTES,
};
use zeroize::Zeroizing;

use crate::ipc::{self, Message};

/// What phase 1 collected.
#[derive(Default)]
struct Collected {
    /// How many recipients the client added. We have no recipient type.
    recipients: usize,
    /// Each identity's recipient, or why there is none.
    identities: Vec<Result<Recipient, String>>,
    /// Each file key, or why it isn't one.
    file_keys: Vec<Result<FileKey, String>>,
    /// Whether the client understands labels.
    labels: bool,
}

fn recipient_of(arguments: &[String]) -> Result<Recipient, String> {
    let [identity] = arguments else {
        return Err("add-identity takes one identity".to_owned());
    };
    match identity.parse::<Identity>() {
        Ok(Identity::Named(recipient)) => Ok(recipient),
        Ok(Identity::AtHand) => Err(
            "this identity names no recipient to encrypt to; use the identity file \
             `skagent age identity` writes, or encrypt to the recipient with -r"
                .to_owned(),
        ),
        Err(error) => Err(format!("{error:#}")),
    }
}

fn collect(input: &mut impl BufRead) -> Result<Collected> {
    let mut collected = Collected::default();
    loop {
        let message = ipc::read(input)?.context("the age client stopped before `done`")?;
        match message.tag.as_str() {
            "done" => return Ok(collected),
            "add-recipient" => collected.recipients = collected.recipients.saturating_add(1),
            "add-identity" => collected.identities.push(recipient_of(&message.arguments)),
            "wrap-file-key" => collected
                .file_keys
                .push(FileKey::from_bytes(&message.body).map_err(|error| format!("{error:#}"))),
            "extension-labels" => collected.labels = true,
            // Commands this version doesn't know are ignored in this phase.
            _ => {}
        }
    }
}

/// Runs the state machine: reads the identities and file keys from `input`
/// and writes one stanza per file key and identity to `output`. `random`
/// fills a buffer from the system's generator.
///
/// # Errors
///
/// Returns an error if the age client breaks the protocol or goes away, or
/// randomness can't be had. What can't be wrapped to is told to the client
/// as an `error`, and then nothing is wrapped at all.
pub fn run(
    input: &mut impl BufRead,
    output: &mut impl Write,
    mut random: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<()> {
    let collected = collect(input)?;
    let done = Message::new("done", &[]);
    let mut error = |about: &[&str], reason: &str| {
        ipc::tell(
            input,
            output,
            &Message::with_body("error", about, reason.as_bytes()),
        )
    };

    let mut failed = false;
    for position in 0..collected.recipients {
        failed = true;
        error(
            &["recipient", &position.to_string()],
            "skagent's plugin has no recipient type of its own; a skagent identity's recipient \
             is a native age1pq1… one",
        )?;
    }
    let mut recipients = Vec::new();
    for (position, identity) in collected.identities.into_iter().enumerate() {
        match identity {
            Ok(recipient) => recipients.push(recipient),
            Err(reason) => {
                failed = true;
                error(&["identity", &position.to_string()], &reason)?;
            }
        }
    }
    let mut file_keys = Vec::new();
    for file_key in collected.file_keys {
        match file_key {
            Ok(file_key) => file_keys.push(file_key),
            Err(reason) => {
                failed = true;
                error(&["internal"], &reason)?;
            }
        }
    }
    if failed {
        return ipc::write(output, &done);
    }

    if collected.labels {
        // The stanzas are post-quantum: the client must not put them into a
        // file next to a classic recipient's.
        ipc::tell(input, output, &Message::new("labels", &[POSTQUANTUM_LABEL]))?;
    }
    for (index, file_key) in file_keys.iter().enumerate() {
        for recipient in &recipients {
            let mut randomness = Zeroizing::new([0_u8; WRAP_RANDOM_BYTES]);
            random(&mut *randomness)?;
            let stanza = recipient.wrap(file_key, &randomness)?;
            let enc = stanza.enc_argument();
            let command = Message::with_body(
                "recipient-stanza",
                &[&index.to_string(), STANZA_TYPE, &enc],
                stanza.body(),
            );
            ipc::tell(input, output, &command)?;
        }
    }
    ipc::write(output, &done)
}
