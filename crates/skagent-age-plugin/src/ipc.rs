//! The plugin protocol's messages: age stanzas, in the text format of an
//! age header, over the plugin's standard input and output.
//!
//! ```text
//! -> command argument argument
//! Base64(data), in lines of 64 columns, the last one shorter
//! ```

use std::io::{BufRead, Write};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use skagent_secret::SecretBuffer;
use zeroize::Zeroizing;

/// Columns of a full line of a stanza's body.
const BODY_COLUMNS: usize = 64;

/// Bytes a full line of a stanza's body decodes to.
const BODY_LINE_BYTES: usize = 48;

/// Longest line read. An identity of ours is under 2000 characters, as is a
/// stanza's first line with its encapsulated key.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Largest body read, decoded.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// One message: a command or a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The command, or the kind of response.
    pub tag: String,
    /// What follows it on the first line.
    pub arguments: Vec<String>,
    /// The decoded data. It may be a file key, so it is wiped when dropped.
    pub body: Zeroizing<Vec<u8>>,
}

impl Message {
    /// A message without data.
    #[must_use]
    pub fn new(tag: &str, arguments: &[&str]) -> Self {
        Self::with_body(tag, arguments, &[])
    }

    /// A message with data.
    #[must_use]
    pub fn with_body(tag: &str, arguments: &[&str], body: &[u8]) -> Self {
        Self {
            tag: tag.to_owned(),
            arguments: arguments
                .iter()
                .map(|&argument| argument.to_owned())
                .collect(),
            body: Zeroizing::new(body.to_vec()),
        }
    }
}

/// Reads one line without its newline; `None` at the end of the input.
fn read_line(input: &mut impl BufRead) -> Result<Option<Zeroizing<String>>> {
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let available = input.fill_buf().context("reading from the age client")?;
        if available.is_empty() {
            ensure!(
                line.is_empty(),
                "the age client's input ends in the middle of a line"
            );
            return Ok(None);
        }
        let (taken, done) = match available.iter().position(|&byte| byte == b'\n') {
            Some(newline) => (newline.saturating_add(1), true),
            None => (available.len(), false),
        };
        let chunk = available.get(..taken).context("a line beyond the buffer")?;
        ensure!(
            line.len().saturating_add(chunk.len()) <= MAX_LINE_BYTES,
            "a line of more than {MAX_LINE_BYTES} bytes from the age client"
        );
        line.extend_from_slice(chunk);
        input.consume(taken);
        if done {
            line.pop();
            let text = std::str::from_utf8(&line)
                .ok()
                .filter(|text| text.bytes().all(|byte| (0x20..0x7f).contains(&byte)))
                .context("a line from the age client isn't printable ASCII")?;
            return Ok(Some(Zeroizing::new(text.to_owned())));
        }
    }
}

/// Reads one message; `None` at the end of the input.
///
/// # Errors
///
/// Returns an error for anything that isn't a stanza as the age format
/// writes it: a first line `-> tag arguments…`, then the body in canonical
/// unpadded base64, in full lines of 64 columns and one shorter line.
pub fn read(input: &mut impl BufRead) -> Result<Option<Message>> {
    let Some(first) = read_line(input)? else {
        return Ok(None);
    };
    let Some(words) = first.strip_prefix("-> ") else {
        bail!("the age client sent something that isn't a stanza");
    };
    let mut words = words.split(' ');
    let tag = words.next().unwrap_or_default().to_owned();
    let arguments: Vec<String> = words.map(str::to_owned).collect();
    ensure!(
        !tag.is_empty() && arguments.iter().all(|argument| !argument.is_empty()),
        "a stanza with an empty tag or argument"
    );

    let mut encoded = Zeroizing::new(String::new());
    loop {
        let line = read_line(input)?.context("the age client's input ends inside a stanza")?;
        ensure!(
            line.len() <= BODY_COLUMNS,
            "a body line of more than {BODY_COLUMNS} columns"
        );
        ensure!(
            encoded.len().saturating_add(line.len()) <= MAX_BODY_BYTES.saturating_mul(2),
            "a stanza body of more than {MAX_BODY_BYTES} bytes"
        );
        encoded.push_str(&line);
        if line.len() < BODY_COLUMNS {
            break;
        }
    }
    let body = STANDARD_NO_PAD
        .decode(encoded.as_bytes())
        .ok()
        .context("a stanza body isn't canonical base64")?;
    Ok(Some(Message {
        tag,
        arguments,
        body: Zeroizing::new(body),
    }))
}

/// Writes one message and flushes, so the age client sees it.
///
/// # Errors
///
/// Returns an error if the output fails, or the message has a tag or an
/// argument that can't be written (empty, or with a space or a control
/// character).
pub fn write(output: &mut impl Write, message: &Message) -> Result<()> {
    let writable =
        |word: &str| !word.is_empty() && word.bytes().all(|byte| (0x21..0x7f).contains(&byte));
    ensure!(
        writable(&message.tag) && message.arguments.iter().all(|argument| writable(argument)),
        "a message with a tag or an argument that can't be written"
    );
    let mut text = Zeroizing::new(format!("-> {}", message.tag));
    for argument in &message.arguments {
        text.push(' ');
        text.push_str(argument);
    }
    text.push('\n');
    let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(&*message.body));
    let mut rest = encoded.as_str();
    // Full lines, then one that is shorter: empty if the data ends on a line.
    while let Some((line, tail)) = rest.split_at_checked(BODY_COLUMNS) {
        text.push_str(line);
        text.push('\n');
        rest = tail;
    }
    text.push_str(rest);
    text.push('\n');
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .context("writing to the age client")
}

/// Sends `command` and reads the age client's response to it.
///
/// # Errors
///
/// Returns an error if writing or reading fails, or the client answers
/// nothing.
pub fn ask(
    input: &mut impl BufRead,
    output: &mut impl Write,
    command: &Message,
) -> Result<Message> {
    write(output, command)?;
    read(input)?.context("the age client closed its side instead of answering")
}

/// Sends `command`, to which the age client answers `ok`.
///
/// # Errors
///
/// Returns an error if writing or reading fails, or the client answers
/// anything else.
pub fn tell(input: &mut impl BufRead, output: &mut impl Write, command: &Message) -> Result<()> {
    let response = ask(input, output, command)?;
    ensure!(
        response.tag == "ok",
        "the age client answered {:?} to {:?}",
        response.tag,
        command.tag
    );
    Ok(())
}

/// Shows `text` to whoever runs the age client (`msg`). A client with
/// nowhere to show it answers `fail`, which is no error.
///
/// # Errors
///
/// Returns an error if writing or reading fails, or the client answers
/// nothing.
pub fn show(input: &mut impl BufRead, output: &mut impl Write, text: &str) -> Result<()> {
    ask(
        input,
        output,
        &Message::with_body("msg", &[], text.as_bytes()),
    )
    .map(|_answer| ())
}

/// What the age client answered when it was asked for a secret.
#[derive(Debug)]
pub enum Secret {
    /// What the user typed, in locked memory.
    Given(SecretBuffer),
    /// More bytes than were asked for at most. They were read to their end
    /// and kept nowhere.
    TooLong,
    /// The client has nobody to ask, or the user cancelled (`fail`).
    Refused,
}

/// Reads one line of a stanza's body into `line`, without its newline, and
/// returns its length. Nothing of it goes to the heap.
fn read_body_line(input: &mut impl BufRead, line: &mut [u8; BODY_COLUMNS]) -> Result<usize> {
    let mut length = 0_usize;
    loop {
        let available = input.fill_buf().context("reading from the age client")?;
        ensure!(
            !available.is_empty(),
            "the age client's input ends inside a stanza"
        );
        let (taken, done) = match available.iter().position(|&byte| byte == b'\n') {
            Some(newline) => (newline, true),
            None => (available.len(), false),
        };
        let end = length
            .checked_add(taken)
            .filter(|&end| end <= BODY_COLUMNS)
            .with_context(|| format!("a body line of more than {BODY_COLUMNS} columns"))?;
        let chunk = available.get(..taken).context("a line beyond the buffer")?;
        line.get_mut(length..end)
            .context("a line beyond its buffer")?
            .copy_from_slice(chunk);
        length = end;
        // With its newline, if the line ends here.
        input.consume(taken.saturating_add(usize::from(done)));
        if done {
            return Ok(length);
        }
    }
}

/// Asks the age client for a secret, a PIN for one (`request-secret`): the
/// client shows `prompt` and answers what the user typed.
///
/// The answer goes from the client's lines into locked memory, at most
/// `max_bytes` of it, a line at a time through buffers on the stack that
/// are wiped: no copy of it is left on the heap by this function. What
/// `input` keeps of the lines it handed out is `input`'s; a reader that
/// wipes what was consumed keeps nothing.
///
/// # Errors
///
/// Returns an error if writing or reading fails, the client answers
/// anything but `ok` or `fail`, the answer isn't canonical base64, or locked
/// memory can't be had. No error carries any of the answer.
pub fn request_secret(
    input: &mut impl BufRead,
    output: &mut impl Write,
    prompt: &str,
    max_bytes: usize,
) -> Result<Secret> {
    write(
        output,
        &Message::with_body("request-secret", &[], prompt.as_bytes()),
    )?;
    let first = read_line(input)?.context("the age client closed its side instead of answering")?;
    let given = match first.as_str() {
        "-> ok" => true,
        "-> fail" => false,
        _ => bail!("the age client answered neither `ok` nor `fail` when asked for a secret"),
    };
    let mut secret = SecretBuffer::with_capacity(max_bytes)
        .context("locked memory for the age client's answer")?;
    let mut too_long = false;
    loop {
        let mut line = Zeroizing::new([0_u8; BODY_COLUMNS]);
        let length = read_body_line(input, &mut line)?;
        let encoded = line.get(..length).context("a line beyond its buffer")?;
        let mut decoded = Zeroizing::new([0_u8; BODY_LINE_BYTES]);
        // Full lines are 64 columns, so each decodes by itself.
        let count = STANDARD_NO_PAD
            .decode_slice(encoded, decoded.as_mut_slice())
            .ok()
            .context("the age client's answer isn't canonical base64")?;
        let bytes = decoded.get(..count).context("more bytes than a line has")?;
        if !too_long && secret.extend_from_slice(bytes).is_err() {
            too_long = true;
            secret.clear();
        }
        if length < BODY_COLUMNS {
            break;
        }
    }
    Ok(match (given, too_long) {
        (false, _) => Secret::Refused,
        (true, true) => Secret::TooLong,
        (true, false) => Secret::Given(secret),
    })
}
