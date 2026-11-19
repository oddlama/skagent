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
use zeroize::Zeroizing;

/// Columns of a full line of a stanza's body.
const BODY_COLUMNS: usize = 64;

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
