//! A minimal Assuan client for pinentry, the PIN dialog GnuPG uses.
//!
//! Every byte read from pinentry goes into locked memory: the PIN arrives in
//! a `D` line, and reading line by line through a normal `BufReader` would
//! leave it in an unlocked heap buffer. Pinentry exchanges are a few hundred
//! bytes, so reading one byte at a time costs nothing noticeable.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context as _, Result, anyhow, bail};
use skagent_secret::SecretBuffer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{ChildStdin, ChildStdout, Command};
use zeroize::Zeroize as _;

/// Longest Assuan line, without the newline (Assuan spec).
const MAX_LINE: usize = 1000;

/// Longest decoded `GETPIN` answer accepted. pinentry has no notion of FIDO
/// PIN limits; the caller checks the PIN itself.
const MAX_ANSWER: usize = 256;

/// What to show in the dialog.
#[derive(Debug, Clone, Copy)]
pub struct Dialog<'a> {
    /// Window title.
    pub title: &'a str,
    /// The longer text; may contain newlines.
    pub description: &'a str,
    /// Label in front of the input field.
    pub prompt: &'a str,
    /// Shown as an error, e.g. after a wrong PIN.
    pub error: Option<&'a str>,
}

/// Runs a pinentry program.
#[derive(Debug, Clone)]
pub struct Pinentry {
    program: PathBuf,
}

impl Pinentry {
    /// Uses `program`, e.g. `pinentry` from `PATH` or `pinentry-gnome3`.
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    /// The pinentry program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Shows `dialog` and returns what the user typed.
    ///
    /// # Errors
    ///
    /// Returns an error if pinentry can't be started, the user cancels, or
    /// pinentry doesn't speak the protocol.
    pub async fn get_pin(&self, dialog: &Dialog<'_>) -> Result<SecretBuffer> {
        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // A client that disconnects drops the request, and with it the dialog.
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting pinentry program {}", self.program.display()))?;
        let mut session = Session {
            stdin: child.stdin.take().context("pinentry has no stdin")?,
            stdout: child.stdout.take().context("pinentry has no stdout")?,
            line: SecretBuffer::with_capacity(MAX_LINE)?,
        };

        let answer = session
            .converse(dialog)
            .await
            .with_context(|| format!("talking to pinentry program {}", self.program.display()));
        // Best effort: pinentry quits on BYE or when its stdin closes.
        let _bye = session.stdin.write_all(b"BYE\n").await;
        drop(session);
        let _exited = child.wait().await;
        answer
    }
}

struct Session {
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// The current line, reused for every line.
    line: SecretBuffer,
}

/// Classified response line.
enum Response {
    Ok,
    Err(String),
    Data,
    /// Comments (`#`) and status lines (`S`).
    Ignored,
    Unexpected(String),
}

impl Session {
    async fn converse(&mut self, dialog: &Dialog<'_>) -> Result<SecretBuffer> {
        match self.read_response().await? {
            Response::Ok => {}
            Response::Err(message) => bail!("pinentry refused to start: {message}"),
            _ => bail!("pinentry didn't greet with OK"),
        }
        self.command("SETTITLE", dialog.title).await?;
        self.command("SETDESC", dialog.description).await?;
        self.command("SETPROMPT", dialog.prompt).await?;
        if let Some(error) = dialog.error {
            self.command("SETERROR", error).await?;
        }

        self.send("GETPIN", None).await?;
        let mut answer = SecretBuffer::with_capacity(MAX_ANSWER)?;
        loop {
            match self.read_response().await? {
                Response::Data => decode_data(self.line.expose(), &mut answer)?,
                Response::Ok => return Ok(answer),
                Response::Err(message) => bail!("the PIN dialog was cancelled ({message})"),
                Response::Ignored => {}
                Response::Unexpected(line) => bail!("unexpected answer to GETPIN: {line}"),
            }
        }
    }

    async fn command(&mut self, command: &str, argument: &str) -> Result<()> {
        self.send(command, Some(argument)).await?;
        loop {
            match self.read_response().await? {
                Response::Ok => return Ok(()),
                Response::Err(message) => bail!("pinentry refused {command}: {message}"),
                Response::Ignored => {}
                Response::Data | Response::Unexpected(_) => bail!("unexpected answer to {command}"),
            }
        }
    }

    async fn send(&mut self, command: &str, argument: Option<&str>) -> Result<()> {
        let mut line = command.to_owned();
        if let Some(argument) = argument {
            line.push(' ');
            line.push_str(&escape(argument));
        }
        if line.len() > MAX_LINE {
            bail!("{command} is longer than an Assuan line may be");
        }
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .with_context(|| format!("sending {command}"))
    }

    /// Reads one line into `self.line` and classifies it.
    async fn read_response(&mut self) -> Result<Response> {
        self.line.clear();
        loop {
            let mut byte = [0_u8; 1];
            let count = self
                .stdout
                .read(&mut byte)
                .await
                .context("reading from pinentry")?;
            if count == 0 {
                bail!("pinentry closed the connection");
            }
            if byte == *b"\n" {
                break;
            }
            self.line
                .extend_from_slice(&byte)
                .map_err(|_| anyhow!("pinentry sent a line longer than {MAX_LINE} bytes"))?;
            // A dead store would be optimized away; zeroize writes volatile.
            byte.zeroize();
        }
        let line = self.line.expose();
        Ok(if line == b"OK" || line.starts_with(b"OK ") {
            Response::Ok
        } else if line.starts_with(b"ERR") {
            Response::Err(String::from_utf8_lossy(line).into_owned())
        } else if line.starts_with(b"D ") {
            Response::Data
        } else if line.starts_with(b"#") || line.starts_with(b"S ") || line == b"S" {
            Response::Ignored
        } else {
            // Not a data line, so it holds no secret.
            Response::Unexpected(String::from_utf8_lossy(line).into_owned())
        })
    }
}

/// Assuan escaping for command arguments: `%`, CR and LF become `%25`,
/// `%0D` and `%0A`.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            '\r' => escaped.push_str("%0D"),
            '\n' => escaped.push_str("%0A"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Appends the percent-decoded payload of a `D ` line to `answer`.
///
/// # Errors
///
/// Returns an error for malformed escapes or if `answer` is full. The
/// message never contains the data.
pub fn decode_data(line: &[u8], answer: &mut SecretBuffer) -> Result<()> {
    let payload = line.strip_prefix(b"D ").context("not a data line")?;
    let mut bytes = payload.iter();
    while let Some(&byte) = bytes.next() {
        let decoded = if byte == b'%' {
            let (Some(&high), Some(&low)) = (bytes.next(), bytes.next()) else {
                bail!("truncated percent escape in pinentry data");
            };
            let (Some(high), Some(low)) = (hex_value(high), hex_value(low)) else {
                bail!("invalid percent escape in pinentry data");
            };
            high.checked_mul(16)
                .and_then(|value| value.checked_add(low))
                .context("percent escape out of range")?
        } else {
            byte
        };
        answer
            .extend_from_slice(&[decoded])
            .map_err(|_| anyhow!("pinentry answer longer than {MAX_ANSWER} bytes"))?;
    }
    Ok(())
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit
            .checked_sub(b'a')
            .and_then(|value| value.checked_add(10)),
        b'A'..=b'F' => digit
            .checked_sub(b'A')
            .and_then(|value| value.checked_add(10)),
        _ => None,
    }
}
