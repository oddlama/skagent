//! Asking the user for the PIN.
//!
//! For now through an askpass program (`--askpass`, `$SSH_ASKPASS`), like
//! OpenSSH's ssh-agent: the program gets the prompt as its only argument and
//! prints the answer on stdout. The answer goes straight into locked memory.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};
use skagent_fido::PIN_MAX_BYTES;
use skagent_secret::SecretBuffer;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use zeroize::Zeroize as _;

/// Shortest valid FIDO PIN.
pub const PIN_MIN_BYTES: usize = 4;

/// Room for the longest PIN plus a `\r\n`.
const ANSWER_CAPACITY: usize = PIN_MAX_BYTES + 2;

/// Runs askpass programs.
#[derive(Debug, Clone)]
pub struct Askpass {
    program: PathBuf,
}

impl Askpass {
    /// Uses `program` for prompts.
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    /// The askpass program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Asks for a FIDO PIN with `prompt`.
    ///
    /// # Errors
    ///
    /// Returns an error if the program can't run, is cancelled (non-zero
    /// exit) or answers with something that isn't a valid PIN.
    pub async fn ask_pin(&self, prompt: &str) -> Result<SecretBuffer> {
        let mut child = Command::new(&self.program)
            .arg(prompt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // A client that disconnects drops the request, and with it the prompt.
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting askpass program {}", self.program.display()))?;
        let mut stdout = child.stdout.take().with_context(|| {
            format!(
                "reading the answer of askpass program {}",
                self.program.display()
            )
        })?;

        let mut answer = SecretBuffer::with_capacity(ANSWER_CAPACITY)?;
        let mut chunk = [0_u8; 64];
        let read = read_into(&mut stdout, &mut chunk, &mut answer).await;
        chunk.zeroize();
        read.with_context(|| {
            format!(
                "reading the answer of askpass program {}",
                self.program.display()
            )
        })?;

        let status = child
            .wait()
            .await
            .with_context(|| format!("waiting for askpass program {}", self.program.display()))?;
        if !status.success() {
            bail!(
                "the PIN prompt was cancelled ({} exited with {status})",
                self.program.display()
            );
        }
        pin_from_answer(&answer)
    }
}

async fn read_into(
    stdout: &mut tokio::process::ChildStdout,
    chunk: &mut [u8; 64],
    answer: &mut SecretBuffer,
) -> Result<()> {
    loop {
        let count = stdout.read(chunk).await.context("reading from the pipe")?;
        if count == 0 {
            return Ok(());
        }
        let Some(bytes) = chunk.get(..count) else {
            bail!("read returned more bytes than the buffer holds");
        };
        answer
            .extend_from_slice(bytes)
            .context("the answer is longer than any valid PIN")?;
    }
}

/// Turns an askpass answer into a PIN: strips one trailing `\n` or `\r\n`
/// and checks the length (4 to 63 bytes).
///
/// # Errors
///
/// Returns an error if the PIN is too short or too long. The message never
/// contains the PIN.
pub fn pin_from_answer(answer: &SecretBuffer) -> Result<SecretBuffer> {
    let bytes = answer.expose();
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.len() < PIN_MIN_BYTES || bytes.len() > PIN_MAX_BYTES {
        bail!(
            "a FIDO PIN has {PIN_MIN_BYTES} to {PIN_MAX_BYTES} bytes, the answer had {}",
            bytes.len()
        );
    }
    SecretBuffer::from_slice(bytes).context("storing the PIN in locked memory")
}
