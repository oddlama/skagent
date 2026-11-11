//! The `skagent` binary itself, run as a child process.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};

/// How long a refusing `skagent serve` may take to exit.
const EXIT_WITHIN: Duration = Duration::from_secs(10);

/// libfido2 writes every message to and from the security key to stderr
/// while `FIDO_DEBUG` is set, past the log redaction: the agent won't start.
#[test]
fn serve_refuses_to_start_with_fido_debug() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let socket = dir.path().join("agent.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_skagent"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .env("FIDO_DEBUG", "1")
        .env_remove("LISTEN_PID")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting skagent serve")?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().context("waiting for skagent serve")? {
            break status;
        }
        if started.elapsed() > EXIT_WITHIN {
            child.kill().context("stopping skagent serve")?;
            child.wait().context("reaping skagent serve")?;
            bail!("skagent serve started despite FIDO_DEBUG");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .context("no stderr pipe")?
        .read_to_string(&mut stderr)
        .context("reading stderr")?;
    ensure!(!status.success(), "serve exited successfully: {stderr}");
    ensure!(stderr.contains("FIDO_DEBUG"), "{stderr}");
    ensure!(!socket.exists(), "the socket was created");
    Ok(())
}
