//! `skagent batch`: runs a command whose age decryptions take one touch
//! together.
//!
//! The tool asks the agent for a batch on a connection it keeps until the
//! command is done, and runs the command as its child. The agent takes the
//! processes that descend from the tool for the batch's members
//! ([`crate::ancestry`]). So that this holds for what the command leaves
//! behind as well, the tool is a child subreaper: a process whose parent
//! exits is handed to it, not to the service manager.
//!
//! The tool holds nothing secret. It stays dumpable, because the agent
//! recognizes it by its executable, and sets no limits, because the command
//! would inherit them.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use rustix::process::{
    Pid, Signal, WaitOptions, WaitStatus, getpid, kill_process, set_child_subreaper, wait,
};
use skagent_age::wire::MAX_COMMAND_BYTES;
use tokio::signal::unix::{SignalKind, signal};

use crate::{client, output};

/// The environment variable that tells skagent's programs where the agent
/// listens for age requests.
pub const AGE_SOCKET_VARIABLE: &str = "SKAGENT_AGE_SOCKET";

/// Exit code if the command can't be run, like `env` and shells have it.
const CANNOT_RUN: u8 = 126;

/// Exit code if the command isn't found.
const NOT_FOUND: u8 = 127;

/// `command` as the agent shows it with the batch's first prompt: its
/// words, cut to what the request carries.
#[must_use]
pub fn shown_command(command: &[OsString]) -> String {
    let joined = command
        .iter()
        .map(|word| word.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let mut shown = String::new();
    for character in joined.chars() {
        if shown.len().saturating_add(character.len_utf8()) > MAX_COMMAND_BYTES {
            break;
        }
        shown.push(character);
    }
    shown
}

/// What the tool exits with for a command that exited with `code`, or was
/// ended by `signal`: the command's own code, or 128 plus the signal, as
/// shells have it.
#[must_use]
pub fn exit_code(code: Option<i32>, signal: Option<i32>) -> u8 {
    let code = match (code, signal) {
        (Some(code), _) => code,
        (None, Some(signal)) => signal.saturating_add(128),
        (None, None) => 1,
    };
    u8::try_from(code & 0xff).unwrap_or(1)
}

/// Runs `command` in a batch of the agent listening at `socket`, lasting
/// `lasting` at most (`None`: as long as the agent allows), and returns
/// the command's exit code.
///
/// # Errors
///
/// Returns an error if the agent can't be reached or opens no batch, or
/// the command can't be waited for. A command that can't be run is no
/// error: the tool says so and exits like `env` does.
pub async fn run(
    socket: &Path,
    lasting: Option<Duration>,
    command: &[OsString],
) -> Result<ExitCode> {
    let (program, arguments) = command.split_first().context("no command to run")?;
    set_child_subreaper(Some(getpid()))
        .context("becoming a child subreaper (prctl PR_SET_CHILD_SUBREAPER)")?;
    // Before the command runs, so that no exit is missed.
    let mut exits = signal(SignalKind::child()).context("installing the SIGCHLD handler")?;
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut hangup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut quit = signal(SignalKind::quit()).context("installing the SIGQUIT handler")?;

    // Kept until the command is done: the batch lasts as long as it.
    let batch = client::open_batch(socket, lasting, &shown_command(command)).await?;
    tracing::debug!(
        seconds = batch.lasts().as_secs(),
        "the agent opened a batch"
    );

    let child = Command::new(program)
        .args(arguments)
        // The agent this batch is with, whatever the command would find.
        .env(AGE_SOCKET_VARIABLE, socket)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::NotFound {
                NOT_FOUND
            } else {
                CANNOT_RUN
            };
            // If stderr is gone, the exit code still says it.
            let _ignored = writeln!(
                io::stderr(),
                "{} can't run {}: {error}",
                output::error_label(),
                Path::new(program).display()
            );
            return Ok(ExitCode::from(code));
        }
    };
    let command_pid = i32::try_from(child.id())
        .ok()
        .and_then(Pid::from_raw)
        .context("the command has no process id")?;
    // Reaped below, with whatever else is handed to this process.
    drop(child);

    let status = loop {
        if let Some(status) = reap(command_pid)? {
            break status;
        }
        tokio::select! {
            _ = exits.recv() => {}
            _ = terminate.recv() => pass_on(command_pid, Signal::TERM),
            _ = hangup.recv() => pass_on(command_pid, Signal::HUP),
            // From the terminal, which sent them to the command as well.
            _ = interrupt.recv() => {}
            _ = quit.recv() => {}
        }
    };
    drop(batch);
    Ok(ExitCode::from(exit_code(
        status.exit_status(),
        status.terminating_signal(),
    )))
}

/// Reaps every child that exited: the command, whose status is returned,
/// and the processes it left behind, which were handed to this one.
fn reap(command: Pid) -> Result<Option<WaitStatus>> {
    loop {
        match wait(WaitOptions::NOHANG) {
            Ok(Some((pid, status))) if pid == command => return Ok(Some(status)),
            Ok(Some(_adopted)) => {}
            Ok(None) => return Ok(None),
            Err(rustix::io::Errno::CHILD) => {
                bail!("the command is gone, and nothing says how it ended")
            }
            Err(error) => return Err(error).context("waiting for the command"),
        }
    }
}

/// Sends the command a signal this process got in its place.
fn pass_on(command: Pid, signal: Signal) {
    if let Err(error) = kill_process(command, signal) {
        tracing::debug!(%error, "passing a signal on to the command failed");
    }
}
