//! A child spawned with `inherit_stdio_only` gets no other descriptor, even
//! one opened without close-on-exec.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsRawFd as _;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, ensure};
use rustix::io::{FdFlags, fcntl_setfd};
use skagent_fds::inherit_stdio_only;

/// Whether a child shell sees descriptor `fd`, and what it printed.
fn child_sees(fd: i32, isolated: bool) -> Result<(bool, String)> {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("echo stdout works; test -e /proc/$$/fd/{fd}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    if isolated {
        inherit_stdio_only(&mut command);
    }
    let output = command.output().context("running /bin/sh")?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

#[test]
fn only_stdio_is_inherited() -> Result<()> {
    // What libfido2 does with /dev/hidraw*: no close-on-exec.
    let file = File::open("/dev/null").context("opening /dev/null")?;
    fcntl_setfd(&file, FdFlags::empty()).context("clearing close-on-exec")?;
    let fd = file.as_raw_fd();

    let (inherited, _) = child_sees(fd, false)?;
    ensure!(inherited, "control: a plain child must inherit fd {fd}");
    let (inherited, stdout) = child_sees(fd, true)?;
    ensure!(!inherited, "fd {fd} leaked into an isolated child");
    ensure!(stdout == "stdout works\n", "stdio broke: {stdout:?}");
    Ok(())
}

#[test]
fn a_failed_exec_is_still_reported() -> Result<()> {
    let mut command = Command::new("/nonexistent/skagent-test-program");
    inherit_stdio_only(&mut command);
    match command.spawn() {
        Ok(mut child) => {
            let status = child.wait();
            anyhow::bail!("spawning a missing program succeeded: {status:?}")
        }
        Err(error) => {
            ensure!(error.kind() == ErrorKind::NotFound, "{error}");
            Ok(())
        }
    }
}
