//! The plugin's way to the agent: a unix socket, and one request per file.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use skagent_age::wire::{
    Refusal, UNWRAP_EXTENSION, UnwrapReply, UnwrapRequest, reply_details, reply_length,
    request_frame,
};
use zeroize::Zeroizing;

/// The name of the agent's socket for age requests in `$XDG_RUNTIME_DIR`.
const AGE_SOCKET_NAME: &str = "skagent-age.sock";

/// How often the wait for the agent's reply looks up.
const WAIT_STEP: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};

/// Whoever unwraps file keys for the plugin: the agent, or a test.
pub trait Unwrap {
    /// Asks for the file key of one file. While the answer isn't there,
    /// `waiting` is called every now and then; an error from it ends the
    /// wait, and with it the request.
    ///
    /// # Errors
    ///
    /// Returns an error if nobody can be asked, or `waiting` returned one. A
    /// refusal is a reply.
    fn unwrap(
        &mut self,
        request: &UnwrapRequest,
        waiting: &mut dyn FnMut() -> Result<()>,
    ) -> Result<UnwrapReply>;
}

/// Whether the other end of `pipe` is closed: the age client that started
/// the plugin is gone, and nobody waits for an answer.
#[must_use]
pub fn hung_up(pipe: impl std::os::fd::AsFd) -> bool {
    let mut fds = [PollFd::new(&pipe, PollFlags::empty())];
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut fds, Some(&zero)).is_ok()
        && fds
            .first()
            .is_some_and(|fd| fd.revents().intersects(PollFlags::HUP | PollFlags::ERR))
}

/// A variable's value as a path, unless it is unset or empty.
fn given(value: Option<&OsStr>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// The socket of an agent on this machine: `SKAGENT_AGE_SOCKET` if set;
/// else the agent's socket for age requests in `XDG_RUNTIME_DIR`, if
/// `exists` says it is there. `None` where no agent runs.
#[must_use]
pub fn local_socket(
    age_socket: Option<&OsStr>,
    runtime_dir: Option<&OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    given(age_socket).or_else(|| {
        given(runtime_dir)
            .map(|directory| directory.join(AGE_SOCKET_NAME))
            .filter(|path| exists(path))
    })
}

/// Where the agent is: on this machine ([`local_socket`]), else
/// `SSH_AUTH_SOCK`, which on a remote host is an agent forwarded from the
/// machine that runs skagent.
///
/// # Errors
///
/// Returns an error if none of them names a socket.
pub fn socket_path(
    age_socket: Option<&OsStr>,
    runtime_dir: Option<&OsStr>,
    ssh_auth_sock: Option<&OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> Result<PathBuf> {
    if let Some(path) = local_socket(age_socket, runtime_dir, exists) {
        return Ok(path);
    }
    given(ssh_auth_sock).context(
        "skagent isn't running here (no socket for age requests in XDG_RUNTIME_DIR), and \
         SSH_AUTH_SOCK names no forwarded agent to ask",
    )
}

/// The agent behind a socket.
#[derive(Debug)]
pub struct Agent {
    socket: PathBuf,
}

impl Agent {
    /// The agent at `socket`.
    #[must_use]
    pub fn at(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// The agent this process's environment leads to, see [`socket_path`].
    ///
    /// # Errors
    ///
    /// Returns an error if the environment names no socket.
    pub fn from_environment() -> Result<Self> {
        Ok(Self::at(socket_path(
            std::env::var_os("SKAGENT_AGE_SOCKET").as_deref(),
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            std::env::var_os("SSH_AUTH_SOCK").as_deref(),
            Path::exists,
        )?))
    }
}

impl Unwrap for Agent {
    fn unwrap(
        &mut self,
        request: &UnwrapRequest,
        waiting: &mut dyn FnMut() -> Result<()>,
    ) -> Result<UnwrapReply> {
        let frame = request_frame(UNWRAP_EXTENSION, &request.encode()?)?;
        let mut stream = UnixStream::connect(&self.socket).with_context(|| {
            format!(
                "connecting to skagent at {} (is it running?)",
                self.socket.display()
            )
        })?;
        stream
            .write_all(&frame)
            .with_context(|| format!("sending the request to {}", self.socket.display()))?;
        // The agent may wait for a PIN, a touch or a security key: there is
        // no deadline here. Giving up closes the connection, which the agent
        // takes as a cancel.
        loop {
            let mut fds = [PollFd::new(&stream, PollFlags::IN)];
            let ready = poll(&mut fds, Some(&WAIT_STEP))
                .with_context(|| format!("waiting for {}", self.socket.display()))?;
            if ready > 0 {
                break;
            }
            waiting()?;
        }
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .with_context(|| format!("reading the reply of {}", self.socket.display()))?;
        // The reply may hold a file key.
        let mut message = Zeroizing::new(vec![0_u8; reply_length(header)?]);
        stream
            .read_exact(&mut message)
            .with_context(|| format!("reading the reply of {}", self.socket.display()))?;
        if let Some(details) = reply_details(UNWRAP_EXTENSION, &message)? {
            return UnwrapReply::decode(details);
        }
        // A failure: an agent that isn't skagent, or skagent on a socket
        // where it doesn't take age requests.
        if self.socket.file_name() == Some(OsStr::new(AGE_SOCKET_NAME)) {
            bail!("skagent at {} refused the request", self.socket.display());
        }
        Ok(UnwrapReply::Refused(Refusal::NotAllowed))
    }
}
