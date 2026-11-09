//! The agent's unix socket: creation with safe permissions, stale socket
//! handling, peer credential checks and cleanup.

use std::ffi::OsStr;
use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::process::{geteuid, umask};
use ssh_agent_lib::agent::ListeningSocket;
use tokio::net::{UnixListener, UnixStream};

/// File name of the socket inside `$XDG_RUNTIME_DIR`.
pub const DEFAULT_SOCKET_NAME: &str = "skagent.sock";

/// Pause after a transient `accept` failure (e.g. out of file descriptors),
/// so a persistent condition doesn't turn into a busy loop.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Resolves the default socket path from the value of `XDG_RUNTIME_DIR`.
///
/// # Errors
///
/// Returns an error if `runtime_dir` is unset, empty or relative.
pub fn default_socket_path(runtime_dir: Option<&OsStr>) -> Result<PathBuf> {
    let Some(runtime_dir) = runtime_dir.filter(|dir| !dir.is_empty()) else {
        bail!("XDG_RUNTIME_DIR is not set, pass --socket or set SKAGENT_SOCKET");
    };
    let runtime_dir = Path::new(runtime_dir);
    if !runtime_dir.is_absolute() {
        bail!(
            "XDG_RUNTIME_DIR {} is not an absolute path, pass --socket or set SKAGENT_SOCKET",
            runtime_dir.display()
        );
    }
    Ok(runtime_dir.join(DEFAULT_SOCKET_NAME))
}

/// Identity of the socket file this process created.
///
/// Used to remove exactly that file on shutdown, and to leave it alone if
/// another agent has replaced it in the meantime.
#[derive(Debug)]
pub struct BoundSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl BoundSocket {
    /// Path of the socket file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the socket file if it is still the one this process created.
    ///
    /// A missing file or a file that has been replaced is left as it is.
    ///
    /// # Errors
    ///
    /// Returns an error if the file can't be inspected or removed.
    pub fn remove(&self) -> Result<()> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspecting agent socket {} before removing it",
                        self.path.display()
                    )
                });
            }
        };
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            tracing::warn!(
                socket = %self.path.display(),
                "socket file was replaced by someone else, leaving it in place"
            );
            return Ok(());
        }
        fs::remove_file(&self.path)
            .with_context(|| format!("removing agent socket {}", self.path.display()))
    }
}

/// Binds the agent socket at `path` with mode `0600`.
///
/// An existing socket file is replaced only if nothing listens on it any more
/// (the leftover of an agent that didn't shut down cleanly). Anything else at
/// `path` is an error.
///
/// Must be called from within a tokio runtime, and during startup: it narrows
/// the process-wide umask for the duration of the `bind` call.
///
/// # Errors
///
/// Returns an error if `path` is occupied by a live agent or a non-socket
/// file, or if binding or setting permissions fails.
pub fn bind(path: &Path) -> Result<(UnixListener, BoundSocket)> {
    remove_stale_socket(path)?;

    // The socket file must never exist with a wider mode, not even briefly.
    let previous_umask = umask(Mode::from_bits_truncate(0o177));
    let bound = UnixListener::bind(path);
    umask(previous_umask);
    let listener = bound.with_context(|| format!("binding agent socket {}", path.display()))?;

    // Explicit, so the mode doesn't depend on how the platform applies the umask to sockets.
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("restricting agent socket {} to mode 0600", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting freshly bound agent socket {}", path.display()))?;

    Ok((
        listener,
        BoundSocket {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspecting existing file at socket path {}", path.display())
            });
        }
    };
    if !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace {}: it exists and is not a socket",
            path.display()
        );
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_live_connection) => bail!("another agent is already listening on {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            tracing::info!(socket = %path.display(), "removing stale agent socket");
            fs::remove_file(path)
                .with_context(|| format!("removing stale agent socket {}", path.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("probing existing agent socket {}", path.display()))
        }
    }
}

/// Whether a peer may use the agent: the agent's own user, or root (who can
/// read the agent's memory anyway). Same policy as OpenSSH's ssh-agent.
#[must_use]
pub fn peer_allowed(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid || peer_uid == 0
}

/// Whether an `accept` error is a temporary condition worth retrying instead
/// of shutting the agent down.
#[must_use]
pub fn is_transient_accept_error(error: &io::Error) -> bool {
    Errno::from_io_error(error).is_some_and(|errno| {
        [
            Errno::CONNABORTED,
            Errno::INTR,
            Errno::MFILE,
            Errno::NFILE,
            Errno::NOBUFS,
            Errno::NOMEM,
            Errno::PROTO,
        ]
        .contains(&errno)
    })
}

/// Listener that only hands out connections whose peer passes [`peer_allowed`].
///
/// Refused connections are closed and logged. The listener keeps accepting
/// after transient errors, so it only stops on conditions that won't go away.
#[derive(Debug)]
pub struct PeerCheckedListener {
    listener: UnixListener,
    own_uid: u32,
}

impl PeerCheckedListener {
    /// Wraps `listener`, allowing peers with the effective uid of this process.
    #[must_use]
    pub fn new(listener: UnixListener) -> Self {
        Self {
            listener,
            own_uid: geteuid().as_raw(),
        }
    }
}

#[async_trait]
impl ListeningSocket for PeerCheckedListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<Self::Stream> {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _address)) => stream,
                Err(error) if is_transient_accept_error(&error) => {
                    tracing::warn!(%error, "accepting an agent connection failed, retrying");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match stream.peer_cred() {
                Ok(credentials) if peer_allowed(credentials.uid(), self.own_uid) => {
                    return Ok(stream);
                }
                Ok(credentials) => tracing::warn!(
                    peer_uid = credentials.uid(),
                    peer_pid = ?credentials.pid(),
                    "refused agent connection from another user"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    "refused agent connection: reading peer credentials failed"
                ),
            }
        }
    }
}
