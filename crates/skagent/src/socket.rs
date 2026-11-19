//! The agent's unix socket: creation with safe permissions, stale socket
//! handling, peer credential checks and cleanup.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use rustix::fs::{CWD, RenameFlags, renameat_with};
use rustix::io::Errno;
use rustix::process::geteuid;
use ssh_agent_lib::agent::ListeningSocket;
use tokio::net::{UnixListener, UnixStream};

use crate::frames::BoundedStream;

/// File name of the socket inside `$XDG_RUNTIME_DIR`.
pub const DEFAULT_SOCKET_NAME: &str = "skagent.sock";

/// What the socket for age requests is called next to a socket `name.sock`:
/// `name-age.sock`.
const AGE_SOCKET_SUFFIX: &str = "-age";

/// Where the socket for age requests is by default: next to the ssh-agent
/// socket `ssh`, named after it. `skagent.sock` gives `skagent-age.sock`, so
/// several agents with sockets of their own don't meet on one path.
#[must_use]
pub fn age_socket_path(ssh: &Path) -> PathBuf {
    let mut name = ssh.file_stem().unwrap_or_default().to_owned();
    name.push(AGE_SOCKET_SUFFIX);
    if let Some(extension) = ssh.extension() {
        name.push(".");
        name.push(extension);
    }
    ssh.with_file_name(name)
}

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
    identity: FileIdentity,
}

/// Device and inode identify a file, but filesystems reuse inode numbers once
/// a file is deleted. The inode change time (nanosecond resolution) tells a
/// later file with a recycled inode apart from ours.
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    change_time: (i64, i64),
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            change_time: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
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
        if FileIdentity::of(&metadata) != self.identity {
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
/// The socket is never reachable with a wider mode: it is bound inside a
/// fresh `0700` directory next to `path`, restricted to `0600`, and only then
/// renamed into place. The rename refuses to overwrite, so an agent that
/// appears at `path` in the meantime is never replaced. No process-wide state
/// such as the umask is touched, so this is safe to call at any time.
///
/// Must be called from within a tokio runtime.
///
/// # Errors
///
/// Returns an error if `path` is occupied by a live agent or a non-socket
/// file, or if creating, restricting or moving the socket fails.
pub fn bind(path: &Path) -> Result<(UnixListener, BoundSocket)> {
    remove_stale_socket(path)?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".skagent-bind-")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "creating a private staging directory in {}",
                parent.display()
            )
        })?;
    let staged = staging.path().join("agent.sock");

    let listener = UnixListener::bind(&staged)
        .with_context(|| format!("binding agent socket in {}", staging.path().display()))?;
    fs::set_permissions(&staged, Permissions::from_mode(0o600))
        .with_context(|| format!("restricting agent socket {} to mode 0600", staged.display()))?;
    renameat_with(CWD, &staged, CWD, path, RenameFlags::NOREPLACE).with_context(|| {
        format!(
            "moving agent socket into place at {} (fails if something appeared there meanwhile)",
            path.display()
        )
    })?;
    staging
        .close()
        .with_context(|| format!("removing staging directory next to {}", path.display()))?;

    // After the rename: renaming updates the inode change time.
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting freshly bound agent socket {}", path.display()))?;

    Ok((
        listener,
        BoundSocket {
            path: path.to_owned(),
            identity: FileIdentity::of(&metadata),
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

/// Listener that only hands out connections whose peer passes [`peer_allowed`],
/// limited to messages OpenSSH's ssh-agent would accept.
///
/// Refused connections are closed and logged. The listener keeps accepting
/// after transient errors, so it only stops on conditions that won't go away.
pub struct PeerCheckedListener {
    listener: UnixListener,
    path: PathBuf,
    own_uid: u32,
}

impl PeerCheckedListener {
    /// Wraps `listener`, which serves the socket at `path`, allowing peers
    /// with the effective uid of this process.
    #[must_use]
    pub fn new(listener: UnixListener, path: &Path) -> Self {
        Self {
            listener,
            path: path.to_owned(),
            own_uid: geteuid().as_raw(),
        }
    }
}

// Manual, because the listener's own address is the staging path it was
// bound at before being renamed into place (see [`bind`]).
impl fmt::Debug for PeerCheckedListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerCheckedListener")
            .field("path", &self.path)
            .field("own_uid", &self.own_uid)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ListeningSocket for PeerCheckedListener {
    /// Messages above [`crate::frames::MAX_MESSAGE_LEN`] end the connection.
    type Stream = BoundedStream<UnixStream>;

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
                    return Ok(BoundedStream::new(stream));
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
