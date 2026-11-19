//! Who is at the other end of a connection to the socket for age requests.
//!
//! That socket takes requests from two programs only: skagent's plugin,
//! which age runs, and skagent's own command line. Both are files next to
//! each other, and a peer is one of them if its executable is that very
//! file. Anything else that connects (a socket forwarded by hand through
//! ssh, another program speaking the protocol) is not what "a request from
//! this machine" means, and is refused.
//!
//! The executable is read from `/proc/<pid>/exe`, which the kernel only
//! shows for processes this user may inspect: the plugin and the command
//! line stay dumpable for it. Where the kernel has pidfds for peers (Linux
//! 6.5), the pid is checked to still be the peer's afterwards.

use std::fs;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tokio::net::UnixStream;

/// The plugin's file name: what age looks for in `PATH` for identities of
/// the plugin `skagent`.
pub const PLUGIN_BINARY: &str = "age-plugin-skagent";

/// Programs that start others without being what the user thinks of as the
/// requester: shells, and what runs a command as or for someone.
const LAUNCHERS: [&str; 15] = [
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "nu",
    "tcsh",
    "csh",
    "nix-shell",
    "su",
    "sudo",
    "doas",
    "env",
    "systemd",
];

/// Scripts that run the age client for the program that asks, and that
/// nobody knows by name: agenix-rekey's `ageWrapper`, which stands between
/// `agenix edit` or `agenix rekey` and rage. What started them is shown.
const WRAPPERS: [&str; 1] = ["ageWrapper"];

/// A file, by where it is stored: two paths to the same file are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    device: u64,
    inode: u64,
}

impl FileId {
    /// The file `path` leads to.
    ///
    /// # Errors
    ///
    /// Returns an error if the file can't be inspected.
    pub fn of(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// skagent's own executables.
#[derive(Debug, Clone)]
pub struct OwnPrograms {
    agent: FileId,
    /// The plugin next to the agent, if it is installed there.
    plugin: Option<FileId>,
    plugin_path: PathBuf,
}

impl OwnPrograms {
    /// Finds this process's executable and the plugin next to it.
    ///
    /// # Errors
    ///
    /// Returns an error if this process's own executable can't be found.
    pub fn locate() -> Result<Self> {
        let agent_path =
            std::env::current_exe().context("finding the path of the agent's executable")?;
        let agent = FileId::of(Path::new("/proc/self/exe"))
            .context("inspecting the agent's executable (/proc/self/exe)")?;
        let plugin_path = agent_path
            .parent()
            .with_context(|| format!("{} has no parent directory", agent_path.display()))?
            .join(PLUGIN_BINARY);
        Ok(Self {
            agent,
            plugin: FileId::of(&plugin_path).ok(),
            plugin_path,
        })
    }

    /// Programs with the given executables, for tests.
    #[must_use]
    pub fn new(agent: FileId, plugin: Option<FileId>) -> Self {
        Self {
            agent,
            plugin,
            plugin_path: PathBuf::from(PLUGIN_BINARY),
        }
    }

    /// Where the plugin is expected.
    #[must_use]
    pub fn plugin_path(&self) -> &Path {
        &self.plugin_path
    }

    /// Whether the plugin is installed next to the agent.
    #[must_use]
    pub fn has_plugin(&self) -> bool {
        self.plugin.is_some()
    }

    /// Which of skagent's programs the executable `file` is.
    #[must_use]
    pub fn program(&self, file: FileId) -> Program {
        if file == self.agent {
            Program::Agent
        } else if self.plugin == Some(file) {
            Program::Plugin
        } else {
            Program::Other
        }
    }
}

/// What a peer runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// skagent's own binary: its command line.
    Agent,
    /// skagent's age plugin.
    Plugin,
    /// Anything else.
    Other,
}

/// The process that connected.
#[derive(Debug)]
pub struct Peer {
    pid: u32,
    /// Refers to the peer for as long as it is kept, where the kernel has it.
    pidfd: Option<OwnedFd>,
    program: Program,
}

impl Peer {
    /// Looks at the process that connected `stream`.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer's pid isn't known, or the peer is gone
    /// already. A peer whose executable can't be read is [`Program::Other`].
    pub fn inspect(stream: &UnixStream, own: &OwnPrograms) -> Result<Self> {
        let pid = stream
            .peer_cred()
            .context("reading the credentials of the connection's peer")?
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|&pid| pid > 0)
            .context("the connection's peer has no process id")?;
        let pidfd = skagent_fds::peer_pidfd(stream.as_fd())?;
        let program = match FileId::of(&proc_path(pid, "exe")) {
            Ok(executable) => own.program(executable),
            Err(error) => {
                tracing::debug!(pid, %error, "can't read the executable of a connection's peer");
                Program::Other
            }
        };
        // What was read about `pid` was about the peer only if the peer
        // still exists: a pid is handed out again once its process is gone.
        if let Some(pidfd) = &pidfd
            && skagent_fds::has_exited(pidfd)?
        {
            bail!("the connection's peer (pid {pid}) is gone");
        }
        Ok(Self {
            pid,
            pidfd,
            program,
        })
    }

    /// The peer's process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Which of skagent's programs the peer runs.
    #[must_use]
    pub fn program(&self) -> Program {
        self.program
    }

    /// Whether the peer was pinned with a pidfd while it was inspected.
    #[must_use]
    pub fn pinned(&self) -> bool {
        self.pidfd.is_some()
    }

    /// The pidfd that pins the peer, where the kernel has them for peers.
    #[must_use]
    pub fn pidfd(&self) -> Option<&OwnedFd> {
        self.pidfd.as_ref()
    }

    /// What started the age client this peer (the plugin) works for, as the
    /// process list names it: `agenix-edit-view` for agenix-rekey's script
    /// that runs rage, `age` itself when a shell ran it. A hint for prompts,
    /// read from `/proc` without a guarantee; `None` if the processes are
    /// gone.
    #[must_use]
    pub fn started_by(&self) -> Option<String> {
        let (_, client_pid) = process(self.pid)?;
        let (client, mut next) = process(client_pid)?;
        // What started the client, and what started that: one of them may
        // be a wrapper.
        let mut above = Vec::new();
        for _ in 0..=WRAPPERS.len() {
            let Some((name, parent)) = process(next) else {
                break;
            };
            above.push(name);
            next = parent;
        }
        let above: Vec<&str> = above.iter().map(String::as_str).collect();
        Some(requester(&client, &above))
    }
}

fn proc_path(pid: u32, file: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{file}"))
}

/// The name and the parent of process `pid`.
fn process(pid: u32) -> Option<(String, u32)> {
    let (name, parent) = parse_stat(&fs::read_to_string(proc_path(pid, "stat")).ok()?)?;
    let name = match fs::read(proc_path(pid, "cmdline")) {
        Ok(command_line) => completed_name(&name, &command_line),
        Err(_) => name,
    };
    Some((name, parent))
}

/// Bytes of a name the process list keeps (`TASK_COMM_LEN` without its NUL).
const LISTED_NAME_BYTES: usize = 15;

/// Arguments of a command line looked at for the rest of a name: the
/// program, and the script an interpreter runs.
const NAME_ARGUMENTS: usize = 3;

/// `name` as the process list has it, with the rest the kernel cut off: a
/// name of 15 bytes may be the start of a longer one, and then the command
/// line (`/proc/<pid>/cmdline`, arguments ending in NUL) has it as the file
/// name of the program or of the script it runs. `skagent-age-che` is
/// `skagent-age-check` there.
#[must_use]
pub fn completed_name(name: &str, command_line: &[u8]) -> String {
    if name.len() != LISTED_NAME_BYTES {
        return name.to_owned();
    }
    command_line
        .split(|byte| *byte == 0)
        .take(NAME_ARGUMENTS)
        .filter_map(|argument| std::str::from_utf8(argument).ok())
        .filter_map(|argument| argument.rsplit('/').next())
        .find(|file_name| file_name.starts_with(name))
        .map_or_else(|| name.to_owned(), str::to_owned)
}

/// The name and the parent's pid from the content of `/proc/<pid>/stat`:
/// `pid (name) state ppid …`. The name may itself contain spaces and
/// parentheses, so it ends at the last `)`.
#[must_use]
pub fn parse_stat(stat: &str) -> Option<(String, u32)> {
    let (before, after) = stat.rsplit_once(')')?;
    let (_, name) = before.split_once('(')?;
    let mut fields = after.split_ascii_whitespace();
    let _state = fields.next()?;
    let parent = fields.next()?.parse().ok()?;
    Some((name.to_owned(), parent))
}

/// Who a request is shown to come from: what started the age client, or
/// the client itself if that was a shell or the like, or isn't known.
/// `above`: the client's parent, that one's parent and so on. A wrapper
/// around the client is passed over.
#[must_use]
pub fn requester(client: &str, above: &[&str]) -> String {
    match above.iter().find(|name| !WRAPPERS.contains(name)) {
        Some(starter) if !LAUNCHERS.contains(starter) => (*starter).to_owned(),
        _ => client.to_owned(),
    }
}
