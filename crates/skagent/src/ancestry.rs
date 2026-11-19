//! Proof that one process descends from another.
//!
//! A batch of decryptions is for the processes its tool started, and nobody
//! else: a process can't choose its parent, so nothing can join from
//! outside. What a process *is*, though, the kernel only tells by pid, a
//! number it hands to another process once this one is gone. So the proof
//! pins every process it looks at:
//!
//! - **A pidfd** refers to one process for as long as it is open. While it
//!   doesn't report an exit, that process exists, and its pid is its own.
//! - **Going up:** read the child's parent pid, take a pidfd of that pid,
//!   and read the parent pid again. If it changed, the pidfd may be of a
//!   process that got the pid after the parent was gone: no proof.
//! - **At the end** every pinned process has to exist still: the one asking,
//!   each parent on the way, the ancestor. Then no pid changed hands while
//!   the proof ran, everything read was about the pinned processes, and
//!   there was a moment at which each was the parent of the one below.
//!
//! Whatever can't be proven (a process that is gone, hidden or changes
//! under the proof) isn't a descendant.

use std::fmt;
use std::fs;
use std::os::fd::OwnedFd;

use rustix::process::{Pid, PidfdFlags, pidfd_open};

use crate::peer::parse_stat;

/// How many parents up a descendant is looked for. Process trees are a few
/// levels deep; this bounds the work of a request.
pub const MAX_GENERATIONS: usize = 64;

/// What the proof needs to know about processes. [`Proc`] asks the kernel;
/// tests script it.
pub trait Processes {
    /// Refers to one process for as long as it is kept.
    type Pinned;

    /// The pid of the parent of whatever process has `pid` right now.
    /// `None` if there is no such process, or it can't be inspected.
    fn parent_of(&self, pid: u32) -> Option<u32>;

    /// Pins whatever process has `pid` right now.
    fn pin(&self, pid: u32) -> Option<Self::Pinned>;

    /// Whether the pinned process still exists. While it does, its pid
    /// names no other process.
    fn exists(&self, pinned: &Self::Pinned) -> bool;
}

/// Why a process isn't taken for a descendant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotProven {
    /// The ancestor is gone.
    AncestorGone,
    /// Its parents lead to the first process without passing the ancestor.
    Outside,
    /// A process on the way, or the one asking, is gone.
    Gone(u32),
    /// A process on the way can't be inspected.
    Hidden(u32),
    /// A process on the way got another parent while it was looked at.
    Reparented(u32),
    /// More than [`MAX_GENERATIONS`] parents.
    TooDeep,
}

impl fmt::Display for NotProven {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AncestorGone => formatter.write_str("the ancestor is gone"),
            Self::Outside => formatter.write_str("its parents don't lead to the ancestor"),
            Self::Gone(pid) => write!(formatter, "process {pid} on the way is gone"),
            Self::Hidden(pid) => write!(formatter, "process {pid} on the way can't be inspected"),
            Self::Reparented(pid) => write!(
                formatter,
                "process {pid} on the way got another parent meanwhile"
            ),
            Self::TooDeep => write!(formatter, "more than {MAX_GENERATIONS} parents"),
        }
    }
}

impl std::error::Error for NotProven {}

/// A process: its pid, and what pins it.
#[derive(Debug)]
pub struct Pinned<'a, P> {
    /// The pid the process had when it was pinned.
    pub pid: u32,
    /// What refers to it.
    pub pin: &'a P,
}

// Not derived: that would ask `P` to be `Copy`, and only the reference is.
impl<P> Clone for Pinned<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Pinned<'_, P> {}

/// Proves that `descendant` was started, however indirectly, by `ancestor`.
///
/// # Errors
///
/// Returns why it isn't proven; see the module's documentation.
pub fn descends<T: Processes>(
    processes: &T,
    descendant: Pinned<'_, T::Pinned>,
    ancestor: Pinned<'_, T::Pinned>,
) -> Result<(), NotProven> {
    // The parents so far, nearest first, each pinned.
    let mut parents: Vec<(u32, T::Pinned)> = Vec::new();
    let mut reached = false;
    for _generation in 0..MAX_GENERATIONS {
        let child = parents.last().map_or(descendant.pid, |(pid, _)| *pid);
        let parent = processes.parent_of(child).ok_or(NotProven::Hidden(child))?;
        if parent == ancestor.pid {
            reached = true;
            break;
        }
        // 1: the first process, which has no parent that could be the
        // ancestor. 0: the parent is outside what this process can see.
        if parent <= 1 {
            return Err(NotProven::Outside);
        }
        let pinned = processes.pin(parent).ok_or(NotProven::Hidden(parent))?;
        // The pid may have changed hands between reading and pinning it.
        if processes.parent_of(child) != Some(parent) {
            return Err(NotProven::Reparented(child));
        }
        parents.push((parent, pinned));
    }
    if !reached {
        return Err(NotProven::TooDeep);
    }
    // Everything above was read by pid. It was about the pinned processes
    // if each of them still exists.
    if !processes.exists(ancestor.pin) {
        return Err(NotProven::AncestorGone);
    }
    if let Some((gone, _)) = parents.iter().find(|(_, pin)| !processes.exists(pin)) {
        return Err(NotProven::Gone(*gone));
    }
    if !processes.exists(descendant.pin) {
        return Err(NotProven::Gone(descendant.pid));
    }
    Ok(())
}

/// The processes of this machine, as `/proc` and pidfds show them.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proc;

impl Processes for Proc {
    type Pinned = OwnedFd;

    fn parent_of(&self, pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_stat(&stat).map(|(_name, parent)| parent)
    }

    fn pin(&self, pid: u32) -> Option<OwnedFd> {
        let pid = Pid::from_raw(i32::try_from(pid).ok()?)?;
        pidfd_open(pid, PidfdFlags::empty()).ok()
    }

    fn exists(&self, pinned: &OwnedFd) -> bool {
        // A pidfd that can't be asked proves nothing.
        skagent_fds::has_exited(pinned).is_ok_and(|exited| !exited)
    }
}
