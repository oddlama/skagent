//! Batches of decryptions (`skagent batch`), as a state machine over
//! explicit time and processes.
//!
//! Rules (see `docs/age.md`):
//! - A batch belongs to the process that asked for it, the tool, and never
//!   outlasts it, its connection or its time limit.
//! - Its members are the tool's descendants, proven anew for every request
//!   ([`crate::ancestry`]). Nothing else is served from it.
//! - The first decryption with an identity is an ordinary one: the PIN and a
//!   touch. Only then is the identity's seed kept, in `memfd_secret(2)`
//!   memory where the kernel has it, and further files of members need
//!   neither.
//! - A batch ends for good: once its time is up, its tool is gone, the
//!   security key a seed came from is unplugged, PINs are evicted or the
//!   user stops it, it serves nothing and keeps nothing any more. Its seeds
//!   are wiped right then (`SecretBuffer`).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent_age::{FileKey, Recipient, Seed, Stanza};
use skagent_secret::strongest_backend;
use tokio::sync::watch;

use crate::ancestry::{NotProven, Pinned, Processes, descends};
use crate::device::DeviceIdentity;
use crate::pin_cache::CredentialKey;

/// How many batches there can be at once. Each is a running `skagent batch`.
pub const MAX_BATCHES: usize = 16;

/// Names a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchId(u64);

impl fmt::Display for BatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Why a batch is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The user stopped it.
    Stopped,
    /// Its time is up.
    TimeUp,
    /// The security key one of its seeds came from was unplugged.
    Unplugged,
    /// PINs were evicted: a lock, sleep, `skagent forget`, `ssh-add -D`.
    PinsEvicted,
    /// Its tool is gone.
    ToolGone,
}

impl fmt::Display for Ended {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stopped => "stopped by the user",
            Self::TimeUp => "its time is up",
            Self::Unplugged => "the security key was unplugged",
            Self::PinsEvicted => "PINs were dropped (lock, sleep or a request to forget them)",
            Self::ToolGone => "its command is gone",
        })
    }
}

/// What a batch tells whoever shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Files decrypted for it so far.
    pub files: u64,
    /// Set once it is over.
    pub ended: Option<Ended>,
}

/// A batch that was just opened.
#[derive(Debug)]
pub struct Opened {
    /// Its name.
    pub id: BatchId,
    /// How long it lasts at most.
    pub lasts: Duration,
    /// When that is.
    pub deadline: Instant,
    /// The command it is for, as shown.
    pub command: String,
    /// What happens to it. Closed when the batch is.
    pub progress: watch::Receiver<Progress>,
}

/// What a request of a batch's member needs to know.
#[derive(Debug, Clone)]
pub struct Member {
    /// The batch.
    pub id: BatchId,
    /// The command the batch is for, as shown.
    pub command: String,
    /// How long the batch still lasts at most.
    pub remaining: Duration,
    /// Held while a member derives a seed for the batch, so the others wait
    /// for it instead of asking for touches of their own.
    pub turn: Arc<tokio::sync::Mutex<()>>,
}

/// What a batch did with a member's request.
#[derive(Debug)]
pub enum Served {
    /// Unwrapped with the kept seed: the file key, or none if no stanza is
    /// for the identity.
    FileKey(Option<FileKey>),
    /// The request names another identity than the one the seed is of.
    AnotherIdentity,
    /// Nothing is kept for the identity, yet or any more: the request is an
    /// ordinary one.
    NotKept,
}

/// The seed of one identity, kept by one batch.
struct Kept {
    seed: Seed,
    recipient: Recipient,
    /// The plug-in of the security key the seed was derived on.
    device: DeviceIdentity,
}

struct Batch<P> {
    tool_pid: u32,
    tool: P,
    command: String,
    deadline: Instant,
    ended: Option<Ended>,
    seeds: HashMap<CredentialKey, Kept>,
    files: u64,
    turn: Arc<tokio::sync::Mutex<()>>,
    progress: watch::Sender<Progress>,
}

impl<P> Batch<P> {
    /// Ends the batch and wipes its seeds. Returns whether it was running.
    fn end(&mut self, reason: Ended) -> bool {
        if self.ended.is_some() {
            return false;
        }
        self.ended = Some(reason);
        // Dropped seeds are wiped.
        self.seeds.clear();
        self.tell();
        true
    }

    fn tell(&self) {
        self.progress.send_replace(Progress {
            files: self.files,
            ended: self.ended,
        });
    }
}

/// The batches of an agent.
pub struct Batches<T: Processes> {
    processes: T,
    /// The longest a batch may last. Zero: there are no batches.
    limit: Duration,
    next: u64,
    by_id: BTreeMap<BatchId, Batch<T::Pinned>>,
}

impl<T: Processes> fmt::Debug for Batches<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Batches")
            .field("limit", &self.limit)
            .field("batches", &self.by_id.len())
            .field("seeds", &self.seeds())
            .finish_non_exhaustive()
    }
}

impl<T: Processes> Batches<T> {
    /// No batches, each lasting `limit` at most. With a `limit` of zero none
    /// can be opened.
    pub fn new(processes: T, limit: Duration) -> Self {
        Self {
            processes,
            limit,
            next: 1,
            by_id: BTreeMap::new(),
        }
    }

    /// The longest a batch may last.
    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// Changes the longest a batch may last, for batches opened from now on.
    pub fn set_limit(&mut self, limit: Duration) {
        self.limit = limit;
    }

    /// Opens a batch for the process `tool` (its pid, and what pins it), to
    /// last `asked` (zero: as long as allowed) but no longer than the limit.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no batches (a limit of zero) or too
    /// many, or the tool is gone.
    pub fn open(
        &mut self,
        (tool_pid, tool): (u32, T::Pinned),
        command: String,
        asked: Duration,
        now: Instant,
    ) -> Result<Opened> {
        ensure!(
            !self.limit.is_zero(),
            "batches are turned off (--batch-lifetime 0)"
        );
        ensure!(
            self.by_id.len() < MAX_BATCHES,
            "{MAX_BATCHES} batches are open already"
        );
        ensure!(
            self.processes.exists(&tool),
            "the process asking for a batch is gone"
        );
        let lasts = if asked.is_zero() {
            self.limit
        } else {
            asked.min(self.limit)
        };
        let deadline = now
            .checked_add(lasts)
            .context("the batch's time limit is too large")?;
        let id = BatchId(self.next);
        self.next = self
            .next
            .checked_add(1)
            .context("no batch numbers are left")?;
        let (progress, shown) = watch::channel(Progress::default());
        self.by_id.insert(
            id,
            Batch {
                tool_pid,
                tool,
                command: command.clone(),
                deadline,
                ended: None,
                seeds: HashMap::new(),
                files: 0,
                turn: Arc::default(),
                progress,
            },
        );
        Ok(Opened {
            id,
            lasts,
            deadline,
            command,
            progress: shown,
        })
    }

    /// Forgets the batch `id`, whose tool closed its connection. Returns
    /// how many files were decrypted for it and why it was over before, if
    /// it was.
    pub fn close(&mut self, id: BatchId) -> Option<(u64, Option<Ended>)> {
        let batch = self.by_id.remove(&id)?;
        Some((batch.files, batch.ended))
    }

    /// Ends the batch `id` for `reason`. Returns whether it was running.
    pub fn end(&mut self, id: BatchId, reason: Ended) -> bool {
        self.by_id
            .get_mut(&id)
            .is_some_and(|batch| batch.end(reason))
    }

    /// Ends every batch for `reason`. Returns how many were running.
    pub fn end_all(&mut self, reason: Ended) -> usize {
        self.by_id
            .values_mut()
            .map(|batch| batch.end(reason))
            .filter(|ended| *ended)
            .count()
    }

    /// Ends the batches whose time is up at `now`, whose tool is gone, or
    /// that keep a seed from a security key that isn't `present` any more.
    /// Returns them.
    pub fn sweep(
        &mut self,
        now: Instant,
        present: impl Fn(&DeviceIdentity) -> bool,
    ) -> Vec<(BatchId, Ended)> {
        let mut ended = Vec::new();
        for (id, batch) in &mut self.by_id {
            if let Some(reason) = Self::overdue(&self.processes, batch, now, &present)
                && batch.end(reason)
            {
                ended.push((*id, reason));
            }
        }
        ended
    }

    /// Why the running `batch` has to end at `now`, if it has to.
    fn overdue(
        processes: &T,
        batch: &Batch<T::Pinned>,
        now: Instant,
        present: &impl Fn(&DeviceIdentity) -> bool,
    ) -> Option<Ended> {
        if batch.ended.is_some() {
            None
        } else if now >= batch.deadline {
            Some(Ended::TimeUp)
        } else if !processes.exists(&batch.tool) {
            Some(Ended::ToolGone)
        } else if batch.seeds.values().any(|kept| !present(&kept.device)) {
            Some(Ended::Unplugged)
        } else {
            None
        }
    }

    /// The running batch `peer` is a member of at `now`: the newest one
    /// whose tool it provably descends from.
    pub fn member(&mut self, peer: Pinned<'_, T::Pinned>, now: Instant) -> Option<Member> {
        for (id, batch) in self.by_id.iter_mut().rev() {
            if batch.ended.is_some() {
                continue;
            }
            if now >= batch.deadline {
                batch.end(Ended::TimeUp);
                continue;
            }
            let tool = Pinned {
                pid: batch.tool_pid,
                pin: &batch.tool,
            };
            match descends(&self.processes, peer, tool) {
                Ok(()) => {
                    return Some(Member {
                        id: *id,
                        command: batch.command.clone(),
                        remaining: batch.deadline.saturating_duration_since(now),
                        turn: Arc::clone(&batch.turn),
                    });
                }
                Err(NotProven::AncestorGone) => {
                    batch.end(Ended::ToolGone);
                }
                Err(reason) => {
                    tracing::debug!(batch = %id, pid = peer.pid, %reason, "not a member of the batch");
                }
            }
        }
        None
    }

    /// Unwraps the file key of `stanzas` with the seed the batch `id` keeps
    /// for the credential `key`, if it does and may still use it at `now`:
    /// the batch runs and the security key the seed came from is `present`.
    /// `named`: the identity the request is for, if it names one.
    ///
    /// # Errors
    ///
    /// Returns an error if unwrapping itself fails.
    pub fn unwrap(
        &mut self,
        id: BatchId,
        key: &CredentialKey,
        named: Option<&Recipient>,
        stanzas: &[Stanza],
        now: Instant,
        present: impl Fn(&DeviceIdentity) -> bool,
    ) -> Result<Served> {
        let Some(batch) = self.by_id.get_mut(&id) else {
            return Ok(Served::NotKept);
        };
        if let Some(reason) = Self::overdue(&self.processes, batch, now, &present) {
            batch.end(reason);
            return Ok(Served::NotKept);
        }
        // An ended batch has none: ending wiped them, and it keeps no more.
        let Some(kept) = batch.seeds.get(key) else {
            return Ok(Served::NotKept);
        };
        // The identity named is checked before any stanza is tried.
        if named.is_some_and(|named| *named != kept.recipient) {
            return Ok(Served::AnotherIdentity);
        }
        let file_key = kept
            .seed
            .unwrap(stanzas)
            .context("unwrapping with a batch's seed")?;
        if file_key.is_some() {
            batch.files = batch.files.saturating_add(1);
            batch.tell();
        }
        Ok(Served::FileKey(file_key))
    }

    /// Keeps `seed`, which a member's request just derived on `device` for
    /// the credential `key`, for the batch `id`'s further requests. Not if
    /// the batch is over at `now`. `decrypted`: whether that request
    /// decrypted a file, which counts. Returns whether the seed is kept.
    ///
    /// # Errors
    ///
    /// Returns an error if there's no memory to keep the seed in.
    pub fn keep(
        &mut self,
        id: BatchId,
        key: CredentialKey,
        (seed, recipient): (&Seed, Recipient),
        device: DeviceIdentity,
        decrypted: bool,
        now: Instant,
    ) -> Result<bool> {
        let Some(batch) = self.by_id.get_mut(&id) else {
            return Ok(false);
        };
        if batch.ended.is_some() {
            return Ok(false);
        }
        if let Some(reason) = Self::overdue(&self.processes, batch, now, &|_| true) {
            batch.end(reason);
            return Ok(false);
        }
        let seed = seed
            .copy_in(strongest_backend())
            .context("keeping an identity's seed for a batch")?;
        batch.seeds.insert(
            key,
            Kept {
                seed,
                recipient,
                device,
            },
        );
        if decrypted {
            batch.files = batch.files.saturating_add(1);
        }
        batch.tell();
        Ok(true)
    }

    /// How many batches there are, ended ones whose tool still runs
    /// included.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether there is no batch.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// How many batches run.
    pub fn running(&self) -> usize {
        self.by_id
            .values()
            .filter(|batch| batch.ended.is_none())
            .count()
    }

    /// How many seeds are kept.
    pub fn seeds(&self) -> usize {
        self.by_id.values().map(|batch| batch.seeds.len()).sum()
    }
}
