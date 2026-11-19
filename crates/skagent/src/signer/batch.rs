//! Batches of decryptions as the signer keeps them: next to the PINs, so
//! that whatever evicts PINs ends them under the same lock. The rules are
//! in [`crate::batch`].

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use skagent_age::{Recipient, Seed, Stanza};

use super::{Caching, Signer, SigningTicket, still_plugged_in};
use crate::ancestry::Pinned;
use crate::batch::{BatchId, Ended, Member, Notice, Opened, Progress, Served};
use crate::device::DeviceIdentity;
use crate::notify::{Answer, Notifier, Standing};
use crate::pin_cache::CredentialKey;

/// The key of the button that stops a batch.
const STOP: &str = "stop";

/// The least time between two updates of a batch's notification: a
/// command can decrypt hundreds of files a second.
const REFRESH: Duration = Duration::from_millis(500);

/// The notification of one batch: there while the batch decrypts without
/// a touch, counting, with a button to stop it. If the batch ends before
/// its command is done, it says why, and stays for a while.
struct Indicator {
    notifier: Option<Arc<Notifier>>,
    standing: Option<Standing>,
    command: String,
    deadline: Instant,
    /// What it shows.
    shows: Option<Progress>,
    /// Nothing more is shown for this batch: the user closed the
    /// notification, or there is no way to show one.
    gone: bool,
    /// When the count may be shown again.
    refresh_at: tokio::time::Instant,
}

impl Indicator {
    fn new(notifier: Option<Arc<Notifier>>, command: String, deadline: Instant) -> Self {
        Self {
            gone: notifier.is_none(),
            notifier,
            standing: None,
            command,
            deadline,
            shows: None,
            refresh_at: tokio::time::Instant::now(),
        }
    }

    /// Whether `now` is something to show that isn't shown.
    fn outdated(&self, now: Progress) -> bool {
        // A batch that keeps nothing yet has nothing to say, and one that
        // ended without ever keeping anything neither.
        let worth = match now.ended {
            Some(_) => self.shows.is_some(),
            None => now.keeps,
        };
        !self.gone && worth && self.shows != Some(now)
    }

    /// Whether `now` waits to be shown until [`Indicator::refresh_at`].
    fn held_back(&self, now: Progress) -> bool {
        self.outdated(now) && now.ended.is_none() && tokio::time::Instant::now() < self.refresh_at
    }

    /// Shows `now`, unless that is shown, not worth showing, or the count
    /// was updated a moment ago.
    async fn update(&mut self, now: Progress) {
        if !self.outdated(now) || self.held_back(now) {
            return;
        }
        if self.standing.is_none()
            && let Some(notifier) = &self.notifier
        {
            self.standing = notifier.standing(&[(STOP, "Stop")]).await;
        }
        let Some(standing) = &mut self.standing else {
            self.gone = true;
            return;
        };
        let notice = match now.ended {
            Some(reason) => Notice::ended(&self.command, now.files, reason),
            None => Notice::running(
                &self.command,
                now.files,
                self.deadline.saturating_duration_since(Instant::now()),
            ),
        };
        if standing
            .show(&notice.summary, &notice.body, now.ended.is_none())
            .await
        {
            self.shows = Some(now);
            self.refresh_at = tokio::time::Instant::now()
                .checked_add(REFRESH)
                .unwrap_or(self.refresh_at);
        } else {
            self.gone = true;
        }
    }

    /// Waits for what the user does with the notification. Doesn't return
    /// while there is none.
    async fn answer(&mut self) -> Answer {
        match &mut self.standing {
            Some(standing) if !self.gone => standing.answer().await,
            _ => std::future::pending().await,
        }
    }

    /// The batch is closed: its command is done. A running batch's
    /// notification goes with it; what says why a batch ended stays for
    /// its while.
    async fn close(self) {
        if let Some(standing) = self.standing
            && self.shows.is_some_and(|shown| shown.ended.is_none())
            && !self.gone
        {
            standing.close().await;
        }
    }
}

impl Signer {
    /// The same signer, with batches of decryptions lasting `lifetime` at
    /// most (`--batch-lifetime`). Zero: no batches.
    #[must_use]
    pub fn with_batch_lifetime(mut self, lifetime: Duration) -> Self {
        self.state.get_mut().batches.set_limit(lifetime);
        self
    }

    /// Opens a batch for the process `tool` (its pid and a pidfd of it), to
    /// last `asked` (zero: as long as allowed).
    ///
    /// # Errors
    ///
    /// Returns an error if there are no batches, too many, or the tool is
    /// gone.
    pub async fn open_batch(
        &self,
        tool: (u32, OwnedFd),
        command: String,
        asked: Duration,
    ) -> Result<Opened> {
        let mut state = self.state.lock().await;
        state.batches.open(tool, command, asked, Instant::now())
    }

    /// Forgets the batch `id`, whose tool closed its connection. Returns
    /// how many files were decrypted for it and why it was over before, if
    /// it was.
    pub async fn close_batch(&self, id: BatchId) -> Option<(u64, Option<Ended>)> {
        self.state.lock().await.batches.close(id)
    }

    /// Ends the batch `id` for `reason`, wiping its seeds. Returns whether
    /// it was running.
    pub async fn end_batch(&self, id: BatchId, reason: Ended) -> bool {
        self.state.lock().await.batches.end(id, reason)
    }

    /// The running batch the process `pid`, pinned by `peer`, is a member
    /// of. None while PINs can't be cached: what a batch keeps is worth more
    /// than a PIN, and is kept under the same conditions.
    pub async fn batch_of(&self, pid: u32, peer: &OwnedFd) -> Option<Member> {
        let mut state = self.state.lock().await;
        if state.batches.running() == 0 {
            return None;
        }
        if state.caching != Caching::Available {
            tracing::info!(
                "not using a batch: lock and sleep events aren't watched, so nothing is kept"
            );
            return None;
        }
        state
            .batches
            .member(Pinned { pid, pin: peer }, Instant::now())
    }

    /// Unwraps the file key of `stanzas` with the seed the batch `id` keeps
    /// for the credential `key`, see [`crate::batch::Batches::unwrap`].
    ///
    /// # Errors
    ///
    /// Returns an error if unwrapping itself fails.
    pub async fn unwrap_in_batch(
        &self,
        id: BatchId,
        key: &CredentialKey,
        named: Option<&Recipient>,
        stanzas: &[Stanza],
    ) -> Result<Served> {
        let mut state = self.state.lock().await;
        state
            .batches
            .unwrap(id, key, named, stanzas, Instant::now(), still_plugged_in)
    }

    /// Keeps `seed`, which the request authorized by `ticket` just derived
    /// on `device`, for the batch `id`. Not after anything evicted PINs
    /// since the request was authorized, not while PINs can't be cached, and
    /// not if the security key was unplugged meanwhile. `decrypted`: whether
    /// the request decrypted a file. Returns whether the seed is kept.
    ///
    /// # Errors
    ///
    /// Returns an error if the request was revoked, or there's no memory to
    /// keep the seed in.
    pub async fn keep_seed(
        &self,
        id: BatchId,
        key: CredentialKey,
        (seed, recipient): (&Seed, Recipient),
        device: DeviceIdentity,
        ticket: &SigningTicket,
        decrypted: bool,
    ) -> Result<bool> {
        let mut state = self.state.lock().await;
        // No awaits from here on: nothing evicts between the checks and the
        // keeping.
        ticket.check()?;
        if state.caching != Caching::Available || !still_plugged_in(&device) {
            return Ok(false);
        }
        state.batches.keep(
            id,
            key,
            (seed, recipient),
            device,
            decrypted,
            Instant::now(),
        )
    }

    /// How many seeds batches keep.
    pub async fn kept_seeds(&self) -> usize {
        self.state.lock().await.batches.seeds()
    }

    /// How many batches run.
    pub async fn running_batches(&self) -> usize {
        self.state.lock().await.batches.running()
    }

    /// The same signer, showing running batches in notifications of
    /// `notifier`.
    #[must_use]
    pub fn with_batch_notifier(mut self, notifier: Arc<Notifier>) -> Self {
        self.batch_notifier = Some(notifier);
        self
    }

    /// Follows the batch `opened` until its tool closes it: ends it when its
    /// time is up or the user stops it in its notification, shows how many
    /// files it decrypted, and logs how it ended.
    pub async fn watch_batch(&self, opened: Opened) {
        let Opened {
            id,
            deadline,
            mut progress,
            command,
            ..
        } = opened;
        let time_up = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(time_up);
        let mut indicator = Indicator::new(self.batch_notifier.clone(), command.clone(), deadline);
        let mut running = true;
        loop {
            let now = *progress.borrow_and_update();
            if let Some(reason) = now.ended
                && running
            {
                running = false;
                tracing::info!(
                    batch = %id,
                    %command,
                    files = now.files,
                    %reason,
                    "the batch ended; its command's further decryptions take a touch each"
                );
            }
            indicator.update(now).await;
            let (held_back, refresh_at) = (indicator.held_back(now), indicator.refresh_at);
            tokio::select! {
                () = &mut time_up, if running => {
                    self.end_batch(id, Ended::TimeUp).await;
                }
                changed = progress.changed() => {
                    if changed.is_err() {
                        // Closed: the tool is gone.
                        indicator.close().await;
                        return;
                    }
                }
                answer = indicator.answer() => match answer {
                    Answer::Action(key) if key == STOP => {
                        self.end_batch(id, Ended::Stopped).await;
                    }
                    Answer::Action(_) => {}
                    Answer::Gone => indicator.gone = true,
                },
                () = tokio::time::sleep_until(refresh_at), if held_back => {}
            }
        }
    }
}
