//! Batches of decryptions as the signer keeps them: next to the PINs, so
//! that whatever evicts PINs ends them under the same lock. The rules are
//! in [`crate::batch`].

use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use anyhow::Result;
use skagent_age::{Recipient, Seed, Stanza};

use super::{Caching, Signer, SigningTicket, still_plugged_in};
use crate::ancestry::Pinned;
use crate::batch::{BatchId, Ended, Member, Opened, Served};
use crate::device::DeviceIdentity;
use crate::pin_cache::CredentialKey;

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

    /// Follows the batch `opened` until its tool closes it: ends it when its
    /// time is up, and logs how it ended.
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
        let mut running = true;
        loop {
            tokio::select! {
                () = &mut time_up, if running => {
                    self.end_batch(id, Ended::TimeUp).await;
                }
                changed = progress.changed() => {
                    if changed.is_err() {
                        // Closed: the tool is gone.
                        return;
                    }
                }
            }
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
        }
    }
}
