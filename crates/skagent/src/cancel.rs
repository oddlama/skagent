//! Ending device operations early: when their request is revoked (eviction,
//! key removal) or abandoned (the client disconnected).
//!
//! Blocking libfido2 calls run on `spawn_blocking` and can't be dropped like
//! futures. Instead:
//! - An assertion waiting for a touch gets `CTAPHID_CANCEL`
//!   ([`DeviceInterrupt`]), repeated until the worker reports it finished:
//!   a cancel sent before the request reached the device is ignored by it.
//! - Touch selection polls an [`Abandoned`] flag every round.
//! - Prompts and queue waits are plain futures and end when dropped.
//!
//! ssh-agent-lib only notices a disconnected client when it writes the
//! reply, so [`Hangup`] watches the connection on the side and lets the
//! agent drop the request future as soon as the client is gone.

use std::future::Future;
use std::io;
use std::os::fd::AsFd as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use skagent_fido::Canceller;
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

use crate::signer::SigningTicket;

/// Pause between repeated cancels.
const CANCEL_RETRY: Duration = Duration::from_millis(100);

/// Give up resending after this long. Longer than any device operation
/// (libfido2's timeout is 35 s), so the worker has ended by then anyway.
const CANCEL_FOR: Duration = Duration::from_secs(40);

/// Set when the request that owns a blocking operation goes away. The
/// operation checks it between steps.
#[derive(Debug, Default)]
pub struct Abandoned(Arc<AtomicBool>);

impl Abandoned {
    /// A flag for the blocking side; true once `self` was dropped.
    #[must_use]
    pub fn flag(&self) -> AbandonedFlag {
        AbandonedFlag(Arc::clone(&self.0))
    }
}

impl Drop for Abandoned {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The blocking side of [`Abandoned`].
#[derive(Debug, Clone)]
pub struct AbandonedFlag(Arc<AtomicBool>);

impl AbandonedFlag {
    /// Whether the request that started the operation is gone.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Cancels a device operation running on a blocking worker, if the request
/// is revoked while it runs, or the request future is dropped before it
/// ended.
#[derive(Debug)]
pub struct DeviceInterrupt {
    canceller: Canceller,
    finished: Arc<AtomicBool>,
}

/// Given to the worker; marks the operation as ended when dropped, which
/// also covers a worker that returns early or panics.
#[derive(Debug)]
pub struct Finished(Arc<AtomicBool>);

impl Drop for Finished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl DeviceInterrupt {
    /// Watches the operation of the device `canceller` belongs to. Move the
    /// returned [`Finished`] into the worker.
    #[must_use]
    pub fn new(canceller: Canceller) -> (Self, Finished) {
        let finished = Arc::new(AtomicBool::new(false));
        (
            Self {
                canceller,
                finished: Arc::clone(&finished),
            },
            Finished(finished),
        )
    }

    /// Waits for `worker`. If `ticket` is revoked first, the operation is
    /// cancelled and the worker still awaited, so the device and the PIN
    /// copy are released before this returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker panicked.
    pub async fn run<T>(self, worker: JoinHandle<T>, ticket: &SigningTicket) -> Result<T> {
        tokio::pin!(worker);
        let joined = tokio::select! {
            biased;
            joined = &mut worker => joined,
            () = ticket.revoked() => {
                tracing::info!("cancelling the security key operation of a revoked request");
                self.cancel_until_finished();
                worker.await
            }
        };
        joined.context("the security key thread panicked or was cancelled")
    }

    fn cancel_until_finished(&self) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        let canceller = self.canceller.clone();
        let finished = Arc::clone(&self.finished);
        let resend = move || {
            let started = Instant::now();
            while !finished.load(Ordering::Acquire) && started.elapsed() < CANCEL_FOR {
                if let Err(error) = canceller.cancel() {
                    tracing::debug!(error = %format!("{error:#}"), "sending a cancel failed");
                }
                std::thread::sleep(CANCEL_RETRY);
            }
        };
        // A thread of its own, not the runtime's blocking pool: requests are
        // also dropped while the runtime shuts down (SIGTERM during a touch
        // wait), and the pool runs nothing new then. The runtime waits for
        // the worker it is cancelling, so the cancels must still go out.
        let spawned = std::thread::Builder::new()
            .name("skagent-cancel".to_owned())
            .spawn(resend);
        if let Err(error) = spawned {
            tracing::warn!(%error, "can't start resending the cancel, sending it once");
            drop(self.canceller.cancel());
        }
    }
}

impl Drop for DeviceInterrupt {
    fn drop(&mut self) {
        // Dropped before the worker ended: the request was abandoned.
        if !self.finished.load(Ordering::Acquire) {
            tracing::info!("cancelling the security key operation of an abandoned request");
            self.cancel_until_finished();
        }
    }
}

/// Notices when an agent client hangs up while its request is still
/// running.
///
/// Watches a duplicate of the connection's descriptor for the peer being
/// gone (`EPOLLHUP`) and never reads from it, so the protocol stream that
/// ssh-agent-lib reads through the original descriptor is untouched. A peer
/// that only shut down its sending side (`EPOLLRDHUP`) may still wait for
/// the reply, so that doesn't count.
#[derive(Debug)]
pub struct Hangup(UnixStream);

impl Hangup {
    /// Starts watching `stream`. Must be called within a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor can't be duplicated or registered.
    pub fn watch(stream: &UnixStream) -> io::Result<Self> {
        let duplicate = std::os::unix::net::UnixStream::from(stream.as_fd().try_clone_to_owned()?);
        // The flag belongs to the shared file description, which tokio
        // already made non-blocking; this only states the precondition.
        duplicate.set_nonblocking(true)?;
        UnixStream::from_std(duplicate).map(Self)
    }

    /// Completes once the client is gone. Data from the client and a half
    /// close don't count. Never completes if the watch fails.
    pub async fn closed(&self) {
        loop {
            // A unix socket whose peer closed reports EPOLLHUP, which tokio
            // only passes on as write-closed, i.e. to writable interest. Read
            // interest would wake up for every request and, after a half
            // close, never stop.
            let Ok(ready) = self.0.ready(Interest::WRITABLE).await else {
                return std::future::pending().await;
            };
            if ready.is_write_closed() {
                return;
            }
            // Room to write, which says nothing about the peer: clear it
            // without writing and wait for the next event. Closed states
            // survive clearing in tokio, so a hangup can't be lost here.
            let _cleared = self.0.try_io(Interest::WRITABLE, || {
                Err::<(), _>(io::ErrorKind::WouldBlock.into())
            });
        }
    }

    /// Runs `work`, unless the client hangs up first: then `work` is dropped
    /// (which cancels what it was doing) and an error returned.
    ///
    /// # Errors
    ///
    /// Returns `work`'s error, or an error if the client hung up.
    pub async fn unless_closed<T>(
        hangup: Option<&Self>,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let Some(hangup) = hangup else {
            return work.await;
        };
        tokio::select! {
            biased;
            result = work => result,
            () = hangup.closed() => anyhow::bail!("the client disconnected, its request was cancelled"),
        }
    }
}
