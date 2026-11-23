//! Letting go of the security key when nobody waits for its answer.
//!
//! A request that waits for a touch blocks in libfido2 for up to half a
//! minute. If the age client goes away meanwhile, or the process is told to
//! end, the key would keep blinking for a touch that is good for nothing,
//! and whoever asks it next would find it busy.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result};
use signal_hook::consts::{SIGINT, SIGTERM};
use skagent_fido::Canceller;

/// How often the watch looks up.
const STEP: Duration = Duration::from_millis(100);

/// The signals that end the process, caught for long enough to cancel the
/// request on the key: systemd stops a unit's whole control group at once,
/// so this process may be told to end together with the age client, before
/// it could see the client go.
///
/// Caught, a signal doesn't end the process by itself, and it interrupts
/// libfido2 where it waits for the key, in the thread that asked. That
/// thread cancels the request then (`PluggedIn::derive`); the watch ends
/// the process, also where no request was waiting.
const ENDING: [i32; 2] = [SIGTERM, SIGINT];

/// A thread that cancels the request on the security key once the age
/// client is gone or the process is told to end, and then lets the signal
/// do what it does: end the process.
#[derive(Debug)]
pub struct Watch {
    canceller: Arc<Mutex<Option<Canceller>>>,
}

impl Watch {
    /// Starts watching. `client_gone` says whether the age client went
    /// away.
    ///
    /// # Errors
    ///
    /// Returns an error if a signal can't be caught or the thread can't be
    /// started.
    pub fn start(client_gone: impl Fn() -> bool + Send + 'static) -> Result<Self> {
        let mut signals = Vec::new();
        for signal in ENDING {
            let arrived = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(signal, Arc::clone(&arrived))
                .with_context(|| format!("catching signal {signal}"))?;
            signals.push((signal, arrived));
        }
        let canceller: Arc<Mutex<Option<Canceller>>> = Arc::default();
        let watched = Arc::clone(&canceller);
        std::thread::Builder::new()
            .name("watch".to_owned())
            .spawn(move || {
                loop {
                    let ending = signals
                        .iter()
                        .find(|(_, arrived)| arrived.load(Ordering::SeqCst))
                        .map(|(signal, _)| *signal);
                    if ending.is_some() || client_gone() {
                        let canceller = watched.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(canceller) = canceller.as_ref() {
                            // Nothing waiting on the key: nothing to cancel.
                            let _nothing_pending = canceller.cancel();
                        }
                    }
                    if let Some(signal) = ending {
                        // Ends the process, as the signal would have.
                        let _ended = signal_hook::low_level::emulate_default_handler(signal);
                    }
                    std::thread::sleep(STEP);
                }
            })
            .context("starting the thread that watches for the age client going away")?;
        Ok(Self { canceller })
    }

    /// From now on, `canceller`'s security key is the one to let go of.
    pub fn cancels(&self, canceller: Canceller) {
        *self
            .canceller
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(canceller);
    }
}
