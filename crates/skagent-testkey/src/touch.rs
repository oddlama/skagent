//! Simulated touch on the key's button.

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long `Touch::File` waits for the trigger file.
const TOUCH_TIMEOUT: Duration = Duration::from_secs(10);
const TOUCH_POLL: Duration = Duration::from_millis(20);

/// How touch requests are answered.
#[derive(Debug)]
pub enum Touch {
    /// Every request is touched right away.
    Auto,
    /// Every request is refused.
    Deny,
    /// A touch is the appearance of this file, which is then deleted.
    File(PathBuf),
}

/// The answer to a touch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchOutcome {
    /// The key was touched.
    Touched,
    /// The touch was refused.
    Refused,
    /// Nobody touched the key in time.
    TimedOut,
}

impl Touch {
    /// Asks for a touch. Every request is logged as `touch requested`, so
    /// tests can count them in the journal.
    pub fn request(&self, operation: &str, rp_id: &str) -> TouchOutcome {
        tracing::info!(operation, rp_id, "touch requested");
        let outcome = match self {
            Self::Auto => TouchOutcome::Touched,
            Self::Deny => TouchOutcome::Refused,
            Self::File(path) => Self::wait_for_file(path),
        };
        tracing::info!(operation, rp_id, ?outcome, "touch answered");
        outcome
    }

    fn wait_for_file(path: &PathBuf) -> TouchOutcome {
        let started = Instant::now();
        while started.elapsed() < TOUCH_TIMEOUT {
            match std::fs::remove_file(path) {
                Ok(()) => return TouchOutcome::Touched,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::thread::sleep(TOUCH_POLL);
                }
                Err(error) => {
                    tracing::error!(%error, path = %path.display(), "consuming the touch file failed");
                    return TouchOutcome::Refused;
                }
            }
        }
        TouchOutcome::TimedOut
    }
}
