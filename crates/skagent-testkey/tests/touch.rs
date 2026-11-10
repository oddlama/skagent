//! The simulated touch and its cancellation.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent_testkey::touch::{Touch, TouchOutcome};

#[test]
fn a_cancel_ends_the_wait_and_leaves_the_touch_unused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let file = dir.path().join("touch");
    let touch = Touch::File(file.clone(), Duration::from_secs(10));
    let mut polls = 0_u32;
    let started = Instant::now();
    let outcome = touch.request("getAssertion", "ssh:example", &mut || {
        polls = polls.saturating_add(1);
        polls >= 3
    });
    ensure!(outcome == TouchOutcome::Cancelled, "{outcome:?}");
    ensure!(
        started.elapsed() < Duration::from_secs(2),
        "kept waiting after the cancel"
    );

    // A touch that arrives later still counts for the next request.
    std::fs::write(&file, "").context("touching")?;
    let outcome = touch.request("getAssertion", "ssh:example", &mut || false);
    ensure!(outcome == TouchOutcome::Touched, "{outcome:?}");
    ensure!(!file.exists(), "the touch was not consumed");
    Ok(())
}

#[test]
fn nobody_touching_times_out() {
    let dir = std::env::temp_dir().join("skagent-touch-never-created");
    let touch = Touch::File(dir, Duration::from_millis(100));
    assert_eq!(
        touch.request("select", "", &mut || false),
        TouchOutcome::TimedOut
    );
}
