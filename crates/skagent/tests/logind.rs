//! The logind watch loop: what failing to reach logind does to requests.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, ensure};
use skagent::agent::SkAgent;
use skagent::logind;
use skagent::signer::Signer;

/// Longer than three retry delays of the watch loop.
const SEVERAL_RETRIES: Duration = Duration::from_secs(100);

/// Without logind, signing runs uncached. Requests must not be cancelled
/// each time another attempt to reach logind fails, and the startup
/// request (socket activation) survives the first failed attempt.
#[tokio::test(start_paused = true)]
async fn failing_to_reach_logind_revokes_no_request() -> Result<()> {
    let agent = SkAgent::new(Signer::default());
    agent.caching_pending().await;
    let startup = agent.signer().ticket();

    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    let watcher = tokio::spawn(logind::watch_with(agent.clone(), move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async {
            Err(zbus::Error::Failure(
                "no system bus in this test".to_owned(),
            ))
        }
    }));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let while_failing = agent.signer().ticket();
    tokio::time::sleep(SEVERAL_RETRIES).await;
    watcher.abort();

    ensure!(
        attempts.load(Ordering::SeqCst) >= 3,
        "the loop didn't retry, so this test proves nothing"
    );
    startup.check()?;
    while_failing.check()?;
    Ok(())
}
