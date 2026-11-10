//! Eviction revokes requests authorized before it, even with an empty cache.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent::signer::Signer;

#[tokio::test]
async fn forget_revokes_old_tickets_but_not_new_ones() -> Result<()> {
    let signer = Signer::default();
    let first = signer.ticket();
    let queued = signer.ticket();
    first.check()?;
    ensure!(signer.forget_all().await == 0);
    ensure!(first.check().is_err());
    ensure!(queued.check().is_err());
    signer.ticket().check()
}

#[tokio::test]
async fn monitoring_transitions_revoke_in_flight_requests() -> Result<()> {
    let signer = Signer::default();
    let before_loss = signer.ticket();
    signer.set_caching_available(false).await;
    ensure!(before_loss.check().is_err());
    let during_loss = signer.ticket();
    during_loss.check()?;
    signer.set_caching_available(true).await;
    ensure!(during_loss.check().is_err());
    signer.ticket().check()
}
