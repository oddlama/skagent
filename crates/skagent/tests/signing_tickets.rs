//! Eviction revokes requests authorized before it, even with an empty cache.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Result, ensure};
use skagent::identities::SkIdentity;
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

/// A signer whose lock and sleep monitoring is up.
async fn watched() -> Signer {
    let signer = Signer::default();
    signer.set_caching_available(true).await;
    signer
}

/// A new signer hasn't watched lock and sleep yet, so it must not cache:
/// it starts like `caching_pending`, where failing to start watching is no
/// transition that revokes. (Leaving available caching would revoke.)
#[tokio::test]
async fn a_new_signer_caches_nothing_until_monitoring_starts() -> Result<()> {
    let signer = Signer::default();
    let startup = signer.ticket();
    signer.set_caching_available(false).await;
    startup.check()
}

#[tokio::test]
async fn monitoring_transitions_revoke_in_flight_requests() -> Result<()> {
    let signer = watched().await;
    let before_loss = signer.ticket();
    signer.set_caching_available(false).await;
    ensure!(before_loss.check().is_err());
    let during_loss = signer.ticket();
    during_loss.check()?;
    signer.set_caching_available(true).await;
    ensure!(during_loss.check().is_err());
    signer.ticket().check()
}

#[tokio::test]
async fn requests_from_before_monitoring_survive_its_start() -> Result<()> {
    let signer = watched().await;
    let cached_era = signer.ticket();
    signer.caching_pending().await;
    ensure!(
        cached_era.check().is_err(),
        "leaving available caching must revoke like a loss"
    );
    let startup = signer.ticket();
    signer.set_caching_available(true).await;
    startup.check()?;
    // From now on transitions revoke again.
    signer.set_caching_available(false).await;
    ensure!(startup.check().is_err());
    Ok(())
}

#[tokio::test]
async fn failing_to_watch_at_startup_revokes_nothing_until_recovery() -> Result<()> {
    let signer = Signer::default();
    signer.caching_pending().await;
    let startup = signer.ticket();
    signer.set_caching_available(false).await;
    startup.check()?;
    signer.set_caching_available(true).await;
    ensure!(
        startup.check().is_err(),
        "a request spanning the recovery survived"
    );
    Ok(())
}

fn identity(seed: u8, comment: &str) -> Result<SkIdentity> {
    SkIdentity::from_credential(support::sk_credential(seed, comment)?, None)
}

#[tokio::test]
async fn removing_one_key_revokes_only_its_own_requests() -> Result<()> {
    let signer = Signer::default();
    let (work, personal) = (identity(1, "work")?, identity(2, "personal")?);
    let work_request = signer.ticket_for(&work).await;
    let personal_request = signer.ticket_for(&personal).await;
    let loading = signer.ticket();

    signer.forget(&work).await;
    ensure!(
        work_request.check().is_err(),
        "removed key's request survived"
    );
    personal_request.check()?;
    loading.check()?;
    // A new request for the re-added key is authorized again.
    signer.ticket_for(&work).await.check()?;
    Ok(())
}

#[tokio::test]
async fn revocation_wakes_waiters() -> Result<()> {
    let signer = Signer::default();
    let work = identity(1, "work")?;
    let waiting = signer.ticket_for(&work).await;
    let global = signer.ticket_for(&identity(2, "personal")?).await;
    signer.forget(&work).await;
    tokio::time::timeout(std::time::Duration::from_secs(1), waiting.revoked()).await?;
    ensure!(
        tokio::time::timeout(std::time::Duration::from_millis(50), global.revoked())
            .await
            .is_err(),
        "another key's request was revoked"
    );
    signer.forget_all().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), global.revoked()).await?;
    Ok(())
}

/// A request whose device work noticed the revocation (and cancelled the
/// assertion) still checks its ticket after the worker returns. That check
/// must not pass just because the wait already saw the revocation.
#[tokio::test]
async fn waiting_for_a_revocation_leaves_the_ticket_revoked() -> Result<()> {
    let signer = Signer::default();
    let global = signer.ticket();
    let credential = signer.ticket_for(&identity(1, "work")?).await;
    signer.forget_all().await;
    for ticket in [&global, &credential] {
        tokio::time::timeout(std::time::Duration::from_secs(1), ticket.revoked()).await?;
        ensure!(
            ticket.check().is_err(),
            "a global revocation was forgotten once a waiter saw it"
        );
    }
    Ok(())
}

#[tokio::test]
async fn remove_all_revokes_every_request() -> Result<()> {
    let signer = Signer::default();
    let work = signer.ticket_for(&identity(1, "work")?).await;
    let loading = signer.ticket();
    signer.remove_all().await;
    ensure!(work.check().is_err());
    ensure!(loading.check().is_err());
    Ok(())
}
