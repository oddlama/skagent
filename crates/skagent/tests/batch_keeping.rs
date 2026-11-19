//! Batches in the signer: a seed is kept under the conditions a PIN is, and
//! used by the processes its batch's tool started. What needs a security
//! key is in the VM test.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use skagent::ancestry::{Proc, Processes as _};
use skagent::batch::{Ended, Opened, Served};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::CredentialKey;
use skagent::signer::Signer;
use skagent_age::{FileKey, Seed, Stanza};

/// This process, as the tool of a batch.
fn myself() -> Result<(u32, OwnedFd)> {
    let pid = std::process::id();
    Ok((pid, Proc.pin(pid).context("a pidfd of this process")?))
}

async fn open(signer: &Signer) -> Result<Opened> {
    signer
        .open_batch(myself()?, "a command".to_owned(), Duration::ZERO)
        .await
}

fn credential() -> CredentialKey {
    CredentialKey::new("skagent:age", &[7; 32])
}

fn seed() -> Result<Seed> {
    Seed::from_bytes(&[7; 32])
}

fn stanza() -> Result<Stanza> {
    seed()?
        .recipient()?
        .wrap(&FileKey::from_bytes(&[1; 16])?, &[1; 64])
}

/// A device node that is there, standing in for a plugged-in security key.
fn plugged_in() -> Result<DeviceIdentity> {
    DeviceIdentity::of("/dev/null")
}

/// The same node as it was before a replug: another plug-in.
fn unplugged() -> DeviceIdentity {
    DeviceIdentity::new("/dev/null", 0, 0, (0, 0))
}

/// Keeps the seed for the batch `opened`, as a request authorized by a
/// ticket taken right now would.
async fn keep(signer: &Signer, opened: &Opened, device: DeviceIdentity) -> Result<bool> {
    let seed = seed()?;
    let recipient = seed.recipient()?;
    signer
        .keep_seed(
            opened.id,
            credential(),
            (&seed, recipient),
            device,
            &signer.ticket(),
            true,
        )
        .await
}

async fn served(signer: &Signer, opened: &Opened) -> Result<bool> {
    let stanza = stanza()?;
    let served = signer
        .unwrap_in_batch(
            opened.id,
            &credential(),
            None,
            std::slice::from_ref(&stanza),
        )
        .await?;
    match served {
        Served::FileKey(Some(_)) => Ok(true),
        Served::NotKept => Ok(false),
        other => bail!("{other:?}"),
    }
}

#[tokio::test]
async fn nothing_is_kept_before_lock_and_sleep_are_watched() -> Result<()> {
    let signer = Signer::default();
    let opened = open(&signer).await?;
    ensure!(
        !keep(&signer, &opened, plugged_in()?).await?,
        "kept without monitoring"
    );
    ensure!(signer.kept_seeds().await == 0);

    // Watching starts: what came before missed no event, and the batch runs.
    signer.set_caching_available(true).await;
    ensure!(signer.running_batches().await == 1);
    ensure!(keep(&signer, &opened, plugged_in()?).await?);
    ensure!(signer.kept_seeds().await == 1);
    ensure!(served(&signer, &opened).await?);
    ensure!(opened.progress.borrow().files == 2);

    // Watching ends: the seed goes with the PINs.
    signer.set_caching_available(false).await;
    ensure!(signer.kept_seeds().await == 0 && signer.running_batches().await == 0);
    ensure!(!served(&signer, &opened).await?);
    ensure!(opened.progress.borrow().ended == Some(Ended::PinsEvicted));
    let unwatched = open(&signer).await?;
    ensure!(
        !keep(&signer, &unwatched, plugged_in()?).await?,
        "kept while monitoring is lost"
    );
    Ok(())
}

#[tokio::test]
async fn a_seed_from_a_security_key_that_is_gone_is_not_kept() -> Result<()> {
    let signer = Signer::default();
    signer.set_caching_available(true).await;
    let opened = open(&signer).await?;
    ensure!(
        !keep(&signer, &opened, unplugged()).await?,
        "kept for a key that was unplugged"
    );
    ensure!(signer.kept_seeds().await == 0);
    // The batch itself goes on, for a key that is there.
    ensure!(keep(&signer, &opened, plugged_in()?).await?);
    Ok(())
}

#[tokio::test]
async fn a_request_from_before_an_eviction_leaves_no_seed() -> Result<()> {
    let signer = Signer::default();
    signer.set_caching_available(true).await;
    let before = signer.ticket();
    signer.forget_all().await;
    // A batch that the eviction didn't end, because it came later.
    let opened = open(&signer).await?;
    let seed = seed()?;
    let kept = signer
        .keep_seed(
            opened.id,
            credential(),
            (&seed, seed.recipient()?),
            plugged_in()?,
            &before,
            true,
        )
        .await;
    ensure!(kept.is_err(), "kept for a revoked request: {kept:?}");
    ensure!(signer.kept_seeds().await == 0);
    Ok(())
}

#[tokio::test]
async fn every_eviction_of_pins_wipes_the_seeds() -> Result<()> {
    let signer = Signer::default();
    signer.set_caching_available(true).await;
    for eviction in 0..4 {
        let opened = open(&signer).await?;
        ensure!(keep(&signer, &opened, plugged_in()?).await?);
        ensure!(signer.kept_seeds().await == 1, "eviction {eviction}");
        match eviction {
            0 => drop(signer.forget_all().await),
            1 => drop(signer.remove_all().await),
            2 => signer.caching_pending().await,
            _ => signer.set_caching_available(false).await,
        }
        ensure!(
            signer.kept_seeds().await == 0,
            "eviction {eviction} left a seed"
        );
        ensure!(signer.running_batches().await == 0, "eviction {eviction}");
        ensure!(signer.close_batch(opened.id).await == Some((1, Some(Ended::PinsEvicted))));
        signer.set_caching_available(true).await;
    }
    Ok(())
}

#[tokio::test]
async fn stopping_and_closing_a_batch_wipe_its_seed() -> Result<()> {
    let signer = Signer::default();
    signer.set_caching_available(true).await;
    let opened = open(&signer).await?;
    ensure!(keep(&signer, &opened, plugged_in()?).await?);
    ensure!(signer.end_batch(opened.id, Ended::Stopped).await);
    ensure!(signer.kept_seeds().await == 0);
    ensure!(
        !signer.end_batch(opened.id, Ended::Stopped).await,
        "stopped twice"
    );
    ensure!(!served(&signer, &opened).await?);

    let opened = open(&signer).await?;
    ensure!(keep(&signer, &opened, plugged_in()?).await?);
    ensure!(signer.close_batch(opened.id).await == Some((1, None)));
    ensure!(signer.kept_seeds().await == 0);
    Ok(())
}

/// A child of this process that stays until killed.
struct Sleeper(Child);

impl Sleeper {
    fn start() -> Result<Self> {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .map(Self)
            .context("running sleep")
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        // Gone already is as good.
        let _gone = self.0.kill();
        let _reaped = self.0.wait();
    }
}

#[tokio::test]
async fn members_are_found_once_something_can_be_kept_for_them() -> Result<()> {
    let child = Sleeper::start()?;
    let pid = child.0.id();
    let pinned = Proc.pin(pid).context("a pidfd of the child")?;

    let signer = Signer::default();
    ensure!(
        signer.batch_of(pid, &pinned).await.is_none(),
        "a member of no batch"
    );
    let opened = open(&signer).await?;
    // Nothing would be kept: the request is an ordinary one, and says so.
    ensure!(
        signer.batch_of(pid, &pinned).await.is_none(),
        "a batch without monitoring"
    );
    signer.set_caching_available(true).await;
    let member = signer
        .batch_of(pid, &pinned)
        .await
        .context("not a member")?;
    ensure!(member.id == opened.id && member.command == "a command");
    ensure!(member.remaining <= opened.lasts && member.remaining > Duration::from_mins(9));

    // This process isn't its own member, and an ended batch has none.
    let (me, my_pin) = myself()?;
    ensure!(signer.batch_of(me, &my_pin).await.is_none());
    ensure!(signer.end_batch(opened.id, Ended::Stopped).await);
    ensure!(signer.batch_of(pid, &pinned).await.is_none());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_watcher_ends_a_batch_when_its_time_is_up() -> Result<()> {
    let signer =
        std::sync::Arc::new(Signer::default().with_batch_lifetime(Duration::from_secs(30)));
    signer.set_caching_available(true).await;
    let opened = open(&signer).await?;
    ensure!(opened.lasts == Duration::from_secs(30));
    let id = opened.id;
    let progress = opened.progress.clone();
    let watcher = {
        let signer = std::sync::Arc::clone(&signer);
        tokio::spawn(async move { signer.watch_batch(opened).await })
    };
    tokio::time::sleep(Duration::from_secs(29)).await;
    ensure!(signer.running_batches().await == 1, "ended early");
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(signer.running_batches().await == 0, "still running");
    ensure!(progress.borrow().ended == Some(Ended::TimeUp));
    // The watcher stays until the tool closes the batch.
    ensure!(!watcher.is_finished());
    ensure!(signer.close_batch(id).await == Some((0, Some(Ended::TimeUp))));
    tokio::time::timeout(Duration::from_secs(5), watcher)
        .await
        .context("the watcher outlived its batch")??;
    Ok(())
}
