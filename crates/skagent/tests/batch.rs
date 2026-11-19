//! Batches as a state machine: who is a member, what a batch keeps and
//! serves, and every way it ends. Time and processes are scripted.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use skagent::ancestry::{Pinned, Processes};
use skagent::batch::{Batches, Ended, MAX_BATCHES, Opened, Progress, Served};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::CredentialKey;
use skagent_age::{FileKey, Recipient, Seed, Stanza};

/// Processes by pid: which one it is (never shared), and its parent's pid.
#[derive(Clone, Default)]
struct Table(Rc<RefCell<HashMap<u32, (u64, u32)>>>);

impl Table {
    /// The first process, a batch tool (10) with a child (20) and a
    /// grandchild (30), and a process started by something else (40).
    fn usual() -> Self {
        let table = Self::default();
        for (pid, parent) in [(1, 0), (10, 1), (20, 10), (30, 20), (40, 1)] {
            table.start(pid, parent);
        }
        table
    }

    fn start(&self, pid: u32, parent: u32) {
        self.0
            .borrow_mut()
            .insert(pid, (u64::from(pid).saturating_add(100), parent));
    }

    /// Another process gets `pid`.
    fn reuse(&self, pid: u32, parent: u32) {
        self.0
            .borrow_mut()
            .insert(pid, (u64::from(pid).saturating_add(900), parent));
    }

    fn exit(&self, pid: u32) {
        self.0.borrow_mut().remove(&pid);
    }
}

impl Processes for Table {
    type Pinned = u64;

    fn parent_of(&self, pid: u32) -> Option<u32> {
        self.0.borrow().get(&pid).map(|(_, parent)| *parent)
    }

    fn pin(&self, pid: u32) -> Option<u64> {
        self.0.borrow().get(&pid).map(|(identity, _)| *identity)
    }

    fn exists(&self, pinned: &u64) -> bool {
        self.0
            .borrow()
            .values()
            .any(|(identity, _)| identity == pinned)
    }
}

/// The process `pid` of [`Table::usual`], pinned.
fn process(pid: u32) -> (u32, u64) {
    (pid, u64::from(pid).saturating_add(100))
}

/// Whether the process `pid` is a member of a batch, and of which command's.
fn member_of(batches: &mut Batches<Table>, pid: u32, now: Instant) -> Option<String> {
    let (pid, pin) = process(pid);
    batches
        .member(Pinned { pid, pin: &pin }, now)
        .map(|member| member.command)
}

const LIMIT: Duration = Duration::from_mins(10);

fn open(batches: &mut Batches<Table>, tool: u32, now: Instant) -> Result<Opened> {
    batches.open(
        process(tool),
        format!("command of {tool}"),
        Duration::ZERO,
        now,
    )
}

fn credential(byte: u8) -> CredentialKey {
    CredentialKey::new("skagent:age", &[byte; 32])
}

fn seed(byte: u8) -> Result<Seed> {
    Seed::from_bytes(&[byte; 32])
}

fn device(inode: u64) -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw0", 1, inode, (0, 0))
}

/// A file key, and the stanza that wraps it for the identity of `seed`.
fn file_for(seed: &Seed, byte: u8) -> Result<(FileKey, Stanza)> {
    let file_key = FileKey::from_bytes(&[byte; 16])?;
    let stanza = seed.recipient()?.wrap(&file_key, &[byte; 64])?;
    Ok((file_key, stanza))
}

/// Keeps the seed `byte` for the credential `byte`, derived on `device(1)`.
fn keep(batches: &mut Batches<Table>, opened: &Opened, byte: u8, now: Instant) -> Result<bool> {
    let seed = seed(byte)?;
    let recipient = seed.recipient()?;
    batches.keep(
        opened.id,
        credential(byte),
        (&seed, recipient),
        device(1),
        true,
        now,
    )
}

/// What the batch answers a request for the credential `byte` with one
/// stanza, with every security key plugged in.
fn ask(
    batches: &mut Batches<Table>,
    opened: &Opened,
    byte: u8,
    named: Option<&Recipient>,
    stanza: &Stanza,
    now: Instant,
) -> Result<Served> {
    batches.unwrap(
        opened.id,
        &credential(byte),
        named,
        std::slice::from_ref(stanza),
        now,
        |_| true,
    )
}

fn later(now: Instant, seconds: u64) -> Result<Instant> {
    now.checked_add(Duration::from_secs(seconds))
        .context("a later time")
}

#[test]
fn a_batch_lasts_what_was_asked_but_never_longer_than_allowed() -> Result<()> {
    let now = Instant::now();
    let mut batches = Batches::new(Table::usual(), LIMIT);
    ensure!(batches.limit() == LIMIT && batches.is_empty());
    let whole = batches.open(process(10), "a".to_owned(), Duration::ZERO, now)?;
    ensure!(whole.lasts == LIMIT && whole.deadline == later(now, 600)?);
    ensure!(whole.command == "a");
    let shorter = batches.open(process(10), "b".to_owned(), Duration::from_mins(1), now)?;
    ensure!(shorter.lasts == Duration::from_mins(1) && shorter.deadline == later(now, 60)?);
    let longer = batches.open(process(10), "c".to_owned(), Duration::from_hours(2), now)?;
    ensure!(longer.lasts == LIMIT, "longer than allowed");
    ensure!(whole.id != shorter.id && shorter.id != longer.id);
    ensure!(batches.len() == 3 && batches.running() == 3 && batches.seeds() == 0);

    // A process that is gone gets none, nor does anyone with a limit of zero.
    ensure!(
        batches
            .open((50, 150), "gone".to_owned(), Duration::ZERO, now)
            .is_err()
    );
    batches.set_limit(Duration::ZERO);
    ensure!(
        open(&mut batches, 10, now).is_err(),
        "opened with batches turned off"
    );
    Ok(())
}

#[test]
fn there_are_only_so_many_batches_at_once() -> Result<()> {
    let now = Instant::now();
    let mut batches = Batches::new(Table::usual(), LIMIT);
    let mut opened = Vec::new();
    for _ in 0..MAX_BATCHES {
        opened.push(open(&mut batches, 10, now)?);
    }
    ensure!(open(&mut batches, 10, now).is_err(), "one too many");
    // An ended one still counts until its tool is gone.
    let first = opened.first().context("a batch")?;
    ensure!(batches.end(first.id, Ended::Stopped));
    ensure!(open(&mut batches, 10, now).is_err());
    ensure!(batches.close(first.id) == Some((0, Some(Ended::Stopped))));
    ensure!(batches.close(first.id).is_none(), "closed twice");
    open(&mut batches, 10, now)?;
    Ok(())
}

#[test]
fn members_are_what_the_tool_started() -> Result<()> {
    let now = Instant::now();
    let table = Table::usual();
    let mut batches = Batches::new(table.clone(), LIMIT);
    ensure!(
        member_of(&mut batches, 30, now).is_none(),
        "a member of no batch"
    );
    let opened = open(&mut batches, 10, now)?;
    for pid in [20, 30] {
        ensure!(member_of(&mut batches, pid, now).as_deref() == Some("command of 10"));
    }
    ensure!(
        member_of(&mut batches, 40, now).is_none(),
        "an outsider is a member"
    );
    ensure!(
        member_of(&mut batches, 10, now).is_none(),
        "the tool is its own member"
    );
    ensure!(member_of(&mut batches, 1, now).is_none());

    // How long the batch still lasts is told with it.
    let (pid, pin) = process(30);
    let member = batches
        .member(Pinned { pid, pin: &pin }, later(now, 100)?)
        .context("a member")?;
    ensure!(member.id == opened.id && member.remaining == Duration::from_secs(500));

    // Of two batches around a process, the inner one is its own.
    let inner = open(&mut batches, 20, now)?;
    ensure!(member_of(&mut batches, 30, now).as_deref() == Some("command of 20"));
    ensure!(member_of(&mut batches, 20, now).as_deref() == Some("command of 10"));
    // An ended batch has no members; the one around it still does.
    ensure!(batches.end(inner.id, Ended::Stopped));
    ensure!(member_of(&mut batches, 30, now).as_deref() == Some("command of 10"));

    // A process that got a member's pid isn't one.
    table.exit(30);
    table.reuse(30, 20);
    ensure!(member_of(&mut batches, 30, now).is_none(), "by pid alone");
    Ok(())
}

#[test]
fn the_seed_of_the_first_request_serves_the_following() -> Result<()> {
    let now = Instant::now();
    let mut batches = Batches::new(Table::usual(), LIMIT);
    let opened = open(&mut batches, 10, now)?;
    let (file_key, stanza) = file_for(&seed(7)?, 1)?;

    // Nothing is kept before a request derived it.
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, now)?,
        Served::NotKept
    ));
    ensure!(batches.seeds() == 0);
    ensure!(keep(&mut batches, &opened, 7, now)?);
    ensure!(batches.seeds() == 1);
    ensure!(
        *opened.progress.borrow()
            == Progress {
                files: 1,
                ended: None
            }
    );

    let Served::FileKey(Some(unwrapped)) = ask(&mut batches, &opened, 7, None, &stanza, now)?
    else {
        bail!("not served from the kept seed");
    };
    ensure!(unwrapped.expose() == file_key.expose());
    ensure!(opened.progress.borrow().files == 2);

    // A file for somebody else isn't opened, and doesn't count.
    let (_, foreign) = file_for(&seed(8)?, 2)?;
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &foreign, now)?,
        Served::FileKey(None)
    ));
    ensure!(opened.progress.borrow().files == 2);

    // A request that names its identity gets that one or nothing.
    let own = seed(7)?.recipient()?;
    let other = seed(8)?.recipient()?;
    ensure!(matches!(
        ask(&mut batches, &opened, 7, Some(&own), &stanza, now)?,
        Served::FileKey(Some(_))
    ));
    ensure!(matches!(
        ask(&mut batches, &opened, 7, Some(&other), &stanza, now)?,
        Served::AnotherIdentity
    ));
    ensure!(opened.progress.borrow().files == 3);

    // Another identity has no seed here, and another batch doesn't have
    // this one's.
    ensure!(matches!(
        ask(&mut batches, &opened, 8, None, &foreign, now)?,
        Served::NotKept
    ));
    let second = open(&mut batches, 10, now)?;
    ensure!(matches!(
        ask(&mut batches, &second, 7, None, &stanza, now)?,
        Served::NotKept
    ));
    Ok(())
}

/// A batch that keeps the seed 7, and a stanza for it.
fn kept(table: &Table, now: Instant) -> Result<(Batches<Table>, Opened, Stanza)> {
    let mut batches = Batches::new(table.clone(), LIMIT);
    let opened = open(&mut batches, 10, now)?;
    ensure!(keep(&mut batches, &opened, 7, now)?);
    let (_, stanza) = file_for(&seed(7)?, 1)?;
    Ok((batches, opened, stanza))
}

/// The batch is over for `reason`: its seed is wiped, and it serves, keeps
/// and has nothing any more, whatever the time and the processes.
fn over(
    batches: &mut Batches<Table>,
    opened: &Opened,
    stanza: &Stanza,
    reason: Ended,
    now: Instant,
) -> Result<()> {
    ensure!(batches.seeds() == 0, "{reason}: the seed is still kept");
    ensure!(batches.running() == 0, "{reason}: still running");
    ensure!(
        opened.progress.borrow().ended == Some(reason),
        "{reason}: told {:?}",
        opened.progress.borrow().ended
    );
    ensure!(
        matches!(ask(batches, opened, 7, None, stanza, now)?, Served::NotKept),
        "{reason}: served"
    );
    ensure!(
        !keep(batches, opened, 7, now)?,
        "{reason}: kept a seed again"
    );
    ensure!(batches.seeds() == 0);
    ensure!(
        member_of(batches, 30, now).is_none(),
        "{reason}: has members"
    );
    ensure!(
        !batches.end(opened.id, Ended::Stopped),
        "{reason}: ended twice"
    );
    ensure!(
        opened.progress.borrow().ended == Some(reason),
        "the reason changed"
    );
    Ok(())
}

#[test]
fn a_batch_is_over_when_its_time_is_up() -> Result<()> {
    let now = Instant::now();
    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, later(now, 599)?)?,
        Served::FileKey(Some(_))
    ));
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, later(now, 600)?)?,
        Served::NotKept
    ));
    // Not even at an earlier time again.
    over(&mut batches, &opened, &stanza, Ended::TimeUp, now)?;

    // Asking who is a member notices it too, and so does keeping.
    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    ensure!(member_of(&mut batches, 30, later(now, 600)?).is_none());
    over(&mut batches, &opened, &stanza, Ended::TimeUp, now)?;
    let mut batches = Batches::new(Table::usual(), LIMIT);
    let opened = open(&mut batches, 10, now)?;
    ensure!(
        !keep(&mut batches, &opened, 7, later(now, 600)?)?,
        "kept after the time"
    );
    ensure!(opened.progress.borrow().ended == Some(Ended::TimeUp));
    Ok(())
}

#[test]
fn a_batch_is_over_when_its_tool_is_gone() -> Result<()> {
    let now = Instant::now();
    let table = Table::usual();
    let (mut batches, opened, stanza) = kept(&table, now)?;
    table.exit(10);
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, now)?,
        Served::NotKept
    ));
    // Not even for a process that got the tool's pid.
    table.reuse(10, 1);
    over(&mut batches, &opened, &stanza, Ended::ToolGone, now)?;

    let table = Table::usual();
    let (mut batches, opened, stanza) = kept(&table, now)?;
    table.exit(10);
    ensure!(member_of(&mut batches, 30, now).is_none());
    over(&mut batches, &opened, &stanza, Ended::ToolGone, now)?;

    let table = Table::usual();
    let mut batches = Batches::new(table.clone(), LIMIT);
    let opened = open(&mut batches, 10, now)?;
    table.exit(10);
    ensure!(
        !keep(&mut batches, &opened, 7, now)?,
        "kept for a tool that is gone"
    );
    Ok(())
}

#[test]
fn a_batch_is_over_when_the_security_key_is_unplugged() -> Result<()> {
    let now = Instant::now();
    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    let asked = std::cell::Cell::new(None);
    let served = batches.unwrap(
        opened.id,
        &credential(7),
        None,
        std::slice::from_ref(&stanza),
        now,
        |device| {
            asked.set(Some(device.clone() == self::device(1)));
            false
        },
    )?;
    ensure!(matches!(served, Served::NotKept));
    ensure!(
        asked.take() == Some(true),
        "not asked about the seed's security key"
    );
    // Plugged in again, it is another plug-in: the batch stays over.
    over(&mut batches, &opened, &stanza, Ended::Unplugged, now)?;
    Ok(())
}

#[test]
fn a_batch_is_over_when_it_is_stopped_or_pins_are_evicted() -> Result<()> {
    let now = Instant::now();
    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    ensure!(batches.end(opened.id, Ended::Stopped));
    over(&mut batches, &opened, &stanza, Ended::Stopped, now)?;

    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    let second = open(&mut batches, 10, now)?;
    ensure!(batches.end_all(Ended::PinsEvicted) == 2);
    ensure!(second.progress.borrow().ended == Some(Ended::PinsEvicted));
    over(&mut batches, &opened, &stanza, Ended::PinsEvicted, now)?;
    ensure!(batches.end_all(Ended::PinsEvicted) == 0);
    Ok(())
}

#[test]
fn the_sweep_ends_batches_nobody_asks() -> Result<()> {
    let now = Instant::now();
    let present = |_: &DeviceIdentity| true;

    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    ensure!(batches.sweep(later(now, 599)?, present).is_empty());
    ensure!(batches.seeds() == 1, "swept a running batch");
    ensure!(batches.sweep(later(now, 600)?, present) == vec![(opened.id, Ended::TimeUp)]);
    over(&mut batches, &opened, &stanza, Ended::TimeUp, now)?;
    ensure!(
        batches.sweep(later(now, 700)?, present).is_empty(),
        "swept twice"
    );

    let table = Table::usual();
    let (mut batches, opened, stanza) = kept(&table, now)?;
    table.exit(10);
    ensure!(batches.sweep(now, present) == vec![(opened.id, Ended::ToolGone)]);
    over(&mut batches, &opened, &stanza, Ended::ToolGone, now)?;

    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    // A batch without a seed doesn't mind which security keys are there.
    let without = open(&mut batches, 10, now)?;
    ensure!(
        batches.sweep(now, |device| *device != self::device(1))
            == vec![(opened.id, Ended::Unplugged)]
    );
    ensure!(without.progress.borrow().ended.is_none());
    ensure!(batches.end(without.id, Ended::Stopped));
    over(&mut batches, &opened, &stanza, Ended::Unplugged, now)?;
    Ok(())
}

#[test]
fn closing_a_batch_drops_its_seed_and_tells_how_it_went() -> Result<()> {
    let now = Instant::now();
    let (mut batches, opened, stanza) = kept(&Table::usual(), now)?;
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, now)?,
        Served::FileKey(Some(_))
    ));
    ensure!(batches.close(opened.id) == Some((2, None)));
    ensure!(batches.is_empty() && batches.seeds() == 0);
    ensure!(matches!(
        ask(&mut batches, &opened, 7, None, &stanza, now)?,
        Served::NotKept
    ));
    ensure!(!keep(&mut batches, &opened, 7, now)?);
    ensure!(member_of(&mut batches, 30, now).is_none());
    // Whoever shows the batch learns that it is gone.
    ensure!(
        opened.progress.has_changed().is_err(),
        "the progress is still open"
    );
    Ok(())
}
