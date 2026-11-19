//! Proving that a process descends from another: against a scripted process
//! table in which pids change hands at every possible moment, and against
//! real processes.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use rustix::process::{Signal, getpid, pidfd_send_signal, set_child_subreaper};
use skagent::ancestry::{MAX_GENERATIONS, NotProven, Pinned, Proc, Processes, descends};

/// One process of the scripted table: which one it is (no two ever share
/// that), and its parent's pid.
#[derive(Debug, Clone, Copy)]
struct Process {
    identity: u64,
    parent: u32,
}

/// What happens to the table before one of its answers.
type Event = Box<dyn Fn(&mut HashMap<u32, Process>)>;

/// A process table that changes while it is asked: `events` happen right
/// before the answer with that number.
#[derive(Default)]
struct Table {
    processes: RefCell<HashMap<u32, Process>>,
    events: RefCell<HashMap<usize, Event>>,
    asked: Cell<usize>,
}

impl Table {
    fn of(processes: &[(u32, u64, u32)]) -> Self {
        let table = Self::default();
        for &(pid, identity, parent) in processes {
            table
                .processes
                .borrow_mut()
                .insert(pid, Process { identity, parent });
        }
        table
    }

    fn before_answer(self, number: usize, event: Event) -> Self {
        self.events.borrow_mut().insert(number, event);
        self
    }

    fn tick(&self) {
        let number = self.asked.get();
        self.asked.set(number.saturating_add(1));
        if let Some(event) = self.events.borrow().get(&number) {
            event(&mut self.processes.borrow_mut());
        }
    }
}

impl Processes for Table {
    type Pinned = u64;

    fn parent_of(&self, pid: u32) -> Option<u32> {
        self.tick();
        self.processes
            .borrow()
            .get(&pid)
            .map(|process| process.parent)
    }

    fn pin(&self, pid: u32) -> Option<u64> {
        self.tick();
        self.processes
            .borrow()
            .get(&pid)
            .map(|process| process.identity)
    }

    fn exists(&self, pinned: &u64) -> bool {
        self.tick();
        self.processes
            .borrow()
            .values()
            .any(|process| process.identity == *pinned)
    }
}

/// The batch tool as pid 10, identity 110.
const TOOL: Pinned<'static, u64> = Pinned { pid: 10, pin: &110 };
/// The process asking as pid 30, identity 130.
const ASKING: Pinned<'static, u64> = Pinned { pid: 30, pin: &130 };

#[test]
fn a_descendant_is_proven_through_any_number_of_parents() -> Result<()> {
    // The tool's child, and its grandchild.
    let child = Table::of(&[(1, 101, 0), (10, 110, 1), (30, 130, 10)]);
    ensure!(descends(&child, ASKING, TOOL) == Ok(()));
    let grandchild = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 10), (30, 130, 20)]);
    ensure!(descends(&grandchild, ASKING, TOOL) == Ok(()));

    // As many parents as are looked at, and one more.
    let line = |parents: usize| -> Result<Table> {
        let mut processes = vec![(1, 101, 0), (10, 110, 1)];
        let mut parent = 10_u32;
        for step in 0..parents.saturating_sub(1) {
            let pid = 1000_u32.saturating_add(u32::try_from(step)?);
            processes.push((pid, u64::from(pid), parent));
            parent = pid;
        }
        processes.push((30, 130, parent));
        Ok(Table::of(&processes))
    };
    ensure!(descends(&line(MAX_GENERATIONS)?, ASKING, TOOL) == Ok(()));
    ensure!(
        descends(&line(MAX_GENERATIONS.saturating_add(1))?, ASKING, TOOL)
            == Err(NotProven::TooDeep)
    );
    Ok(())
}

#[test]
fn what_is_not_a_descendant_is_not_proven() -> Result<()> {
    // Started by something else.
    let outside = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 1), (30, 130, 20)]);
    ensure!(descends(&outside, ASKING, TOOL) == Err(NotProven::Outside));
    // The parent can't be seen from here (another pid namespace).
    let no_parent = Table::of(&[(10, 110, 1), (30, 130, 0)]);
    ensure!(descends(&no_parent, ASKING, TOOL) == Err(NotProven::Outside));
    // The tool's parent doesn't descend from the tool.
    let parent = Table::of(&[(1, 101, 0), (30, 130, 1), (10, 110, 30)]);
    ensure!(descends(&parent, ASKING, TOOL) == Err(NotProven::Outside));
    // Nor does the tool itself.
    let alone = Table::of(&[(1, 101, 0), (10, 110, 1)]);
    ensure!(descends(&alone, TOOL, TOOL) == Err(NotProven::Outside));

    // The tool is gone, and another process has its pid.
    let reused = Table::of(&[(1, 101, 0), (10, 999, 1), (30, 130, 10)]);
    ensure!(descends(&reused, ASKING, TOOL) == Err(NotProven::AncestorGone));
    // The process asking is gone, and another one has its pid.
    let replaced = Table::of(&[(1, 101, 0), (10, 110, 1), (30, 999, 10)]);
    ensure!(descends(&replaced, ASKING, TOOL) == Err(NotProven::Gone(30)));
    // A parent that can't be inspected.
    let hidden = Table::of(&[(1, 101, 0), (10, 110, 1), (30, 130, 20)]);
    ensure!(descends(&hidden, ASKING, TOOL) == Err(NotProven::Hidden(20)));
    Ok(())
}

/// How many answers a proof asks the table for at most in these tests.
const ANSWERS: usize = 40;

#[test]
fn a_pid_changing_hands_never_makes_an_outsider_a_descendant() -> Result<()> {
    // The process asking was started by 20, which the tool didn't start.
    // At some moment 20 exits, the process asking goes to the first
    // process, and a child of the tool gets the pid 20.
    for moment in 0..ANSWERS {
        let table = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 1), (30, 130, 20)])
            .before_answer(
                moment,
                Box::new(|processes| {
                    processes.insert(
                        20,
                        Process {
                            identity: 220,
                            parent: 10,
                        },
                    );
                    if let Some(asking) = processes.get_mut(&30) {
                        asking.parent = 1;
                    }
                }),
            );
        let proven = descends(&table, ASKING, TOOL);
        ensure!(proven.is_err(), "proven at moment {moment}");
        ensure!(table.asked.get() < ANSWERS, "more answers than tried");
    }
    Ok(())
}

#[test]
fn the_pid_of_the_process_asking_changing_hands_proves_nothing() -> Result<()> {
    // The process asking, an outsider, exits, and a child of the tool gets
    // its pid.
    for moment in 0..ANSWERS {
        let table = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 1), (30, 130, 20)])
            .before_answer(
                moment,
                Box::new(|processes| {
                    processes.insert(
                        30,
                        Process {
                            identity: 230,
                            parent: 10,
                        },
                    );
                }),
            );
        ensure!(
            descends(&table, ASKING, TOOL).is_err(),
            "proven at moment {moment}"
        );
    }
    Ok(())
}

#[test]
fn the_pid_of_the_tool_changing_hands_proves_nothing() -> Result<()> {
    // The tool exits, and the outsider that started the process asking
    // gets its pid.
    for moment in 0..ANSWERS {
        let table = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 1), (30, 130, 20)])
            .before_answer(
                moment,
                Box::new(|processes| {
                    processes.remove(&20);
                    processes.insert(
                        10,
                        Process {
                            identity: 210,
                            parent: 1,
                        },
                    );
                    if let Some(asking) = processes.get_mut(&30) {
                        asking.parent = 10;
                    }
                }),
            );
        ensure!(
            descends(&table, ASKING, TOOL).is_err(),
            "proven at moment {moment}"
        );
    }
    Ok(())
}

#[test]
fn a_descendant_whose_parent_exits_meanwhile_stays_one_or_asks_again() -> Result<()> {
    // The tool adopts what its children leave behind. A proof that sees the
    // change may give up, never more.
    let mut proven = 0_usize;
    for moment in 0..ANSWERS {
        let table = Table::of(&[(1, 101, 0), (10, 110, 1), (20, 120, 10), (30, 130, 20)])
            .before_answer(
                moment,
                Box::new(|processes| {
                    processes.remove(&20);
                    if let Some(asking) = processes.get_mut(&30) {
                        asking.parent = 10;
                    }
                }),
            );
        match descends(&table, ASKING, TOOL) {
            Ok(()) => proven = proven.saturating_add(1),
            Err(NotProven::Gone(20) | NotProven::Reparented(30) | NotProven::Hidden(20)) => {}
            Err(other) => bail!("at moment {moment}: {other}"),
        }
    }
    // Before the proof starts, and after it ended.
    ensure!(proven >= 2, "never proven");
    Ok(())
}

/// A pidfd of the process `pid`, which is one of ours.
fn pin(pid: u32) -> Result<std::os::fd::OwnedFd> {
    Proc.pin(pid)
        .with_context(|| format!("taking a pidfd of process {pid}"))
}

/// Waits until `done` holds, for a few seconds.
fn eventually(what: &str, done: impl Fn() -> bool) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .context("a deadline")?;
    while !done() {
        ensure!(Instant::now() < deadline, "never happened: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Runs `script` with a shell and returns it with the pid it prints first.
fn shell_printing_a_pid(script: &str) -> Result<(std::process::Child, u32)> {
    let mut shell = Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .context("running sh")?;
    let mut line = String::new();
    BufReader::new(shell.stdout.take().context("the shell's stdout")?)
        .read_line(&mut line)
        .context("reading the pid the shell prints")?;
    let pid = line.trim().parse().context("the shell printed no pid")?;
    Ok((shell, pid))
}

#[test]
fn real_processes_descend_from_those_that_started_them() -> Result<()> {
    let me = std::process::id();
    let my_pin = pin(me)?;
    let myself = Pinned {
        pid: me,
        pin: &my_pin,
    };
    // A shell that starts a process and waits for it.
    let (mut shell, grandchild) = shell_printing_a_pid("sleep 60 >/dev/null & echo $!; wait")?;
    let shell_pin = pin(shell.id())?;
    let grandchild_pin = pin(grandchild)?;
    let child = Pinned {
        pid: shell.id(),
        pin: &shell_pin,
    };
    let grandchild = Pinned {
        pid: grandchild,
        pin: &grandchild_pin,
    };

    ensure!(descends(&Proc, child, myself) == Ok(()));
    ensure!(descends(&Proc, grandchild, myself) == Ok(()));
    ensure!(descends(&Proc, grandchild, child) == Ok(()));
    ensure!(descends(&Proc, child, grandchild) == Err(NotProven::Outside));
    ensure!(descends(&Proc, myself, child) == Err(NotProven::Outside));
    ensure!(descends(&Proc, myself, myself) == Err(NotProven::Outside));

    // Once they are gone, their pids prove nothing any more.
    pidfd_send_signal(&grandchild_pin, Signal::KILL).context("ending the grandchild")?;
    shell.wait().context("waiting for the shell")?;
    eventually("the grandchild is gone", || !Proc.exists(&grandchild_pin))?;
    ensure!(descends(&Proc, grandchild, myself) == Err(NotProven::Hidden(grandchild.pid)));
    ensure!(descends(&Proc, grandchild, child).is_err());
    ensure!(!Proc.exists(&shell_pin), "an ended process still exists");
    Ok(())
}

#[test]
fn what_a_child_leaves_behind_still_descends_from_a_subreaper() -> Result<()> {
    let me = std::process::id();
    let my_pin = pin(me)?;
    let myself = Pinned {
        pid: me,
        pin: &my_pin,
    };
    // Like `skagent batch`: what the children of this process leave behind
    // is handed to it, not to the first process.
    set_child_subreaper(Some(getpid())).context("becoming a child subreaper")?;
    let (mut shell, orphan) = shell_printing_a_pid("sleep 60 >/dev/null & echo $!")?;
    let orphan_pin = pin(orphan)?;
    shell.wait().context("waiting for the shell")?;
    eventually("the orphan is handed to this process", || {
        Proc.parent_of(orphan) == Some(me)
    })?;
    let orphan = Pinned {
        pid: orphan,
        pin: &orphan_pin,
    };
    let proven = descends(&Proc, orphan, myself);
    pidfd_send_signal(&orphan_pin, Signal::KILL).context("ending the orphan")?;
    set_child_subreaper(None).context("no longer a child subreaper")?;
    ensure!(proven == Ok(()), "{proven:?}");
    Ok(())
}
