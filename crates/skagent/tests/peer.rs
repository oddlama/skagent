//! Who is at the other end of a connection: which program, and what
//! started it.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use skagent::peer::{FileId, OwnPrograms, PLUGIN_BINARY, Peer, Program, parse_stat, requester};
use tokio::net::UnixStream;

#[test]
fn the_plugin_is_called_what_age_looks_for() {
    assert_eq!(PLUGIN_BINARY, "age-plugin-skagent");
}

#[test]
fn a_file_is_itself_under_any_path_and_no_other() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("program");
    let link = directory.path().join("link");
    let symlink = directory.path().join("symlink");
    let copy = directory.path().join("copy");
    std::fs::write(&file, "x")?;
    std::fs::hard_link(&file, &link)?;
    std::os::unix::fs::symlink(&file, &symlink)?;
    std::fs::copy(&file, &copy)?;
    let id = FileId::of(&file)?;
    ensure!(FileId::of(&link)? == id && FileId::of(&symlink)? == id);
    ensure!(FileId::of(&copy)? != id, "a copy is another file");
    ensure!(FileId::of(&directory.path().join("missing")).is_err());
    Ok(())
}

#[test]
fn a_peer_is_one_of_ours_only_by_its_executable() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut ids = Vec::new();
    for name in ["agent", "plugin", "other"] {
        let path = directory.path().join(name);
        std::fs::write(&path, name)?;
        ids.push(FileId::of(&path)?);
    }
    let [agent, plugin, other] = ids.as_slice() else {
        anyhow::bail!("three files");
    };
    let own = OwnPrograms::new(*agent, Some(*plugin));
    ensure!(own.has_plugin());
    ensure!(own.program(*agent) == Program::Agent);
    ensure!(own.program(*plugin) == Program::Plugin);
    ensure!(own.program(*other) == Program::Other);

    let without = OwnPrograms::new(*agent, None);
    ensure!(!without.has_plugin());
    ensure!(without.program(*plugin) == Program::Other);
    Ok(())
}

#[test]
fn the_agents_own_programs_are_found_next_to_it() -> Result<()> {
    let own = OwnPrograms::locate()?;
    ensure!(own.program(FileId::of(Path::new("/proc/self/exe"))?) == Program::Agent);
    ensure!(own.plugin_path().file_name() == Some(PLUGIN_BINARY.as_ref()));
    ensure!(own.plugin_path().parent() == std::env::current_exe()?.parent());
    Ok(())
}

#[tokio::test]
async fn the_peer_of_a_connection_is_looked_up_by_its_pid() -> Result<()> {
    let this = FileId::of(Path::new("/proc/self/exe"))?;
    let directory = tempfile::tempdir()?;
    let stranger = directory.path().join("stranger");
    std::fs::write(&stranger, "x")?;
    let stranger = FileId::of(&stranger)?;

    // Both ends of a socket pair are this process.
    let (ours, _theirs) = UnixStream::pair()?;
    let peer = Peer::inspect(&ours, &OwnPrograms::new(this, None))?;
    ensure!(peer.pid() == std::process::id());
    ensure!(peer.program() == Program::Agent);
    ensure!(
        Peer::inspect(&ours, &OwnPrograms::new(stranger, Some(this)))?.program() == Program::Plugin
    );
    ensure!(Peer::inspect(&ours, &OwnPrograms::new(stranger, None))?.program() == Program::Other);

    // What started what started this process has a name.
    let started_by = peer.started_by().context("no parents")?;
    ensure!(!started_by.is_empty());
    Ok(())
}

#[test]
fn a_process_is_named_and_placed_by_its_stat_line() {
    assert_eq!(
        parse_stat("4242 (age) S 4100 4242 4100 34816 4242 4194304 100 0"),
        Some(("age".to_owned(), 4100))
    );
    // The name is whatever the program calls itself: spaces and parentheses
    // included. It ends at the last one.
    assert_eq!(
        parse_stat("7 (a) b) (c) R 1 7 7 0"),
        Some(("a) b) (c".to_owned(), 1))
    );
    assert_eq!(parse_stat("7 () Z 3 7"), Some((String::new(), 3)));
    for malformed in [
        "",
        "7",
        "7 age S 1",
        "7 (age)",
        "7 (age) S",
        "7 (age) S x",
        "7 (age S 1",
    ] {
        assert_eq!(parse_stat(malformed), None, "{malformed:?}");
    }
}

#[test]
fn a_request_comes_from_what_started_age_unless_that_only_launches() {
    assert_eq!(requester("age", Some("agenix")), "agenix");
    assert_eq!(
        requester("rage", Some(".agenix-rekey-wrapped")),
        ".agenix-rekey-wrapped"
    );
    for launcher in [
        "bash", "sh", "zsh", "fish", "nu", "su", "sudo", "env", "systemd",
    ] {
        assert_eq!(requester("age", Some(launcher)), "age", "{launcher}");
    }
    assert_eq!(requester("rage", None), "rage");
}
