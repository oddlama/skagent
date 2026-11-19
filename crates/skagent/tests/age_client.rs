//! What the command line prints for an identity, and how the sockets
//! systemd passes are told apart.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::os::unix::net::UnixListener;

use anyhow::{Context as _, Result, ensure};
use skagent::client::identity_file;
use skagent::serve::{AGE_SOCKET_NAME, Activated};
use skagent_age::{Identity, Seed};
use skagent_fds::Passed;

#[test]
fn an_identity_file_names_its_recipient_twice() -> Result<()> {
    let recipient = Seed::from_bytes(&[1; 32])?.recipient()?;
    let file = identity_file(&recipient);
    let lines: Vec<&str> = file.lines().collect();
    let [comment, in_words, identity] = lines.as_slice() else {
        anyhow::bail!("{} lines", lines.len());
    };
    ensure!(file.ends_with('\n'));
    // For people, and for tools that read the recipient from a comment.
    ensure!(
        comment.starts_with("# ") && comment.contains("no secret"),
        "{comment}"
    );
    ensure!(*in_words == format!("# Recipient: {recipient}"));
    // For age: the identity, which carries the recipient itself.
    ensure!(identity.parse::<Identity>()? == Identity::Named(recipient));
    Ok(())
}

fn passed(directory: &tempfile::TempDir, file: &str, name: Option<&str>) -> Result<Passed> {
    Ok(Passed {
        name: name.map(str::to_owned),
        listener: UnixListener::bind(directory.path().join(file))?,
    })
}

#[test]
fn the_socket_named_age_is_for_age_requests_and_any_other_is_the_ssh_agents() -> Result<()> {
    let directory = tempfile::tempdir()?;
    ensure!(AGE_SOCKET_NAME == "age");
    let none = Activated::from_passed(Vec::new())?;
    ensure!(none.ssh.is_none() && none.age.is_none());

    for name in [None, Some("skagent.socket"), Some("ssh")] {
        let one = Activated::from_passed(vec![passed(&directory, "one.sock", name)?])?;
        ensure!(one.ssh.is_some() && one.age.is_none(), "{name:?}");
        std::fs::remove_file(directory.path().join("one.sock"))?;
    }

    // In either order.
    for order in [[Some("skagent.socket"), Some("age")], [Some("age"), None]] {
        let sockets = vec![
            passed(&directory, "first.sock", *order.first().context("first")?)?,
            passed(&directory, "second.sock", *order.get(1).context("second")?)?,
        ];
        let both = Activated::from_passed(sockets)?;
        let age = both.age.context("no socket for age requests")?;
        let expected = if order.first() == Some(&Some("age")) {
            "first.sock"
        } else {
            "second.sock"
        };
        ensure!(age.local_addr()?.as_pathname() == Some(directory.path().join(expected).as_path()));
        ensure!(both.ssh.is_some());
        std::fs::remove_file(directory.path().join("first.sock"))?;
        std::fs::remove_file(directory.path().join("second.sock"))?;
    }
    Ok(())
}

#[test]
fn two_sockets_of_one_kind_or_age_alone_are_refused() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let two_ssh = vec![
        passed(&directory, "a.sock", Some("skagent.socket"))?,
        passed(&directory, "b.sock", None)?,
    ];
    ensure!(
        Activated::from_passed(two_ssh).is_err(),
        "two ssh-agent sockets"
    );
    let two_age = vec![
        passed(&directory, "c.sock", Some("age"))?,
        passed(&directory, "d.sock", Some("age"))?,
    ];
    ensure!(
        Activated::from_passed(two_age).is_err(),
        "two sockets for age requests"
    );
    let alone = vec![passed(&directory, "e.sock", Some("age"))?];
    ensure!(
        Activated::from_passed(alone).is_err(),
        "no ssh-agent socket"
    );
    Ok(())
}
