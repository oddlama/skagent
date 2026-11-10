//! The Assuan client, against scripted fake pinentry programs.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use skagent::pinentry::{Dialog, Pinentry, decode_data, escape};
use skagent::prompt::{PinPrompt, PinRequest};
use skagent_secret::SecretBuffer;

/// A pinentry that logs every command it gets and answers GETPIN with `getpin`.
fn fake_pinentry(dir: &Path, greeting: &str, getpin: &str) -> Result<(PathBuf, PathBuf)> {
    let log = dir.join("commands");
    let path = dir.join("pinentry");
    let script = format!(
        r#"#!/bin/sh
echo '{greeting}'
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{log}'
  case "$line" in
    GETPIN) {getpin};;
    BYE) echo 'OK closing connection'; exit 0;;
    *) echo OK;;
  esac
done
"#,
        log = log.display()
    );
    fs::write(&path, script).context("writing fake pinentry")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .context("making it executable")?;
    Ok((path, log))
}

fn dialog(error: Option<&str>) -> Dialog<'_> {
    Dialog {
        title: "skagent",
        description: "line one\nline two 100%",
        prompt: "PIN:",
        error,
    }
}

async fn get_pin(program: PathBuf, error: Option<&str>) -> Result<SecretBuffer> {
    Pinentry::new(program).get_pin(&dialog(error)).await
}

#[tokio::test]
async fn the_dialog_is_set_up_and_the_answer_decoded() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let (program, log) = fake_pinentry(
        dir.path(),
        "OK Pleased to meet you",
        "echo 'S PROGRESS'; echo '# comment'; echo 'D 24%2568%0A10'; echo OK",
    )?;
    let answer = get_pin(program, None).await?;
    ensure!(answer.expose() == b"24%68\n10", "decoded wrong");

    let commands = fs::read_to_string(&log).context("reading command log")?;
    let expected = [
        "SETTITLE skagent",
        "SETDESC line one%0Aline two 100%25",
        "SETPROMPT PIN:",
        "GETPIN",
        "BYE",
    ];
    ensure!(
        commands.lines().collect::<Vec<_>>() == expected,
        "commands: {commands}"
    );
    Ok(())
}

#[tokio::test]
async fn an_error_is_shown_with_seterror() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let (program, log) = fake_pinentry(dir.path(), "OK", "echo 'D 123456'; echo OK")?;
    get_pin(program, Some("The previous PIN was wrong")).await?;
    let commands = fs::read_to_string(&log).context("reading command log")?;
    ensure!(
        commands.contains("SETERROR The previous PIN was wrong\nGETPIN"),
        "{commands}"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_is_an_error() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let (program, _) = fake_pinentry(
        dir.path(),
        "OK",
        "echo 'ERR 83886179 Operation cancelled <Pinentry>'",
    )?;
    let error = match get_pin(program, None).await {
        Ok(_) => bail!("cancelled dialog returned a PIN"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(error.contains("cancelled"), "{error}");
    Ok(())
}

#[tokio::test]
async fn protocol_violations_are_errors() -> Result<()> {
    let cases = [
        ("bad greeting", "HELLO", "echo OK"),
        ("quits during GETPIN", "OK", "exit 0"),
        ("bad escape", "OK", "echo 'D 12%G4'; echo OK"),
        ("truncated escape", "OK", "echo 'D 1234%4'; echo OK"),
        ("inquire", "OK", "echo 'INQUIRE QUALITY 1234'; echo OK"),
        (
            "overlong line",
            "OK",
            "printf 'D '; head -c 1100 /dev/zero | tr '\\0' 7; echo; echo OK",
        ),
    ];
    for (case, greeting, getpin) in cases {
        let dir = tempfile::tempdir().context("creating temp dir")?;
        let (program, _) = fake_pinentry(dir.path(), greeting, getpin)?;
        ensure!(get_pin(program, None).await.is_err(), "{case}: accepted");
    }
    let missing = Pinentry::new(PathBuf::from("/nonexistent/pinentry"));
    ensure!(
        missing.get_pin(&dialog(None)).await.is_err(),
        "missing program accepted"
    );
    Ok(())
}

#[tokio::test]
async fn the_pin_prompt_checks_the_pin_length() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let (short, _) = fake_pinentry(dir.path(), "OK", "echo 'D 123'; echo OK")?;
    let request = PinRequest {
        key: "work key",
        retries: Some(8),
        error: None,
    };
    ensure!(
        PinPrompt::Pinentry(Pinentry::new(short))
            .ask(&request)
            .await
            .is_err(),
        "3-byte PIN accepted"
    );

    let other = tempfile::tempdir().context("creating temp dir")?;
    let (good, _) = fake_pinentry(other.path(), "OK", "echo 'D 246810'; echo OK")?;
    let pin = PinPrompt::Pinentry(Pinentry::new(good))
        .ask(&request)
        .await?;
    ensure!(pin.expose() == b"246810");
    Ok(())
}

#[test]
fn escaping_covers_percent_and_line_breaks() {
    assert_eq!(escape("50% off\r\nnext"), "50%25 off%0D%0Anext");
    assert_eq!(escape("plain"), "plain");
}

#[test]
fn decoding_errors_never_contain_the_data() -> Result<()> {
    let mut answer = SecretBuffer::with_capacity(16)?;
    let error = match decode_data(b"D 9753%ZZ", &mut answer) {
        Ok(()) => bail!("bad escape accepted"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(!error.contains("9753"), "data in error: {error}");
    Ok(())
}

#[test]
fn prompts_mention_errors_and_low_retries_only() {
    let calm = PinRequest {
        key: "work key",
        retries: Some(8),
        error: None,
    };
    assert_eq!(
        calm.askpass_text(),
        "Enter PIN for work key, then touch the key"
    );
    assert!(!calm.pinentry_description().contains("attempts"));

    let worried = PinRequest {
        key: "work key",
        retries: Some(2),
        error: Some("The previous PIN was wrong"),
    };
    assert_eq!(
        worried.askpass_text(),
        "The previous PIN was wrong. Enter PIN for work key, then touch the key (2 PIN attempts left before the key locks)"
    );
    assert!(
        worried
            .pinentry_description()
            .contains("2 PIN attempts left")
    );
}
