//! Reading PINs from askpass programs.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use skagent::prompt::{Askpass, pin_from_answer};
use skagent_secret::SecretBuffer;

fn answer(bytes: &[u8]) -> Result<SecretBuffer> {
    SecretBuffer::from_slice(bytes)
}

fn script(dir: &Path, name: &str, body: &str) -> Result<PathBuf> {
    support::executable_script(dir, name, body)
}

#[test]
fn trailing_newlines_are_stripped_once() -> Result<()> {
    ensure!(pin_from_answer(&answer(b"123456\n")?)?.expose() == b"123456");
    ensure!(pin_from_answer(&answer(b"123456\r\n")?)?.expose() == b"123456");
    ensure!(pin_from_answer(&answer(b"123456")?)?.expose() == b"123456");
    ensure!(
        pin_from_answer(&answer(b"12 34 \n")?)?.expose() == b"12 34 ",
        "inner spaces kept"
    );
    Ok(())
}

#[test]
fn pins_must_have_4_to_63_bytes() -> Result<()> {
    ensure!(
        pin_from_answer(&answer(b"123\n")?).is_err(),
        "3 bytes accepted"
    );
    ensure!(pin_from_answer(&answer(b"1234")?).is_ok());
    ensure!(pin_from_answer(&answer(&[b'7'; 63])?).is_ok());
    ensure!(
        pin_from_answer(&answer(&[b'7'; 64])?).is_err(),
        "64 bytes accepted"
    );
    Ok(())
}

#[test]
fn length_errors_never_contain_the_pin() -> Result<()> {
    let error = match pin_from_answer(&answer(b"987\n")?) {
        Ok(_) => anyhow::bail!("short PIN accepted"),
        Err(error) => format!("{error:#}"),
    };
    ensure!(!error.contains("987"), "PIN in error message: {error}");
    Ok(())
}

#[tokio::test]
async fn the_askpass_answer_becomes_the_pin() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let prompt_file = dir.path().join("prompt");
    let program = script(
        dir.path(),
        "askpass",
        &format!(
            "printf '%s' \"$1\" > '{}'\nprintf '246810\\n'",
            prompt_file.display()
        ),
    )?;

    let pin = Askpass::new(program)
        .ask_pin("Enter PIN for work key")
        .await?;
    ensure!(pin.expose() == b"246810");
    ensure!(
        fs::read_to_string(&prompt_file).context("reading prompt")? == "Enter PIN for work key"
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_and_broken_prompts_fail() -> Result<()> {
    let dir = tempfile::tempdir().context("creating temp dir")?;
    let cancelled = script(dir.path(), "cancelled", "printf '246810\\n'; exit 1")?;
    let flooding = script(dir.path(), "flooding", "head -c 200 /dev/zero | tr '\\0' 7")?;
    let missing = dir.path().join("missing");

    for program in [cancelled, flooding, missing] {
        let result = Askpass::new(program.clone()).ask_pin("prompt").await;
        ensure!(result.is_err(), "{} gave a PIN", program.display());
    }
    Ok(())
}
