//! Command line parsing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use clap::{CommandFactory as _, Parser as _};
use skagent::cli::{Cli, Command, ServeArgs, parse_duration};
use skagent::prompt::PinPrompt;
use skagent::serve::pin_prompt;

fn serve(args: &[&str]) -> Result<ServeArgs> {
    let cli =
        Cli::try_parse_from(["skagent", "serve"].iter().chain(args)).context("parsing serve")?;
    match cli.command {
        Command::Serve(args) => Ok(args),
        Command::Forget(_) => bail!("parsed as forget"),
    }
}

#[test]
fn cli_definition_is_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn serve_takes_an_optional_socket() -> Result<()> {
    let args = serve(&["--socket", "/tmp/agent.sock"])?;
    ensure!(args.socket.socket.as_deref() == Some(Path::new("/tmp/agent.sock")));
    Ok(())
}

#[test]
fn log_filter_is_global_and_defaults_to_info() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "serve"]).context("parsing serve")?;
    ensure!(cli.log == "info", "default filter is {:?}", cli.log);

    let cli = Cli::try_parse_from(["skagent", "serve", "--log", "skagent=debug"])
        .context("parsing serve --log")?;
    ensure!(cli.log == "skagent=debug");
    Ok(())
}

#[test]
fn a_subcommand_is_required() {
    assert!(Cli::try_parse_from(["skagent"]).is_err());
}

#[test]
fn pinentry_is_the_default_prompt_and_askpass_replaces_it() -> Result<()> {
    match pin_prompt(&serve(&[])?) {
        PinPrompt::Pinentry(pinentry) => ensure!(pinentry.program() == Path::new("pinentry")),
        PinPrompt::Askpass(_) => bail!("askpass by default"),
    }
    match pin_prompt(&serve(&["--askpass", "/usr/bin/ssh-askpass"])?) {
        PinPrompt::Askpass(askpass) => {
            ensure!(askpass.program() == Path::new("/usr/bin/ssh-askpass"));
        }
        PinPrompt::Pinentry(_) => bail!("pinentry despite --askpass"),
    }
    ensure!(
        serve(&["--askpass", "/a", "--pinentry", "/p"]).is_err(),
        "--askpass and --pinentry together accepted"
    );
    Ok(())
}

#[test]
fn pins_are_cached_for_eight_hours_by_default() -> Result<()> {
    let args = serve(&[])?;
    ensure!(args.pin_lifetime == Duration::from_hours(8));
    ensure!(args.pin_idle.is_none());
    let args = serve(&["--pin-lifetime", "0", "--pin-idle", "30m"])?;
    ensure!(args.pin_lifetime.is_zero());
    ensure!(args.pin_idle == Some(Duration::from_mins(30)));
    Ok(())
}

#[test]
fn durations_need_a_unit() {
    let valid = [("90s", 90), ("30m", 1800), ("8h", 28_800), ("0", 0)];
    for (text, seconds) in valid {
        assert_eq!(
            parse_duration(text),
            Ok(Duration::from_secs(seconds)),
            "{text}"
        );
    }
    for text in [
        "",
        "8",
        "h",
        "8d",
        "-1h",
        "1.5h",
        "8 h",
        "18446744073709551615h",
    ] {
        assert!(parse_duration(text).is_err(), "{text:?} accepted");
    }
}

#[test]
fn forget_takes_the_socket() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "forget", "--socket", "/run/a.sock"])
        .context("parsing forget")?;
    let Command::Forget(args) = cli.command else {
        bail!("not parsed as forget");
    };
    ensure!(args.socket.as_deref() == Some(Path::new("/run/a.sock")));
    Ok(())
}
