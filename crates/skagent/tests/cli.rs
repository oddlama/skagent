//! Command line parsing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use clap::{CommandFactory as _, Parser as _};
use skagent::cli::{Cli, Command};
use skagent::serve::askpass_program;
use std::ffi::OsString;
use std::path::PathBuf;

#[test]
fn cli_definition_is_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn serve_takes_an_optional_socket() -> Result<()> {
    let cli = Cli::try_parse_from(["skagent", "serve", "--socket", "/tmp/agent.sock"])
        .context("parsing serve --socket")?;
    let Command::Serve(args) = cli.command;
    ensure!(args.socket.as_deref() == Some(Path::new("/tmp/agent.sock")));
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
fn askpass_comes_from_the_flag_then_a_non_empty_environment() {
    let flag = Some(PathBuf::from("/flag"));
    let environment = Some(OsString::from("/env"));
    assert_eq!(askpass_program(flag.clone(), environment.clone()), flag);
    assert_eq!(
        askpass_program(None, environment),
        Some(PathBuf::from("/env"))
    );
    assert_eq!(
        askpass_program(None, Some(OsString::new())),
        None,
        "empty SSH_ASKPASS used"
    );
    assert_eq!(askpass_program(None, None), None);
}
