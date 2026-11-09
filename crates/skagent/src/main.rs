//! `skagent` binary entry point.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, IsTerminal as _, Write as _};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use skagent::cli::{Cli, Command};
use skagent::{hardening, logging, output, serve};

fn main() -> ExitCode {
    let color = output::color_enabled(
        io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    );
    output::configure(color);
    let cli = Cli::parse();

    match run(cli, color) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // If stderr itself is gone there is nowhere left to report to;
            // the exit code still signals the failure.
            let _ignored = writeln!(io::stderr(), "{} {error:#}", output::error_label());
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli, color: bool) -> Result<()> {
    // First, before any secret can enter the process.
    hardening::harden_process()?;
    logging::init(&cli.log, color)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    match cli.command {
        Command::Serve(args) => runtime.block_on(serve::run(args)),
    }
}
