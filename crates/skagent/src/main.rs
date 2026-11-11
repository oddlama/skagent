//! `skagent` binary entry point.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::{self, IsTerminal as _, Write as _};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use skagent::cli::{Cli, Command};
use skagent::{client, hardening, logging, output, serve};

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

    // Before the runtime opens descriptors of its own, while the passed
    // socket is the only unowned one.
    let activated = match &cli.command {
        Command::Serve(_) => {
            skagent_fds::activated_listener().context("taking over the socket systemd passed")?
        }
        Command::Forget(_) | Command::Load(_) => None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    match cli.command {
        Command::Serve(args) => runtime.block_on(serve::run(args, activated)),
        Command::Forget(args) => runtime.block_on(client::forget_pins(&serve::socket_path(args)?)),
        Command::Load(args) => {
            let count = runtime.block_on(client::load_keys(&serve::socket_path(args)?))?;
            writeln!(io::stdout(), "Loaded {count} resident SSH key(s).")
                .context("writing the resident-loading result")
        }
    }
}
