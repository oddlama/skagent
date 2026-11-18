//! `skagent` binary entry point.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::{self, IsTerminal as _, Write as _};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use skagent::cli::{CheckConfigArgs, Cli, Command};
use skagent::config::Config;
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
        Command::Forget(_) | Command::Load(_) | Command::CheckConfig(_) => None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    match cli.command {
        Command::Serve(args) => runtime.block_on(serve::run(args, activated)),
        Command::Forget(args) => runtime.block_on(client::forget_pins(&serve::socket_path(args)?)),
        Command::Load(args) => {
            if args.if_connected && !client::security_key_connected()? {
                return writeln!(io::stdout(), "No security key connected, nothing to load.")
                    .context("writing the resident-loading result");
            }
            let count = runtime.block_on(client::load_keys(&serve::socket_path(args.socket)?))?;
            writeln!(io::stdout(), "Loaded {count} resident SSH key(s).")
                .context("writing the resident-loading result")
        }
        Command::CheckConfig(args) => check_config(&args),
    }
}

/// `skagent check-config`: the skipped settings on stderr, a verdict on
/// stdout.
fn check_config(args: &CheckConfigArgs) -> Result<()> {
    let (path, required) = serve::config_path(args.config.as_deref())?;
    if !required && !path.exists() {
        return writeln!(
            io::stdout(),
            "No configuration at {}; skagent uses its defaults.",
            path.display()
        )
        .context("writing the check's result");
    }
    let config = Config::load(&path, true)?;
    let mut stderr = io::stderr().lock();
    for warning in config.warnings() {
        writeln!(stderr, "{} {warning}", output::warning_label())
            .context("writing a skipped setting")?;
    }
    anyhow::ensure!(
        config.warnings().is_empty(),
        "skagent would skip {} setting(s) in {}",
        config.warnings().len(),
        path.display()
    );
    writeln!(io::stdout(), "{} is fine.", path.display()).context("writing the check's result")
}
