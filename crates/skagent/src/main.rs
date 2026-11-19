//! `skagent` binary entry point.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::io::{self, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use clap::Parser as _;
use skagent::cli::{AgeCommand, AgeSocketArgs, CheckConfigArgs, Cli, Command};
use skagent::config::Config;
use skagent::serve::Activated;
use skagent::{client, hardening, logging, output, serve, socket};
use skagent_age::Recipient;

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
    // First, before any secret can enter the process. `skagent age` holds
    // none, and the agent has to be able to see which program asks it.
    if matches!(cli.command, Command::Age(_)) {
        hardening::disable_core_dumps()?;
    } else {
        hardening::harden_process()?;
    }
    logging::init(&cli.log, color)?;

    // Before the runtime opens descriptors of its own, while the passed
    // sockets are the only unowned ones.
    let activated = match &cli.command {
        Command::Serve(_) => Activated::from_passed(
            skagent_fds::activated_listeners().context("taking over the sockets systemd passed")?,
        )?,
        Command::Forget(_) | Command::Load(_) | Command::CheckConfig(_) | Command::Age(_) => {
            Activated::default()
        }
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
            let loaded = runtime.block_on(client::load_keys(&serve::socket_path(args.socket)?))?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "Loaded {} resident SSH key(s).", loaded.keys)
                .context("writing the resident-loading result")?;
            if loaded.age_identities > 0 {
                writeln!(stdout, "Found {} age identity(ies).", loaded.age_identities)
                    .context("writing the resident-loading result")?;
            }
            Ok(())
        }
        Command::CheckConfig(args) => check_config(&args),
        Command::Age(args) => age(&runtime, args.command),
    }
}

/// The agent's socket for age requests: `--age-socket`, else next to the
/// default ssh-agent socket.
fn age_socket(args: AgeSocketArgs) -> Result<PathBuf> {
    match args.age_socket {
        Some(path) => Ok(path),
        None => Ok(socket::age_socket_path(&socket::default_socket_path(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        )?)),
    }
}

/// `skagent age`: what the user needs on stdout, hints on stderr.
fn age(runtime: &tokio::runtime::Runtime, command: AgeCommand) -> Result<()> {
    let mut stdout = io::stdout().lock();
    match command {
        AgeCommand::New { socket, another } => {
            let recipient = runtime.block_on(client::age_new(&age_socket(socket)?, another))?;
            writeln!(stdout, "{recipient}").context("writing the new identity's recipient")?;
            writeln!(
                io::stderr(),
                "Created an age identity. Encrypt to the recipient above with `age -r`.\n\
                 `skagent age identity > FILE` writes the identity file for `age -d -i FILE`.\n\
                 The key exists on this security key only: give every file a second recipient."
            )
            .context("writing the hints")
        }
        AgeCommand::List(socket) => {
            let identities = runtime.block_on(client::age_list(&age_socket(socket)?))?;
            let unknown = identities
                .iter()
                .filter(|identity| identity.is_none())
                .count();
            for recipient in identities.iter().flatten() {
                writeln!(stdout, "{recipient}").context("writing a recipient")?;
            }
            if unknown > 0 {
                writeln!(
                    io::stderr(),
                    "{unknown} more identity(ies) whose recipient skagent hasn't derived on this \
                     machine yet: decrypt a file with one, and it is listed."
                )
                .context("writing the hints")?;
            }
            if identities.is_empty() {
                writeln!(
                    io::stderr(),
                    "No age identities known. `skagent load` finds the ones on a security key, \
                     `skagent age new` creates one."
                )
                .context("writing the hints")?;
            }
            Ok(())
        }
        AgeCommand::Identity { socket, recipient } => {
            let recipient: Recipient = if let Some(recipient) = recipient {
                recipient.parse()?
            } else {
                let identities = runtime.block_on(client::age_list(&age_socket(socket)?))?;
                let mut known = identities.into_iter().flatten();
                match (known.next(), known.next()) {
                    (Some(only), None) => only,
                    (None, _) => bail!(
                        "skagent knows no age identity with its recipient yet; pass the \
                         recipient (age1pq1…)"
                    ),
                    (Some(_), Some(_)) => bail!(
                        "skagent knows several age identities; pass the recipient of the one \
                         you mean (`skagent age list` prints them)"
                    ),
                }
            };
            write!(stdout, "{}", client::identity_file(&recipient))
                .context("writing the identity file")
        }
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
