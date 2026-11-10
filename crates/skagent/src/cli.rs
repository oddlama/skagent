//! Command line interface.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// ssh-agent for FIDO2 (sk) keys: caches the PIN, still requires a touch per signature.
#[derive(Debug, Parser)]
#[command(name = "skagent", version, about)]
pub struct Cli {
    /// Log filter in `tracing` env-filter syntax, e.g. `info` or `skagent=debug`.
    ///
    /// Debug and trace output of the ssh-agent protocol library is always
    /// suppressed, because it contains key handles and lock passphrases.
    #[arg(long, env = "SKAGENT_LOG", default_value = "info", global = true)]
    pub log: String,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve the ssh-agent protocol on a unix socket until SIGINT or SIGTERM.
    Serve(ServeArgs),
}

/// Arguments of `skagent serve`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Path of the agent socket. Defaults to `$XDG_RUNTIME_DIR/skagent.sock`.
    #[arg(long, env = "SKAGENT_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Program that asks for the PIN: gets the prompt as its argument and
    /// prints the PIN. Defaults to `$SSH_ASKPASS` if that is set and not
    /// empty. Without one, keys created with `verify-required` can't sign.
    #[arg(long)]
    pub askpass: Option<PathBuf>,
}
