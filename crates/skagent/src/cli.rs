//! Command line interface.

use clap::Parser;

/// ssh-agent for FIDO2 (sk) keys: caches the PIN, still requires a touch per signature.
#[derive(Debug, Parser)]
#[command(name = "skagent", version, about)]
pub struct Cli {}
