//! `skagent` binary entry point.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser as _;
use skagent::cli::Cli;

fn main() {
    let _cli = Cli::parse();
}
