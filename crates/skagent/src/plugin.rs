//! `age-plugin-skagent` binary entry point. Everything is in
//! `skagent-age-plugin`; nothing of the agent's library is used here, so the
//! plugin links neither libfido2 nor anything else the agent needs.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    skagent_age_plugin::main()
}
