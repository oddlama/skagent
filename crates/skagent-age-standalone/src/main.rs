//! The standalone plugin's binary. It is built under its crate's name,
//! since the regular plugin's binary is called `age-plugin-skagent` in the
//! same workspace, and installed as `age-plugin-skagent`: age finds a plugin
//! by the name in the identity.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    skagent_age_standalone::main()
}
