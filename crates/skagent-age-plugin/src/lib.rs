//! `age-plugin-skagent`: what age runs for an identity of skagent's
//! (`AGE-PLUGIN-SKAGENT-1…`, or `age -j skagent`).
//!
//! The plugin holds no key. To decrypt (`identity-v1`) it hands the stanzas
//! of a file's header to the running agent, which has the security key
//! derive the key and returns the file key ([`identity`]). To encrypt to an
//! identity (`recipient-v1`) it wraps to the recipient the identity names,
//! like stock age would ([`recipient`]); the agent isn't involved.
//!
//! The agent recognizes the plugin by its executable, which the kernel only
//! shows for a process that can be inspected. So the plugin switches core
//! dumps off, but stays dumpable; the file key it passes on is in the age
//! client's memory just the same.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod agent;
pub mod identity;
pub mod ipc;
pub mod recipient;

use std::io::{self, Write as _};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use rustix::process::{Resource, Rlimit, setrlimit};
use rustix::rand::{GetRandomFlags, getrandom};

/// What the plugin says when it isn't run by age.
const HELP: &str = "\
age-plugin-skagent is run by age (or rage) for identities of skagent:

  age -d -i IDENTITY-FILE FILE     decrypt; skagent asks for the PIN and a touch
  age -d -j skagent FILE           the same, with the identity on the security key at hand
  age -e -i IDENTITY-FILE          encrypt to the identity; needs no security key

`skagent age new` creates an identity, `skagent age identity` writes its identity file.
";

/// Fills `buffer` from the system's random number generator.
fn random(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0_usize;
    while let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        let written = getrandom(rest, GetRandomFlags::empty())
            .context("reading from the system's random number generator")?;
        if written == 0 {
            bail!("the system's random number generator returned nothing");
        }
        filled = filled.saturating_add(written);
    }
    Ok(())
}

fn run(state_machine: &str) -> Result<()> {
    // A crash must not write the file key to a core file.
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .context("disabling core dumps (setrlimit RLIMIT_CORE to 0)")?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    match state_machine {
        "identity-v1" => {
            let mut agent = agent::Agent::from_environment()?;
            // The age client holds the other end of standard input. Once it
            // is gone, nobody waits for a file key.
            identity::run(&mut input, &mut output, &mut agent, || {
                agent::hung_up(io::stdin())
            })
        }
        "recipient-v1" => recipient::run(&mut input, &mut output, random),
        other => bail!(
            "the age client asks for the state machine {other:?}, which this plugin doesn't know"
        ),
    }
}

/// The plugin's `main`: `--age-plugin=STATE_MACHINE` runs one, anything else
/// prints what the plugin is.
#[must_use]
pub fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let state_machine = match (arguments.next(), arguments.next()) {
        (Some(argument), None) => argument.strip_prefix("--age-plugin=").map(str::to_owned),
        _ => None,
    };
    let Some(state_machine) = state_machine else {
        // Nowhere to report a failure to write this.
        let _ignored = io::stdout().write_all(HELP.as_bytes());
        return ExitCode::SUCCESS;
    };
    match run(&state_machine) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The age client shows the plugin's standard error.
            let _ignored = writeln!(io::stderr(), "age-plugin-skagent: {error:#}");
            ExitCode::FAILURE
        }
    }
}
