//! `age-plugin-skagent` for systems without the agent: an initrd that
//! unlocks a disk, a rescue system.
//!
//! The regular plugin (`skagent-age-plugin`) holds no key and asks the
//! running agent. This one asks the security key itself: the same
//! identities (`AGE-PLUGIN-SKAGENT-1…`), the same derivation by the same
//! code (`skagent-fido`, `skagent-age`), the same files. What the agent
//! adds for a desktop session isn't here: no PIN cache, no batches, no
//! telling apart who asks. Every decryption takes the PIN, which the age
//! client asks for, and a touch, and nothing outlives the run
//! (`docs/age.md`, the standalone plugin).
//!
//! - [`flow`]: `identity-v1`, from what the age client hands over to the
//!   file key. Key first: one PIN, each of the key's credentials derived
//!   once, compared with every recipient named.
//! - [`key`]: what the flow needs of a security key, and which of the
//!   plugged-in ones it takes. [`device`]: the real ones.
//! - [`stdio`]: the age client's end, without buffers that keep a PIN.
//!
//! Where an agent runs, its own plugin answers: this one refuses next to an
//! agent's socket for age requests, so that a wrong order in `PATH` doesn't
//! go unnoticed. That keeps accidents away, nothing else: whoever can open
//! the key's device and knows the PIN needs no plugin.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod device;
pub mod flow;
pub mod key;
pub mod stdio;
mod watch;

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, bail};
use skagent_age_plugin::agent::{hung_up, local_socket};
use skagent_age_plugin::recipient;

use crate::key::{Found, select};
use crate::stdio::{ClientInput, ClientOutput};
use crate::watch::Watch;

/// What the plugin says when it isn't run by age.
const HELP: &str = "\
age-plugin-skagent (standalone) is run by age or rage for identities of skagent on systems
where skagent itself doesn't run. It asks the security key directly and keeps nothing:

  rage -d -i IDENTITY-FILE FILE    decrypt; asks for the security key's PIN, then for a touch
  age -e -i IDENTITY-FILE          encrypt to the identity; needs no security key

IDENTITY-FILE comes from `skagent age identity`. With rage it may hold the identities of
everyone the file is encrypted to; with age, one identity per file. Where skagent runs,
its own age-plugin-skagent answers instead.
";

/// What the age client is told where an agent runs, at `socket`.
fn next_to_an_agent(socket: &Path) -> String {
    format!(
        "skagent runs here and answers for its identities ({}); this is the plugin for systems \
         without it. The agent's own age-plugin-skagent has to be the one in PATH",
        socket.display()
    )
}

fn run(state_machine: &str) -> Result<()> {
    if !matches!(state_machine, "identity-v1" | "recipient-v1") {
        bail!(
            "the age client asks for the state machine {state_machine:?}, which this plugin \
             doesn't know"
        );
    }
    // Before a PIN or a file key can come in: nothing of this process in a
    // core file, and no other process of the user reading its memory.
    skagent_secret::harden_process()?;
    let mut input = ClientInput::stdin();
    let mut output = ClientOutput;
    let agent = local_socket(
        std::env::var_os("SKAGENT_AGE_SOCKET").as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        Path::exists,
    );
    if let Some(socket) = agent {
        return flow::refuse(&mut input, &mut output, &next_to_an_agent(&socket));
    }
    if state_machine == "recipient-v1" {
        return recipient::run(&mut input, &mut output, skagent_age_plugin::random);
    }
    // The age client holds the other end of standard input.
    let watch = Watch::start(|| hung_up(rustix::stdio::stdin()))?;
    flow::run(&mut input, &mut output, || {
        let found = select(device::plugged_in()?);
        if let Found::One(key) = &found {
            watch.cancels(key.canceller());
        }
        Ok(found)
    })
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
        let _ignored = std::io::stdout().write_all(HELP.as_bytes());
        return ExitCode::SUCCESS;
    };
    match run(&state_machine) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The age client shows the plugin's standard error.
            let _ignored = writeln!(std::io::stderr(), "age-plugin-skagent: {error:#}");
            ExitCode::FAILURE
        }
    }
}
