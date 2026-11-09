//! Process hardening, applied before any secret can enter the process.

use anyhow::{Context as _, Result};
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Makes the process unsuitable for leaking secrets through its memory image.
///
/// - `RLIMIT_CORE = 0`: a crash never writes a core file containing a cached PIN.
/// - `PR_SET_DUMPABLE = 0`: no core dumps either way, `/proc/<pid>` becomes
///   root-owned, and other processes of the same user can no longer ptrace
///   this one (independent of the yama `ptrace_scope` setting).
///
/// Fails closed: if either step fails, the agent must not start.
///
/// # Errors
///
/// Returns an error if the core dump limit or the dumpable flag can't be set.
pub fn harden_process() -> Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .context("disabling core dumps (setrlimit RLIMIT_CORE to 0)")?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context("marking the process non-dumpable (prctl PR_SET_DUMPABLE to 0)")?;
    Ok(())
}
