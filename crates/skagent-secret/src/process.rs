//! What a process owes the secrets in its memory: nothing of it in a core
//! file, and no other process of the user reading it.

use anyhow::{Context as _, Result};
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Makes the process unsuitable for leaking secrets through its memory image.
/// To be called first, before any secret can enter the process.
///
/// - `RLIMIT_CORE = 0`: a crash never writes a core file containing a PIN.
/// - `PR_SET_DUMPABLE = 0`: no core dumps either way, `/proc/<pid>` becomes
///   root-owned, and other processes of the same user can no longer ptrace
///   this one or read its memory (independent of the yama `ptrace_scope`
///   setting).
///
/// That covers all of the process's memory, also what isn't a
/// [`SecretBuffer`](crate::SecretBuffer): a key event on its way through a
/// user interface toolkit, for one. Fails closed: if either step fails, the
/// process must not go on to take a secret.
///
/// # Errors
///
/// Returns an error if the core dump limit or the dumpable flag can't be set.
pub fn harden_process() -> Result<()> {
    disable_core_dumps()?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context("marking the process non-dumpable (prctl PR_SET_DUMPABLE to 0)")?;
    Ok(())
}

/// `RLIMIT_CORE = 0` alone, for a program that another one has to recognize
/// by its executable (`/proc/<pid>/exe`), which the kernel hides for a
/// non-dumpable process.
///
/// # Errors
///
/// Returns an error if the core dump limit can't be set.
pub fn disable_core_dumps() -> Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .context("disabling core dumps (setrlimit RLIMIT_CORE to 0)")
}
