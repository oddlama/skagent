//! Process hardening, applied before any secret can enter the process.
//!
//! - [`harden_process`]: the agent, and the commands that pass it a PIN or a
//!   passphrase. No core dumps, and no other process of the user reads its
//!   memory.
//! - [`disable_core_dumps`]: skagent's programs that talk to the agent's
//!   socket for age requests. The agent recognizes them by their executable
//!   (`/proc/<pid>/exe`), which the kernel hides for a non-dumpable process.
//!   They hold no PIN and no long-term secret.
//!
//! Both are skagent-secret's, which the popup uses for itself too.

pub use skagent_secret::{disable_core_dumps, harden_process};
