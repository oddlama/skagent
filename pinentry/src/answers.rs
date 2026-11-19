//! Answers to the agent, on stdout.

use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsFd as _;

/// Where the popup's answers go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answers {
    /// To the agent, on stdout.
    Agent,
    /// Nowhere: `--preview`.
    Preview,
}

impl Answers {
    /// Sends one line, newline included. A PIN line goes straight from
    /// locked memory to the pipe: through the descriptor itself, not through
    /// the standard library's `Stdout`, which has a buffer of its own that
    /// nothing wipes.
    pub fn send(self, line: &[u8]) {
        if self == Self::Preview {
            return;
        }
        let sent = std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from)
            .and_then(|mut pipe| pipe.write_all(line));
        if let Err(error) = sent {
            tracing::error!(%error, "can't answer the agent");
        }
    }
}
