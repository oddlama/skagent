//! Answers to the agent, on stdout.

use std::io::Write as _;

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
    /// locked memory to the pipe.
    pub fn send(self, line: &[u8]) {
        if self == Self::Preview {
            return;
        }
        let mut stdout = std::io::stdout().lock();
        if let Err(error) = stdout.write_all(line).and_then(|()| stdout.flush()) {
            tracing::error!(%error, "can't answer the agent");
        }
    }
}
