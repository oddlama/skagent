//! `skagent serve`: bind the socket, serve until shutdown, clean up.

use std::future::Future;
use std::path::Path;

use anyhow::{Context as _, Result};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::agent::SkAgent;
use crate::cli::ServeArgs;
use crate::socket::{self, PeerCheckedListener};

/// Runs `skagent serve` until SIGINT or SIGTERM.
///
/// # Errors
///
/// Returns an error if the socket path can't be resolved or bound, the signal
/// handlers can't be installed, or serving fails.
pub async fn run(args: ServeArgs) -> Result<()> {
    let socket_path = match args.socket {
        Some(path) => path,
        None => socket::default_socket_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref())?,
    };
    // Installed before the socket exists, so a signal can't kill the process
    // between binding and serving and leave a stale socket behind.
    let signals = ShutdownSignals::install()?;
    serve_until(&socket_path, signals.wait()).await
}

/// Serves the agent on `socket_path` until `shutdown` completes, then removes
/// the socket file.
///
/// # Errors
///
/// Returns an error if binding or serving fails, if `shutdown` resolves to an
/// error, or if the socket file can't be removed afterwards.
pub async fn serve_until<F>(socket_path: &Path, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let (listener, bound) = socket::bind(socket_path)?;
    tracing::info!(
        socket = %bound.path().display(),
        "agent listening, point SSH_AUTH_SOCK at the socket"
    );

    let served = tokio::select! {
        result = ssh_agent_lib::agent::listen(PeerCheckedListener::new(listener), SkAgent::default()) => {
            result.with_context(|| {
                format!("serving the ssh-agent protocol on {}", socket_path.display())
            })
        }
        result = shutdown => result,
    };

    let removed = bound.remove();
    match (served, removed) {
        (Ok(()), removed) => removed,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(removal_error)) => {
            // The serving error is the one to report; the cleanup failure is secondary.
            tracing::error!(
                error = format!("{removal_error:#}"),
                "cleaning up after a failure"
            );
            Err(error)
        }
    }
}

/// SIGINT and SIGTERM handlers, installed up front.
#[derive(Debug)]
pub struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
}

impl ShutdownSignals {
    /// Installs the handlers. Must be called from within a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler can't be installed.
    pub fn install() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("installing the SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("installing the SIGTERM handler")?,
        })
    }

    /// Completes when SIGINT or SIGTERM arrives.
    ///
    /// # Errors
    ///
    /// Never fails today. The `Result` lets it plug into [`serve_until`].
    pub async fn wait(mut self) -> Result<()> {
        tokio::select! {
            _ = self.interrupt.recv() => tracing::info!("received SIGINT, shutting down"),
            _ = self.terminate.recv() => tracing::info!("received SIGTERM, shutting down"),
        }
        Ok(())
    }
}
