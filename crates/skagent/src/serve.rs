//! `skagent serve`: bind the socket, serve until shutdown, clean up.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::agent::SkAgent;
use crate::cli::{ServeArgs, SocketArgs};
use crate::pin_cache::CachePolicy;
use crate::pinentry::Pinentry;
use crate::prompt::{Askpass, PinPrompt};
use crate::signer::Signer;
use crate::socket::{self, PeerCheckedListener};

/// How often expired PINs are wiped. Lookups check expiry themselves; this
/// only makes sure an unused PIN doesn't sit in memory past its time.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// The socket path from `--socket` / `SKAGENT_SOCKET`, or the default in
/// `$XDG_RUNTIME_DIR`.
///
/// # Errors
///
/// Returns an error if no path is given and `XDG_RUNTIME_DIR` is unusable.
pub fn socket_path(args: SocketArgs) -> Result<PathBuf> {
    match args.socket {
        Some(path) => Ok(path),
        None => socket::default_socket_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref()),
    }
}

/// The prompt `args` ask for: askpass if `--askpass` is given, else pinentry.
#[must_use]
pub fn pin_prompt(args: &ServeArgs) -> PinPrompt {
    match &args.askpass {
        Some(program) => PinPrompt::Askpass(Askpass::new(program.clone())),
        None => PinPrompt::Pinentry(Pinentry::new(args.pinentry.clone())),
    }
}

/// Runs `skagent serve` until SIGINT or SIGTERM.
///
/// # Errors
///
/// Returns an error if the socket path can't be resolved or bound, the signal
/// handlers can't be installed, or serving fails.
pub async fn run(args: ServeArgs) -> Result<()> {
    let prompt = pin_prompt(&args);
    let policy = CachePolicy {
        lifetime: args.pin_lifetime,
        idle_timeout: args.pin_idle,
    };
    match &prompt {
        PinPrompt::Pinentry(pinentry) => {
            tracing::info!(pinentry = %pinentry.program().display(), "asking for PINs with pinentry");
        }
        PinPrompt::Askpass(askpass) => {
            tracing::info!(askpass = %askpass.program().display(), "asking for PINs with askpass");
        }
    }
    if policy.caches() {
        tracing::info!(
            lifetime_seconds = policy.lifetime.as_secs(),
            idle_seconds = policy.idle_timeout.map(|idle| idle.as_secs()),
            "caching PINs"
        );
    } else {
        tracing::info!("PIN caching disabled, asking for every signature");
    }
    let socket_path = socket_path(args.socket)?;
    let agent = SkAgent::new(Signer::new(Some(prompt), policy));
    // Installed before the socket exists, so a signal can't kill the process
    // between binding and serving and leave a stale socket behind.
    let signals = ShutdownSignals::install()?;
    serve_until(&socket_path, agent, signals.wait()).await
}

/// Serves `agent` on `socket_path` until `shutdown` completes, then drops all
/// cached PINs and removes the socket file.
///
/// # Errors
///
/// Returns an error if binding or serving fails, if `shutdown` resolves to an
/// error, or if the socket file can't be removed afterwards.
pub async fn serve_until<F>(socket_path: &Path, agent: SkAgent, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let (listener, bound) = socket::bind(socket_path)?;
    tracing::info!(
        socket = %bound.path().display(),
        "agent listening, point SSH_AUTH_SOCK at the socket"
    );

    let served = tokio::select! {
        result = ssh_agent_lib::agent::listen(PeerCheckedListener::new(listener, bound.path()), agent.clone()) => {
            result.with_context(|| {
                format!("serving the ssh-agent protocol on {}", socket_path.display())
            })
        }
        result = sweep_expired_pins(agent.clone()) => result,
        result = shutdown => result,
    };
    agent.forget_pins("shutdown").await;

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

/// Wipes expired PINs periodically. Never returns.
async fn sweep_expired_pins(agent: SkAgent) -> Result<()> {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        agent.expire_pins().await;
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
