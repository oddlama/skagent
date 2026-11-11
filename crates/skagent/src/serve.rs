//! `skagent serve`: bind the socket, serve until shutdown, clean up.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::agent::SkAgent;
use crate::cli::{SecretMemory, ServeArgs, SocketArgs};
use crate::logind;
use crate::notify::Notifier;
use crate::pin_cache::CachePolicy;
use crate::pinentry::Pinentry;
use crate::prompt::{Askpass, PinPrompt};
use crate::signer::Signer;
use crate::socket::{self, PeerCheckedListener};

/// How often expired PINs and keys are wiped. Lookups check expiry
/// themselves; this makes sure an unused PIN doesn't sit in memory past its
/// time, and a key whose `ssh-add -t` lifetime ended takes its PIN with it.
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

/// Where the agent gets its socket.
#[derive(Debug)]
pub enum Listening {
    /// Bind a socket at this path; it is removed on shutdown.
    Bind(PathBuf),
    /// The socket systemd passed (socket activation). It stays on shutdown:
    /// systemd owns it and starts the agent again on the next connection.
    Activated(std::os::unix::net::UnixListener),
}

/// Path of a socket systemd passed.
///
/// # Errors
///
/// Returns an error if the socket has no path (abstract or unnamed), which
/// `SSH_AUTH_SOCK` couldn't point at.
pub fn activated_path(listener: &std::os::unix::net::UnixListener) -> Result<PathBuf> {
    let address = listener
        .local_addr()
        .context("reading the address of the socket systemd passed")?;
    address
        .as_pathname()
        .map(Path::to_path_buf)
        .context("the socket systemd passed has no path; use ListenStream=%t/skagent.sock")
}

/// Runs `skagent serve` until SIGINT or SIGTERM, on `activated` if systemd
/// passed a socket, else on one it binds.
///
/// # Errors
///
/// Returns an error if `FIDO_DEBUG` is set, the socket path can't be
/// resolved or bound, or
/// `--socket` names another socket than the one systemd passed, the signal
/// handlers can't be installed, or serving fails.
pub async fn run(
    args: ServeArgs,
    activated: Option<std::os::unix::net::UnixListener>,
) -> Result<()> {
    skagent_fido::ensure_debug_off().context("refusing to serve")?;
    // Before any secret exists: the first buffer fixes where all of them live.
    if args.secret_memory == SecretMemory::MemfdSecret {
        skagent_secret::use_secretmem().context("--secret-memory memfd-secret")?;
        tracing::info!(
            "keeping secrets in memfd_secret memory; the system can't hibernate while the agent holds any"
        );
    }
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
    let listening = match activated {
        Some(listener) => {
            let passed = activated_path(&listener)?;
            if let Some(given) = &args.socket.socket {
                anyhow::ensure!(
                    *given == passed,
                    "systemd passed the socket {}, but --socket or SKAGENT_SOCKET names {}",
                    passed.display(),
                    given.display()
                );
            }
            Listening::Activated(listener)
        }
        None => Listening::Bind(socket_path(args.socket)?),
    };
    for rule in &args.pin_policies {
        tracing::info!(?rule, "caching the PINs of matching keys differently");
    }
    let mut signer = Signer::new(Some(prompt), policy).with_pin_policies(args.pin_policies);
    if args.no_touch_notification {
        tracing::info!("not showing touch notifications");
    } else {
        signer = signer.with_notifier(Arc::new(Notifier::default()));
    }
    let agent = SkAgent::new(signer);
    // Installed before the socket exists, so a signal can't kill the process
    // between binding and serving and leave a stale socket behind.
    let signals = ShutdownSignals::install()?;
    serve_until(listening, agent, signals.wait()).await
}

/// Serves `agent` until `shutdown` completes, then drops all cached PINs and
/// removes the socket file if the agent bound it.
///
/// # Errors
///
/// Returns an error if binding or serving fails, if `shutdown` resolves to an
/// error, or if the socket file can't be removed afterwards.
pub async fn serve_until<F>(listening: Listening, agent: SkAgent, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    agent.caching_pending().await;
    let (listener, socket_path, bound) = match listening {
        Listening::Bind(path) => {
            let (listener, bound) = socket::bind(&path)?;
            (listener, path, Some(bound))
        }
        Listening::Activated(listener) => {
            let path = activated_path(&listener)?;
            let listener = tokio::net::UnixListener::from_std(listener)
                .context("serving the socket systemd passed")?;
            (listener, path, None)
        }
    };
    tracing::info!(
        socket = %socket_path.display(),
        activated = bound.is_none(),
        "agent listening, point SSH_AUTH_SOCK at the socket"
    );

    let served = tokio::select! {
        result = ssh_agent_lib::agent::listen(PeerCheckedListener::new(listener, &socket_path), agent.clone()) => {
            result.with_context(|| {
                format!("serving the ssh-agent protocol on {}", socket_path.display())
            })
        }
        result = sweep_expired(agent.clone()) => result,
        result = logind::watch(agent.clone()) => result,
        result = shutdown => result,
    };
    agent.forget_pins("shutdown").await;

    let removed = bound.as_ref().map_or(Ok(()), socket::BoundSocket::remove);
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

/// Wipes expired PINs and keys periodically. Never returns.
async fn sweep_expired(agent: SkAgent) -> Result<()> {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        agent.expire().await;
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
