//! `skagent serve`: bind the socket, serve until shutdown, clean up.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::age::{AgeIdentities, default_age_path};
use crate::agent::SkAgent;
use crate::bindings::{Bindings, default_bindings_path};
use crate::cli::{SecretMemory, ServeArgs, SocketArgs};
use crate::config::{self, Config};
use crate::identities::{IdentityStore, default_keys_path};
use crate::logind;
use crate::notify::Notifier;
use crate::peer::OwnPrograms;
use crate::pin_cache::CachePolicy;
use crate::pinentry::Pinentry;
use crate::popup::Popup;
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

/// The configuration file to read: `--config`, which must exist, or the
/// default path, which may be missing.
///
/// # Errors
///
/// Returns an error if there's no `--config` and no default path.
pub fn config_path(path: Option<&Path>) -> Result<(PathBuf, bool)> {
    Ok(match path {
        Some(path) => (path.to_path_buf(), true),
        None => (
            config::default_config_path(
                std::env::var_os("XDG_CONFIG_HOME").as_deref(),
                std::env::var_os("HOME").as_deref(),
            )?,
            false,
        ),
    })
}

/// The configuration from `--config`, or from the default path if it exists.
///
/// # Errors
///
/// Returns an error if a given file is missing, or any file doesn't parse.
pub fn load_config(path: Option<&Path>) -> Result<Config> {
    let (path, required) = config_path(path)?;
    let config = Config::load(&path, required)?;
    tracing::info!(config = %path.display(), "read the configuration");
    for warning in config.warnings() {
        tracing::warn!(config = %path.display(), "skipped a setting: {warning}");
    }
    Ok(config)
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

/// What systemd calls the socket for age requests: `FileDescriptorName=age`
/// in its socket unit. A socket of any other name is the ssh-agent socket.
pub const AGE_SOCKET_NAME: &str = "age";

/// The sockets systemd passed (socket activation).
#[derive(Debug, Default)]
pub struct Activated {
    /// The ssh-agent socket.
    pub ssh: Option<std::os::unix::net::UnixListener>,
    /// The socket for age requests.
    pub age: Option<std::os::unix::net::UnixListener>,
}

impl Activated {
    /// Tells the passed sockets apart by their names.
    ///
    /// # Errors
    ///
    /// Returns an error for two sockets of the same kind, or a socket for
    /// age requests without an ssh-agent socket.
    pub fn from_passed(passed: Vec<skagent_fds::Passed>) -> Result<Self> {
        let mut activated = Self::default();
        for socket in passed {
            let slot = if socket.name.as_deref() == Some(AGE_SOCKET_NAME) {
                &mut activated.age
            } else {
                &mut activated.ssh
            };
            if slot.replace(socket.listener).is_some() {
                bail!(
                    "systemd passed two sockets of the same kind; name the one for age requests \
                     with FileDescriptorName={AGE_SOCKET_NAME}"
                );
            }
        }
        if activated.age.is_some() && activated.ssh.is_none() {
            bail!("systemd passed a socket for age requests, but no ssh-agent socket");
        }
        Ok(activated)
    }
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

/// Where the agent listens: on the sockets systemd passed, else on ones it
/// binds at `socket` (or the default path) and, for age requests, at
/// `age_socket` (or next to the first).
fn sockets(
    activated: Activated,
    socket: SocketArgs,
    age_socket: Option<PathBuf>,
) -> Result<(Listening, Option<Listening>)> {
    let Some(listener) = activated.ssh else {
        let path = socket_path(socket)?;
        let age = age_socket.unwrap_or_else(|| socket::age_socket_path(&path));
        return Ok((Listening::Bind(path), Some(Listening::Bind(age))));
    };
    let passed = activated_path(&listener)?;
    if let Some(given) = &socket.socket {
        anyhow::ensure!(
            *given == passed,
            "systemd passed the socket {}, but --socket or SKAGENT_SOCKET names {}",
            passed.display(),
            given.display()
        );
    }
    if activated.age.is_none() {
        tracing::info!(
            "systemd passed no socket named \"{AGE_SOCKET_NAME}\": not answering age requests"
        );
    }
    Ok((
        Listening::Activated(listener),
        activated.age.map(Listening::Activated),
    ))
}

/// The keys and the age identities remembered from before a restart, where
/// they can be remembered at all.
fn remembered() -> (IdentityStore, AgeIdentities) {
    let state_home = std::env::var_os("XDG_STATE_HOME");
    let home = std::env::var_os("HOME");
    let identities = match default_keys_path(state_home.as_deref(), home.as_deref()) {
        Ok(file) => IdentityStore::remembered_in(file),
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "not remembering keys across restarts"
            );
            IdentityStore::default()
        }
    };
    let age = match default_age_path(state_home.as_deref(), home.as_deref()) {
        Ok(file) => AgeIdentities::remembered_in(file),
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "not remembering age identities across restarts"
            );
            AgeIdentities::default()
        }
    };
    (identities, age)
}

/// Runs `skagent serve` until SIGINT or SIGTERM, on `activated` if systemd
/// passed sockets, else on ones it binds.
///
/// # Errors
///
/// Returns an error if `FIDO_DEBUG` is set, the socket path can't be
/// resolved or bound, or
/// `--socket` names another socket than the one systemd passed, the signal
/// handlers can't be installed, or serving fails.
pub async fn run(args: ServeArgs, activated: Activated) -> Result<()> {
    skagent_fido::ensure_debug_off().context("refusing to serve")?;
    // Before any secret exists: the first buffer fixes where all of them live.
    if args.secret_memory == SecretMemory::MemfdSecret {
        skagent_secret::use_secretmem().context("--secret-memory memfd-secret")?;
        tracing::info!(
            "keeping secrets in memfd_secret memory; the system can't hibernate while the agent holds any"
        );
    }
    let config = load_config(args.config.as_deref())?;
    let prompt = pin_prompt(&args);
    let policy = CachePolicy {
        lifetime: args.pin_lifetime,
        idle_timeout: args.pin_idle,
    };
    let popup = args
        .popup
        .as_ref()
        .map(|program| Arc::new(Popup::new(program.clone(), config.style().clone())));
    match (&popup, &prompt) {
        (Some(popup), _) => {
            tracing::info!(popup = %popup.program().display(), "showing prompts in the popup");
        }
        (None, PinPrompt::Pinentry(pinentry)) => {
            tracing::info!(pinentry = %pinentry.program().display(), "asking for PINs with pinentry");
        }
        (None, PinPrompt::Askpass(askpass)) => {
            tracing::info!(askpass = %askpass.program().display(), "asking for PINs with askpass");
        }
    }
    if policy.caches() {
        tracing::info!(
            lifetime_seconds = policy.lifetime.as_secs(),
            idle_seconds = policy.idle().map(|idle| idle.as_secs()),
            "caching PINs"
        );
    } else {
        tracing::info!("PIN caching disabled, asking for every signature");
    }
    let (listening, age_listening) = sockets(activated, args.socket, args.age_socket)?;
    for rule in &args.pin_policies {
        tracing::info!(?rule, "caching the PINs of matching keys differently");
    }
    let mut signer = Signer::new(popup.is_none().then_some(prompt), policy)
        .with_pin_policies(args.pin_policies)
        .with_config(Arc::new(config))
        .with_plug_in_timeout(args.plug_in_timeout)
        .with_pairing(!args.no_pairing);
    match default_bindings_path(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    ) {
        Ok(file) => signer = signer.with_bindings(Bindings::remembered_in(file)),
        Err(error) => tracing::warn!(
            error = %format!("{error:#}"),
            "not remembering which YubiKey holds which key across restarts"
        ),
    }
    if let Some(popup) = popup {
        // The popup shows the touch itself.
        signer = signer.with_popup(popup);
    } else if args.no_touch_notification {
        tracing::info!("not showing touch notifications");
    } else {
        signer = signer.with_notifier(Arc::new(Notifier::default()));
    }
    let (identities, age) = remembered();
    // The socket for age requests only answers skagent's own programs, and
    // without knowing them it answers nobody.
    let (own, age_listening) = match OwnPrograms::locate() {
        Ok(own) => {
            if !own.has_plugin() {
                tracing::info!(
                    plugin = %own.plugin_path().display(),
                    "the age plugin isn't installed next to the agent: decryptions are refused"
                );
            }
            (Some(own), age_listening)
        }
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "can't find the agent's own executable: not answering age requests"
            );
            (None, None)
        }
    };
    let agent = SkAgent::with_stores(signer, identities, age, own);
    // Installed before the socket exists, so a signal can't kill the process
    // between binding and serving and leave a stale socket behind.
    let signals = ShutdownSignals::install()?;
    serve_sockets_until(listening, age_listening, agent, signals.wait()).await
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
    serve_sockets_until(listening, None, agent, shutdown).await
}

/// A socket the agent serves: the listener, its path, and what to remove on
/// shutdown if the agent bound it itself.
struct Served {
    listener: tokio::net::UnixListener,
    path: PathBuf,
    bound: Option<socket::BoundSocket>,
}

impl Served {
    fn open(listening: Listening) -> Result<Self> {
        match listening {
            Listening::Bind(path) => {
                let (listener, bound) = socket::bind(&path)?;
                Ok(Self {
                    listener,
                    path,
                    bound: Some(bound),
                })
            }
            Listening::Activated(listener) => {
                let path = activated_path(&listener)?;
                let listener = tokio::net::UnixListener::from_std(listener)
                    .context("serving the socket systemd passed")?;
                Ok(Self {
                    listener,
                    path,
                    bound: None,
                })
            }
        }
    }
}

/// [`serve_until`], also answering age requests on the socket `age`, if
/// there is one. That socket failing to open only costs the age requests,
/// with a warning.
///
/// # Errors
///
/// Returns an error where [`serve_until`] does.
pub async fn serve_sockets_until<F>(
    listening: Listening,
    age: Option<Listening>,
    agent: SkAgent,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    agent.caching_pending().await;
    let Served {
        listener,
        path: socket_path,
        bound,
    } = Served::open(listening)?;
    tracing::info!(
        socket = %socket_path.display(),
        activated = bound.is_none(),
        "agent listening, point SSH_AUTH_SOCK at the socket"
    );
    let age = age.and_then(|listening| match Served::open(listening) {
        Ok(open) => {
            tracing::info!(
                socket = %open.path.display(),
                activated = open.bound.is_none(),
                "answering age requests"
            );
            Some(open)
        }
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "can't open the socket for age requests: not answering them"
            );
            None
        }
    });
    let (age_listener, age_bound) = match age {
        Some(open) => (Some((open.listener, open.path)), open.bound),
        None => (None, None),
    };
    let age_served = async {
        match age_listener {
            Some((listener, path)) => ssh_agent_lib::agent::listen(
                PeerCheckedListener::new(listener, &path),
                agent.age_socket(),
            )
            .await
            .with_context(|| format!("serving age requests on {}", path.display())),
            None => std::future::pending().await,
        }
    };

    let served = tokio::select! {
        result = ssh_agent_lib::agent::listen(PeerCheckedListener::new(listener, &socket_path), agent.clone()) => {
            result.with_context(|| {
                format!("serving the ssh-agent protocol on {}", socket_path.display())
            })
        }
        result = age_served => result,
        result = sweep_expired(agent.clone()) => result,
        result = logind::watch(agent.clone()) => result,
        result = shutdown => result,
    };
    agent.forget_pins("shutdown").await;

    let age_removed = age_bound
        .as_ref()
        .map_or(Ok(()), socket::BoundSocket::remove);
    if let Err(error) = &age_removed {
        tracing::error!(
            error = format!("{error:#}"),
            "removing the socket for age requests"
        );
    }
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
