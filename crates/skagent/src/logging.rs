//! Log setup with a hard redaction rule for the protocol library.

use std::io;

use anyhow::{Context as _, Result};
use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, FilterExt as _, filter_fn};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Layer as _, fmt};

/// Log target of `ssh-agent-lib`. It logs every request and response at
/// `debug` level, including key handles and `LOCK` passphrases.
const PROTOCOL_LIBRARY_TARGET: &str = "ssh_agent_lib";

/// Installs the global log subscriber, writing to stderr.
///
/// `filter` uses `tracing` env-filter syntax. Whatever it says, events that
/// [`is_redacted`] matches are dropped. `log` records from dependencies are
/// bridged into `tracing` and pass through the same filters.
///
/// # Errors
///
/// Returns an error if `filter` doesn't parse or a global subscriber is
/// already installed.
pub fn init(filter: &str, ansi: bool) -> Result<()> {
    let env_filter = EnvFilter::try_new(filter)
        .with_context(|| format!("parsing log filter {filter:?} (from --log or SKAGENT_LOG)"))?;
    let redaction = filter_fn(|metadata| !is_redacted(metadata.target(), *metadata.level()));
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(io::stderr)
                .with_ansi(ansi)
                .with_filter(env_filter.and(redaction)),
        )
        .try_init()
        .context("installing the global log subscriber")
}

/// Whether an event must never be logged: anything more verbose than `info`
/// from the protocol library, because that output contains secrets.
#[must_use]
pub fn is_redacted(target: &str, level: Level) -> bool {
    let from_protocol_library = target == PROTOCOL_LIBRARY_TARGET
        || target
            .strip_prefix(PROTOCOL_LIBRARY_TARGET)
            .is_some_and(|rest| rest.starts_with("::"));
    // `tracing` orders levels by verbosity: TRACE > DEBUG > INFO.
    from_protocol_library && level > Level::INFO
}
