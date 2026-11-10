//! Dropping cached PINs when a session of ours locks or the machine is about
//! to sleep, through logind on the system D-Bus.
//!
//! Three signals count:
//! - `Session.Lock`: `loginctl lock-session`, which swayidle, hypridle and
//!   xss-lock react to.
//! - `LockedHint` turning true on a session: GNOME's own lock (Super+L) only
//!   sets the hint and never sends `Lock`.
//! - `Manager.PrepareForSleep(true)`: right before suspend or hibernate.
//!
//! A screen locker that does none of this needs `skagent forget` in its lock
//! command.

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context as _, Result};
use futures_util::StreamExt as _;
use rustix::process::geteuid;
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, Message, MessageStream, OwnedObjectPath, OwnedVariant, Proxy};

use crate::agent::SkAgent;

const LOGIND: &str = "org.freedesktop.login1";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const SESSIONS_PATH: &str = "/org/freedesktop/login1/session";

/// Pause before reconnecting after the bus or logind went away.
const RETRY_DELAY: Duration = Duration::from_secs(30);

/// Watches logind until the process ends.
///
/// While not connected, a lock can't be noticed. So every lost or failed
/// connection drops all PINs, and the first failure after a working
/// connection is logged as a warning.
///
/// # Errors
///
/// Never returns; the `Result` lets it run next to the agent in a `select!`.
pub async fn watch(agent: SkAgent) -> Result<()> {
    let uid = geteuid().as_raw();
    let mut warn_on_failure = true;
    loop {
        let mut connected = false;
        let error = match run(&agent, uid, &mut connected).await {
            Ok(never) => match never {},
            Err(error) => error,
        };
        let forgotten = agent.forget_pins("logind connection lost").await;
        if connected || warn_on_failure {
            tracing::warn!(
                error = %format!("{error:#}"),
                forgotten,
                retry_seconds = RETRY_DELAY.as_secs(),
                "can't watch logind, cached PINs are not dropped on screen lock or suspend until it works again"
            );
        } else {
            tracing::debug!(error = %format!("{error:#}"), "still can't watch logind");
        }
        warn_on_failure = false;
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

async fn run(agent: &SkAgent, uid: u32, connected: &mut bool) -> Result<Infallible> {
    let connection = Connection::system()
        .await
        .context("connecting to the system D-Bus")?;
    let mut locks = subscribe(
        &connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(LOGIND)
            .interface(SESSION_INTERFACE)
            .member("Lock")
            .path_namespace(SESSIONS_PATH),
        "Session.Lock",
    )
    .await?;
    let mut hints = subscribe(
        &connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(LOGIND)
            .interface(PROPERTIES_INTERFACE)
            .member("PropertiesChanged")
            .path_namespace(SESSIONS_PATH)
            .arg(0, SESSION_INTERFACE),
        "Session properties",
    )
    .await?;
    let mut sleeps = subscribe(
        &connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(LOGIND)
            .interface(MANAGER_INTERFACE)
            .member("PrepareForSleep")
            .path(MANAGER_PATH),
        "Manager.PrepareForSleep",
    )
    .await?;
    *connected = true;
    tracing::info!(
        uid,
        "dropping cached PINs when a session locks or the machine sleeps (logind)"
    );

    loop {
        tokio::select! {
            message = locks.next() => {
                let message = message.context("the Session.Lock subscription ended")?.context("receiving Session.Lock")?;
                if ours(&connection, &message, uid).await {
                    agent.forget_pins("session locked").await;
                }
            }
            message = hints.next() => {
                let message = message.context("the session property subscription ended")?.context("receiving PropertiesChanged")?;
                let (_interface, changed, _invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
                    message.body().deserialize().context("decoding PropertiesChanged")?;
                let locked = changed
                    .get("LockedHint")
                    .is_some_and(|hint| bool::try_from(hint).unwrap_or(false));
                if locked && ours(&connection, &message, uid).await {
                    agent.forget_pins("session locked (LockedHint)").await;
                }
            }
            message = sleeps.next() => {
                let message = message.context("the PrepareForSleep subscription ended")?.context("receiving PrepareForSleep")?;
                let suspending: bool = message.body().deserialize().context("decoding PrepareForSleep")?;
                if suspending {
                    agent.forget_pins("suspending").await;
                }
            }
        }
    }
}

async fn subscribe(
    connection: &Connection,
    rule: zbus::match_rule::Builder<'_>,
    what: &str,
) -> Result<MessageStream> {
    let rule = rule
        .build()
        .with_context(|| format!("building the {what} match rule"))?;
    MessageStream::for_match_rule(rule, connection, None)
        .await
        .with_context(|| format!("subscribing to {what}"))
}

/// Whether the session that sent `message` belongs to `uid`. If that can't
/// be found out, it counts as ours: dropping PINs once too often only costs
/// a prompt.
async fn ours(connection: &Connection, message: &Message, uid: u32) -> bool {
    let header = message.header();
    let Some(path) = header.path() else {
        return true;
    };
    let owner = async {
        let session = Proxy::new(
            connection,
            LOGIND,
            path.as_str().to_owned(),
            SESSION_INTERFACE,
        )
        .await?;
        let (owner, _user_path): (u32, OwnedObjectPath) = session.get_property("User").await?;
        Ok::<u32, zbus::Error>(owner)
    };
    match owner.await {
        Ok(owner) => owner == uid,
        Err(error) => {
            tracing::debug!(%error, session = %path, "can't tell whose session locked, assuming ours");
            true
        }
    }
}
