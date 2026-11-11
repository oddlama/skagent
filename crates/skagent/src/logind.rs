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
//!
//! The signal loop must keep polling all streams: zbus blocks its socket
//! reader when any subscription queue is full, which would also stall the
//! reply to a method call made from inside the loop. So the calls made
//! there (session ownership, the sleep inhibitor after resuming) are
//! bounded by [`CALL_IN_LOOP_TIMEOUT`], and proxies don't cache properties
//! (caching adds a match rule and a `GetAll` round trip per proxy). A
//! timed-out inhibitor ends the watch like a lost connection: caching stays
//! off until the next attempt succeeds.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use anyhow::{Context as _, Result};
use futures_util::StreamExt as _;
use rustix::process::geteuid;
use zbus::message::Type as MessageType;
use zbus::proxy::CacheProperties;
use zbus::{
    Connection, MatchRule, Message, MessageStream, OwnedFd, OwnedObjectPath, OwnedVariant, Proxy,
};

use crate::agent::SkAgent;

const LOGIND: &str = "org.freedesktop.login1";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const SESSIONS_PATH: &str = "/org/freedesktop/login1/session";

/// Pause before reconnecting after the bus or logind went away.
const RETRY_DELAY: Duration = Duration::from_secs(30);

/// Longest wait for a method call made inside the signal loop. Well below
/// logind's default sleep delay (`InhibitDelayMaxSec=5`), so a slow call
/// can't hold up the `PrepareForSleep` handling until the machine suspends
/// anyway.
const CALL_IN_LOOP_TIMEOUT: Duration = Duration::from_secs(1);

/// Watches logind on the system bus until the process ends.
///
/// While disconnected, signing asks for the PIN every time. Caching only
/// resumes once subscriptions and a sleep delay inhibitor are in place.
///
/// # Errors
///
/// Never returns; the `Result` lets it run next to the agent in a `select!`.
pub async fn watch(agent: SkAgent) -> Result<()> {
    watch_with(agent, Connection::system).await
}

/// [`watch`], connecting to the bus with `connect` on every attempt.
///
/// Only losing an established watch evicts PINs and revokes requests.
/// Attempts that fail before it was established change nothing: requests
/// running meanwhile missed no lock or sleep event, and caching is already
/// off. So a machine without logind still signs, just uncached.
///
/// # Errors
///
/// Never returns; the `Result` lets it run next to the agent in a `select!`.
pub async fn watch_with<C, F>(agent: SkAgent, mut connect: C) -> Result<()>
where
    C: FnMut() -> F,
    F: Future<Output = zbus::Result<Connection>>,
{
    let uid = geteuid().as_raw();
    let mut warn_on_failure = true;
    loop {
        let mut connected = false;
        let attempt = async {
            let connection = connect().await.context("connecting to the system D-Bus")?;
            run(&agent, &connection, uid, &mut connected).await
        };
        let error = match attempt.await {
            Ok(never) => match never {},
            Err(error) => error,
        };
        agent.set_caching_available(false).await;
        let forgotten = if connected {
            agent.forget_pins("logind connection lost").await
        } else {
            0
        };
        if connected || warn_on_failure {
            tracing::warn!(
                error = %format!("{error:#}"),
                forgotten,
                retry_seconds = RETRY_DELAY.as_secs(),
                "can't watch logind; PIN caching is disabled until it works again"
            );
        } else {
            tracing::debug!(error = %format!("{error:#}"), "still can't watch logind");
        }
        warn_on_failure = false;
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

async fn run(
    agent: &SkAgent,
    connection: &Connection,
    uid: u32,
    connected: &mut bool,
) -> Result<Infallible> {
    let mut owners = owner_changes(connection).await?;
    let manager = uncached_proxy(connection, MANAGER_PATH.to_owned(), MANAGER_INTERFACE)
        .await
        .context("opening the logind manager")?;
    let mut inhibitor = Some(inhibit(&manager).await?);
    let owner = zbus::fdo::DBusProxy::new(connection)
        .await?
        .get_name_owner(LOGIND.try_into()?)
        .await
        .context("finding logind's bus owner")?;
    let mut locks = subscribe(
        connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(owner.as_str())
            .interface(SESSION_INTERFACE)
            .member("Lock")
            .path_namespace(SESSIONS_PATH),
        "Session.Lock",
    )
    .await?;
    let mut hints = subscribe(
        connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(owner.as_str())
            .interface(PROPERTIES_INTERFACE)
            .member("PropertiesChanged")
            .path_namespace(SESSIONS_PATH)
            .arg(0, SESSION_INTERFACE),
        "Session properties",
    )
    .await?;
    let mut sleeps = subscribe(
        connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(owner.as_str())
            .interface(MANAGER_INTERFACE)
            .member("PrepareForSleep")
            .path(MANAGER_PATH),
        "Manager.PrepareForSleep",
    )
    .await?;
    let sleeping: bool = manager
        .get_property("PreparingForSleep")
        .await
        .context("reading logind's sleep state")?;
    if sleeping {
        drop(inhibitor.take());
    }
    agent.set_caching_available(!sleeping).await;
    *connected = true;
    tracing::info!(
        uid,
        "dropping cached PINs when a session locks or the machine sleeps (logind)"
    );

    loop {
        tokio::select! {
            _ = owners.next() => anyhow::bail!("logind's bus owner changed; reconnecting"),
            message = locks.next() => {
                let message = message.context("the Session.Lock subscription ended")?.context("receiving Session.Lock")?;
                if ours(connection, &message, uid).await {
                    agent.forget_pins("session locked").await;
                }
            }
            message = hints.next() => {
                let message = message.context("the session property subscription ended")?.context("receiving PropertiesChanged")?;
                let (_interface, changed, invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
                    message.body().deserialize().context("decoding PropertiesChanged")?;
                let locked = changed
                    .get("LockedHint")
                    .is_some_and(|hint| bool::try_from(hint).unwrap_or(true))
                    || invalidated.iter().any(|name| name == "LockedHint");
                if locked && ours(connection, &message, uid).await {
                    agent.forget_pins("session locked (LockedHint)").await;
                }
            }
            message = sleeps.next() => {
                let message = message.context("the PrepareForSleep subscription ended")?.context("receiving PrepareForSleep")?;
                let suspending: bool = message.body().deserialize().context("decoding PrepareForSleep")?;
                if suspending {
                    agent.set_caching_available(false).await;
                    agent.forget_pins("suspending").await;
                    // logind waits for this fd to close (up to its delay limit).
                    drop(inhibitor.take());
                } else {
                    // A method call inside the loop: bounded, see above.
                    let taken = tokio::time::timeout(CALL_IN_LOOP_TIMEOUT, inhibit(&manager))
                        .await
                        .context("taking logind's sleep delay inhibitor after resuming timed out")??;
                    inhibitor = Some(taken);
                    agent.set_caching_available(true).await;
                }
            }
        }
    }
}

async fn uncached_proxy(
    connection: &Connection,
    path: String,
    interface: &'static str,
) -> zbus::Result<Proxy<'static>> {
    zbus::proxy::Builder::<Proxy<'static>>::new(connection)
        .destination(LOGIND)
        .path(path)
        .interface(interface)
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

async fn owner_changes(connection: &Connection) -> Result<MessageStream> {
    subscribe(
        connection,
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender("org.freedesktop.DBus")
            .interface("org.freedesktop.DBus")
            .member("NameOwnerChanged")
            .arg(0, LOGIND),
        "logind owner changes",
    )
    .await
}

async fn inhibit(manager: &Proxy<'_>) -> Result<OwnedFd> {
    manager
        .call(
            "Inhibit",
            &("sleep", "skagent", "Drop cached PINs before sleep", "delay"),
        )
        .await
        .context("taking logind's sleep delay inhibitor")
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
/// be found out in time, it counts as ours: dropping PINs once too often only
/// costs a prompt.
async fn ours(connection: &Connection, message: &Message, uid: u32) -> bool {
    let header = message.header();
    let Some(path) = header.path() else {
        return true;
    };
    let owner = async {
        let session =
            uncached_proxy(connection, path.as_str().to_owned(), SESSION_INTERFACE).await?;
        let (owner, _user_path): (u32, OwnedObjectPath) = session.get_property("User").await?;
        Ok::<u32, zbus::Error>(owner)
    };
    match tokio::time::timeout(CALL_IN_LOOP_TIMEOUT, owner).await {
        Ok(Ok(owner)) => owner == uid,
        Ok(Err(error)) => {
            tracing::debug!(%error, session = %path, "can't tell whose session locked, assuming ours");
            true
        }
        Err(_elapsed) => {
            tracing::warn!(session = %path, "looking up whose session locked timed out, assuming ours");
            true
        }
    }
}
