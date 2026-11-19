//! Desktop notifications (`org.freedesktop.Notifications` on the session
//! bus): while a security key waits for a touch, and while a batch of
//! decryptions runs.
//!
//! Best effort and never in the way: the D-Bus calls have short timeouts,
//! and without a session bus or a notification service everything works as
//! before.
//!
//! - **A touch** ([`Notifier::show`]): shown from a separate task and
//!   closed as soon as its [`Notification`] guard is dropped, i.e. when the
//!   touch happened or the operation ended otherwise.
//! - **A batch** ([`Notifier::standing`]): a [`Standing`] notification
//!   stays, is replaced in place as files are decrypted, and has a button
//!   to stop the batch.
//!
//! A service closes a notification whose button was pressed (unless it is
//! `resident`): `ActionInvoked`, and `NotificationClosed` right after it.
//! The two are read from one stream, in the order the service sent them. Read
//! from a stream each, whichever was looked at first won, and a pressed
//! button was taken for a notification the user had closed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use tokio::sync::{Mutex, oneshot};
use zbus::message::Type as MessageType;
use zbus::proxy::CacheProperties;
use zbus::{Connection, MatchRule, MessageStream, Proxy, Variant};

const SERVICE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

/// Longest wait for the bus or the notification service.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);

/// Should closing the notification get lost, servers drop it after this
/// (a little longer than libfido2 waits for a touch).
const EXPIRE_MILLISECONDS: i32 = 40_000;

/// Shows notifications on the session bus, connecting on first use.
#[derive(Debug, Default)]
pub struct Notifier {
    connection: Mutex<Option<Connection>>,
}

/// An open notification; closed when dropped.
#[derive(Debug)]
pub struct Notification {
    _close: Option<oneshot::Sender<()>>,
}

impl Notifier {
    /// Shows `summary` and `body` until the returned guard is dropped.
    /// Returns immediately; failures are only logged at debug level.
    #[must_use]
    pub fn show(self: &Arc<Self>, summary: &str, body: &str) -> Notification {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Notification { _close: None };
        };
        let (close, closed) = oneshot::channel::<()>();
        let notifier = Arc::clone(self);
        let (summary, body) = (summary.to_owned(), markup_escaped(body));
        drop(runtime.spawn(async move {
            let Some(proxy) = notifier.proxy().await else {
                return;
            };
            let hints: HashMap<&str, Variant<'_>> = HashMap::from([
                ("urgency", Variant::from(1_u8)),
                ("transient", Variant::from(true)),
                ("category", Variant::from("device")),
            ]);
            let shown = tokio::time::timeout(
                CALL_TIMEOUT,
                proxy.call::<_, _, u32>(
                    "Notify",
                    &(
                        "skagent",
                        0_u32,
                        "",
                        summary.as_str(),
                        body.as_str(),
                        Vec::<&str>::new(),
                        hints,
                        EXPIRE_MILLISECONDS,
                    ),
                ),
            )
            .await;
            let id = match shown {
                Ok(Ok(id)) => id,
                Ok(Err(error)) => {
                    tracing::debug!(%error, "showing a notification failed");
                    notifier.forget_connection().await;
                    return;
                }
                Err(_elapsed) => {
                    tracing::debug!("the notification service didn't answer");
                    return;
                }
            };
            // Ends when the guard is dropped.
            let _dropped = closed.await;
            let closing = tokio::time::timeout(
                CALL_TIMEOUT,
                proxy.call::<_, _, ()>("CloseNotification", &(id,)),
            )
            .await;
            if !matches!(closing, Ok(Ok(()))) {
                tracing::debug!(id, "closing a notification failed");
            }
        }));
        Notification {
            _close: Some(close),
        }
    }

    /// Prepares a notification that stays until it is closed, with the
    /// buttons `actions` (a key and a label each). `None` without a session
    /// bus or a notification service; why is logged at debug level.
    pub async fn standing(self: &Arc<Self>, actions: &[(&str, &str)]) -> Option<Standing> {
        let proxy = self.proxy().await?;
        // Before anything is shown, so that no answer is missed. All of the
        // service's signals in one stream: see the module's documentation.
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .interface(SERVICE)
            .path(PATH)
            .build()
            .map_err(|error| tracing::debug!(%error, "building a match rule failed"))
            .ok()?;
        let subscribed = tokio::time::timeout(
            CALL_TIMEOUT,
            MessageStream::for_match_rule(rule, proxy.connection(), None),
        )
        .await;
        let signals = match subscribed {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::debug!(%error, "subscribing to notification signals failed");
                return None;
            }
            Err(_elapsed) => {
                tracing::debug!("subscribing to notification signals timed out");
                return None;
            }
        };
        Some(Standing {
            notifier: Arc::clone(self),
            proxy,
            actions: actions
                .iter()
                .flat_map(|(key, label)| [(*key).to_owned(), (*label).to_owned()])
                .collect(),
            id: 0,
            pressed: None,
            signals,
        })
    }

    async fn proxy(&self) -> Option<Proxy<'static>> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            match tokio::time::timeout(CALL_TIMEOUT, Connection::session()).await {
                Ok(Ok(connected)) => *connection = Some(connected),
                Ok(Err(error)) => {
                    tracing::debug!(%error, "no session bus for notifications");
                    return None;
                }
                Err(_elapsed) => {
                    tracing::debug!("connecting to the session bus timed out");
                    return None;
                }
            }
        }
        let connection = connection.as_ref()?;
        zbus::proxy::Builder::<Proxy<'static>>::new(connection)
            .destination(SERVICE)
            .path(PATH)
            .interface(SERVICE)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|error| tracing::debug!(%error, "creating the notification proxy failed"))
            .ok()
    }

    /// Drops a connection that failed, so the next notification reconnects.
    async fn forget_connection(&self) {
        self.connection.lock().await.take();
    }
}

/// What the user did with a [`Standing`] notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Pressed the button with this key.
    Action(String),
    /// Closed it, or it went away by itself.
    Gone,
}

/// Why a notification was closed, as `NotificationClosed` says it: by a
/// call to `CloseNotification`, i.e. by skagent itself.
const CLOSED_BY_CALL: u32 = 3;

/// A notification that stays until it is closed, see
/// [`Notifier::standing`].
#[derive(Debug)]
pub struct Standing {
    notifier: Arc<Notifier>,
    proxy: Proxy<'static>,
    /// Keys and labels, alternating, as `Notify` takes them.
    actions: Vec<String>,
    /// What the service calls it; zero until it was shown, and again once
    /// one of its buttons was pressed.
    id: u32,
    /// What the service called it when one of its buttons was pressed. The
    /// press is the end of that notification; what is shown next is a new
    /// one.
    pressed: Option<u32>,
    /// The service's signals, in the order it sent them.
    signals: MessageStream,
}

impl Standing {
    /// Shows `summary` and `body` in place of what this notification showed
    /// before. `lasting`: with its buttons, until it is closed or replaced;
    /// else without buttons, for as long as the service keeps
    /// notifications. Returns whether the service took it.
    pub async fn show(&mut self, summary: &str, body: &str, lasting: bool) -> bool {
        if let Some(pressed) = self.pressed.take() {
            // A service that keeps a notification after a button was
            // pressed would show it next to this one.
            self.close_id(pressed).await;
        }
        let hints: HashMap<&str, Variant<'_>> = HashMap::from([
            ("urgency", Variant::from(1_u8)),
            ("transient", Variant::from(true)),
            ("category", Variant::from("device")),
        ]);
        let actions: Vec<&str> = if lasting {
            self.actions.iter().map(String::as_str).collect()
        } else {
            Vec::new()
        };
        // 0: never expires. -1: as the service sees fit.
        let expire: i32 = if lasting { 0 } else { -1 };
        let body = markup_escaped(body);
        let shown = tokio::time::timeout(
            CALL_TIMEOUT,
            self.proxy.call::<_, _, u32>(
                "Notify",
                &(
                    "skagent",
                    self.id,
                    "",
                    summary,
                    body.as_str(),
                    actions,
                    hints,
                    expire,
                ),
            ),
        )
        .await;
        match shown {
            Ok(Ok(id)) => {
                if id != self.id {
                    tracing::debug!(id, lasting, "showing a notification that stays");
                }
                self.id = id;
                true
            }
            Ok(Err(error)) => {
                tracing::debug!(%error, "showing a notification failed");
                self.notifier.forget_connection().await;
                false
            }
            Err(_elapsed) => {
                tracing::debug!("the notification service didn't answer");
                false
            }
        }
    }

    /// Waits for what the user does with the notification. Doesn't return
    /// if the service says nothing more. Cancel-safe.
    ///
    /// A pressed button counts for a notification the service called closed
    /// just before, too: that is the other order to say the two things in.
    /// So [`Answer::Gone`] can be followed by an [`Answer::Action`].
    pub async fn answer(&mut self) -> Answer {
        loop {
            let Some(Ok(message)) = self.signals.next().await else {
                return std::future::pending().await;
            };
            let header = message.header();
            let member = header.member().map(zbus::names::MemberName::as_str);
            match member {
                Some("ActionInvoked") => {
                    if let Ok((id, key)) = message.body().deserialize::<(u32, String)>()
                        && id == self.id
                        && id != 0
                    {
                        tracing::debug!(id, ?key, "a button of the notification was pressed");
                        self.pressed = Some(id);
                        self.id = 0;
                        return Answer::Action(key);
                    }
                }
                Some("NotificationClosed") => {
                    if let Ok((id, reason)) = message.body().deserialize::<(u32, u32)>()
                        && id == self.id
                        && id != 0
                        && reason != CLOSED_BY_CALL
                    {
                        tracing::debug!(id, reason, "the notification was closed");
                        return Answer::Gone;
                    }
                }
                _ => {}
            }
        }
    }

    /// Closes the notification, if it is shown.
    pub async fn close(mut self) {
        if let Some(pressed) = self.pressed.take() {
            self.close_id(pressed).await;
        }
        if self.id != 0 {
            self.close_id(self.id).await;
        }
    }

    /// Asks the service to close what it calls `id`. It may be gone: then
    /// the service says so, which is as good.
    async fn close_id(&self, id: u32) {
        let closing = tokio::time::timeout(
            CALL_TIMEOUT,
            self.proxy.call::<_, _, ()>("CloseNotification", &(id,)),
        )
        .await;
        if !matches!(closing, Ok(Ok(()))) {
            tracing::debug!(
                id,
                "closing a notification failed, or it was closed already"
            );
        }
    }
}

/// `text` for a notification body, which servers may render as markup. The
/// text can come from another machine (forwarded agents), so nothing in it
/// may be taken for markup.
#[must_use]
pub fn markup_escaped(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other => escaped.push(other),
        }
    }
    escaped
}
