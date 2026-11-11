//! Desktop notifications while a security key waits for a touch
//! (`org.freedesktop.Notifications` on the session bus).
//!
//! Best effort and never in the way: the D-Bus calls run in a separate task
//! with short timeouts, and without a session bus or a notification service
//! signing works as before. A notification is closed as soon as its
//! [`Notification`] guard is dropped, i.e. when the touch happened or the
//! operation ended otherwise.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, oneshot};
use zbus::proxy::CacheProperties;
use zbus::{Connection, Proxy, Variant};

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
