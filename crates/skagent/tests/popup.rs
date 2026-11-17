//! The popup session: starting, asking, cancelling, queueing, closing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use skagent::popup::{Popup, cancelled_in_popup};
use skagent_popup::{Key, Request, State};

const SOON: Duration = Duration::from_secs(5);

/// A fake popup in `dir` that logs every line it gets to `dir/log`. It says
/// READY unless `dir/exit` exists (then it exits right away), answers PIN
/// states with `1234%` (sent escaped) or, if `dir/cancel` exists, cancels
/// them and touch states.
fn fake_popup(dir: &Path) -> Result<PathBuf> {
    let dir = dir.display();
    support::executable_script(
        Path::new(&dir.to_string()),
        "popup",
        &format!(
            r#"echo start >> {dir}/log
[ -e {dir}/exit ] && exit 1
if [ -e {dir}/version-two ]; then echo "READY 2"; else echo "READY 1"; fi
while IFS= read -r line; do
  printf '%s\n' "$line" >> {dir}/log
  seq=$(printf '%s\n' "$line" | sed -n 's/.*"seq":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"name":"pin"'*)
      if [ -e {dir}/garbage ]; then echo "hunter2"
      elif [ -e {dir}/cancel ]; then echo "CANCEL $seq"
      else echo "PIN $seq 1234%25"; fi ;;
    *'"name":"touch"'*)
      if [ -e {dir}/cancel ]; then echo "CANCEL $seq"; fi ;;
  esac
done
echo exit >> {dir}/log"#
        ),
    )
}

fn pin_state() -> State {
    State::Pin {
        key: key(),
        request: Request::Sign {
            namespace: "git".to_owned(),
        },
        security_key: None,
        mistake: None,
    }
}

fn touch_state() -> State {
    State::Touch {
        key: key(),
        request: Request::Unknown,
        security_key: None,
        timeout_ms: 15_000,
        again: false,
    }
}

fn key() -> Key {
    Key {
        emoji: Some("🦊".to_owned()),
        label: "github-work".to_owned(),
        fingerprint: "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ".to_owned(),
    }
}

fn log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("log")).unwrap_or_default()
}

/// Waits until the fake popup's log satisfies `done`.
async fn log_until(dir: &Path, done: impl Fn(&str) -> bool) -> Result<String> {
    tokio::time::timeout(SOON, async {
        loop {
            let text = log(dir);
            if done(&text) {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .with_context(|| format!("the popup log never got there: {}", log(dir)))
}

fn popup(dir: &Path) -> Result<Arc<Popup>> {
    Ok(Arc::new(Popup::new(fake_popup(dir)?)))
}

#[tokio::test]
async fn the_pin_comes_back_from_the_popup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON).await?;
    session.start().await?;
    let pin = session.ask_pin(pin_state()).await?;
    ensure!(
        pin.expose() == b"1234%",
        "the escaped PIN was decoded wrong"
    );
    drop(session);
    let text = log_until(dir.path(), |text| text.ends_with("exit\n")).await?;
    ensure!(
        text.contains(r#""name":"pin""#) && text.contains("github-work"),
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_in_the_popup_cancels_the_request() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("cancel"), "")?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON).await?;
    session.start().await?;
    let error = session
        .ask_pin(pin_state())
        .await
        .err()
        .context("a cancelled prompt returned a PIN")?;
    ensure!(cancelled_in_popup(&error), "{error:#}");

    // While the key waits for a touch, the cancel ends the wait.
    session.show(touch_state())?;
    tokio::time::timeout(SOON, session.cancelled())
        .await
        .context("the cancel during the touch went unnoticed")?;
    Ok(())
}

#[tokio::test]
async fn a_popup_that_fails_to_start_fails_the_request() -> Result<()> {
    for flag in ["exit", "version-two"] {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(flag), "")?;
        let popup = popup(dir.path())?;
        let mut session = popup.session(SOON).await?;
        ensure!(session.start().await.is_err(), "started despite {flag}");
        ensure!(session.show(pin_state()).is_err(), "showed despite {flag}");
    }
    Ok(())
}

/// A popup that sends garbage is gone for the request, and the garbage,
/// which could be a PIN, doesn't show up in the error.
#[tokio::test]
async fn garbage_from_the_popup_ends_the_request() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("garbage"), "")?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON).await?;
    session.start().await?;
    let error = session
        .ask_pin(pin_state())
        .await
        .err()
        .context("garbage was taken for a PIN")?;
    ensure!(!format!("{error:#}").contains("hunter2"), "{error:#}");
    ensure!(!cancelled_in_popup(&error));
    Ok(())
}

#[tokio::test]
async fn waiting_requests_reuse_the_popup_and_the_last_one_closes_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let popup = popup(dir.path())?;
    let mut first = popup.session(SOON).await?;
    first.start().await?;
    first.show(touch_state())?;

    let waiting = {
        let popup = Arc::clone(&popup);
        tokio::spawn(async move {
            let mut second = popup.session(SOON).await?;
            second.start().await?;
            second.show(touch_state())?;
            Ok::<_, anyhow::Error>(second)
        })
    };
    // The popup learns that a request waits.
    log_until(dir.path(), |text| {
        text.contains(r#"{"type":"queue","waiting":1}"#)
    })
    .await?;
    drop(first);
    let second = waiting.await??;
    let text = log_until(dir.path(), |text| {
        text.matches(r#""name":"touch""#).count() == 2
    })
    .await?;
    ensure!(
        text.matches("start").count() == 1,
        "the popup was started twice: {text}"
    );
    ensure!(
        !text.contains("exit"),
        "the popup closed while a request waited: {text}"
    );

    drop(second);
    log_until(dir.path(), |text| text.ends_with("exit\n")).await?;
    Ok(())
}

#[tokio::test]
async fn a_busy_popup_makes_others_give_up_in_time() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let popup = popup(dir.path())?;
    let _first = popup.session(SOON).await?;
    ensure!(
        popup.session(Duration::from_millis(100)).await.is_err(),
        "waited past the timeout"
    );
    Ok(())
}
