//! The popup session: starting, asking, cancelling, queueing, closing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use skagent::popup::{Popup, cancelled_in_popup, not_shown};
use skagent_popup::style::Style;
use skagent_popup::{Key, Message, Queued, Request, State, decode_message};

const SOON: Duration = Duration::from_secs(5);

/// A fake popup in `dir` that logs every line it gets to `dir/log`. It says
/// READY unless `dir/exit` exists (then it exits right away), says of every
/// state that it is shown (not with `dir/blind`, and with `dir/slow` only
/// after 400 ms), answers PIN states with `1234%` (sent escaped) and
/// timeouts with RETRY or, if `dir/cancel` exists, cancels them and touch
/// states.
fn fake_popup(dir: &Path) -> Result<PathBuf> {
    let dir = dir.display();
    support::executable_script(
        Path::new(&dir.to_string()),
        "popup",
        &format!(
            r#"echo start >> {dir}/log
[ -e {dir}/exit ] && exit 1
if [ -e {dir}/old-version ]; then echo "READY 1"; else echo "READY 2"; fi
while IFS= read -r line; do
  printf '%s\n' "$line" >> {dir}/log
  seq=$(printf '%s\n' "$line" | sed -n 's/.*"seq":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"type":"show"'*)
      if [ -e {dir}/slow ]; then sleep 0.4; fi
      if [ ! -e {dir}/blind ]; then echo "SHOWN $seq"; fi ;;
  esac
  case "$line" in
    *'"name":"pin"'*)
      if [ -e {dir}/garbage ]; then echo "hunter2"
      elif [ -e {dir}/cancel ]; then echo "CANCEL $seq"
      else echo "PIN $seq 1234%25"; fi ;;
    *'"name":"touch"'*)
      if [ -e {dir}/cancel ]; then echo "CANCEL $seq"; fi ;;
    *'"name":"timeout"'*)
      if [ -e {dir}/cancel ]; then echo "CANCEL $seq"; else echo "RETRY $seq"; fi ;;
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

fn queued() -> Queued {
    Queued { key: Some(key()) }
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
    Ok(Arc::new(Popup::new(fake_popup(dir)?, Style::default())))
}

#[tokio::test]
async fn every_started_popup_first_learns_how_to_look() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = skagent::config::Config::parse(
        "[popup]\nscale = 1.5\n[popup.dark]\naccent = \"#88c0d0\"\n",
    )?;
    let popup = Arc::new(Popup::new(fake_popup(dir.path())?, config.style().clone()));
    for round in 1..=2 {
        let mut session = popup.session(SOON, queued()).await?;
        session.start().await?;
        drop(session);
        log_until(dir.path(), |text| text.matches("exit\n").count() == round).await?;
    }
    let text = log(dir.path());
    let lines: Vec<&str> = text.lines().collect();
    let firsts: Vec<&str> = lines
        .windows(2)
        .filter_map(|pair| match pair {
            ["start", first] => Some(*first),
            _ => None,
        })
        .collect();
    ensure!(firsts.len() == 2, "{text}");
    for first in firsts {
        let Message::Style { style } = decode_message(first)? else {
            bail!("the first line wasn't the style: {first}");
        };
        ensure!(style.scale_percent == 150 && style.dark.accent.to_string() == "#88c0d0");
    }
    Ok(())
}

#[tokio::test]
async fn the_pin_comes_back_from_the_popup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON, queued()).await?;
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
    let mut session = popup.session(SOON, queued()).await?;
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
async fn a_timeout_is_retried_or_cancelled_in_the_popup() -> Result<()> {
    let timeout = || State::Timeout {
        key: Some(key()),
        security_key: None,
    };
    let dir = tempfile::tempdir()?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON, queued()).await?;
    session.start().await?;
    session.ask_retry(timeout()).await?;

    std::fs::write(dir.path().join("cancel"), "")?;
    let error = session
        .ask_retry(timeout())
        .await
        .err()
        .context("a cancel was taken for a retry")?;
    ensure!(cancelled_in_popup(&error), "{error:#}");
    Ok(())
}

#[tokio::test]
async fn a_popup_that_fails_to_start_fails_the_request() -> Result<()> {
    for flag in ["exit", "old-version"] {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(flag), "")?;
        let popup = popup(dir.path())?;
        let mut session = popup.session(SOON, queued()).await?;
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
    let mut session = popup.session(SOON, queued()).await?;
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
    let mut first = popup.session(SOON, queued()).await?;
    first.start().await?;
    first.show(touch_state())?;

    let waiting = {
        let popup = Arc::clone(&popup);
        tokio::spawn(async move {
            let mut second = popup.session(SOON, queued()).await?;
            second.start().await?;
            second.show(touch_state())?;
            Ok::<_, anyhow::Error>(second)
        })
    };
    // The popup learns that a request waits, and with which key.
    log_until(dir.path(), |text| {
        text.lines().any(|line| {
            line.starts_with(r#"{"type":"queue","waiting":[{"key":{"#)
                && line.contains("github-work")
        })
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
    let _first = popup.session(SOON, queued()).await?;
    ensure!(
        popup
            .session(Duration::from_millis(100), queued())
            .await
            .is_err(),
        "waited past the timeout"
    );
    Ok(())
}

/// What the user has to see before something happens isn't taken for
/// shown because it was sent.
#[tokio::test]
async fn what_has_to_be_seen_waits_until_the_popup_says_it_shows_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("slow"), "")?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON, queued()).await?;
    session.start().await?;
    let sent = std::time::Instant::now();
    session.show_visibly(touch_state()).await?;
    ensure!(
        sent.elapsed() >= Duration::from_millis(300),
        "went on {} ms after sending the state, before the popup showed it",
        sent.elapsed().as_millis()
    );
    // A result is only read: nothing waits for it.
    let sent = std::time::Instant::now();
    session.show(touch_state())?;
    ensure!(sent.elapsed() < Duration::from_millis(300));
    Ok(())
}

/// A popup that takes the states and shows nothing (its window can't open,
/// its drawing thread is gone): the request fails instead of asking for a
/// touch or a PIN nobody was told about, and the popup isn't used again.
#[tokio::test]
async fn a_popup_that_shows_nothing_fails_the_request_and_is_replaced() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("blind"), "")?;
    let popup = Arc::new(
        Popup::new(fake_popup(dir.path())?, Style::default())
            .showing_within(Duration::from_millis(300)),
    );
    let mut first = popup.session(SOON, queued()).await?;
    first.start().await?;
    let error = first
        .show_visibly(touch_state())
        .await
        .err()
        .context("a state nobody showed counted as shown")?;
    ensure!(not_shown(&error), "{error:#}");
    ensure!(!cancelled_in_popup(&error), "{error:#}");
    // The fake popup answers every PIN state: an answer to a prompt that
    // isn't on the screen is no answer.
    let error = first
        .ask_pin(pin_state())
        .await
        .err()
        .context("took a PIN for a prompt nobody showed")?;
    ensure!(not_shown(&error), "{error:#}");

    // A request that waits doesn't inherit the broken popup.
    let waiting = {
        let popup = Arc::clone(&popup);
        tokio::spawn(async move {
            let mut second = popup.session(SOON, queued()).await?;
            second.start().await?;
            second.show_visibly(touch_state()).await?;
            Ok::<_, anyhow::Error>(second)
        })
    };
    log_until(dir.path(), |text| {
        text.contains(r#"{"type":"queue","waiting":[{"#)
    })
    .await?;
    std::fs::remove_file(dir.path().join("blind"))?;
    drop(first);
    let second = waiting.await??;
    let text = log(dir.path());
    ensure!(
        text.matches("start\n").count() == 2,
        "the popup that showed nothing was used again: {text}"
    );
    // The first one was killed, not asked to leave.
    ensure!(!text.contains("exit\n"), "{text}");
    drop(second);
    log_until(dir.path(), |text| text.ends_with("exit\n")).await?;
    Ok(())
}

/// Cancelling doesn't have to wait for a popup that is slow to show.
#[tokio::test]
async fn a_cancel_ends_the_wait_for_a_state_to_be_shown() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("blind"), "")?;
    std::fs::write(dir.path().join("cancel"), "")?;
    let popup = popup(dir.path())?;
    let mut session = popup.session(SOON, queued()).await?;
    session.start().await?;
    let error = tokio::time::timeout(SOON, session.show_visibly(touch_state()))
        .await
        .context("the cancel went unnoticed until the popup was given up")?
        .err()
        .context("a cancelled state counted as shown")?;
    ensure!(cancelled_in_popup(&error), "{error:#}");
    Ok(())
}

#[test]
fn a_state_gets_longer_to_be_shown_than_the_one_before_may_stay() {
    // A failure of the request before stays for `LONGEST_LINGER`, and the
    // next request's first state only follows it.
    assert!(
        skagent::popup::SHOW_TIMEOUT
            >= skagent_popup::LONGEST_LINGER.saturating_add(Duration::from_secs(3))
    );
}

#[test]
fn a_closed_popup_gets_longer_to_leave_than_it_may_keep_a_final_state_up() {
    // A failure stays for `LONGEST_LINGER`. A popup killed at that very
    // moment would be cut off mid-sentence, and logged as stuck.
    assert!(
        skagent::popup::CLOSE_TIMEOUT
            >= skagent_popup::LONGEST_LINGER.saturating_add(Duration::from_secs(2))
    );
}
