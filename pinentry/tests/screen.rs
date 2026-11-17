//! The copy and layout of every screen, against design B+.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use skagent_pinentry::fixtures::{NAMES, fixture};
use skagent_pinentry::screen::{
    Anchor, Badge, Body, Close, Glyph, Screen, Tone, glyph, request_subtitle, short_fingerprint,
    tries_left,
};
use skagent_popup::{Host, Key, Request, State};

fn screen(name: &str) -> Result<Screen> {
    let (state, _) = fixture(name).with_context(|| format!("no fixture {name}"))?;
    Ok(Screen::of(&state))
}

/// Title and subtitle of each designed screen, word for word.
#[test]
fn every_screen_says_what_the_design_says() -> Result<()> {
    let expected = [
        ("pin", "github-work", "github.com"),
        ("wrong-pin", "github-work", "Wrong PIN · 6 tries left"),
        ("touch", "Touch your YubiKey", "Desk 5C NFC"),
        (
            "touch-again",
            "Touch once more",
            "Desk 5C NFC · now to sign",
        ),
        ("done", "Signed", "github.com"),
        (
            "select",
            "Touch the right YubiKey",
            "The one holding github-work",
        ),
        (
            "select-load",
            "Touch a YubiKey",
            "to load its keys into skagent",
        ),
        ("load-pin", "Desk 5C NFC", "Load keys into skagent"),
        ("load-done", "Loaded 3 keys", "from Desk 5C NFC"),
        (
            "wrong-key",
            "Plug in Desk 5C NFC",
            "Keychain 5 Nano doesn't hold github-work",
        ),
        ("nokey-known", "Plug in Desk 5C NFC", "It holds github-work"),
        (
            "nokey-unknown",
            "Plug in your YubiKey",
            "The one holding github-work",
        ),
        (
            "replug",
            "Unplug and reinsert",
            "Desk 5C NFC paused after 3 wrong PINs",
        ),
        (
            "locked",
            "PIN locked",
            "Desk 5C NFC can only be reset now. A reset erases every key on it.",
        ),
        (
            "new-pin",
            "Set a new PIN first",
            "Desk 5C NFC still has a temporary PIN",
        ),
        (
            "timeout",
            "Timed out",
            "Desk 5C NFC wasn't touched · PIN kept",
        ),
        (
            "failed",
            "Couldn't sign",
            "Desk 5C NFC was unplugged mid-signature",
        ),
        ("queue", "github-work", "Git signature"),
    ];
    ensure!(expected.len() == NAMES.len(), "a screen isn't checked");
    for (name, title, subtitle) in expected {
        let screen = screen(name)?;
        ensure!(screen.title == title, "{name}: title {:?}", screen.title);
        ensure!(
            screen.subtitle.text() == subtitle,
            "{name}: subtitle {:?}",
            screen.subtitle.text()
        );
    }
    Ok(())
}

#[test]
fn badges_layout_and_buttons_follow_the_design() -> Result<()> {
    let expected = [
        ("pin", None, true, Close::Cancel),
        ("touch-again", Some(Badge::Again), false, Close::Cancel),
        ("done", Some(Badge::Done), false, Close::None),
        ("load-done", Some(Badge::Done), false, Close::None),
        ("wrong-key", Some(Badge::Swap), false, Close::Cancel),
        ("nokey-known", Some(Badge::Plug), false, Close::Cancel),
        ("replug", Some(Badge::Replug), false, Close::Cancel),
        ("locked", Some(Badge::Lock), false, Close::Close),
        ("new-pin", Some(Badge::Pencil), true, Close::Close),
        ("timeout", Some(Badge::Clock), true, Close::Cancel),
        ("failed", Some(Badge::Failed), false, Close::Close),
    ];
    for (name, badge, top, close) in expected {
        let screen = screen(name)?;
        ensure!(screen.badge == badge, "{name}: badge {:?}", screen.badge);
        ensure!(screen.top_aligned() == top, "{name}: layout");
        ensure!(screen.close == close, "{name}: close {:?}", screen.close);
    }
    ensure!(matches!(
        screen("wrong-pin")?.body,
        Body::Pin { error: true, .. }
    ));
    ensure!(screen("wrong-pin")?.subtitle.tone == Tone::Error);
    ensure!(screen("select")?.body == Body::Devices(3));
    ensure!(screen("replug")?.body == Body::Tries(5));
    ensure!(matches!(screen("load-pin")?.anchor, Anchor::Device { .. }));
    ensure!(matches!(
        screen("nokey-known")?.anchor,
        Anchor::Key { missing: true, .. }
    ));
    ensure!(matches!(
        screen("touch")?.anchor,
        Anchor::Countdown { pulse: true, .. }
    ));
    ensure!(matches!(
        screen("select")?.anchor,
        Anchor::Countdown { pulse: false, .. }
    ));
    ensure!(screen("failed")?.lingers.is_some() && screen("done")?.lingers.is_some());
    Ok(())
}

#[test]
fn subtitles_name_what_is_signed() {
    let named = |name: &str| Host::Named {
        name: name.to_owned(),
    };
    let login = |host, via| Request::Login {
        user: "git".to_owned(),
        host,
        via,
    };
    let fingerprint = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".to_owned();
    let cases = [
        (login(named("github.com"), None), "github.com"),
        (
            login(named("target"), Some(named("jump"))),
            "target · via jump",
        ),
        (
            login(Host::HostKey { fingerprint }, None),
            "Unknown host · SHA256:+DiY3wvv…",
        ),
        (login(Host::Unverified, None), "Unknown host"),
        (
            Request::Sign {
                namespace: "git".to_owned(),
            },
            "Git signature",
        ),
        (
            Request::Sign {
                namespace: "file".to_owned(),
            },
            "Signature for \"file\"",
        ),
        (Request::Unknown, "Unknown request"),
    ];
    for (request, expected) in cases {
        assert_eq!(request_subtitle(&request).text(), expected);
    }
    assert_eq!(request_subtitle(&Request::Unknown).tone, Tone::Warning);
    let unknown = request_subtitle(&login(
        Host::HostKey {
            fingerprint: "SHA256:abc".to_owned(),
        },
        None,
    ));
    assert!(
        unknown
            .spans
            .iter()
            .any(|span| span.mono && span.text == "SHA256:abc")
    );
}

#[test]
fn small_words_and_fallbacks() {
    assert_eq!(tries_left(1), "1 try left");
    assert_eq!(tries_left(0), "0 tries left");
    assert_eq!(short_fingerprint("SHA256:abcdefghij"), "SHA256:abcdefgh…");
    let key = |emoji: Option<&str>, label: &str| Key {
        emoji: emoji.map(ToOwned::to_owned),
        label: label.to_owned(),
        fingerprint: String::new(),
    };
    assert_eq!(
        glyph(&key(None, "github-work")),
        Glyph::Initial("G".to_owned())
    );
    assert_eq!(glyph(&key(None, "  ")), Glyph::Initial("?".to_owned()));
    assert_eq!(glyph(&key(Some("🦊"), "x")), Glyph::Emoji("🦊".to_owned()));
}

/// Keys that aren't YubiKeys report no serial, so no name.
#[test]
fn screens_without_a_yubikey_name_still_read() {
    let touch = Screen::of(&State::Touch {
        key: Key {
            emoji: None,
            label: "work".to_owned(),
            fingerprint: String::new(),
        },
        request: Request::Unknown,
        security_key: None,
        timeout_ms: 15_000,
        again: false,
    });
    assert_eq!(touch.title, "Touch your security key");
    assert_eq!(touch.subtitle.text(), "Unknown request");
    let locked = Screen::of(&State::Locked {
        key: None,
        security_key: None,
    });
    assert!(
        locked
            .subtitle
            .text()
            .starts_with("Your security key can only")
    );
}
