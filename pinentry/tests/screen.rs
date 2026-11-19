//! The copy and layout of every screen, against design B+.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use skagent_pinentry::fixtures::{NAMES, fixture};
use skagent_pinentry::screen::{
    Anchor, Badge, Body, Close, Glyph, Screen, Tone, glyph, request_subtitle, short_fingerprint,
    tries_left,
};
use skagent_popup::{Failure, Host, Key, Request, Requester, SecurityKey, State};

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
fn badges_and_buttons_follow_the_design() -> Result<()> {
    let expected = [
        ("pin", None, Close::Cancel),
        ("touch-again", Some(Badge::Again), Close::Cancel),
        ("done", Some(Badge::Done), Close::None),
        ("load-done", Some(Badge::Done), Close::None),
        ("wrong-key", Some(Badge::Swap), Close::Cancel),
        ("nokey-known", Some(Badge::Plug), Close::Cancel),
        ("replug", Some(Badge::Replug), Close::Cancel),
        ("locked", Some(Badge::Lock), Close::Close),
        ("new-pin", Some(Badge::Pencil), Close::Close),
        ("timeout", Some(Badge::Clock), Close::Cancel),
        ("failed", Some(Badge::Failed), Close::Close),
    ];
    for (name, badge, close) in expected {
        let screen = screen(name)?;
        ensure!(screen.badge == badge, "{name}: badge {:?}", screen.badge);
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
        (
            Request::Decrypt {
                by: Requester::Program {
                    name: Some("agenix".to_owned()),
                },
            },
            "Decrypt a file · agenix",
        ),
        (
            Request::Decrypt {
                by: Requester::Program { name: None },
            },
            "Decrypt a file",
        ),
        (
            Request::Decrypt {
                by: Requester::Forwarded {
                    host: named("build-host"),
                },
            },
            "Decrypt a file · for build-host",
        ),
        (
            Request::Decrypt {
                by: Requester::Forwarded {
                    host: Host::Unverified,
                },
            },
            "Decrypt a file · for Unknown host",
        ),
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

/// A decryption goes through the screens of a signature, with its own words.
#[test]
fn a_decryption_is_decrypted_not_signed() {
    let identity = || Key {
        emoji: None,
        label: "age identity".to_owned(),
        fingerprint: "age1pq1x34nzs…fzv49zc0k".to_owned(),
    };
    let request = || Request::Decrypt {
        by: Requester::Program {
            name: Some("agenix".to_owned()),
        },
    };
    let done = Screen::of(&State::Signed {
        key: identity(),
        request: request(),
    });
    assert_eq!(done.title, "Decrypted");
    assert_eq!(done.subtitle.text(), "Decrypt a file · agenix");
    assert_eq!(done.announcement, "Decrypted, Decrypt a file · agenix");

    let again = |security_key| {
        Screen::of(&State::Touch {
            key: identity(),
            request: request(),
            security_key,
            timeout_ms: 15_000,
            again: true,
        })
    };
    assert_eq!(again(None).subtitle.text(), "now to decrypt");
    assert_eq!(
        again(Some(SecurityKey {
            name: "Desk 5C NFC".to_owned(),
        }))
        .subtitle
        .text(),
        "Desk 5C NFC · now to decrypt"
    );
    let pin = Screen::of(&State::Pin {
        key: identity(),
        request: request(),
        security_key: None,
        mistake: None,
    });
    assert_eq!(pin.title, "age identity");
    assert_eq!(pin.subtitle.text(), "Decrypt a file · agenix");
}

/// Creating an age identity: the PIN, then two touches.
#[test]
fn creating_an_identity_says_what_each_touch_is_for() {
    let key = || Key {
        emoji: None,
        label: "New age identity".to_owned(),
        fingerprint: String::new(),
    };
    assert_eq!(
        request_subtitle(&Request::Create).text(),
        "Create an age identity"
    );
    let touch = |again| {
        Screen::of(&State::Touch {
            key: key(),
            request: Request::Create,
            security_key: None,
            timeout_ms: 15_000,
            again,
        })
    };
    assert_eq!(touch(false).subtitle.text(), "Create an age identity");
    assert_eq!(touch(true).title, "Touch once more");
    assert_eq!(touch(true).subtitle.text(), "now to read its recipient");
    let done = Screen::of(&State::Signed {
        key: key(),
        request: Request::Create,
    });
    assert_eq!(done.title, "Created");
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

fn work_key() -> Key {
    Key {
        emoji: None,
        label: "work".to_owned(),
        fingerprint: String::new(),
    }
}

/// The subtitle of a failed signature (`signing`) or loading.
fn failed(reason: Failure, signing: bool, name: Option<&str>) -> String {
    Screen::of(&State::Failed {
        key: signing.then(work_key),
        security_key: name.map(|name| SecurityKey {
            name: name.to_owned(),
        }),
        reason,
    })
    .subtitle
    .text()
}

/// The reason where the agent knows it, short; a pointer to the log
/// otherwise.
#[test]
fn failures_say_why_where_known() {
    let desk = Some("Desk 5C NFC");
    for (reason, signing, expected) in [
        (
            Failure::Unplugged,
            true,
            "Desk 5C NFC was unplugged mid-signature",
        ),
        (
            Failure::Unplugged,
            false,
            "Desk 5C NFC was unplugged while loading",
        ),
        (Failure::Refused, true, "Desk 5C NFC refused to sign"),
        (
            Failure::Refused,
            false,
            "Desk 5C NFC refused to list its keys",
        ),
        (Failure::NotOnKey, true, "Desk 5C NFC doesn't hold work"),
        (Failure::NotOnKey, false, "Desk 5C NFC holds no SSH keys"),
        (Failure::NoPin, true, "Desk 5C NFC has no PIN set"),
        (Failure::NotPluggedIn, true, "Desk 5C NFC wasn't plugged in"),
        (
            Failure::Duplicate,
            true,
            "Two security keys claim to be Desk 5C NFC",
        ),
        (
            Failure::Unrecognized,
            true,
            "This isn't the Desk 5C NFC skagent paired",
        ),
        (
            Failure::Other,
            true,
            "Something went wrong · see skagent's log",
        ),
    ] {
        assert_eq!(failed(reason, signing, desk), expected, "{reason:?}");
    }
    assert_eq!(
        failed(Failure::NotOnKey, true, None),
        "Your security key doesn't hold work"
    );
    assert_eq!(
        failed(Failure::NotPluggedIn, true, None),
        "No security key was plugged in"
    );
}

/// Without a name, a security key isn't called a YubiKey: keys that report
/// no serial aren't.
#[test]
fn the_wrong_key_without_names_says_security_key() {
    let screen = Screen::of(&State::WrongKey {
        key: work_key(),
        security_key: None,
        other: None,
    });
    assert_eq!(screen.title, "Plug in your security key");
    assert_eq!(
        screen.subtitle.text(),
        "This security key doesn't hold work"
    );
}

/// Right after the first signature on a key: one more touch, which the user
/// can skip.
#[test]
fn pairing_asks_for_one_more_touch() {
    let pair = |security_key: Option<SecurityKey>| {
        Screen::of(&State::Pair {
            security_key,
            timeout_ms: 15_000,
        })
    };
    let named = pair(Some(SecurityKey {
        name: "Desk 5C NFC".to_owned(),
    }));
    assert_eq!(named.title, "Touch once more");
    assert_eq!(named.subtitle.text(), "to pair Desk 5C NFC with skagent");
    assert_eq!(named.badge, Some(Badge::Again));
    assert_eq!(named.close, Close::Cancel);
    assert_eq!(
        pair(None).subtitle.text(),
        "to pair your security key with skagent"
    );
}
