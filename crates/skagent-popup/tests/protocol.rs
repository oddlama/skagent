//! The popup protocol: messages to the popup and intents from it.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, bail, ensure};
use skagent_popup::{
    Failure, Host, Intent, Key, Message, Mistake, Queued, Request, Requester, SecurityKey, State,
    VERSION, cancel_line, decode_message, encode_message, parse_intent, pin_line, ready_line,
    retry_line,
};

fn key() -> Key {
    Key {
        emoji: Some("🦊".to_owned()),
        label: "github-work".to_owned(),
        fingerprint: "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ".to_owned(),
    }
}

/// Strips the trailing newline of a line from `pin_line` and friends.
fn without_newline(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

#[test]
fn messages_are_single_json_lines_and_round_trip() -> Result<()> {
    let message = Message::Show {
        seq: 3,
        waiting: vec![Queued { key: Some(key()) }, Queued { key: None }],
        state: Box::new(State::Pin {
            key: key(),
            request: Request::Login {
                user: "git".to_owned(),
                host: Host::Named {
                    name: "github.com".to_owned(),
                },
                via: Some(Host::HostKey {
                    fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU".to_owned(),
                }),
            },
            security_key: Some(SecurityKey {
                name: "Desk 5C NFC".to_owned(),
            }),
            mistake: Some(Mistake { tries_left: 6 }),
        }),
    };
    let line = encode_message(&message)?;
    let text = String::from_utf8(line)?;
    ensure!(
        text.ends_with('\n') && text.matches('\n').count() == 1,
        "{text}"
    );
    ensure!(
        text.contains(r#""type":"show""#) && text.contains(r#""name":"pin""#),
        "{text}"
    );
    ensure!(decode_message(text.trim_end())? == message);
    Ok(())
}

#[test]
fn a_label_with_a_newline_stays_on_one_line() -> Result<()> {
    let mut key = key();
    key.label = "a\nb".to_owned();
    let line = encode_message(&Message::Show {
        seq: 1,
        waiting: Vec::new(),
        state: Box::new(State::Signed {
            key,
            request: Request::Unknown,
        }),
    })?;
    ensure!(
        line.strip_suffix(b"\n")
            .is_some_and(|body| !body.contains(&b'\n'))
    );
    Ok(())
}

#[test]
fn pins_survive_escaping_and_land_in_locked_memory() -> Result<()> {
    for pin in [
        &b"123456"[..],
        b"100%",
        b"line\nbreak\r",
        b"spaces in pin",
        "äöü€".as_bytes(),
    ] {
        let line = pin_line(7, pin)?;
        let Intent::Pin { seq, pin: parsed } = parse_intent(without_newline(line.expose()))? else {
            bail!("not parsed as a PIN");
        };
        ensure!(seq == 7);
        ensure!(parsed.expose() == pin, "{pin:?} came back different");
    }
    Ok(())
}

#[test]
fn the_other_intents_parse() -> Result<()> {
    ensure!(matches!(
        parse_intent(without_newline(ready_line().as_bytes()))?,
        Intent::Ready { version } if version == VERSION
    ));
    ensure!(matches!(
        parse_intent(without_newline(cancel_line(9).as_bytes()))?,
        Intent::Cancel { seq: 9 }
    ));
    ensure!(matches!(
        parse_intent(without_newline(retry_line(10).as_bytes()))?,
        Intent::Retry { seq: 10 }
    ));
    Ok(())
}

/// Error messages never repeat what the popup sent: a garbled line could be
/// the PIN.
#[test]
fn malformed_intents_are_refused_without_their_content() {
    let malformed: [&[u8]; 9] = [
        b"",
        b"hunter22",
        b"PIN",
        b"PIN 1",
        b"PIN x hunter22",
        b"PIN 1 hunter%2",
        b"PIN 1 hunter%zz",
        b"CANCEL",
        b"READY one",
    ];
    for line in malformed {
        let error = parse_intent(line).err();
        assert!(error.is_some(), "accepted {line:?}");
        let text = error.map(|error| format!("{error:#}")).unwrap_or_default();
        assert!(!text.contains("hunter"), "{text}");
    }
}

#[test]
fn pins_have_a_length_limit() {
    assert!(pin_line(1, b"").is_err());
    assert!(pin_line(1, &[b'1'; 257]).is_err());
    let mut line = b"PIN 1 ".to_vec();
    line.extend_from_slice(&[b'1'; 257]);
    assert!(parse_intent(&line).is_err());
}

/// One state of every kind.
fn every_state() -> Vec<State> {
    let desk = || {
        Some(SecurityKey {
            name: "Desk 5C NFC".to_owned(),
        })
    };
    let request = || Request::Sign {
        namespace: "git".to_owned(),
    };
    vec![
        State::Select {
            key: Some(key()),
            devices: 2,
            timeout_ms: 30_000,
        },
        State::Pin {
            key: key(),
            request: request(),
            security_key: desk(),
            mistake: None,
        },
        State::LoadPin {
            security_key: desk(),
            mistake: None,
        },
        State::Touch {
            key: key(),
            request: request(),
            security_key: desk(),
            timeout_ms: 15_000,
            again: false,
        },
        State::Pair {
            security_key: desk(),
            timeout_ms: 15_000,
        },
        State::Signed {
            key: key(),
            request: request(),
        },
        State::Loaded {
            security_key: desk(),
            keys: vec![key()],
        },
        State::WrongKey {
            key: key(),
            security_key: desk(),
            other: None,
        },
        State::NoKey {
            key: Some(key()),
            security_key: None,
        },
        State::Replug {
            key: Some(key()),
            security_key: desk(),
            tries_left: Some(5),
        },
        State::Locked {
            key: None,
            security_key: desk(),
        },
        State::NewPin {
            key: None,
            security_key: desk(),
        },
        State::Timeout {
            key: Some(key()),
            security_key: desk(),
        },
        State::Failed {
            key: Some(key()),
            security_key: desk(),
            reason: Failure::Unplugged,
            request: None,
        },
    ]
}

#[test]
fn state_names_are_the_ones_on_the_wire() -> Result<()> {
    let states = every_state();
    ensure!(states.len() == 14, "a state is missing from the test");
    for state in states {
        let name = state.name();
        let text = String::from_utf8(encode_message(&Message::Show {
            seq: 1,
            waiting: Vec::new(),
            state: Box::new(state),
        })?)?;
        ensure!(
            text.contains(&format!(r#""name":"{name}""#)),
            "{name}: {text}"
        );
    }
    Ok(())
}

/// A `failed` state with `reason`, as the agent would send it.
fn failed_line(reason: &str) -> String {
    format!(
        r#"{{"type":"show","seq":2,"waiting":[],"state":{{"name":"failed","key":null,"security_key":null,"reason":"{reason}"}}}}"#
    )
}

#[test]
fn failure_reasons_have_their_names_on_the_wire() -> Result<()> {
    for (reason, name) in [
        (Failure::Unplugged, "unplugged"),
        (Failure::Refused, "refused"),
        (Failure::NotOnKey, "not-on-key"),
        (Failure::NoPin, "no-pin"),
        (Failure::NotPluggedIn, "not-plugged-in"),
        (Failure::Duplicate, "duplicate"),
        (Failure::Unrecognized, "unrecognized"),
        (Failure::NotForIdentity, "not-for-identity"),
        (Failure::AnotherIdentity, "another-identity"),
        (Failure::Other, "other"),
    ] {
        let state = State::Failed {
            key: None,
            security_key: None,
            reason,
            request: None,
        };
        let message = Message::Show {
            seq: 2,
            waiting: Vec::new(),
            state: Box::new(state),
        };
        ensure!(
            String::from_utf8(encode_message(&message)?)?.trim_end() == failed_line(name),
            "{name}"
        );
        ensure!(decode_message(&failed_line(name))? == message, "{name}");
    }
    Ok(())
}

#[test]
fn an_unknown_failure_reason_is_shown_as_other() -> Result<()> {
    let Message::Show { state, .. } = decode_message(&failed_line("from-a-newer-agent"))? else {
        bail!("not a show message");
    };
    ensure!(
        matches!(
            *state,
            State::Failed {
                reason: Failure::Other,
                ..
            }
        ),
        "{state:?}"
    );
    Ok(())
}

#[test]
fn a_decryption_says_who_asks() -> Result<()> {
    let identity = Key {
        emoji: None,
        label: "age identity".to_owned(),
        fingerprint: "age1pq1x34nzs…fzv49zc0k".to_owned(),
    };
    let requesters = [
        (
            Requester::Program {
                name: Some("agenix".to_owned()),
            },
            r#""by":{"kind":"program","name":"agenix"}"#,
        ),
        (
            Requester::Program { name: None },
            r#""by":{"kind":"program","name":null}"#,
        ),
        (
            Requester::Forwarded {
                host: Host::Unverified,
                via: None,
            },
            r#""by":{"kind":"forwarded","host":{"kind":"unverified"},"via":null}"#,
        ),
        (
            Requester::Forwarded {
                host: Host::HostKey {
                    fingerprint: "SHA256:target".to_owned(),
                },
                via: Some(Host::HostKey {
                    fingerprint: "SHA256:jump".to_owned(),
                }),
            },
            r#""via":{"kind":"host-key","fingerprint":"SHA256:jump"}"#,
        ),
    ];
    for (by, expected) in requesters {
        let message = Message::Show {
            seq: 1,
            waiting: Vec::new(),
            state: Box::new(State::Touch {
                key: identity.clone(),
                request: Request::Decrypt { by },
                security_key: None,
                timeout_ms: 15_000,
                again: false,
            }),
        };
        let text = String::from_utf8(encode_message(&message)?)?;
        ensure!(text.contains(r#""kind":"decrypt""#), "{text}");
        ensure!(text.contains(expected), "{text}");
        ensure!(decode_message(text.trim_end())? == message);
    }
    Ok(())
}

#[test]
fn creating_an_identity_is_a_request_kind_of_its_own() -> Result<()> {
    let message = Message::Show {
        seq: 1,
        waiting: Vec::new(),
        state: Box::new(State::Signed {
            key: key(),
            request: Request::Create,
        }),
    };
    let text = String::from_utf8(encode_message(&message)?)?;
    ensure!(text.contains(r#""request":{"kind":"create"}"#), "{text}");
    ensure!(decode_message(text.trim_end())? == message);
    Ok(())
}

#[test]
fn a_batch_is_a_request_kind_of_its_own() -> Result<()> {
    let message = Message::Show {
        seq: 1,
        waiting: Vec::new(),
        state: Box::new(State::Touch {
            key: key(),
            request: Request::Batch {
                command: "agenix rekey".to_owned(),
                seconds: 600,
            },
            security_key: None,
            timeout_ms: 15_000,
            again: false,
        }),
    };
    let text = String::from_utf8(encode_message(&message)?)?;
    ensure!(
        text.contains(r#""request":{"kind":"batch","command":"agenix rekey","seconds":600}"#),
        "{text}"
    );
    ensure!(decode_message(text.trim_end())? == message);
    // A popup that doesn't know batches can't take one for a single file.
    let older = text.replace(r#""kind":"batch""#, r#""kind":"decrypt""#);
    ensure!(
        decode_message(older.trim_end()).is_err(),
        "decoded as a decryption"
    );
    Ok(())
}

#[test]
fn a_failure_says_what_was_asked_unless_it_was_loading() -> Result<()> {
    let failed = |request| Message::Show {
        seq: 2,
        waiting: Vec::new(),
        state: Box::new(State::Failed {
            key: None,
            security_key: None,
            reason: Failure::Refused,
            request,
        }),
    };
    // Nothing more on the wire without one: an older agent's failure reads
    // the same.
    ensure!(
        String::from_utf8(encode_message(&failed(None))?)?.trim_end() == failed_line("refused")
    );
    let decryption = failed(Some(Request::Decrypt {
        by: Requester::Program { name: None },
    }));
    let text = String::from_utf8(encode_message(&decryption)?)?;
    ensure!(
        text.contains(r#""request":{"kind":"decrypt","by":{"kind":"program","name":null}}"#),
        "{text}"
    );
    ensure!(decode_message(text.trim_end())? == decryption);
    Ok(())
}
