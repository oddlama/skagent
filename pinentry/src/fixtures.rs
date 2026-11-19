//! The design's screens with example data, for `--preview`.

use skagent_popup::{Failure, Key, Mistake, Queued, Request, SecurityKey, State};

/// The screens of design B+, by name.
pub const NAMES: [&str; 20] = [
    "pin",
    "wrong-pin",
    "touch",
    "touch-again",
    "done",
    "batch-touch",
    "batch-done",
    "select",
    "select-load",
    "load-pin",
    "load-done",
    "wrong-key",
    "nokey-known",
    "nokey-unknown",
    "replug",
    "locked",
    "new-pin",
    "timeout",
    "failed",
    "queue",
];

fn key(emoji: &str, label: &str) -> Key {
    Key {
        emoji: Some(emoji.to_owned()),
        label: label.to_owned(),
        fingerprint: "SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ".to_owned(),
    }
}

fn fox() -> Key {
    key("🦊", "github-work")
}

fn desk() -> SecurityKey {
    named("Desk 5C NFC")
}

fn named(name: &str) -> SecurityKey {
    SecurityKey {
        name: name.to_owned(),
    }
}

/// An age identity, as the agent names it.
fn identity() -> Key {
    Key {
        emoji: None,
        label: "age identity".to_owned(),
        fingerprint: "age1pq1x34nzs…fzv49zc0k".to_owned(),
    }
}

fn batch() -> Request {
    Request::Batch {
        command: "agenix rekey".to_owned(),
        seconds: 600,
    }
}

fn github() -> Request {
    Request::Login {
        user: "git".to_owned(),
        host: skagent_popup::Host::Named {
            name: "github.com".to_owned(),
        },
        via: None,
    }
}

/// The state and the waiting requests of the screen `name`.
#[must_use]
pub fn fixture(name: &str) -> Option<(State, Vec<Queued>)> {
    if name == "queue" {
        return Some(queue());
    }
    signing(name)
        .or_else(|| waiting(name))
        .map(|state| (state, Vec::new()))
}

/// The screens of a signature and of loading.
fn signing(name: &str) -> Option<State> {
    Some(match name {
        "pin" | "wrong-pin" => State::Pin {
            key: fox(),
            request: github(),
            security_key: Some(desk()),
            mistake: (name == "wrong-pin").then_some(Mistake { tries_left: 6 }),
        },
        "touch" | "touch-again" => State::Touch {
            key: fox(),
            request: github(),
            security_key: Some(desk()),
            timeout_ms: 15_000,
            again: name == "touch-again",
        },
        "done" => State::Signed {
            key: fox(),
            request: github(),
        },
        "batch-touch" => State::Touch {
            key: identity(),
            request: batch(),
            security_key: Some(desk()),
            timeout_ms: 15_000,
            again: false,
        },
        "batch-done" => State::Signed {
            key: identity(),
            request: batch(),
        },
        "select" => State::Select {
            key: Some(fox()),
            devices: 3,
            timeout_ms: 30_000,
        },
        "select-load" => State::Select {
            key: None,
            devices: 3,
            timeout_ms: 30_000,
        },
        "load-pin" => State::LoadPin {
            security_key: Some(desk()),
            mistake: None,
        },
        "load-done" => State::Loaded {
            security_key: Some(desk()),
            keys: vec![fox(), key("🐙", "github-sign"), key("🛰️", "deploy-prod")],
        },
        _ => return None,
    })
}

/// The screens that wait for the user, and the dead ends.
fn waiting(name: &str) -> Option<State> {
    Some(match name {
        "wrong-key" => State::WrongKey {
            key: fox(),
            security_key: Some(desk()),
            other: Some(named("Keychain 5 Nano")),
        },
        "nokey-known" | "nokey-unknown" => State::NoKey {
            key: Some(fox()),
            security_key: (name == "nokey-known").then(desk),
        },
        "replug" => State::Replug {
            key: Some(fox()),
            security_key: Some(desk()),
            tries_left: Some(5),
        },
        "locked" => State::Locked {
            key: Some(fox()),
            security_key: Some(desk()),
        },
        "new-pin" => State::NewPin {
            key: Some(fox()),
            security_key: Some(desk()),
        },
        "timeout" => State::Timeout {
            key: Some(fox()),
            security_key: Some(desk()),
        },
        "failed" => State::Failed {
            key: Some(fox()),
            security_key: Some(desk()),
            reason: Failure::Unplugged,
            request: None,
        },
        _ => return None,
    })
}

/// A PIN prompt with two requests waiting.
fn queue() -> (State, Vec<Queued>) {
    let waiting = vec![
        Queued {
            key: Some(key("🐙", "github-sign")),
        },
        Queued {
            key: Some(key("🛰️", "deploy-prod")),
        },
    ];
    let state = State::Pin {
        key: fox(),
        request: Request::Sign {
            namespace: "git".to_owned(),
        },
        security_key: Some(desk()),
        mistake: None,
    };
    (state, waiting)
}
