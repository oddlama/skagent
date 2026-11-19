//! What one screen of the popup shows, derived from the agent's state: the
//! copy and layout of design B+, free of any GUI code so it can be tested.

use std::time::Duration;

use skagent_popup::{Failure, Host, Key, Request, Requester, SecurityKey, State};

/// PIN tries a YubiKey starts with: the dots of the re-plug screen.
pub const TOTAL_TRIES: u32 = 8;

/// How long `select` waits when the agent doesn't say.
const SELECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Final screens stay this long before the next request or the end.
const SIGNED_FOR: Duration = Duration::from_millis(900);
/// As long as the agent gives a popup at all once it closed its input.
const FAILED_FOR: Duration = skagent_popup::LONGEST_LINGER;

/// Loaded keys shown as tiles; more become `+N`.
const MAX_TILES: usize = 5;

/// Base64 characters of a host key fingerprint shown before the `…`.
const FINGERPRINT_CHARS: usize = 8;

/// One screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The picture at the top.
    pub anchor: Anchor,
    /// The status badge on the anchor.
    pub badge: Option<Badge>,
    /// What to do.
    pub title: String,
    /// What it's for, or what went wrong.
    pub subtitle: Subtitle,
    /// The bottom slot.
    pub body: Body,
    /// The ✕ button.
    pub close: Close,
    /// For screen readers when the screen appears.
    pub announcement: String,
    /// For final screens: how long they stay at least.
    pub lingers: Option<Duration>,
}

/// The picture at the top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// The SSH key's emoji in a rounded square.
    Key {
        /// Emoji or initial.
        glyph: Glyph,
        /// Fill behind it.
        tint: Tint,
        /// Faded with a dashed outline: the YubiKey holding it is missing.
        missing: bool,
    },
    /// A YubiKey drawing in a rounded square.
    Device {
        /// Fill behind it.
        tint: Tint,
        /// How the contact is drawn.
        contact: Contact,
    },
    /// A circle with a countdown ring, for the screens that wait for a
    /// touch.
    Countdown {
        /// The SSH key's glyph, or a YubiKey drawing without one.
        glyph: Option<Glyph>,
        /// How long the ring drains.
        duration: Duration,
        /// Pulse rings behind it.
        pulse: bool,
    },
}

/// The SSH key's emoji, or the initial of its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Glyph {
    /// A configured emoji.
    Emoji(String),
    /// The first letter of the label, upper case.
    Initial(String),
}

/// Fill behind an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tint {
    /// `avatarTint`.
    Key,
    /// `avatarTintWarning`.
    Warning,
    /// `avatarTintError`.
    Error,
    /// `deviceTint`.
    Device,
}

/// The contact of the YubiKey drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contact {
    /// Filled in the warning colour.
    Filled,
    /// Just an outline (locked).
    Outline,
}

/// A status badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// ⇅ on warning: swap YubiKeys.
    Swap,
    /// A plug on accent: plug one in.
    Plug,
    /// ↻ on warning, bobbing: re-plug.
    Replug,
    /// A clock on warning: timed out.
    Clock,
    /// A pencil on warning: change the PIN.
    Pencil,
    /// A lock on error: locked.
    Lock,
    /// ! on error: failed.
    Failed,
    /// ✓ on success, popping in: done.
    Done,
    /// "2×": the second touch.
    Again,
}

/// The subtitle: text, partly monospaced, in one tone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subtitle {
    /// The pieces.
    pub spans: Vec<Span>,
    /// How it's coloured.
    pub tone: Tone,
}

impl Subtitle {
    fn muted(text: impl Into<String>) -> Self {
        Self {
            spans: vec![Span::text(text)],
            tone: Tone::Muted,
        }
    }

    /// The whole text, for tests and announcements.
    #[must_use]
    pub fn text(&self) -> String {
        self.spans.iter().map(|span| span.text.as_str()).collect()
    }
}

/// A piece of a subtitle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The text.
    pub text: String,
    /// In the monospaced font (fingerprints).
    pub mono: bool,
}

impl Span {
    fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mono: false,
        }
    }
}

/// How the subtitle is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// `textMuted`.
    Muted,
    /// `error`, weight 500.
    Error,
    /// `warning`.
    Warning,
}

/// The bottom slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Nothing.
    Empty,
    /// The PIN field with its submit button.
    Pin {
        /// After a wrong PIN: the error ring, and a shake.
        error: bool,
        /// The submit button's accessible name.
        submit: &'static str,
    },
    /// The Try again button.
    TryAgain,
    /// A command to copy.
    Command(&'static str),
    /// A spinner: waiting for a YubiKey.
    Spinner,
    /// One blinking YubiKey per plugged-in key, and how many.
    Devices(usize),
    /// Tries left out of [`TOTAL_TRIES`], as dots and a caption.
    Tries(u32),
    /// The loaded keys, and how many more there are.
    Tiles {
        /// Up to five glyphs.
        glyphs: Vec<Glyph>,
        /// Keys beyond those.
        more: usize,
    },
    /// A bar that drains until the screen closes.
    Closing(Duration),
}

/// The ✕ button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Close {
    /// No button.
    None,
    /// Cancels the request.
    Cancel,
    /// Closes a final screen.
    Close,
}

impl Close {
    /// The accessible name.
    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Cancel => Some("Cancel"),
            Self::Close => Some("Close"),
        }
    }
}

impl Screen {
    /// The screen for `state`.
    #[must_use]
    pub fn of(state: &State) -> Self {
        match state {
            State::Pin {
                key,
                request,
                mistake,
                ..
            } => pin(
                Anchor::key(key, Tint::Key),
                key.label.clone(),
                request_subtitle(request),
                mistake.map(|mistake| mistake.tries_left),
                "Unlock",
            ),
            State::LoadPin {
                security_key,
                mistake,
            } => pin(
                Anchor::device(),
                name_or(security_key.as_ref(), "Your security key"),
                Subtitle::muted("Load keys into skagent"),
                mistake.map(|mistake| mistake.tries_left),
                "Load",
            ),
            State::Touch {
                key,
                security_key,
                timeout_ms,
                again,
                request,
            } => touch(key, security_key.as_ref(), request, *timeout_ms, *again),
            State::Pair {
                security_key,
                timeout_ms,
            } => pair(security_key.as_ref(), *timeout_ms),
            State::Signed { key, request } => signed(key, request),
            State::Select {
                key,
                devices,
                timeout_ms,
            } => select(key.as_ref(), *devices, *timeout_ms),
            State::Loaded { security_key, keys } => loaded(security_key.as_ref(), keys),
            State::WrongKey {
                key,
                security_key,
                other,
            } => waiting(
                Anchor::missing(key),
                Badge::Swap,
                format!(
                    "Plug in {}",
                    name_or(security_key.as_ref(), "your security key")
                ),
                Subtitle::muted(format!(
                    "{} doesn't hold {}",
                    name_or(other.as_ref(), "This security key"),
                    key.label
                )),
            ),
            State::NoKey { key, security_key } => no_key(key.as_ref(), security_key.as_ref()),
            State::Replug {
                key,
                security_key,
                tries_left,
            } => replug(key.as_ref(), security_key.as_ref(), *tries_left),
            State::Locked { security_key, .. } => locked(security_key.as_ref()),
            State::NewPin { security_key, .. } => new_pin(security_key.as_ref()),
            State::Timeout { key, security_key } => timeout(key.as_ref(), security_key.as_ref()),
            State::Failed {
                key,
                security_key,
                reason,
                request,
            } => failed(
                key.as_ref(),
                security_key.as_ref(),
                *reason,
                request.as_ref(),
            ),
        }
    }
}

impl Anchor {
    fn key(key: &Key, tint: Tint) -> Self {
        Self::Key {
            glyph: glyph(key),
            tint,
            missing: false,
        }
    }

    fn missing(key: &Key) -> Self {
        Self::Key {
            glyph: glyph(key),
            tint: Tint::Key,
            missing: true,
        }
    }

    fn device() -> Self {
        Self::Device {
            tint: Tint::Device,
            contact: Contact::Filled,
        }
    }
}

/// The key's emoji, or the initial of its label.
#[must_use]
pub fn glyph(key: &Key) -> Glyph {
    match &key.emoji {
        Some(emoji) => Glyph::Emoji(emoji.clone()),
        None => Glyph::Initial(
            key.label
                .chars()
                .find(|character| character.is_alphanumeric())
                .map_or_else(
                    || "?".to_owned(),
                    |initial| initial.to_uppercase().collect(),
                ),
        ),
    }
}

fn name_or(security_key: Option<&SecurityKey>, fallback: &str) -> String {
    security_key.map_or_else(|| fallback.to_owned(), |key| key.name.clone())
}

/// What a request is for, as a subtitle.
#[must_use]
pub fn request_subtitle(request: &Request) -> Subtitle {
    match request {
        Request::Login { host, via, .. } => {
            let mut spans = host_spans(host);
            if let Some(via) = via {
                spans.push(Span::text(" · via "));
                spans.extend(host_spans(via));
            }
            Subtitle {
                spans,
                tone: Tone::Muted,
            }
        }
        Request::Sign { namespace } if namespace == "git" => Subtitle::muted("Git signature"),
        Request::Sign { namespace } => Subtitle::muted(format!("Signature for \"{namespace}\"")),
        Request::Create => Subtitle::muted("Create an age identity"),
        Request::Batch { command, seconds } => Subtitle {
            spans: vec![
                Span::text(format!("Decrypt files for {}", about(*seconds))),
                Span::text(format!(" · {command}")),
            ],
            tone: Tone::Muted,
        },
        Request::Decrypt { by } => {
            let mut spans = vec![Span::text("Decrypt a file")];
            match by {
                Requester::Program { name: None } => {}
                Requester::Program { name: Some(name) } => {
                    spans.push(Span::text(format!(" · {name}")));
                }
                // One host fits the line, by its key alone if it has no
                // name. Of several hops it is the first: the one this
                // machine's ssh connected to, which vouches for the rest.
                Requester::Forwarded { host, via: None } => {
                    spans.push(Span::text(" · for "));
                    spans.push(forwarded_host(host));
                }
                Requester::Forwarded {
                    via: Some(first), ..
                } => {
                    spans.push(Span::text(" · via "));
                    spans.push(forwarded_host(first));
                }
            }
            Subtitle {
                spans,
                tone: Tone::Muted,
            }
        }
        Request::Unknown => Subtitle {
            spans: vec![Span::text("Unknown request")],
            tone: Tone::Warning,
        },
    }
}

/// A host a decryption is for, in the room a subtitle has left.
fn forwarded_host(host: &Host) -> Span {
    match host {
        Host::Named { name } => Span::text(name.clone()),
        Host::HostKey { fingerprint } => Span {
            text: short_fingerprint(fingerprint),
            mono: true,
        },
        Host::Unverified => Span::text("Unknown host"),
    }
}

fn host_spans(host: &Host) -> Vec<Span> {
    match host {
        Host::Named { name } => vec![Span::text(name.clone())],
        Host::HostKey { fingerprint } => vec![
            Span::text("Unknown host · "),
            Span {
                text: short_fingerprint(fingerprint),
                mono: true,
            },
        ],
        Host::Unverified => vec![Span::text("Unknown host")],
    }
}

/// `SHA256:+DiY3wvv…`: the algorithm and the first few characters.
#[must_use]
pub fn short_fingerprint(fingerprint: &str) -> String {
    let (algorithm, hash) = fingerprint.split_once(':').unwrap_or(("", fingerprint));
    let head: String = hash.chars().take(FINGERPRINT_CHARS).collect();
    let cut = if hash.chars().count() > FINGERPRINT_CHARS {
        "…"
    } else {
        ""
    };
    if algorithm.is_empty() {
        format!("{head}{cut}")
    } else {
        format!("{algorithm}:{head}{cut}")
    }
}

/// About how long `seconds` are, never less: "45 s", "10 min", "2 h".
#[must_use]
pub fn about(seconds: u64) -> String {
    if seconds < 120 {
        format!("{seconds} s")
    } else if seconds < 7200 {
        format!("{} min", seconds.div_ceil(60))
    } else {
        format!("{} h", seconds.div_ceil(3600))
    }
}

/// "6 tries left", "1 try left".
#[must_use]
pub fn tries_left(tries: u32) -> String {
    if tries == 1 {
        "1 try left".to_owned()
    } else {
        format!("{tries} tries left")
    }
}

fn pin(
    anchor: Anchor,
    title: String,
    subtitle: Subtitle,
    mistake: Option<u32>,
    submit: &'static str,
) -> Screen {
    let (subtitle, announcement) = if let Some(tries) = mistake {
        (
            Subtitle {
                spans: vec![Span::text(format!("Wrong PIN · {}", tries_left(tries)))],
                tone: Tone::Error,
            },
            format!("Wrong PIN, {}", tries_left(tries)),
        )
    } else {
        let announcement = format!("Enter the PIN, {title}");
        (subtitle, announcement)
    };
    Screen {
        anchor,
        badge: None,
        title,
        subtitle,
        body: Body::Pin {
            error: mistake.is_some(),
            submit,
        },
        close: Close::Cancel,
        announcement,
        lingers: None,
    }
}

fn pair(security_key: Option<&SecurityKey>, timeout_ms: u64) -> Screen {
    let subtitle = format!(
        "to pair {} with skagent",
        name_or(security_key, "your security key")
    );
    Screen {
        anchor: Anchor::Countdown {
            glyph: None,
            duration: Duration::from_millis(timeout_ms),
            pulse: true,
        },
        badge: Some(Badge::Again),
        announcement: format!("Touch once more {subtitle}"),
        title: "Touch once more".to_owned(),
        subtitle: Subtitle::muted(subtitle),
        body: Body::Empty,
        close: Close::Cancel,
        lingers: None,
    }
}

fn signed(key: &Key, request: &Request) -> Screen {
    let title = match request {
        Request::Decrypt { .. } => "Decrypted",
        Request::Batch { .. } => "Batch started",
        Request::Create => "Created",
        Request::Login { .. } | Request::Sign { .. } | Request::Unknown => "Signed",
    };
    Screen {
        anchor: Anchor::key(key, Tint::Key),
        badge: Some(Badge::Done),
        title: title.to_owned(),
        subtitle: request_subtitle(request),
        body: Body::Empty,
        close: Close::None,
        announcement: format!("{title}, {}", request_subtitle(request).text()),
        lingers: Some(SIGNED_FOR),
    }
}

fn locked(security_key: Option<&SecurityKey>) -> Screen {
    Screen {
        anchor: Anchor::Device {
            tint: Tint::Error,
            contact: Contact::Outline,
        },
        badge: Some(Badge::Lock),
        title: "PIN locked".to_owned(),
        subtitle: Subtitle::muted(format!(
            "{} can only be reset now. A reset erases every key on it.",
            name_or(security_key, "Your security key")
        )),
        body: Body::Empty,
        close: Close::Close,
        announcement: "PIN locked".to_owned(),
        lingers: None,
    }
}

fn new_pin(security_key: Option<&SecurityKey>) -> Screen {
    Screen {
        anchor: Anchor::device(),
        badge: Some(Badge::Pencil),
        title: "Set a new PIN first".to_owned(),
        subtitle: Subtitle::muted(format!(
            "{} still has a temporary PIN",
            name_or(security_key, "Your security key")
        )),
        body: Body::Command("ykman fido access change-pin"),
        close: Close::Close,
        announcement: "Set a new PIN first".to_owned(),
        lingers: None,
    }
}

fn timeout(key: Option<&Key>, security_key: Option<&SecurityKey>) -> Screen {
    Screen {
        anchor: key.map_or_else(Anchor::device, |key| Anchor::key(key, Tint::Key)),
        badge: Some(Badge::Clock),
        title: "Timed out".to_owned(),
        subtitle: Subtitle::muted(format!(
            "{} wasn't touched · PIN kept",
            name_or(security_key, "Your security key")
        )),
        body: Body::TryAgain,
        close: Close::Cancel,
        announcement: "Timed out".to_owned(),
        lingers: None,
    }
}

fn touch(
    key: &Key,
    security_key: Option<&SecurityKey>,
    request: &Request,
    timeout_ms: u64,
    again: bool,
) -> Screen {
    let title = match (again, security_key) {
        (true, _) => "Touch once more",
        (false, Some(_)) => "Touch your YubiKey",
        (false, None) => "Touch your security key",
    };
    let now_to = match request {
        Request::Decrypt { .. } | Request::Batch { .. } => "now to decrypt",
        Request::Create => "now to read its recipient",
        Request::Login { .. } | Request::Sign { .. } | Request::Unknown => "now to sign",
    };
    let subtitle = match (again, security_key) {
        // What this touch allows beyond itself, and that another machine
        // asks for it, is said with every touch, also the one that follows
        // a cached PIN.
        _ if matches!(
            request,
            Request::Batch { .. }
                | Request::Decrypt {
                    by: Requester::Forwarded { .. }
                }
        ) =>
        {
            request_subtitle(request)
        }
        (true, Some(security_key)) => Subtitle::muted(format!("{} · {now_to}", security_key.name)),
        (true, None) => Subtitle::muted(now_to),
        (false, Some(security_key)) => Subtitle::muted(security_key.name.clone()),
        (false, None) => request_subtitle(request),
    };
    Screen {
        anchor: Anchor::Countdown {
            glyph: Some(glyph(key)),
            duration: Duration::from_millis(timeout_ms),
            pulse: true,
        },
        badge: again.then_some(Badge::Again),
        announcement: format!("{title}, {}", subtitle.text()),
        title: title.to_owned(),
        subtitle,
        body: Body::Empty,
        close: Close::Cancel,
        lingers: None,
    }
}

fn select(key: Option<&Key>, devices: usize, timeout_ms: u64) -> Screen {
    let (title, subtitle) = match key {
        Some(key) => (
            "Touch the right YubiKey".to_owned(),
            format!("The one holding {}", key.label),
        ),
        None => (
            "Touch a YubiKey".to_owned(),
            "to load its keys into skagent".to_owned(),
        ),
    };
    let duration = if timeout_ms == 0 {
        SELECT_TIMEOUT
    } else {
        Duration::from_millis(timeout_ms)
    };
    Screen {
        anchor: Anchor::Countdown {
            glyph: key.map(glyph),
            duration,
            pulse: false,
        },
        badge: None,
        announcement: format!("{title}, {devices} plugged in"),
        title,
        subtitle: Subtitle::muted(subtitle),
        body: Body::Devices(devices),
        close: Close::Cancel,
        lingers: None,
    }
}

fn loaded(security_key: Option<&SecurityKey>, keys: &[Key]) -> Screen {
    let title = if keys.len() == 1 {
        "Loaded 1 key".to_owned()
    } else {
        format!("Loaded {} keys", keys.len())
    };
    Screen {
        anchor: Anchor::device(),
        badge: Some(Badge::Done),
        announcement: title.clone(),
        title,
        subtitle: Subtitle::muted(format!(
            "from {}",
            name_or(security_key, "your security key")
        )),
        body: Body::Tiles {
            glyphs: keys.iter().take(MAX_TILES).map(glyph).collect(),
            more: keys.len().saturating_sub(MAX_TILES),
        },
        close: Close::None,
        lingers: Some(SIGNED_FOR),
    }
}

fn waiting(anchor: Anchor, badge: Badge, title: String, subtitle: Subtitle) -> Screen {
    Screen {
        anchor,
        badge: Some(badge),
        announcement: format!("{title}, {}", subtitle.text()),
        title,
        subtitle,
        body: Body::Spinner,
        close: Close::Cancel,
        lingers: None,
    }
}

fn no_key(key: Option<&Key>, security_key: Option<&SecurityKey>) -> Screen {
    let anchor = key.map_or_else(Anchor::device, Anchor::missing);
    let (title, subtitle) = match (key, security_key) {
        (Some(key), Some(security_key)) => (
            format!("Plug in {}", security_key.name),
            format!("It holds {}", key.label),
        ),
        (Some(key), None) => (
            "Plug in your YubiKey".to_owned(),
            format!("The one holding {}", key.label),
        ),
        (None, _) => (
            "Plug in your YubiKey".to_owned(),
            "to load its keys into skagent".to_owned(),
        ),
    };
    waiting(anchor, Badge::Plug, title, Subtitle::muted(subtitle))
}

fn replug(key: Option<&Key>, security_key: Option<&SecurityKey>, tries: Option<u32>) -> Screen {
    let anchor = match key {
        Some(key) => Anchor::key(key, Tint::Warning),
        None => Anchor::Device {
            tint: Tint::Warning,
            contact: Contact::Filled,
        },
    };
    Screen {
        anchor,
        badge: Some(Badge::Replug),
        title: "Unplug and reinsert".to_owned(),
        subtitle: Subtitle::muted(format!(
            "{} paused after 3 wrong PINs",
            name_or(security_key, "Your security key")
        )),
        body: tries.map_or(Body::Empty, Body::Tries),
        close: Close::Cancel,
        announcement: "Unplug and reinsert your security key".to_owned(),
        lingers: None,
    }
}

/// What a request that failed was doing: the words differ.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Doing {
    Signing,
    Decrypting,
    Creating,
    Loading,
}

fn failed(
    key: Option<&Key>,
    security_key: Option<&SecurityKey>,
    reason: Failure,
    request: Option<&Request>,
) -> Screen {
    let doing = match (request, key) {
        (Some(Request::Decrypt { .. } | Request::Batch { .. }), _) => Doing::Decrypting,
        (Some(Request::Create), _) => Doing::Creating,
        (_, Some(_)) => Doing::Signing,
        (_, None) => Doing::Loading,
    };
    let name = name_or(security_key, "Your security key");
    // The reason where the agent knows it; the log has the rest.
    let reason = match (reason, key) {
        (Failure::Unplugged, _) => match doing {
            Doing::Signing => format!("{name} was unplugged mid-signature"),
            Doing::Decrypting => format!("{name} was unplugged while decrypting"),
            Doing::Creating => format!("{name} was unplugged meanwhile"),
            Doing::Loading => format!("{name} was unplugged while loading"),
        },
        (Failure::Refused, _) => match doing {
            Doing::Signing => format!("{name} refused to sign"),
            Doing::Decrypting => format!("{name} refused to decrypt"),
            Doing::Creating => format!("{name} refused to create it"),
            Doing::Loading => format!("{name} refused to list its keys"),
        },
        (Failure::NotOnKey, Some(_)) if doing == Doing::Decrypting => {
            format!("{name} doesn't hold this age identity")
        }
        (Failure::NotOnKey, Some(key)) => format!("{name} doesn't hold {}", key.label),
        (Failure::NotOnKey, None) => format!("{name} holds no SSH keys"),
        (Failure::NoPin, _) => format!("{name} has no PIN set"),
        (Failure::NotForIdentity, _) => "The file isn't encrypted to this identity".to_owned(),
        (Failure::AnotherIdentity, _) => format!("{name} holds another age identity"),
        (Failure::Unrecognized, _) => format!(
            "This isn't the {} skagent paired",
            name_or(security_key, "security key")
        ),
        (Failure::Duplicate, _) => format!(
            "Two security keys claim to be {}",
            name_or(security_key, "your YubiKey")
        ),
        (Failure::NotPluggedIn, _) => match security_key {
            Some(security_key) => format!("{} wasn't plugged in", security_key.name),
            None => "No security key was plugged in".to_owned(),
        },
        (Failure::Other, _) => "Something went wrong · see skagent's log".to_owned(),
    };
    let title = match doing {
        Doing::Signing => "Couldn't sign",
        Doing::Decrypting => "Couldn't decrypt",
        Doing::Creating => "Couldn't create it",
        Doing::Loading => "Couldn't load keys",
    };
    Screen {
        anchor: key.map_or_else(Anchor::device, |key| Anchor::key(key, Tint::Key)),
        badge: Some(Badge::Failed),
        title: title.to_owned(),
        announcement: format!("{title}, {reason}"),
        subtitle: Subtitle::muted(reason),
        body: Body::Closing(FAILED_FOR),
        close: Close::Close,
        lingers: Some(FAILED_FOR),
    }
}
