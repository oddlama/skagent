//! Where a signature may go, following OpenSSH's ssh-agent
//! (`PROTOCOL.agent`, `ssh-agent.c`).
//!
//! - **Session binding.** ssh binds every agent connection to the SSH session
//!   it serves (`session-bind@openssh.com`): the server's host key, the
//!   session ID and the host key's signature over that ID, and whether the
//!   connection authenticates the user or forwards the agent on. Each
//!   forwarding hop adds a binding, so a request that arrives through
//!   forwarded agents carries its whole path.
//! - **Destination constraints.** `ssh-add -h` attaches hops to a key
//!   (`restrict-destination-v00@openssh.com`). A constrained key is only
//!   listed, replaced, removed and used on connections whose every bound hop
//!   a constraint allows, and only signs the SSH user authentication of the
//!   most recently bound session.
//! - **Websafe.** A key whose application isn't `ssh:…` belongs to a web
//!   origin. It only signs SSH user authentication and SSHSIG data, never
//!   something a website could accept as a login.
//!
//! Unlike OpenSSH, skagent can't decode host certificates or host key types
//! newer than its SSH library, such as OpenSSH 10's `ssh-mldsa44-ed25519`.
//! Binding a session to such a host key fails, which keeps constrained keys
//! off that connection (fail closed). In constraints, keys of unknown types
//! are skipped (`ssh-add -h` sends every host key it knows for a host) and
//! CA entries never match: both only narrow where a key may be used.
//!
//! Every decoder here is strict: reserved fields must be empty, names must
//! not contain NUL, and nothing may follow the last field.

use std::fmt;

use anyhow::{Context as _, Result, anyhow, ensure};
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::ssh_encoding::{self, Decode as _, Reader};
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::ssh_key::{self, Algorithm, HashAlg, Signature};

use crate::display::{self, MAX_NAME_CHARS};

/// Agent extension that binds a connection to an SSH session.
pub const SESSION_BIND_EXTENSION: &str = "session-bind@openssh.com";

/// Key constraint extension carrying destination constraints (`ssh-add -h`).
pub const RESTRICT_DESTINATION_CONSTRAINT: &str = "restrict-destination-v00@openssh.com";

/// Most bindings per connection (OpenSSH: `AGENT_MAX_SESSION_IDS`).
const MAX_BINDINGS: usize = 16;
/// Longest session ID (OpenSSH: `AGENT_MAX_SID_LEN`).
const MAX_SESSION_ID_LEN: usize = 128;
/// Most constraints per key (OpenSSH: `AGENT_MAX_DEST_CONSTRAINTS`).
const MAX_CONSTRAINTS: usize = 1024;
/// Longest user pattern (OpenSSH: `AGENT_USER_CONSTRAINT_MAX_LEN`).
const MAX_USER_PATTERN_LEN: usize = 256;
/// `SSH2_MSG_USERAUTH_REQUEST`.
const USERAUTH_REQUEST: u8 = 50;
/// Applications that aren't a web origin.
const SSH_APPLICATION_PREFIX: &str = "ssh:";

/// One verified hop: a host key that signed the session ID.
#[derive(Debug, Clone)]
struct Binding {
    host_key: KeyData,
    session_id: Vec<u8>,
    forwarding: bool,
}

/// What ssh told the agent about one client connection.
#[derive(Debug, Default)]
pub struct SessionBindings {
    bindings: Vec<Binding>,
    /// Set by any bind request, also a failed one.
    attempted: bool,
}

/// Outcome of a successful bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// A new hop was recorded.
    New {
        /// Whether the hop forwards the agent rather than authenticates.
        forwarding: bool,
    },
    /// The same session and host key were bound before.
    AlreadyBound,
}

impl SessionBindings {
    /// Handles a `session-bind@openssh.com` request (`details` is the
    /// extension payload): checks the host key's signature over the session
    /// ID and the consistency with earlier bindings, then records the hop.
    ///
    /// Any attempt counts, also a failed one: a connection whose binding
    /// failed never sees destination-constrained keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is malformed, the signature doesn't
    /// verify, or the binding contradicts an earlier one.
    pub fn bind(&mut self, details: &[u8]) -> Result<Bound> {
        self.attempted = true;
        let request = decode_session_bind(details)?;
        ensure!(
            request.session_id.len() <= MAX_SESSION_ID_LEN,
            "a session ID of {} bytes is too long",
            request.session_id.len()
        );
        request.verify_signature().map_err(|error| {
            anyhow!("the host key's signature over the session ID doesn't verify: {error}")
        })?;
        for existing in &self.bindings {
            ensure!(
                existing.forwarding,
                "the connection is already bound for authentication"
            );
            if existing.session_id == request.session_id {
                ensure!(
                    existing.host_key == request.host_key,
                    "the session ID is already bound to another host key"
                );
                return Ok(Bound::AlreadyBound);
            }
        }
        ensure!(
            self.bindings.len() < MAX_BINDINGS,
            "more than {MAX_BINDINGS} session bindings on one connection"
        );
        self.bindings.push(Binding {
            host_key: request.host_key,
            session_id: request.session_id,
            forwarding: request.is_forwarding,
        });
        Ok(Bound::New {
            forwarding: request.is_forwarding,
        })
    }

    /// Whether ssh tried to bind this connection, i.e. it comes from an SSH
    /// session (possibly through forwarded agents) rather than a local tool.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        self.attempted
    }

    /// Number of recorded hops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether no hop is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Where a destination-constrained key may be used: from one hop to the next.
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationConstraint {
    from: Hop,
    to: Hop,
    /// Host keys of types skagent can't decode, left out of `from` and `to`.
    skipped_host_keys: usize,
}

impl DestinationConstraint {
    /// How many host keys were left out because skagent doesn't know their
    /// type. Such keys could never match a binding anyway.
    #[must_use]
    pub fn skipped_host_keys(&self) -> usize {
        self.skipped_host_keys
    }
}

impl fmt::Debug for DestinationConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let from = self.from.hostname.as_deref().unwrap_or("(this machine)");
        let to = self.to.hostname.as_deref().unwrap_or("(any)");
        write!(
            formatter,
            "{from} ({} keys) > {}{to} ({} keys)",
            self.from.keys.len(),
            self.to
                .user
                .as_deref()
                .map(|user| format!("{user}@"))
                .unwrap_or_default(),
            self.to.keys.len()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hop {
    /// Glob pattern for the user to log in as; only on the "to" side.
    user: Option<String>,
    hostname: Option<String>,
    keys: Vec<HopKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HopKey {
    key: KeyData,
    is_ca: bool,
}

impl Hop {
    /// Whether `key` is one of this hop's plain host keys. CA entries only
    /// match host certificates, which skagent never binds.
    fn matches(&self, key: &KeyData) -> bool {
        self.keys
            .iter()
            .any(|entry| !entry.is_ca && entry.key == *key)
    }
}

/// Parses and validates the payload of a `restrict-destination-v00@openssh.com`
/// key constraint, with OpenSSH's rules: the first hop of a constraint has no
/// user and either a hostname with keys or neither (the machine skagent runs
/// on); the second always has a hostname and keys.
///
/// # Errors
///
/// Returns an error for anything malformed, inconsistent or reserved for
/// future use, and for an empty list.
pub fn parse_destination_constraints(details: &[u8]) -> Result<Vec<DestinationConstraint>> {
    let mut reader = details;
    let mut constraints = Vec::new();
    while !reader.is_finished() {
        ensure!(
            constraints.len() < MAX_CONSTRAINTS,
            "more than {MAX_CONSTRAINTS} destination constraints"
        );
        let (from, to, reserved) = reader
            .read_prefixed(|constraint| -> Result<_, ssh_key::Error> {
                let from = constraint.read_prefixed(decode_hop)?;
                let to = constraint.read_prefixed(decode_hop)?;
                let reserved = Vec::<u8>::decode(constraint)?;
                finished(constraint)?;
                Ok((from, to, reserved))
            })
            .map_err(|error| anyhow!("decoding a destination constraint: {error}"))?;
        ensure!(
            reserved.is_empty(),
            "a destination constraint uses reserved fields skagent doesn't understand"
        );
        constraints.push(DestinationConstraint::validate(from, to)?);
    }
    ensure!(
        !constraints.is_empty(),
        "a destination restriction without any destination"
    );
    Ok(constraints)
}

/// A hop as read from the wire, not yet validated.
struct RawHop {
    user: String,
    hostname: String,
    reserved: Vec<u8>,
    keys: Vec<HopKey>,
    /// Keys of types skagent doesn't know, not in `keys`.
    skipped: usize,
}

impl RawHop {
    /// All keys that were sent, also the skipped ones.
    fn sent_keys(&self) -> usize {
        self.keys.len().saturating_add(self.skipped)
    }
}

fn decode_hop(reader: &mut impl Reader) -> Result<RawHop, ssh_key::Error> {
    let user = decode_name(reader)?;
    let hostname = decode_name(reader)?;
    let reserved = Vec::<u8>::decode(reader)?;
    let mut keys = Vec::new();
    let mut skipped: usize = 0;
    while !reader.is_finished() {
        let blob = Vec::<u8>::decode(reader)?;
        let is_ca = u8::decode(reader)? != 0;
        // Unknown type: skip. Known type but malformed: refuse.
        let mut peek = blob.as_slice();
        if Algorithm::new(&String::decode(&mut peek)?).is_err() {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let mut blob = blob.as_slice();
        let key = KeyData::decode(&mut blob)?;
        finished(&blob)?;
        keys.push(HopKey { key, is_ca });
    }
    Ok(RawHop {
        user,
        hostname,
        reserved,
        keys,
        skipped,
    })
}

impl DestinationConstraint {
    fn validate(from: RawHop, to: RawHop) -> Result<Self> {
        ensure!(
            from.reserved.is_empty() && to.reserved.is_empty(),
            "a destination constraint hop uses reserved fields skagent doesn't understand"
        );
        ensure!(
            from.user.is_empty(),
            "the first hop of a destination constraint names a user"
        );
        ensure!(
            from.hostname.is_empty() == (from.sent_keys() == 0),
            "the first hop of a destination constraint needs both a hostname and host keys, or neither"
        );
        ensure!(
            !to.hostname.is_empty() && to.sent_keys() > 0,
            "the destination of a destination constraint needs a hostname and host keys"
        );
        ensure!(
            to.user.len() <= MAX_USER_PATTERN_LEN,
            "the user pattern of a destination constraint is longer than {MAX_USER_PATTERN_LEN} bytes"
        );
        let present = |text: String| Some(text).filter(|text| !text.is_empty());
        let skipped_host_keys = from.skipped.saturating_add(to.skipped);
        Ok(Self {
            skipped_host_keys,
            from: Hop {
                user: None,
                hostname: present(from.hostname),
                keys: from.keys,
            },
            to: Hop {
                user: present(to.user),
                hostname: present(to.hostname),
                keys: to.keys,
            },
        })
    }
}

/// Hostnames, as the constraints name them, of the first forwarding hop and
/// of the final destination of a permitted connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Permitted<'a> {
    /// Destination of the first hop, if the connection was forwarded.
    pub forwarded_to: Option<&'a str>,
    /// Destination of the last hop.
    pub destination: Option<&'a str>,
}

/// Whether a key with `constraints` may be seen and used on a connection with
/// `bindings`; `user` is the user a signature request logs in as (`None` for
/// listing, replacing and removing). Ported from OpenSSH's
/// `identity_permitted`: every bound hop must be allowed by some constraint
/// from the previous hop's host key, only the last hop may authenticate, and
/// a key that may be used at the last host but not beyond it is hidden on a
/// connection forwarded to that host.
///
/// # Errors
///
/// Returns an error naming why the key isn't permitted.
pub fn permitted<'a>(
    constraints: &'a [DestinationConstraint],
    bindings: &SessionBindings,
    user: Option<&str>,
) -> Result<Permitted<'a>> {
    let mut permitted = Permitted::default();
    if constraints.is_empty() {
        return Ok(permitted);
    }
    ensure!(
        !(bindings.attempted && bindings.bindings.is_empty()),
        "binding this connection to its SSH session failed earlier"
    );
    let Some(last_index) = bindings.bindings.len().checked_sub(1) else {
        // A local connection, e.g. ssh-add on this machine.
        return Ok(permitted);
    };
    let mut from: Option<&KeyData> = None;
    for (index, binding) in bindings.bindings.iter().enumerate() {
        let is_last = index == last_index;
        if is_last {
            ensure!(
                !(binding.forwarding && user.is_some()),
                "a signature was requested on a hop bound for forwarding"
            );
        } else {
            ensure!(
                binding.forwarding,
                "a hop bound for authentication was forwarded further"
            );
        }
        let test_user = if is_last { user } else { None };
        let hostname = matching_constraint(constraints, from, Some(&binding.host_key), test_user)
            .context("the key's destination constraints don't allow this host")?
            .to
            .hostname
            .as_deref();
        if is_last {
            permitted.destination = hostname;
        } else if index == 0 {
            permitted.forwarded_to = hostname;
        }
        from = Some(&binding.host_key);
    }
    if let Some(last) = bindings.bindings.last()
        && last.forwarding
        && user.is_none()
    {
        matching_constraint(constraints, Some(&last.host_key), None, None)
            .context("the key may be used at this host but not beyond it")?;
    }
    Ok(permitted)
}

/// The first constraint allowing the hop from `from` (`None`: this machine)
/// to `to` (`None`: anywhere) as `user`.
fn matching_constraint<'a>(
    constraints: &'a [DestinationConstraint],
    from: Option<&KeyData>,
    to: Option<&KeyData>,
    user: Option<&str>,
) -> Option<&'a DestinationConstraint> {
    constraints.iter().find(|constraint| {
        let from_matches = match from {
            None => constraint.from.hostname.is_none() && constraint.from.keys.is_empty(),
            Some(key) => constraint.from.matches(key),
        };
        let to_matches = to.is_none_or(|key| constraint.to.matches(key));
        let user_matches = match (constraint.to.user.as_deref(), user) {
            (Some(pattern), Some(user)) => glob_matches(pattern, user),
            _ => true,
        };
        from_matches && to_matches && user_matches
    })
}

/// OpenSSH's `match_pattern`: `*` matches any sequence, `?` any one
/// character, everything else itself.
#[must_use]
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0_usize, 0_usize);
    // Where the last `*` was, and which text position it currently absorbs up to.
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (pattern.get(p), text.get(t)) {
            (Some('*'), _) => {
                star = Some((p, t));
                p = p.saturating_add(1);
            }
            (Some(&expected), Some(&actual)) if expected == '?' || expected == actual => {
                p = p.saturating_add(1);
                t = t.saturating_add(1);
            }
            (None, None) => return true,
            _ => match star {
                // Let the last `*` absorb one more character and retry.
                Some((star_p, star_t)) if star_t < text.len() => {
                    let absorbed = star_t.saturating_add(1);
                    star = Some((star_p, absorbed));
                    p = star_p.saturating_add(1);
                    t = absorbed;
                }
                _ => return false,
            },
        }
    }
}

/// A well-formed SSH public key user authentication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthRequest {
    /// The session the request authenticates in.
    pub session_id: Vec<u8>,
    /// The user to log in as.
    pub user: String,
    /// The server's host key, for `publickey-hostbound-v00@openssh.com`.
    pub host_key: Option<KeyData>,
}

/// `data` as the public key user authentication request (RFC 4252 7) it
/// would be when ssh logs in with `key`, or `None`.
#[must_use]
pub fn parse_userauth_request(data: &[u8], key: &KeyData) -> Option<UserauthRequest> {
    let mut reader = data;
    let session_id = Vec::<u8>::decode(&mut reader).ok()?;
    if session_id.is_empty() || u8::decode(&mut reader).ok()? != USERAUTH_REQUEST {
        return None;
    }
    let user = decode_name(&mut reader).ok()?;
    let service = decode_name(&mut reader).ok()?;
    let method = decode_name(&mut reader).ok()?;
    let signature_follows = u8::decode(&mut reader).ok()?;
    let algorithm = decode_name(&mut reader).ok()?;
    let signed_key = decode_key(&mut reader).ok()?;
    if service != "ssh-connection"
        || signature_follows != 1
        || Algorithm::new(&algorithm).ok()? != key.algorithm()
        || signed_key != *key
    {
        return None;
    }
    let host_key = match method.as_str() {
        "publickey" => None,
        "publickey-hostbound-v00@openssh.com" => Some(decode_key(&mut reader).ok()?),
        _ => return None,
    };
    reader.is_finished().then_some(UserauthRequest {
        session_id,
        user,
        host_key,
    })
}

/// The namespace of an SSHSIG signature request (`ssh-keygen -Y sign`,
/// git commit signing), or `None` if `data` isn't one.
#[must_use]
pub fn parse_sshsig_request(data: &[u8]) -> Option<String> {
    let mut reader = data.strip_prefix(b"SSHSIG")?;
    let namespace = decode_name(&mut reader).ok()?;
    let _reserved = Vec::<u8>::decode(&mut reader).ok()?;
    let _hash_algorithm = decode_name(&mut reader).ok()?;
    let _message_hash = Vec::<u8>::decode(&mut reader).ok()?;
    reader.is_finished().then_some(namespace)
}

/// What a signature request is for, as shown in PIN prompts and touch
/// notifications. User, host and namespace names are sanitized for display
/// ([`display::shown`]): on a forwarded agent they come from another machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// Logging in somewhere over SSH.
    Login {
        /// The user to log in as.
        user: String,
        /// Where.
        destination: Destination,
        /// The first host the agent was forwarded to, for forwarded requests.
        forwarded_to: Option<Destination>,
    },
    /// An SSHSIG signature (`ssh-keygen -Y sign`, git commit signing).
    SignData {
        /// What kind of data, e.g. `git` or `file`.
        namespace: String,
    },
    /// Data of no known kind.
    Unknown,
}

/// A host as far as the agent can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Named by the key's destination constraint.
    Named(String),
    /// Identified by the host key that signed the session (fingerprint).
    HostKey(String),
    /// Not bound to a verified session.
    Unverified,
}

impl fmt::Display for Destination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(hostname) => formatter.write_str(hostname),
            Self::HostKey(fingerprint) => write!(formatter, "the host with key {fingerprint}"),
            Self::Unverified => formatter.write_str("an unverified host"),
        }
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login {
                user,
                destination,
                forwarded_to,
            } => {
                write!(formatter, "log in as \"{user}\" to {destination}")?;
                if let Some(forwarded_to) = forwarded_to {
                    write!(
                        formatter,
                        " (through your agent forwarded to {forwarded_to})"
                    )?;
                }
                Ok(())
            }
            Self::SignData { namespace } => write!(formatter, "sign \"{namespace}\" data"),
            Self::Unknown => formatter.write_str("sign data of an unknown kind"),
        }
    }
}

/// Checks a signature request against the key's destination constraints and
/// the websafe rule, on a connection with `bindings`. Returns what the
/// signature is for.
///
/// # Errors
///
/// Returns an error naming the rule the request breaks.
pub fn authorize_signature(
    key: &KeyData,
    application: &str,
    constraints: &[DestinationConstraint],
    bindings: &SessionBindings,
    data: &[u8],
) -> Result<Purpose> {
    let userauth = parse_userauth_request(data, key);
    let mut named = Permitted::default();
    if !constraints.is_empty() {
        let last = bindings.bindings.last().context(
            "a destination-constrained key only signs on connections bound to an SSH session",
        )?;
        let request = userauth
            .as_ref()
            .context("a destination-constrained key only signs SSH user authentication requests")?;
        named = permitted(constraints, bindings, Some(&request.user))?;
        ensure!(
            request.session_id == last.session_id,
            "the request authenticates in another session than the one most recently bound"
        );
        ensure!(
            bindings.bindings.len() == 1 || request.host_key.is_some(),
            "a forwarded authentication request doesn't name its host key"
        );
        if let Some(host_key) = &request.host_key {
            ensure!(
                *host_key == last.host_key,
                "the host key in the request isn't the one most recently bound"
            );
        }
    }
    let sshsig = parse_sshsig_request(data);
    if !application.starts_with(SSH_APPLICATION_PREFIX) {
        ensure!(
            userauth.is_some() || sshsig.is_some(),
            "the key for the web origin {} only signs SSH logins and SSHSIG data",
            shown(application)
        );
    }
    Ok(describe(userauth, sshsig, bindings, &named))
}

fn describe(
    userauth: Option<UserauthRequest>,
    sshsig: Option<String>,
    bindings: &SessionBindings,
    named: &Permitted<'_>,
) -> Purpose {
    let Some(request) = userauth else {
        return sshsig.map_or(Purpose::Unknown, |namespace| Purpose::SignData {
            namespace: shown(&namespace),
        });
    };
    // Only a request for the most recently bound, authenticating session
    // names a verified host.
    let verified = bindings.bindings.last().filter(|last| {
        !last.forwarding
            && last.session_id == request.session_id
            && request
                .host_key
                .as_ref()
                .is_none_or(|host_key| *host_key == last.host_key)
    });
    let destination = match (named.destination, verified) {
        (Some(hostname), Some(_)) => Destination::Named(shown(hostname)),
        (None, Some(last)) => Destination::HostKey(fingerprint(&last.host_key)),
        (_, None) => Destination::Unverified,
    };
    let forwarded_to = (bindings.bindings.len() > 1)
        .then(|| bindings.bindings.first())
        .flatten()
        .map(|first| {
            named.forwarded_to.map_or_else(
                || Destination::HostKey(fingerprint(&first.host_key)),
                |hostname| Destination::Named(shown(hostname)),
            )
        });
    Purpose::Login {
        user: shown(&request.user),
        destination,
        forwarded_to,
    }
}

fn fingerprint(key: &KeyData) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// `text` from the signed data or a constraint, safe to show.
fn shown(text: &str) -> String {
    display::shown(text, MAX_NAME_CHARS)
}

/// The fields of a `session-bind@openssh.com` request, nothing after them.
fn decode_session_bind(details: &[u8]) -> Result<SessionBind> {
    let mut reader = details;
    let decoded = (|| -> Result<SessionBind, ssh_key::Error> {
        let host_key = decode_key(&mut reader)?;
        let session_id = Vec::<u8>::decode(&mut reader)?;
        let signature = reader.read_prefixed(|nested| {
            let signature = Signature::decode(nested)?;
            finished(nested)?;
            Ok::<_, ssh_key::Error>(signature)
        })?;
        let is_forwarding = u8::decode(&mut reader)? != 0;
        finished(&reader)?;
        Ok(SessionBind {
            host_key,
            session_id,
            signature,
            is_forwarding,
        })
    })();
    decoded.map_err(|error| anyhow!("decoding a session-bind request: {error}"))
}

/// A `string` holding exactly one encoded public key.
fn decode_key(reader: &mut impl Reader) -> Result<KeyData, ssh_key::Error> {
    reader.read_prefixed(|nested| {
        let key = KeyData::decode(nested)?;
        finished(nested)?;
        Ok(key)
    })
}

/// A `string` holding UTF-8 without NUL, like OpenSSH's `sshbuf_get_cstring`.
fn decode_name(reader: &mut impl Reader) -> Result<String, ssh_key::Error> {
    let name = String::decode(reader)?;
    if name.contains('\0') {
        return Err(ssh_encoding::Error::CharacterEncoding.into());
    }
    Ok(name)
}

fn finished(reader: &impl Reader) -> Result<(), ssh_key::Error> {
    if reader.is_finished() {
        Ok(())
    } else {
        Err(ssh_encoding::Error::TrailingData {
            remaining: reader.remaining_len(),
        }
        .into())
    }
}
