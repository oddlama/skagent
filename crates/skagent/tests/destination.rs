//! Session binding, destination constraints and the websafe rule, with real
//! host key signatures.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, ensure};
use signature::Signer as _;
use skagent::destination::{
    Bound, Destination, Purpose, SessionBindings, authorize_signature, glob_matches,
    parse_destination_constraints, parse_sshsig_request, parse_userauth_request, permitted,
};
use ssh_agent_lib::proto::extension::{
    DestinationConstraint as WireConstraint, HostTuple, KeySpec, RestrictDestination, SessionBind,
};
use ssh_agent_lib::ssh_encoding::Encode as _;
use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::ssh_key::{HashAlg, Signature};

/// A host with a deterministic Ed25519 host key.
struct Host {
    name: &'static str,
    keypair: Ed25519Keypair,
}

impl Host {
    fn new(name: &'static str, seed: u8) -> Self {
        Self {
            name,
            keypair: Ed25519Keypair::from_seed(&[seed; 32]),
        }
    }

    fn key(&self) -> KeyData {
        KeyData::Ed25519(self.keypair.public)
    }

    fn fingerprint(&self) -> String {
        self.key().fingerprint(HashAlg::Sha256).to_string()
    }

    /// A session-bind payload as ssh sends it, signed by this host.
    fn bind(&self, session_id: &[u8], forwarding: bool) -> Result<Vec<u8>> {
        let signature: Signature = self.keypair.try_sign(session_id)?;
        encode(&SessionBind {
            host_key: self.key(),
            session_id: session_id.to_vec(),
            signature,
            is_forwarding: forwarding,
        })
    }
}

fn encode(value: &impl ssh_agent_lib::ssh_encoding::Encode) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes).context("encoding test data")?;
    Ok(bytes)
}

fn hop(user: &str, host: Option<&Host>) -> HostTuple {
    HostTuple {
        username: user.to_owned(),
        hostname: host.map(|host| host.name.to_owned()).unwrap_or_default(),
        keys: host
            .map(|host| {
                vec![KeySpec {
                    keyblob: host.key(),
                    is_ca: false,
                }]
            })
            .unwrap_or_default(),
    }
}

/// `ssh-add -h` constraints, `(from, to, user pattern)`; `from: None` is
/// the machine the agent runs on.
fn constraints(
    hops: &[(Option<&Host>, &Host, &str)],
) -> Result<Vec<skagent::destination::DestinationConstraint>> {
    let wire = RestrictDestination {
        constraints: hops
            .iter()
            .map(|(from, to, user)| WireConstraint {
                from: hop("", *from),
                to: hop(user, Some(to)),
            })
            .collect(),
    };
    parse_destination_constraints(&encode(&wire)?)
}

fn user_key() -> KeyData {
    KeyData::SkEd25519(support::sk_public(1))
}

/// What ssh asks the agent to sign to log in as `user`.
fn userauth(
    session_id: &[u8],
    user: &str,
    key: &KeyData,
    host_key: Option<&KeyData>,
) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    session_id.to_vec().encode(&mut data)?;
    50_u8.encode(&mut data)?;
    user.encode(&mut data)?;
    "ssh-connection".encode(&mut data)?;
    let method = if host_key.is_some() {
        "publickey-hostbound-v00@openssh.com"
    } else {
        "publickey"
    };
    method.encode(&mut data)?;
    1_u8.encode(&mut data)?;
    key.algorithm().as_str().encode(&mut data)?;
    key.encode_prefixed(&mut data)?;
    if let Some(host_key) = host_key {
        host_key.encode_prefixed(&mut data)?;
    }
    Ok(data)
}

fn sshsig(namespace: &str) -> Result<Vec<u8>> {
    let mut data = b"SSHSIG".to_vec();
    namespace.encode(&mut data)?;
    Vec::<u8>::new().encode(&mut data)?;
    "sha512".encode(&mut data)?;
    vec![7_u8; 64].encode(&mut data)?;
    Ok(data)
}

#[test]
fn a_valid_binding_is_recorded_and_repeats_are_harmless() -> Result<()> {
    let jump = Host::new("jump", 1);
    let mut bindings = SessionBindings::default();
    ensure!(!bindings.is_remote());
    ensure!(bindings.bind(&jump.bind(b"session-1", true)?)? == Bound::New { forwarding: true });
    ensure!(bindings.bind(&jump.bind(b"session-1", true)?)? == Bound::AlreadyBound);
    ensure!(bindings.len() == 1 && bindings.is_remote());
    Ok(())
}

#[test]
fn bindings_that_dont_verify_or_contradict_are_refused() -> Result<()> {
    let (jump, target) = (Host::new("jump", 1), Host::new("target", 2));

    // Signed by another key than the one it claims.
    let mut forged = SessionBind {
        host_key: target.key(),
        session_id: b"session".to_vec(),
        signature: jump.keypair.try_sign(b"session")?,
        is_forwarding: false,
    };
    let mut bindings = SessionBindings::default();
    ensure!(
        bindings.bind(&encode(&forged)?).is_err(),
        "forged signature accepted"
    );
    ensure!(
        bindings.is_remote() && bindings.is_empty(),
        "a failed bind must still count"
    );

    // Signature over another session ID.
    forged.host_key = jump.key();
    forged.session_id = b"other".to_vec();
    ensure!(SessionBindings::default().bind(&encode(&forged)?).is_err());

    let long = vec![1_u8; 129];
    ensure!(
        SessionBindings::default()
            .bind(&jump.bind(&long, false)?)
            .is_err(),
        "long session ID"
    );

    let mut trailing = jump.bind(b"session", false)?;
    trailing.push(0);
    ensure!(
        SessionBindings::default().bind(&trailing).is_err(),
        "trailing data"
    );
    ensure!(
        SessionBindings::default().bind(&[]).is_err(),
        "empty request"
    );

    // Same session ID, other host key.
    let mut bindings = SessionBindings::default();
    bindings.bind(&jump.bind(b"session", true)?)?;
    ensure!(bindings.bind(&target.bind(b"session", true)?).is_err());

    // Nothing may follow a binding for authentication.
    let mut bindings = SessionBindings::default();
    bindings.bind(&jump.bind(b"session-1", false)?)?;
    ensure!(bindings.bind(&target.bind(b"session-2", false)?).is_err());
    Ok(())
}

#[test]
fn at_most_sixteen_hops() -> Result<()> {
    let jump = Host::new("jump", 1);
    let mut bindings = SessionBindings::default();
    for hop in 0..16_u8 {
        bindings.bind(&jump.bind(&[hop, 1], true)?)?;
    }
    ensure!(bindings.bind(&jump.bind(&[99, 1], true)?).is_err());
    Ok(())
}

#[test]
fn malformed_or_reserved_constraints_are_refused() -> Result<()> {
    let jump = Host::new("jump", 1);
    let target = Host::new("target", 2);
    let valid = WireConstraint {
        from: hop("", None),
        to: hop("", Some(&jump)),
    };
    let encode_one = |constraint: &WireConstraint| {
        encode(&RestrictDestination {
            constraints: vec![constraint.clone()],
        })
    };
    ensure!(parse_destination_constraints(&encode_one(&valid)?)?.len() == 1);

    let mut cases: Vec<(&str, WireConstraint)> = Vec::new();
    let mut user_on_first_hop = valid.clone();
    user_on_first_hop.from.username = "alice".to_owned();
    cases.push(("user on the first hop", user_on_first_hop));
    let mut hostname_without_keys = valid.clone();
    hostname_without_keys.from.hostname = "jump".to_owned();
    cases.push(("first hop hostname without keys", hostname_without_keys));
    let mut keys_without_hostname = valid.clone();
    keys_without_hostname.from = hop("", Some(&target));
    keys_without_hostname.from.hostname = String::new();
    cases.push(("first hop keys without hostname", keys_without_hostname));
    let mut no_destination_name = valid.clone();
    no_destination_name.to.hostname = String::new();
    cases.push(("destination without hostname", no_destination_name));
    let mut no_destination_keys = valid.clone();
    no_destination_keys.to.keys.clear();
    cases.push(("destination without keys", no_destination_keys));
    let mut nul = valid.clone();
    nul.to.hostname = "jump\0evil".to_owned();
    cases.push(("NUL in a hostname", nul));
    let mut long_user = valid.clone();
    long_user.to.username = "u".repeat(257);
    cases.push(("long user pattern", long_user));
    for (case, constraint) in cases {
        ensure!(
            parse_destination_constraints(&encode_one(&constraint)?).is_err(),
            "accepted: {case}"
        );
    }
    ensure!(
        parse_destination_constraints(&[]).is_err(),
        "empty list accepted"
    );

    // Reserved fields, which ssh-agent-lib's own types can't even express.
    let mut reserved_constraint = Vec::new();
    {
        let mut inner = Vec::new();
        valid.from.encode_prefixed(&mut inner)?;
        valid.to.encode_prefixed(&mut inner)?;
        "future".encode(&mut inner)?;
        inner.encode(&mut reserved_constraint)?;
    }
    ensure!(
        parse_destination_constraints(&reserved_constraint).is_err(),
        "reserved constraint field"
    );
    let mut reserved_hop = Vec::new();
    {
        let mut to = Vec::new();
        "".encode(&mut to)?;
        "jump".encode(&mut to)?;
        "future".encode(&mut to)?;
        jump.key().encode_prefixed(&mut to)?;
        0_u8.encode(&mut to)?;
        let mut inner = Vec::new();
        valid.from.encode_prefixed(&mut inner)?;
        to.encode(&mut inner)?;
        "".encode(&mut inner)?;
        inner.encode(&mut reserved_hop)?;
    }
    ensure!(
        parse_destination_constraints(&reserved_hop).is_err(),
        "reserved hop field"
    );
    let mut trailing = encode_one(&valid)?;
    trailing.push(0);
    ensure!(
        parse_destination_constraints(&trailing).is_err(),
        "trailing data"
    );
    Ok(())
}

#[test]
fn constrained_keys_follow_the_bound_path() -> Result<()> {
    let (jump, target, elsewhere) = (
        Host::new("jump", 1),
        Host::new("target", 2),
        Host::new("elsewhere", 3),
    );
    // ssh-add -h jump -h "jump>target"
    let through_jump = constraints(&[(None, &jump, ""), (Some(&jump), &target, "")])?;
    // ssh-add -h jump
    let only_jump = constraints(&[(None, &jump, "")])?;

    // Unconstrained keys and local connections see everything.
    let mut local = SessionBindings::default();
    ensure!(permitted(&[], &local, Some("alice")).is_ok());
    ensure!(permitted(&only_jump, &local, None).is_ok());

    // A failed bind hides constrained keys.
    ensure!(local.bind(b"garbage").is_err());
    ensure!(permitted(&only_jump, &local, None).is_err());
    ensure!(
        permitted(&[], &local, None).is_ok(),
        "unconstrained keys stay usable"
    );

    // Logging in to jump directly.
    let mut direct = SessionBindings::default();
    direct.bind(&jump.bind(b"s1", false)?)?;
    let allowed = permitted(&only_jump, &direct, Some("alice"))?;
    ensure!(allowed.destination == Some("jump"));
    let mut to_target = SessionBindings::default();
    to_target.bind(&target.bind(b"s2", false)?)?;
    ensure!(
        permitted(&only_jump, &to_target, None).is_err(),
        "listed for the wrong host"
    );

    // Forwarded to jump, logging in to target from there.
    let mut forwarded = SessionBindings::default();
    forwarded.bind(&jump.bind(b"s1", true)?)?;
    ensure!(
        permitted(&through_jump, &forwarded, None).is_ok(),
        "hidden on jump"
    );
    ensure!(
        permitted(&only_jump, &forwarded, None).is_err(),
        "listed beyond jump although only jump is allowed"
    );
    ensure!(
        permitted(&through_jump, &forwarded, Some("alice")).is_err(),
        "signed on a forwarding hop"
    );
    forwarded.bind(&target.bind(b"s2", false)?)?;
    let allowed = permitted(&through_jump, &forwarded, Some("alice"))?;
    ensure!(
        allowed
            == skagent::destination::Permitted {
                forwarded_to: Some("jump"),
                destination: Some("target"),
            }
    );
    ensure!(permitted(&only_jump, &forwarded, Some("alice")).is_err());

    // Forwarded to jump, logging in somewhere not listed.
    let mut astray = SessionBindings::default();
    astray.bind(&jump.bind(b"s1", true)?)?;
    astray.bind(&elsewhere.bind(b"s3", false)?)?;
    ensure!(permitted(&through_jump, &astray, Some("alice")).is_err());
    Ok(())
}

#[test]
fn user_patterns_restrict_the_last_hop() -> Result<()> {
    let jump = Host::new("jump", 1);
    let git_only = constraints(&[(None, &jump, "git*")])?;
    let mut bindings = SessionBindings::default();
    bindings.bind(&jump.bind(b"s1", false)?)?;
    ensure!(permitted(&git_only, &bindings, Some("gitlab")).is_ok());
    ensure!(permitted(&git_only, &bindings, Some("alice")).is_err());
    ensure!(
        permitted(&git_only, &bindings, None).is_ok(),
        "listing doesn't know the user yet"
    );
    Ok(())
}

#[test]
fn constrained_signatures_must_be_logins_into_the_bound_session() -> Result<()> {
    let (jump, target) = (Host::new("jump", 1), Host::new("target", 2));
    let key = user_key();
    let only_jump = constraints(&[(None, &jump, "")])?;
    let through_jump = constraints(&[(None, &jump, ""), (Some(&jump), &target, "")])?;

    let local = SessionBindings::default();
    ensure!(
        authorize_signature(
            &key,
            "ssh:example",
            &only_jump,
            &local,
            &userauth(b"s1", "alice", &key, None)?
        )
        .is_err(),
        "signed on an unbound connection"
    );

    let mut direct = SessionBindings::default();
    direct.bind(&jump.bind(b"s1", false)?)?;
    ensure!(
        authorize_signature(&key, "ssh:example", &only_jump, &direct, &sshsig("git")?).is_err(),
        "signed SSHSIG data"
    );
    ensure!(
        authorize_signature(
            &key,
            "ssh:example",
            &only_jump,
            &direct,
            &userauth(b"s0", "alice", &key, None)?
        )
        .is_err(),
        "signed for another session"
    );
    ensure!(
        authorize_signature(
            &key,
            "ssh:example",
            &only_jump,
            &direct,
            &userauth(b"s1", "alice", &key, Some(&target.key()))?
        )
        .is_err(),
        "signed for another host key"
    );
    let purpose = authorize_signature(
        &key,
        "ssh:example",
        &only_jump,
        &direct,
        &userauth(b"s1", "alice", &key, None)?,
    )?;
    ensure!(
        purpose
            == Purpose::Login {
                user: "alice".to_owned(),
                destination: Destination::Named("jump".to_owned()),
                forwarded_to: None,
            }
    );

    let mut forwarded = SessionBindings::default();
    forwarded.bind(&jump.bind(b"s1", true)?)?;
    forwarded.bind(&target.bind(b"s2", false)?)?;
    ensure!(
        authorize_signature(
            &key,
            "ssh:example",
            &through_jump,
            &forwarded,
            &userauth(b"s2", "alice", &key, None)?
        )
        .is_err(),
        "a forwarded request without its host key"
    );
    let purpose = authorize_signature(
        &key,
        "ssh:example",
        &through_jump,
        &forwarded,
        &userauth(b"s2", "alice", &key, Some(&target.key()))?,
    )?;
    ensure!(
        purpose.to_string()
            == "log in as \"alice\" to target (through your agent forwarded to jump)"
    );
    Ok(())
}

#[test]
fn unconstrained_keys_describe_what_they_sign() -> Result<()> {
    let jump = Host::new("jump", 1);
    let key = user_key();
    let mut bound = SessionBindings::default();
    bound.bind(&jump.bind(b"s1", false)?)?;
    let purpose = authorize_signature(
        &key,
        "ssh:example",
        &[],
        &bound,
        &userauth(b"s1", "git", &key, None)?,
    )?;
    ensure!(
        purpose.to_string()
            == format!(
                "log in as \"git\" to the host with key {}",
                jump.fingerprint()
            )
    );

    // Not the bound session: the host is unverified.
    let purpose = authorize_signature(
        &key,
        "ssh:example",
        &[],
        &bound,
        &userauth(b"s9", "git", &key, None)?,
    )?;
    ensure!(purpose.to_string() == "log in as \"git\" to an unverified host");
    let local = SessionBindings::default();
    let purpose = authorize_signature(&key, "ssh:example", &[], &local, &sshsig("git")?)?;
    ensure!(purpose.to_string() == "sign \"git\" data");
    let purpose = authorize_signature(&key, "ssh:example", &[], &local, b"anything")?;
    ensure!(purpose == Purpose::Unknown);

    // Names from another machine can't break the prompt's layout.
    let purpose = authorize_signature(
        &key,
        "ssh:example",
        &[],
        &local,
        &userauth(
            b"s1",
            &format!("git\nApproved by IT{}", "x".repeat(100)),
            &key,
            None,
        )?,
    )?;
    let shown = purpose.to_string();
    ensure!(
        !shown.contains('\n') && shown.contains("git?Approved") && shown.contains('…'),
        "{shown}"
    );
    Ok(())
}

#[test]
fn web_origin_keys_only_sign_ssh_data() -> Result<()> {
    let key = user_key();
    let local = SessionBindings::default();
    let web = "https://example.com";
    ensure!(authorize_signature(&key, web, &[], &local, b"webauthn client data").is_err());
    ensure!(authorize_signature(&key, web, &[], &local, &sshsig("file")?).is_ok());
    ensure!(
        authorize_signature(&key, web, &[], &local, &userauth(b"s1", "git", &key, None)?).is_ok()
    );
    ensure!(authorize_signature(&key, "ssh:example", &[], &local, b"anything").is_ok());
    Ok(())
}

#[test]
fn only_well_formed_requests_for_this_key_count_as_logins() -> Result<()> {
    let key = user_key();
    let other = KeyData::SkEd25519(support::sk_public(2));
    ensure!(parse_userauth_request(&userauth(b"s1", "git", &key, None)?, &key).is_some());
    ensure!(
        parse_userauth_request(&userauth(b"s1", "git", &other, None)?, &key).is_none(),
        "another key"
    );
    ensure!(
        parse_userauth_request(&userauth(b"", "git", &key, None)?, &key).is_none(),
        "empty session ID"
    );
    let mut trailing = userauth(b"s1", "git", &key, None)?;
    trailing.push(0);
    ensure!(
        parse_userauth_request(&trailing, &key).is_none(),
        "trailing data"
    );
    ensure!(parse_sshsig_request(&sshsig("git")?) == Some("git".to_owned()));
    ensure!(parse_sshsig_request(b"SSHSIG").is_none());
    Ok(())
}

#[test]
fn globs_match_like_openssh() {
    for (pattern, text, expected) in [
        ("*", "", true),
        ("*", "anything", true),
        ("git", "git", true),
        ("git", "gitlab", false),
        ("git*", "gitlab", true),
        ("?it", "git", true),
        ("?it", "it", false),
        ("a*b*c", "aXXbYYc", true),
        ("a*b*c", "aXXbYY", false),
        ("*a", "banana", true),
        ("*ab", "aab", true),
        ("", "", true),
        ("", "x", false),
    ] {
        assert_eq!(glob_matches(pattern, text), expected, "{pattern} vs {text}");
    }
}

#[test]
fn host_keys_of_unknown_types_are_skipped_malformed_ones_refused() -> Result<()> {
    let jump = Host::new("jump", 1);
    // What ssh-add sends for a host that also has an OpenSSH 10 post-quantum key.
    let hop_with = |extra_blob: &[u8]| -> Result<Vec<u8>> {
        let mut to = Vec::new();
        "".encode(&mut to)?;
        "jump".encode(&mut to)?;
        "".encode(&mut to)?;
        jump.key().encode_prefixed(&mut to)?;
        0_u8.encode(&mut to)?;
        extra_blob.to_vec().encode(&mut to)?;
        0_u8.encode(&mut to)?;
        let mut constraint = Vec::new();
        hop("", None).encode_prefixed(&mut constraint)?;
        to.encode(&mut constraint)?;
        "".encode(&mut constraint)?;
        let mut details = Vec::new();
        constraint.encode(&mut details)?;
        Ok(details)
    };
    let mut post_quantum = Vec::new();
    "ssh-mldsa44-ed25519".encode(&mut post_quantum)?;
    vec![9_u8; 1344].encode(&mut post_quantum)?;
    let parsed = parse_destination_constraints(&hop_with(&post_quantum)?)?;
    let only = parsed.first().context("no constraint")?;
    ensure!(only.skipped_host_keys() == 1);
    let mut bindings = SessionBindings::default();
    bindings.bind(&jump.bind(b"s1", false)?)?;
    ensure!(
        permitted(&parsed, &bindings, Some("alice")).is_ok(),
        "the known key must still match"
    );

    let mut broken_ed25519 = Vec::new();
    "ssh-ed25519".encode(&mut broken_ed25519)?;
    vec![1_u8; 5].encode(&mut broken_ed25519)?;
    ensure!(
        parse_destination_constraints(&hop_with(&broken_ed25519)?).is_err(),
        "malformed known type accepted"
    );
    Ok(())
}
