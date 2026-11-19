//! The messages between the plugin and the agent: what round-trips, and
//! that nothing else is accepted.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Context as _, Result, bail, ensure};
use skagent_age::wire::{
    BATCH_EXTENSION, BatchReply, BatchRequest, LIST_EXTENSION, ListReply, MAX_COMMAND_BYTES,
    MAX_LISTED, MAX_REPLY_BYTES, MAX_STANZAS, NEW_EXTENSION, NewReply, Refusal, UNWRAP_EXTENSION,
    UnwrapReply, UnwrapRequest, check_simple_request, decode_new_request, new_request,
    reply_details, reply_length, request_frame, simple_request,
};
use skagent_age::{FileKey, Identity, STANZA_BYTES, Stanza, WRAP_RANDOM_BYTES};

fn stanza(randomness: u8) -> Result<Stanza> {
    support::spec_recipient()?.wrap(
        &FileKey::from_bytes(b"0123456789abcdef")?,
        &[randomness; WRAP_RANDOM_BYTES],
    )
}

fn request(stanzas: usize, identity: Identity) -> Result<UnwrapRequest> {
    let stanza = stanza(1)?;
    Ok(UnwrapRequest {
        identity,
        stanzas: vec![stanza; stanzas],
    })
}

#[test]
fn the_extensions_carry_skagents_name() {
    for name in [
        UNWRAP_EXTENSION,
        NEW_EXTENSION,
        LIST_EXTENSION,
        BATCH_EXTENSION,
    ] {
        assert!(
            name.starts_with("age-") && name.ends_with("@skagent"),
            "{name}"
        );
    }
}

#[test]
fn an_unwrap_request_round_trips_with_either_kind_of_identity() -> Result<()> {
    let named = Identity::Named(support::spec_recipient()?);
    for identity in [Identity::AtHand, named] {
        let request = UnwrapRequest {
            identity,
            stanzas: vec![stanza(1)?, stanza(2)?],
        };
        let details = request.encode()?;
        ensure!(details.first() == Some(&1), "version");
        ensure!(UnwrapRequest::decode(&details)? == request);
    }
    // Without data the identity is one length field: version, 0, count.
    let details = request(1, Identity::AtHand)?.encode()?;
    ensure!(
        details.len() == 1 + 4 + 4 + STANZA_BYTES,
        "{}",
        details.len()
    );
    Ok(())
}

#[test]
fn an_unwrap_request_has_one_to_sixty_four_stanzas() -> Result<()> {
    ensure!(request(0, Identity::AtHand)?.encode().is_err(), "none");
    ensure!(request(MAX_STANZAS, Identity::AtHand)?.encode().is_ok());
    ensure!(
        request(MAX_STANZAS + 1, Identity::AtHand)?
            .encode()
            .is_err(),
        "too many"
    );

    // What a client that doesn't check sends is refused by the agent too.
    let one = request(1, Identity::AtHand)?.encode()?;
    let count_at = 1 + 4;
    let stanza = one.get(count_at + 4..).context("stanza")?;
    let with_count = |count: u32, stanzas: usize| {
        let mut details = one.get(..count_at).unwrap_or_default().to_vec();
        details.extend_from_slice(&count.to_be_bytes());
        for _ in 0..stanzas {
            details.extend_from_slice(stanza);
        }
        details
    };
    ensure!(UnwrapRequest::decode(&with_count(1, 1)).is_ok());
    ensure!(UnwrapRequest::decode(&with_count(0, 0)).is_err(), "zero");
    ensure!(UnwrapRequest::decode(&with_count(65, 65)).is_err(), "65");
    ensure!(
        UnwrapRequest::decode(&with_count(u32::MAX, 1)).is_err(),
        "a count without stanzas"
    );
    ensure!(
        UnwrapRequest::decode(&with_count(1, 2)).is_err(),
        "more than counted"
    );
    ensure!(
        UnwrapRequest::decode(&with_count(2, 1)).is_err(),
        "fewer than counted"
    );
    Ok(())
}

#[test]
fn an_unwrap_request_is_decoded_strictly() -> Result<()> {
    let good = request(2, Identity::Named(support::spec_recipient()?))?.encode()?;
    ensure!(UnwrapRequest::decode(&good).is_ok());

    // Cut anywhere, it is refused; so is anything after its end.
    for length in [0, 1, 4, 5, 6, 1000, 1221, 1222, 1226, 2378, good.len() - 1] {
        let cut = good.get(..length).context("cut")?;
        ensure!(UnwrapRequest::decode(cut).is_err(), "cut at {length}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    ensure!(UnwrapRequest::decode(&trailing).is_err(), "trailing byte");

    for version in [0, 2, 255] {
        let mut other = good.clone();
        *other.first_mut().context("empty")? = version;
        ensure!(UnwrapRequest::decode(&other).is_err(), "version {version}");
    }

    // An identity of a later version, and a stanza with a low-order share.
    let mut later = good.clone();
    *later.get_mut(5).context("identity version")? = 2;
    ensure!(UnwrapRequest::decode(&later).is_err(), "identity version 2");
    let mut low_order = good.clone();
    let end = low_order.len() - 32;
    low_order.get_mut(end - 32..end).context("share")?.fill(0);
    ensure!(
        UnwrapRequest::decode(&low_order).is_err(),
        "low-order share"
    );
    Ok(())
}

#[test]
fn an_unwrap_reply_is_a_file_key_no_match_or_a_reason() -> Result<()> {
    let file_key = UnwrapReply::FileKey(FileKey::from_bytes(b"0123456789abcdef")?).encode();
    ensure!(file_key.len() == 2 + 16);
    let UnwrapReply::FileKey(decoded) = UnwrapReply::decode(&file_key)? else {
        bail!("not a file key");
    };
    ensure!(decoded.expose() == b"0123456789abcdef");

    ensure!(matches!(
        UnwrapReply::decode(&UnwrapReply::NoMatch.encode())?,
        UnwrapReply::NoMatch
    ));

    for refusal in [
        Refusal::Cancelled,
        Refusal::TimedOut,
        Refusal::Locked,
        Refusal::NoIdentity,
        Refusal::AnotherIdentity,
        Refusal::Ambiguous,
        Refusal::NotAllowed,
        Refusal::Failed,
    ] {
        let details = UnwrapReply::Refused(refusal).encode();
        ensure!(details.len() == 3, "{refusal:?}");
        let UnwrapReply::Refused(decoded) = UnwrapReply::decode(&details)? else {
            bail!("not a refusal");
        };
        ensure!(decoded == refusal, "{refusal:?}");
        ensure!(
            refusal.message().contains("skagent") || refusal.message().contains("security key")
        );
    }
    // A reason a later agent adds reads as "failed", not as an error.
    let UnwrapReply::Refused(unknown) = UnwrapReply::decode(&[1, 2, 99])? else {
        bail!("not a refusal");
    };
    ensure!(unknown == Refusal::Failed);
    Ok(())
}

#[test]
fn an_unwrap_reply_is_decoded_strictly() -> Result<()> {
    let file_key = UnwrapReply::FileKey(FileKey::from_bytes(b"0123456789abcdef")?).encode();
    for length in 0..file_key.len() {
        let cut = file_key.get(..length).context("cut")?;
        ensure!(UnwrapReply::decode(cut).is_err(), "cut at {length}");
    }
    let mut longer = file_key.clone();
    longer.push(0);
    ensure!(UnwrapReply::decode(&longer).is_err(), "a 17-byte file key");
    ensure!(
        UnwrapReply::decode(&[1, 1, 0]).is_err(),
        "no match with data"
    );
    ensure!(
        UnwrapReply::decode(&[1, 2]).is_err(),
        "refusal without a reason"
    );
    ensure!(UnwrapReply::decode(&[1, 3]).is_err(), "unknown kind");
    ensure!(UnwrapReply::decode(&[2, 1]).is_err(), "version 2");
    Ok(())
}

#[test]
fn requests_that_say_nothing_are_one_version_byte() {
    assert_eq!(simple_request(), [1]);
    assert!(check_simple_request(&[1]).is_ok());
    for other in [&[][..], &[0], &[2], &[1, 0], &[1, 1]] {
        assert!(check_simple_request(other).is_err(), "{other:?}");
    }
}

#[test]
fn a_request_for_a_new_identity_says_whether_another_is_meant() -> Result<()> {
    ensure!(new_request(false) == [1, 0] && new_request(true) == [1, 1]);
    ensure!(!decode_new_request(&[1, 0])?);
    ensure!(decode_new_request(&[1, 1])?);
    for other in [&[][..], &[1], &[1, 2], &[2, 0], &[1, 0, 0]] {
        ensure!(decode_new_request(other).is_err(), "{other:?}");
    }
    Ok(())
}

#[test]
fn a_new_identity_is_answered_with_its_recipient() -> Result<()> {
    let reply = NewReply {
        recipient: support::spec_recipient()?,
    };
    let details = reply.encode();
    ensure!(details.len() == 1 + 1216);
    ensure!(NewReply::decode(&details)? == reply);
    ensure!(NewReply::decode(details.get(..1216).context("cut")?).is_err());
    let mut longer = details.clone();
    longer.push(0);
    ensure!(NewReply::decode(&longer).is_err());
    Ok(())
}

#[test]
fn a_list_names_recipients_where_they_are_known() -> Result<()> {
    let recipient = support::spec_recipient()?;
    for identities in [
        vec![],
        vec![None],
        vec![Some(recipient.clone()), None, Some(recipient.clone())],
    ] {
        let reply = ListReply { identities };
        let details = reply.encode()?;
        ensure!(ListReply::decode(&details)? == reply);
        let mut longer = details.clone();
        longer.push(0);
        ensure!(ListReply::decode(&longer).is_err(), "trailing byte");
    }
    ensure!(
        ListReply {
            identities: vec![None; MAX_LISTED + 1]
        }
        .encode()
        .is_err()
    );
    // A count without entries, and an entry of an unknown kind.
    ensure!(ListReply::decode(&[1, 0, 0, 0, 2, 0]).is_err());
    ensure!(ListReply::decode(&[1, 0, 0, 0, 1, 2]).is_err());
    ensure!(ListReply::decode(&[1, 0xff, 0xff, 0xff, 0xff]).is_err());
    Ok(())
}

#[test]
fn a_request_frame_is_an_ssh_agent_extension_message() -> Result<()> {
    let frame = request_frame("age-list@skagent", &[1])?;
    let mut expected = Vec::new();
    // length: type + string(name) + details
    expected.extend_from_slice(&u32::try_from(1 + 4 + 16 + 1)?.to_be_bytes());
    expected.push(27);
    expected.extend_from_slice(&16_u32.to_be_bytes());
    expected.extend_from_slice(b"age-list@skagent");
    expected.push(1);
    ensure!(frame == expected);
    Ok(())
}

#[test]
fn a_reply_is_the_extensions_response_or_a_failure() -> Result<()> {
    let mut response = vec![29];
    response.extend_from_slice(&16_u32.to_be_bytes());
    response.extend_from_slice(b"age-list@skagent");
    response.extend_from_slice(&[1, 0, 0, 0, 0]);
    ensure!(reply_details(LIST_EXTENSION, &response)? == Some(&[1, 0, 0, 0, 0][..]));
    ensure!(
        reply_details(NEW_EXTENSION, &response).is_err(),
        "another extension"
    );

    // SSH_AGENT_FAILURE and SSH_AGENT_EXTENSION_FAILURE: the agent refuses.
    ensure!(reply_details(LIST_EXTENSION, &[5])?.is_none());
    ensure!(reply_details(LIST_EXTENSION, &[28])?.is_none());
    // SSH_AGENT_SUCCESS carries nothing, so it answers none of our requests.
    ensure!(reply_details(LIST_EXTENSION, &[6]).is_err());
    ensure!(reply_details(LIST_EXTENSION, &[]).is_err());
    ensure!(
        reply_details(LIST_EXTENSION, &[29, 0, 0]).is_err(),
        "truncated name"
    );

    ensure!(reply_length([0, 0, 0, 1])? == 1);
    ensure!(reply_length([0, 0, 0, 0]).is_err());
    ensure!(reply_length(u32::try_from(MAX_REPLY_BYTES)?.to_be_bytes()).is_ok());
    ensure!(reply_length(u32::try_from(MAX_REPLY_BYTES + 1)?.to_be_bytes()).is_err());
    Ok(())
}

#[test]
fn a_batch_is_asked_for_with_a_duration_and_the_command_to_show() -> Result<()> {
    let request = BatchRequest {
        seconds: 300,
        command: "agenix rekey".to_owned(),
    };
    let details = request.encode()?;
    ensure!(details.len() == 1 + 4 + 4 + 12);
    ensure!(BatchRequest::decode(&details)? == request);
    for length in 0..details.len() {
        ensure!(
            BatchRequest::decode(details.get(..length).context("cut")?).is_err(),
            "{length}"
        );
    }
    let mut longer = details.clone();
    longer.push(0);
    ensure!(BatchRequest::decode(&longer).is_err(), "trailing byte");

    let limit = BatchRequest {
        seconds: 0,
        command: "x".repeat(MAX_COMMAND_BYTES),
    };
    ensure!(BatchRequest::decode(&limit.encode()?)? == limit);
    let too_long = BatchRequest {
        seconds: 0,
        command: "x".repeat(MAX_COMMAND_BYTES + 1),
    };
    ensure!(too_long.encode().is_err());
    // What a client that doesn't check sends: too long, or not text.
    let mut raw = vec![1, 0, 0, 0, 0];
    raw.extend_from_slice(&u32::try_from(MAX_COMMAND_BYTES + 1)?.to_be_bytes());
    raw.extend(std::iter::repeat_n(b'x', MAX_COMMAND_BYTES + 1));
    ensure!(
        BatchRequest::decode(&raw).is_err(),
        "a long command was decoded"
    );
    ensure!(
        BatchRequest::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]).is_err(),
        "not UTF-8"
    );

    let reply = BatchReply { seconds: 600 };
    ensure!(reply.encode() == [1, 0, 0, 2, 0x58]);
    ensure!(BatchReply::decode(&reply.encode())? == reply);
    ensure!(
        BatchReply::decode(&[1, 0, 0, 2]).is_err() && BatchReply::decode(&[2, 0, 0, 2, 0]).is_err()
    );
    Ok(())
}
