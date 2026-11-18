//! When the test key asks for a touch.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use ciborium::Value;
use skagent_testkey::ctap::{TouchRequirement, list_hmac_secret, touch_requirement};

fn request(command: u8, parameters: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    let mut bytes = vec![command];
    ciborium::into_writer(&Value::Map(parameters), &mut bytes).context("encoding test request")?;
    Ok(bytes)
}

fn options(up: Option<bool>) -> Value {
    Value::Map(
        up.map(|up| (Value::Text("up".to_owned()), Value::Bool(up)))
            .into_iter()
            .collect(),
    )
}

fn get_assertion(up: Option<bool>) -> Result<Vec<u8>> {
    let mut parameters = vec![
        (
            Value::Integer(1.into()),
            Value::Text("ssh:example".to_owned()),
        ),
        (Value::Integer(2.into()), Value::Bytes(vec![0; 32])),
    ];
    if up.is_some() {
        parameters.push((Value::Integer(5.into()), options(up)));
    }
    request(0x02, parameters)
}

#[test]
fn assertions_need_a_touch_after_success_unless_up_is_false() -> Result<()> {
    let expected = TouchRequirement::AfterSuccess {
        operation: "getAssertion",
        rp_id: "ssh:example".to_owned(),
    };
    ensure!(
        touch_requirement(&get_assertion(None)?)? == expected,
        "default up"
    );
    ensure!(
        touch_requirement(&get_assertion(Some(true))?)? == expected,
        "up=true"
    );
    ensure!(
        touch_requirement(&get_assertion(Some(false))?)? == TouchRequirement::None,
        "up=false"
    );
    Ok(())
}

/// A `getAssertion` that asks for the hmac-secret extension.
fn derivation(up: Option<bool>) -> Result<Vec<u8>> {
    let extensions = Value::Map(vec![(
        Value::Text("hmac-secret".to_owned()),
        Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(vec![0; 32]))]),
    )]);
    let mut parameters = vec![
        (
            Value::Integer(1.into()),
            Value::Text("skagent:age".to_owned()),
        ),
        (Value::Integer(2.into()), Value::Bytes(vec![0; 32])),
        (Value::Integer(4.into()), extensions),
    ];
    if up.is_some() {
        parameters.push((Value::Integer(5.into()), options(up)));
    }
    request(0x02, parameters)
}

#[test]
fn hmac_secret_is_refused_without_a_touch() -> Result<()> {
    let touched = TouchRequirement::AfterSuccess {
        operation: "getAssertion",
        rp_id: "skagent:age".to_owned(),
    };
    ensure!(
        touch_requirement(&derivation(None)?)? == touched,
        "default up"
    );
    ensure!(
        touch_requirement(&derivation(Some(true))?)? == touched,
        "up=true"
    );
    ensure!(
        touch_requirement(&derivation(Some(false))?)? == TouchRequirement::UpRequired,
        "up=false"
    );
    Ok(())
}

/// The extensions (key 2) of an `authenticatorGetInfo` response.
fn listed_extensions(response: &[u8]) -> Result<Vec<String>> {
    let (status, payload) = response.split_first().context("empty response")?;
    ensure!(*status == 0, "status {status}");
    let info: Value = ciborium::from_reader(payload).context("decoding the response")?;
    let extensions = info
        .as_map()
        .context("not a map")?
        .iter()
        .find(|(key, _)| key.as_integer() == Some(2.into()))
        .and_then(|(_, value)| value.as_array())
        .context("no extensions")?;
    Ok(extensions
        .iter()
        .filter_map(|extension| extension.as_text().map(str::to_owned))
        .collect())
}

#[test]
fn hmac_secret_is_listed_in_get_info() -> Result<()> {
    let versions = (
        Value::Integer(1.into()),
        Value::Array(vec![Value::Text("FIDO_2_0".to_owned())]),
    );
    let aaguid = (Value::Integer(3.into()), Value::Bytes(vec![7; 16]));
    let extensions = |names: &[&str]| {
        (
            Value::Integer(2.into()),
            Value::Array(
                names
                    .iter()
                    .map(|name| Value::Text((*name).to_owned()))
                    .collect(),
            ),
        )
    };
    let response = |entries: Vec<(Value, Value)>| request(0, entries);

    // Added once, next to what is listed already.
    for listed in [vec!["credProtect"], vec!["credProtect", "hmac-secret"]] {
        let patched = list_hmac_secret(
            &[0x04],
            response(vec![versions.clone(), extensions(&listed), aaguid.clone()])?,
        )?;
        ensure!(
            listed_extensions(&patched)? == ["credProtect", "hmac-secret"],
            "from {listed:?}"
        );
    }

    // Without any extension the entry is added, in CTAP's key order.
    let patched = list_hmac_secret(&[0x04], response(vec![versions.clone(), aaguid.clone()])?)?;
    ensure!(listed_extensions(&patched)? == ["hmac-secret"]);
    let info: Value = ciborium::from_reader(patched.get(1..).context("payload")?)?;
    let keys: Vec<_> = info
        .as_map()
        .context("not a map")?
        .iter()
        .filter_map(|(key, _)| key.as_integer().map(i128::from))
        .collect();
    ensure!(keys == [1, 2, 3], "keys {keys:?}");

    // Other commands and failed responses pass through unchanged.
    let other = response(vec![versions.clone(), extensions(&["credProtect"])])?;
    ensure!(list_hmac_secret(&[0x06], other.clone())? == other);
    ensure!(list_hmac_secret(&[0x04], vec![0x01])? == [0x01]);
    ensure!(list_hmac_secret(&[], other.clone())? == other);
    Ok(())
}

#[test]
fn credential_creation_needs_a_touch_after_success() -> Result<()> {
    let rp = Value::Map(vec![(
        Value::Text("id".to_owned()),
        Value::Text("ssh:example".to_owned()),
    )]);
    let make_credential = request(
        0x01,
        vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0; 32])),
            (Value::Integer(2.into()), rp),
        ],
    )?;
    ensure!(
        touch_requirement(&make_credential)?
            == TouchRequirement::AfterSuccess {
                operation: "makeCredential",
                rp_id: "ssh:example".to_owned(),
            }
    );
    Ok(())
}

#[test]
fn other_commands_and_empty_requests_need_no_touch() -> Result<()> {
    // authenticatorGetInfo and authenticatorClientPIN
    ensure!(touch_requirement(&[0x04])? == TouchRequirement::None);
    ensure!(touch_requirement(&request(0x06, vec![])?)? == TouchRequirement::None);
    ensure!(touch_requirement(&[])? == TouchRequirement::None);
    Ok(())
}

#[test]
fn empty_pin_auth_selects_by_touch_without_a_pin_attempt() -> Result<()> {
    let selection = request(0x01, vec![(Value::Integer(8.into()), Value::Bytes(vec![]))])?;
    ensure!(touch_requirement(&selection)? == TouchRequirement::Selection);
    let regular = request(
        0x01,
        vec![(Value::Integer(8.into()), Value::Bytes(vec![1; 16]))],
    )?;
    ensure!(matches!(
        touch_requirement(&regular)?,
        TouchRequirement::AfterSuccess { .. }
    ));
    Ok(())
}

#[test]
fn malformed_requests_are_rejected() {
    assert!(
        touch_requirement(&[0x02, 0xff, 0x00]).is_err(),
        "garbage accepted"
    );
    assert!(
        touch_requirement(&[0x02, 0x01]).is_err(),
        "non-map accepted"
    );
}
