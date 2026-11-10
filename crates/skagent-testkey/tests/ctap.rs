//! When the test key asks for a touch.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use ciborium::Value;
use skagent_testkey::ctap::{TouchRequirement, touch_requirement};

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
