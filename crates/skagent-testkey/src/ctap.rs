//! Just enough CTAP2 request parsing to decide when the key needs a touch.
//!
//! soft-fido2 treats a fresh PIN token as user presence and then never asks
//! for a touch. A YubiKey always does, and so does CTAP 2.1 for tokens that
//! came from a PIN. So the test key decides about touch itself, for
//! `authenticatorMakeCredential` and for `authenticatorGetAssertion` unless
//! its `up` option is `false`.
//!
//! The touch is requested after the request succeeded, because a YubiKey
//! rejects invalid requests (missing PIN, unknown credential) without
//! blinking. If the touch doesn't happen, the result is withheld and a
//! credential the request created is removed again.

use anyhow::{Context as _, Result, bail};
use ciborium::Value;

/// `authenticatorMakeCredential`.
const MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
const GET_ASSERTION: u8 = 0x02;

/// Map keys of the parameters we look at.
const MAKE_CREDENTIAL_RP: i128 = 0x02;
const MAKE_CREDENTIAL_OPTIONS: i128 = 0x07;
const MAKE_CREDENTIAL_PIN_AUTH: i128 = 0x08;
const GET_ASSERTION_RP_ID: i128 = 0x01;
const GET_ASSERTION_OPTIONS: i128 = 0x05;

/// CTAP2 status: success.
pub const STATUS_OK: u8 = 0x00;
/// CTAP2 status: the request parameters aren't valid CBOR.
pub const STATUS_INVALID_CBOR: u8 = 0x12;
/// CTAP2 status: the user refused (touch denied).
pub const STATUS_OPERATION_DENIED: u8 = 0x27;
/// CTAP2 status: the request was cancelled with `CTAPHID_CANCEL`.
pub const STATUS_KEEPALIVE_CANCEL: u8 = 0x2d;
/// Empty `pinUvAuthParam`: touch first, then `PIN_AUTH_INVALID` (no retry used).
pub const STATUS_PIN_AUTH_INVALID: u8 = 0x33;
/// CTAP2 status: no touch within the timeout.
pub const STATUS_USER_ACTION_TIMEOUT: u8 = 0x2f;

/// When a request needs a touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchRequirement {
    /// No touch.
    None,
    /// libfido2 selects a device with makeCredential + empty pinUvAuthParam.
    /// CTAP requires a touch before rejecting it, without checking a PIN.
    Selection,
    /// Run the request; release a successful result only after a touch.
    AfterSuccess {
        /// CTAP2 command name, for the log.
        operation: &'static str,
        /// Relying party, e.g. `ssh:example`.
        rp_id: String,
    },
}

/// Inspects a CTAP2 request (command byte + CBOR parameters).
///
/// # Errors
///
/// Returns an error if a request we must inspect isn't well-formed CBOR.
pub fn touch_requirement(request: &[u8]) -> Result<TouchRequirement> {
    let Some((&command, parameters)) = request.split_first() else {
        return Ok(TouchRequirement::None);
    };
    match command {
        MAKE_CREDENTIAL => {
            let parameters = parse_map(parameters)?;
            if lookup(&parameters, MAKE_CREDENTIAL_PIN_AUTH)
                .and_then(Value::as_bytes)
                .is_some_and(Vec::is_empty)
            {
                return Ok(TouchRequirement::Selection);
            }
            let rp_id = lookup(&parameters, MAKE_CREDENTIAL_RP)
                .and_then(Value::as_map)
                .and_then(|rp| text_entry(rp, "id"))
                .unwrap_or_default();
            if option(&parameters, MAKE_CREDENTIAL_OPTIONS, "up") == Some(false) {
                bail!("makeCredential with up=false is invalid in CTAP2");
            }
            Ok(TouchRequirement::AfterSuccess {
                operation: "makeCredential",
                rp_id,
            })
        }
        GET_ASSERTION => {
            let parameters = parse_map(parameters)?;
            if option(&parameters, GET_ASSERTION_OPTIONS, "up") == Some(false) {
                return Ok(TouchRequirement::None);
            }
            let rp_id = lookup(&parameters, GET_ASSERTION_RP_ID)
                .and_then(Value::as_text)
                .map(str::to_owned)
                .unwrap_or_default();
            Ok(TouchRequirement::AfterSuccess {
                operation: "getAssertion",
                rp_id,
            })
        }
        _ => Ok(TouchRequirement::None),
    }
}

fn parse_map(parameters: &[u8]) -> Result<Vec<(Value, Value)>> {
    let value: Value =
        ciborium::from_reader(parameters).context("decoding CTAP2 request parameters")?;
    value
        .into_map()
        .map_err(|_| anyhow::anyhow!("CTAP2 request parameters are not a CBOR map"))
}

fn lookup(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(candidate, _)| {
            candidate
                .as_integer()
                .is_some_and(|integer| i128::from(integer) == key)
        })
        .map(|(_, value)| value)
}

fn text_entry(map: &[(Value, Value)], key: &str) -> Option<String> {
    map.iter()
        .find(|(candidate, _)| candidate.as_text() == Some(key))
        .and_then(|(_, value)| value.as_text())
        .map(str::to_owned)
}

fn option(parameters: &[(Value, Value)], key: i128, name: &str) -> Option<bool> {
    lookup(parameters, key)
        .and_then(Value::as_map)?
        .iter()
        .find(|(candidate, _)| candidate.as_text() == Some(name))
        .and_then(|(_, value)| value.as_bool())
}
