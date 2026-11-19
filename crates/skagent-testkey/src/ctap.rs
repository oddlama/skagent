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
//!
//! soft-fido2 also answers the hmac-secret extension without a touch. A
//! YubiKey refuses that with `CTAP2_ERR_UP_REQUIRED`, and so does the test
//! key, before soft-fido2 sees the request. soft-fido2 doesn't list the
//! extension it answers, so the test key adds it to `authenticatorGetInfo`.

use anyhow::{Context as _, Result, bail};
use ciborium::Value;

/// `authenticatorMakeCredential`.
const MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
const GET_ASSERTION: u8 = 0x02;
/// `authenticatorGetInfo`.
const GET_INFO: u8 = 0x04;

/// Map keys of the parameters we look at.
const MAKE_CREDENTIAL_RP: i128 = 0x02;
const MAKE_CREDENTIAL_OPTIONS: i128 = 0x07;
const MAKE_CREDENTIAL_PIN_AUTH: i128 = 0x08;
const GET_ASSERTION_RP_ID: i128 = 0x01;
const GET_ASSERTION_EXTENSIONS: i128 = 0x04;
const GET_ASSERTION_OPTIONS: i128 = 0x05;
const GET_INFO_EXTENSIONS: i128 = 0x02;

/// The extension that derives a secret from a credential.
const HMAC_SECRET: &str = "hmac-secret";

/// CTAP2 status: success.
pub const STATUS_OK: u8 = 0x00;
/// CTAP2 status: the request parameters aren't valid CBOR.
pub const STATUS_INVALID_CBOR: u8 = 0x12;
/// CTAP2 status: the user refused, or didn't touch in time.
pub const STATUS_OPERATION_DENIED: u8 = 0x27;
/// CTAP2 status: the request was cancelled with `CTAPHID_CANCEL`.
pub const STATUS_KEEPALIVE_CANCEL: u8 = 0x2d;
/// Empty `pinUvAuthParam`: touch first, then `PIN_AUTH_INVALID` (no retry used).
pub const STATUS_PIN_AUTH_INVALID: u8 = 0x33;
/// CTAP2 status: the request needs a touch and asked for none.
pub const STATUS_UP_REQUIRED: u8 = 0x3b;

/// When a request needs a touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchRequirement {
    /// No touch.
    None,
    /// hmac-secret with `up=false`: refused with [`STATUS_UP_REQUIRED`],
    /// without running the request.
    UpRequired,
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
                let derives = lookup(&parameters, GET_ASSERTION_EXTENSIONS)
                    .and_then(Value::as_map)
                    .is_some_and(|extensions| {
                        extensions
                            .iter()
                            .any(|(name, _)| name.as_text() == Some(HMAC_SECRET))
                    });
                return Ok(if derives {
                    TouchRequirement::UpRequired
                } else {
                    TouchRequirement::None
                });
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

/// Adds hmac-secret to the extensions of a successful
/// `authenticatorGetInfo` response. Other responses are left untouched.
///
/// # Errors
///
/// Returns an error if a successful response isn't the CBOR map it must be.
pub fn list_hmac_secret(request: &[u8], response: Vec<u8>) -> Result<Vec<u8>> {
    if request.first() != Some(&GET_INFO) {
        return Ok(response);
    }
    let Some((&STATUS_OK, payload)) = response.split_first() else {
        return Ok(response);
    };
    let mut info = parse_map(payload)?;
    let listed = info.iter_mut().find(|(key, _)| {
        key.as_integer()
            .is_some_and(|key| i128::from(key) == GET_INFO_EXTENSIONS)
    });
    match listed {
        Some((_, Value::Array(extensions))) => {
            if !extensions
                .iter()
                .any(|extension| extension.as_text() == Some(HMAC_SECRET))
            {
                extensions.push(Value::Text(HMAC_SECRET.to_owned()));
            }
        }
        Some(_) => bail!("the extensions of authenticatorGetInfo are not an array"),
        None => {
            info.push((
                Value::Integer(GET_INFO_EXTENSIONS.try_into()?),
                Value::Array(vec![Value::Text(HMAC_SECRET.to_owned())]),
            ));
            // libfido2 enforces CTAP's ascending integer-key order.
            info.sort_by_key(|(key, _)| key.as_integer().map(i128::from));
        }
    }
    let mut patched = vec![STATUS_OK];
    ciborium::into_writer(&Value::Map(info), &mut patched)
        .context("encoding authenticatorGetInfo with hmac-secret")?;
    Ok(patched)
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
