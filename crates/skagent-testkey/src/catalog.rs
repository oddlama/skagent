//! Work around soft-fido2 0.17's incomplete credential-management replies.
//!
//! Capture the public COSE key from a successful enrollment's authenticator
//! data. Only authenticated, successful enumeration replies are supplemented;
//! this code never derives or accesses a private key.

use std::collections::HashMap;
use std::io::Cursor;

use anyhow::{Context as _, Result, bail, ensure};
use ciborium::Value;

/// Public keys and protection policies of successfully enrolled credentials.
#[derive(Debug, Default)]
pub struct Catalog(HashMap<Vec<u8>, (Value, u8)>);

impl Catalog {
    /// Records a successfully touched makeCredential response. `protection`
    /// reads credProtect from the test authenticator's credential store.
    ///
    /// # Errors
    /// Refuses malformed authenticator data or a missing stored credential.
    pub fn record(
        &mut self,
        response: &[u8],
        protection: impl FnOnce(&[u8]) -> Result<u8>,
    ) -> Result<()> {
        let map = success_map(response)?;
        let data = field(&map, 2)
            .and_then(Value::as_bytes)
            .context("enrollment has no authenticator data")?;
        ensure!(
            data.get(32).is_some_and(|flags| flags & 0x40 != 0),
            "enrollment has no attested credential data"
        );
        let length: [u8; 2] = data
            .get(53..55)
            .context("missing credential id length")?
            .try_into()?;
        let end = 55_usize
            .checked_add(usize::from(u16::from_be_bytes(length)))
            .context("credential id length overflow")?;
        let id = data.get(55..end).context("truncated credential id")?;
        ensure!(!id.is_empty(), "empty enrollment credential id");
        let remaining = data.get(end..).context("missing COSE public key")?;
        let public: Value = ciborium::from_reader(Cursor::new(remaining))
            .context("decoding enrolled COSE public key")?;
        ensure!(public.is_map(), "COSE public key is not a map");
        let protection = protection(id)?;
        self.0.insert(id.to_vec(), (public, protection));
        Ok(())
    }

    /// Fills publicKey and credProtect on successful enumerateCredentials
    /// begin/next replies only. Other requests and errors are left untouched.
    ///
    /// # Errors
    /// Refuses malformed successful listings or unknown credential ids.
    pub fn repair(&self, request: &[u8], response: Vec<u8>) -> Result<Vec<u8>> {
        let Some((&command, parameters)) = request.split_first() else {
            return Ok(response);
        };
        if !matches!(command, 0x0a | 0x41) || response.first() != Some(&0) {
            return Ok(response);
        }
        let parameters: Value =
            ciborium::from_reader(parameters).context("decoding credential-management request")?;
        let parameters = parameters
            .as_map()
            .context("credential-management parameters are not a map")?;
        let subcommand = field(parameters, 1)
            .and_then(Value::as_integer)
            .map(i128::from);
        if !matches!(subcommand, Some(4 | 5)) {
            return Ok(response);
        }
        let mut map = success_map(&response)?;
        let descriptor = field(&map, 7)
            .and_then(Value::as_map)
            .context("listing has no credential descriptor")?;
        let id = descriptor
            .iter()
            .find(|(key, _)| key.as_text() == Some("id"))
            .and_then(|(_, value)| value.as_bytes())
            .context("listing has no credential id")?;
        let (public, protection) = self
            .0
            .get(id)
            .context("listed credential was not enrolled on this test key")?;
        // Preserve fields if the upstream implementation eventually supplies them.
        if field(&map, 8).is_none() {
            map.push((Value::Integer(8.into()), public.clone()));
        }
        if field(&map, 10).is_none() {
            map.push((
                Value::Integer(10.into()),
                Value::Integer((*protection).into()),
            ));
        }
        // libfido2 enforces CTAP's ascending integer-key order. Appending
        // publicKey after totalCredentials (9) would otherwise be rejected.
        map.sort_by_key(|(key, _)| key.as_integer().map(i128::from));
        let mut patched = vec![0];
        ciborium::into_writer(&Value::Map(map), &mut patched)
            .context("encoding complete credential listing")?;
        Ok(patched)
    }
}

fn success_map(response: &[u8]) -> Result<Vec<(Value, Value)>> {
    let Some((&0, payload)) = response.split_first() else {
        bail!("CTAP response was not successful")
    };
    let value: Value =
        ciborium::from_reader(payload).context("decoding successful CTAP response")?;
    value
        .into_map()
        .map_err(|_| anyhow::anyhow!("CTAP response is not a map"))
}

fn field(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(candidate, _)| {
            candidate
                .as_integer()
                .is_some_and(|value| i128::from(value) == key)
        })
        .map(|(_, value)| value)
}
