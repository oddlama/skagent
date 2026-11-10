//! Public credential-listing repairs are gated on successful CTAP responses.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use ciborium::Value;
use skagent_testkey::catalog::Catalog;

fn encode(prefix: u8, value: &Value) -> Result<Vec<u8>> {
    let mut bytes = vec![prefix];
    ciborium::into_writer(value, &mut bytes).context("encoding test CBOR")?;
    Ok(bytes)
}

fn public_key() -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer(3.into()), Value::Integer((-8).into())),
        (Value::Integer((-1).into()), Value::Integer(6.into())),
        (Value::Integer((-2).into()), Value::Bytes(vec![42; 32])),
    ])
}

fn enrollment() -> Result<Vec<u8>> {
    let mut data = vec![0; 32];
    data.extend_from_slice(&[0x40, 0, 0, 0, 0]);
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
    ciborium::into_writer(&public_key(), &mut data).context("encoding COSE")?;
    encode(
        0,
        &Value::Map(vec![(Value::Integer(2.into()), Value::Bytes(data))]),
    )
}

fn request(subcommand: u8) -> Result<Vec<u8>> {
    encode(
        0x0a,
        &Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer(subcommand.into()),
        )]),
    )
}

fn listing() -> Result<Vec<u8>> {
    encode(
        0,
        &Value::Map(vec![(
            Value::Integer(7.into()),
            Value::Map(vec![
                (Value::Text("id".to_owned()), Value::Bytes(vec![1, 2, 3, 4])),
                (
                    Value::Text("type".to_owned()),
                    Value::Text("public-key".to_owned()),
                ),
            ]),
        )]),
    )
}

#[test]
fn both_enumeration_responses_get_public_key_and_protection() -> Result<()> {
    let mut catalog = Catalog::default();
    catalog.record(&enrollment()?, |id| {
        ensure!(id == [1, 2, 3, 4]);
        Ok(3)
    })?;
    for subcommand in [4, 5] {
        let response = catalog.repair(&request(subcommand)?, listing()?)?;
        let (_, payload) = response.split_first().context("empty response")?;
        let value: Value = ciborium::from_reader(payload).context("decoding patched listing")?;
        let map = value.as_map().context("not a map")?;
        ensure!(map.contains(&(Value::Integer(8.into()), public_key())));
        ensure!(map.contains(&(Value::Integer(10.into()), Value::Integer(3.into()))));
        ensure!(catalog.repair(&request(subcommand)?, response.clone())? == response);
    }
    Ok(())
}

#[test]
fn errors_and_unrelated_commands_are_not_modified() -> Result<()> {
    let catalog = Catalog::default();
    for failure in [0x31, 0x33, 0x36] {
        ensure!(catalog.repair(&request(4)?, vec![failure])? == [failure]);
    }
    ensure!(catalog.repair(&request(1)?, listing()?)? == listing()?);
    ensure!(catalog.repair(&[0x04], listing()?)? == listing()?);
    Ok(())
}

#[test]
fn unknown_credentials_and_malformed_enrollments_are_refused() -> Result<()> {
    let mut catalog = Catalog::default();
    ensure!(catalog.repair(&request(4)?, listing()?).is_err());
    for bad in [vec![], vec![0x31], vec![0, 0xa0]] {
        ensure!(catalog.record(&bad, |_| Ok(3)).is_err());
    }
    ensure!(
        catalog
            .record(&enrollment()?, |_| anyhow::bail!("unknown credential"))
            .is_err()
    );
    ensure!(catalog.repair(&request(4)?, listing()?).is_err());
    Ok(())
}
