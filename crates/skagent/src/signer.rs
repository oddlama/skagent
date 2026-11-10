//! Signing with an sk key on its security key.

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::{Digest as _, Sha256};
use skagent_fido::{AssertRequest, Device, ErrorKind, Statement, error_kind, hid_devices};
use skagent_secret::SecretBuffer;
use ssh_agent_lib::ssh_key::{Algorithm, Signature};

use crate::identities::SkIdentity;
use crate::prompt::Askpass;

/// OpenSSH sk flag: the key needs a touch for every signature.
pub const SK_USER_PRESENCE_REQUIRED: u8 = 0x01;
/// OpenSSH sk flag: the key needs user verification (PIN) for every signature.
pub const SK_USER_VERIFICATION_REQUIRED: u8 = 0x04;

/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Signs `data` with `identity`.
///
/// Needs exactly one connected security key. Asks for the PIN through
/// `askpass` if the key requires user verification.
///
/// # Errors
///
/// Returns an error if no unique device is connected, the PIN prompt fails,
/// or the device refuses (wrong PIN, no touch, unknown credential).
pub async fn sign(
    identity: &SkIdentity,
    data: &[u8],
    askpass: Option<&Askpass>,
) -> Result<Signature> {
    let path = only_device().await?;

    let pin = if identity.flags() & SK_USER_VERIFICATION_REQUIRED != 0 {
        let askpass = askpass.ok_or_else(|| {
            anyhow!(
                "{} needs a PIN, but no askpass program is configured (--askpass or SSH_ASKPASS)",
                describe(identity)
            )
        })?;
        Some(
            askpass
                .ask_pin(&format!(
                    "Enter PIN for {} and touch the key",
                    describe(identity)
                ))
                .await?,
        )
    } else {
        None
    };

    let request = OwnedAssertRequest {
        rp_id: identity.application().to_owned(),
        client_data_hash: Sha256::digest(data).into(),
        key_handle: identity.key_handle().to_vec(),
        user_presence: identity.flags() & SK_USER_PRESENCE_REQUIRED != 0,
    };
    let key = describe(identity);
    let statement = tokio::task::spawn_blocking(move || assert_on(&path, &request, pin.as_ref()))
        .await
        .context("the signing thread panicked or was cancelled")?
        .with_context(|| format!("signing with {key}"))?;
    ssh_signature(&statement)
}

/// The key as the user knows it: comment and fingerprint.
fn describe(identity: &SkIdentity) -> String {
    format!("{} ({})", identity.comment(), identity.fingerprint())
}

async fn only_device() -> Result<String> {
    let devices = tokio::task::spawn_blocking(hid_devices)
        .await
        .context("the device listing thread panicked or was cancelled")??;
    match devices.as_slice() {
        [] => bail!("no FIDO security key is connected"),
        [device] => Ok(device.path.clone()),
        several => bail!(
            "{} FIDO security keys are connected ({}); skagent can't pick one yet, leave only the key that holds this credential",
            several.len(),
            several
                .iter()
                .map(|device| format!("{} {}", device.path, device.product))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

struct OwnedAssertRequest {
    rp_id: String,
    client_data_hash: [u8; 32],
    key_handle: Vec<u8>,
    user_presence: bool,
}

fn assert_on(
    path: &str,
    request: &OwnedAssertRequest,
    pin: Option<&SecretBuffer>,
) -> Result<Statement> {
    let mut device = Device::open(path)?;
    let result = device.assert(
        &AssertRequest {
            rp_id: &request.rp_id,
            client_data_hash: request.client_data_hash,
            key_handle: &request.key_handle,
            user_presence: request.user_presence,
        },
        pin,
    );
    if let Err(error) = &result
        && error_kind(error) == Some(ErrorKind::PinInvalid)
    {
        // Reading the counter is free; it tells the user how close they are to a lockout.
        match device.pin_retries() {
            Ok(retries) => tracing::warn!(device = path, retries, "wrong PIN"),
            Err(retries_error) => tracing::warn!(
                device = path,
                error = %format!("{retries_error:#}"),
                "wrong PIN, and the retry counter can't be read"
            ),
        }
    }
    result
}

/// The `sk-ssh-ed25519@openssh.com` signature: Ed25519 signature, then the
/// authenticator flags and the signature counter, which the server needs to
/// rebuild the signed authenticator data.
///
/// # Errors
///
/// Returns an error if the signature isn't 64 bytes.
pub fn ssh_signature(statement: &Statement) -> Result<Signature> {
    if statement.signature.len() != ED25519_SIGNATURE_BYTES {
        bail!(
            "the security key returned a {}-byte signature, Ed25519 has {ED25519_SIGNATURE_BYTES}",
            statement.signature.len()
        );
    }
    let mut bytes = statement.signature.clone();
    bytes.push(statement.flags);
    bytes.extend_from_slice(&statement.counter.to_be_bytes());
    Signature::new(Algorithm::SkEd25519, bytes).context("encoding the sk-ssh-ed25519 signature")
}
