//! The security key itself: the plugged-in FIDO devices, through libfido2.

use anyhow::Result;
use skagent_age::batch_salt;
use skagent_fido::{AgeCredential, Canceller, Device, ErrorKind, error_kind, hid_devices};
use skagent_secret::SecretBuffer;

use crate::key::{Failure, SecurityKey};

/// Most characters of a product name that go into a prompt.
const MAX_NAME_CHARS: usize = 40;

/// A plugged-in security key that could hold an age identity, opened.
#[derive(Debug)]
pub struct PluggedIn {
    device: Device,
    name: String,
}

impl PluggedIn {
    /// A handle that cancels the request waiting on this key, from another
    /// thread: when whoever asked is gone, the key stops blinking.
    #[must_use]
    pub fn canceller(&self) -> Canceller {
        self.device.canceller()
    }
}

/// Whether `error` is the security key's answer to a request, and not the
/// end of waiting for one.
fn answered(error: &anyhow::Error) -> bool {
    !matches!(
        error_kind(error),
        None | Some(ErrorKind::Transport | ErrorKind::Other)
    )
}

/// What the flow makes of a refusal by libfido2 or the key.
fn failure(error: anyhow::Error) -> Failure {
    match error_kind(&error) {
        Some(ErrorKind::PinInvalid) => Failure::WrongPin,
        Some(ErrorKind::PinAuthBlocked) => Failure::BlockedUntilReplugged,
        Some(ErrorKind::PinBlocked) => Failure::PinBlocked,
        Some(ErrorKind::TouchTimeout) => Failure::NotTouched,
        Some(ErrorKind::Cancelled) => Failure::Cancelled,
        _ => Failure::Other(error),
    }
}

impl SecurityKey for PluggedIn {
    fn name(&self) -> &str {
        &self.name
    }

    fn tries_left(&mut self) -> Result<u32> {
        self.device.pin_retries()
    }

    fn credentials(&mut self, pin: &SecretBuffer) -> Result<Vec<AgeCredential>, Failure> {
        self.device.age_credentials(pin).map_err(failure)
    }

    fn derive(
        &mut self,
        credential: &AgeCredential,
        pin: &SecretBuffer,
    ) -> Result<SecretBuffer, Failure> {
        // The salt of the agent's identities: the same key, by the same code.
        let derived = self.device.derive(credential, &batch_salt(), pin);
        if let Err(error) = &derived
            && !answered(error)
        {
            // The wait ended on this side: a signal that is caught
            // interrupts libfido2 where it waits for the key (`ppoll`),
            // which looks like a device that stopped answering. The key
            // still waits for its touch, and is told not to. One that
            // waits for nothing ignores this.
            let _nothing_pending = self.device.canceller().cancel();
        }
        derived.map_err(failure)
    }
}

/// What a person calls a security key: a YubiKey by its serial, as printed
/// on it, any other by its product name. Printable ASCII, since it goes
/// into prompts that may be shown anywhere.
#[must_use]
pub fn name(serial: Option<u32>, product: &str) -> String {
    if let Some(serial) = serial {
        return format!("YubiKey {serial}");
    }
    let product: String = product
        .chars()
        .filter(|character| character.is_ascii_graphic() || *character == ' ')
        .take(MAX_NAME_CHARS)
        .collect();
    let product = product.split_whitespace().collect::<Vec<_>>().join(" ");
    if product.is_empty() {
        "the security key".to_owned()
    } else {
        product
    }
}

/// The plugged-in FIDO devices, each with its name, and with itself if it
/// could hold an age identity: it speaks CTAP2, has a PIN, and lists what
/// an identity's credential needs. Else with why it can't. None of this
/// takes a PIN.
///
/// # Errors
///
/// Returns an error if the devices can't be listed, or libfido2's debug
/// output is switched on.
pub fn plugged_in() -> Result<Vec<(String, Result<PluggedIn, String>)>> {
    let mut devices = Vec::new();
    for info in hid_devices()? {
        // Before libfido2 has the device open; a key that isn't a YubiKey
        // answers with an error, which is no serial.
        let serial = skagent_fido::yubikey_serial(&info.path).ok().flatten();
        let name = name(serial, &info.product);
        let usable = usable(&info.path).map(|device| PluggedIn {
            device,
            name: name.clone(),
        });
        devices.push((name, usable));
    }
    Ok(devices)
}

/// Opens the device at `path` if it could hold an age identity.
fn usable(path: &str) -> Result<Device, String> {
    // A U2F token fails here.
    let mut device = Device::open(path).map_err(|error| format!("{error:#}"))?;
    if !device.has_pin() {
        return Err("it has no PIN".to_owned());
    }
    device
        .check_age_support()
        .map_err(|error| format!("{error:#}"))?;
    Ok(device)
}
