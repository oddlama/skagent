//! Safe wrapper over the parts of libfido2 skagent needs: list devices, read
//! the PIN retry counter, and get one assertion.
//!
//! All calls block. Run them off the async runtime (`spawn_blocking`).
//!
//! Errors are `anyhow` errors with a [`FidoError`] inside; [`error_kind`]
//! finds it, so callers can react to e.g. a wrong PIN.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// libfido2 is a C library. The `unsafe` is confined to `raw.rs`, and every
// block there carries a SAFETY comment.
#![allow(unsafe_code)]

mod error;
mod raw;

use std::ffi::{CStr, CString};

use anyhow::{Context as _, Result, anyhow, bail};
use skagent_secret::SecretBuffer;

pub use crate::error::{ErrorKind, FidoError};

/// Most devices listed at once.
const MAX_DEVICES: usize = 16;

/// Device paths of USB HID authenticators on Linux. libfido2 >= 1.13 also
/// lists CCID (`pcsc://...`) and NFC devices, so a YubiKey shows up twice;
/// only the HID entry is used.
pub const HIDRAW_PREFIX: &str = "/dev/hidraw";

/// How long one device operation may block, touch included. A YubiKey gives up
/// waiting for a touch after about 30 s on its own.
const OPERATION_TIMEOUT_MS: i32 = 35_000;

/// The FIDO PIN is 4 to 63 bytes of UTF-8 (CTAP 2.1, `authenticatorClientPIN`).
pub const PIN_MAX_BYTES: usize = 63;

/// The [`ErrorKind`] of the libfido2 failure inside `error`, if there is one.
#[must_use]
pub fn error_kind(error: &anyhow::Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<FidoError>())
        .map(FidoError::kind)
}

/// A connected FIDO device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Device path, e.g. `/dev/hidraw3`.
    pub path: String,
    /// USB manufacturer string.
    pub manufacturer: String,
    /// USB product string.
    pub product: String,
}

/// The connected USB HID FIDO devices.
///
/// # Errors
///
/// Returns an error if libfido2 can't enumerate devices.
pub fn hid_devices() -> Result<Vec<DeviceInfo>> {
    let listed = raw::list_devices(MAX_DEVICES).map_err(anyhow::Error::new)?;
    Ok(listed
        .into_iter()
        .filter(|device| device.path.starts_with(HIDRAW_PREFIX))
        .map(|device| DeviceInfo {
            path: device.path,
            manufacturer: device.manufacturer,
            product: device.product,
        })
        .collect())
}

/// What to ask the authenticator to sign.
#[derive(Debug, Clone, Copy)]
pub struct AssertRequest<'a> {
    /// Relying party id, e.g. `ssh:example`.
    pub rp_id: &'a str,
    /// SHA-256 of the client data. OpenSSH uses the SHA-256 of the message.
    pub client_data_hash: [u8; 32],
    /// Credential id of the key to use.
    pub key_handle: &'a [u8],
    /// Whether the device must see a touch.
    pub user_presence: bool,
}

/// One signature from the authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The raw signature (64 bytes for EdDSA).
    pub signature: Vec<u8>,
    /// Authenticator data flags (user present, user verified, ...).
    pub flags: u8,
    /// The credential's signature counter.
    pub counter: u32,
}

/// An open FIDO device.
pub struct Device {
    inner: raw::Device,
    path: String,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Device")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Opens the device at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the device can't be opened or doesn't speak CTAP2.
    pub fn open(path: &str) -> Result<Self> {
        let c_path = CString::new(path)
            .with_context(|| format!("device path {path:?} contains a NUL byte"))?;
        let mut inner =
            raw::Device::open(&c_path).with_context(|| format!("opening FIDO device {path}"))?;
        if !inner.is_fido2() {
            bail!("FIDO device {path} doesn't support CTAP2 (U2F only)");
        }
        inner
            .set_timeout(OPERATION_TIMEOUT_MS)
            .with_context(|| format!("setting the operation timeout of {path}"))?;
        Ok(Self {
            inner,
            path: path.to_owned(),
        })
    }

    /// The device path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// PIN attempts left. Reading it doesn't use one.
    ///
    /// # Errors
    ///
    /// Returns an error if the device can't be asked.
    pub fn pin_retries(&mut self) -> Result<u32> {
        self.inner
            .pin_retries()
            .with_context(|| format!("reading the PIN retry counter of {}", self.path))
    }

    /// Asks the device for one signature. Blocks until touched, if a touch is
    /// required, or until the operation times out.
    ///
    /// With a `pin`, libfido2 first trades it for a PIN token. A wrong PIN
    /// costs a retry.
    ///
    /// # Errors
    ///
    /// Returns an error with a [`FidoError`] inside if the device refuses;
    /// see [`error_kind`].
    pub fn assert(
        &mut self,
        request: &AssertRequest<'_>,
        pin: Option<&SecretBuffer>,
    ) -> Result<Statement> {
        let rp_id = CString::new(request.rp_id)
            .with_context(|| format!("relying party id {:?} contains a NUL byte", request.rp_id))?;
        let pin = pin.map(nul_terminated_pin).transpose()?;
        let pin = pin
            .as_ref()
            .map(|pin| {
                CStr::from_bytes_with_nul(pin.expose()).context("the PIN contains a NUL byte")
            })
            .transpose()?;

        let mut assertion = raw::Assertion::new()?;
        assertion.set_rp(&rp_id)?;
        assertion.set_clientdata_hash(&request.client_data_hash)?;
        assertion.allow_credential(request.key_handle)?;
        assertion.set_user_presence(if request.user_presence {
            raw::Opt::True
        } else {
            raw::Opt::False
        })?;
        // With a PIN, user verification happens through the PIN token, like
        // OpenSSH does it; the `uv` option itself stays unset.
        assertion.set_user_verification(raw::Opt::Omit)?;

        self.inner
            .get_assert(&mut assertion, pin)
            .with_context(|| {
                format!(
                    "getting an assertion from {} for {}",
                    self.path, request.rp_id
                )
            })?;

        if assertion.count() != 1 {
            bail!(
                "{} returned {} assertions for one allowed credential",
                self.path,
                assertion.count()
            );
        }
        let (signature, flags, counter) = assertion
            .statement(0)
            .ok_or_else(|| anyhow!("{} returned an assertion without a signature", self.path))?;
        Ok(Statement {
            signature,
            flags,
            counter,
        })
    }
}

/// Copies `pin` with a trailing NUL into locked memory, for libfido2.
fn nul_terminated_pin(pin: &SecretBuffer) -> Result<SecretBuffer> {
    if pin.len() < 4 || pin.len() > PIN_MAX_BYTES {
        bail!("a FIDO PIN has 4 to {PIN_MAX_BYTES} bytes");
    }
    let capacity = pin
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow!("PIN length overflows"))?;
    let mut terminated = SecretBuffer::with_capacity(capacity)?;
    terminated.extend_from_slice(pin.expose())?;
    terminated.extend_from_slice(&[0])?;
    Ok(terminated)
}
