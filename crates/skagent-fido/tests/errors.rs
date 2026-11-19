//! Error classification and device access without a device present.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use libfido2_sys as sys;
use skagent_fido::{Device, ErrorKind, FidoError, error_kind, hid_devices};

#[test]
fn pin_failures_are_told_apart() {
    let cases = [
        (sys::FIDO_ERR_PIN_INVALID, ErrorKind::PinInvalid),
        (sys::FIDO_ERR_PIN_AUTH_BLOCKED, ErrorKind::PinAuthBlocked),
        (sys::FIDO_ERR_PIN_BLOCKED, ErrorKind::PinBlocked),
        (sys::FIDO_ERR_PIN_REQUIRED, ErrorKind::PinRequired),
        (sys::FIDO_ERR_PIN_NOT_SET, ErrorKind::PinNotSet),
        (
            sys::FIDO_ERR_PIN_POLICY_VIOLATION,
            ErrorKind::PinPolicyViolation,
        ),
        (sys::FIDO_ERR_NO_CREDENTIALS, ErrorKind::NoCredentials),
        // What a key answers when nobody touched it: the code CTAP has for
        // it, which a YubiKey 5.8 gives, and the ones of other firmware.
        (sys::FIDO_ERR_OPERATION_DENIED, ErrorKind::TouchTimeout),
        (sys::FIDO_ERR_ACTION_TIMEOUT, ErrorKind::TouchTimeout),
        (sys::FIDO_ERR_USER_ACTION_TIMEOUT, ErrorKind::TouchTimeout),
        (sys::FIDO_ERR_TX, ErrorKind::Transport),
        (sys::FIDO_ERR_RX, ErrorKind::Transport),
        (sys::FIDO_ERR_INTERNAL, ErrorKind::Other),
    ];
    for (code, kind) in cases {
        assert_eq!(ErrorKind::from_code(code), kind, "code {code}");
    }
}

#[test]
fn only_pin_failures_invalidate_the_pin() {
    for kind in [
        ErrorKind::PinInvalid,
        ErrorKind::PinAuthBlocked,
        ErrorKind::PinBlocked,
        ErrorKind::PinPolicyViolation,
    ] {
        assert!(kind.invalidates_pin(), "{kind:?}");
    }
    for kind in [
        ErrorKind::PinRequired,
        ErrorKind::NoCredentials,
        ErrorKind::TouchTimeout,
        ErrorKind::Transport,
        ErrorKind::Other,
    ] {
        assert!(!kind.invalidates_pin(), "{kind:?}");
    }
}

#[test]
fn the_kind_is_found_through_context() -> Result<()> {
    let error = anyhow::Error::new(FidoError::new(
        "fido_dev_get_assert",
        sys::FIDO_ERR_PIN_INVALID,
    ))
    .context("getting an assertion from /dev/hidraw0")
    .context("signing for ssh:example");
    ensure!(error_kind(&error) == Some(ErrorKind::PinInvalid));
    ensure!(error_kind(&anyhow::anyhow!("unrelated")).is_none());

    let message = format!("{error:#}");
    ensure!(message.contains("fido_dev_get_assert failed"), "{message}");
    ensure!(message.contains("libfido2 code 49"), "{message}");
    Ok(())
}

#[test]
fn listing_works_without_devices_and_only_returns_hidraw() -> Result<()> {
    let devices = hid_devices().context("listing devices")?;
    ensure!(
        devices
            .iter()
            .all(|device| device.path.starts_with("/dev/hidraw")),
        "{devices:?}"
    );
    Ok(())
}

#[test]
fn opening_a_missing_device_fails() {
    assert!(Device::open("/dev/hidraw-does-not-exist").is_err());
    assert!(
        Device::open("/dev/hidraw\0").is_err(),
        "NUL in path accepted"
    );
}
