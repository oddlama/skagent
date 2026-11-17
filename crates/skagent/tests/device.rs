//! Telling whether a plug-in is still there, and saying so when it isn't.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent::device::{DeviceGone, DeviceIdentity};

/// Whether `identity` counts as gone, with a [`DeviceGone`] in the chain.
fn gone(identity: &DeviceIdentity) -> bool {
    identity.ensure_present().is_err_and(|error| {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<DeviceGone>())
            .is_some()
    })
}

#[test]
fn a_device_still_plugged_in_is_present() -> Result<()> {
    // A character device that exists everywhere, the build sandbox included.
    DeviceIdentity::of("/dev/null")?.ensure_present()
}

#[test]
fn unplugged_or_replaced_devices_are_gone() -> Result<()> {
    ensure!(
        gone(&DeviceIdentity::new(
            "/dev/does-not-exist",
            0xf302,
            1234,
            (1, 2)
        )),
        "a missing node counts as present"
    );
    // Same path, but another device and inode: something else took it.
    ensure!(
        gone(&DeviceIdentity::new("/dev/null", 0xf302, 1234, (1, 2))),
        "a replaced node counts as present"
    );
    Ok(())
}

#[test]
fn a_gone_device_is_named_in_the_error() -> Result<()> {
    let missing = DeviceIdentity::new("/dev/does-not-exist", 0xf302, 1234, (1, 2));
    let message = match missing.ensure_present() {
        Ok(()) => String::new(),
        Err(error) => format!("{error:#}"),
    };
    ensure!(
        message.starts_with("the security key at /dev/does-not-exist was unplugged or replaced"),
        "{message}"
    );
    Ok(())
}
