//! The test key's answer to Yubico's `READ_CONFIG` vendor command.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, ensure};
use skagent_testkey::vendor::reply;

fn request(cmd: u8) -> [u8; 64] {
    let mut packet = [0_u8; 64];
    packet[..8].copy_from_slice(&[1, 2, 3, 4, cmd, 0, 1, 0]);
    packet
}

#[test]
fn a_serial_is_reported_as_device_info() -> Result<()> {
    let frame = reply(&request(0xc2), Some(12_345_678)).context("no reply")?;
    ensure!(
        frame.get(..14)
            == Some([1, 2, 3, 4, 0xc2, 0, 7, 6, 0x02, 4, 0x00, 0xbc, 0x61, 0x4e].as_slice()),
        "{:02x?}",
        frame.get(..14)
    );
    Ok(())
}

#[test]
fn without_a_serial_the_command_is_unknown() -> Result<()> {
    let frame = reply(&request(0xc2), None).context("no reply")?;
    ensure!(frame.get(..8) == Some([1, 2, 3, 4, 0xbf, 0, 1, 0x01].as_slice()));
    Ok(())
}

#[test]
fn other_commands_go_to_soft_fido2() {
    for cmd in [0x86, 0x90, 0x91, 0x00, 0x05] {
        assert!(
            reply(&request(cmd), Some(1)).is_none(),
            "intercepted {cmd:#04x}"
        );
    }
}
