//! Yubico's `READ_CONFIG` vendor command, which skagent uses to read a
//! YubiKey's serial. soft-fido2 doesn't know vendor commands, so the test key
//! answers it before soft-fido2 sees the frame.

/// `READ_CONFIG` (`0x42`) with the bit that marks the first frame.
pub const READ_CONFIG_FRAME: u8 = 0xc2;
/// CTAPHID `ERROR`, and its code for an unknown command.
const ERROR_FRAME: u8 = 0xbf;
const ERR_INVALID_CMD: u8 = 0x01;
/// Device info tag of the serial number.
const TAG_SERIAL: u8 = 0x02;

/// The reply to `packet` if it is a `READ_CONFIG` request: a device info with
/// `serial`, or without one an `ERR_INVALID_CMD`, like an authenticator that
/// isn't a YubiKey. `None` for every other packet.
#[must_use]
pub fn reply(packet: &[u8; 64], serial: Option<u32>) -> Option<[u8; 64]> {
    if packet.get(4) != Some(&READ_CONFIG_FRAME) {
        return None;
    }
    let mut message = packet.get(..4)?.to_vec();
    match serial {
        Some(serial) => {
            let mut info = vec![6, TAG_SERIAL, 4];
            info.extend_from_slice(&serial.to_be_bytes());
            message.push(READ_CONFIG_FRAME);
            message.extend_from_slice(&u16::try_from(info.len()).ok()?.to_be_bytes());
            message.extend_from_slice(&info);
        }
        None => message.extend_from_slice(&[ERROR_FRAME, 0, 1, ERR_INVALID_CMD]),
    }
    let mut frame = [0_u8; 64];
    frame.get_mut(..message.len())?.copy_from_slice(&message);
    Some(frame)
}
