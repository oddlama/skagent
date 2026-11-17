//! Reading YubiKey serials with Yubico's `READ_CONFIG` vendor command.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use skagent_fido::yubikey::{REPORT_LEN, Reports, serial, serial_from_device_info};

const NONCE: [u8; 8] = *b"nonce123";
const CID: u32 = 0x0102_0304;
const TIMEOUT: Duration = Duration::from_secs(1);
/// 12345678 = 0x00bc614e.
const SERIAL_TLV: [u8; 6] = [0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e];

/// A device that answers with scripted reports, in order, whatever was sent.
#[derive(Default)]
struct Scripted {
    replies: VecDeque<[u8; REPORT_LEN]>,
    sent: Vec<[u8; REPORT_LEN]>,
}

impl Reports for Scripted {
    fn send(&mut self, report: &[u8; REPORT_LEN]) -> Result<()> {
        self.sent.push(*report);
        Ok(())
    }

    fn receive(&mut self, _deadline: Instant) -> Result<Option<[u8; REPORT_LEN]>> {
        Ok(self.replies.pop_front())
    }
}

fn frame(cid: u32, rest: &[u8]) -> Result<[u8; REPORT_LEN]> {
    let mut frame = [0_u8; REPORT_LEN];
    let mut bytes = cid.to_be_bytes().to_vec();
    bytes.extend_from_slice(rest);
    frame
        .get_mut(..bytes.len())
        .context("frame too long")?
        .copy_from_slice(&bytes);
    Ok(frame)
}

/// The reply to INIT with `nonce`, allocating `cid`.
fn init_reply(nonce: [u8; 8], cid: u32) -> Result<[u8; REPORT_LEN]> {
    let mut payload = vec![0x86, 0x00, 17];
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&cid.to_be_bytes());
    payload.extend_from_slice(&[2, 5, 7, 4, 0x05]);
    frame(0xffff_ffff, &payload)
}

/// `message` as the frames of a `READ_CONFIG` reply on `CID`.
fn config_reply(message: &[u8]) -> Result<Vec<[u8; REPORT_LEN]>> {
    let length = u16::try_from(message.len())?.to_be_bytes();
    let (first, rest) = message.split_at(message.len().min(57));
    let mut head = vec![0xc2, length[0], length[1]];
    head.extend_from_slice(first);
    let mut frames = vec![frame(CID, &head)?];
    for (seq, chunk) in rest.chunks(59).enumerate() {
        let mut body = vec![u8::try_from(seq)?];
        body.extend_from_slice(chunk);
        frames.push(frame(CID, &body)?);
    }
    Ok(frames)
}

fn device_info(tlvs: &[u8]) -> Result<Vec<u8>> {
    let mut info = vec![u8::try_from(tlvs.len())?];
    info.extend_from_slice(tlvs);
    Ok(info)
}

#[test]
fn the_serial_is_found_among_the_other_entries() -> Result<()> {
    let mut tlvs = vec![0x01, 0x02, 0x02, 0x3f];
    tlvs.extend_from_slice(&SERIAL_TLV);
    tlvs.extend_from_slice(&[0x05, 0x03, 0x05, 0x07, 0x04]);
    ensure!(serial_from_device_info(&device_info(&tlvs)?)? == Some(12_345_678));
    // Long-form lengths are understood.
    let long = [0x10, 0x81, 0x02, 0xaa, 0xbb, 0x02, 0x01, 0x07];
    ensure!(serial_from_device_info(&device_info(&long)?)? == Some(7));
    Ok(())
}

#[test]
fn no_serial_or_a_zero_serial_is_none() -> Result<()> {
    ensure!(serial_from_device_info(&device_info(&[0x01, 0x02, 0x02, 0x3f])?)?.is_none());
    ensure!(serial_from_device_info(&device_info(&[0x02, 0x04, 0, 0, 0, 0])?)?.is_none());
    ensure!(serial_from_device_info(&[0])?.is_none());
    Ok(())
}

#[test]
fn malformed_device_info_is_refused() {
    let malformed: [&[u8]; 5] = [
        &[],
        &[0x05, 0x02, 0x04],                // shorter than announced
        &[0x04, 0x02, 0x05, 0x00, 0x00],    // entry longer than the info
        &[0x06, 0x02, 0x05, 1, 2, 3, 4, 5], // five-byte serial
        &[0x03, 0x1f, 0x01, 0x00],          // multi-byte tag
    ];
    for info in malformed {
        assert!(
            serial_from_device_info(info).is_err(),
            "accepted {info:02x?}"
        );
    }
}

#[test]
fn the_exchange_allocates_a_channel_and_reads_a_multi_frame_reply() -> Result<()> {
    // Enough entries before the serial to need two continuation frames.
    let mut tlvs = vec![0x10, 100];
    tlvs.extend_from_slice(&[0xee; 100]);
    tlvs.extend_from_slice(&SERIAL_TLV);
    let mut device = Scripted::default();
    // Another program's allocation, then ours; a keepalive before the reply.
    device
        .replies
        .push_back(init_reply(*b"another!", 0x0909_0909)?);
    device.replies.push_back(init_reply(NONCE, CID)?);
    device
        .replies
        .push_back(frame(CID, &[0xbb, 0x00, 0x01, 0x01])?);
    device
        .replies
        .push_back(frame(0x0909_0909, &[0x90, 0x00, 0x01, 0x00])?);
    device.replies.extend(config_reply(&device_info(&tlvs)?)?);

    ensure!(serial(&mut device, NONCE, TIMEOUT)? == Some(12_345_678));

    let [init, read_config] = device.sent.as_slice() else {
        anyhow::bail!("sent {} frames", device.sent.len());
    };
    ensure!(init.get(..7) == Some([0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08].as_slice()));
    ensure!(init.get(7..15) == Some(NONCE.as_slice()));
    ensure!(read_config.get(..8) == Some([1, 2, 3, 4, 0xc2, 0x00, 0x01, 0x00].as_slice()));
    Ok(())
}

#[test]
fn an_error_reply_means_no_serial() -> Result<()> {
    let mut device = Scripted::default();
    device.replies.push_back(init_reply(NONCE, CID)?);
    device
        .replies
        .push_back(frame(CID, &[0xbf, 0x00, 0x01, 0x01])?);
    ensure!(serial(&mut device, NONCE, TIMEOUT)?.is_none());
    Ok(())
}

#[test]
fn silence_and_nonsense_are_errors() -> Result<()> {
    let mut silent = Scripted::default();
    ensure!(
        serial(&mut silent, NONCE, TIMEOUT).is_err(),
        "no reply at all"
    );

    let mut no_answer = Scripted::default();
    no_answer.replies.push_back(init_reply(NONCE, CID)?);
    ensure!(
        serial(&mut no_answer, NONCE, TIMEOUT).is_err(),
        "no READ_CONFIG reply"
    );

    let mut wrong_command = Scripted::default();
    wrong_command.replies.push_back(init_reply(NONCE, CID)?);
    wrong_command
        .replies
        .push_back(frame(CID, &[0x90, 0x00, 0x01, 0x00])?);
    ensure!(
        serial(&mut wrong_command, NONCE, TIMEOUT).is_err(),
        "a reply to another command"
    );

    let mut broadcast = Scripted::default();
    broadcast.replies.push_back(init_reply(NONCE, 0xffff_ffff)?);
    ensure!(
        serial(&mut broadcast, NONCE, TIMEOUT).is_err(),
        "the broadcast channel allocated"
    );
    Ok(())
}
