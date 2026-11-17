//! YubiKey serial numbers, read over the FIDO interface.
//!
//! FIDO has no portable device serial, but YubiKeys answer Yubico's vendor
//! command `READ_CONFIG` (CTAPHID `0x42`, sent as `0xc2`) on their FIDO HID
//! interface with their device info, the serial included (`ykman` reads it
//! the same way). libfido2 can't send vendor commands, so this module speaks
//! the few CTAPHID frames needed itself: allocate a channel (`INIT`), send
//! `READ_CONFIG` for page 0, read the reply. Authenticators that don't know
//! the command answer with a CTAPHID error, which means "no serial".
//!
//! The exchange runs on its own channel, but the device serves one request at
//! a time: callers hold the device's lock and call this while libfido2 has no
//! request running on it.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};

/// Bytes in a FIDO HID report.
pub const REPORT_LEN: usize = 64;

/// Yubico's vendor command that returns the device info.
pub const READ_CONFIG: u8 = 0x42;

/// Channel used to allocate a channel.
const BROADCAST_CID: u32 = 0xffff_ffff;
/// Set on the command byte of the first frame of a message.
const FRAME_INIT: u8 = 0x80;
const CMD_INIT: u8 = 0x06;
const CMD_KEEPALIVE: u8 = 0x3b;
const CMD_ERROR: u8 = 0x3f;
/// Payload bytes in the first and in each following frame.
const INIT_PAYLOAD: usize = REPORT_LEN - 7;
const CONT_PAYLOAD: usize = REPORT_LEN - 5;
/// The device info is about a hundred bytes; anything far larger is wrong.
const MAX_MESSAGE: usize = 1024;
/// Device info tag holding the serial number.
const TAG_SERIAL: u8 = 0x02;

/// Sends and receives raw HID reports of one device.
pub trait Reports {
    /// Sends one report.
    ///
    /// # Errors
    ///
    /// Returns an error if the device can't be written to.
    fn send(&mut self, report: &[u8; REPORT_LEN]) -> Result<()>;

    /// Receives one report, or `None` once `deadline` has passed.
    ///
    /// # Errors
    ///
    /// Returns an error if the device can't be read.
    fn receive(&mut self, deadline: Instant) -> Result<Option<[u8; REPORT_LEN]>>;
}

/// Asks the device behind `reports` for its YubiKey serial, within `timeout`.
/// `nonce` identifies the reply to the channel allocation; it only has to
/// differ from what other programs use at the same time.
///
/// # Errors
///
/// Returns an error if the device doesn't answer in time or answers
/// malformed frames. `Ok(None)` means it has no serial to report.
pub fn serial(
    reports: &mut impl Reports,
    nonce: [u8; 8],
    timeout: Duration,
) -> Result<Option<u32>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("the timeout is too large")?;
    reports.send(&init_frame(BROADCAST_CID, CMD_INIT, &nonce)?)?;
    let cid = loop {
        let frame = reports
            .receive(deadline)?
            .context("the security key didn't answer the channel allocation")?;
        // Replies to other programs' allocations arrive here too.
        if let (Some(BROADCAST_CID), Some(&cmd)) = (frame_cid(&frame), frame.get(4))
            && cmd == FRAME_INIT | CMD_INIT
            && frame.get(7..15) == Some(nonce.as_slice())
        {
            let cid = frame
                .get(15..19)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_be_bytes)
                .context("the channel allocation reply is too short")?;
            ensure!(
                cid != BROADCAST_CID && cid != 0,
                "the security key allocated an invalid channel"
            );
            break cid;
        }
    };
    reports.send(&init_frame(cid, READ_CONFIG, &[0])?)?;
    match message(reports, cid, READ_CONFIG, deadline)? {
        Some(info) => serial_from_device_info(&info),
        None => Ok(None),
    }
}

/// The serial in a `READ_CONFIG` reply: a length byte, then TLVs.
///
/// # Errors
///
/// Returns an error if the reply or its serial is malformed.
pub fn serial_from_device_info(info: &[u8]) -> Result<Option<u32>> {
    let (&length, rest) = info.split_first().context("the device info is empty")?;
    let mut tlvs = rest
        .get(..usize::from(length))
        .context("the device info is shorter than it says")?;
    while let Some((&tag, rest)) = tlvs.split_first() {
        ensure!(tag & 0x1f != 0x1f, "the device info uses multi-byte tags");
        let (length, rest) = tlv_length(rest)?;
        let value = rest
            .get(..length)
            .context("a device info entry is longer than the device info")?;
        tlvs = rest.get(length..).unwrap_or_default();
        if tag == TAG_SERIAL {
            ensure!(
                (1..=4).contains(&value.len()),
                "the serial has {} bytes",
                value.len()
            );
            // Right-aligned into four bytes, big-endian.
            let mut bytes = [0_u8; 4];
            bytes
                .get_mut(4_usize.saturating_sub(value.len())..)
                .context("the serial doesn't fit four bytes")?
                .copy_from_slice(value);
            let serial = u32::from_be_bytes(bytes);
            return Ok((serial != 0).then_some(serial));
        }
    }
    Ok(None)
}

/// A BER length: one byte below 0x80, or 0x81/0x82 followed by one or two.
fn tlv_length(bytes: &[u8]) -> Result<(usize, &[u8])> {
    let (&first, rest) = bytes
        .split_first()
        .context("a device info entry has no length")?;
    match first {
        0..=0x7f => Ok((usize::from(first), rest)),
        0x81 => {
            let (&length, rest) = rest
                .split_first()
                .context("a device info length is cut off")?;
            Ok((usize::from(length), rest))
        }
        0x82 => {
            let length = rest
                .get(..2)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map(u16::from_be_bytes)
                .context("a device info length is cut off")?;
            Ok((usize::from(length), rest.get(2..).unwrap_or_default()))
        }
        _ => bail!("a device info length has an unsupported form"),
    }
}

/// Reads the reply to `command` on `cid`. `None`: the device answered with
/// a CTAPHID error, i.e. it doesn't know the command.
fn message(
    reports: &mut impl Reports,
    cid: u32,
    command: u8,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    let (length, mut message) = loop {
        let frame = reports
            .receive(deadline)?
            .context("the security key didn't answer READ_CONFIG in time")?;
        if frame_cid(&frame) != Some(cid) {
            continue;
        }
        let Some(&cmd) = frame.get(4) else { continue };
        if cmd == FRAME_INIT | CMD_KEEPALIVE {
            continue;
        }
        if cmd == FRAME_INIT | CMD_ERROR {
            return Ok(None);
        }
        ensure!(
            cmd == FRAME_INIT | command,
            "the security key answered command {cmd:#04x} instead of {:#04x}",
            FRAME_INIT | command
        );
        let length = frame
            .get(5..7)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(|bytes| usize::from(u16::from_be_bytes(bytes)))
            .context("the reply frame is too short")?;
        ensure!(length <= MAX_MESSAGE, "the reply announces {length} bytes");
        let first = frame
            .get(7..7_usize.saturating_add(length.min(INIT_PAYLOAD)))
            .unwrap_or_default();
        break (length, first.to_vec());
    };
    let mut sequence: u8 = 0;
    while message.len() < length {
        let frame = reports
            .receive(deadline)?
            .context("the security key stopped in the middle of its reply")?;
        if frame_cid(&frame) != Some(cid) {
            continue;
        }
        let seq = *frame
            .get(4)
            .context("the continuation frame is too short")?;
        ensure!(
            seq == sequence,
            "continuation frame {seq} arrived, {sequence} was expected"
        );
        sequence = sequence
            .checked_add(1)
            .filter(|next| *next < FRAME_INIT)
            .context("the reply has too many frames")?;
        let wanted = length.saturating_sub(message.len()).min(CONT_PAYLOAD);
        let part = frame
            .get(5..5_usize.saturating_add(wanted))
            .context("the continuation frame is too short")?;
        message.extend_from_slice(part);
    }
    Ok(Some(message))
}

/// The first frame of a message of at most one frame.
fn init_frame(cid: u32, command: u8, payload: &[u8]) -> Result<[u8; REPORT_LEN]> {
    ensure!(
        payload.len() <= INIT_PAYLOAD,
        "the message doesn't fit one frame"
    );
    let length = u16::try_from(payload.len()).context("the message is too long")?;
    let mut frame = [0_u8; REPORT_LEN];
    let header = frame.get_mut(..7).context("the frame is too short")?;
    header
        .get_mut(..4)
        .context("the frame is too short")?
        .copy_from_slice(&cid.to_be_bytes());
    if let Some(byte) = header.get_mut(4) {
        *byte = FRAME_INIT | command;
    }
    header
        .get_mut(5..7)
        .context("the frame is too short")?
        .copy_from_slice(&length.to_be_bytes());
    frame
        .get_mut(7..7_usize.saturating_add(payload.len()))
        .context("the frame is too short")?
        .copy_from_slice(payload);
    Ok(frame)
}

fn frame_cid(frame: &[u8; REPORT_LEN]) -> Option<u32> {
    frame
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
}

/// A nonce for the channel allocation: the time and this process's id, so
/// concurrent programs (and repeated calls) don't collide.
#[must_use]
pub fn nonce() -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mixed =
        seconds.rotate_left(32) ^ u64::from(nanos) ^ u64::from(std::process::id()).rotate_left(16);
    mixed.to_be_bytes()
}

#[cfg(target_os = "linux")]
pub use self::hidraw::Hidraw;

#[cfg(target_os = "linux")]
mod hidraw {
    use std::fs::{File, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::time::Instant;

    use anyhow::{Context as _, Result, ensure};
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    use super::{REPORT_LEN, Reports};

    /// A `/dev/hidrawN` device, read and written as raw reports.
    #[derive(Debug)]
    pub struct Hidraw {
        file: File,
        path: String,
    }

    impl Hidraw {
        /// Opens `path`, which must be a `/dev/hidraw*` node.
        ///
        /// # Errors
        ///
        /// Returns an error if `path` isn't a hidraw node or can't be opened.
        pub fn open(path: &str) -> Result<Self> {
            ensure!(
                path.starts_with(crate::HIDRAW_PREFIX),
                "{path} is not a hidraw device"
            );
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .with_context(|| format!("opening {path}"))?;
            Ok(Self {
                file,
                path: path.to_owned(),
            })
        }
    }

    impl Reports for Hidraw {
        fn send(&mut self, report: &[u8; REPORT_LEN]) -> Result<()> {
            // Report number 0 first: FIDO HID devices don't number reports.
            let mut buffer = [0_u8; REPORT_LEN + 1];
            buffer
                .get_mut(1..)
                .context("the report buffer is too short")?
                .copy_from_slice(report);
            self.file
                .write_all(&buffer)
                .with_context(|| format!("writing a report to {}", self.path))
        }

        fn receive(&mut self, deadline: Instant) -> Result<Option<[u8; REPORT_LEN]>> {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                let timeout = Timespec {
                    tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
                    tv_nsec: i64::from(remaining.subsec_nanos()),
                };
                let mut fds = [PollFd::new(&self.file, PollFlags::IN)];
                let ready = poll(&mut fds, Some(&timeout))
                    .with_context(|| format!("waiting for {}", self.path))?;
                if ready == 0 {
                    continue;
                }
                let mut report = [0_u8; REPORT_LEN];
                let read = self
                    .file
                    .read(&mut report)
                    .with_context(|| format!("reading a report from {}", self.path))?;
                ensure!(
                    read == REPORT_LEN,
                    "{} returned a {read}-byte report",
                    self.path
                );
                return Ok(Some(report));
            }
        }
    }
}
