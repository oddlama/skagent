//! Telling security keys apart across replugs.
//!
//! FIDO has no portable device serial. What does change on every plug-in is
//! the device node: devtmpfs creates `/dev/hidrawN` anew, with a fresh inode
//! and change time, even if the number `N` is reused. So "same path, same
//! device number, same inode, same change time" means "still the same
//! plug-in of the same device".

use std::fmt;
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

use anyhow::{Context as _, Result, bail};

/// One plug-in of one device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    path: String,
    device_number: u64,
    inode: u64,
    change_time: (i64, i64),
}

impl DeviceIdentity {
    /// Builds an identity from its parts, e.g. for tests.
    #[must_use]
    pub fn new(path: &str, device_number: u64, inode: u64, change_time: (i64, i64)) -> Self {
        Self {
            path: path.to_owned(),
            device_number,
            inode,
            change_time,
        }
    }

    /// The identity of the device node at `path` right now.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` doesn't exist or isn't a character device.
    pub fn of(path: &str) -> Result<Self> {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("inspecting device node {path}"))?;
        if !metadata.file_type().is_char_device() {
            bail!("{path} is not a character device");
        }
        Ok(Self {
            path: path.to_owned(),
            device_number: metadata.rdev(),
            inode: metadata.ino(),
            change_time: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    /// The device path, e.g. `/dev/hidraw3`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Checks that this plug-in is still there: the node at its path exists
    /// and is still the same device.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceGone`] if the security key was unplugged, or something
    /// else took its path.
    pub fn ensure_present(&self) -> Result<()> {
        match Self::of(&self.path) {
            Ok(now) if now == *self => Ok(()),
            Ok(_) => Err(DeviceGone::new(&self.path, None).into()),
            Err(error) => Err(DeviceGone::new(&self.path, Some(&error)).into()),
        }
    }
}

/// A security key that was unplugged, or replaced by another device at its
/// path, while a request used it.
#[derive(Debug)]
pub struct DeviceGone {
    path: String,
    /// Why the node couldn't be inspected, if that's how it showed.
    detail: Option<String>,
}

impl DeviceGone {
    fn new(path: &str, detail: Option<&anyhow::Error>) -> Self {
        Self {
            path: path.to_owned(),
            detail: detail.map(|error| format!("{error:#}")),
        }
    }
}

impl fmt::Display for DeviceGone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the security key at {} was unplugged or replaced",
            self.path
        )?;
        match &self.detail {
            Some(detail) => write!(formatter, " ({detail})"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for DeviceGone {}
