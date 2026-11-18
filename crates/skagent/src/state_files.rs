//! skagent's files in `$XDG_STATE_HOME/skagent`: what it learned and keeps
//! across restarts (which security key holds which key, the keys to offer).
//! Nothing in them is secret. They're written privately (0600, in a 0700
//! directory) to a new file that is then renamed over the old one, so a crash
//! leaves either.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, ensure};

/// Where skagent's file `name` lives: `$XDG_STATE_HOME/skagent/name`, else
/// `$HOME/.local/state/skagent/name`.
///
/// # Errors
///
/// Returns an error if neither variable gives an absolute path.
pub fn state_path(
    name: &str,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf> {
    let absolute = |value: Option<&OsStr>| {
        value
            .map(Path::new)
            .filter(|path| path.is_absolute())
            .map(Path::to_path_buf)
    };
    let base = absolute(xdg_state_home)
        .or_else(|| absolute(home).map(|home| home.join(".local").join("state")))
        .context("neither XDG_STATE_HOME nor HOME is an absolute path")?;
    Ok(base.join("skagent").join(name))
}

/// The file's text, or `None` if there is no such file.
pub(crate) fn read(file: &Path) -> Result<Option<String>> {
    match fs::read_to_string(file) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", file.display())),
    }
}

/// Replaces `file` with `text`: written to a new, private file first, then
/// renamed over the old one.
pub(crate) fn write(file: &Path, text: &str) -> Result<()> {
    let directory = file
        .parent()
        .with_context(|| format!("{} has no parent directory", file.display()))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let mut name = file
        .file_name()
        .with_context(|| format!("{} has no file name", file.display()))?
        .to_owned();
    name.push(".new");
    let new = file.with_file_name(name);
    match fs::remove_file(&new) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("removing {}", new.display()));
        }
        _ => {}
    }
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&new)
        .with_context(|| format!("creating {}", new.display()))?;
    out.write_all(text.as_bytes())
        .and_then(|()| out.sync_all())
        .with_context(|| format!("writing {}", new.display()))?;
    fs::rename(&new, file)
        .with_context(|| format!("renaming {} to {}", new.display(), file.display()))
}

/// `bytes` as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut text, byte| {
            // Writing to a String can't fail.
            let _ = write!(text, "{byte:02x}");
            text
        },
    )
}

/// Hex of 1 to `max` bytes.
pub(crate) fn parse_hex(text: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty()
            && text.len().is_multiple_of(2)
            && text.len() <= max.saturating_mul(2)
            && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{text:?} is not hex of 1 to {max} bytes"
    );
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).context("hex")?;
            u8::from_str_radix(pair, 16).context("hex")
        })
        .collect()
}

/// Hex of exactly `N` bytes.
pub(crate) fn parse_fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    parse_hex(text, N)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{} bytes instead of {N}", bytes.len()))
}

/// `text` as a TOML basic string, quotes included: backslashes, quotes and
/// control characters escaped.
pub(crate) fn toml_string(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len().saturating_add(2));
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\t' => quoted.push(character),
            control if control.is_control() => {
                // Writing to a String can't fail.
                let _ = write!(quoted, "\\u{:04X}", u32::from(control));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}
