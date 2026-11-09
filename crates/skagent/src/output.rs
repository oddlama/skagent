//! Styling for the few messages skagent writes to the terminal itself.
//!
//! Only the basic ANSI colors are used, so the user's terminal theme decides
//! what they look like. Red marks errors, nothing else is colored yet.

use std::ffi::OsStr;

use colored::{ColoredString, Colorize as _};

/// Whether output to a stream should be colored: only on a terminal, and
/// never when `NO_COLOR` is set to a non-empty value (<https://no-color.org>).
#[must_use]
pub fn color_enabled(stream_is_terminal: bool, no_color: Option<&OsStr>) -> bool {
    let no_color_requested = no_color.is_some_and(|value| !value.is_empty());
    stream_is_terminal && !no_color_requested
}

/// Applies the color decision to everything rendered with `colored`.
pub fn configure(color: bool) {
    colored::control::set_override(color);
}

/// The `error:` prefix of fatal error messages.
#[must_use]
pub fn error_label() -> ColoredString {
    "error:".red().bold()
}
