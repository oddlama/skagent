//! When skagent colors its own terminal output.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;

use skagent::output::color_enabled;

#[test]
fn color_only_on_a_terminal() {
    assert!(color_enabled(true, None));
    assert!(!color_enabled(false, None));
}

#[test]
fn no_color_disables_color_when_non_empty() {
    assert!(!color_enabled(true, Some(OsStr::new("1"))));
    assert!(!color_enabled(true, Some(OsStr::new("anything"))));
    // https://no-color.org: an empty NO_COLOR doesn't count as set.
    assert!(color_enabled(true, Some(OsStr::new(""))));
}
