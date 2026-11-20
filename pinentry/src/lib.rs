//! skagent's popup: one window that takes the user through a request of the
//! agent (selection, PIN, touch, result), speaking the protocol in
//! `skagent-popup`. Design "B+".
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod answers;
pub mod assets;
pub mod fixtures;
pub mod fonts;
pub mod pin;
pub mod rendering;
pub mod screen;
pub mod theme;
pub mod ui;
