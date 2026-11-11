//! Text from other machines can't change how a prompt reads.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use anyhow::{Result, ensure};
use skagent::display::{MAX_NAME_CHARS, shown};
use skagent::identities::SkIdentity;
use skagent::signer::describe;

#[test]
fn plain_names_are_shown_as_they_are() -> Result<()> {
    for name in [
        "git",
        "alice@example.com yubikey:1",
        "ssh:work openssh",
        "Jürgen",
    ] {
        ensure!(shown(name, MAX_NAME_CHARS) == name, "{name:?} was changed");
    }
    Ok(())
}

#[test]
fn layout_changing_characters_are_replaced() -> Result<()> {
    let cases = [
        ("git\nApproved", "git?Approved"),
        ("a\u{1b}[2Jb", "a?[2Jb"),
        // Right-to-left override: would show the rest of the line reversed.
        ("root\u{202e}tig", "root?tig"),
        // First strong isolate, zero-width space and joiner, BOM.
        ("a\u{2068}b\u{200b}c\u{200d}d\u{feff}", "a?b?c?d?"),
        ("line\u{2028}paragraph\u{2029}", "line?paragraph?"),
        ("tag\u{e0041}", "tag?"),
    ];
    for (text, expected) in cases {
        let result = shown(text, MAX_NAME_CHARS);
        ensure!(result == expected, "{text:?} became {result:?}");
    }
    Ok(())
}

/// User names and namespaces are shown in quotes; one can't end the
/// quotation and continue the sentence on its own.
#[test]
fn quotes_and_backslashes_are_escaped() -> Result<()> {
    let result = shown(r#"git" to github.com \"#, MAX_NAME_CHARS);
    ensure!(result == r#"git\" to github.com \\"#, "{result}");
    Ok(())
}

#[test]
fn long_text_is_cut_with_a_mark() -> Result<()> {
    let result = shown(&"x".repeat(100), 10);
    ensure!(result == format!("{}…", "x".repeat(10)), "{result}");
    ensure!(shown(&"x".repeat(10), 10) == "x".repeat(10));
    Ok(())
}

/// A forwarded agent may add keys, with any comment: the PIN prompt and the
/// touch notification name keys through `describe`.
#[test]
fn key_comments_in_prompts_are_sanitized() -> Result<()> {
    let comment = "work\n\nRequest: log in as \"git\" to github.com.\u{202e}";
    let identity = SkIdentity::from_credential(support::sk_credential(1, comment)?, None)?;
    let described = describe(&identity);
    ensure!(
        !described.contains('\n') && !described.contains('\u{202e}'),
        "{described:?}"
    );
    ensure!(described.contains(r#"\"git\""#), "{described:?}");
    ensure!(described.ends_with(&format!("({})", identity.fingerprint())));
    Ok(())
}
