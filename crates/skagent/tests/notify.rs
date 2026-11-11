//! What goes into a notification body.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use skagent::notify::markup_escaped;

#[test]
fn text_from_other_machines_is_never_markup() {
    assert_eq!(
        markup_escaped(r#"log in as "<b>git</b>" & more"#),
        r#"log in as "&lt;b&gt;git&lt;/b&gt;" &amp; more"#
    );
    assert_eq!(markup_escaped("plain"), "plain");
}
