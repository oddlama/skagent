//! Text from outside, made safe to show in prompts and notifications.
//!
//! Key comments, user names and SSHSIG namespaces can come from another
//! machine (forwarded agents may add keys and sign). A PIN prompt is a
//! security decision, so nothing in such text may change how the rest of the
//! prompt reads: control characters, line and paragraph separators,
//! invisible formatting characters (zero-width, bidi embeddings, overrides
//! and isolates, which can reorder the surrounding text) become `?`, quotes
//! are escaped so a name can't close its own quotation, and the length is
//! capped.

/// Longest user, host or namespace shown.
pub const MAX_NAME_CHARS: usize = 64;

/// Longest key comment shown.
pub const MAX_COMMENT_CHARS: usize = 128;

/// `text` safe to show: see the module documentation. At most `max_chars`
/// characters of `text` are kept, then `…` marks the cut.
#[must_use]
pub fn shown(text: &str, max_chars: usize) -> String {
    sanitized(text, max_chars, true)
}

/// [`shown`] without escaping quotes, for text shown on its own rather
/// than quoted in a sentence (the popup's fields).
#[must_use]
pub fn plain(text: &str, max_chars: usize) -> String {
    sanitized(text, max_chars, false)
}

fn sanitized(text: &str, max_chars: usize, escape_quotes: bool) -> String {
    let mut shown = String::with_capacity(text.len().min(max_chars.saturating_mul(4)));
    for character in text.chars().take(max_chars) {
        match character {
            '"' | '\\' if escape_quotes => {
                shown.push('\\');
                shown.push(character);
            }
            _ if is_hidden(character) => shown.push('?'),
            _ => shown.push(character),
        }
    }
    if text.chars().nth(max_chars).is_some() {
        shown.push('…');
    }
    shown
}

/// Characters that aren't shown as themselves, or that change how the text
/// around them is laid out: controls (Cc), line and paragraph separators
/// (Zl, Zp) and format characters (Cf, Unicode 15.1).
fn is_hidden(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}
