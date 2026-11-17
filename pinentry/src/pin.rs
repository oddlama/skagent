//! The PIN being typed: in locked, zeroizing memory, never in a `String`.

use anyhow::Result;
use skagent_secret::SecretBuffer;

/// The FIDO PIN is at most 63 bytes of UTF-8 (CTAP 2.1).
pub const MAX_PIN_BYTES: usize = 63;

/// The PIN field's content.
#[derive(Debug)]
pub struct PinInput {
    buffer: SecretBuffer,
    chars: usize,
}

impl PinInput {
    /// An empty field.
    ///
    /// # Errors
    ///
    /// Returns an error if locked memory can't be allocated.
    pub fn new() -> Result<Self> {
        Ok(Self {
            buffer: SecretBuffer::with_capacity(MAX_PIN_BYTES)?,
            chars: 0,
        })
    }

    /// Appends typed `text`, all of it or nothing: returns false if it
    /// doesn't fit a FIDO PIN or contains control characters.
    pub fn push(&mut self, text: &str) -> bool {
        if text.is_empty() || text.chars().any(char::is_control) {
            return false;
        }
        if self.buffer.extend_from_slice(text.as_bytes()).is_err() {
            return false;
        }
        self.chars = self.chars.saturating_add(text.chars().count());
        true
    }

    /// Removes the last character.
    pub fn pop(&mut self) {
        let bytes = self.buffer.expose();
        // The last character starts at the last byte that isn't a UTF-8
        // continuation byte.
        if let Some(start) = bytes.iter().rposition(|&byte| byte & 0xc0 != 0x80) {
            self.buffer.truncate(start);
            self.chars = self.chars.saturating_sub(1);
        }
    }

    /// Empties the field.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.chars = 0;
    }

    /// Characters typed, for the dots.
    #[must_use]
    pub fn chars(&self) -> usize {
        self.chars
    }

    /// Whether nothing is typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chars == 0
    }

    /// The `PIN` line for state `seq`, in locked memory, and an empty field.
    ///
    /// # Errors
    ///
    /// Returns an error if the field is empty or locked memory can't be
    /// allocated.
    pub fn take_line(&mut self, seq: u64) -> Result<SecretBuffer> {
        let line = skagent_popup::pin_line(seq, self.buffer.expose());
        self.clear();
        line
    }
}
