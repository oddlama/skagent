//! The PIN being typed.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use anyhow::{Result, ensure};
use skagent_pinentry::pin::{MAX_PIN_BYTES, PinInput};
use skagent_popup::{Intent, parse_intent};

#[test]
fn typing_editing_and_handing_over() -> Result<()> {
    let mut pin = PinInput::new()?;
    ensure!(pin.is_empty());
    ensure!(pin.push("24") && pin.push("68") && pin.push("ä€"));
    ensure!(pin.chars() == 6);
    pin.pop();
    pin.pop();
    ensure!(pin.chars() == 4);
    ensure!(pin.push("10"));
    let line = pin.take_line(7)?;
    ensure!(pin.is_empty(), "the field kept the PIN");
    let body = line.expose().strip_suffix(b"\n").unwrap_or(line.expose());
    let Intent::Pin { seq: 7, pin: sent } = parse_intent(body)? else {
        anyhow::bail!("not a PIN line");
    };
    ensure!(sent.expose() == b"246810");
    Ok(())
}

#[test]
fn control_characters_and_overlong_pins_are_refused() -> Result<()> {
    let mut pin = PinInput::new()?;
    ensure!(!pin.push("\n") && !pin.push("\u{8}") && !pin.push(""));
    ensure!(pin.push(&"1".repeat(MAX_PIN_BYTES)));
    ensure!(!pin.push("1"), "more than a FIDO PIN fits");
    ensure!(pin.chars() == MAX_PIN_BYTES);
    pin.pop();
    pin.pop();
    pin.clear();
    pin.pop();
    ensure!(pin.is_empty());
    Ok(())
}
