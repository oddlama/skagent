//! The design's fonts, bundled by the Nix package so the popup looks as
//! designed whether or not Inter is installed, and the configured ones.
//! Emoji use the system's colour emoji font, as the design says.

use std::borrow::Cow;

use gpui::{App, SharedString};
use skagent_popup::style::Style;

use crate::theme::{DESIGN_FONT, DESIGN_MONO, Fonts};

/// Font files, `:`-separated, chosen when the binary is built: the Nix
/// package points this at Inter and JetBrains Mono in the store. Builds
/// without it use whatever the system has.
const BUNDLED: Option<&str> = option_env!("SKAGENT_PINENTRY_FONTS");

/// Makes the bundled fonts available to the window. A font that can't be
/// read leaves the system's in its place.
pub fn load_bundled(cx: &App) {
    let Some(paths) = BUNDLED else {
        return;
    };
    let fonts: Vec<Cow<'static, [u8]>> = paths
        .split(':')
        .filter(|path| !path.is_empty())
        .filter_map(|path| match std::fs::read(path) {
            Ok(bytes) => Some(Cow::Owned(bytes)),
            Err(error) => {
                tracing::warn!(path, %error, "can't read a bundled font");
                None
            }
        })
        .collect();
    if let Err(error) = cx.text_system().add_fonts(fonts) {
        tracing::warn!(error = %format!("{error:#}"), "can't load the bundled fonts");
    }
}

/// The font families `style` asks for where they're installed (or bundled),
/// else the design's, with a warning: GPUI would silently fall back to some
/// other font.
#[must_use]
pub fn available(style: &Style, cx: &App) -> Fonts {
    if style.font.is_none() && style.monospace_font.is_none() {
        return Fonts::default();
    }
    let installed = cx.text_system().all_font_names();
    let pick = |wanted: Option<&str>, design: &'static str| -> SharedString {
        let Some(wanted) = wanted else {
            return design.into();
        };
        if let Some(name) = installed
            .iter()
            .find(|name| name.eq_ignore_ascii_case(wanted))
        {
            name.clone().into()
        } else {
            tracing::warn!(
                font = wanted,
                instead = design,
                "the configured font isn't installed"
            );
            design.into()
        }
    };
    Fonts {
        text: pick(style.font.as_deref(), DESIGN_FONT),
        mono: pick(style.monospace_font.as_deref(), DESIGN_MONO),
    }
}
