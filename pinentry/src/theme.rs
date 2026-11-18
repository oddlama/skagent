//! The colours, fonts and size the popup is drawn with: design B+'s presets
//! (`tokens.json`), or what the agent's configuration made of them
//! (`skagent_popup::style`).

use std::sync::Arc;

use gpui::{FontFeatures, Hsla, Pixels, SharedString, px, rgba};
use skagent_popup::style::{Appearance, Color, Palette, SCALE_PERCENT, Style};

/// The design's font for text, bundled with the package.
pub const DESIGN_FONT: &str = "Inter";

/// The design's font for commands and fingerprints, bundled with the package.
pub const DESIGN_MONO: &str = "JetBrains Mono";

/// Light or dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The light theme.
    Light,
    /// The dark theme.
    Dark,
}

impl Mode {
    /// The mode `appearance` forces, if it does.
    #[must_use]
    pub const fn forced_by(appearance: Appearance) -> Option<Self> {
        match appearance {
            Appearance::System => None,
            Appearance::Light => Some(Self::Light),
            Appearance::Dark => Some(Self::Dark),
        }
    }
}

/// The font families to draw with: the configured ones where the system
/// has them, else the design's (see [`crate::fonts::available`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fonts {
    /// For text.
    pub text: SharedString,
    /// For commands and fingerprints.
    pub mono: SharedString,
}

impl Default for Fonts {
    fn default() -> Self {
        Self {
            text: DESIGN_FONT.into(),
            mono: DESIGN_MONO.into(),
        }
    }
}

/// Every colour the popup uses, its fonts and its size.
#[derive(Debug, Clone)]
pub struct Theme {
    /// Light or dark.
    pub mode: Mode,
    /// `surface`.
    pub surface: Hsla,
    /// `border`.
    pub border: Hsla,
    /// `text`.
    pub text: Hsla,
    /// `muted-text`.
    pub text_muted: Hsla,
    /// `placeholder`.
    pub placeholder: Hsla,
    /// `field`.
    pub field: Hsla,
    /// `field-error`.
    pub field_error: Hsla,
    /// `accent`.
    pub accent: Hsla,
    /// `on-accent`.
    pub on_accent: Hsla,
    /// `error`.
    pub error: Hsla,
    /// `warning`.
    pub warning: Hsla,
    /// `on-warning`.
    pub on_warning: Hsla,
    /// `success`.
    pub success: Hsla,
    /// `on-success`.
    pub on_success: Hsla,
    /// `avatar`.
    pub avatar_tint: Hsla,
    /// `avatar-warning`.
    pub avatar_tint_warning: Hsla,
    /// `avatar-error`.
    pub avatar_tint_error: Hsla,
    /// `avatar-missing`.
    pub avatar_missing_border: Hsla,
    /// `device`.
    pub device_tint: Hsla,
    /// `ring-track`.
    pub ring_track: Hsla,
    /// `dot`.
    pub dot_filled: Hsla,
    /// `dot-hollow`.
    pub dot_hollow: Hsla,
    /// Peak opacity of the pulse rings.
    pub pulse_opacity: f32,
    /// The font family for text.
    pub font: SharedString,
    /// Its OpenType features.
    pub font_features: FontFeatures,
    /// The font family for commands and fingerprints.
    pub mono: SharedString,
    /// Its OpenType features.
    pub mono_features: FontFeatures,
    /// The popup's size relative to the design's.
    pub scale: f32,
}

fn hsla(color: Color) -> Hsla {
    Hsla::from(rgba(u32::from_be_bytes([
        color.red,
        color.green,
        color.blue,
        color.alpha,
    ])))
}

fn features(configured: &std::collections::BTreeMap<String, u32>) -> FontFeatures {
    if configured.is_empty() {
        return FontFeatures::default();
    }
    FontFeatures(Arc::new(
        configured
            .iter()
            .map(|(tag, value)| (tag.clone(), *value))
            .collect(),
    ))
}

impl Theme {
    /// The design's theme for `mode`.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self::styled(&Style::default(), mode, &Fonts::default())
    }

    /// `style`'s theme for `mode`, drawn with `fonts`.
    #[must_use]
    pub fn styled(style: &Style, mode: Mode, fonts: &Fonts) -> Self {
        let (palette, pulse_opacity): (&Palette, f32) = match mode {
            Mode::Light => (&style.light, 0.35),
            Mode::Dark => (&style.dark, 0.4),
        };
        Self {
            mode,
            surface: hsla(palette.surface),
            border: hsla(palette.border),
            text: hsla(palette.text),
            text_muted: hsla(palette.muted_text),
            placeholder: hsla(palette.placeholder),
            field: hsla(palette.field),
            field_error: hsla(palette.field_error),
            accent: hsla(palette.accent),
            on_accent: hsla(palette.on_accent),
            error: hsla(palette.error),
            warning: hsla(palette.warning),
            on_warning: hsla(palette.on_warning),
            success: hsla(palette.success),
            on_success: hsla(palette.on_success),
            avatar_tint: hsla(palette.avatar),
            avatar_tint_warning: hsla(palette.avatar_warning),
            avatar_tint_error: hsla(palette.avatar_error),
            avatar_missing_border: hsla(palette.avatar_missing),
            device_tint: hsla(palette.device),
            ring_track: hsla(palette.ring_track),
            dot_filled: hsla(palette.dot),
            dot_hollow: hsla(palette.dot_hollow),
            pulse_opacity,
            font: fonts.text.clone(),
            font_features: features(&style.font_features),
            mono: fonts.mono.clone(),
            mono_features: features(&style.monospace_font_features),
            scale: scale(style),
        }
    }

    /// `value` design pixels at this theme's size.
    #[must_use]
    pub fn px(&self, value: f32) -> Pixels {
        px(value * self.scale)
    }
}

/// `style`'s size relative to the design's, kept within
/// [`SCALE_PERCENT`] whatever the agent sent.
#[must_use]
pub fn scale(style: &Style) -> f32 {
    let percent = style
        .scale_percent
        .clamp(*SCALE_PERCENT.start(), *SCALE_PERCENT.end());
    f32::from(percent) / 100.
}
