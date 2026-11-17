//! Design B+'s colours (`tokens.json`), light and dark.

use gpui::{Hsla, rgb};

/// Light or dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The light theme.
    Light,
    /// The dark theme.
    Dark,
}

/// Every colour the popup uses.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Light or dark.
    pub mode: Mode,
    /// `surface`.
    pub surface: Hsla,
    /// `border`.
    pub border: Hsla,
    /// `text`.
    pub text: Hsla,
    /// `textMuted`.
    pub text_muted: Hsla,
    /// `placeholder`.
    pub placeholder: Hsla,
    /// `field`.
    pub field: Hsla,
    /// `fieldError`.
    pub field_error: Hsla,
    /// `accent`.
    pub accent: Hsla,
    /// `onAccent`.
    pub on_accent: Hsla,
    /// `error`.
    pub error: Hsla,
    /// `warning`.
    pub warning: Hsla,
    /// `onWarning`.
    pub on_warning: Hsla,
    /// `success`.
    pub success: Hsla,
    /// `onSuccess`.
    pub on_success: Hsla,
    /// `avatarTint`.
    pub avatar_tint: Hsla,
    /// `avatarTintWarning`.
    pub avatar_tint_warning: Hsla,
    /// `avatarTintError`.
    pub avatar_tint_error: Hsla,
    /// `avatarMissingBorder`.
    pub avatar_missing_border: Hsla,
    /// `deviceTint`.
    pub device_tint: Hsla,
    /// `ringTrack`.
    pub ring_track: Hsla,
    /// `dotFilled`.
    pub dot_filled: Hsla,
    /// `dotHollow`.
    pub dot_hollow: Hsla,
    /// Peak opacity of the pulse rings.
    pub pulse_opacity: f32,
}

fn color(hex: u32) -> Hsla {
    Hsla::from(rgb(hex))
}

impl Theme {
    /// The theme for `mode`.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        match mode {
            Mode::Light => Self {
                mode,
                surface: color(0x00ff_ffff),
                border: color(0x00e4_e4e8),
                text: color(0x001f_1f23),
                text_muted: color(0x006b_6970),
                placeholder: color(0x006b_6970),
                field: color(0x00f4_f4f6),
                field_error: color(0x00fd_f0f1),
                accent: color(0x001c_71d8),
                on_accent: color(0x00ff_ffff),
                error: color(0x00c0_1c28),
                warning: color(0x00e5_a50a),
                on_warning: color(0x001f_1f23),
                success: color(0x001a_7f5a),
                on_success: color(0x00ff_ffff),
                avatar_tint: color(0x00ff_f1e5),
                avatar_tint_warning: color(0x00fd_f3e1),
                avatar_tint_error: color(0x00fd_f0f1),
                avatar_missing_border: color(0x00b9_b8bf),
                device_tint: color(0x00ee_f0f4),
                ring_track: color(0x00ec_ecf0),
                dot_filled: color(0x001f_1f23),
                dot_hollow: color(0x009a_99a0),
                pulse_opacity: 0.35,
            },
            Mode::Dark => Self {
                mode,
                surface: color(0x001c_1c1f),
                border: color(0x0030_3036),
                text: color(0x00f2_f2f4),
                text_muted: color(0x00a3_a2a8),
                placeholder: color(0x009a_99a0),
                field: color(0x002a_2a2f),
                field_error: color(0x0035_2224),
                accent: color(0x0035_84e4),
                on_accent: color(0x00ff_ffff),
                error: color(0x00ff_7b72),
                warning: color(0x00f5_c26b),
                on_warning: color(0x001c_1c1f),
                success: color(0x0057_e389),
                on_success: color(0x001c_1c1f),
                avatar_tint: color(0x003d_2b1f),
                avatar_tint_warning: color(0x003a_2f1a),
                avatar_tint_error: color(0x0035_2224),
                avatar_missing_border: color(0x005a_5960),
                device_tint: color(0x002c_2e33),
                ring_track: color(0x002f_2f35),
                dot_filled: color(0x00f2_f2f4),
                dot_hollow: color(0x006b_6a70),
                pulse_opacity: 0.4,
            },
        }
    }
}
