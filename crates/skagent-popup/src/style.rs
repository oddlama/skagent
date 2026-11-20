//! How the popup looks: colours for light and dark, fonts and size.
//!
//! The agent reads them from the `[popup]` table of its configuration and
//! sends them to the popup as a [`crate::Message::Style`] before anything
//! else. A popup that gets none uses the design's presets. What the popup
//! draws with ([`Renderer`]) is in that table too, and goes another way: the
//! popup has to know when it starts, so it is an argument of its.
//!
//! Light and dark each start from the design's preset, and the configuration
//! overrides single colours. A colour the configuration doesn't set is the
//! preset's as long as the colours it's made from are unchanged. Once one of
//! those changes it is mixed anew (see [`Token::rule`]): changing the surface
//! alone still gives tints, borders and fields that go with it.
//!
//! Settings that can't be used are skipped with a warning, the rest apply.
//! The popup is cosmetic: a typo in a colour mustn't stop the agent.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Smallest and largest `scale`, in percent.
pub const SCALE_PERCENT: std::ops::RangeInclusive<u16> = 50..=300;

/// WCAG's minimum contrast for icons and other graphics.
pub const MIN_ICON_CONTRAST: f32 = 3.;

/// Longest font family name, in characters.
pub const MAX_FONT_CHARS: usize = 100;

/// An sRGB colour with alpha, `#rrggbb` or `#rrggbbaa` as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Color {
    /// Red, 0 to 255.
    pub red: u8,
    /// Green, 0 to 255.
    pub green: u8,
    /// Blue, 0 to 255.
    pub blue: u8,
    /// Opacity, 0 (transparent) to 255 (opaque).
    pub alpha: u8,
}

impl Color {
    /// The opaque colour `0xRRGGBB`.
    #[must_use]
    pub const fn rgb(hex: u32) -> Self {
        let [_, red, green, blue] = hex.to_be_bytes();
        Self {
            red,
            green,
            blue,
            alpha: u8::MAX,
        }
    }

    /// Parses `#rgb`, `#rrggbb` or `#rrggbbaa`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits: Vec<u8> = text
            .strip_prefix('#')?
            .chars()
            .map(|digit| {
                digit
                    .to_digit(16)
                    .and_then(|value| u8::try_from(value).ok())
            })
            .collect::<Option<_>>()?;
        let byte = |high: u8, low: u8| high.checked_mul(16)?.checked_add(low);
        let [red, green, blue, alpha] = match digits.as_slice() {
            [red, green, blue] => [
                byte(*red, *red)?,
                byte(*green, *green)?,
                byte(*blue, *blue)?,
                u8::MAX,
            ],
            [r1, r2, g1, g2, b1, b2] => {
                [byte(*r1, *r2)?, byte(*g1, *g2)?, byte(*b1, *b2)?, u8::MAX]
            }
            [r1, r2, g1, g2, b1, b2, a1, a2] => [
                byte(*r1, *r2)?,
                byte(*g1, *g2)?,
                byte(*b1, *b2)?,
                byte(*a1, *a2)?,
            ],
            _ => return None,
        };
        Some(Self {
            red,
            green,
            blue,
            alpha,
        })
    }

    /// `percent` of the way from `self` to `towards`, channel by channel.
    #[must_use]
    pub fn mix(self, towards: Self, percent: u8) -> Self {
        let percent = u16::from(percent.min(100));
        let channel = |from: u8, to: u8| {
            let sum = u16::from(from)
                .saturating_mul(100_u16.saturating_sub(percent))
                .saturating_add(u16::from(to).saturating_mul(percent))
                .saturating_add(50);
            u8::try_from(sum.checked_div(100).unwrap_or(0)).unwrap_or(u8::MAX)
        };
        Self {
            red: channel(self.red, towards.red),
            green: channel(self.green, towards.green),
            blue: channel(self.blue, towards.blue),
            alpha: channel(self.alpha, towards.alpha),
        }
    }

    /// Relative luminance (WCAG 2), ignoring alpha.
    #[must_use]
    pub fn luminance(self) -> f32 {
        let linear = |channel: u8| {
            let value = f32::from(channel) / 255.;
            if value <= 0.040_45 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(self.red) + 0.7152 * linear(self.green) + 0.0722 * linear(self.blue)
    }

    /// Contrast ratio with `other` (WCAG 2): 1 for equal colours, 21 for
    /// black on white.
    #[must_use]
    pub fn contrast(self, other: Self) -> f32 {
        let (one, two) = (self.luminance(), other.luminance());
        (one.max(two) + 0.05) / (one.min(two) + 0.05)
    }
}

impl fmt::Display for Color {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "#{:02x}{:02x}{:02x}",
            self.red, self.green, self.blue
        )?;
        if self.alpha != u8::MAX {
            write!(formatter, "{:02x}", self.alpha)?;
        }
        Ok(())
    }
}

impl Serialize for Color {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Color {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| {
            serde::de::Error::custom(format!("{text:?} isn't a colour like #rrggbb"))
        })
    }
}

/// Every colour of the popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Palette {
    /// The card.
    pub surface: Color,
    /// Titles and typed PIN dots.
    pub text: Color,
    /// The PIN field's ring, buttons, the countdown and pulse.
    pub accent: Color,
    /// The badge of a finished request.
    pub success: Color,
    /// Warning badges and text, the YubiKey's contact.
    pub warning: Color,
    /// Error badges, text and the wrong PIN's ring.
    pub error: Color,
    /// Subtitles and small print.
    pub muted_text: Color,
    /// "PIN" in the empty field.
    pub placeholder: Color,
    /// The card's edge.
    pub border: Color,
    /// The PIN field, the command box and the queue pill.
    pub field: Color,
    /// The PIN field after a wrong PIN.
    pub field_error: Color,
    /// Icons on accent and error.
    pub on_accent: Color,
    /// The icon on success.
    pub on_success: Color,
    /// Icons on warning.
    pub on_warning: Color,
    /// Behind the key's emoji.
    pub avatar: Color,
    /// Behind the key's emoji when something needs attention.
    pub avatar_warning: Color,
    /// Behind the key's emoji when something failed.
    pub avatar_error: Color,
    /// The dashed edge of a key that isn't there.
    pub avatar_missing: Color,
    /// Behind the YubiKey drawing and loaded keys.
    pub device: Color,
    /// The countdown ring's track and the closing bar's.
    pub ring_track: Color,
    /// PIN tries left.
    pub dot: Color,
    /// PIN tries used, and the closing bar.
    pub dot_hollow: Color,
}

impl Palette {
    /// The design's light colours.
    pub const LIGHT: Self = Self {
        surface: Color::rgb(0x00ff_ffff),
        text: Color::rgb(0x001f_1f23),
        accent: Color::rgb(0x001c_71d8),
        success: Color::rgb(0x001a_7f5a),
        warning: Color::rgb(0x00e5_a50a),
        error: Color::rgb(0x00c0_1c28),
        muted_text: Color::rgb(0x006b_6970),
        placeholder: Color::rgb(0x006b_6970),
        border: Color::rgb(0x00e4_e4e8),
        field: Color::rgb(0x00f4_f4f6),
        field_error: Color::rgb(0x00fd_f0f1),
        on_accent: Color::rgb(0x00ff_ffff),
        on_success: Color::rgb(0x00ff_ffff),
        on_warning: Color::rgb(0x001f_1f23),
        avatar: Color::rgb(0x00ff_f1e5),
        avatar_warning: Color::rgb(0x00fd_f3e1),
        avatar_error: Color::rgb(0x00fd_f0f1),
        avatar_missing: Color::rgb(0x00b9_b8bf),
        device: Color::rgb(0x00ee_f0f4),
        ring_track: Color::rgb(0x00ec_ecf0),
        dot: Color::rgb(0x001f_1f23),
        dot_hollow: Color::rgb(0x009a_99a0),
    };

    /// The design's dark colours.
    pub const DARK: Self = Self {
        surface: Color::rgb(0x001c_1c1f),
        text: Color::rgb(0x00f2_f2f4),
        accent: Color::rgb(0x0035_84e4),
        success: Color::rgb(0x0057_e389),
        warning: Color::rgb(0x00f5_c26b),
        error: Color::rgb(0x00ff_7b72),
        muted_text: Color::rgb(0x00a3_a2a8),
        placeholder: Color::rgb(0x009a_99a0),
        border: Color::rgb(0x0030_3036),
        field: Color::rgb(0x002a_2a2f),
        field_error: Color::rgb(0x0035_2224),
        on_accent: Color::rgb(0x00ff_ffff),
        on_success: Color::rgb(0x001c_1c1f),
        on_warning: Color::rgb(0x001c_1c1f),
        avatar: Color::rgb(0x003d_2b1f),
        avatar_warning: Color::rgb(0x003a_2f1a),
        avatar_error: Color::rgb(0x0035_2224),
        avatar_missing: Color::rgb(0x005a_5960),
        device: Color::rgb(0x002c_2e33),
        ring_track: Color::rgb(0x002f_2f35),
        dot: Color::rgb(0x00f2_f2f4),
        dot_hollow: Color::rgb(0x006b_6a70),
    };

    /// The colour `token` names.
    #[must_use]
    pub const fn get(&self, token: Token) -> Color {
        match token {
            Token::Surface => self.surface,
            Token::Text => self.text,
            Token::Accent => self.accent,
            Token::Success => self.success,
            Token::Warning => self.warning,
            Token::Error => self.error,
            Token::MutedText => self.muted_text,
            Token::Placeholder => self.placeholder,
            Token::Border => self.border,
            Token::Field => self.field,
            Token::FieldError => self.field_error,
            Token::OnAccent => self.on_accent,
            Token::OnSuccess => self.on_success,
            Token::OnWarning => self.on_warning,
            Token::Avatar => self.avatar,
            Token::AvatarWarning => self.avatar_warning,
            Token::AvatarError => self.avatar_error,
            Token::AvatarMissing => self.avatar_missing,
            Token::Device => self.device,
            Token::RingTrack => self.ring_track,
            Token::Dot => self.dot,
            Token::DotHollow => self.dot_hollow,
        }
    }

    const fn slot(&mut self, token: Token) -> &mut Color {
        match token {
            Token::Surface => &mut self.surface,
            Token::Text => &mut self.text,
            Token::Accent => &mut self.accent,
            Token::Success => &mut self.success,
            Token::Warning => &mut self.warning,
            Token::Error => &mut self.error,
            Token::MutedText => &mut self.muted_text,
            Token::Placeholder => &mut self.placeholder,
            Token::Border => &mut self.border,
            Token::Field => &mut self.field,
            Token::FieldError => &mut self.field_error,
            Token::OnAccent => &mut self.on_accent,
            Token::OnSuccess => &mut self.on_success,
            Token::OnWarning => &mut self.on_warning,
            Token::Avatar => &mut self.avatar,
            Token::AvatarWarning => &mut self.avatar_warning,
            Token::AvatarError => &mut self.avatar_error,
            Token::AvatarMissing => &mut self.avatar_missing,
            Token::Device => &mut self.device,
            Token::RingTrack => &mut self.ring_track,
            Token::Dot => &mut self.dot,
            Token::DotHollow => &mut self.dot_hollow,
        }
    }

    /// `preset` with `overrides`, and the colours made from changed ones
    /// mixed anew (see the module documentation).
    #[must_use]
    pub fn resolve(preset: &Self, overrides: &BTreeMap<Token, Color>) -> Self {
        let mut palette = *preset;
        // `Token::ALL` lists every colour after the ones it's made from.
        for token in Token::ALL {
            let color = if let Some(color) = overrides.get(&token) {
                *color
            } else {
                let rule = token.rule();
                let unchanged = rule
                    .inputs()
                    .iter()
                    .all(|input| palette.get(*input) == preset.get(*input));
                if unchanged {
                    preset.get(token)
                } else {
                    rule.apply(&palette)
                }
            };
            *palette.slot(token) = color;
        }
        palette
    }
}

/// A colour's name in the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Token {
    /// `surface`
    Surface,
    /// `text`
    Text,
    /// `accent`
    Accent,
    /// `success`
    Success,
    /// `warning`
    Warning,
    /// `error`
    Error,
    /// `muted-text`
    MutedText,
    /// `placeholder`
    Placeholder,
    /// `border`
    Border,
    /// `field`
    Field,
    /// `field-error`
    FieldError,
    /// `on-accent`
    OnAccent,
    /// `on-success`
    OnSuccess,
    /// `on-warning`
    OnWarning,
    /// `avatar`
    Avatar,
    /// `avatar-warning`
    AvatarWarning,
    /// `avatar-error`
    AvatarError,
    /// `avatar-missing`
    AvatarMissing,
    /// `device`
    Device,
    /// `ring-track`
    RingTrack,
    /// `dot`
    Dot,
    /// `dot-hollow`
    DotHollow,
}

/// How a colour the configuration doesn't set is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// It isn't: one of the six base colours.
    Base,
    /// The surface, `percent` of the way towards another colour.
    Tint {
        /// The colour mixed in.
        towards: Token,
        /// How much of it.
        percent: u8,
    },
    /// The same as another colour.
    Same(Token),
    /// Ink on another colour: the lighter of text and surface where it
    /// reaches 3:1 (WCAG's minimum for icons), else the darker.
    On(Token),
}

impl Rule {
    /// The colours this one is made from.
    #[must_use]
    pub fn inputs(self) -> Vec<Token> {
        match self {
            Self::Base => Vec::new(),
            Self::Tint { towards, .. } => vec![Token::Surface, towards],
            Self::Same(token) => vec![token],
            Self::On(token) => vec![token, Token::Surface, Token::Text],
        }
    }

    /// The colour, made from `palette`.
    #[must_use]
    pub fn apply(self, palette: &Palette) -> Color {
        match self {
            // Never asked for: base colours are always the preset's or set.
            Self::Base => palette.surface,
            Self::Tint { towards, percent } => palette.surface.mix(palette.get(towards), percent),
            Self::Same(token) => palette.get(token),
            Self::On(token) => {
                let fill = palette.get(token);
                let (light, dark) = if palette.text.luminance() > palette.surface.luminance() {
                    (palette.text, palette.surface)
                } else {
                    (palette.surface, palette.text)
                };
                if fill.contrast(light) >= MIN_ICON_CONTRAST {
                    light
                } else {
                    dark
                }
            }
        }
    }
}

impl Token {
    /// Every colour, each after the ones it's made from.
    pub const ALL: [Self; 22] = [
        Self::Surface,
        Self::Text,
        Self::Accent,
        Self::Success,
        Self::Warning,
        Self::Error,
        Self::MutedText,
        Self::Placeholder,
        Self::Border,
        Self::Field,
        Self::FieldError,
        Self::OnAccent,
        Self::OnSuccess,
        Self::OnWarning,
        Self::Avatar,
        Self::AvatarWarning,
        Self::AvatarError,
        Self::AvatarMissing,
        Self::Device,
        Self::RingTrack,
        Self::Dot,
        Self::DotHollow,
    ];

    /// The name in the configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Surface => "surface",
            Self::Text => "text",
            Self::Accent => "accent",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::MutedText => "muted-text",
            Self::Placeholder => "placeholder",
            Self::Border => "border",
            Self::Field => "field",
            Self::FieldError => "field-error",
            Self::OnAccent => "on-accent",
            Self::OnSuccess => "on-success",
            Self::OnWarning => "on-warning",
            Self::Avatar => "avatar",
            Self::AvatarWarning => "avatar-warning",
            Self::AvatarError => "avatar-error",
            Self::AvatarMissing => "avatar-missing",
            Self::Device => "device",
            Self::RingTrack => "ring-track",
            Self::Dot => "dot",
            Self::DotHollow => "dot-hollow",
        }
    }

    /// The colour called `name` in the configuration.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|token| token.name() == name)
    }

    /// How the colour is made when the configuration doesn't set it but
    /// changes what it's made from. The mixes are close to the design's
    /// values in both presets.
    #[must_use]
    pub fn rule(self) -> Rule {
        let tint = |towards, percent| Rule::Tint { towards, percent };
        match self {
            Self::Surface
            | Self::Text
            | Self::Accent
            | Self::Success
            | Self::Warning
            | Self::Error => Rule::Base,
            Self::MutedText => tint(Self::Text, 65),
            Self::Placeholder => tint(Self::Text, 63),
            Self::Border => tint(Self::Text, 11),
            Self::Field => tint(Self::Text, 6),
            Self::FieldError => tint(Self::Error, 9),
            Self::OnAccent => Rule::On(Self::Accent),
            Self::OnSuccess => Rule::On(Self::Success),
            Self::OnWarning => Rule::On(Self::Warning),
            Self::Avatar => tint(Self::Warning, 11),
            Self::AvatarWarning => tint(Self::Warning, 9),
            Self::AvatarError => Rule::Same(Self::FieldError),
            Self::AvatarMissing => tint(Self::Text, 30),
            Self::Device => tint(Self::Text, 7),
            Self::RingTrack => tint(Self::Text, 8),
            Self::Dot => Rule::Same(Self::Text),
            Self::DotHollow => tint(Self::Text, 41),
        }
    }
}

/// Light, dark, or whichever the desktop prefers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Appearance {
    /// Follow the desktop.
    #[default]
    System,
    /// Always the light colours.
    Light,
    /// Always the dark colours.
    Dark,
}

/// What the popup draws its window with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Renderer {
    /// The CPU alone: the popup loads no GPU driver.
    #[default]
    Cpu,
    /// The GPU the display server draws on, if the popup can tell which
    /// that is and can keep away from every other one; else the CPU.
    Gpu,
}

impl Renderer {
    /// The name in the configuration and in the popup's `--renderer`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
        }
    }

    /// The renderer called `name`.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        [Self::Cpu, Self::Gpu]
            .into_iter()
            .find(|renderer| renderer.name() == name)
    }
}

/// How the popup looks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Style {
    /// What the popup draws with. Not part of the message: the popup can't
    /// change it once it runs, so the agent starts it with `--renderer`.
    #[serde(skip)]
    pub renderer: Renderer,
    /// Light, dark or the desktop's choice.
    pub appearance: Appearance,
    /// The font family for text; `None` is the bundled Inter.
    pub font: Option<String>,
    /// The font family for commands and fingerprints; `None` is the bundled
    /// JetBrains Mono.
    pub monospace_font: Option<String>,
    /// OpenType features of `font`, e.g. `cv11` = 1.
    pub font_features: BTreeMap<String, u32>,
    /// OpenType features of `monospace_font`.
    pub monospace_font_features: BTreeMap<String, u32>,
    /// The size of the whole popup, in percent of the design's.
    pub scale_percent: u16,
    /// The light colours.
    pub light: Palette,
    /// The dark colours.
    pub dark: Palette,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            renderer: Renderer::Cpu,
            appearance: Appearance::System,
            font: None,
            monospace_font: None,
            font_features: BTreeMap::new(),
            monospace_font_features: BTreeMap::new(),
            scale_percent: 100,
            light: Palette::LIGHT,
            dark: Palette::DARK,
        }
    }
}

impl Style {
    /// The style a configuration's `[popup]` table describes, and a warning
    /// for each setting that was skipped because it can't be used.
    #[must_use]
    pub fn from_table(table: &toml::Table) -> (Self, Vec<String>) {
        let mut style = Self::default();
        let mut warnings = Vec::new();
        for (key, value) in table {
            let setting = format!("popup.{key}");
            let applied = match key.as_str() {
                "renderer" => parse_renderer(value).map(|renderer| style.renderer = renderer),
                "appearance" => parse_appearance(value).map(|appearance| {
                    style.appearance = appearance;
                }),
                "font" => parse_font(value).map(|font| style.font = Some(font)),
                "monospace-font" => parse_font(value).map(|font| style.monospace_font = Some(font)),
                "font-features" => parse_features(value, &setting, &mut warnings)
                    .map(|features| style.font_features = features),
                "monospace-font-features" => parse_features(value, &setting, &mut warnings)
                    .map(|features| style.monospace_font_features = features),
                "scale" => parse_scale(value).map(|scale| style.scale_percent = scale),
                "light" => parse_colors(value, &setting, &mut warnings)
                    .map(|overrides| style.light = Palette::resolve(&Palette::LIGHT, &overrides)),
                "dark" => parse_colors(value, &setting, &mut warnings)
                    .map(|overrides| style.dark = Palette::resolve(&Palette::DARK, &overrides)),
                _ => Err(
                    "no such setting (known: renderer, appearance, font, monospace-font, \
                          font-features, monospace-font-features, scale, light, dark)"
                        .to_owned(),
                ),
            };
            if let Err(problem) = applied {
                warnings.push(format!("{setting}: {problem}"));
            }
        }
        (style, warnings)
    }
}

fn parse_renderer(value: &toml::Value) -> Result<Renderer, String> {
    value
        .as_str()
        .and_then(Renderer::named)
        .ok_or_else(|| format!("{} isn't \"cpu\" or \"gpu\"", shown(value)))
}

fn parse_appearance(value: &toml::Value) -> Result<Appearance, String> {
    match value.as_str() {
        Some("system") => Ok(Appearance::System),
        Some("light") => Ok(Appearance::Light),
        Some("dark") => Ok(Appearance::Dark),
        _ => Err(format!(
            "{} isn't \"system\", \"light\" or \"dark\"",
            shown(value)
        )),
    }
}

fn parse_font(value: &toml::Value) -> Result<String, String> {
    let name = value
        .as_str()
        .ok_or_else(|| format!("{} isn't a font family name", shown(value)))?
        .trim();
    if name.is_empty() {
        return Err("the font family name is empty".to_owned());
    }
    if name.chars().count() > MAX_FONT_CHARS || name.chars().any(char::is_control) {
        return Err(format!(
            "{} isn't a font family name (at most {MAX_FONT_CHARS} printable characters)",
            shown(value)
        ));
    }
    Ok(name.to_owned())
}

/// A table of OpenType feature tags and values: `{ cv11 = 1, liga = false }`.
/// Malformed entries are skipped with a warning.
fn parse_features(
    value: &toml::Value,
    setting: &str,
    warnings: &mut Vec<String>,
) -> Result<BTreeMap<String, u32>, String> {
    let table = value.as_table().ok_or_else(|| {
        format!(
            "{} isn't a table of features like {{ cv11 = 1 }}",
            shown(value)
        )
    })?;
    let mut features = BTreeMap::new();
    for (tag, value) in table {
        let valid_tag = tag.len() == 4 && tag.bytes().all(|byte| byte.is_ascii_graphic());
        let number = match value {
            toml::Value::Boolean(on) => Some(u32::from(*on)),
            toml::Value::Integer(number) => u32::try_from(*number).ok(),
            _ => None,
        };
        match (valid_tag, number) {
            (true, Some(number)) => {
                features.insert(tag.clone(), number);
            }
            (false, _) => warnings.push(format!(
                "{setting}.{tag}: not an OpenType feature tag (four letters or digits, like cv11)"
            )),
            (true, None) => warnings.push(format!(
                "{setting}.{tag}: {} isn't true, false or a number of 0 or more",
                shown(value)
            )),
        }
    }
    Ok(features)
}

/// `1.25` or `1` to percent, within [`SCALE_PERCENT`].
fn parse_scale(value: &toml::Value) -> Result<u16, String> {
    let factor = match value {
        toml::Value::Float(factor) => Some(*factor),
        toml::Value::Integer(factor) => i32::try_from(*factor).ok().map(f64::from),
        _ => None,
    };
    let percent = factor.and_then(|factor| {
        SCALE_PERCENT
            .clone()
            .find(|percent| (f64::from(*percent) / 100. - factor).abs() < 0.005)
    });
    percent.ok_or_else(|| {
        format!(
            "{} isn't a size between {} and {} (1 is the design's)",
            shown(value),
            f64::from(*SCALE_PERCENT.start()) / 100.,
            f64::from(*SCALE_PERCENT.end()) / 100.
        )
    })
}

/// A table of colour names and colours. Unknown names and malformed colours
/// are skipped with a warning.
fn parse_colors(
    value: &toml::Value,
    setting: &str,
    warnings: &mut Vec<String>,
) -> Result<BTreeMap<Token, Color>, String> {
    let table = value.as_table().ok_or_else(|| {
        format!(
            "{} isn't a table of colours like {{ accent = \"#1c71d8\" }}",
            shown(value)
        )
    })?;
    let mut overrides = BTreeMap::new();
    for (name, value) in table {
        let Some(token) = Token::named(name) else {
            let known: Vec<&str> = Token::ALL.iter().map(|token| token.name()).collect();
            warnings.push(format!(
                "{setting}.{name}: no such colour (known: {})",
                known.join(", ")
            ));
            continue;
        };
        match value.as_str().and_then(Color::parse) {
            Some(color) => {
                overrides.insert(token, color);
            }
            None => warnings.push(format!(
                "{setting}.{name}: {} isn't a colour like \"#rrggbb\" (or #rgb, #rrggbbaa)",
                shown(value)
            )),
        }
    }
    Ok(overrides)
}

/// A configuration value in a warning. Strings are quoted and escaped:
/// they're shown as written, control characters included.
fn shown(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => format!("{text:?}"),
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Float(number) => number.to_string(),
        toml::Value::Boolean(on) => on.to_string(),
        toml::Value::Datetime(_) => "a date".to_owned(),
        toml::Value::Array(_) => "a list".to_owned(),
        toml::Value::Table(_) => "a table".to_owned(),
    }
}
