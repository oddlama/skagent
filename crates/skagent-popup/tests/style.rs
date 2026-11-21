//! The popup's style: colours, their presets and mixes, and the `[popup]`
//! table of the agent's configuration.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};
use skagent_popup::style::{Appearance, Color, Palette, Renderer, Rule, Style, Token};
use skagent_popup::{Message, decode_message, encode_message};

fn table(text: &str) -> Result<toml::Table> {
    let config: toml::Table = toml::from_str(text).context("parsing the example")?;
    match config.get("popup") {
        Some(toml::Value::Table(popup)) => Ok(popup.clone()),
        _ => Ok(toml::Table::new()),
    }
}

fn channel_distance(one: Color, two: Color) -> u8 {
    [
        one.red.abs_diff(two.red),
        one.green.abs_diff(two.green),
        one.blue.abs_diff(two.blue),
        one.alpha.abs_diff(two.alpha),
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}

#[test]
fn colours_parse_in_the_three_css_forms_and_print_back() -> Result<()> {
    let accent = Color::rgb(0x001c_71d8);
    ensure!(Color::parse("#1c71d8") == Some(accent));
    ensure!(Color::parse("#1C71D8") == Some(accent));
    ensure!(Color::parse("#fff") == Some(Color::rgb(0x00ff_ffff)));
    let translucent = Color::parse("#1c71d880").context("#rrggbbaa")?;
    ensure!(translucent.alpha == 0x80);
    ensure!(accent.to_string() == "#1c71d8");
    ensure!(translucent.to_string() == "#1c71d880");
    for broken in [
        "",
        "#",
        "1c71d8",
        "#1c71d",
        "#1c71d8f",
        "#ggg",
        "#１２３",
        "#1c71d8 ",
    ] {
        ensure!(Color::parse(broken).is_none(), "{broken:?} parsed");
    }
    Ok(())
}

#[test]
fn contrast_follows_wcag() {
    let (black, white) = (Color::rgb(0), Color::rgb(0x00ff_ffff));
    assert!((black.contrast(white) - 21.).abs() < 0.01);
    assert!((white.contrast(white) - 1.).abs() < 0.001);
    assert_eq!(black.mix(white, 50), Color::rgb(0x0080_8080));
    assert_eq!(black.mix(white, 0), black);
    assert_eq!(black.mix(white, 100), white);
}

#[test]
fn every_colour_has_a_unique_name_and_comes_after_what_it_is_made_from() -> Result<()> {
    let mut seen = Vec::new();
    for token in Token::ALL {
        ensure!(
            Token::named(token.name()) == Some(token),
            "{}",
            token.name()
        );
        for input in token.rule().inputs() {
            ensure!(
                seen.contains(&input),
                "{} before {}",
                token.name(),
                input.name()
            );
        }
        ensure!(!seen.contains(&token), "{} twice", token.name());
        seen.push(token);
    }
    Ok(())
}

#[test]
fn the_mixes_come_close_to_the_design() -> Result<()> {
    for (mode, preset) in [("light", Palette::LIGHT), ("dark", Palette::DARK)] {
        for token in Token::ALL {
            let rule = token.rule();
            if rule == Rule::Base {
                continue;
            }
            let (designed, mixed) = (preset.get(token), rule.apply(&preset));
            let distance = channel_distance(designed, mixed);
            ensure!(
                distance <= 13,
                "{mode} {}: designed {designed}, mixed {mixed}",
                token.name()
            );
        }
    }
    Ok(())
}

#[test]
fn without_settings_the_popup_looks_as_designed() -> Result<()> {
    let (style, warnings) = Style::from_table(&toml::Table::new());
    ensure!(warnings.is_empty(), "{warnings:?}");
    ensure!(style == Style::default());
    ensure!(style.light == Palette::LIGHT && style.dark == Palette::DARK);
    ensure!(style.scale_percent == 100 && style.appearance == Appearance::System);
    // And is drawn on a GPU if one takes it, else on the CPU.
    ensure!(style.renderer == Renderer::Auto);
    for preset in [Palette::LIGHT, Palette::DARK] {
        ensure!(Palette::resolve(&preset, &BTreeMap::new()) == preset);
        // Setting a colour to the preset's own changes nothing else.
        let same = BTreeMap::from([(Token::Surface, preset.surface)]);
        ensure!(Palette::resolve(&preset, &same) == preset);
    }
    Ok(())
}

#[test]
fn a_new_accent_brings_its_own_ink_and_leaves_the_rest() -> Result<()> {
    // A pale accent needs dark icons on it.
    let pale = Color::rgb(0x00a0_c4ff);
    let palette = Palette::resolve(&Palette::LIGHT, &BTreeMap::from([(Token::Accent, pale)]));
    ensure!(palette.accent == pale);
    ensure!(palette.on_accent == Palette::LIGHT.text);
    for token in Token::ALL {
        if !matches!(token, Token::Accent | Token::OnAccent) {
            ensure!(
                palette.get(token) == Palette::LIGHT.get(token),
                "{}",
                token.name()
            );
        }
    }
    Ok(())
}

#[test]
fn a_new_surface_remixes_what_is_made_from_it_unless_set() -> Result<()> {
    let nord = Color::rgb(0x002e_3440);
    let field = Color::rgb(0x003b_4252);
    let palette = Palette::resolve(
        &Palette::DARK,
        &BTreeMap::from([(Token::Surface, nord), (Token::Field, field)]),
    );
    ensure!(palette.surface == nord);
    ensure!(palette.field == field, "set explicitly");
    ensure!(palette.border == nord.mix(Palette::DARK.text, 11));
    ensure!(palette.avatar == nord.mix(Palette::DARK.warning, 11));
    ensure!(palette.avatar_error == palette.field_error);
    // Not made from the surface.
    ensure!(palette.accent == Palette::DARK.accent && palette.dot == Palette::DARK.dot);
    Ok(())
}

#[test]
fn a_whole_configuration_applies() -> Result<()> {
    let (style, warnings) = Style::from_table(&table(
        r##"
        [popup]
        appearance = "dark"
        font = "IBM Plex Sans"
        monospace-font = " Iosevka "
        font-features = { cv11 = 1, liga = false, ss01 = true }
        monospace-font-features = { zero = 1 }
        scale = 1.25

        [popup.light]
        accent = "#2f6feb"

        [popup.dark]
        surface = "#2e3440"
        text = "#eceff4"
        "##,
    )?);
    ensure!(warnings.is_empty(), "{warnings:?}");
    ensure!(style.appearance == Appearance::Dark);
    ensure!(style.font.as_deref() == Some("IBM Plex Sans"));
    ensure!(style.monospace_font.as_deref() == Some("Iosevka"));
    ensure!(
        style.font_features
            == BTreeMap::from([
                ("cv11".to_owned(), 1),
                ("liga".to_owned(), 0),
                ("ss01".to_owned(), 1)
            ])
    );
    ensure!(style.monospace_font_features == BTreeMap::from([("zero".to_owned(), 1)]));
    ensure!(style.scale_percent == 125);
    ensure!(style.light.accent == Color::rgb(0x002f_6feb));
    ensure!(style.dark.surface == Color::rgb(0x002e_3440));
    ensure!(style.dark.text == Color::rgb(0x00ec_eff4));
    ensure!(style.dark.dot == style.dark.text);
    Ok(())
}

#[test]
fn unusable_settings_are_skipped_with_a_warning_and_the_rest_applies() -> Result<()> {
    let (style, warnings) = Style::from_table(&table(
        r##"
        [popup]
        renderer = "fast"
        appearance = "dim"
        font = ""
        monospace-font = "Mono\u0007"
        font-features = { cv11 = 1, toolong = 1, liga = -1 }
        scale = 9
        colour = "blue"

        [popup.light]
        acent = "#2f6feb"
        accent = "2f6feb"
        surface = "#fafafa"
        "##,
    )?);
    let expected = [
        "popup.renderer: \"fast\" isn't \"auto\", \"gpu\" or \"cpu\"",
        "popup.appearance: \"dim\" isn't",
        "popup.font: the font family name is empty",
        "popup.monospace-font: \"Mono\\u{7}\" isn't a font family name",
        "popup.font-features.toolong: not an OpenType feature tag",
        "popup.font-features.liga: -1 isn't",
        "popup.scale: 9 isn't a size between 0.5 and 3",
        "popup.colour: no such setting",
        "popup.light.acent: no such colour (known: surface, text,",
        "popup.light.accent: \"2f6feb\" isn't a colour",
    ];
    for start in expected {
        ensure!(
            warnings.iter().any(|warning| warning.starts_with(start)),
            "no warning starting {start:?} in {warnings:#?}"
        );
    }
    ensure!(warnings.len() == expected.len(), "{warnings:#?}");
    ensure!(style.appearance == Appearance::System && style.font.is_none());
    ensure!(style.renderer == Renderer::Auto);
    ensure!(style.monospace_font.is_none() && style.scale_percent == 100);
    ensure!(style.font_features == BTreeMap::from([("cv11".to_owned(), 1)]));
    ensure!(style.light.accent == Palette::LIGHT.accent);
    ensure!(style.light.surface == Color::rgb(0x00fa_fafa));
    Ok(())
}

/// What the popup draws with is the configuration's to say, and the popup's
/// to know before it starts: the agent passes it as an argument, and the
/// style message, which comes when the popup runs, doesn't carry it.
#[test]
fn the_renderer_is_read_from_the_table_and_not_sent_with_the_style() -> Result<()> {
    let (style, warnings) = Style::from_table(&table("[popup]\nrenderer = \"gpu\"")?);
    ensure!(warnings.is_empty(), "{warnings:?}");
    ensure!(style.renderer == Renderer::Gpu);
    for (renderer, name) in [
        (Renderer::Auto, "auto"),
        (Renderer::Gpu, "gpu"),
        (Renderer::Cpu, "cpu"),
    ] {
        ensure!(renderer.name() == name && Renderer::named(name) == Some(renderer));
    }
    ensure!(Renderer::named("GPU").is_none() && Renderer::named("").is_none());

    let line = encode_message(&Message::Style {
        style: Box::new(style),
    })?;
    let text = std::str::from_utf8(&line)?;
    ensure!(
        !text.contains("renderer") && !text.contains("gpu"),
        "{text}"
    );
    let Message::Style { style: received } = decode_message(text.trim_end())? else {
        anyhow::bail!("not a style message: {text}");
    };
    ensure!(received.renderer == Renderer::Auto);
    Ok(())
}

#[test]
fn scales_are_whole_percents_in_range() -> Result<()> {
    for (text, percent) in [
        ("1", 100),
        ("0.5", 50),
        ("3", 300),
        ("1.1", 110),
        ("1.234", 123),
    ] {
        let (style, warnings) = Style::from_table(&table(&format!("[popup]\nscale = {text}"))?);
        ensure!(
            style.scale_percent == percent && warnings.is_empty(),
            "{text}"
        );
    }
    for text in ["0.4", "3.01", "-1", "\"big\"", "nan", "inf"] {
        let (style, warnings) = Style::from_table(&table(&format!("[popup]\nscale = {text}"))?);
        ensure!(
            style.scale_percent == 100 && warnings.len() == 1,
            "{text}: {warnings:?}"
        );
    }
    Ok(())
}

#[test]
fn the_style_travels_to_the_popup_as_one_line() -> Result<()> {
    let (style, _) = Style::from_table(&table(
        "[popup]\nscale = 1.5\nfont = \"Inter Display\"\n[popup.dark]\naccent = \"#88c0d0\"\n",
    )?);
    let message = Message::Style {
        style: Box::new(style),
    };
    let line = encode_message(&message)?;
    let text = std::str::from_utf8(&line).context("UTF-8")?;
    ensure!(text.ends_with('\n') && text.matches('\n').count() == 1);
    ensure!(text.contains(r##""accent":"#88c0d0""##), "{text}");
    ensure!(decode_message(text.trim_end())? == message);
    Ok(())
}
