//! The icons, embedded. GPUI draws an SVG as a mask in one colour, so the
//! strokes' own colour doesn't matter.

use std::borrow::Cow;

use anyhow::Result;
use gpui::{AssetSource, SharedString};

/// The icons of design B+, by asset path.
const ICONS: [(&str, &str); 13] = [
    (
        "icons/close.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>"##,
    ),
    (
        "icons/submit.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>"##,
    ),
    (
        "icons/retry.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.3-5.6"/><path d="M20 4v5h-5"/></svg>"##,
    ),
    (
        "icons/done.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5 9-10"/></svg>"##,
    ),
    (
        "icons/failed.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="3" stroke-linecap="round"><path d="M12 6v8"/><path d="M12 18.5h.01"/></svg>"##,
    ),
    (
        "icons/lock.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>"##,
    ),
    (
        "icons/pencil.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L19 9l-4-4L4 16z"/></svg>"##,
    ),
    (
        "icons/plug.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3v5M15 3v5"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v4"/></svg>"##,
    ),
    (
        "icons/replug.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.3-5.6"/><path d="M20 4v5h-5"/></svg>"##,
    ),
    (
        "icons/clock.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg>"##,
    ),
    (
        "icons/swap.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4v16M3 16l4 4 4-4"/><path d="M17 20V4M13 8l4-4 4 4"/></svg>"##,
    ),
    (
        "icons/device-frame.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 30" fill="none" stroke="#000"><rect x="1" y="1" width="18" height="28" rx="5" stroke-width="1.8"/><circle cx="10" cy="6" r="1.4" stroke-width="1.4"/></svg>"##,
    ),
    (
        "icons/device-outline.svg",
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 30" fill="none" stroke="#000"><rect x="1" y="1" width="18" height="28" rx="5" stroke-width="2"/></svg>"##,
    ),
];

/// The embedded icons.
#[derive(Debug, Clone, Copy, Default)]
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        Ok(ICONS
            .iter()
            .find(|(name, _)| *name == path)
            .map(|(_, svg)| Cow::Borrowed(svg.as_bytes())))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(ICONS
            .iter()
            .filter(|(name, _)| name.starts_with(path))
            .map(|(name, _)| SharedString::from(*name))
            .collect())
    }
}
