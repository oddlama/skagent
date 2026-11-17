//! The design's fonts, bundled by the Nix package so the popup looks as
//! designed whether or not Inter is installed. Emoji use the system's colour
//! emoji font, as the design says.

use std::borrow::Cow;

use gpui::App;

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
