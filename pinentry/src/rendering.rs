//! The popup draws on the CPU and loads no GPU driver.
//!
//! GPUI renders through wgpu, which asks the Vulkan loader and EGL for
//! every device there is before it picks one. Asking loads every vendor's
//! driver into the process. On a laptop with two GPUs that wakes the one
//! that sleeps, for a window of a few hundred pixels: a second or two before
//! a prompt appears, and a PIN prompt at the mercy of that driver
//! (`docs/research/popup-rendering.md` has the day one took the popup down).
//!
//! The loaders take orders through their environment alone, read when they
//! are loaded. So the popup makes sure of its own environment first thing,
//! and starts itself again in the right one if it has to:
//!
//! - **Vulkan** finds Mesa's lavapipe, a CPU rasterizer, and nothing else:
//!   the loader skips every other driver before it would load it.
//! - **No Vulkan layer** is loaded, whatever the system or the session
//!   installed: overlays, capture, another vendor's device switching.
//! - **EGL** finds no vendor library, so wgpu has Vulkan alone.
//!
//! What the popup draws with is logged when its window opens
//! ([`report`]), with a warning if it is a GPU after all.

use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use gpui::GpuSpecs;

/// The variables the graphics loaders read, as the popup needs them: a
/// value, or `None` for one that mustn't be set.
pub const ENVIRONMENT: [(&str, Option<&str>); 5] = [
    // The Vulkan loader (1.3.234 or newer) loads only the drivers whose
    // manifest's file name matches: Mesa installs lavapipe's as
    // `lvp_icd.<architecture>.json` everywhere.
    ("VK_LOADER_DRIVERS_SELECT", Some("lvp_icd.*")),
    // No layer, implicit or asked for ...
    ("VK_LOADER_LAYERS_DISABLE", Some("~all~")),
    // ... and none exempt from that.
    ("VK_LOADER_LAYERS_ALLOW", None),
    // libglvnd loads the vendor libraries listed here instead of the ones
    // it finds: none.
    ("__EGL_VENDOR_LIBRARY_FILENAMES", Some("")),
    // An EGL that isn't libglvnd's is Mesa's own: on the CPU too, so that
    // wgpu still prefers lavapipe to it.
    ("LIBGL_ALWAYS_SOFTWARE", Some("true")),
];

/// What `variable` (a lookup in an environment) lacks of [`ENVIRONMENT`]:
/// each variable that differs, with what it has to be.
pub fn missing(
    variable: impl Fn(&str) -> Option<OsString>,
) -> Vec<(&'static str, Option<&'static str>)> {
    ENVIRONMENT
        .into_iter()
        .filter(|(name, wanted)| variable(name).as_deref() != wanted.map(OsStr::new))
        .collect()
}

/// Makes sure the graphics loaders will find [`ENVIRONMENT`]. If this
/// process's environment differs, the process is replaced by the same
/// program with the same arguments in the right one, and this doesn't
/// return. To be called first: before anything is loaded that reads the
/// variables, and before the process holds anything.
///
/// # Errors
///
/// Returns an error if the program can't be found or started again.
pub fn on_the_cpu() -> Result<()> {
    let changes = missing(|name| std::env::var_os(name));
    if changes.is_empty() {
        return Ok(());
    }
    let program = std::env::current_exe().context("finding the popup's own executable")?;
    let mut arguments = std::env::args_os();
    let mut again = Command::new(&program);
    if let Some(name) = arguments.next() {
        again.arg0(name);
    }
    again.args(arguments);
    for (name, wanted) in changes {
        match wanted {
            Some(value) => again.env(name, value),
            None => again.env_remove(name),
        };
    }
    // Only returns if it failed.
    let error = again.exec();
    bail!(
        "starting {} again with the graphics loaders' environment: {error}",
        program.display()
    )
}

/// Logs what the popup's window is drawn with. A GPU is worth a warning:
/// then a loader didn't take [`ENVIRONMENT`], and loaded the drivers the
/// popup is meant to stay away from.
pub fn report(specs: Option<&GpuSpecs>) {
    match specs {
        Some(specs) if specs.is_software_emulated => tracing::debug!(
            renderer = %specs.device_name,
            driver = %specs.driver_name,
            "drawing on the CPU"
        ),
        Some(specs) => tracing::warn!(
            renderer = %specs.device_name,
            driver = %specs.driver_name,
            "drawing on a GPU: the graphics loaders didn't keep to the software renderer \
             (the Vulkan loader does from 1.3.234 on)"
        ),
        None => tracing::warn!("can't tell what the popup is drawn with"),
    }
}
