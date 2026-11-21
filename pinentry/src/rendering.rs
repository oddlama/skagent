//! What the popup's window is drawn with: a GPU if one takes it and else the
//! CPU, a GPU or nothing, or the CPU alone ([`Renderer`]).
//!
//! GPUI renders through wgpu, which asks the Vulkan loader and EGL for
//! every device there is and takes the first that can draw the window: the
//! GPU the display server draws on, then a discrete GPU, an integrated one,
//! and last a software renderer. That is what any program with a window
//! does, and what [`Renderer::Auto`] leaves as it is. [`Renderer::Gpu`] is
//! the same, except that the popup doesn't show a window that ended up with
//! the software renderer.
//!
//! Asking for every device loads every vendor's driver into the process. On
//! a laptop with two GPUs that wakes the one that sleeps, for a window of a
//! few hundred pixels: a second or two before a prompt appears, and a PIN
//! prompt at the mercy of that driver (`docs/research/popup-rendering.md`
//! has the day one took the popup down). [`Renderer::Cpu`] is for whoever
//! would rather not: the popup draws with Mesa's lavapipe, a CPU
//! rasterizer, and loads no GPU driver.
//!
//! The loaders take orders through their environment, read when they are
//! loaded. So for the CPU the popup makes sure of its own environment first
//! thing ([`prepare`]), and starts itself again in the right one if it has
//! to ([`ON_THE_CPU`]):
//!
//! - **Vulkan** finds lavapipe alone. The loader skips every other driver
//!   before it would load it. It looks among the drivers installed: a list
//!   of the session's own is taken away.
//! - **No Vulkan layer** is loaded, whatever the system or the session
//!   installed or asks for: overlays, capture, another vendor's device
//!   switching.
//! - **EGL** finds no vendor library, so wgpu has Vulkan alone.
//!
//! One order isn't in the environment: a settings file of the Vulkan
//! configurator that orders the devices makes the loader ignore the
//! selection of drivers. The popup can't help that, and an old loader
//! doesn't know the selection. So the popup looks at what its window is
//! drawn with once it is open ([`check`]), and doesn't show one that a GPU
//! draws where the CPU was asked for.

use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use gpui::GpuSpecs;
pub use skagent_popup::style::Renderer;

/// Set to the popup's process id when it starts itself again, which keeps
/// the id: a popup that finds its own there doesn't start a third time.
const STARTED_AGAIN: &str = "SKAGENT_PINENTRY_STARTED_AGAIN";

/// The variables the graphics loaders read, as the popup needs them to draw
/// on the CPU alone: a value, or `None` for one that mustn't be set.
pub const ON_THE_CPU: [(&str, Option<&str>); 9] = [
    // The Vulkan loader (1.3.234 or newer) loads only the drivers whose
    // manifest's file name matches: Mesa's lavapipe, `lvp_icd.<arch>.json`
    // everywhere ...
    ("VK_LOADER_DRIVERS_SELECT", Some("lvp_icd.*")),
    // ... among the drivers installed. A session that names its drivers
    // itself, for games on one GPU, names no lavapipe: the selection would
    // leave nothing, and no window.
    ("VK_DRIVER_FILES", None),
    ("VK_ICD_FILENAMES", None),
    // No layer, implicit or asked for ...
    ("VK_LOADER_LAYERS_DISABLE", Some("~all~")),
    // ... and none exempt from that: not allowed, not enabled over the
    // disabling, and not added without a look at it.
    ("VK_LOADER_LAYERS_ALLOW", None),
    ("VK_LOADER_LAYERS_ENABLE", None),
    ("VK_INSTANCE_LAYERS", None),
    // libglvnd loads the vendor libraries listed here instead of the ones
    // it finds: none.
    ("__EGL_VENDOR_LIBRARY_FILENAMES", Some("")),
    // An EGL that isn't libglvnd's is Mesa's own: on the CPU, so that wgpu
    // still prefers Vulkan to it.
    ("LIBGL_ALWAYS_SOFTWARE", Some("true")),
];

/// What `variable` (a lookup in an environment) lacks of `wanted`: each
/// variable that differs, with what it has to be.
pub fn missing(
    variable: impl Fn(&str) -> Option<OsString>,
    wanted: &[(&'static str, Option<&'static str>)],
) -> Vec<(&'static str, Option<&'static str>)> {
    wanted
        .iter()
        .filter(|(name, value)| variable(name).as_deref() != value.map(OsStr::new))
        .copied()
        .collect()
}

/// Whether the process `pid` is a popup that started itself again:
/// `marker` is what its environment has for that, the id of the process
/// that did. Another process's id there was inherited and means nothing.
#[must_use]
pub fn started_again(marker: Option<&OsStr>, pid: u32) -> bool {
    marker.and_then(OsStr::to_str) == Some(pid.to_string().as_str())
}

/// For [`Renderer::Cpu`], makes sure the graphics loaders will find the
/// environment to draw on the CPU alone ([`ON_THE_CPU`]). If this process's
/// differs, the process is replaced by the same program with the same
/// arguments in the right one, and this doesn't return; there it finds
/// nothing to change and goes on. It starts again once: a popup that was
/// started again and still finds another environment gives up. For the
/// other renderers the environment is left as it is. To be called first:
/// before anything is loaded that reads the variables, and before the
/// process holds anything.
///
/// # Errors
///
/// Returns an error if the program can't be found or started again, or if
/// starting it again didn't settle its environment.
pub fn prepare(renderer: Renderer) -> Result<()> {
    if renderer != Renderer::Cpu {
        return Ok(());
    }
    let changes = missing(|name| std::env::var_os(name), &ON_THE_CPU);
    if changes.is_empty() {
        return Ok(());
    }
    let pid = std::process::id();
    if started_again(std::env::var_os(STARTED_AGAIN).as_deref(), pid) {
        let names: Vec<_> = changes.iter().map(|(name, _)| *name).collect();
        bail!(
            "the graphics loaders' environment isn't the one to draw on the CPU with, though the \
             popup started itself again for it: {} differ",
            names.join(", ")
        );
    }
    let program = std::env::current_exe().context("finding the popup's own executable")?;
    let mut arguments = std::env::args_os();
    let mut again = Command::new(&program);
    if let Some(name) = arguments.next() {
        again.arg0(name);
    }
    again.args(arguments);
    again.env(STARTED_AGAIN, pid.to_string());
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

/// What became of the renderer the popup was asked for, once its window is
/// open and something draws it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Drawn as asked: on a GPU, or on the CPU for [`Renderer::Cpu`].
    AsAsked,
    /// [`Renderer::Auto`] on the CPU: no GPU took the window.
    NoGpu,
    /// [`Renderer::Gpu`], and only a software renderer took the window. It
    /// isn't shown.
    OnlyTheCpu,
    /// [`Renderer::Cpu`], and a GPU draws the window: a loader didn't keep
    /// to lavapipe, and loaded the drivers the popup was to stay away from.
    /// It isn't shown.
    NotTheCpu,
}

/// What became of `renderer`, for a window drawn by a software renderer
/// (`software`) or by a GPU.
#[must_use]
pub const fn outcome(renderer: Renderer, software: bool) -> Outcome {
    match (renderer, software) {
        (Renderer::Auto | Renderer::Gpu, false) | (Renderer::Cpu, true) => Outcome::AsAsked,
        (Renderer::Auto, true) => Outcome::NoGpu,
        (Renderer::Gpu, true) => Outcome::OnlyTheCpu,
        (Renderer::Cpu, false) => Outcome::NotTheCpu,
    }
}

/// Logs what the popup's window is drawn with (`specs`), and holds it
/// against what was asked for.
///
/// # Errors
///
/// Returns an error if the window isn't to be shown: a software renderer
/// draws it for [`Renderer::Gpu`], a GPU for [`Renderer::Cpu`], or there is
/// no telling for either.
pub fn check(renderer: Renderer, specs: Option<&GpuSpecs>) -> Result<()> {
    let asked = renderer.name();
    let Some(specs) = specs else {
        if renderer == Renderer::Auto {
            tracing::warn!("can't tell what the popup is drawn with");
            return Ok(());
        }
        bail!("can't tell what the window is drawn with, and renderer = \"{asked}\" has to know");
    };
    let (device, driver) = (&specs.device_name, &specs.driver_name);
    match outcome(renderer, specs.is_software_emulated) {
        Outcome::AsAsked if specs.is_software_emulated => {
            tracing::debug!(%device, %driver, asked, "drawing on the CPU");
            Ok(())
        }
        Outcome::AsAsked => {
            tracing::debug!(%device, %driver, asked, "drawing on a GPU");
            Ok(())
        }
        Outcome::NoGpu => {
            tracing::info!(%device, %driver, asked, "drawing on the CPU: no GPU took the window");
            Ok(())
        }
        Outcome::OnlyTheCpu => bail!(
            "renderer = \"gpu\", and only the CPU would draw the window ({device}): no GPU here \
             has a driver that takes it. With renderer = \"auto\" the popup draws on the CPU then"
        ),
        Outcome::NotTheCpu => bail!(
            "renderer = \"cpu\", and a GPU would draw the window ({device}): the graphics loaders \
             didn't keep to Mesa's lavapipe. The Vulkan loader does from 1.3.234 on, unless a \
             settings file of the Vulkan configurator orders its devices"
        ),
    }
}

/// What the popup needs to open its window with `renderer`, for the log
/// when it can't: the one thing a desktop may lack.
#[must_use]
pub const fn needs(renderer: Renderer) -> &'static str {
    match renderer {
        Renderer::Auto => {
            "the popup needs a GPU with a Vulkan or OpenGL driver, or Mesa's software renderer"
        }
        Renderer::Gpu => "renderer = \"gpu\" needs a GPU with a Vulkan or OpenGL driver",
        Renderer::Cpu => {
            "renderer = \"cpu\" draws with Mesa's software Vulkan driver, lavapipe, which has to \
             be installed"
        }
    }
}
