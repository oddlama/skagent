//! What the popup's window is drawn with: the CPU, or on request the GPU
//! the display server draws on. Never another GPU, and never its driver.
//!
//! GPUI renders through wgpu, which asks the Vulkan loader and EGL for
//! every device there is before it picks one. Asking loads every vendor's
//! driver into the process. On a laptop with two GPUs that wakes the one
//! that sleeps, for a window of a few hundred pixels: a second or two before
//! a prompt appears, and a PIN prompt at the mercy of that driver
//! (`docs/research/popup-rendering.md` has the day one took the popup down).
//!
//! The loaders take orders through their environment, read when they are
//! loaded. So the popup makes sure of its own environment first thing
//! ([`prepare`]), and starts itself again in the right one if it has to:
//!
//! - **Vulkan** finds Mesa's lavapipe, a CPU rasterizer, and with
//!   [`Renderer::Gpu`] the driver of the display server's GPU. The loader
//!   skips every other driver before it would load it. It looks among the
//!   drivers installed: a list of the session's own is taken away.
//! - **No Vulkan layer** is loaded, whatever the system or the session
//!   installed or asks for: overlays, capture, another vendor's device
//!   switching.
//! - **EGL** finds no vendor library, so wgpu has Vulkan alone.
//!
//! One order isn't in the environment: a settings file of the Vulkan
//! configurator that orders the devices makes the loader ignore the
//! selection of drivers. The popup can't help that; it warns if its window
//! is then drawn on a GPU ([`report`]).
//!
//! [`Renderer::Gpu`] falls back to the CPU wherever the popup can't be sure
//! to stay with that one GPU ([`choose`]), and by itself where the GPU's
//! driver doesn't take the window: GPUI tries lavapipe next. What the
//! window ends up drawn with is logged when it opens ([`report`]).

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use gpui::GpuSpecs;
pub use skagent_popup::style::Renderer;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry;
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_protocols::wp::linux_dmabuf::zv1::client::{
    zwp_linux_dmabuf_feedback_v1, zwp_linux_dmabuf_v1,
};

/// Set to the popup's process id when it starts itself again, which keeps
/// the id: a popup that finds its own there doesn't start a third time.
const STARTED_AGAIN: &str = "SKAGENT_PINENTRY_STARTED_AGAIN";

/// Mesa's lavapipe, by its manifest's file name: `lvp_icd.<architecture>.json`
/// everywhere.
const LAVAPIPE: &str = "lvp_icd.*";

/// The Vulkan drivers, by their manifests' file names, for the GPUs of
/// kernel drivers: Mesa's, and NVIDIA's own. A kernel driver that isn't
/// here has no GPU the popup would draw on.
const VULKAN_DRIVERS: [(&[&str], &[&str]); 8] = [
    (&["i915", "xe"], &["intel_icd.*", "intel_hasvk_icd.*"]),
    (&["amdgpu"], &["radeon_icd.*"]),
    (&["nouveau"], &["nouveau_icd.*"]),
    (&["nvidia"], &["nvidia_icd.*"]),
    (&["virtio_gpu"], &["virtio_icd.*"]),
    (&["panfrost", "panthor"], &["panfrost_icd.*"]),
    (&["v3d"], &["broadcom_icd.*"]),
    (&["asahi"], &["asahi_icd.*"]),
];

/// What the popup's window is drawn with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drawing {
    /// On the CPU, with Mesa's lavapipe.
    Cpu(Why),
    /// On the display server's GPU, the one of this kernel driver; on the
    /// CPU if its Vulkan driver doesn't take the window.
    Gpu(String),
}

/// Why the popup draws on the CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// It was told to, or not told otherwise.
    Asked,
    /// The display server didn't name the GPU it draws on (it isn't a
    /// Wayland compositor, or draws without one), or the device it named
    /// has no driver to be found.
    NoGpuNamed,
    /// The display server's GPU has this kernel driver, which the popup
    /// knows no Vulkan driver for.
    NoVulkanDriver(String),
    /// The Vulkan driver for this kernel driver would look at `count` GPUs,
    /// not at the display server's alone: it could wake another one.
    NotAlone {
        /// The kernel driver of the display server's GPU.
        driver: String,
        /// The GPUs its Vulkan driver serves here, as far as they can be
        /// seen.
        count: usize,
    },
}

impl fmt::Display for Why {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asked => formatter.write_str("as configured"),
            Self::NoGpuNamed => {
                formatter.write_str("the display server doesn't say which GPU it draws on")
            }
            Self::NoVulkanDriver(driver) => write!(
                formatter,
                "no Vulkan driver is known for the display server's GPU ({driver})"
            ),
            Self::NotAlone { driver, count } => write!(
                formatter,
                "the Vulkan driver for the display server's GPU ({driver}) serves {count} GPUs \
                 here, not that one alone"
            ),
        }
    }
}

/// The Vulkan drivers for the GPUs of the kernel driver `kernel_driver`.
fn vulkan_drivers(kernel_driver: &str) -> Option<&'static [&'static str]> {
    VULKAN_DRIVERS
        .iter()
        .find(|(kernel, _)| kernel.contains(&kernel_driver))
        .map(|(_, vulkan)| *vulkan)
}

/// What to draw with. `compositor`: the kernel driver of the GPU the
/// display server draws on, if it named one. `render_devices`: the kernel
/// driver of every device here that can render.
///
/// A GPU only if the popup can stay with that one: the Vulkan driver for it
/// is known, and serves no other device, which it would open as well.
#[must_use]
pub fn choose(renderer: Renderer, compositor: Option<&str>, render_devices: &[String]) -> Drawing {
    if renderer == Renderer::Cpu {
        return Drawing::Cpu(Why::Asked);
    }
    let Some(driver) = compositor else {
        return Drawing::Cpu(Why::NoGpuNamed);
    };
    let Some(vulkan) = vulkan_drivers(driver) else {
        return Drawing::Cpu(Why::NoVulkanDriver(driver.to_owned()));
    };
    let count = render_devices
        .iter()
        .filter(|other| vulkan_drivers(other) == Some(vulkan))
        .count();
    if count == 1 {
        Drawing::Gpu(driver.to_owned())
    } else {
        Drawing::Cpu(Why::NotAlone {
            driver: driver.to_owned(),
            count,
        })
    }
}

/// The variables the graphics loaders read, as the popup needs them to draw
/// with `drawing`: a value, or `None` for one that mustn't be set.
#[must_use]
pub fn environment(drawing: &Drawing) -> Vec<(&'static str, Option<String>)> {
    let drivers = match drawing {
        Drawing::Cpu(_) => LAVAPIPE.to_owned(),
        // Lavapipe too: what GPUI falls back to if the GPU's driver fails.
        Drawing::Gpu(driver) => vulkan_drivers(driver)
            .unwrap_or_default()
            .iter()
            .chain([&LAVAPIPE])
            .copied()
            .collect::<Vec<_>>()
            .join(","),
    };
    vec![
        // The Vulkan loader (1.3.234 or newer) loads only the drivers whose
        // manifest's file name matches ...
        ("VK_LOADER_DRIVERS_SELECT", Some(drivers)),
        // ... among the drivers installed. A session that names its drivers
        // itself, for games on one GPU, names no lavapipe: the selection
        // would leave nothing, and no window.
        ("VK_DRIVER_FILES", None),
        ("VK_ICD_FILENAMES", None),
        // No layer, implicit or asked for ...
        ("VK_LOADER_LAYERS_DISABLE", Some("~all~".to_owned())),
        // ... and none exempt from that: not allowed, not enabled over the
        // disabling, and not added without a look at it.
        ("VK_LOADER_LAYERS_ALLOW", None),
        ("VK_LOADER_LAYERS_ENABLE", None),
        ("VK_INSTANCE_LAYERS", None),
        // libglvnd loads the vendor libraries listed here instead of the
        // ones it finds: none.
        ("__EGL_VENDOR_LIBRARY_FILENAMES", Some(String::new())),
        // An EGL that isn't libglvnd's is Mesa's own: on the CPU, so that
        // wgpu still prefers Vulkan to it.
        ("LIBGL_ALWAYS_SOFTWARE", Some("true".to_owned())),
    ]
}

/// What `variable` (a lookup in an environment) lacks of `wanted`: each
/// variable that differs, with what it has to be.
pub fn missing(
    variable: impl Fn(&str) -> Option<OsString>,
    wanted: Vec<(&'static str, Option<String>)>,
) -> Vec<(&'static str, Option<String>)> {
    wanted
        .into_iter()
        .filter(|(name, value)| variable(name).as_deref() != value.as_deref().map(OsStr::new))
        .collect()
}

/// Whether the process `pid` is a popup that started itself again:
/// `marker` is what its environment has for that, the id of the process
/// that did. Another process's id there was inherited and means nothing.
#[must_use]
pub fn started_again(marker: Option<&OsStr>, pid: u32) -> bool {
    marker.and_then(OsStr::to_str) == Some(pid.to_string().as_str())
}

/// Decides what to draw with ([`choose`]) and makes sure the graphics
/// loaders will find the environment for it ([`environment`]). If this
/// process's differs, the process is replaced by the same program with the
/// same arguments in the right one, and this doesn't return; there it
/// decides the same again and goes on. It starts again once: a popup that
/// was started again and still finds another environment than it decides
/// on gives up. To be called first: before anything is loaded that reads
/// the variables, and before the process holds anything.
///
/// # Errors
///
/// Returns an error if the program can't be found or started again, or if
/// starting it again didn't settle its environment.
pub fn prepare(renderer: Renderer) -> Result<Drawing> {
    let drawing = match renderer {
        Renderer::Cpu => choose(renderer, None, &[]),
        Renderer::Gpu => {
            let compositor = compositor_device().and_then(kernel_driver);
            choose(renderer, compositor.as_deref(), &render_devices())
        }
    };
    let changes = missing(|name| std::env::var_os(name), environment(&drawing));
    if changes.is_empty() {
        return Ok(drawing);
    }
    let pid = std::process::id();
    if started_again(std::env::var_os(STARTED_AGAIN).as_deref(), pid) {
        let names: Vec<_> = changes.iter().map(|(name, _)| *name).collect();
        bail!(
            "the graphics loaders' environment isn't the one to draw with ({drawing:?}), though \
             the popup started itself again for it: {} differ",
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

/// Logs what the popup's window is drawn with, next to what was decided.
/// Worth a warning: a GPU where the CPU was decided on (then a loader
/// didn't take the environment, and loaded the drivers the popup is meant
/// to stay away from), and the CPU where the configuration asks for the
/// GPU, with the reason. This sees what draws the window, not what else a
/// loader loaded.
pub fn report(drawing: &Drawing, specs: Option<&GpuSpecs>) {
    let Some(specs) = specs else {
        tracing::warn!("can't tell what the popup is drawn with");
        return;
    };
    let (renderer, driver) = (&specs.device_name, &specs.driver_name);
    match (drawing, specs.is_software_emulated) {
        (Drawing::Cpu(Why::Asked), true) => {
            tracing::debug!(%renderer, %driver, "drawing on the CPU");
        }
        (Drawing::Cpu(why), true) => {
            tracing::warn!(%renderer, %driver, %why, "drawing on the CPU, not on a GPU");
        }
        (Drawing::Cpu(_), false) => tracing::warn!(
            %renderer,
            %driver,
            "drawing on a GPU: the graphics loaders didn't keep to the software renderer (the \
             Vulkan loader does from 1.3.234 on, unless a settings file of the Vulkan \
             configurator orders its devices)"
        ),
        (Drawing::Gpu(_), false) => {
            tracing::debug!(%renderer, %driver, "drawing on the display server's GPU");
        }
        (Drawing::Gpu(kernel_driver), true) => tracing::warn!(
            %renderer,
            %driver,
            %kernel_driver,
            "drawing on the CPU: the Vulkan driver of the display server's GPU didn't take the \
             window, or isn't installed"
        ),
    }
}

/// The major and minor number of the device `device` (a `dev_t` as glibc
/// packs it).
#[must_use]
pub const fn device_numbers(device: u64) -> (u64, u64) {
    let major = (device.wrapping_shr(32) & 0xffff_f000) | (device.wrapping_shr(8) & 0x0fff);
    let minor = (device.wrapping_shr(12) & 0xffff_ff00) | (device & 0x00ff);
    (major, minor)
}

/// The kernel driver of the character device `device`, from sysfs.
fn kernel_driver(device: u64) -> Option<String> {
    let (major, minor) = device_numbers(device);
    driver_of(Path::new(&format!("/sys/dev/char/{major}:{minor}/device")))
}

/// The kernel driver of every device that can render: the DRM render nodes.
fn render_devices() -> Vec<String> {
    let Ok(nodes) = std::fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    nodes
        .filter_map(Result::ok)
        .filter(|node| node.file_name().to_string_lossy().starts_with("renderD"))
        .filter_map(|node| driver_of(&node.path().join("device")))
        .collect()
}

/// The name of the driver bound to the sysfs device `device`.
fn driver_of(device: &Path) -> Option<String> {
    let driver = std::fs::read_link(device.join("driver")).ok()?;
    Some(driver.file_name()?.to_str()?.to_owned())
}

/// The device the Wayland compositor draws on, as it tells every client
/// (the main device of its dmabuf feedback). `None` without a compositor, or
/// with one that doesn't say.
fn compositor_device() -> Option<u64> {
    let connection = Connection::connect_to_env().ok()?;
    let (globals, mut queue) = registry_queue_init::<Probe>(&connection).ok()?;
    let handle = queue.handle();
    // Version 4 has the feedback.
    let dmabuf: zwp_linux_dmabuf_v1::ZwpLinuxDmabufV1 = globals.bind(&handle, 4..=4, ()).ok()?;
    let feedback = dmabuf.get_default_feedback(&handle, ());
    let mut probe = Probe { device: None };
    queue.roundtrip(&mut probe).ok()?;
    feedback.destroy();
    dmabuf.destroy();
    probe.device
}

/// What [`compositor_device`] learns from the compositor.
struct Probe {
    device: Option<u64>,
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Probe {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<zwp_linux_dmabuf_v1::ZwpLinuxDmabufV1, ()> for Probe {
    fn event(
        _: &mut Self,
        _: &zwp_linux_dmabuf_v1::ZwpLinuxDmabufV1,
        _: zwp_linux_dmabuf_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<zwp_linux_dmabuf_feedback_v1::ZwpLinuxDmabufFeedbackV1, ()> for Probe {
    fn event(
        probe: &mut Self,
        _: &zwp_linux_dmabuf_feedback_v1::ZwpLinuxDmabufFeedbackV1,
        event: zwp_linux_dmabuf_feedback_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // A `dev_t`, as the compositor's C library has it.
        if let zwp_linux_dmabuf_feedback_v1::Event::MainDevice { device } = event
            && let Ok(bytes) = <[u8; 8]>::try_from(device.as_slice())
        {
            probe.device = Some(u64::from_ne_bytes(bytes));
        }
    }
}
