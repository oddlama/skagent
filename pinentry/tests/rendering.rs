//! What the popup draws with, and the environment it gives the graphics
//! loaders for it.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use skagent_pinentry::rendering::{
    Compositor, Drawing, Renderer, Why, choose, device_numbers, environment, kernel_driver,
    missing, render_devices, started_again,
};

type Environment = HashMap<&'static str, OsString>;

fn lacking(
    environment_now: &Environment,
    drawing: &Drawing,
) -> Vec<(&'static str, Option<String>)> {
    missing(
        |name| environment_now.get(name).cloned(),
        environment(drawing),
    )
}

/// `environment_now` after what [`missing`] asks for.
fn corrected(mut environment_now: Environment, drawing: &Drawing) -> Environment {
    for (name, wanted) in lacking(&environment_now, drawing) {
        match wanted {
            Some(value) => environment_now.insert(name, OsString::from(value)),
            None => environment_now.remove(name),
        };
    }
    environment_now
}

/// Devices that can render, by their kernel drivers.
fn drivers(names: &[&str]) -> Vec<Option<String>> {
    names.iter().map(|name| Some((*name).to_owned())).collect()
}

/// The Vulkan drivers `drawing` lets the loader load.
fn selected(drawing: &Drawing) -> Result<String> {
    environment(drawing)
        .into_iter()
        .find(|(name, _)| *name == "VK_LOADER_DRIVERS_SELECT")
        .and_then(|(_, value)| value)
        .context("no driver selection")
}

fn on_the_cpu() -> Drawing {
    Drawing::Cpu(Why::Asked)
}

/// A session set up for games on the other GPU, with a debugging layer
/// and an overlay forced on.
fn a_gaming_session() -> Environment {
    Environment::from([
        ("VK_LOADER_DRIVERS_SELECT", OsString::from("nvidia*")),
        ("VK_DRIVER_FILES", OsString::from("/x/nvidia_icd.json")),
        ("VK_ICD_FILENAMES", OsString::from("/x/nvidia_icd.json")),
        ("VK_LOADER_LAYERS_ALLOW", OsString::from("*")),
        ("VK_LOADER_LAYERS_ENABLE", OsString::from("*overlay*")),
        (
            "VK_INSTANCE_LAYERS",
            OsString::from("VK_LAYER_KHRONOS_validation"),
        ),
        ("LIBGL_ALWAYS_SOFTWARE", OsString::from("0")),
        ("__EGL_VENDOR_LIBRARY_FILENAMES", OsString::from("/x.json")),
    ])
}

#[test]
fn an_ordinary_environment_lacks_every_setting() -> Result<()> {
    let lacks = lacking(&Environment::new(), &on_the_cpu());
    // All that has a value; what mustn't be set isn't.
    let wanted: Vec<_> = environment(&on_the_cpu())
        .into_iter()
        .filter(|(_, value)| value.is_some())
        .collect();
    ensure!(lacks == wanted, "{lacks:?}");
    Ok(())
}

#[test]
fn the_corrected_environment_lacks_nothing() -> Result<()> {
    // Started again in it, the popup goes on instead of starting once more.
    for drawing in [on_the_cpu(), Drawing::Gpu("i915".to_owned())] {
        for start in [Environment::new(), a_gaming_session()] {
            let environment_now = corrected(start, &drawing);
            ensure!(
                lacking(&environment_now, &drawing).is_empty(),
                "{environment_now:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn on_the_cpu_only_lavapipe_no_layer_and_no_egl_vendor() -> Result<()> {
    let environment_now = corrected(
        Environment::from([(
            "VK_LOADER_LAYERS_ALLOW",
            OsString::from("VK_LAYER_NV_optimus"),
        )]),
        &on_the_cpu(),
    );
    let value = |name: &str| environment_now.get(name).and_then(|value| value.to_str());
    ensure!(value("VK_LOADER_DRIVERS_SELECT") == Some("lvp_icd.*"));
    ensure!(value("VK_LOADER_LAYERS_DISABLE") == Some("~all~"));
    // Set and empty: unset, libglvnd would look for vendors itself.
    ensure!(value("__EGL_VENDOR_LIBRARY_FILENAMES") == Some(""));
    ensure!(value("LIBGL_ALWAYS_SOFTWARE") == Some("true"));
    // A layer allowed here would be exempt from the disabling.
    ensure!(value("VK_LOADER_LAYERS_ALLOW").is_none());
    Ok(())
}

/// What a session tells the Vulkan loader past the popup's orders: a list
/// of drivers of its own, which has no lavapipe and would leave the popup
/// without a window, and layers the loader loads whatever is disabled.
#[test]
fn a_sessions_own_drivers_and_forced_layers_are_taken_away() -> Result<()> {
    for drawing in [on_the_cpu(), Drawing::Gpu("amdgpu".to_owned())] {
        let environment_now = corrected(a_gaming_session(), &drawing);
        for name in [
            "VK_DRIVER_FILES",
            "VK_ICD_FILENAMES",
            "VK_LOADER_LAYERS_ENABLE",
            "VK_INSTANCE_LAYERS",
            "VK_LOADER_LAYERS_ALLOW",
        ] {
            ensure!(
                !environment_now.contains_key(name),
                "{name} for {drawing:?}"
            );
        }
    }
    Ok(())
}

/// The CPU unless asked otherwise, whatever the machine has.
#[test]
fn nothing_is_asked_of_a_gpu_unless_configured() -> Result<()> {
    let only = drivers(&["i915"]);
    for renderer in [Renderer::default(), Renderer::Cpu] {
        let drawing = choose(renderer, Compositor::Gpu("i915"), &only);
        ensure!(drawing == on_the_cpu(), "{drawing:?}");
    }
    Ok(())
}

/// A machine with one GPU, which the compositor draws on: its driver, and
/// lavapipe to fall back on.
#[test]
fn the_only_gpu_here_with_its_driver_alone() -> Result<()> {
    let mut drawing = on_the_cpu();
    for (kernel, vulkan) in [
        ("i915", "intel_icd.*,intel_hasvk_icd.*,lvp_icd.*"),
        ("xe", "intel_icd.*,intel_hasvk_icd.*,lvp_icd.*"),
        ("amdgpu", "radeon_icd.*,lvp_icd.*"),
        ("nouveau", "nouveau_icd.*,lvp_icd.*"),
        ("nvidia", "nvidia_icd.*,lvp_icd.*"),
        ("virtio_gpu", "virtio_icd.*,lvp_icd.*"),
    ] {
        drawing = choose(Renderer::Gpu, Compositor::Gpu(kernel), &drivers(&[kernel]));
        ensure!(drawing == Drawing::Gpu(kernel.to_owned()), "{drawing:?}");
        ensure!(selected(&drawing)? == vulkan, "{kernel}");
    }
    // Layers and EGL stay as on the CPU.
    let (with_gpu, without) = (environment(&drawing), environment(&on_the_cpu()));
    ensure!(with_gpu.get(1..) == without.get(1..), "{with_gpu:?}");
    Ok(())
}

/// A second GPU, whatever its driver: the Vulkan driver of the first may
/// open it while it looks for its own.
#[test]
fn the_cpu_wherever_there_is_another_gpu() -> Result<()> {
    for (compositor, all) in [
        // A laptop whose NVIDIA GPU sleeps, the compositor on the Intel
        // one, and the other way around.
        ("i915", ["i915", "nvidia"]),
        ("nvidia", ["i915", "nvidia"]),
        ("amdgpu", ["amdgpu", "nvidia"]),
        // Two of a kind.
        ("amdgpu", ["amdgpu", "amdgpu"]),
        ("i915", ["i915", "xe"]),
    ] {
        let drawing = choose(Renderer::Gpu, Compositor::Gpu(compositor), &drivers(&all));
        let expected = Drawing::Cpu(Why::NotAlone {
            driver: compositor.to_owned(),
            count: 2,
        });
        ensure!(drawing == expected, "{drawing:?}");
        // On the CPU, lavapipe alone.
        ensure!(selected(&drawing)? == "lvp_icd.*");
    }
    // A second device whose driver can't be read is a second device.
    let drawing = choose(
        Renderer::Gpu,
        Compositor::Gpu("i915"),
        &[Some("i915".to_owned()), None],
    );
    ensure!(
        matches!(drawing, Drawing::Cpu(Why::NotAlone { count: 2, .. })),
        "{drawing:?}"
    );
    Ok(())
}

/// Where the popup can't tell which GPU the display server draws on, or
/// what else is here, it draws on the CPU.
#[test]
fn the_cpu_wherever_the_popup_cant_tell() -> Result<()> {
    let only = drivers(&["i915"]);
    // No compositor that says where it draws: X11, or one without a GPU.
    let drawing = choose(Renderer::Gpu, Compositor::Silent, &only);
    ensure!(drawing == Drawing::Cpu(Why::NoGpuNamed), "{drawing:?}");
    // A device named that sysfs has no driver for.
    let drawing = choose(Renderer::Gpu, Compositor::Device(226, 128), &only);
    let expected = Drawing::Cpu(Why::NoDriver {
        major: 226,
        minor: 128,
    });
    ensure!(drawing == expected, "{drawing:?}");
    ensure!(reason(&drawing)?.contains("(226:128)"));
    // A GPU whose Vulkan driver the popup doesn't know.
    let drawing = choose(Renderer::Gpu, Compositor::Gpu("vgem"), &drivers(&["vgem"]));
    ensure!(
        drawing == Drawing::Cpu(Why::NoVulkanDriver("vgem".to_owned())),
        "{drawing:?}"
    );
    // The devices here can't be listed, the only one has no driver to be
    // read, or it is another one than the display server's.
    for seen in [Vec::new(), vec![None], drivers(&["amdgpu"])] {
        let drawing = choose(Renderer::Gpu, Compositor::Gpu("i915"), &seen);
        ensure!(
            drawing == Drawing::Cpu(Why::NotSeen("i915".to_owned())),
            "{drawing:?}"
        );
        ensure!(selected(&drawing)? == "lvp_icd.*");
    }
    Ok(())
}

/// The reason a drawing on the CPU gives, as the log has it.
fn reason(drawing: &Drawing) -> Result<String> {
    match drawing {
        Drawing::Cpu(why) => Ok(why.to_string()),
        Drawing::Gpu(_) => anyhow::bail!("not on the CPU: {drawing:?}"),
    }
}

#[test]
fn device_numbers_are_unpacked_as_glibc_packs_them() {
    // /dev/dri/renderD128 and /dev/dri/card1.
    assert_eq!(device_numbers(0xe280), (226, 128));
    assert_eq!(device_numbers(0xe201), (226, 1));
    // Numbers past 12 and 8 bits: their high parts are stored further up.
    assert_eq!(
        device_numbers(0x1234_59ab_cde6_78f1),
        (0x1234_5678, 0x9abc_def1)
    );
}

/// A popup starts itself again once: it knows by its own process id in the
/// environment, which an exec keeps. What another process left there
/// doesn't count.
#[test]
fn a_popup_knows_that_it_started_itself_again() {
    assert!(started_again(Some(OsStr::new("4711")), 4711));
    assert!(!started_again(None, 4711));
    assert!(!started_again(Some(OsStr::new("4712")), 4711));
    assert!(!started_again(Some(OsStr::new("")), 4711));
    assert!(!started_again(Some(OsStr::new("04711")), 4711));
}

/// A directory of a test's own, removed when the test is over.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("skagent-pinentry-{test}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A GPU on the PCI bus as sysfs has it.
struct Gpu {
    address: &'static str,
    /// The kernel driver bound to it, if one is.
    driver: Option<&'static str>,
    /// The number of its `card` node.
    card: u64,
    /// The number of its `renderD` node, if it can render.
    render: Option<u64>,
}

/// Lays out `gpus` under `root` the way the kernel does under `/sys`: the
/// devices with their `driver` links, their DRM nodes with `device` links
/// back, and the links to the nodes by class and by device number.
fn sysfs(root: &Path, gpus: &[Gpu]) -> Result<()> {
    std::fs::create_dir_all(root.join("class/drm"))?;
    std::fs::create_dir_all(root.join("dev/char"))?;
    for gpu in gpus {
        let device = Path::new("devices/pci0000:00").join(gpu.address);
        std::fs::create_dir_all(root.join(&device))?;
        if let Some(driver) = gpu.driver {
            symlink(
                Path::new("../../../bus/pci/drivers").join(driver),
                root.join(&device).join("driver"),
            )?;
        }
        let card = (format!("card{}", gpu.card), gpu.card);
        let render = gpu
            .render
            .map(|number| (format!("renderD{number}"), number));
        for (name, minor) in std::iter::once(card).chain(render) {
            let node = device.join("drm").join(&name);
            std::fs::create_dir_all(root.join(&node))?;
            symlink("../..", root.join(&node).join("device"))?;
            let from_two_below = Path::new("../..").join(&node);
            symlink(&from_two_below, root.join("class/drm").join(&name))?;
            symlink(
                &from_two_below,
                root.join("dev/char").join(format!("226:{minor}")),
            )?;
        }
    }
    Ok(())
}

const INTEL: Gpu = Gpu {
    address: "0000:00:02.0",
    driver: Some("i915"),
    card: 1,
    render: Some(128),
};

const NVIDIA: Gpu = Gpu {
    address: "0000:01:00.0",
    driver: Some("nvidia"),
    card: 0,
    render: Some(129),
};

/// The laptop this is for: an Intel GPU the compositor draws on, and an
/// NVIDIA GPU. The compositor's device is found by its number, as a render
/// node or a card, both are counted, and the popup stays on the CPU.
#[test]
fn a_laptop_with_two_gpus_as_sysfs_has_it() -> Result<()> {
    let scratch = Scratch::new("two-gpus")?;
    let root = scratch.0.as_path();
    sysfs(root, &[INTEL, NVIDIA])?;

    ensure!(kernel_driver(root, 226, 128).as_deref() == Some("i915"));
    ensure!(kernel_driver(root, 226, 129).as_deref() == Some("nvidia"));
    // Named by its card, as some compositors do.
    ensure!(kernel_driver(root, 226, 1).as_deref() == Some("i915"));
    ensure!(kernel_driver(root, 226, 130).is_none());
    // Each GPU once: by its render node, not also by its card.
    let devices = render_devices(root);
    ensure!(devices == drivers(&["i915", "nvidia"]), "{devices:?}");

    let drawing = choose(Renderer::Gpu, Compositor::Gpu("i915"), &devices);
    let expected = Drawing::Cpu(Why::NotAlone {
        driver: "i915".to_owned(),
        count: 2,
    });
    ensure!(drawing == expected, "{drawing:?}");
    Ok(())
}

#[test]
fn a_machine_with_one_gpu_as_sysfs_has_it() -> Result<()> {
    let scratch = Scratch::new("one-gpu")?;
    let root = scratch.0.as_path();
    sysfs(root, &[INTEL])?;

    let driver = kernel_driver(root, 226, 128).context("no driver")?;
    let devices = render_devices(root);
    ensure!(devices == drivers(&["i915"]), "{devices:?}");
    let drawing = choose(Renderer::Gpu, Compositor::Gpu(&driver), &devices);
    ensure!(drawing == Drawing::Gpu("i915".to_owned()), "{drawing:?}");
    Ok(())
}

/// A device that can render counts whether or not its driver can be read,
/// one that can't doesn't, and without sysfs nothing is known.
#[test]
fn what_sysfs_doesnt_say_isnt_made_up() -> Result<()> {
    let scratch = Scratch::new("unknown")?;
    let root = scratch.0.as_path();
    let unbound = Gpu {
        address: "0000:01:00.0",
        driver: None,
        card: 0,
        render: Some(129),
    };
    let display_only = Gpu {
        address: "0000:02:00.0",
        driver: Some("simpledrm"),
        card: 2,
        render: None,
    };
    sysfs(root, &[INTEL, unbound, display_only])?;

    ensure!(kernel_driver(root, 226, 129).is_none());
    let devices = render_devices(root);
    ensure!(devices == [None, Some("i915".to_owned())], "{devices:?}");

    let nowhere = root.join("no-such-sysfs");
    ensure!(kernel_driver(&nowhere, 226, 128).is_none());
    ensure!(render_devices(&nowhere).is_empty());
    Ok(())
}
