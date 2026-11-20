//! What the popup draws with, and the environment it gives the graphics
//! loaders for it.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::OsString;

use anyhow::{Context as _, Result, ensure};
use skagent_pinentry::rendering::{
    Drawing, Renderer, Why, choose, device_numbers, environment, missing,
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

fn drivers(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
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
        for start in [
            Environment::new(),
            Environment::from([
                // A session set up for games on the other GPU.
                ("VK_LOADER_DRIVERS_SELECT", OsString::from("nvidia*")),
                ("VK_LOADER_LAYERS_ALLOW", OsString::from("*")),
                ("LIBGL_ALWAYS_SOFTWARE", OsString::from("0")),
                ("__EGL_VENDOR_LIBRARY_FILENAMES", OsString::from("/x.json")),
            ]),
        ] {
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

/// The CPU unless asked otherwise, whatever the machine has.
#[test]
fn nothing_is_asked_of_a_gpu_unless_configured() {
    let all = drivers(&["i915", "nvidia"]);
    assert_eq!(
        choose(Renderer::default(), Some("i915"), &all),
        on_the_cpu()
    );
    assert_eq!(choose(Renderer::Cpu, Some("i915"), &all), on_the_cpu());
}

/// A laptop with an Intel GPU the compositor draws on and an NVIDIA GPU
/// that sleeps: the Intel driver, lavapipe to fall back on, and nothing
/// of NVIDIA's.
#[test]
fn the_display_servers_gpu_and_no_other() -> Result<()> {
    let both = drivers(&["i915", "nvidia"]);
    let drawing = choose(Renderer::Gpu, Some("i915"), &both);
    ensure!(drawing == Drawing::Gpu("i915".to_owned()), "{drawing:?}");
    let selected_drivers = selected(&drawing)?;
    ensure!(
        selected_drivers == "intel_icd.*,intel_hasvk_icd.*,lvp_icd.*",
        "{selected_drivers}"
    );
    // The other way around, for a compositor on the NVIDIA GPU.
    let drawing = choose(Renderer::Gpu, Some("nvidia"), &both);
    ensure!(selected(&drawing)? == "nvidia_icd.*,lvp_icd.*");
    for (kernel, vulkan) in [
        ("xe", "intel_icd.*,intel_hasvk_icd.*,lvp_icd.*"),
        ("amdgpu", "radeon_icd.*,lvp_icd.*"),
        ("nouveau", "nouveau_icd.*,lvp_icd.*"),
        ("virtio_gpu", "virtio_icd.*,lvp_icd.*"),
    ] {
        let drawing = choose(Renderer::Gpu, Some(kernel), &drivers(&[kernel]));
        ensure!(selected(&drawing)? == vulkan, "{kernel}");
    }
    // Layers and EGL stay as on the CPU.
    let (with_gpu, without) = (environment(&drawing), environment(&on_the_cpu()));
    ensure!(with_gpu.get(1..) == without.get(1..), "{with_gpu:?}");
    Ok(())
}

/// Where the popup can't be sure to stay with the display server's GPU,
/// it draws on the CPU.
#[test]
fn the_cpu_wherever_another_gpu_could_be_touched() -> Result<()> {
    // No compositor that says where it draws: X11, or one without a GPU.
    let drawing = choose(Renderer::Gpu, None, &drivers(&["i915"]));
    ensure!(drawing == Drawing::Cpu(Why::NoGpuNamed), "{drawing:?}");
    // A GPU whose Vulkan driver the popup doesn't know.
    let drawing = choose(Renderer::Gpu, Some("vgem"), &drivers(&["vgem"]));
    ensure!(
        drawing == Drawing::Cpu(Why::NoVulkanDriver("vgem".to_owned())),
        "{drawing:?}"
    );
    // Two GPUs of one Vulkan driver, which would open both: two AMD ones,
    // or an Intel one of each kernel driver.
    for (compositor, all) in [("amdgpu", ["amdgpu", "amdgpu"]), ("i915", ["i915", "xe"])] {
        let drawing = choose(Renderer::Gpu, Some(compositor), &drivers(&all));
        let expected = Drawing::Cpu(Why::NotAlone {
            driver: compositor.to_owned(),
            count: 2,
        });
        ensure!(drawing == expected, "{drawing:?}");
    }
    // The devices here can't be seen: no telling how many there are.
    let drawing = choose(Renderer::Gpu, Some("i915"), &[]);
    ensure!(
        matches!(drawing, Drawing::Cpu(Why::NotAlone { count: 0, .. })),
        "{drawing:?}"
    );
    // On the CPU, lavapipe alone.
    ensure!(selected(&drawing)? == "lvp_icd.*");
    Ok(())
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
