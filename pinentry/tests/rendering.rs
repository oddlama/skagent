//! What the popup draws with: the environment it gives the graphics loaders
//! for the CPU, and what it makes of the renderer its window ended up with.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};

use anyhow::{Result, ensure};
use skagent_pinentry::rendering::{
    ON_THE_CPU, Outcome, Renderer, missing, needs, outcome, started_again,
};

type Environment = HashMap<&'static str, OsString>;

fn lacking(environment: &Environment) -> Vec<(&'static str, Option<&'static str>)> {
    missing(|name| environment.get(name).cloned(), &ON_THE_CPU)
}

/// `environment` after what [`missing`] asks for.
fn corrected(mut environment: Environment) -> Environment {
    for (name, wanted) in lacking(&environment) {
        match wanted {
            Some(value) => environment.insert(name, OsString::from(value)),
            None => environment.remove(name),
        };
    }
    environment
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
    let lacks = lacking(&Environment::new());
    // All that has a value; what mustn't be set isn't.
    let wanted: Vec<_> = ON_THE_CPU
        .into_iter()
        .filter(|(_, value)| value.is_some())
        .collect();
    ensure!(lacks == wanted, "{lacks:?}");
    Ok(())
}

#[test]
fn the_corrected_environment_lacks_nothing() -> Result<()> {
    // Started again in it, the popup goes on instead of starting once more.
    for start in [Environment::new(), a_gaming_session()] {
        let environment = corrected(start);
        ensure!(lacking(&environment).is_empty(), "{environment:?}");
    }
    Ok(())
}

#[test]
fn on_the_cpu_only_lavapipe_no_layer_and_no_egl_vendor() -> Result<()> {
    let environment = corrected(Environment::from([(
        "VK_LOADER_LAYERS_ALLOW",
        OsString::from("VK_LAYER_NV_optimus"),
    )]));
    let value = |name: &str| environment.get(name).and_then(|value| value.to_str());
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
    let environment = corrected(a_gaming_session());
    for name in [
        "VK_DRIVER_FILES",
        "VK_ICD_FILENAMES",
        "VK_LOADER_LAYERS_ENABLE",
        "VK_INSTANCE_LAYERS",
        "VK_LOADER_LAYERS_ALLOW",
    ] {
        ensure!(!environment.contains_key(name), "{name}");
    }
    Ok(())
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

/// auto takes what it gets, a GPU first. gpu and cpu take the one they
/// name and nothing else: the popup doesn't show a window drawn by the
/// other.
#[test]
fn a_window_is_shown_only_if_drawn_with_what_was_asked_for() {
    let (software, gpu) = (true, false);
    assert_eq!(outcome(Renderer::Auto, gpu), Outcome::AsAsked);
    assert_eq!(outcome(Renderer::Auto, software), Outcome::NoGpu);
    assert_eq!(outcome(Renderer::Gpu, gpu), Outcome::AsAsked);
    assert_eq!(outcome(Renderer::Gpu, software), Outcome::OnlyTheCpu);
    assert_eq!(outcome(Renderer::Cpu, software), Outcome::AsAsked);
    assert_eq!(outcome(Renderer::Cpu, gpu), Outcome::NotTheCpu);
    // Without a setting: auto.
    assert_eq!(outcome(Renderer::default(), software), Outcome::NoGpu);
}

/// A window that can't open says what the renderer asked for would need.
#[test]
fn what_is_missing_is_named_for_the_renderer_asked_for() {
    assert!(needs(Renderer::Cpu).contains("lavapipe"));
    assert!(needs(Renderer::Gpu).contains("renderer = \"gpu\""));
    assert!(!needs(Renderer::Gpu).contains("software"));
    assert!(needs(Renderer::Auto).contains("software"));
}
