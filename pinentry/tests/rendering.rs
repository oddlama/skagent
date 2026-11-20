//! The environment the popup gives the graphics loaders.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::OsString;

use anyhow::{Result, ensure};
use skagent_pinentry::rendering::{ENVIRONMENT, missing};

type Environment = HashMap<&'static str, OsString>;

fn lacking(environment: &Environment) -> Vec<(&'static str, Option<&'static str>)> {
    missing(|name| environment.get(name).cloned())
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

#[test]
fn an_ordinary_environment_lacks_every_setting() -> Result<()> {
    let lacks = lacking(&Environment::new());
    // All that has a value; what mustn't be set isn't.
    let wanted: Vec<_> = ENVIRONMENT
        .into_iter()
        .filter(|(_, value)| value.is_some())
        .collect();
    ensure!(lacks == wanted, "{lacks:?}");
    Ok(())
}

#[test]
fn the_corrected_environment_lacks_nothing() -> Result<()> {
    // Started again in it, the popup goes on instead of starting once more.
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
        let environment = corrected(start);
        ensure!(lacking(&environment).is_empty(), "{environment:?}");
    }
    Ok(())
}

#[test]
fn only_lavapipe_no_layer_and_no_egl_vendor() -> Result<()> {
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
