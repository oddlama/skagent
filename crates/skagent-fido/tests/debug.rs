//! libfido2's debug output (`FIDO_DEBUG`) would log key handles: refused.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use skagent_fido::{DEBUG_VARIABLE, Device, ensure_debug_off, hid_devices};

/// Set in the child process this test starts.
const CHILD: &str = "SKAGENT_TEST_FIDO_DEBUG_CHILD";
const TEST: &str = "device_access_is_refused_while_fido_debug_is_set";

/// Changing the environment of the test process isn't safe (other test
/// threads read it), so the test runs itself again with the variable set.
#[test]
fn device_access_is_refused_while_fido_debug_is_set() -> Result<()> {
    if std::env::var_os(CHILD).is_some() {
        ensure!(ensure_debug_off().is_err());
        let listing = hid_devices().err().context("listing devices worked")?;
        ensure!(
            format!("{listing:#}").contains(DEBUG_VARIABLE),
            "{listing:#}"
        );
        let opening = Device::open("/dev/null").err().context("opening worked")?;
        ensure!(
            format!("{opening:#}").contains(DEBUG_VARIABLE),
            "{opening:#}"
        );
        return Ok(());
    }
    // Empty counts too: libfido2 only checks that the variable exists.
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", TEST, "--nocapture"])
        .env(DEBUG_VARIABLE, "")
        .env(CHILD, "1")
        .output()
        .context("running the test in a child process")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    ensure!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed or didn't run the test: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
