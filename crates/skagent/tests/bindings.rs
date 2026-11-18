//! Which device a request goes to: independent of enumeration order, never
//! another device in place of a known one, a YubiKey recognized by its
//! serial, and waiting for a security key that isn't plugged in. Serial
//! bindings are remembered in a file.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use skagent::bindings::{Bindings, Missing, Resolution, default_bindings_path};
use skagent::device::DeviceIdentity;
use skagent::pin_cache::CredentialKey;

const DESK: u32 = 12_345_678;
const NANO: u32 = 23_456_789;

fn work() -> CredentialKey {
    CredentialKey::new("ssh:work", &[1; 32])
}

fn personal() -> CredentialKey {
    CredentialKey::new("ssh:personal", &[2; 32])
}

fn device(inode: u64) -> DeviceIdentity {
    DeviceIdentity::new("/dev/hidraw1", 1, inode, (100, 0))
}

/// Serials of the test devices: inode 1 and 11 are the desk YubiKey (two
/// plug-ins), 2 the nano, anything else reports none.
fn serial(device: &DeviceIdentity) -> Option<u32> {
    [(1, DESK), (11, DESK), (2, NANO)]
        .into_iter()
        .find(|(inode, _)| *device == self::device(*inode))
        .map(|(_, serial)| serial)
}

fn no_serials(_: &DeviceIdentity) -> Option<u32> {
    None
}

fn resolve(bindings: &Bindings, key: &CredentialKey, devices: &[DeviceIdentity]) -> Resolution {
    bindings.resolve(Some(key), devices, serial)
}

#[test]
fn unknown_credentials_need_selection_unless_there_is_only_one_device() {
    let bindings = Bindings::default();
    assert_eq!(
        resolve(&bindings, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: None })
    );
    assert_eq!(
        resolve(&bindings, &work(), &[device(1)]),
        Resolution::Direct(device(1))
    );
    assert_eq!(
        resolve(&bindings, &work(), &[device(1), device(2)]),
        Resolution::Touch
    );
}

#[test]
fn loading_takes_the_only_device_and_selects_among_several() {
    let bindings = Bindings::default();
    assert_eq!(
        bindings.resolve(None, &[], serial),
        Resolution::Wait(Missing::Nothing { serial: None })
    );
    assert_eq!(
        bindings.resolve(None, &[device(3)], serial),
        Resolution::Direct(device(3))
    );
    assert_eq!(
        bindings.resolve(None, &[device(3), device(4)], serial),
        Resolution::Touch
    );
}

#[test]
fn bindings_override_enumeration_order() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    bindings.bind(&personal(), device(2), Some(NANO));
    for candidates in [[device(1), device(2)], [device(2), device(1)]] {
        assert_eq!(
            resolve(&bindings, &work(), &candidates),
            Resolution::Direct(device(1))
        );
        assert_eq!(
            resolve(&bindings, &personal(), &candidates),
            Resolution::Direct(device(2))
        );
    }
}

#[test]
fn losing_a_binding_without_a_serial_requires_touch_even_with_one_remaining_device() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(3), None);
    assert_eq!(resolve(&bindings, &work(), &[device(4)]), Resolution::Touch);
    assert_eq!(
        resolve(&bindings, &work(), &[device(4), device(5)]),
        Resolution::Touch
    );
    assert_eq!(
        resolve(&bindings, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: None })
    );
}

#[test]
fn a_replugged_yubikey_is_recognized_by_its_serial() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    // Unplugged and plugged back in: a new plug-in of the same YubiKey.
    assert_eq!(
        resolve(&bindings, &work(), &[device(2), device(11)]),
        Resolution::Direct(device(11))
    );
    // Without the serials read, nothing is recognized.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(11)], no_serials),
        Resolution::Wait(Missing::Elsewhere {
            serial: DESK,
            other: None
        })
    );
}

#[test]
fn a_missing_yubikey_is_waited_for_never_replaced() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    assert_eq!(
        resolve(&bindings, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: Some(DESK) })
    );
    assert_eq!(
        resolve(&bindings, &work(), &[device(2)]),
        Resolution::Wait(Missing::Elsewhere {
            serial: DESK,
            other: Some(NANO)
        })
    );
    // A device without a serial isn't the YubiKey either, nor the only one.
    assert_eq!(
        resolve(&bindings, &work(), &[device(3)]),
        Resolution::Wait(Missing::Elsewhere {
            serial: DESK,
            other: None
        })
    );
}

#[test]
fn serials_are_only_needed_when_the_plug_in_is_gone() {
    let mut bindings = Bindings::default();
    assert!(
        !bindings.needs_serials(Some(&work()), &[device(2)]),
        "unbound"
    );
    bindings.bind(&work(), device(1), Some(DESK));
    assert!(
        !bindings.needs_serials(Some(&work()), &[device(1), device(2)]),
        "plugged in"
    );
    assert!(bindings.needs_serials(Some(&work()), &[device(2)]));
    assert!(bindings.needs_serials(Some(&work()), &[]));
    assert!(!bindings.needs_serials(None, &[device(2)]), "loading");
    bindings.bind(&personal(), device(3), None);
    assert!(
        !bindings.needs_serials(Some(&personal()), &[device(2)]),
        "no serial"
    );
}

#[test]
fn removing_one_binding_leaves_the_other_alone() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    bindings.bind(&personal(), device(2), Some(NANO));
    bindings.forget(&work());
    let candidates = [device(1), device(2)];
    assert_eq!(resolve(&bindings, &work(), &candidates), Resolution::Touch);
    assert_eq!(
        resolve(&bindings, &personal(), &candidates),
        Resolution::Direct(device(2))
    );
}

#[test]
fn clearing_identities_forgets_all_bindings() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    bindings.bind(&personal(), device(2), None);
    bindings.clear();
    for key in [work(), personal()] {
        assert_eq!(
            resolve(&bindings, &key, &[device(1), device(2)]),
            Resolution::Touch
        );
    }
}

#[test]
fn a_serial_stays_when_it_couldnt_be_read_again() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    bindings.bind(&work(), device(11), None);
    assert_eq!(
        resolve(&bindings, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: Some(DESK) })
    );
}

fn remembered(file: &Path) -> Result<String> {
    std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))
}

#[test]
fn serial_bindings_are_remembered_across_restarts() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("skagent").join("bindings.toml");
    let mut bindings = Bindings::remembered_in(file.clone());
    bindings.bind(&work(), device(1), Some(DESK));
    // Without a serial there is nothing to remember.
    bindings.bind(&personal(), device(3), None);
    drop(bindings);

    let restarted = Bindings::remembered_in(file.clone());
    assert_eq!(
        resolve(&restarted, &work(), &[device(11)]),
        Resolution::Direct(device(11))
    );
    assert_eq!(
        resolve(&restarted, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: Some(DESK) })
    );
    assert_eq!(
        resolve(&restarted, &personal(), &[device(3), device(4)]),
        Resolution::Touch
    );

    let text = remembered(&file)?;
    ensure!(text.contains("serial = 12345678"), "{text}");
    ensure!(text.matches("[[binding]]").count() == 1, "{text}");
    // A digest, not the key handle.
    ensure!(!text.contains(&"01".repeat(32)), "{text}");
    let mode = |path: &Path| -> Result<u32> {
        Ok(std::fs::metadata(path)
            .with_context(|| format!("inspecting {}", path.display()))?
            .permissions()
            .mode()
            & 0o777)
    };
    ensure!(mode(&file)? == 0o600, "file mode {:o}", mode(&file)?);
    let parent = file.parent().context("no parent")?;
    ensure!(mode(parent)? == 0o700, "directory mode {:o}", mode(parent)?);
    Ok(())
}

#[test]
fn removing_identities_forgets_what_was_remembered() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("bindings.toml");
    let mut bindings = Bindings::remembered_in(file.clone());
    bindings.bind(&work(), device(1), Some(DESK));
    bindings.bind(&personal(), device(2), Some(NANO));
    bindings.forget(&work());
    let text = remembered(&file)?;
    ensure!(
        !text.contains("12345678") && text.contains("23456789"),
        "{text}"
    );
    bindings.clear();
    let text = remembered(&file)?;
    ensure!(!text.contains("[[binding]]"), "{text}");
    Ok(())
}

#[test]
fn an_unreadable_file_is_ignored_and_replaced() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("bindings.toml");
    for broken in [
        "not toml at all [",
        "[[binding]]\ncredential = \"abc\"\nserial = 1\n",
        "[[binding]]\ncredential = \"00\"\nserial = 1\nextra = true\n",
    ] {
        std::fs::write(&file, broken).context("writing a broken file")?;
        let mut bindings = Bindings::remembered_in(file.clone());
        assert_eq!(
            resolve(&bindings, &work(), &[device(3)]),
            Resolution::Direct(device(3))
        );
        bindings.bind(&work(), device(1), Some(DESK));
        ensure!(remembered(&file)?.contains("serial = 12345678"));
    }
    Ok(())
}

#[test]
fn bindings_live_in_the_state_directory() -> Result<()> {
    ensure!(
        default_bindings_path(Some("/state".as_ref()), Some("/home/alice".as_ref()))?
            == Path::new("/state/skagent/bindings.toml")
    );
    ensure!(
        default_bindings_path(Some("relative".as_ref()), Some("/home/alice".as_ref()))?
            == Path::new("/home/alice/.local/state/skagent/bindings.toml")
    );
    ensure!(default_bindings_path(None, None).is_err());
    Ok(())
}

#[test]
fn a_serial_reported_twice_gets_no_pin() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK));
    // Plug-in 11 is the desk YubiKey again; plug-in 21 claims to be it too.
    let impostor = |candidate: &DeviceIdentity| {
        if *candidate == device(21) {
            Some(DESK)
        } else {
            serial(candidate)
        }
    };
    for candidates in [[device(11), device(21)], [device(21), device(11)]] {
        assert_eq!(
            bindings.resolve(Some(&work()), &candidates, impostor),
            Resolution::Ambiguous { serial: DESK }
        );
    }
    // The plug-in that signed before is still trusted while it stays.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(21), device(1)], impostor),
        Resolution::Direct(device(1))
    );
}
