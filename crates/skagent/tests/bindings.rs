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
use skagent::pairing::Proof;
use skagent::pin_cache::CredentialKey;
use skagent_fido::PairingCredential;

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

fn no_proofs(_: &DeviceIdentity) -> Proof {
    Proof::Unknown
}

fn resolve(bindings: &Bindings, key: &CredentialKey, devices: &[DeviceIdentity]) -> Resolution {
    bindings.resolve(Some(key), devices, serial, no_proofs)
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
        bindings.resolve(None, &[], serial, no_proofs),
        Resolution::Wait(Missing::Nothing { serial: None })
    );
    assert_eq!(
        bindings.resolve(None, &[device(3)], serial, no_proofs),
        Resolution::Direct(device(3))
    );
    assert_eq!(
        bindings.resolve(None, &[device(3), device(4)], serial, no_proofs),
        Resolution::Touch
    );
}

#[test]
fn bindings_override_enumeration_order() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK), None);
    bindings.bind(&personal(), device(2), Some(NANO), None);
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
    bindings.bind(&work(), device(3), None, None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    // Unplugged and plugged back in: a new plug-in of the same YubiKey.
    assert_eq!(
        resolve(&bindings, &work(), &[device(2), device(11)]),
        Resolution::Direct(device(11))
    );
    // Without the serials read, nothing is recognized.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(11)], no_serials, no_proofs),
        Resolution::Wait(Missing::Elsewhere {
            serial: Some(DESK),
            other: None
        })
    );
}

#[test]
fn a_missing_yubikey_is_waited_for_never_replaced() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK), None);
    assert_eq!(
        resolve(&bindings, &work(), &[]),
        Resolution::Wait(Missing::Nothing { serial: Some(DESK) })
    );
    assert_eq!(
        resolve(&bindings, &work(), &[device(2)]),
        Resolution::Wait(Missing::Elsewhere {
            serial: Some(DESK),
            other: Some(NANO)
        })
    );
    // A device without a serial isn't the YubiKey either, nor the only one.
    assert_eq!(
        resolve(&bindings, &work(), &[device(3)]),
        Resolution::Wait(Missing::Elsewhere {
            serial: Some(DESK),
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    assert!(
        !bindings.needs_serials(Some(&work()), &[device(1), device(2)]),
        "plugged in"
    );
    assert!(bindings.needs_serials(Some(&work()), &[device(2)]));
    assert!(bindings.needs_serials(Some(&work()), &[]));
    assert!(!bindings.needs_serials(None, &[device(2)]), "loading");
    bindings.bind(&personal(), device(3), None, None);
    assert!(
        !bindings.needs_serials(Some(&personal()), &[device(2)]),
        "no serial"
    );
}

#[test]
fn removing_one_binding_leaves_the_other_alone() {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(1), Some(DESK), None);
    bindings.bind(&personal(), device(2), Some(NANO), None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    bindings.bind(&personal(), device(2), None, None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    bindings.bind(&work(), device(11), None, None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    // Without a serial there is nothing to remember.
    bindings.bind(&personal(), device(3), None, None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
    bindings.bind(&personal(), device(2), Some(NANO), None);
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
        bindings.bind(&work(), device(1), Some(DESK), None);
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
    bindings.bind(&work(), device(1), Some(DESK), None);
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
            bindings.resolve(Some(&work()), &candidates, impostor, no_proofs),
            Resolution::Ambiguous { serial: Some(DESK) }
        );
    }
    // The plug-in that signed before is still trusted while it stays.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(21), device(1)], impostor, no_proofs),
        Resolution::Direct(device(1))
    );
}

fn pairing() -> PairingCredential {
    PairingCredential {
        id: vec![9; 48],
        public_key: [7; 32],
    }
}

/// Answers of the test devices to the pairing challenge: plug-ins 1 and 11
/// (the desk YubiKey) and 3 (a key without a serial) hold the pairing.
fn holds_pairing(device: &DeviceIdentity) -> Proof {
    if [1, 11, 3]
        .iter()
        .any(|inode| *device == self::device(*inode))
    {
        Proof::Proven
    } else {
        Proof::Disproven
    }
}

fn paired(serial: Option<u32>, inode: u64) -> Bindings {
    let mut bindings = Bindings::default();
    bindings.bind(&work(), device(inode), serial, Some(pairing()));
    bindings
}

#[test]
fn a_paired_key_is_the_device_that_proves_it() {
    // Replugged, among others: found by its pairing, no touch.
    let bindings = paired(Some(DESK), 1);
    assert_eq!(
        bindings.resolve(
            Some(&work()),
            &[device(2), device(11)],
            serial,
            holds_pairing
        ),
        Resolution::Direct(device(11))
    );
    // Keys without a serial are recognized the same way.
    let bindings = paired(None, 4);
    assert_eq!(
        bindings.resolve(
            Some(&work()),
            &[device(5), device(3)],
            serial,
            holds_pairing
        ),
        Resolution::Direct(device(3))
    );
}

#[test]
fn a_device_claiming_a_paired_serial_without_the_proof_gets_no_pin() {
    let bindings = paired(Some(DESK), 1);
    let fake = |candidate: &DeviceIdentity| {
        if *candidate == device(21) {
            Some(DESK)
        } else {
            serial(candidate)
        }
    };
    // Swapped for a fake.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(21)], fake, holds_pairing),
        Resolution::Unrecognized { serial: DESK }
    );
    // Next to the real one, the real one proves it and is used.
    assert_eq!(
        bindings.resolve(
            Some(&work()),
            &[device(21), device(11)],
            fake,
            holds_pairing
        ),
        Resolution::Direct(device(11))
    );
    // A device that couldn't be asked yet is no proof either way: wait.
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(21)], fake, no_proofs),
        Resolution::Wait(Missing::Elsewhere {
            serial: Some(DESK),
            other: Some(DESK)
        })
    );
}

#[test]
fn a_paired_key_that_is_away_is_waited_for() {
    let bindings = paired(Some(DESK), 1);
    assert_eq!(
        bindings.resolve(Some(&work()), &[], serial, holds_pairing),
        Resolution::Wait(Missing::Nothing { serial: Some(DESK) })
    );
    assert_eq!(
        bindings.resolve(Some(&work()), &[device(2)], serial, holds_pairing),
        Resolution::Wait(Missing::Elsewhere {
            serial: Some(DESK),
            other: Some(NANO)
        })
    );
    // Without a serial, there's no touch selection to fall back to.
    let bindings = paired(None, 4);
    assert_eq!(
        bindings.resolve(
            Some(&work()),
            &[device(5), device(6)],
            serial,
            holds_pairing
        ),
        Resolution::Wait(Missing::Elsewhere {
            serial: None,
            other: None
        })
    );
}

#[test]
fn two_devices_proving_one_pairing_get_no_pin() {
    let bindings = paired(Some(DESK), 4);
    assert_eq!(
        bindings.resolve(
            Some(&work()),
            &[device(1), device(3)],
            serial,
            holds_pairing
        ),
        Resolution::Ambiguous { serial: Some(DESK) }
    );
}

#[test]
fn proofs_are_only_needed_when_the_plug_in_is_gone() {
    let bindings = paired(Some(DESK), 1);
    assert_eq!(bindings.needs_proof(Some(&work()), &[device(1)]), None);
    assert_eq!(
        bindings.needs_proof(Some(&work()), &[device(11)]),
        Some(&pairing())
    );
    assert_eq!(bindings.needs_proof(None, &[device(11)]), None);
    assert_eq!(
        Bindings::default().needs_proof(Some(&work()), &[device(11)]),
        None
    );
}

#[test]
fn a_pairing_stays_once_known() {
    let mut bindings = paired(Some(DESK), 1);
    bindings.bind(&work(), device(11), Some(DESK), None);
    assert_eq!(bindings.pairing_of(&work()), Some(&pairing()));
}

#[test]
fn pairings_are_remembered_across_restarts() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("bindings.toml");
    let mut bindings = Bindings::remembered_in(file.clone());
    bindings.bind(&work(), device(1), Some(DESK), Some(pairing()));
    // Without a serial, the pairing alone is worth remembering.
    bindings.bind(&personal(), device(4), None, Some(pairing()));
    drop(bindings);

    let restarted = Bindings::remembered_in(file.clone());
    assert_eq!(restarted.pairing_of(&work()), Some(&pairing()));
    assert_eq!(restarted.pairing_of(&personal()), Some(&pairing()));
    assert_eq!(
        restarted.resolve(Some(&personal()), &[device(3)], serial, holds_pairing),
        Resolution::Direct(device(3))
    );
    let text = remembered(&file)?;
    ensure!(text.matches("[[binding]]").count() == 2, "{text}");
    ensure!(
        text.contains(&format!("pairing-key = \"{}\"", "07".repeat(32))),
        "{text}"
    );
    Ok(())
}

#[test]
fn a_half_remembered_pairing_is_refused() -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let file = dir.path().join("bindings.toml");
    let credential = "00".repeat(32);
    std::fs::write(
        &file,
        format!("[[binding]]\ncredential = \"{credential}\"\npairing-id = \"0909\"\n"),
    )
    .context("writing the file")?;
    let bindings = Bindings::remembered_in(file);
    // The whole file is ignored, as unreadable.
    assert_eq!(
        resolve(&bindings, &work(), &[device(3)]),
        Resolution::Direct(device(3))
    );
    Ok(())
}
