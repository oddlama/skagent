//! Credential-to-device bindings and device-operation serialization.
//!
//! Bound devices can sign concurrently. Selecting an unbound credential takes
//! exclusive access to all devices, so its touch probes cannot steal a touch
//! from an assertion. No PIN is involved in selection.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use skagent_fido::{Device, hid_devices};
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

use crate::device::DeviceIdentity;
use crate::pin_cache::CredentialKey;
use crate::signer::SigningTicket;

const SELECTION_TIMEOUT: Duration = Duration::from_secs(30);
const TOUCH_POLL: Duration = Duration::from_millis(50);

/// A routing decision made without touching a device or reading a PIN.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// An established binding, or the only device on first use.
    Direct(DeviceIdentity),
    /// Multiple candidates, or a binding was lost. Require explicit selection.
    Touch,
}

/// Successful credential-to-device associations, independent of cached PINs.
#[derive(Debug, Default)]
pub struct Bindings(HashMap<CredentialKey, DeviceIdentity>);

impl Bindings {
    /// Binds a credential only after a successful assertion on this device.
    pub fn bind(&mut self, key: CredentialKey, device: DeviceIdentity) {
        self.0.insert(key, device);
    }

    /// Removes an identity's binding, not merely its PIN.
    pub fn forget(&mut self, key: &CredentialKey) {
        self.0.remove(key);
    }

    /// Removes all associations when the agent unloads all identities.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Chooses a known device, never another device in its place. A changed
    /// or absent binding always requires touch, even with a single candidate.
    ///
    /// # Errors
    /// Refuses when no FIDO devices are connected.
    pub fn resolve(&self, key: &CredentialKey, devices: &[DeviceIdentity]) -> Result<Resolution> {
        ensure!(!devices.is_empty(), "no FIDO security key is connected");
        if let Some(bound) = self.0.get(key) {
            return Ok(if devices.contains(bound) {
                Resolution::Direct(bound.clone())
            } else {
                Resolution::Touch
            });
        }
        Ok(match devices {
            [only] => Resolution::Direct(only.clone()),
            _ => Resolution::Touch,
        })
    }
}

/// Independent locks, reclaimed once nobody holds or waits for them.
#[derive(Debug)]
pub struct KeyedLocks<K>(Mutex<HashMap<K, Weak<Mutex<()>>>>);

impl<K> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Eq + Hash> KeyedLocks<K> {
    /// Waits for this key only; other keys can proceed independently.
    pub async fn lock(&self, key: K) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.0.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

#[derive(Debug, Default)]
pub(crate) struct Router {
    bindings: Mutex<Bindings>,
    devices: KeyedLocks<DeviceIdentity>,
    pub credentials: KeyedLocks<CredentialKey>,
    /// Readers are assertions; a writer is touch selection across devices.
    access: Arc<RwLock<()>>,
}

/// These locks travel with the open device into blocking workers. Dropping an
/// async request cannot release them while a worker still uses the hardware.
pub(crate) struct RoutedDevice {
    pub identity: DeviceIdentity,
    pub device: Device,
    _operation: OwnedMutexGuard<()>,
    _access: OwnedRwLockReadGuard<()>,
}

impl Router {
    pub async fn bind(&self, key: CredentialKey, device: DeviceIdentity) {
        self.bindings.lock().await.bind(key, device);
    }

    pub async fn forget(&self, key: &CredentialKey) {
        self.bindings.lock().await.forget(key);
    }

    pub async fn clear(&self) {
        self.bindings.lock().await.clear();
    }

    pub async fn route(&self, key: &CredentialKey, ticket: SigningTicket) -> Result<RoutedDevice> {
        self.route_key(Some(key), ticket).await
    }

    pub async fn for_load(&self, ticket: SigningTicket) -> Result<RoutedDevice> {
        self.route_key(None, ticket).await
    }

    async fn resolve(
        &self,
        key: Option<&CredentialKey>,
        candidates: &[DeviceIdentity],
    ) -> Result<Resolution> {
        if let Some(key) = key {
            self.bindings.lock().await.resolve(key, candidates)
        } else {
            ensure!(!candidates.is_empty(), "no FIDO security key is connected");
            Ok(match candidates {
                [only] => Resolution::Direct(only.clone()),
                _ => Resolution::Touch,
            })
        }
    }

    async fn route_key(
        &self,
        key: Option<&CredentialKey>,
        ticket: SigningTicket,
    ) -> Result<RoutedDevice> {
        let read = Arc::clone(&self.access).read_owned().await;
        ticket.check()?;
        let candidates = connected().await?;
        let decision = self.resolve(key, &candidates).await?;
        if let Resolution::Direct(identity) = decision {
            return self.open_direct(identity, read).await;
        }
        drop(read);

        // Re-enumerate after obtaining exclusive access: another request may
        // have waited for a touch or changed a binding in the meantime.
        let exclusive = Arc::clone(&self.access).write_owned().await;
        ticket.check()?;
        let candidates = connected().await?;
        let decision = self.resolve(key, &candidates).await?;
        if let Resolution::Direct(identity) = decision {
            return self.open_direct(identity, exclusive.downgrade()).await;
        }
        if key.is_some() {
            tracing::info!(
                "touch the key holding the requested credential to select it; signing will need another touch"
            );
        } else {
            tracing::info!(
                "touch the security key whose resident SSH credentials you want to load"
            );
        }
        let (identity, device, exclusive) = tokio::task::spawn_blocking(move || {
            // Keep exclusive access until the worker stops, even if its caller
            // goes away. Outstanding probes are cancelled on drop.
            let selected = select_by_touch(candidates, &ticket)?;
            Ok::<_, anyhow::Error>((selected.0, selected.1, exclusive))
        })
        .await
        .context("the device selection thread failed")??;
        let operation = self.devices.lock(identity.clone()).await;
        Ok(RoutedDevice {
            identity,
            device,
            _operation: operation,
            _access: exclusive.downgrade(),
        })
    }

    async fn open_direct(
        &self,
        identity: DeviceIdentity,
        access: OwnedRwLockReadGuard<()>,
    ) -> Result<RoutedDevice> {
        let operation = self.devices.lock(identity.clone()).await;
        tokio::task::spawn_blocking(move || {
            let device = open_checked(&identity)?;
            Ok(RoutedDevice {
                identity,
                device,
                _operation: operation,
                _access: access,
            })
        })
        .await
        .context("opening the routed security key in the device thread")?
    }
}

async fn connected() -> Result<Vec<DeviceIdentity>> {
    tokio::task::spawn_blocking(|| {
        hid_devices()?
            .into_iter()
            .map(|device| DeviceIdentity::of(&device.path))
            .collect()
    })
    .await
    .context("the device listing thread failed")?
}

fn open_checked(identity: &DeviceIdentity) -> Result<Device> {
    ensure!(
        DeviceIdentity::of(identity.path())? == *identity,
        "security key changed before opening {}",
        identity.path()
    );
    let device = Device::open(identity.path())?;
    ensure!(
        DeviceIdentity::of(identity.path())? == *identity,
        "security key changed while opening {}",
        identity.path()
    );
    Ok(device)
}

fn select_by_touch(
    identities: Vec<DeviceIdentity>,
    ticket: &SigningTicket,
) -> Result<(DeviceIdentity, Device)> {
    let started = Instant::now();
    let mut probes = Vec::new();
    for identity in identities {
        ticket.check()?;
        let probe = open_checked(&identity)?.begin_touch()?;
        probes.push((identity, probe));
    }
    while started.elapsed() < SELECTION_TIMEOUT {
        let mut selected = None;
        for (identity, probe) in &mut probes {
            ticket.check()?;
            if probe.poll(TOUCH_POLL)? {
                ensure!(
                    selected.is_none(),
                    "several security keys were touched; select only one"
                );
                selected = Some(identity.clone());
            }
        }
        if let Some(selected) = selected {
            for (identity, probe) in probes {
                if identity == selected {
                    ensure!(
                        DeviceIdentity::of(identity.path())? == identity,
                        "selected security key changed"
                    );
                    return Ok((identity, probe.finish()?));
                }
            }
            bail!("selected security key disappeared from the candidate list");
        }
    }
    bail!("timed out selecting a security key; touch the key holding this credential")
}
