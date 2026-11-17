//! Credential-to-device bindings and device-operation serialization.
//!
//! Bound devices can sign concurrently. Selecting an unbound credential takes
//! exclusive access to all devices, so its touch probes cannot steal a touch
//! from an assertion. No PIN is involved in selection.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use skagent_fido::{Device, hid_devices, yubikey_serial};
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

use crate::cancel::{Abandoned, AbandonedFlag};
use crate::device::DeviceIdentity;
use crate::notify::Notifier;
use crate::pin_cache::CredentialKey;
use crate::signer::SigningTicket;

/// How long a touch selection waits.
pub(crate) const SELECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Called with the number of candidates when a touch selection starts.
pub(crate) type OnSelect = Box<dyn FnOnce(usize) + Send>;

/// Longest wait for a busy security key or credential. A request ahead can
/// hold a key for a PIN prompt (60 s) plus a touch (35 s); this lets one such
/// request finish, but stops requests from piling up behind an unresponsive
/// key forever.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(120);
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
    /// [`KeyedLocks::lock`], giving up after `timeout`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock wasn't free within `timeout`.
    pub async fn lock_within(&self, key: K, timeout: Duration) -> Result<OwnedMutexGuard<()>> {
        tokio::time::timeout(timeout, self.lock(key))
            .await
            .map_err(|_elapsed| busy(timeout))
    }

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

/// YubiKey serials of the plug-ins seen so far: read once per plug-in,
/// before libfido2 opens it. `None`: the device reports no serial.
#[derive(Debug, Default)]
pub(crate) struct Serials(std::sync::Mutex<HashMap<DeviceIdentity, Option<u32>>>);

impl Serials {
    /// The serial of `identity`, read from the device the first time. Call it
    /// under the device's lock, before libfido2 opens it.
    fn of(&self, identity: &DeviceIdentity) -> Option<u32> {
        if let Some(serial) = self.lock().get(identity) {
            return *serial;
        }
        // Not under the lock: reading takes up to a second.
        match yubikey_serial(identity.path()) {
            Ok(serial) => {
                self.lock().insert(identity.clone(), serial);
                serial
            }
            Err(error) => {
                // Possibly transient (busy): asked again next time.
                tracing::debug!(
                    device = identity.path(),
                    error = %format!("{error:#}"),
                    "reading the security key's serial failed"
                );
                None
            }
        }
    }

    /// Forgets plug-ins that aren't connected any more.
    fn retain(&self, connected: &[DeviceIdentity]) {
        self.lock()
            .retain(|identity, _| connected.contains(identity));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<DeviceIdentity, Option<u32>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Router {
    bindings: Mutex<Bindings>,
    serials: Arc<Serials>,
    devices: KeyedLocks<DeviceIdentity>,
    pub credentials: KeyedLocks<CredentialKey>,
    /// Readers are assertions; a writer is touch selection across devices.
    access: Arc<RwLock<()>>,
    /// Shows "touch the key to use" while selecting.
    pub notifier: Option<Arc<Notifier>>,
}

/// These locks travel with the open device into blocking workers. Dropping an
/// async request cannot release them while a worker still uses the hardware.
pub(crate) struct RoutedDevice {
    pub identity: DeviceIdentity,
    /// The YubiKey's serial, if it reports one.
    pub serial: Option<u32>,
    /// The user picked the device by touch for this request.
    pub selected_by_touch: bool,
    pub device: Device,
    _operation: OwnedMutexGuard<()>,
    _access: OwnedRwLockReadGuard<()>,
}

impl Router {
    /// The bindings, locked. Callers that change them together with other
    /// state take every lock first and then change everything without
    /// awaiting, so a cancelled caller can't leave half of it done.
    pub async fn bindings(&self) -> MutexGuard<'_, Bindings> {
        self.bindings.lock().await
    }

    /// The device for `key`, described as `label` should the user have to
    /// select it by touch. `on_select` is called with the number of
    /// candidates right before a selection starts.
    pub async fn route(
        &self,
        key: &CredentialKey,
        ticket: SigningTicket,
        label: &str,
        on_select: Option<OnSelect>,
    ) -> Result<RoutedDevice> {
        self.route_key(Some(key), ticket, label, on_select).await
    }

    /// The device to load resident keys from, see [`Router::route`].
    pub async fn for_load(
        &self,
        ticket: SigningTicket,
        on_select: Option<OnSelect>,
    ) -> Result<RoutedDevice> {
        self.route_key(None, ticket, "", on_select).await
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
        label: &str,
        on_select: Option<OnSelect>,
    ) -> Result<RoutedDevice> {
        let read = within_queue_timeout(Arc::clone(&self.access).read_owned()).await?;
        ticket.check()?;
        let candidates = connected().await?;
        self.serials.retain(&candidates);
        let decision = self.resolve(key, &candidates).await?;
        if let Resolution::Direct(identity) = decision {
            return self.open_direct(identity, read).await;
        }
        drop(read);

        // Re-enumerate after obtaining exclusive access: another request may
        // have waited for a touch or changed a binding in the meantime.
        let exclusive = within_queue_timeout(Arc::clone(&self.access).write_owned()).await?;
        ticket.check()?;
        let candidates = connected().await?;
        let decision = self.resolve(key, &candidates).await?;
        if let Resolution::Direct(identity) = decision {
            return self.open_direct(identity, exclusive.downgrade()).await;
        }
        let body = if key.is_some() {
            tracing::info!(
                "touch the key holding the requested credential to select it; signing will need another touch"
            );
            format!("The one holding {label}. Signing then needs another touch.")
        } else {
            tracing::info!(
                "touch the security key whose resident SSH credentials you want to load"
            );
            "The one to load resident SSH keys from.".to_owned()
        };
        let _selecting = self
            .notifier
            .as_ref()
            .map(|notifier| notifier.show("Touch the security key to use", &body));
        if let Some(on_select) = on_select {
            on_select(candidates.len());
        }
        // Set when this request is dropped (client gone): the selection then
        // stops at its next round instead of blocking everyone for 30 s.
        let abandoned = Abandoned::default();
        let flag = abandoned.flag();
        let serials = Arc::clone(&self.serials);
        let (selected, exclusive) = tokio::task::spawn_blocking(move || {
            // Keep exclusive access until the worker stops, even if its caller
            // goes away. Outstanding probes are cancelled on drop.
            let selected = select_by_touch(candidates, &serials, &ticket, &flag)?;
            Ok::<_, anyhow::Error>((selected, exclusive))
        })
        .await
        .context("the device selection thread failed")??;
        let operation = self
            .devices
            .lock_within(selected.identity.clone(), QUEUE_TIMEOUT)
            .await?;
        Ok(RoutedDevice {
            identity: selected.identity,
            serial: selected.serial,
            selected_by_touch: true,
            device: selected.device,
            _operation: operation,
            _access: exclusive.downgrade(),
        })
    }

    async fn open_direct(
        &self,
        identity: DeviceIdentity,
        access: OwnedRwLockReadGuard<()>,
    ) -> Result<RoutedDevice> {
        let operation = self
            .devices
            .lock_within(identity.clone(), QUEUE_TIMEOUT)
            .await?;
        let serials = Arc::clone(&self.serials);
        tokio::task::spawn_blocking(move || {
            let (device, serial) = open_checked(&identity, &serials)?;
            Ok(RoutedDevice {
                identity,
                serial,
                selected_by_touch: false,
                device,
                _operation: operation,
                _access: access,
            })
        })
        .await
        .context("opening the routed security key in the device thread")?
    }
}

fn busy(waited: Duration) -> anyhow::Error {
    anyhow::anyhow!(
        "the security key is busy with other requests; gave up waiting after {} s",
        waited.as_secs()
    )
}

async fn within_queue_timeout<T>(wait: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::time::timeout(QUEUE_TIMEOUT, wait)
        .await
        .map_err(|_elapsed| busy(QUEUE_TIMEOUT))
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

/// Opens the plug-in `identity`, with its YubiKey serial (read first, while
/// libfido2 doesn't have the device open yet).
fn open_checked(identity: &DeviceIdentity, serials: &Serials) -> Result<(Device, Option<u32>)> {
    identity.ensure_present().context("before opening it")?;
    let serial = serials.of(identity);
    let device = Device::open(identity.path())?;
    identity.ensure_present().context("while opening it")?;
    Ok((device, serial))
}

/// The device a touch selected.
struct Selected {
    identity: DeviceIdentity,
    serial: Option<u32>,
    device: Device,
}

/// Asks every candidate for a touch and returns the one that got it.
///
/// A device that can't be asked, or that fails while waiting (unplugged,
/// gave up waiting for its own touch, refused), drops out of the selection
/// like in OpenSSH's `sk_select_by_touch`; the others keep waiting. Dropped
/// probes are cancelled. Selection fails when no candidate is left, two
/// devices report a touch in the same round, or nobody touches in time.
fn select_by_touch(
    identities: Vec<DeviceIdentity>,
    serials: &Serials,
    ticket: &SigningTicket,
    abandoned: &AbandonedFlag,
) -> Result<Selected> {
    let started = Instant::now();
    let mut probes = Vec::new();
    for identity in identities {
        ticket.check()?;
        let opened = open_checked(&identity, serials)
            .and_then(|(device, serial)| Ok((device.begin_touch()?, serial)));
        match opened {
            Ok((probe, serial)) => probes.push((identity, serial, probe)),
            Err(error) => tracing::warn!(
                device = identity.path(),
                error = %format!("{error:#}"),
                "leaving a security key out of touch selection"
            ),
        }
    }
    while started.elapsed() < SELECTION_TIMEOUT {
        ensure!(
            !probes.is_empty(),
            "no connected security key could be asked for a touch"
        );
        ticket.check()?;
        ensure!(
            !abandoned.is_set(),
            "the request went away, stopped the touch selection"
        );
        let mut touched: Vec<DeviceIdentity> = Vec::new();
        probes.retain_mut(|(identity, _, probe)| match probe.poll(TOUCH_POLL) {
            Ok(true) => {
                touched.push(identity.clone());
                true
            }
            Ok(false) => true,
            Err(error) => {
                tracing::warn!(
                    device = identity.path(),
                    error = %format!("{error:#}"),
                    "security key dropped out of touch selection"
                );
                false
            }
        });
        match touched.as_slice() {
            [] => {}
            [selected] => {
                let (identity, serial, probe) = probes
                    .into_iter()
                    .find(|(identity, _, _)| identity == selected)
                    .context("the touched security key disappeared from the candidates")?;
                identity.ensure_present().context("after it was selected")?;
                return Ok(Selected {
                    identity,
                    serial,
                    device: probe.finish()?,
                });
            }
            _ => bail!("several security keys were touched; touch only the one you mean"),
        }
    }
    bail!("timed out selecting a security key; touch the key holding this credential")
}
