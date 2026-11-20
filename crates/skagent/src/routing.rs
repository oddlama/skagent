//! Finding the device for a request, and device-operation serialization.
//!
//! Bound devices can sign concurrently. Selecting an unbound credential takes
//! exclusive access to all devices, so its touch probes cannot steal a touch
//! from an assertion. No PIN is involved in selection. A request whose
//! security key isn't plugged in waits for it, up to the plug-in timeout.

use std::collections::HashMap;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use skagent_fido::{Device, ErrorKind, PairingCredential, error_kind, hid_devices, yubikey_serial};
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

use crate::bindings::{
    Bindings, Missing, NotPluggedIn, Presence, Resolution, SerialClaimedTwice, Unrecognized,
};
use crate::cancel::{Abandoned, AbandonedFlag};
use crate::device::DeviceIdentity;
use crate::notify::Notifier;
use crate::pairing::{self, Proof};
use crate::pin_cache::CredentialKey;
use crate::signer::SigningTicket;

/// How long a touch selection waits.
pub(crate) const SELECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Called with the number of candidates when a touch selection starts. The
/// selection waits for what it returns: the security keys blink once the
/// user was told why, and not at all if that failed.
pub(crate) type OnSelect =
    Box<dyn FnOnce(usize) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send>;

/// Called when a request starts waiting for its security key, and whenever
/// what it waits for changes (e.g. the wrong one was plugged in).
pub(crate) type OnWait = Box<dyn FnMut(Missing) + Send>;

/// How often a request waiting for its security key looks for it.
const PLUG_IN_POLL: Duration = Duration::from_millis(250);

/// How long reading a new plug-in's serial waits for the device. Devices
/// busy with another request had their serial read when they were opened.
const SERIAL_LOCK_WAIT: Duration = Duration::from_millis(100);

/// Longest wait for a busy security key or credential. A request ahead can
/// hold a key for a PIN prompt (60 s) plus a touch (35 s); this lets one such
/// request finish, but stops requests from piling up behind an unresponsive
/// key forever.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(120);
const TOUCH_POLL: Duration = Duration::from_millis(50);

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

    /// The serial of `identity` if it was read, without reading it.
    fn cached(&self, identity: &DeviceIdentity) -> Option<u32> {
        self.lock().get(identity).copied().flatten()
    }

    /// Whether the serial of `identity` was read (reporting one or none).
    fn known(&self, identity: &DeviceIdentity) -> bool {
        self.lock().contains_key(identity)
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

/// What plug-ins answered to pairing challenges, by the pairing's public
/// key. Only definite answers: a plug-in can't become another device, so it
/// is asked once.
#[derive(Debug, Default)]
pub(crate) struct Proofs(std::sync::Mutex<HashMap<(DeviceIdentity, [u8; 32]), bool>>);

impl Proofs {
    fn get(&self, identity: &DeviceIdentity, public_key: &[u8; 32]) -> Proof {
        match self.lock().get(&(identity.clone(), *public_key)) {
            Some(true) => Proof::Proven,
            Some(false) => Proof::Disproven,
            None => Proof::Unknown,
        }
    }

    fn set(&self, identity: &DeviceIdentity, public_key: &[u8; 32], proven: bool) {
        self.lock().insert((identity.clone(), *public_key), proven);
    }

    /// Forgets plug-ins that aren't connected any more.
    fn retain(&self, connected: &[DeviceIdentity]) {
        self.lock()
            .retain(|(identity, _), _| connected.contains(identity));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(DeviceIdentity, [u8; 32]), bool>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Router {
    bindings: Mutex<Bindings>,
    serials: Arc<Serials>,
    proofs: Arc<Proofs>,
    devices: KeyedLocks<DeviceIdentity>,
    pub credentials: KeyedLocks<CredentialKey>,
    /// Readers are assertions; a writer is touch selection across devices.
    access: Arc<RwLock<()>>,
    /// Shows "touch the key to use" while selecting.
    pub notifier: Option<Arc<Notifier>>,
    /// How long a request waits for its security key to be plugged in.
    pub plug_in_timeout: Duration,
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
    /// The same router, starting from `bindings`.
    #[must_use]
    pub fn with_bindings(mut self, bindings: Bindings) -> Self {
        self.bindings = Mutex::new(bindings);
        self
    }

    /// The bindings, locked. Callers that change them together with other
    /// state take every lock first and then change everything without
    /// awaiting, so a cancelled caller can't leave half of it done.
    pub async fn bindings(&self) -> MutexGuard<'_, Bindings> {
        self.bindings.lock().await
    }

    /// The device for `key`, described as `label` should the user have to
    /// select it by touch. `on_select` is called with the number of
    /// candidates right before a selection starts, `on_wait` when the
    /// request waits for its security key to be plugged in.
    pub async fn route(
        &self,
        key: &CredentialKey,
        ticket: SigningTicket,
        label: &str,
        on_select: Option<OnSelect>,
        on_wait: Option<OnWait>,
    ) -> Result<RoutedDevice> {
        self.route_key(Some(key), ticket, label, on_select, on_wait)
            .await
    }

    /// The device to load resident keys from, see [`Router::route`].
    pub async fn for_load(
        &self,
        ticket: SigningTicket,
        on_select: Option<OnSelect>,
        on_wait: Option<OnWait>,
    ) -> Result<RoutedDevice> {
        self.route_key(None, ticket, "", on_select, on_wait).await
    }

    /// Where each of `keys` is right now, to list the ones on a plugged-in
    /// security key first. Reads the serials and pairing proofs the bindings
    /// need, like routing does (once per plug-in); touches no device when
    /// none of the keys has a binding.
    pub async fn presence(&self, keys: &[CredentialKey]) -> Vec<Presence> {
        let unknown = vec![Presence::Unknown; keys.len()];
        let known = {
            let bindings = self.bindings.lock().await;
            keys.iter().any(|key| bindings.knows(key))
        };
        if !known {
            return unknown;
        }
        let candidates = match connected().await {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "can't list security keys to order keys");
                return unknown;
            }
        };
        self.serials.retain(&candidates);
        self.proofs.retain(&candidates);
        let (needs_serials, mut pairings) = {
            let bindings = self.bindings.lock().await;
            let needs_serials = keys
                .iter()
                .any(|key| bindings.needs_serials(Some(key), &candidates));
            let pairings: Vec<PairingCredential> = keys
                .iter()
                .filter_map(|key| bindings.needs_proof(Some(key), &candidates).cloned())
                .collect();
            (needs_serials, pairings)
        };
        if needs_serials {
            self.learn_serials(&candidates).await;
        }
        // Keys on one security key share its pairing.
        pairings.sort_by_key(|pairing| pairing.public_key);
        pairings.dedup_by(|left, right| left.public_key == right.public_key);
        for pairing in &pairings {
            self.prove(pairing, &candidates).await;
        }
        let (serials, proofs) = (&self.serials, &self.proofs);
        let bindings = self.bindings.lock().await;
        keys.iter()
            .map(|key| {
                let pairing = bindings
                    .needs_proof(Some(key), &candidates)
                    .map(|pairing| pairing.public_key);
                bindings.presence(
                    key,
                    &candidates,
                    |identity| serials.cached(identity),
                    |identity| {
                        pairing.map_or(Proof::Unknown, |public_key| {
                            proofs.get(identity, &public_key)
                        })
                    },
                )
            })
            .collect()
    }

    /// The connected devices, with the serials and pairing proofs resolving
    /// `key` needs.
    async fn candidates(&self, key: Option<&CredentialKey>) -> Result<Vec<DeviceIdentity>> {
        let candidates = connected().await?;
        self.serials.retain(&candidates);
        self.proofs.retain(&candidates);
        let (needs_serials, pairing) = {
            let bindings = self.bindings.lock().await;
            (
                bindings.needs_serials(key, &candidates),
                bindings.needs_proof(key, &candidates).cloned(),
            )
        };
        if needs_serials {
            self.learn_serials(&candidates).await;
        }
        if let Some(pairing) = pairing {
            self.prove(&pairing, &candidates).await;
        }
        Ok(candidates)
    }

    /// Challenges the plug-ins not asked yet to prove `pairing`, each under
    /// its device lock, silently (no touch, no PIN).
    async fn prove(&self, pairing: &PairingCredential, candidates: &[DeviceIdentity]) {
        for identity in candidates {
            if self.proofs.get(identity, &pairing.public_key) != Proof::Unknown {
                continue;
            }
            let Ok(operation) = self
                .devices
                .lock_within(identity.clone(), SERIAL_LOCK_WAIT)
                .await
            else {
                continue;
            };
            let (serials, proofs) = (Arc::clone(&self.serials), Arc::clone(&self.proofs));
            let (identity, pairing) = (identity.clone(), pairing.clone());
            // The device lock goes along, as for serials.
            let asked = tokio::task::spawn_blocking(move || {
                let _operation = operation;
                let proof = challenge(&identity, &serials, &pairing);
                tracing::debug!(
                    device = identity.path(),
                    ?proof,
                    "asked for skagent's pairing"
                );
                match proof {
                    Proof::Proven => proofs.set(&identity, &pairing.public_key, true),
                    Proof::Disproven => proofs.set(&identity, &pairing.public_key, false),
                    Proof::Unknown => {}
                }
            })
            .await;
            if let Err(error) = asked {
                tracing::debug!(%error, "the pairing challenge thread failed");
            }
        }
    }

    /// Reads the serials of new plug-ins, each under its device lock.
    async fn learn_serials(&self, candidates: &[DeviceIdentity]) {
        for identity in candidates {
            if self.serials.known(identity) {
                continue;
            }
            let Ok(operation) = self
                .devices
                .lock_within(identity.clone(), SERIAL_LOCK_WAIT)
                .await
            else {
                continue;
            };
            let serials = Arc::clone(&self.serials);
            let identity = identity.clone();
            // The device lock goes along: dropping this request can't
            // release it while the worker still talks to the device.
            let read = tokio::task::spawn_blocking(move || {
                let _operation = operation;
                serials.of(&identity);
            })
            .await;
            if let Err(error) = read {
                tracing::debug!(%error, "the serial reading thread failed");
            }
        }
    }

    async fn resolve(
        &self,
        key: Option<&CredentialKey>,
        candidates: &[DeviceIdentity],
    ) -> Resolution {
        let (serials, proofs) = (&self.serials, &self.proofs);
        let bindings = self.bindings.lock().await;
        let pairing = bindings
            .needs_proof(key, candidates)
            .map(|pairing| pairing.public_key);
        bindings.resolve(
            key,
            candidates,
            |identity| serials.cached(identity),
            |identity| {
                pairing.map_or(Proof::Unknown, |public_key| {
                    proofs.get(identity, &public_key)
                })
            },
        )
    }

    async fn route_key(
        &self,
        key: Option<&CredentialKey>,
        ticket: SigningTicket,
        label: &str,
        on_select: Option<OnSelect>,
        mut on_wait: Option<OnWait>,
    ) -> Result<RoutedDevice> {
        let started = Instant::now();
        let mut waiting_for = None;
        loop {
            let read = within_queue_timeout(Arc::clone(&self.access).read_owned()).await?;
            ticket.check()?;
            let candidates = self.candidates(key).await?;
            match self.resolve(key, &candidates).await {
                Resolution::Direct(identity) => return self.open_direct(identity, read).await,
                Resolution::Touch => break,
                Resolution::Ambiguous { serial } => return Err(claimed_twice(serial)),
                Resolution::Unrecognized { serial } => return Err(unrecognized(serial)),
                Resolution::Wait(missing) => {
                    drop(read);
                    if started.elapsed() >= self.plug_in_timeout {
                        return Err(NotPluggedIn {
                            serial: missing.serial(),
                        }
                        .into());
                    }
                    if waiting_for != Some(missing) {
                        tracing::info!(
                            serial = missing.serial(),
                            timeout_secs = self.plug_in_timeout.as_secs(),
                            "waiting for the security key to be plugged in"
                        );
                        if let Some(on_wait) = on_wait.as_mut() {
                            on_wait(missing);
                        }
                        waiting_for = Some(missing);
                    }
                    tokio::time::sleep(PLUG_IN_POLL).await;
                }
            }
        }
        // Closes a notification asking to plug the key in.
        drop(on_wait);

        // Re-enumerate after obtaining exclusive access: another request may
        // have waited for a touch or changed a binding in the meantime.
        let exclusive = within_queue_timeout(Arc::clone(&self.access).write_owned()).await?;
        ticket.check()?;
        let candidates = self.candidates(key).await?;
        match self.resolve(key, &candidates).await {
            Resolution::Direct(identity) => {
                return self.open_direct(identity, exclusive.downgrade()).await;
            }
            // Unplugged since: no more waiting.
            Resolution::Wait(missing) => {
                return Err(NotPluggedIn {
                    serial: missing.serial(),
                }
                .into());
            }
            Resolution::Ambiguous { serial } => return Err(claimed_twice(serial)),
            Resolution::Unrecognized { serial } => return Err(unrecognized(serial)),
            Resolution::Touch => {}
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
            on_select(candidates.len()).await?;
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

/// Refuses a request because two devices claim to be the bound key.
fn claimed_twice(serial: Option<u32>) -> anyhow::Error {
    tracing::warn!(
        serial,
        "two plugged-in security keys claim to be the one holding the key; one of them pretends, \
         refusing the request"
    );
    SerialClaimedTwice { serial }.into()
}

/// Refuses a request because the device claiming a paired key's serial
/// can't prove the pairing.
fn unrecognized(serial: u32) -> anyhow::Error {
    tracing::warn!(
        serial,
        "a security key reports the serial of the paired YubiKey but can't prove skagent's \
         pairing; refusing the request"
    );
    Unrecognized { serial }.into()
}

/// Asks the plug-in `identity` to prove `pairing`.
fn challenge(identity: &DeviceIdentity, serials: &Serials, pairing: &PairingCredential) -> Proof {
    let answer = pairing::challenge().and_then(|challenge| {
        let (mut device, _) = open_checked(identity, serials)?;
        let statement = device.sign_challenge(pairing, challenge)?;
        Ok(pairing::verify(pairing, &challenge, &statement))
    });
    match answer {
        Ok(true) => Proof::Proven,
        Ok(false) => Proof::Disproven,
        Err(error) if error_kind(&error) == Some(ErrorKind::NoCredentials) => Proof::Disproven,
        Err(error) => {
            tracing::debug!(
                device = identity.path(),
                error = %format!("{error:#}"),
                "a pairing challenge failed"
            );
            Proof::Unknown
        }
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
