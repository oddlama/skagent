//! The PIN cache, as a state machine over explicit time.
//!
//! Rules (see `docs/design.md`):
//! - Only PINs the device just accepted are stored, together with the
//!   identity of that device and its PIN retry counter right after.
//! - A cached PIN is only handed out for the same device identity and an
//!   unchanged retry counter. A lower counter means someone entered a wrong
//!   PIN since; a different identity means a replug or another device. Both
//!   drop the entry, so the caller asks the user instead.
//! - Entries end at a hard lifetime after creation, and optionally after an
//!   idle period. A lifetime of zero disables caching.
//! - Dropped entries are zeroized right away (`SecretBuffer`).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use skagent_secret::SecretBuffer;

use crate::device::DeviceIdentity;

/// Which credential a PIN belongs to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialKey {
    rp_id: String,
    key_handle: Vec<u8>,
}

impl CredentialKey {
    /// The credential `key_handle` of relying party `rp_id`.
    #[must_use]
    pub fn new(rp_id: &str, key_handle: &[u8]) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            key_handle: key_handle.to_vec(),
        }
    }
}

impl fmt::Debug for CredentialKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialKey")
            .field("rp_id", &self.rp_id)
            .field("key_handle_len", &self.key_handle.len())
            .finish()
    }
}

/// How long PINs are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// Hard limit since the PIN was entered. Zero disables caching.
    pub lifetime: Duration,
    /// Drop the PIN if it wasn't used for this long.
    pub idle_timeout: Option<Duration>,
}

impl CachePolicy {
    /// Default lifetime: a working day.
    pub const DEFAULT_LIFETIME: Duration = Duration::from_hours(8);

    /// Whether PINs are cached at all.
    #[must_use]
    pub fn caches(self) -> bool {
        !self.lifetime.is_zero()
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            lifetime: Self::DEFAULT_LIFETIME,
            idle_timeout: None,
        }
    }
}

/// Why no cached PIN was handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// Nothing cached for this credential.
    NotCached,
    /// The lifetime ended.
    Expired,
    /// Not used within the idle timeout.
    Idle,
    /// The device was replugged or is a different one.
    DeviceChanged,
    /// The retry counter changed since the PIN was stored: someone entered a
    /// wrong PIN in between (or the PIN was reset).
    RetriesChanged {
        /// Counter when the PIN was stored.
        stored: u32,
        /// Counter now.
        current: u32,
    },
}

impl fmt::Display for Miss {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCached => formatter.write_str("no PIN cached"),
            Self::Expired => formatter.write_str("the cached PIN reached its lifetime"),
            Self::Idle => formatter.write_str("the cached PIN was idle for too long"),
            Self::DeviceChanged => {
                formatter.write_str("the security key was replugged or replaced")
            }
            Self::RetriesChanged { stored, current } => write!(
                formatter,
                "the PIN retry counter changed from {stored} to {current} since the PIN was cached"
            ),
        }
    }
}

/// Result of a lookup.
#[derive(Debug)]
pub enum Lookup {
    /// A copy of the cached PIN, in its own locked buffer.
    Hit(SecretBuffer),
    /// No PIN; the entry, if there was one, is gone.
    Miss(Miss),
}

#[derive(Debug)]
struct Entry {
    pin: SecretBuffer,
    device: DeviceIdentity,
    retries: u32,
    created_at: Instant,
    last_used: Instant,
}

impl Entry {
    fn ended(&self, policy: CachePolicy, now: Instant) -> Option<Miss> {
        let expired = self
            .created_at
            .checked_add(policy.lifetime)
            .is_none_or(|end| now >= end);
        if expired {
            return Some(Miss::Expired);
        }
        let idle = policy.idle_timeout.is_some_and(|idle| {
            self.last_used
                .checked_add(idle)
                .is_none_or(|end| now >= end)
        });
        idle.then_some(Miss::Idle)
    }
}

/// Cached PINs, one per credential.
#[derive(Debug, Default)]
pub struct PinCache {
    policy: CachePolicy,
    entries: HashMap<CredentialKey, Entry>,
}

impl PinCache {
    /// An empty cache with `policy`.
    #[must_use]
    pub fn new(policy: CachePolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    /// The policy in use.
    #[must_use]
    pub fn policy(&self) -> CachePolicy {
        self.policy
    }

    /// Number of cached PINs (expired ones included until [`PinCache::expire`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The cached PIN for `key`, if it may be used on `device` whose retry
    /// counter reads `retries` at `now`. Any reason not to use it drops it.
    ///
    /// # Errors
    ///
    /// Returns an error if the copy of the PIN can't be allocated.
    pub fn lookup(
        &mut self,
        key: &CredentialKey,
        device: &DeviceIdentity,
        retries: u32,
        now: Instant,
    ) -> Result<Lookup> {
        let Some(entry) = self.entries.get(key) else {
            return Ok(Lookup::Miss(Miss::NotCached));
        };
        let miss = entry.ended(self.policy, now).or_else(|| {
            if entry.device != *device {
                Some(Miss::DeviceChanged)
            } else if entry.retries != retries {
                Some(Miss::RetriesChanged {
                    stored: entry.retries,
                    current: retries,
                })
            } else {
                None
            }
        });
        if let Some(miss) = miss {
            self.entries.remove(key);
            return Ok(Lookup::Miss(miss));
        }
        let pin = SecretBuffer::from_slice(entry.pin.expose()).context("copying the cached PIN")?;
        Ok(Lookup::Hit(pin))
    }

    /// Stores `pin` for `key` after `device` accepted it at `now` and its
    /// retry counter read `retries` afterwards. Replaces an existing entry and
    /// restarts its lifetime. Does nothing if caching is disabled.
    pub fn store(
        &mut self,
        key: CredentialKey,
        pin: SecretBuffer,
        device: DeviceIdentity,
        retries: u32,
        now: Instant,
    ) {
        if !self.policy.caches() {
            return;
        }
        self.entries.insert(
            key,
            Entry {
                pin,
                device,
                retries,
                created_at: now,
                last_used: now,
            },
        );
    }

    /// Records that the cached PIN for `key` was used successfully at `now`.
    /// The lifetime is not extended.
    pub fn mark_used(&mut self, key: &CredentialKey, now: Instant) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_used = now;
        }
    }

    /// Drops the PIN for `key`. Returns whether there was one.
    pub fn evict(&mut self, key: &CredentialKey) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Drops every PIN tied to a device that rejected a loading PIN.
    pub fn evict_device(&mut self, device: &DeviceIdentity) {
        self.entries.retain(|_, entry| entry.device != *device);
    }

    /// Drops all PINs. Returns how many there were.
    pub fn clear(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    /// Drops the PINs whose lifetime or idle timeout ended at `now`. Returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let policy = self.policy;
        self.entries
            .retain(|_, entry| entry.ended(policy, now).is_none());
        before.saturating_sub(self.entries.len())
    }
}
