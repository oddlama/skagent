//! Credential storage for the test key.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use soft_fido2::{
    AuthenticatorCallbacks, Credential, CredentialRef, Error, Result, UpResult, UvResult,
};

type Store = Arc<Mutex<HashMap<Vec<u8>, Credential>>>;

/// In-memory credential store. Touch is decided by the CTAP wrapper, see
/// [`crate::ctap`], so soft-fido2's own presence check always passes.
#[derive(Debug, Default)]
pub struct Callbacks {
    credentials: Store,
}

impl Callbacks {
    /// A handle on the same store, for undoing credentials whose creation
    /// wasn't confirmed by a touch.
    #[must_use]
    pub fn undo_handle(&self) -> UndoHandle {
        UndoHandle {
            credentials: Arc::clone(&self.credentials),
        }
    }

    fn store(&self) -> Result<MutexGuard<'_, HashMap<Vec<u8>, Credential>>> {
        self.credentials.lock().map_err(|_poisoned| Error::Other)
    }
}

/// Removes credentials created after a snapshot.
#[derive(Debug)]
pub struct UndoHandle {
    credentials: Store,
}

/// The credential ids that existed at some point.
#[derive(Debug)]
pub struct Snapshot(HashSet<Vec<u8>>);

impl UndoHandle {
    /// Records which credentials exist now.
    ///
    /// # Errors
    ///
    /// Returns an error if the store's lock is poisoned.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let store = self.credentials.lock().map_err(|_poisoned| Error::Other)?;
        Ok(Snapshot(store.keys().cloned().collect()))
    }

    /// Removes every credential that didn't exist at `snapshot`. Returns how many.
    ///
    /// # Errors
    ///
    /// Returns an error if the store's lock is poisoned.
    pub fn undo_since(&self, snapshot: &Snapshot) -> Result<usize> {
        let mut store = self.credentials.lock().map_err(|_poisoned| Error::Other)?;
        let before = store.len();
        store.retain(|id, _| snapshot.0.contains(id));
        Ok(before.saturating_sub(store.len()))
    }
}

impl AuthenticatorCallbacks for Callbacks {
    fn request_up(&self, info: &str, _user_name: Option<&str>, rp_id: &str) -> Result<UpResult> {
        tracing::debug!(
            rp_id,
            info,
            "soft-fido2 presence check, already answered by the CTAP wrapper"
        );
        Ok(UpResult::Accepted)
    }

    fn request_uv(&self, info: &str, _user_name: Option<&str>, rp_id: &str) -> Result<UvResult> {
        // The key has no built-in user verification, only the client PIN.
        tracing::warn!(
            rp_id,
            info,
            "built-in user verification requested, refusing"
        );
        Ok(UvResult::Denied)
    }

    fn write_credential(&self, credential: &CredentialRef) -> Result<()> {
        let credential = credential.to_owned();
        tracing::info!(
            rp_id = %credential.rp.id,
            discoverable = credential.discoverable,
            cred_protect = credential.extensions.cred_protect,
            "credential created"
        );
        self.store()?.insert(credential.id.clone(), credential);
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        Ok(self.store()?.get(cred_id).cloned())
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        self.store()?.remove(cred_id);
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        Ok(self
            .store()?
            .values()
            .filter(|credential| credential.rp.id == rp_id)
            .filter(|credential| user_id.is_none_or(|user_id| credential.user.id == user_id))
            .cloned()
            .collect())
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        let mut relying_parties: Vec<(String, Option<String>, usize)> = Vec::new();
        for credential in self
            .store()?
            .values()
            .filter(|credential| credential.discoverable)
        {
            match relying_parties
                .iter_mut()
                .find(|(rp_id, _, _)| *rp_id == credential.rp.id)
            {
                Some((_, _, count)) => *count = count.saturating_add(1),
                None => {
                    relying_parties.push((credential.rp.id.clone(), credential.rp.name.clone(), 1));
                }
            }
        }
        Ok(relying_parties)
    }

    fn credential_count(&self) -> Result<usize> {
        Ok(self
            .store()?
            .values()
            .filter(|credential| credential.discoverable)
            .count())
    }

    fn get_timestamp_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}
