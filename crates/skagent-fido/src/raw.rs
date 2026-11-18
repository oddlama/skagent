//! Owning wrappers around libfido2 objects. All `unsafe` of the crate lives here.
//!
//! libfido2 objects are opaque pointers with `*_new`/`*_free` pairs. Each
//! wrapper owns exactly one object, frees it on drop and only hands out
//! borrowed data whose lifetime is tied to the wrapper.

use std::ffi::{CStr, CString, c_int};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, Once, PoisonError};

use libfido2_sys as sys;

use crate::error::FidoError;

static INIT: Once = Once::new();

/// Initializes libfido2 once per process, before the first object is created.
fn init() {
    INIT.call_once(|| {
        // SAFETY: fido_init only sets library-global flags; `Once` makes sure
        // it runs exactly once and before any other libfido2 call of ours.
        unsafe { sys::fido_init(0) };
    });
}

fn check(operation: &'static str, code: c_int) -> Result<(), FidoError> {
    if code == sys::FIDO_OK {
        Ok(())
    } else {
        Err(FidoError::new(operation, code))
    }
}

/// libfido2's description of a return code.
pub(crate) fn error_message(code: i32) -> String {
    // SAFETY: fido_strerr returns a pointer to a static, NUL-terminated
    // string for every input, including unknown codes.
    let message = unsafe { sys::fido_strerr(code) };
    if message.is_null() {
        return "unknown error".to_owned();
    }
    // SAFETY: non-null, static and NUL-terminated, see above.
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

/// Copies a C string owned by libfido2. Null becomes empty.
///
/// # Safety
///
/// `pointer` must be null or point to a NUL-terminated string that stays
/// valid for the duration of the call.
unsafe fn owned_string(pointer: *const std::ffi::c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// One entry of the device list, copied out of libfido2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedDevice {
    pub path: String,
    pub manufacturer: String,
    pub product: String,
}

/// Lists up to `max` devices.
pub(crate) fn list_devices(max: usize) -> Result<Vec<ListedDevice>, FidoError> {
    init();
    // SAFETY: allocates an array of `max` empty entries, or returns null.
    let list = unsafe { sys::fido_dev_info_new(max) };
    if list.is_null() {
        return Err(FidoError::new("fido_dev_info_new", sys::FIDO_ERR_INTERNAL));
    }
    let mut found: usize = 0;
    // SAFETY: `list` has room for `max` entries; libfido2 writes at most that
    // many and stores the number in `found`.
    let status = unsafe { sys::fido_dev_info_manifest(list, max, &raw mut found) };
    let devices = check("fido_dev_info_manifest", status).map(|()| {
        (0..found.min(max))
            .filter_map(|index| {
                // SAFETY: `index < found <= max`, so the entry exists.
                let entry = unsafe { sys::fido_dev_info_ptr(list, index) };
                if entry.is_null() {
                    return None;
                }
                // `entry` is a valid entry of `list`, which outlives these
                // calls; each string is copied before `list` is freed.
                // SAFETY: valid entry; returns a string owned by the entry.
                let path = unsafe { sys::fido_dev_info_path(entry) };
                // SAFETY: as above.
                let manufacturer = unsafe { sys::fido_dev_info_manufacturer_string(entry) };
                // SAFETY: as above.
                let product = unsafe { sys::fido_dev_info_product_string(entry) };
                // SAFETY: null or NUL-terminated strings of the live entry.
                let path = unsafe { owned_string(path) };
                // SAFETY: as above.
                let manufacturer = unsafe { owned_string(manufacturer) };
                // SAFETY: as above.
                let product = unsafe { owned_string(product) };
                Some(ListedDevice {
                    path,
                    manufacturer,
                    product,
                })
            })
            .collect()
    });
    let mut list = list;
    // SAFETY: `list` came from fido_dev_info_new(max) and is freed once; the
    // call nulls our pointer.
    unsafe { sys::fido_dev_info_free(&raw mut list, max) };
    devices
}

/// An open device.
pub(crate) struct Device {
    raw: NonNull<sys::fido_dev_t>,
    touch_pending: bool,
    /// Lets other threads cancel the request running on this handle.
    cancel: Arc<CancelSlot>,
}

/// The device handle as seen by cancellers: present while the device is
/// open, cleared (under the lock) before it is closed and freed.
pub(crate) struct CancelSlot(Mutex<Option<SharedHandle>>);

struct SharedHandle(NonNull<sys::fido_dev_t>);

// SAFETY: the pointer is only used through `CancelSlot::cancel`, under the
// slot's lock, for the one libfido2 call that may run concurrently with the
// owner's operations (see there).
unsafe impl Send for SharedHandle {}

impl CancelSlot {
    /// Sends `CTAPHID_CANCEL` on the device's channel, from any thread. A
    /// request waiting for a touch then fails with `KEEPALIVE_CANCEL`; with
    /// nothing pending the authenticator ignores it.
    pub(crate) fn cancel(&self) -> Result<(), FidoError> {
        let handle = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(SharedHandle(raw)) = handle.as_ref() else {
            return Err(FidoError::new(
                "fido_dev_cancel",
                sys::FIDO_ERR_INVALID_ARGUMENT,
            ));
        };
        // SAFETY: the handle is open: `Device::drop` empties the slot under
        // this lock before closing it, so it can't be closed or freed while
        // we hold the lock. The owner may be inside another libfido2 call on
        // the same handle on another thread; that is what this is for, and
        // it is free of data races in libfido2 1.17: fido_dev_cancel only
        // reads fields that are written by fido_dev_open, fido_dev_set_timeout,
        // fido_dev_set_pin and fido_dev_force_* (cid, tx_len, attr.flags,
        // io, io_handle, transport, timeout_ms), and this crate calls none of
        // those after `Device::open` returned. It then writes a single HID
        // report with write(2); concurrent read(2)/write(2) on one hidraw fd
        // are fine. Debug logging, which uses global state, is never enabled:
        // `fido_init` gets no flags, and the safe wrapper refuses to touch
        // libfido2 while FIDO_DEBUG is set (`ensure_debug_off`).
        check("fido_dev_cancel", unsafe {
            sys::fido_dev_cancel(raw.as_ptr())
        })
    }
}

// SAFETY: a fido_dev_t is used by one thread at a time; `Device` is only
// usable through `&mut self` and isn't `Sync`, so moving it between threads
// (e.g. into `spawn_blocking`) is fine.
unsafe impl Send for Device {}

impl Device {
    pub(crate) fn open(path: &CStr) -> Result<Self, FidoError> {
        init();
        // SAFETY: allocates a closed device handle, or returns null.
        let raw = NonNull::new(unsafe { sys::fido_dev_new() })
            .ok_or_else(|| FidoError::new("fido_dev_new", sys::FIDO_ERR_INTERNAL))?;
        let device = Self {
            raw,
            touch_pending: false,
            cancel: Arc::new(CancelSlot(Mutex::new(Some(SharedHandle(raw))))),
        };
        // SAFETY: `raw` is a fresh handle and `path` is NUL-terminated.
        check("fido_dev_open", unsafe {
            sys::fido_dev_open(device.raw.as_ptr(), path.as_ptr())
        })?;
        Ok(device)
    }

    /// The cancel slot of this handle. Must only be handed out after
    /// `set_timeout`, see `CancelSlot::cancel`.
    pub(crate) fn cancel_slot(&self) -> Arc<CancelSlot> {
        Arc::clone(&self.cancel)
    }

    pub(crate) fn set_timeout(&mut self, milliseconds: c_int) -> Result<(), FidoError> {
        // SAFETY: `raw` is an open device owned by `self`.
        check("fido_dev_set_timeout", unsafe {
            sys::fido_dev_set_timeout(self.raw.as_ptr(), milliseconds)
        })
    }

    pub(crate) fn supports_credman(&self) -> bool {
        // SAFETY: reads capabilities of our open device, without mutation.
        unsafe { sys::fido_dev_supports_credman(self.raw.as_ptr()) }
    }

    /// The extensions the device lists in `authenticatorGetInfo`.
    pub(crate) fn extensions(&mut self) -> Result<Vec<String>, FidoError> {
        // SAFETY: creates an empty owned info object, or null on failure.
        let info = Info(
            NonNull::new(unsafe { sys::fido_cbor_info_new() })
                .ok_or_else(|| FidoError::new("fido_cbor_info_new", sys::FIDO_ERR_INTERNAL))?,
        );
        // SAFETY: exclusive open device and an owned output object. The call
        // only sends and receives on the device and fills `info`; it writes
        // none of the device fields `CancelSlot::cancel` reads.
        check("fido_dev_get_cbor_info", unsafe {
            sys::fido_dev_get_cbor_info(self.raw.as_ptr(), info.0.as_ptr())
        })?;
        // SAFETY: populated info; returns an array owned by it, or null.
        let pointer = unsafe { sys::fido_cbor_info_extensions_ptr(info.0.as_ptr()) };
        // SAFETY: as above; only reads.
        let length = unsafe { sys::fido_cbor_info_extensions_len(info.0.as_ptr()) };
        if pointer.is_null() || length == 0 {
            return Ok(Vec::new());
        }
        if length > 64 {
            return Err(FidoError::new(
                "extension count exceeds 64",
                sys::FIDO_ERR_INTERNAL,
            ));
        }
        // SAFETY: libfido2's pointer and length for the array of string
        // pointers, valid while `info` lives, which is past this function's
        // last use of them.
        let entries = unsafe { std::slice::from_raw_parts(pointer, length) };
        Ok(entries
            .iter()
            // SAFETY: null or a NUL-terminated string owned by the live info.
            .map(|&entry| unsafe { owned_string(entry) })
            .collect())
    }

    pub(crate) fn resident_rps(&mut self, pin: &CStr) -> Result<Vec<String>, FidoError> {
        // SAFETY: creates an empty owned RP list, or null on allocation failure.
        let list = ResidentParties(
            NonNull::new(unsafe { sys::fido_credman_rp_new() })
                .ok_or_else(|| FidoError::new("fido_credman_rp_new", sys::FIDO_ERR_INTERNAL))?,
        );
        // SAFETY: exclusive device, valid owned output list and NUL-terminated PIN.
        check("fido_credman_get_dev_rp", unsafe {
            sys::fido_credman_get_dev_rp(self.raw.as_ptr(), list.0.as_ptr(), pin.as_ptr())
        })?;
        // SAFETY: populated list, alive for this entire loop.
        let count = unsafe { sys::fido_credman_rp_count(list.0.as_ptr()) };
        if count > 1024 {
            return Err(FidoError::new(
                "resident RP count exceeds 1024",
                sys::FIDO_ERR_INTERNAL,
            ));
        }
        (0..count)
            .map(|index| {
                // SAFETY: populated list and an in-bounds index; returns a
                // string owned by the list, or null.
                let id = unsafe { sys::fido_credman_rp_id(list.0.as_ptr(), index) };
                // SAFETY: null or NUL-terminated, copied before the list drops.
                let id = unsafe { owned_string(id) };
                if id.is_empty() {
                    return Err(FidoError::new(
                        "empty resident RP id",
                        sys::FIDO_ERR_INTERNAL,
                    ));
                }
                Ok(id)
            })
            .collect()
    }

    /// Verifies `pin` by reading credential management metadata: the device
    /// trades the PIN for a token, without a touch and without signing.
    pub(crate) fn credman_metadata(&mut self, pin: &CStr) -> Result<(), FidoError> {
        // SAFETY: creates an empty owned metadata object, or null on failure.
        let metadata = Metadata(
            NonNull::new(unsafe { sys::fido_credman_metadata_new() }).ok_or_else(|| {
                FidoError::new("fido_credman_metadata_new", sys::FIDO_ERR_INTERNAL)
            })?,
        );
        // SAFETY: exclusive device, owned output object and NUL-terminated PIN.
        check("fido_credman_get_dev_metadata", unsafe {
            sys::fido_credman_get_dev_metadata(self.raw.as_ptr(), metadata.0.as_ptr(), pin.as_ptr())
        })
    }

    pub(crate) fn resident_keys(
        &mut self,
        rp: &CStr,
        pin: &CStr,
    ) -> Result<Vec<ResidentKey>, FidoError> {
        // SAFETY: creates an empty owned credential list, or null on failure.
        let list = ResidentKeys(
            NonNull::new(unsafe { sys::fido_credman_rk_new() })
                .ok_or_else(|| FidoError::new("fido_credman_rk_new", sys::FIDO_ERR_INTERNAL))?,
        );
        // SAFETY: exclusive device, owned output list, RP and PIN live through the call.
        check("fido_credman_get_dev_rk", unsafe {
            sys::fido_credman_get_dev_rk(
                self.raw.as_ptr(),
                rp.as_ptr(),
                list.0.as_ptr(),
                pin.as_ptr(),
            )
        })?;
        // SAFETY: populated, live credential list.
        let count = unsafe { sys::fido_credman_rk_count(list.0.as_ptr()) };
        if count > 1024 {
            return Err(FidoError::new(
                "resident credential count exceeds 1024",
                sys::FIDO_ERR_INTERNAL,
            ));
        }
        let mut keys = Vec::new();
        for index in 0..count {
            // SAFETY: in-bounds index; the borrowed credential lives until list drops.
            let key = unsafe { sys::fido_credman_rk(list.0.as_ptr(), index) };
            if key.is_null() {
                return Err(FidoError::new(
                    "null resident credential",
                    sys::FIDO_ERR_INTERNAL,
                ));
            }
            // `key` is a valid credential borrowed from `list`; every blob
            // and string is copied before `list` is freed. Only EdDSA keys
            // are returned.
            // SAFETY: valid credential; only reads.
            if unsafe { sys::fido_cred_type(key) } != sys::COSE_EDDSA {
                continue;
            }
            // SAFETY: valid credential; returns a pointer into it, or null.
            let public_key = unsafe { sys::fido_cred_pubkey_ptr(key) };
            // SAFETY: valid credential; only reads.
            let public_key_len = unsafe { sys::fido_cred_pubkey_len(key) };
            // SAFETY: valid credential; returns a pointer into it, or null.
            let key_handle = unsafe { sys::fido_cred_id_ptr(key) };
            // SAFETY: valid credential; only reads.
            let key_handle_len = unsafe { sys::fido_cred_id_len(key) };
            // SAFETY: valid credential; only reads.
            let protection = unsafe { sys::fido_cred_prot(key) };
            // SAFETY: valid credential; returns a string owned by it, or null.
            let user_name = unsafe { sys::fido_cred_user_name(key) };
            keys.push(ResidentKey {
                // SAFETY: pointer and length libfido2 gave for the live credential.
                public_key: unsafe { copy_credential_blob(public_key, public_key_len) }?,
                // SAFETY: as above.
                key_handle: unsafe { copy_credential_blob(key_handle, key_handle_len) }?,
                protection,
                // SAFETY: null or NUL-terminated string of the live credential.
                user_name: unsafe { owned_string(user_name) },
            });
        }
        Ok(keys)
    }

    pub(crate) fn is_fido2(&self) -> bool {
        // SAFETY: `raw` is an open device owned by `self`; the call only reads.
        unsafe { sys::fido_dev_is_fido2(self.raw.as_ptr()) }
    }

    pub(crate) fn touch_begin(&mut self) -> Result<(), FidoError> {
        // SAFETY: exclusive access to an open device. This sends a request;
        // touch_status will read its response on this same handle.
        check("fido_dev_get_touch_begin", unsafe {
            sys::fido_dev_get_touch_begin(self.raw.as_ptr())
        })?;
        self.touch_pending = true;
        Ok(())
    }

    pub(crate) fn touch_status(&mut self, milliseconds: c_int) -> Result<bool, FidoError> {
        let mut touched = 0;
        // SAFETY: exclusive access; `touched` is a valid output pointer and
        // milliseconds bounds this poll. No other operation uses this handle.
        check("fido_dev_get_touch_status", unsafe {
            sys::fido_dev_get_touch_status(self.raw.as_ptr(), &raw mut touched, milliseconds)
        })?;
        if touched != 0 {
            self.touch_pending = false;
        }
        Ok(touched != 0)
    }

    pub(crate) fn pin_retries(&mut self) -> Result<u32, FidoError> {
        let mut retries: c_int = 0;
        // SAFETY: `raw` is an open device owned by `self`; `retries` is a valid out pointer.
        check("fido_dev_get_retry_count", unsafe {
            sys::fido_dev_get_retry_count(self.raw.as_ptr(), &raw mut retries)
        })?;
        u32::try_from(retries)
            .map_err(|_| FidoError::new("fido_dev_get_retry_count", sys::FIDO_ERR_INTERNAL))
    }

    /// Creates `credential` on the device. `pin` must be NUL-terminated if
    /// given.
    pub(crate) fn make_cred(
        &mut self,
        credential: &mut Credential,
        pin: Option<&CStr>,
    ) -> Result<(), FidoError> {
        let pin = pin.map_or(std::ptr::null(), CStr::as_ptr);
        // SAFETY: device and credential are valid objects owned by their
        // wrappers; `pin` is null or NUL-terminated and outlives the call.
        check("fido_dev_make_cred", unsafe {
            sys::fido_dev_make_cred(self.raw.as_ptr(), credential.raw.as_ptr(), pin)
        })
    }

    /// Runs `assertion` on the device. `pin` must be NUL-terminated if given.
    pub(crate) fn get_assert(
        &mut self,
        assertion: &mut Assertion,
        pin: Option<&CStr>,
    ) -> Result<(), FidoError> {
        let pin = pin.map_or(std::ptr::null(), CStr::as_ptr);
        // SAFETY: device and assertion are valid objects owned by their
        // wrappers; `pin` is null or NUL-terminated and outlives the call.
        check("fido_dev_get_assert", unsafe {
            sys::fido_dev_get_assert(self.raw.as_ptr(), assertion.raw.as_ptr(), pin)
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // First, so no canceller can reach the handle any more; waits for a
        // cancel that is being sent right now.
        self.cancel
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let mut raw = self.raw.as_ptr();
        // `raw` is owned by `self` and used for the last time.
        if self.touch_pending {
            // Best effort: stop blinking on unselected devices.
            // SAFETY: open device; only a transmit, and no other use of the
            // handle remains (the cancel slot is empty).
            let _cancelled = unsafe { sys::fido_dev_cancel(raw) };
        }
        // SAFETY: our device; closing an already closed device is harmless.
        let _closed = unsafe { sys::fido_dev_close(raw) };
        // SAFETY: allocated by fido_dev_new and freed once; nulls our copy.
        unsafe { sys::fido_dev_free(&raw mut raw) };
    }
}

pub(crate) struct ResidentKey {
    pub public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub protection: i32,
    pub user_name: String,
}

struct Info(NonNull<sys::fido_cbor_info_t>);
struct Metadata(NonNull<sys::fido_credman_metadata_t>);
struct ResidentParties(NonNull<sys::fido_credman_rp_t>);
struct ResidentKeys(NonNull<sys::fido_credman_rk_t>);

impl Drop for Info {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        // SAFETY: unique owned object allocated by fido_cbor_info_new.
        unsafe { sys::fido_cbor_info_free(&raw mut raw) };
    }
}

impl Drop for Metadata {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        // SAFETY: unique owned object allocated by fido_credman_metadata_new.
        unsafe { sys::fido_credman_metadata_free(&raw mut raw) };
    }
}

impl Drop for ResidentParties {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        // SAFETY: unique owned list allocated by fido_credman_rp_new.
        unsafe { sys::fido_credman_rp_free(&raw mut raw) };
    }
}

impl Drop for ResidentKeys {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        // SAFETY: unique owned list allocated by fido_credman_rk_new.
        unsafe { sys::fido_credman_rk_free(&raw mut raw) };
    }
}

/// Copies a blob borrowed from a live libfido2 credential.
///
/// # Safety
/// Pointer must be null or readable for `length` bytes through this call.
unsafe fn copy_credential_blob(pointer: *const u8, length: usize) -> Result<Vec<u8>, FidoError> {
    if pointer.is_null() || length == 0 || length > 1024 {
        return Err(FidoError::new(
            "invalid resident credential blob",
            sys::FIDO_ERR_INTERNAL,
        ));
    }
    // SAFETY: guaranteed by caller, non-null and bounded above.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

/// An assertion request and, after `get_assert`, its result.
pub(crate) struct Assertion {
    raw: NonNull<sys::fido_assert_t>,
}

// SAFETY: like `Device`: only usable through `&mut self` or `&self` reads,
// never shared between threads (not `Sync`).
unsafe impl Send for Assertion {}

/// libfido2's tri-state option.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Opt {
    Omit,
    False,
    True,
}

impl Opt {
    fn raw(self) -> sys::fido_opt_t {
        match self {
            Self::Omit => sys::fido_opt_t_FIDO_OPT_OMIT,
            Self::False => sys::fido_opt_t_FIDO_OPT_FALSE,
            Self::True => sys::fido_opt_t_FIDO_OPT_TRUE,
        }
    }
}

impl Assertion {
    pub(crate) fn new() -> Result<Self, FidoError> {
        init();
        // SAFETY: allocates an empty assertion, or returns null.
        let raw = NonNull::new(unsafe { sys::fido_assert_new() })
            .ok_or_else(|| FidoError::new("fido_assert_new", sys::FIDO_ERR_INTERNAL))?;
        Ok(Self { raw })
    }

    pub(crate) fn set_rp(&mut self, rp_id: &CString) -> Result<(), FidoError> {
        // SAFETY: valid assertion; libfido2 copies the NUL-terminated string.
        check("fido_assert_set_rp", unsafe {
            sys::fido_assert_set_rp(self.raw.as_ptr(), rp_id.as_ptr())
        })
    }

    pub(crate) fn set_clientdata_hash(&mut self, hash: &[u8; 32]) -> Result<(), FidoError> {
        // SAFETY: valid assertion; libfido2 copies `hash.len()` bytes.
        check("fido_assert_set_clientdata_hash", unsafe {
            sys::fido_assert_set_clientdata_hash(self.raw.as_ptr(), hash.as_ptr(), hash.len())
        })
    }

    pub(crate) fn allow_credential(&mut self, key_handle: &[u8]) -> Result<(), FidoError> {
        // SAFETY: valid assertion; libfido2 copies `key_handle.len()` bytes.
        check("fido_assert_allow_cred", unsafe {
            sys::fido_assert_allow_cred(self.raw.as_ptr(), key_handle.as_ptr(), key_handle.len())
        })
    }

    pub(crate) fn set_user_presence(&mut self, option: Opt) -> Result<(), FidoError> {
        // SAFETY: valid assertion, valid enum value.
        check("fido_assert_set_up", unsafe {
            sys::fido_assert_set_up(self.raw.as_ptr(), option.raw())
        })
    }

    pub(crate) fn set_user_verification(&mut self, option: Opt) -> Result<(), FidoError> {
        // SAFETY: valid assertion, valid enum value.
        check("fido_assert_set_uv", unsafe {
            sys::fido_assert_set_uv(self.raw.as_ptr(), option.raw())
        })
    }

    /// Asks for the hmac-secret extension: the authenticator answers
    /// `HMAC-SHA-256(the credential's secret, salt)`.
    pub(crate) fn derive_with(&mut self, salt: &[u8; 32]) -> Result<(), FidoError> {
        // SAFETY: valid assertion, an extension libfido2 knows for assertions.
        check("fido_assert_set_extensions", unsafe {
            sys::fido_assert_set_extensions(self.raw.as_ptr(), sys::FIDO_EXT_HMAC_SECRET)
        })?;
        // SAFETY: valid assertion; libfido2 copies `salt.len()` bytes.
        check("fido_assert_set_hmac_salt", unsafe {
            sys::fido_assert_set_hmac_salt(self.raw.as_ptr(), salt.as_ptr(), salt.len())
        })
    }

    /// Hands the hmac-secret output of statement `index` to `read`, if the
    /// authenticator returned one. The bytes stay in libfido2's memory, which
    /// wipes them when the assertion is freed; `read` decides where a copy
    /// goes.
    pub(crate) fn with_hmac_secret<T>(
        &self,
        index: usize,
        read: impl FnOnce(&[u8]) -> T,
    ) -> Option<T> {
        if index >= self.count() {
            return None;
        }
        let raw = self.raw.as_ptr();
        // SAFETY: valid assertion and `index < count`; returns a pointer
        // into the assertion, or null.
        let pointer = unsafe { sys::fido_assert_hmac_secret_ptr(raw, index) };
        // SAFETY: as above; only reads.
        let length = unsafe { sys::fido_assert_hmac_secret_len(raw, index) };
        if pointer.is_null() || length == 0 || length > 64 {
            return None;
        }
        // SAFETY: libfido2's pointer and length for this statement, valid
        // while the assertion is; `&self` keeps it alive and unchanged for
        // the borrow handed to `read`.
        let secret = unsafe { std::slice::from_raw_parts(pointer, length) };
        Some(read(secret))
    }

    pub(crate) fn count(&self) -> usize {
        // SAFETY: valid assertion; the call only reads.
        unsafe { sys::fido_assert_count(self.raw.as_ptr()) }
    }

    /// Signature, flags and signature counter of statement `index`.
    pub(crate) fn statement(&self, index: usize) -> Option<(Vec<u8>, u8, u32)> {
        if index >= self.count() {
            return None;
        }
        let raw = self.raw.as_ptr();
        // SAFETY: valid assertion and `index < count`; returns a pointer
        // into the assertion, or null.
        let pointer = unsafe { sys::fido_assert_sig_ptr(raw, index) };
        // SAFETY: as above; only reads.
        let length = unsafe { sys::fido_assert_sig_len(raw, index) };
        if pointer.is_null() || length == 0 {
            return None;
        }
        // SAFETY: libfido2's pointer and length for this statement, valid
        // while the assertion is (it isn't changed meanwhile); copied out.
        let signature = unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec();
        // SAFETY: valid assertion and index; only reads.
        let flags = unsafe { sys::fido_assert_flags(raw, index) };
        // SAFETY: as above.
        let counter = unsafe { sys::fido_assert_sigcount(raw, index) };
        Some((signature, flags, counter))
    }
}

impl Drop for Assertion {
    fn drop(&mut self) {
        let mut raw = self.raw.as_ptr();
        // SAFETY: `raw` is owned by `self` and freed exactly once.
        unsafe { sys::fido_assert_free(&raw mut raw) };
    }
}

/// A credential to create and, after `make_cred`, the created one.
pub(crate) struct Credential {
    raw: NonNull<sys::fido_cred_t>,
}

// SAFETY: like `Assertion`: only usable through `&mut self` or `&self`
// reads, never shared between threads (not `Sync`).
unsafe impl Send for Credential {}

impl Credential {
    pub(crate) fn new() -> Result<Self, FidoError> {
        init();
        // SAFETY: allocates an empty credential, or returns null.
        let raw = NonNull::new(unsafe { sys::fido_cred_new() })
            .ok_or_else(|| FidoError::new("fido_cred_new", sys::FIDO_ERR_INTERNAL))?;
        Ok(Self { raw })
    }

    /// An Ed25519 credential.
    pub(crate) fn set_type_eddsa(&mut self) -> Result<(), FidoError> {
        // SAFETY: valid credential, a COSE algorithm libfido2 knows.
        check("fido_cred_set_type", unsafe {
            sys::fido_cred_set_type(self.raw.as_ptr(), sys::COSE_EDDSA)
        })
    }

    pub(crate) fn set_rp(&mut self, id: &CStr, name: &CStr) -> Result<(), FidoError> {
        // SAFETY: valid credential; libfido2 copies both NUL-terminated strings.
        check("fido_cred_set_rp", unsafe {
            sys::fido_cred_set_rp(self.raw.as_ptr(), id.as_ptr(), name.as_ptr())
        })
    }

    pub(crate) fn set_user(&mut self, id: &[u8], name: &CStr) -> Result<(), FidoError> {
        // SAFETY: valid credential; libfido2 copies `id.len()` bytes and the
        // NUL-terminated name; display name and icon are left out (null).
        check("fido_cred_set_user", unsafe {
            sys::fido_cred_set_user(
                self.raw.as_ptr(),
                id.as_ptr(),
                id.len(),
                name.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            )
        })
    }

    pub(crate) fn set_clientdata_hash(&mut self, hash: &[u8; 32]) -> Result<(), FidoError> {
        // SAFETY: valid credential; libfido2 copies `hash.len()` bytes.
        check("fido_cred_set_clientdata_hash", unsafe {
            sys::fido_cred_set_clientdata_hash(self.raw.as_ptr(), hash.as_ptr(), hash.len())
        })
    }

    /// Whether the credential is discoverable (resident).
    pub(crate) fn set_resident(&mut self, option: Opt) -> Result<(), FidoError> {
        // SAFETY: valid credential, valid enum value.
        check("fido_cred_set_rk", unsafe {
            sys::fido_cred_set_rk(self.raw.as_ptr(), option.raw())
        })
    }

    /// credProtect level 2: usable without user verification only by its id.
    pub(crate) fn set_protection_uv_optional_with_id(&mut self) -> Result<(), FidoError> {
        // SAFETY: valid credential, a protection level libfido2 knows.
        check("fido_cred_set_prot", unsafe {
            sys::fido_cred_set_prot(self.raw.as_ptr(), sys::FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID)
        })
    }

    /// credProtect level 3: unusable, and invisible, without user verification.
    pub(crate) fn set_protection_uv_required(&mut self) -> Result<(), FidoError> {
        // SAFETY: valid credential, a protection level libfido2 knows.
        check("fido_cred_set_prot", unsafe {
            sys::fido_cred_set_prot(self.raw.as_ptr(), sys::FIDO_CRED_PROT_UV_REQUIRED)
        })
    }

    /// Asks for the hmac-secret extension: the authenticator keeps a secret
    /// with the credential that assertions can derive from.
    pub(crate) fn enable_hmac_secret(&mut self) -> Result<(), FidoError> {
        // SAFETY: valid credential, an extension libfido2 knows for credentials.
        check("fido_cred_set_extensions", unsafe {
            sys::fido_cred_set_extensions(self.raw.as_ptr(), sys::FIDO_EXT_HMAC_SECRET)
        })
    }

    /// The created credential's id.
    pub(crate) fn id(&self) -> Result<Vec<u8>, FidoError> {
        let raw = self.raw.as_ptr();
        // SAFETY: valid credential; returns a pointer into it, or null.
        let pointer = unsafe { sys::fido_cred_id_ptr(raw) };
        // SAFETY: as above; only reads.
        let length = unsafe { sys::fido_cred_id_len(raw) };
        // SAFETY: libfido2's pointer and length, valid while the credential
        // is (it isn't changed meanwhile); copied out.
        unsafe { copy_credential_blob(pointer, length) }
    }

    /// The created credential's public key: 32 bytes for Ed25519.
    pub(crate) fn public_key(&self) -> Result<Vec<u8>, FidoError> {
        let raw = self.raw.as_ptr();
        // SAFETY: valid credential; returns a pointer into it, or null.
        let pointer = unsafe { sys::fido_cred_pubkey_ptr(raw) };
        // SAFETY: as above; only reads.
        let length = unsafe { sys::fido_cred_pubkey_len(raw) };
        // SAFETY: as for `id`.
        unsafe { copy_credential_blob(pointer, length) }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        let mut raw = self.raw.as_ptr();
        // SAFETY: `raw` is owned by `self` and freed exactly once.
        unsafe { sys::fido_cred_free(&raw mut raw) };
    }
}
