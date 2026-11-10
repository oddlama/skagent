//! Owning wrappers around libfido2 objects. All `unsafe` of the crate lives here.
//!
//! libfido2 objects are opaque pointers with `*_new`/`*_free` pairs. Each
//! wrapper owns exactly one object, frees it on drop and only hands out
//! borrowed data whose lifetime is tied to the wrapper.

use std::ffi::{CStr, CString, c_int};
use std::ptr::NonNull;
use std::sync::Once;

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
                // SAFETY: `entry` is a valid entry of `list`, which outlives
                // these calls; the strings are copied before `list` is freed.
                Some(unsafe {
                    ListedDevice {
                        path: owned_string(sys::fido_dev_info_path(entry)),
                        manufacturer: owned_string(sys::fido_dev_info_manufacturer_string(entry)),
                        product: owned_string(sys::fido_dev_info_product_string(entry)),
                    }
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
        };
        // SAFETY: `raw` is a fresh handle and `path` is NUL-terminated.
        check("fido_dev_open", unsafe {
            sys::fido_dev_open(device.raw.as_ptr(), path.as_ptr())
        })?;
        Ok(device)
    }

    pub(crate) fn set_timeout(&mut self, milliseconds: c_int) -> Result<(), FidoError> {
        // SAFETY: `raw` is an open device owned by `self`.
        check("fido_dev_set_timeout", unsafe {
            sys::fido_dev_set_timeout(self.raw.as_ptr(), milliseconds)
        })
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
        let mut raw = self.raw.as_ptr();
        // SAFETY: `raw` is owned by `self` and used for the last time. Closing
        // an already closed device is harmless; free nulls our copy.
        unsafe {
            if self.touch_pending {
                // Best effort: stop blinking on unselected devices. Only a
                // transmit, with no concurrent use of this handle.
                let _cancelled = sys::fido_dev_cancel(raw);
            }
            let _closed = sys::fido_dev_close(raw);
            sys::fido_dev_free(&raw mut raw);
        }
    }
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
        // SAFETY: valid assertion and `index < count`; libfido2 returns a
        // pointer into the assertion and its length, read before any change.
        let signature = unsafe {
            let pointer = sys::fido_assert_sig_ptr(raw, index);
            let length = sys::fido_assert_sig_len(raw, index);
            if pointer.is_null() || length == 0 {
                return None;
            }
            std::slice::from_raw_parts(pointer, length).to_vec()
        };
        // SAFETY: valid assertion and index, see above.
        let (flags, counter) = unsafe {
            (
                sys::fido_assert_flags(raw, index),
                sys::fido_assert_sigcount(raw, index),
            )
        };
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
