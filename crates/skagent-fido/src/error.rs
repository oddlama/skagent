//! libfido2 errors, classified by what the agent has to do about them.

use std::fmt;

use libfido2_sys as sys;

/// What a libfido2 status code means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The PIN was wrong. The device decremented its retry counter.
    PinInvalid,
    /// Too many wrong PINs since the device was powered up. Replugging resets this.
    PinAuthBlocked,
    /// The retry counter is exhausted. Only a FIDO reset helps.
    PinBlocked,
    /// The operation needs a PIN and none was given.
    PinRequired,
    /// The device has no PIN set.
    PinNotSet,
    /// The device refuses the PIN until it is changed (forcePINChange).
    PinPolicyViolation,
    /// The device doesn't hold the credential, or hides it without user verification.
    NoCredentials,
    /// The user didn't touch the device in time.
    TouchTimeout,
    /// The user (or the device) refused the operation.
    OperationDenied,
    /// The request was cancelled (`CTAPHID_CANCEL`) while it waited.
    Cancelled,
    /// The device was unplugged or stopped answering.
    Transport,
    /// Anything else.
    Other,
}

impl ErrorKind {
    /// Classifies a libfido2 return code. `FIDO_OK` is not an error and maps to `Other`.
    #[must_use]
    pub fn from_code(code: i32) -> Self {
        match code {
            sys::FIDO_ERR_PIN_INVALID => Self::PinInvalid,
            sys::FIDO_ERR_PIN_AUTH_BLOCKED => Self::PinAuthBlocked,
            sys::FIDO_ERR_PIN_BLOCKED => Self::PinBlocked,
            sys::FIDO_ERR_PIN_REQUIRED => Self::PinRequired,
            sys::FIDO_ERR_PIN_NOT_SET => Self::PinNotSet,
            sys::FIDO_ERR_PIN_POLICY_VIOLATION => Self::PinPolicyViolation,
            sys::FIDO_ERR_NO_CREDENTIALS => Self::NoCredentials,
            sys::FIDO_ERR_ACTION_TIMEOUT | sys::FIDO_ERR_USER_ACTION_TIMEOUT => Self::TouchTimeout,
            sys::FIDO_ERR_OPERATION_DENIED => Self::OperationDenied,
            sys::FIDO_ERR_KEEPALIVE_CANCEL => Self::Cancelled,
            sys::FIDO_ERR_TX | sys::FIDO_ERR_RX => Self::Transport,
            _ => Self::Other,
        }
    }

    /// Whether the PIN that was used must not be used again: it was wrong, or
    /// the device currently refuses any PIN.
    #[must_use]
    pub fn invalidates_pin(self) -> bool {
        matches!(
            self,
            Self::PinInvalid | Self::PinAuthBlocked | Self::PinBlocked | Self::PinPolicyViolation
        )
    }
}

/// A failed libfido2 call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidoError {
    operation: &'static str,
    code: i32,
}

impl FidoError {
    /// Wraps the return `code` of the libfido2 call `operation`.
    #[must_use]
    pub fn new(operation: &'static str, code: i32) -> Self {
        Self { operation, code }
    }

    /// The libfido2 function that failed.
    #[must_use]
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    /// The raw libfido2 return code.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// What the failure means for the caller.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        ErrorKind::from_code(self.code)
    }
}

impl fmt::Display for FidoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed: {} (libfido2 code {})",
            self.operation,
            crate::raw::error_message(self.code),
            self.code
        )
    }
}

impl std::error::Error for FidoError {}
