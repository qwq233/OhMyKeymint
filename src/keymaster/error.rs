// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Keystore error provides convenience methods and types for Keystore error handling.
//!
//! Here are some important types and helper functions:
//!
//! `Error` type encapsulate Keystore, Keymint, and Binder errors. It is used internally by
//! Keystore to diagnose error conditions that need to be reported to the client.
//!
//! `SerializedError` is used send error codes on the wire.
//!
//! `into_[logged_]binder` is a convenience method used to convert `anyhow::Error` into
//! `SerializedError` wire type.
//!
//! Keystore functions should use `anyhow::Result` to return error conditions, and context should
//! be added every time an error is forwarded.

pub use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
pub use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::keymaster::utils::AppUid;
use crate::selinux;
use log::{log, warn, Level};
use rsbinder::status::Result as BinderResult;
use rsbinder::{ExceptionCode, Status as BinderStatus, StatusCode};
use std::cmp::PartialEq;

#[cfg(test)]
pub mod tests;

/// This is the main Keystore error type. It wraps the Keystore `ResponseCode` generated
/// from AIDL in the `Rc` variant and Keymint `ErrorCode` in the Km variant.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wraps a Keystore `ResponseCode` as defined by the Keystore AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Keymint `ErrorCode` as defined by the Keymint AIDL interface specification.
    #[error("Error::Km({0:?})")]
    Km(ErrorCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
    /// Wraps a Binder status code.
    #[error("Binder transaction error {0:?}")]
    BinderTransaction(StatusCode),
}

pub type KsError = Error;

/// Log a client-triggered error according to the error log level policy.
pub fn log_client_error(level: Option<Level>, e: &anyhow::Error) {
    if let Some(level) = level {
        let uid = AppUid::calling();
        log!(level, "{e:?} for {uid:?}");
    }
}

/// Log a client-triggered error.
///
/// Use `log_client_err!(e)` to log according to the error log level policy.
/// This policy reduces noise for expected or benign client-triggered errors.
/// Use `log_client_err!(e, level)` to override the default error log level.
#[macro_export]
macro_rules! log_client_err {
    ($e:expr) => {
        $crate::keymaster::error::log_client_error(
            $crate::keymaster::error::get_log_level(&$e),
            &$e,
        )
    };
    ($e:expr, $level:expr) => {
        $crate::keymaster::error::log_client_error(Some($level), &$e)
    };
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SYSTEM_ERROR)`
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SYSTEM_ERROR)
    }

    /// Short hand for `Error::Rc(ResponseCode::PERMISSION_DENIED)`
    pub fn perm() -> Self {
        Error::Rc(ResponseCode::PERMISSION_DENIED)
    }

    /// Returns the log level for the error.
    pub fn log_level(&self) -> Option<Level> {
        match self {
            // Client app using a wrong alias
            Error::Rc(ResponseCode::KEY_NOT_FOUND) => None,
            // Some clients use this error to determine if the device has been unlocked recently
            Error::Km(ErrorCode::KEY_USER_NOT_AUTHENTICATED) => Some(Level::Info),
            // Optional feature that other system components (e.g. vold) try to use if present,
            // but can cope and fall back if the feature is unavailable.
            Error::Km(ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE) => Some(Level::Info),
            _ => Some(Level::Error),
        }
    }
}

/// Get the log level for the given error based on its root cause.
pub fn get_log_level(e: &anyhow::Error) -> Option<Level> {
    match e.root_cause().downcast_ref::<Error>() {
        Some(e) => e.log_level(),
        _ => Some(Level::Error),
    }
}

/// Helper function to map the binder status we get from calls into KeyMint
/// to a Keystore Error. We don't create an anyhow error here to make
/// it easier to evaluate KeyMint errors, which we must do in some cases, e.g.,
/// when diagnosing authentication requirements, update requirements, and running
/// out of operation slots.
pub fn map_km_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| {
        match s.exception_code() {
            ExceptionCode::ServiceSpecific => {
                let se = s.service_specific_error();
                if se < 0 {
                    // Negative service specific errors are KM error codes.
                    Error::Km(ErrorCode(s.service_specific_error()))
                } else {
                    // Non negative error codes cannot be KM error codes.
                    // So we create an `Error::Binder` variant to preserve
                    // the service specific error code for logging.
                    Error::Binder(ExceptionCode::ServiceSpecific, se)
                }
            }
            ExceptionCode::TransactionFailed => {
                let e = s.transaction_error();
                Error::BinderTransaction(e)
            }
            // We create `Error::Binder` to preserve the exception code
            // for logging.
            e_code => Error::Binder(e_code, 0),
        }
    })
}

/// This function is similar to map_km_error only that we don't expect
/// any KeyMint error codes, we simply preserve the exception code and optional
/// service specific exception.
pub fn map_binder_status<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::ServiceSpecific => {
            let se = s.service_specific_error();
            Error::Binder(ExceptionCode::ServiceSpecific, se)
        }
        ExceptionCode::TransactionFailed => {
            let e = s.transaction_error();
            Error::BinderTransaction(e)
        }
        e_code => Error::Binder(e_code, 0),
    })
}

/// This function maps a status code onto a Keystore Error.
pub fn map_binder_status_code<T>(r: Result<T, StatusCode>) -> Result<T, Error> {
    r.map_err(Error::BinderTransaction)
}

pub fn map_ks_error(e: Error) -> BinderStatus {
    match e {
        Error::Rc(rc) => BinderStatus::new_service_specific_error(rc.0, Some(format!("{rc:?}"))),
        Error::Km(ec) => BinderStatus::new_service_specific_error(ec.0, Some(format!("{ec:?}"))),
        Error::Binder(ExceptionCode::ServiceSpecific, se) => {
            BinderStatus::new_service_specific_error(se, None)
        }
        Error::Binder(ec, _se) => BinderStatus::from(ec),
        Error::BinderTransaction(sc) => BinderStatus::from(sc),
    }
}

pub fn map_ks_result<T>(r: Result<T, Error>) -> Result<T, BinderStatus> {
    r.map_err(map_ks_error)
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`], logging the value
/// along the way (except if it is `KEY_NOT_FOUND`).
pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
    log_client_err!(e);
    into_binder(e)
}

/// This function turns an anyhow error into an optional CString.
/// This is especially useful to add a message string to a service specific error.
/// If the formatted string was not convertible because it contained a nul byte,
/// None is returned and a warning is logged.
pub fn anyhow_error_to_cstring(e: &anyhow::Error) -> Option<String> {
    let formatted = format!("{e:?}");
    if formatted.contains('\0') {
        warn!("Cannot convert error message to String. It contained a nul byte.");
        None
    } else {
        Some(formatted)
    }
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`].
pub fn into_binder(e: anyhow::Error) -> BinderStatus {
    let rc = anyhow_error_to_serialized_error(&e);
    BinderStatus::new_service_specific_error(rc.0, anyhow_error_to_cstring(&e))
}

/// This type is used to send error codes on the wire.
///
/// Errors are squashed into one number space using following rules:
/// - All Keystore and Keymint errors codes are identity mapped. It's possible because by
///   convention Keystore `ResponseCode` errors are positive, and Keymint `ErrorCode` errors are
///   negative.
/// - `selinux::Error::PermissionDenied` is mapped to `ResponseCode::PERMISSION_DENIED`.
/// - All other error conditions, e.g. Binder errors, are mapped to `ResponseCode::SYSTEM_ERROR`.
///
/// The type should be used to forward all error codes to clients of Keystore AIDL interface and to
/// metrics events.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SerializedError(pub i32);

/// Returns a SerializedError given a reference to Error.
pub fn error_to_serialized_error(e: &Error) -> SerializedError {
    match e {
        Error::Rc(rcode) => SerializedError(rcode.0),
        Error::Km(ec) => SerializedError(ec.0),
        // Binder errors are reported as system error.
        Error::Binder(_, _) | Error::BinderTransaction(_) => {
            SerializedError(ResponseCode::SYSTEM_ERROR.0)
        }
    }
}

/// Returns a SerializedError given a reference to anyhow::Error.
pub fn anyhow_error_to_serialized_error(e: &anyhow::Error) -> SerializedError {
    let root_cause = e.root_cause();
    match root_cause.downcast_ref::<Error>() {
        Some(e) => error_to_serialized_error(e),
        None => match root_cause.downcast_ref::<selinux::Error>() {
            Some(selinux::Error::PermissionDenied) => {
                SerializedError(ResponseCode::PERMISSION_DENIED.0)
            }
            _ => SerializedError(ResponseCode::SYSTEM_ERROR.0),
        },
    }
}
