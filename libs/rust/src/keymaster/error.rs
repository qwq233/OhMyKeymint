use rsbinder::{ExceptionCode, Status, StatusCode};

use crate::android::{
    hardware::security::keymint::ErrorCode::ErrorCode,
    system::keystore2::ResponseCode::ResponseCode,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KsError {
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

impl KsError {
    /// Short hand for `Error::Rc(ResponseCode::SYSTEM_ERROR)`
    pub fn sys() -> Self {
        KsError::Rc(ResponseCode::SYSTEM_ERROR)
    }

    /// Short hand for `Error::Rc(ResponseCode::PERMISSION_DENIED)`
    pub fn perm() -> Self {
        KsError::Rc(ResponseCode::PERMISSION_DENIED)
    }
}

/// This function is similar to map_km_error only that we don't expect
/// any KeyMint error codes, we simply preserve the exception code and optional
/// service specific exception.
pub fn map_binder_status<T>(r: rsbinder::status::Result<T>) -> Result<T, KsError> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => Err(match e.exception_code() {
            ExceptionCode::ServiceSpecific => {
                let se = e.service_specific_error();
                KsError::Binder(ExceptionCode::ServiceSpecific, se)
            }
            ExceptionCode::TransactionFailed => {
                let e = e.transaction_error();
                KsError::BinderTransaction(e)
            }
            e_code => KsError::Binder(e_code, 0),
        }),
    }
}

pub fn map_ks_error(r: KsError) -> Status {
    match r {
        KsError::Rc(rc) => {
            Status::new_service_specific_error(rc.0, format!("KeystoreError: {:?}", rc).into())
        }
        KsError::Km(ec) => {
            Status::new_service_specific_error(ec.0, format!("KeymintError: {:?}", ec).into())
        }
        KsError::Binder(ec, se) => Status::from(ec),
        KsError::BinderTransaction(sc) => Status::from(sc),
    }
}

pub fn map_ks_result<T>(r: Result<T, KsError>) -> Result<T, Status> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => Err(map_ks_error(e)),
    }
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`], logging the value
/// along the way (except if it is `KEY_NOT_FOUND`).
pub fn into_logged_binder(e: anyhow::Error) -> Status {
    // Log everything except key not found.
    if !matches!(
        e.root_cause().downcast_ref::<KsError>(),
        Some(KsError::Rc(ResponseCode::KEY_NOT_FOUND))
    ) {
        log::error!("{:?}", e);
    }
    into_binder(e)
}

/// This function turns an anyhow error into an optional CString.
/// This is especially useful to add a message string to a service specific error.
/// If the formatted string was not convertible because it contained a nul byte,
/// None is returned and a warning is logged.
pub fn anyhow_error_to_string(e: &anyhow::Error) -> Option<String> {
    let formatted = format!("{:?}", e);
    if formatted.contains('\0') {
        log::warn!("Cannot convert error message to String. It contained a nul byte.");
        None
    } else {
        Some(formatted)
    }
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
pub fn error_to_serialized_error(e: &KsError) -> SerializedError {
    match e {
        KsError::Rc(rcode) => SerializedError(rcode.0),
        KsError::Km(ec) => SerializedError(ec.0),
        // Binder errors are reported as system error.
        KsError::Binder(_, _) | KsError::BinderTransaction(_) => {
            SerializedError(ResponseCode::SYSTEM_ERROR.0)
        }
    }
}

/// Returns a SerializedError given a reference to anyhow::Error.
pub fn anyhow_error_to_serialized_error(e: &anyhow::Error) -> SerializedError {
    let root_cause = e.root_cause();
    match root_cause.downcast_ref::<KsError>() {
        Some(e) => error_to_serialized_error(e),
        None => SerializedError(ResponseCode::SYSTEM_ERROR.0),
    }
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`].
pub fn into_binder(e: anyhow::Error) -> rsbinder::Status {
    let rc = anyhow_error_to_serialized_error(&e);
    rsbinder::Status::new_service_specific_error(rc.0, anyhow_error_to_string(&e))
}
