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
