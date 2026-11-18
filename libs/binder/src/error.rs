/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::binder::AsNative;
use crate::sys;

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::ptr;
use std::result;

use std::error;

pub use sys::binder_status_t as status_t;

/// Low-level status codes from Android `libutils`.
// All error codes are negative integer values. Derived from the anonymous enum
// in utils/Errors.h
pub use sys::android_c_interface_StatusCode as StatusCode;

/// A specialized [`Result`](result::Result) for binder operations.
pub type Result<T> = result::Result<T, StatusCode>;

/// Convert a low-level status code into an empty result.
///
/// An OK status is converted into an `Ok` result, any other status is converted
/// into an `Err` result holding the status code.
pub fn status_result(status: status_t) -> Result<()> {
    match parse_status_code(status) {
        StatusCode::OK => Ok(()),
        e => Err(e),
    }
}

fn parse_status_code(code: i32) -> StatusCode {
    match code {
        e if e == StatusCode::OK as i32 => StatusCode::OK,
        e if e == StatusCode::NO_MEMORY as i32 => StatusCode::NO_MEMORY,
        e if e == StatusCode::INVALID_OPERATION as i32 => StatusCode::INVALID_OPERATION,
        e if e == StatusCode::BAD_VALUE as i32 => StatusCode::BAD_VALUE,
        e if e == StatusCode::BAD_TYPE as i32 => StatusCode::BAD_TYPE,
        e if e == StatusCode::NAME_NOT_FOUND as i32 => StatusCode::NAME_NOT_FOUND,
        e if e == StatusCode::PERMISSION_DENIED as i32 => StatusCode::PERMISSION_DENIED,
        e if e == StatusCode::NO_INIT as i32 => StatusCode::NO_INIT,
        e if e == StatusCode::ALREADY_EXISTS as i32 => StatusCode::ALREADY_EXISTS,
        e if e == StatusCode::DEAD_OBJECT as i32 => StatusCode::DEAD_OBJECT,
        e if e == StatusCode::FAILED_TRANSACTION as i32 => StatusCode::FAILED_TRANSACTION,
        e if e == StatusCode::BAD_INDEX as i32 => StatusCode::BAD_INDEX,
        e if e == StatusCode::NOT_ENOUGH_DATA as i32 => StatusCode::NOT_ENOUGH_DATA,
        e if e == StatusCode::WOULD_BLOCK as i32 => StatusCode::WOULD_BLOCK,
        e if e == StatusCode::TIMED_OUT as i32 => StatusCode::TIMED_OUT,
        e if e == StatusCode::UNKNOWN_TRANSACTION as i32 => StatusCode::UNKNOWN_TRANSACTION,
        e if e == StatusCode::FDS_NOT_ALLOWED as i32 => StatusCode::FDS_NOT_ALLOWED,
        e if e == StatusCode::UNEXPECTED_NULL as i32 => StatusCode::UNEXPECTED_NULL,
        _ => StatusCode::UNKNOWN_ERROR,
    }
}

pub use sys::android_c_interface_ExceptionCode as ExceptionCode;

fn parse_exception_code(code: i32) -> ExceptionCode {
    match code {
        e if e == ExceptionCode::NONE as i32 => ExceptionCode::NONE,
        e if e == ExceptionCode::SECURITY as i32 => ExceptionCode::SECURITY,
        e if e == ExceptionCode::BAD_PARCELABLE as i32 => ExceptionCode::BAD_PARCELABLE,
        e if e == ExceptionCode::ILLEGAL_ARGUMENT as i32 => ExceptionCode::ILLEGAL_ARGUMENT,
        e if e == ExceptionCode::NULL_POINTER as i32 => ExceptionCode::NULL_POINTER,
        e if e == ExceptionCode::ILLEGAL_STATE as i32 => ExceptionCode::ILLEGAL_STATE,
        e if e == ExceptionCode::NETWORK_MAIN_THREAD as i32 => ExceptionCode::NETWORK_MAIN_THREAD,
        e if e == ExceptionCode::UNSUPPORTED_OPERATION as i32 => {
            ExceptionCode::UNSUPPORTED_OPERATION
        }
        e if e == ExceptionCode::SERVICE_SPECIFIC as i32 => ExceptionCode::SERVICE_SPECIFIC,
        _ => ExceptionCode::TRANSACTION_FAILED,
    }
}

// Safety: `Status` always contains a owning pointer to a valid `AStatus`. The
// lifetime of the contained pointer is the same as the `Status` object.
/// High-level binder status object that encapsulates a standard way to keep
/// track of and chain binder errors along with service specific errors.
///
/// Used in AIDL transactions to represent failed transactions.
pub struct Status(ptr::NonNull<sys::AStatus>);

// Safety: The `AStatus` that the `Status` points to must have an entirely thread-safe API for the
// duration of the `Status` object's lifetime. We ensure this by not allowing mutation of a `Status`
// in Rust, and the NDK API says we're the owner of our `AStatus` objects so outside code should not
// be mutating them underneath us.
unsafe impl Sync for Status {}

// Safety: `Status` always contains an owning pointer to a global, immutable, interned `AStatus`.
// A thread-local `AStatus` would not be valid.
unsafe impl Send for Status {}

fn to_cstring<T: AsRef<str>>(message: T) -> Option<CString> {
    CString::new(message.as_ref()).ok()
}

impl Status {
    /// Create a status object representing a successful transaction.
    pub fn ok() -> Self {
        // Safety: `AStatus_newOk` always returns a new, heap allocated
        // pointer to an `ASTatus` object, so we know this pointer will be
        // valid.
        //
        // Rust takes ownership of the returned pointer.
        let ptr = unsafe { sys::AStatus_newOk() };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
    }

    /// Create a status object from a service specific error
    pub fn new_service_specific_error(err: i32, message: Option<&CStr>) -> Status {
        let ptr = if let Some(message) = message {
            // Safety: Any i32 is a valid service specific error for the
            // error code parameter. We construct a valid, null-terminated
            // `CString` from the message, which must be a valid C-style
            // string to pass as the message. This function always returns a
            // new, heap allocated pointer to an `AStatus` object, so we
            // know the returned pointer will be valid.
            //
            // Rust takes ownership of the returned pointer.
            unsafe { sys::AStatus_fromServiceSpecificErrorWithMessage(err, message.as_ptr()) }
        } else {
            // Safety: Any i32 is a valid service specific error for the
            // error code parameter. This function always returns a new,
            // heap allocated pointer to an `AStatus` object, so we know the
            // returned pointer will be valid.
            //
            // Rust takes ownership of the returned pointer.
            unsafe { sys::AStatus_fromServiceSpecificError(err) }
        };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
    }

    /// Creates a status object from a service specific error.
    pub fn new_service_specific_error_str<T: AsRef<str>>(err: i32, message: Option<T>) -> Status {
        Self::new_service_specific_error(err, message.and_then(to_cstring).as_deref())
    }

    /// Create a status object from an exception code
    pub fn new_exception(exception: ExceptionCode, message: Option<&CStr>) -> Status {
        if let Some(message) = message {
            // Safety: the C string pointer is valid and not retained by the
            // function.
            let ptr = unsafe {
                sys::AStatus_fromExceptionCodeWithMessage(exception as i32, message.as_ptr())
            };
            Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
        } else {
            exception.into()
        }
    }

    /// Creates a status object from an exception code and message.
    pub fn new_exception_str<T: AsRef<str>>(
        exception: ExceptionCode,
        message: Option<T>,
    ) -> Status {
        Self::new_exception(exception, message.and_then(to_cstring).as_deref())
    }

    /// Create a status object from a raw `AStatus` pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe iff `ptr` is a valid pointer to an `AStatus`.
    pub(crate) unsafe fn from_ptr(ptr: *mut sys::AStatus) -> Self {
        Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
    }

    /// Returns `true` if this status represents a successful transaction.
    pub fn is_ok(&self) -> bool {
        // Safety: `Status` always contains a valid `AStatus` pointer, so we
        // are always passing a valid pointer to `AStatus_isOk` here.
        unsafe { sys::AStatus_isOk(self.as_native()) }
    }

    /// Returns a description of the status.
    pub fn get_description(&self) -> String {
        // Safety: `Status` always contains a valid `AStatus` pointer, so we
        // are always passing a valid pointer to `AStatus_getDescription`
        // here.
        //
        // `AStatus_getDescription` always returns a valid pointer to a null
        // terminated C string. Rust is responsible for freeing this pointer
        // via `AStatus_deleteDescription`.
        let description_ptr = unsafe { sys::AStatus_getDescription(self.as_native()) };
        // Safety: `AStatus_getDescription` always returns a valid C string,
        // which can be safely converted to a `CStr`.
        let description = unsafe { CStr::from_ptr(description_ptr) };
        let description = description.to_string_lossy().to_string();
        // Safety: `description_ptr` was returned from
        // `AStatus_getDescription` above, and must be freed via
        // `AStatus_deleteDescription`. We must not access the pointer after
        // this call, so we copy it into an owned string above and return
        // that string.
        unsafe {
            sys::AStatus_deleteDescription(description_ptr);
        }
        description
    }

    /// Returns the exception code of the status.
    pub fn exception_code(&self) -> ExceptionCode {
        // Safety: `Status` always contains a valid `AStatus` pointer, so we
        // are always passing a valid pointer to `AStatus_getExceptionCode`
        // here.
        let code = unsafe { sys::AStatus_getExceptionCode(self.as_native()) };
        parse_exception_code(code)
    }

    /// Return a status code representing a transaction failure, or
    /// `StatusCode::OK` if there was no transaction failure.
    ///
    /// If this method returns `OK`, the status may still represent a different
    /// exception or a service specific error. To find out if this transaction
    /// as a whole is okay, use [`is_ok`](Self::is_ok) instead.
    pub fn transaction_error(&self) -> StatusCode {
        // Safety: `Status` always contains a valid `AStatus` pointer, so we
        // are always passing a valid pointer to `AStatus_getStatus` here.
        let code = unsafe { sys::AStatus_getStatus(self.as_native()) };
        parse_status_code(code)
    }

    /// Return a service specific error if this status represents one.
    ///
    /// This function will only ever return a non-zero result if
    /// [`exception_code`](Self::exception_code) returns
    /// `ExceptionCode::SERVICE_SPECIFIC`. If this function returns 0, the
    /// status object may still represent a different exception or status. To
    /// find out if this transaction as a whole is okay, use
    /// [`is_ok`](Self::is_ok) instead.
    pub fn service_specific_error(&self) -> i32 {
        // Safety: `Status` always contains a valid `AStatus` pointer, so we
        // are always passing a valid pointer to
        // `AStatus_getServiceSpecificError` here.
        unsafe { sys::AStatus_getServiceSpecificError(self.as_native()) }
    }

    /// Calls `op` if the status was ok, otherwise returns an `Err` value of
    /// `self`.
    pub fn and_then<T, F>(self, op: F) -> result::Result<T, Status>
    where
        F: FnOnce() -> result::Result<T, Status>,
    {
        <result::Result<(), Status>>::from(self)?;
        op()
    }
}

impl error::Error for Status {}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.get_description())
    }
}

impl Debug for Status {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.get_description())
    }
}

impl PartialEq for Status {
    fn eq(&self, other: &Status) -> bool {
        let self_code = self.exception_code();
        let other_code = other.exception_code();

        match (self_code, other_code) {
            (ExceptionCode::NONE, ExceptionCode::NONE) => true,
            (ExceptionCode::TRANSACTION_FAILED, ExceptionCode::TRANSACTION_FAILED) => {
                self.transaction_error() == other.transaction_error()
                    && self.get_description() == other.get_description()
            }
            (ExceptionCode::SERVICE_SPECIFIC, ExceptionCode::SERVICE_SPECIFIC) => {
                self.service_specific_error() == other.service_specific_error()
                    && self.get_description() == other.get_description()
            }
            (e1, e2) => e1 == e2 && self.get_description() == other.get_description(),
        }
    }
}

impl Eq for Status {}

impl From<StatusCode> for Status {
    fn from(status: StatusCode) -> Status {
        (status as status_t).into()
    }
}

impl From<status_t> for Status {
    fn from(status: status_t) -> Status {
        // Safety: `AStatus_fromStatus` expects any `status_t` integer, so
        // this is a safe FFI call. Unknown values will be coerced into
        // UNKNOWN_ERROR.
        let ptr = unsafe { sys::AStatus_fromStatus(status) };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
    }
}

impl From<ExceptionCode> for Status {
    fn from(code: ExceptionCode) -> Status {
        // Safety: `AStatus_fromExceptionCode` expects any
        // `binder_exception_t` (i32) integer, so this is a safe FFI call.
        // Unknown values will be coerced into EX_TRANSACTION_FAILED.
        let ptr = unsafe { sys::AStatus_fromExceptionCode(code as i32) };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null AStatus pointer"))
    }
}

// TODO: impl Try for Status when try_trait is stabilized
// https://github.com/rust-lang/rust/issues/42327
impl From<Status> for result::Result<(), Status> {
    fn from(status: Status) -> result::Result<(), Status> {
        if status.is_ok() {
            Ok(())
        } else {
            Err(status)
        }
    }
}

impl From<Status> for status_t {
    fn from(status: Status) -> status_t {
        status.transaction_error() as status_t
    }
}

impl Drop for Status {
    fn drop(&mut self) {
        // Safety: `Status` manages the lifetime of its inner `AStatus`
        // pointee, so we need to delete it here. We know that the pointer
        // will be valid here since `Status` always contains a valid pointer
        // while it is alive.
        unsafe {
            sys::AStatus_delete(self.0.as_mut());
        }
    }
}

/// Safety: `Status` always contains a valid pointer to an `AStatus` object, so
/// we can trivially convert it to a correctly-typed raw pointer.
///
/// Care must be taken that the returned pointer is only dereferenced while the
/// `Status` object is still alive.
unsafe impl AsNative<sys::AStatus> for Status {
    fn as_native(&self) -> *const sys::AStatus {
        self.0.as_ptr()
    }

    fn as_native_mut(&mut self) -> *mut sys::AStatus {
        // Safety: The pointer will be valid here since `Status` always contains
        // a valid and initialized pointer while it is alive.
        unsafe { self.0.as_mut() }
    }
}

/// A conversion from `std::result::Result<T, E>` to `binder::Result<T>`. If this type is `Ok(T)`,
/// it's returned as is. If this type is `Err(E)`, `E` is converted into `Status` which can be
/// either a general binder exception, or a service-specific exception.
///
/// # Examples
///
/// ```
/// // std::io::Error is formatted as the exception's message
/// fn file_exists(name: &str) -> binder::Result<bool> {
///     std::fs::metadata(name)
///         .or_service_specific_exception(NOT_FOUND)?
/// }
///
/// // A custom function is used to create the exception's message
/// fn file_exists(name: &str) -> binder::Result<bool> {
///     std::fs::metadata(name)
///         .or_service_specific_exception_with(NOT_FOUND,
///             |e| format!("file {} not found: {:?}", name, e))?
/// }
///
/// // anyhow::Error is formatted as the exception's message
/// use anyhow::{Context, Result};
/// fn file_exists(name: &str) -> binder::Result<bool> {
///     std::fs::metadata(name)
///         .context("file {} not found")
///         .or_service_specific_exception(NOT_FOUND)?
/// }
///
/// // General binder exceptions can be created similarly
/// fn file_exists(name: &str) -> binder::Result<bool> {
///     std::fs::metadata(name)
///         .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)?
/// }
/// ```
pub trait IntoBinderResult<T, E> {
    /// Converts the embedded error into a general binder exception of code `exception`. The
    /// message of the exception is set by formatting the error for debugging.
    fn or_binder_exception(self, exception: ExceptionCode) -> result::Result<T, Status>;

    /// Converts the embedded error into a general binder exception of code `exception`. The
    /// message of the exception is set by lazily evaluating the `op` function.
    fn or_binder_exception_with<M: AsRef<str>, O: FnOnce(E) -> M>(
        self,
        exception: ExceptionCode,
        op: O,
    ) -> result::Result<T, Status>;

    /// Converts the embedded error into a service-specific binder exception. `error_code` is used
    /// to distinguish different service-specific binder exceptions. The message of the exception
    /// is set by formatting the error for debugging.
    fn or_service_specific_exception(self, error_code: i32) -> result::Result<T, Status>;

    /// Converts the embedded error into a service-specific binder exception. `error_code` is used
    /// to distinguish different service-specific binder exceptions. The message of the exception
    /// is set by lazily evaluating the `op` function.
    fn or_service_specific_exception_with<M: AsRef<str>, O: FnOnce(E) -> M>(
        self,
        error_code: i32,
        op: O,
    ) -> result::Result<T, Status>;
}

impl<T, E: core::fmt::Debug> IntoBinderResult<T, E> for result::Result<T, E> {
    fn or_binder_exception(self, exception: ExceptionCode) -> result::Result<T, Status> {
        self.or_binder_exception_with(exception, |e| std::format!("{:?}", e))
    }

    fn or_binder_exception_with<M: AsRef<str>, O: FnOnce(E) -> M>(
        self,
        exception: ExceptionCode,
        op: O,
    ) -> result::Result<T, Status> {
        self.map_err(|e| Status::new_exception_str(exception, Some(op(e))))
    }

    fn or_service_specific_exception(self, error_code: i32) -> result::Result<T, Status> {
        self.or_service_specific_exception_with(error_code, |e| std::format!("{:?}", e))
    }

    fn or_service_specific_exception_with<M: AsRef<str>, O: FnOnce(E) -> M>(
        self,
        error_code: i32,
        op: O,
    ) -> result::Result<T, Status> {
        self.map_err(|e| Status::new_service_specific_error_str(error_code, Some(op(e))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_service_specific_error() {
        let status = Status::new_service_specific_error_str(-42, Some("message"));

        assert!(!status.is_ok());
        assert_eq!(status.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
        assert_eq!(status.service_specific_error(), -42);
        assert_eq!(
            status.get_description(),
            "Status(-8, EX_SERVICE_SPECIFIC): '-42: message'".to_string()
        );
    }

    #[test]
    fn make_exception() {
        let status = Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some("message"));

        assert!(!status.is_ok());
        assert_eq!(status.exception_code(), ExceptionCode::ILLEGAL_STATE);
        assert_eq!(status.service_specific_error(), 0);
        assert_eq!(status.get_description(), "Status(-5, EX_ILLEGAL_STATE): 'message'".to_string());
    }

    #[test]
    fn make_exception_null() {
        let status = Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some("one\0two"));

        assert!(!status.is_ok());
        assert_eq!(status.exception_code(), ExceptionCode::ILLEGAL_STATE);
        assert_eq!(status.service_specific_error(), 0);
        assert_eq!(status.get_description(), "Status(-5, EX_ILLEGAL_STATE): ''".to_string());
    }

    #[test]
    fn convert_to_service_specific_exception() {
        let res: std::result::Result<(), Status> =
            Err("message").or_service_specific_exception(-42);

        assert!(res.is_err());
        let status = res.unwrap_err();
        assert_eq!(status.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
        assert_eq!(status.service_specific_error(), -42);
        assert_eq!(
            status.get_description(),
            "Status(-8, EX_SERVICE_SPECIFIC): '-42: \"message\"'".to_string()
        );
    }

    #[test]
    fn convert_to_service_specific_exception_with() {
        let res: std::result::Result<(), Status> = Err("message")
            .or_service_specific_exception_with(-42, |e| format!("outer message: {:?}", e));

        assert!(res.is_err());
        let status = res.unwrap_err();
        assert_eq!(status.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
        assert_eq!(status.service_specific_error(), -42);
        assert_eq!(
            status.get_description(),
            "Status(-8, EX_SERVICE_SPECIFIC): '-42: outer message: \"message\"'".to_string()
        );
    }

    #[test]
    fn convert_to_binder_exception() {
        let res: std::result::Result<(), Status> =
            Err("message").or_binder_exception(ExceptionCode::ILLEGAL_STATE);

        assert!(res.is_err());
        let status = res.unwrap_err();
        assert_eq!(status.exception_code(), ExceptionCode::ILLEGAL_STATE);
        assert_eq!(status.service_specific_error(), 0);
        assert_eq!(
            status.get_description(),
            "Status(-5, EX_ILLEGAL_STATE): '\"message\"'".to_string()
        );
    }

    #[test]
    fn convert_to_binder_exception_with() {
        let res: std::result::Result<(), Status> = Err("message")
            .or_binder_exception_with(ExceptionCode::ILLEGAL_STATE, |e| {
                format!("outer message: {:?}", e)
            });

        assert!(res.is_err());
        let status = res.unwrap_err();
        assert_eq!(status.exception_code(), ExceptionCode::ILLEGAL_STATE);
        assert_eq!(status.service_specific_error(), 0);
        assert_eq!(
            status.get_description(),
            "Status(-5, EX_ILLEGAL_STATE): 'outer message: \"message\"'".to_string()
        );
    }
}
