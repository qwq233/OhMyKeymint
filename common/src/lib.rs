// Copyright 2022, The Android Open Source Project
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

//! Functionality for KeyMint implementation that is common across HAL and TA.

extern crate std;

use core::convert::From;
use core::num::TryFromIntError;
use der::ErrorKind as DerErrorKind;
use kmr_wire::{cbor, keymint::ErrorCode, rpc as wire_rpc, CborError};
use std::{borrow::Cow, vec::Vec};

pub use kmr_wire as wire;

pub mod android_version;
pub mod consts;
pub mod crypto;
pub mod keyblob;
pub mod rpc;
pub mod runtime;
pub mod tag;

/// Location in a source file where an error originated.
///
/// Don't construct this type directly but instead use [`km_err_new!`] to get an [`Error`] with the
/// correct location.
#[derive(Copy, Clone, Debug)]
pub struct ErrorLocation {
    /// Name of the source file.
    pub file: &'static str,
    /// Line within the source file.
    pub line: u32,
}

/// A list specifying the categories of error.
#[derive(Debug)]
pub enum ErrorKind {
    /// Error from CBOR conversion.
    Cbor(CborError),
    /// Error from ASN.1 DER conversion.
    Der(DerErrorKind),
    /// Error as reported on the HAL interface.
    ///
    /// The `IKeyMintDevice`, `ISharedSecret` and `ISecureClock` HALs all share the same numbering
    /// space for error codes, encoded here as [`kmr_wire::keymint::ErrorCode`].
    Hal(ErrorCode, Cow<'static, str>),
    /// Error as reported on the `IRemotelyProvisionedComponent` HAL, which uses its own error
    /// codes.
    Rpc(wire_rpc::ErrorCode, Cow<'static, str>),
    /// Memory allocation error.
    ///
    /// This holds a string literal rather than an allocated `String` to avoid allocating in an
    /// allocation error path.
    Alloc(&'static str),
}

/// The error type for a KeyMint operation with an [`ErrorKind`] and diagnostic information.
#[derive(Debug)]
pub struct Error {
    location: Option<ErrorLocation>,
    kind: ErrorKind,
}

impl Error {
    /// Creates a new error at a given source location.
    pub fn new_at(location: ErrorLocation, kind: ErrorKind) -> Error {
        Error {
            location: Some(location),
            kind,
        }
    }

    /// Gets the source location of the error.
    pub fn location(&self) -> Option<ErrorLocation> {
        self.location
    }

    /// Gets the kind of error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

// The following macros for error generation allow the message portion to be automatically
// compiled out in future, avoiding potential information leakage and allocation.

/// Macro to build an [`Error`] instance with location information.
#[macro_export]
macro_rules! km_err_new {
    { $kind:expr} => {
        $crate::Error::new_at($crate::ErrorLocation { file: file!(), line: line!() }, $kind)
    }
}

/// Macro to build an [`ErrorKind::Hal`] error for a specific [`ErrorCode`] value known at compile
/// time: `km_err!(InvalidTag, "some {} format", arg)`.
#[macro_export]
macro_rules! km_err {
    { $error_code:ident, $($arg:tt)+ } => {
        $crate::km_err_new!($crate::ErrorKind::Hal(
            kmr_wire::keymint::ErrorCode::$error_code,
            $crate::format_cow(format_args!($($arg)+)),
        ))
    }
}

/// Macro to build an [`ErrorKind::Hal`] error:
/// `km_verr!(rc, "some {} format", arg)`.
#[macro_export]
macro_rules! km_verr {
    { $error_code:expr, $($arg:tt)+ } => {
       $crate::km_err_new!($crate::ErrorKind::Hal(
            $error_code,
            $crate::format_cow(format_args!($($arg)+)),
        ))
    }
}

/// Macro to build an [`ErrorKind::Alloc`] error. Note that this builds a `&'static str` at compile
/// time, so there is no allocation needed for the message (which would be failure-prone when
/// dealing with an allocation failure).
#[macro_export]
macro_rules! alloc_err {
    { $len:expr } => {
        $crate::km_err_new!($crate::ErrorKind::Alloc(stringify!($len)))
    }
}

/// Macro to build an [`ErrorKind::Der`] error from a [`der::Error`].
#[macro_export]
macro_rules! der_err {
    { $err:expr, $($arg:tt)+ } => {
        {
            log::warn!("{}: {:?} at {:?}", format_args!($($arg)+), $err, $err.position());
            $crate::Error::from($crate::ErrorKind::Der($err.kind()))
        }
    }
}

/// Macro to build an [`ErrorKind::Rpc`] error for a specific [`rpc::ErrorCode`] value known at
/// compile time: `rpc_err!(Removed, "some {} format", arg)`.
#[macro_export]
macro_rules! rpc_err {
    { $error_code:ident, $($arg:tt)+ } => {
        $crate::km_err_new!($crate::ErrorKind::Rpc(
            kmr_wire::rpc::ErrorCode::$error_code,
            $crate::format_cow(format_args!($($arg)+)),
        ))
    }
}

/// Macro to allocate a `Vec<T>` with the given length reserved, detecting allocation failure.
#[macro_export]
macro_rules! vec_try_with_capacity {
    { $len:expr} => {
        {
            let mut v = std::vec::Vec::new();
            match v.try_reserve($len) {
                Err(_e) => Err($crate::alloc_err!($len)),
                Ok(_) => Ok(v),
            }
        }
    }
}

/// Macro that mimics `vec!` but which detects allocation failure.
#[macro_export]
macro_rules! vec_try {
    { $elem:expr ; $len:expr } => {
        kmr_wire::vec_try_fill_with_alloc_err($elem, $len, || $crate::alloc_err!($len))
    };
    { $x1:expr, $x2:expr, $x3:expr, $x4:expr $(,)? } => {
        kmr_wire::vec_try4_with_alloc_err($x1, $x2, $x3, $x4, || $crate::alloc_err!(4))
    };
    { $x1:expr, $x2:expr, $x3:expr $(,)? } => {
        kmr_wire::vec_try3_with_alloc_err($x1, $x2, $x3, || $crate::alloc_err!(3))
    };
    { $x1:expr, $x2:expr $(,)? } => {
        kmr_wire::vec_try2_with_alloc_err($x1, $x2, || $crate::alloc_err!(2))
    };
    { $x1:expr $(,)? } => {
        kmr_wire::vec_try1_with_alloc_err($x1, || $crate::alloc_err!(1))
    };
}

#[doc(hidden)]
#[inline(always)]
pub fn format_cow(args: core::fmt::Arguments) -> Cow<'static, str> {
    match args.as_str() {
        Some(s) => s.into(),
        None => std::format!("{}", args).into(),
    }
}

/// Function that mimics `slice.to_vec()` but which detects allocation failures.
#[inline]
pub fn try_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, Error> {
    let mut v = vec_try_with_capacity!(s.len())?;
    v.extend_from_slice(s);
    Ok(v)
}

/// Extension trait to provide fallible-allocation variants of `Vec` methods.
pub trait FallibleAllocExt<T> {
    /// Try to add the `value` to the collection, failing on memory exhaustion.
    fn try_push(&mut self, value: T) -> Result<(), std::collections::TryReserveError>;
    /// Try to extend the collection with the contents of `other`, failing on memory exhaustion.
    fn try_extend_from_slice(
        &mut self,
        other: &[T],
    ) -> Result<(), std::collections::TryReserveError>
    where
        T: Clone;
}

impl<T> FallibleAllocExt<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<(), std::collections::TryReserveError> {
        self.try_reserve(1)?;
        self.push(value);
        Ok(())
    }
    fn try_extend_from_slice(
        &mut self,
        other: &[T],
    ) -> Result<(), std::collections::TryReserveError>
    where
        T: Clone,
    {
        self.try_reserve(other.len())?;
        self.extend_from_slice(other);
        Ok(())
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            location: None,
            kind,
        }
    }
}

impl From<std::collections::TryReserveError> for Error {
    fn from(_e: std::collections::TryReserveError) -> Self {
        ErrorKind::Hal(
            kmr_wire::keymint::ErrorCode::MemoryAllocationFailed,
            "allocation of Vec failed".into(),
        )
        .into()
    }
}

impl From<TryFromIntError> for Error {
    fn from(_e: TryFromIntError) -> Self {
        ErrorKind::Hal(
            kmr_wire::keymint::ErrorCode::InvalidArgument,
            "failed to convert integer".into(),
        )
        .into()
    }
}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        ErrorKind::Cbor(e).into()
    }
}

impl From<cbor::value::Error> for Error {
    fn from(e: cbor::value::Error) -> Self {
        ErrorKind::Cbor(e.into()).into()
    }
}

/// Check for an expected error.
#[macro_export]
macro_rules! expect_err {
    ($result:expr, $err_msg:expr) => {
        assert!(
            $result.is_err(),
            "Expected error containing '{}', got success {:?}",
            $err_msg,
            $result
        );
        let err = $result.err();
        assert!(
            std::format!("{:?}", err).contains($err_msg),
            "Unexpected error {:?}, doesn't contain '{}'",
            err,
            $err_msg
        );
    };
}
