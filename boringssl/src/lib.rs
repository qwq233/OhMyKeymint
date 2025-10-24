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

//! Implementations of [`kmr_common::crypto`] traits based on BoringSSL.
extern crate alloc;

use kmr_common::Error;
use kmr_wire::keymint::{Digest, ErrorCode};
use log::error;
use openssl::hash::MessageDigest;

pub mod aes_cmac;

pub mod aes;
pub mod des;
pub mod ec;
pub mod eq;
pub mod error;
pub mod hmac;
pub mod km;
pub mod rng;
pub mod rsa;
pub mod sha256;
pub mod zvec;

#[cfg(soong)]
mod err;
#[cfg(soong)]
use err::*;

#[cfg(test)]
mod tests;

mod types;

/// Map an OpenSSL `ErrorStack` into a KeyMint [`ErrorCode`] value.
pub(crate) fn map_openssl_errstack(errs: &openssl::error::ErrorStack) -> ErrorCode {
    let errors = errs.errors();
    if errors.is_empty() {
        error!("BoringSSL error requested but none available!");
        return ErrorCode::BoringSslError;
    }
    let err = &errors[0]; // safe: length checked above
    map_openssl_err(err)
}

/// Stub function for mapping an OpenSSL `ErrorStack` into a KeyMint [`ErrorCode`] value.
#[cfg(not(soong))]
fn map_openssl_err(_err: &openssl::error::Error) -> ErrorCode {
    ErrorCode::BoringSslError
}

/// Macro to auto-generate error mapping around invocations of `openssl` methods.
/// An invocation like:
///
/// ```ignore
/// let x = ossl!(y.func(a, b))?;
/// ```
///
/// will map to:
///
/// ```ignore
/// let x = y.func(a, b).map_err(openssl_err!("failed to perform: y.func(a, b)"))?;
/// ```
#[macro_export]
macro_rules! ossl {
    { $e:expr } => {
        $e.map_err(openssl_err!(concat!("failed to perform: ", stringify!($e))))
    }
}

/// Macro to emit a closure that builds an [`Error::Hal`] instance, based on an
/// openssl `ErrorStack` together with a format-like message.
#[macro_export]
macro_rules! openssl_err {
    { $($arg:tt)+ } => {
        |e| kmr_common::Error::Hal(
            $crate::map_openssl_errstack(&e),
            format!("{}:{}: {}: {:?}", file!(), line!(), format_args!($($arg)+), e)
        )
    };
}

/// Macro to emit a closure that builds an [`Error::Hal`] instance, based on an openssl `ErrorStack`
/// together with a format-like message, plus default `ErrorCode` to be used if no OpenSSL error is
/// available.
#[macro_export]
macro_rules! openssl_err_or {
    { $default:ident, $($arg:tt)+ } => {
        |e| {
            let errors = e.errors();
            let errcode = if errors.is_empty() {
                kmr_wire::keymint::ErrorCode::$default
            } else {
                $crate::map_openssl_err(&errors[0]) // safe: length checked above
            };
            kmr_common::Error::Hal(
                errcode,
                format!("{}:{}: {}: {:?}", file!(), line!(), format_args!($($arg)+), e)
            )
        }
    };
}

/// Macro to emit an [`Error`] indicating allocation failure at the current location.
#[macro_export]
macro_rules! malloc_err {
    {} => {
        kmr_common::Error::Alloc(concat!(file!(), ":", line!(), ": BoringSSL allocation failed"))
    };
}

/// Translate the most recent OpenSSL error into [`Error`].
fn openssl_last_err() -> Error {
    from_openssl_err(openssl::error::ErrorStack::get())
}

/// Translate a returned `openssl` error into [`Error`].
fn from_openssl_err(errs: openssl::error::ErrorStack) -> Error {
    Error::Hal(map_openssl_errstack(&errs), "OpenSSL failure".to_string())
}

/// Translate a [`keymint::Digest`] into an OpenSSL [`MessageDigest`].
fn digest_into_openssl(digest: Digest) -> Option<MessageDigest> {
    match digest {
        Digest::None => None,
        Digest::Md5 => Some(MessageDigest::md5()),
        Digest::Sha1 => Some(MessageDigest::sha1()),
        Digest::Sha224 => Some(MessageDigest::sha224()),
        Digest::Sha256 => Some(MessageDigest::sha256()),
        Digest::Sha384 => Some(MessageDigest::sha384()),
        Digest::Sha512 => Some(MessageDigest::sha512()),
    }
}

#[inline]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, Error> {
    if r.is_null() {
        Err(openssl_last_err())
    } else {
        Ok(r)
    }
}

#[inline]
fn ocvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
fn cvt(r: libc::c_int) -> Result<libc::c_int, Error> {
    if r <= 0 {
        Err(openssl_last_err())
    } else {
        Ok(r)
    }
}
