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
#![cfg_attr(feature = "nightly", feature(allocator_api))]

extern crate std;

use core::mem::MaybeUninit;
use kmr_common::{crypto, Error, ErrorKind};
use kmr_wire::keymint::{Digest, ErrorCode};
use log::error;
use openssl::hash::MessageDigest;
use std::boxed::Box;

// There is no OpenSSL CMAC API that is available in both BoringSSL for Android (which has `cmac.h`
// functions but not `EVP_PKEY_CMAC` functionality) and in tip OpenSSL (which has `EVP_PKEY_CMAC`
// functionality but which has removed `cmac.h`).  So only build AES-CMAC for Android.
pub mod aes_cmac;

pub mod aes;
pub mod des;
pub mod ec;
pub mod eq;
pub mod error;
pub mod hmac;
pub mod km;
pub mod mldsa;
pub mod rng;
pub mod rsa;
pub mod sha256;
pub mod zvec;

mod err;
use err::map_openssl_err;

#[cfg(test)]
mod tests;

mod types;

/// Return a collection of BoringSSL-backed cryptographic trait implementations (together
/// with the provided RNG and clock implementations).
pub fn implementation(
    rng: Box<dyn crypto::Rng>,
    clock: Box<dyn crypto::MonotonicClock>,
) -> crypto::Implementation {
    crypto::Implementation {
        rng,
        clock: Some(clock),
        compare: Box::new(eq::BoringEq),
        aes: Box::new(aes::BoringAes),
        des: Box::new(des::BoringDes),
        hmac: Box::new(hmac::BoringHmac),
        rsa: Box::<rsa::BoringRsa>::default(),
        ec: Box::<ec::BoringEc>::default(),
        ckdf: Box::new(aes_cmac::BoringAesCmac),
        hkdf: Box::new(hmac::BoringHmac),
        sha256: Box::new(sha256::BoringSha256),
        mldsa: Box::new(mldsa::BoringMlDsa),
    }
}

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

/// Macro to emit a closure that builds an [`Error`] instance, based on an openssl `ErrorStack`
/// together with a format-like message.
#[macro_export]
macro_rules! openssl_err {
    { $($arg:tt)+ } => {
        |e| {
            kmr_common::km_err_new!(kmr_common::ErrorKind::Hal(
                $crate::map_openssl_errstack(&e),
                std::format!("{}: {e:?}", format_args!($($arg)+)).into(),
            ))
        }
    };
}

/// Macro to emit a closure that builds an [`Error`] instance, based on an openssl `ErrorStack`
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
            kmr_common::km_err_new!(kmr_common::ErrorKind::Hal(
                errcode,
                std::format!("{}: {e:?}", format_args!($($arg)+)).into(),
            ))
        }
    };
}

/// Macro to emit an [`Error`] indicating allocation failure at the current location.
#[macro_export]
macro_rules! malloc_err {
    {} => {
        kmr_common::km_err_new!(kmr_common::ErrorKind::Alloc("BoringSSL allocation failed"))
    };
}

/// Translate the most recent OpenSSL error into [`Error`].
fn openssl_last_err() -> Error {
    from_openssl_err(openssl::error::ErrorStack::get())
}

/// Translate a returned `openssl` error into [`Error`].
fn from_openssl_err(errs: openssl::error::ErrorStack) -> Error {
    ErrorKind::Hal(map_openssl_errstack(&errs), "OpenSSL failure".into()).into()
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
fn cvt(r: libc::c_int) -> Result<libc::c_int, Error> {
    if r <= 0 {
        Err(openssl_last_err())
    } else {
        Ok(r)
    }
}

/// Returns a boxed BoringSSL structure that is initialized by some function.
/// Requires that the given function completely initializes the value or else
/// returns `Err`.
///
/// Adapted from boringssl/rust/bssl-crypto/lib.rs
///
/// # Safety
///
/// The argument must fully initialize the pointed-to `T` if it returns
/// `Ok`. If it returns `Err` then there are no safety requirements.
unsafe fn initialized_boxed_struct<T, F>(init: F) -> Result<Box<T>, Error>
where
    F: FnOnce(*mut T) -> Result<(), Error>,
{
    #[cfg(feature = "nightly")]
    let Ok(mut out_uninit) = Box::try_new(MaybeUninit::<T>::uninit()) else {
        return Err(kmr_common::alloc_err!("Box<T>"));
    };
    #[cfg(not(feature = "nightly"))]
    let mut out_uninit = Box::new(MaybeUninit::<T>::uninit());

    init(out_uninit.as_mut_ptr()).map(|_| {
        // Safety: argument assumed to fully initialize the `T` on returning `Ok`.
        unsafe { out_uninit.assume_init() }
    })
}

/// Returns a BoringSSL structure that is initialized by some function.
/// Requires that the given function completely initializes the value or else
/// returns `Err`.
///
/// Adapted from boringssl/rust/bssl-crypto/lib.rs
///
/// # Safety
///
/// The argument must fully initialize the pointed-to `T` in all circumstances.
unsafe fn initialized_struct<T, F>(init: F) -> Result<T, Error>
where
    F: FnOnce(*mut T) -> Result<(), Error>,
{
    let mut out_uninit = MaybeUninit::<T>::uninit();
    init(out_uninit.as_mut_ptr()).map(|_| {
        // Safety: argument assumed to fully initialize the `T` on returning `Ok`.
        unsafe { out_uninit.assume_init() }
    })
}

/// FfiSlice exists to provide `as_ffi_ptr` on slices. Calling `as_ptr` on an
/// empty Rust slice may return the alignment of the type, rather than NULL, as
/// the pointer. When passing pointers into C/C++ code, that is not a valid
/// pointer. Thus this method should be used whenever passing a pointer to a
/// slice into BoringSSL code.
///
/// Copied from boringssl/rust/bssl-crypto/lib.rs
trait FfiSlice<T> {
    fn as_ffi_ptr(&self) -> *const T;
}

impl<T> FfiSlice<T> for [T] {
    fn as_ffi_ptr(&self) -> *const T {
        if self.is_empty() {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

impl<T, const N: usize> FfiSlice<T> for [T; N] {
    fn as_ffi_ptr(&self) -> *const T {
        if N == 0 {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

/// See the comment for [`FfiSlice`].
///
/// Copied from boringssl/rust/bssl-crypto/lib.rs
trait FfiMutSlice {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8;
}

impl FfiMutSlice for [u8] {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8 {
        if self.is_empty() {
            core::ptr::null_mut()
        } else {
            self.as_mut_ptr()
        }
    }
}
