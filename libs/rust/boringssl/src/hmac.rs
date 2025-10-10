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

//! BoringSSL-based implementation of HMAC.
use crate::types::HmacCtx;
use crate::{malloc_err, openssl_last_err};
use anyhow::Result;
#[cfg(soong)]
use bssl_sys as ffi;
use kmr_common::crypto::Hkdf;
use kmr_common::{crypto, crypto::OpaqueOr, explicit, km_err, vec_try, Error};
use kmr_wire::keymint::Digest;
use log::error;
use Box;
use Vec;

/// [`crypto::Hmac`] implementation based on BoringSSL.
pub struct BoringHmac;

impl crypto::Hmac for BoringHmac {
    fn begin(
        &self,
        key: OpaqueOr<crypto::hmac::Key>,
        digest: Digest,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let op = BoringHmacOperation {
            // Safety: BoringSSL emits either null or a valid raw pointer, and the value is
            // immediately checked for null below.
            ctx: unsafe { HmacCtx(ffi::HMAC_CTX_new()) },
        };
        if op.ctx.0.is_null() {
            return Err(malloc_err!());
        }

        let digest = digest_into_openssl_ffi(digest)?;
        #[cfg(soong)]
        let key_len = key.0.len();
        #[cfg(not(soong))]
        let key_len = key.0.len() as i32;

        // Safety: `op.ctx` is known non-null and valid, as is the result of
        // `digest_into_openssl_ffi()`.  `key_len` is length of `key.0`, which is a valid `Vec<u8>`.
        #[cfg(not(target_os = "android"))]
        let result = unsafe {
            ffi::HMAC_Init_ex(
                op.ctx.0,
                key.0.as_ptr() as *const libc::c_void,
                key_len,
                digest,
                core::ptr::null_mut(),
            )
        };

        #[cfg(target_os = "android")]
        let result = unsafe {
            ffi::HMAC_Init_ex(
                op.ctx.0,
                key.0.as_ptr() as *const libc::c_void,
                key_len as usize,
                digest,
                core::ptr::null_mut(),
            )
        };

        if result != 1 {
            error!("Failed to HMAC_Init_ex()");
            return Err(openssl_last_err());
        }
        Ok(Box::new(op))
    }
}

/// HMAC operation based on BoringSSL.
///
/// This implementation uses the `unsafe` wrappers around `HMAC_*` functions directly, because
/// BoringSSL does not support the `EVP_PKEY_HMAC` implementations that are used in the rust-openssl
/// crate.
pub struct BoringHmacOperation {
    // Safety: `ctx` is always non-null and valid except for initial error path in `begin()`
    ctx: HmacCtx,
}

impl core::ops::Drop for BoringHmacOperation {
    fn drop(&mut self) {
        // Safety: `self.ctx` might be null (in the error path when `ffi::HMAC_CTX_new` fails)
        // but `ffi::HMAC_CTX_free` copes with null.
        unsafe {
            ffi::HMAC_CTX_free(self.ctx.0);
        }
    }
}

impl crypto::AccumulatingOperation for BoringHmacOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // Safety: `self.ctx` is non-null and valid, and `data` is a valid slice.
        let result = unsafe { ffi::HMAC_Update(self.ctx.0, data.as_ptr(), data.len()) };
        if result != 1 {
            return Err(openssl_last_err());
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut output_len = ffi::EVP_MAX_MD_SIZE as u32;
        let mut output = vec_try![0; ffi::EVP_MAX_MD_SIZE as usize]?;

        // Safety: `self.ctx` is non-null and valid; `output_len` is correct size of `output`
        // buffer.
        let result = unsafe {
            // (force line break for safety lint limitation)
            ffi::HMAC_Final(self.ctx.0, output.as_mut_ptr(), &mut output_len as *mut u32)
        };
        if result != 1 {
            return Err(openssl_last_err());
        }
        output.truncate(output_len as usize);
        Ok(output)
    }
}

/// Translate a [`keymint::Digest`] into a raw [`ffi::EVD_MD`].
fn digest_into_openssl_ffi(digest: Digest) -> Result<*const ffi::EVP_MD, Error> {
    // Safety: all of the `EVP_<digest>` functions return a non-null valid pointer.
    unsafe {
        match digest {
            Digest::Md5 => Ok(ffi::EVP_md5()),
            Digest::Sha1 => Ok(ffi::EVP_sha1()),
            Digest::Sha224 => Ok(ffi::EVP_sha224()),
            Digest::Sha256 => Ok(ffi::EVP_sha256()),
            Digest::Sha384 => Ok(ffi::EVP_sha384()),
            Digest::Sha512 => Ok(ffi::EVP_sha512()),
            d => Err(km_err!(UnsupportedDigest, "unknown digest {:?}", d)),
        }
    }
}

pub fn hkdf_expand(out_len: usize, key: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    let hmac = BoringHmac;
    let key = crypto::hmac::Key(key.to_vec());
    let key: OpaqueOr<crypto::hmac::Key> = OpaqueOr::Explicit(key);

    let result = hmac.expand(&key, info, out_len);

    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(anyhow::anyhow!("hkdf expand error:0 {:?}", e)),
    }
}
