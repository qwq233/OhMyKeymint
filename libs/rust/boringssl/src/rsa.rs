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

//! BoringSSL-based implementation of RSA.
use crate::types::{EvpMdCtx, EvpPkeyCtx};
use crate::{cvt, cvt_p, digest_into_openssl, openssl_err, openssl_last_err, ossl};
use Box;
use Vec;
#[cfg(soong)]
use bssl_sys as ffi;
use core::ptr;
use foreign_types::ForeignType;
use kmr_common::crypto::{
    rsa::{DecryptionMode, SignMode, PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD},
    OpaqueOr,
};
use kmr_common::{crypto, explicit, km_err, vec_try, Error, FallibleAllocExt};
use kmr_wire::{keymint, keymint::Digest, KeySizeInBits, RsaExponent};
use openssl::hash::MessageDigest;

/// Smallest allowed public exponent.
const MIN_RSA_EXPONENT: RsaExponent = RsaExponent(3);

/// [`crypto::Rsa`] implementation based on BoringSSL.
pub struct BoringRsa {
    /// Zero-sized private field to force use of [`default()`] for initialization.
    _priv: core::marker::PhantomData<()>,
}

impl core::default::Default for BoringRsa {
    fn default() -> Self {
        ffi::init();
        Self { _priv: core::marker::PhantomData }
    }
}

impl crypto::Rsa for BoringRsa {
    fn generate_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        key_size: KeySizeInBits,
        pub_exponent: RsaExponent,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        // Reject some obviously-wrong parameter values.
        if pub_exponent < MIN_RSA_EXPONENT {
            return Err(km_err!(
                InvalidArgument,
                "Invalid public exponent, {:?} < {:?}",
                pub_exponent,
                MIN_RSA_EXPONENT
            ));
        }
        if pub_exponent.0 % 2 != 1 {
            return Err(km_err!(
                InvalidArgument,
                "Invalid public exponent {:?} (even number)",
                pub_exponent
            ));
        }
        let exponent = openssl::bn::BigNum::from_slice(&pub_exponent.0.to_be_bytes()[..])
            .map_err(openssl_err!("failed to create BigNum for exponent {:?}", pub_exponent))?;

        let rsa_key =
            openssl::rsa::Rsa::generate_with_e(key_size.0, &exponent).map_err(openssl_err!(
                "failed to generate RSA key size {:?} exponent {:?}",
                key_size,
                pub_exponent
            ))?;
        let asn1_data = ossl!(rsa_key.private_key_to_der())?;
        Ok(crypto::KeyMaterial::Rsa(crypto::rsa::Key(asn1_data).into()))
    }

    fn begin_decrypt(
        &self,
        key: OpaqueOr<crypto::rsa::Key>,
        mode: DecryptionMode,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let max_size = key.size();
        Ok(Box::new(BoringRsaDecryptOperation { key, mode, pending_input: Vec::new(), max_size }))
    }

    fn begin_sign(
        &self,
        key: OpaqueOr<crypto::rsa::Key>,
        mode: SignMode,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let padding = match mode {
            SignMode::NoPadding => openssl::rsa::Padding::NONE,
            SignMode::Pkcs1_1_5Padding(_) => openssl::rsa::Padding::PKCS1,
            SignMode::PssPadding(_) => openssl::rsa::Padding::PKCS1_PSS,
        };

        match mode {
            SignMode::NoPadding | SignMode::Pkcs1_1_5Padding(Digest::None) => {
                Ok(Box::new(BoringRsaUndigestSignOperation::new(key, mode)?))
            }
            SignMode::Pkcs1_1_5Padding(digest) | SignMode::PssPadding(digest) => {
                if let Some(digest) = digest_into_openssl(digest) {
                    Ok(Box::new(BoringRsaDigestSignOperation::new(key, mode, digest, padding)?))
                } else {
                    Err(km_err!(InvalidArgument, "no digest provided for mode {:?}", mode))
                }
            }
        }
    }
}

/// RSA decryption operation based on BoringSSL.
pub struct BoringRsaDecryptOperation {
    key: crypto::rsa::Key,
    mode: DecryptionMode,
    pending_input: Vec<u8>, // Limited to size of key (`max_size` below).
    max_size: usize,
}

impl crypto::AccumulatingOperation for BoringRsaDecryptOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        let rsa_key = ossl!(openssl::rsa::Rsa::private_key_from_der(&self.key.0))?;
        let priv_key = ossl!(openssl::pkey::PKey::from_rsa(rsa_key))?;
        let mut decrypter = ossl!(openssl::encrypt::Decrypter::new(&priv_key))?;

        let padding = match self.mode {
            DecryptionMode::NoPadding => openssl::rsa::Padding::NONE,
            DecryptionMode::OaepPadding { msg_digest: _, mgf_digest: _ } => {
                openssl::rsa::Padding::PKCS1_OAEP
            }
            DecryptionMode::Pkcs1_1_5Padding => openssl::rsa::Padding::PKCS1,
        };
        decrypter
            .set_rsa_padding(padding)
            .map_err(openssl_err!("failed to create set_rsa_padding for {:?}", self.mode))?;

        if let DecryptionMode::OaepPadding { msg_digest, mgf_digest } = self.mode {
            let omsg_digest = digest_into_openssl(msg_digest).ok_or_else(|| {
                km_err!(UnsupportedDigest, "Digest::None not allowed for RSA-OAEP msg digest")
            })?;
            let omgf_digest = digest_into_openssl(mgf_digest).ok_or_else(|| {
                km_err!(UnsupportedDigest, "Digest::None not allowed for RSA-OAEP MGF1 digest")
            })?;
            decrypter
                .set_rsa_oaep_md(omsg_digest)
                .map_err(openssl_err!("failed to set digest {:?}", msg_digest))?;
            decrypter
                .set_rsa_mgf1_md(omgf_digest)
                .map_err(openssl_err!("failed to set MGF digest {:?}", mgf_digest))?;
        }

        let buf_len = ossl!(decrypter.decrypt_len(&self.pending_input))?;
        let mut output = vec_try![0; buf_len]?;

        if self.mode == DecryptionMode::NoPadding && self.pending_input.len() < buf_len {
            self.pending_input = zero_pad_left(&self.pending_input, buf_len)?;
        }

        let actual_len = ossl!(decrypter.decrypt(&self.pending_input, &mut output))?;
        output.truncate(actual_len);

        Ok(output)
    }
}

/// RSA signing operation based on BoringSSL, for when an external digest is used.
/// Directly uses FFI functions because [`openssl::sign::Signer`] requires a lifetime.
pub struct BoringRsaDigestSignOperation {
    // Safety: `pkey` internally holds a pointer to BoringSSL-allocated data (`EVP_PKEY`),
    // as do both of the raw pointers.  This means that this item stays valid under moves,
    // because the FFI-allocated data doesn't move.
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,

    // Safety invariant: both `pctx` and `md_ctx` are non-`nullptr` (and valid and non-aliased) once
    // item is constructed.
    md_ctx: EvpMdCtx,
    pctx: EvpPkeyCtx,
}

impl Drop for BoringRsaDigestSignOperation {
    fn drop(&mut self) {
        // Safety: `md_ctx` is non-`nullptr` and valid due to invariant. `pctx` is owned by the
        // `md_ctx`, so no need to explicitly free it.
        unsafe {
            ffi::EVP_MD_CTX_free(self.md_ctx.0);
        }
    }
}

impl BoringRsaDigestSignOperation {
    fn new(
        key: crypto::rsa::Key,
        mode: SignMode,
        digest: MessageDigest,
        padding: openssl::rsa::Padding,
    ) -> Result<Self, Error> {
        let rsa_key = ossl!(openssl::rsa::Rsa::private_key_from_der(&key.0))?;
        let pkey = ossl!(openssl::pkey::PKey::from_rsa(rsa_key))?;

        // Safety: all raw pointers are non-`nullptr` (and valid and non-aliasing) if returned
        // without error from BoringSSL entrypoints.
        unsafe {
            let mut op = BoringRsaDigestSignOperation {
                pkey,
                md_ctx: EvpMdCtx(cvt_p(ffi::EVP_MD_CTX_new())?),
                pctx: EvpPkeyCtx(ptr::null_mut()),
            };

            let r = ffi::EVP_DigestSignInit(
                op.md_ctx.0,
                &mut op.pctx.0,
                digest.as_ptr(),
                ptr::null_mut(),
                op.pkey.as_ptr(),
            );
            if r != 1 {
                return Err(openssl_last_err());
            }
            if op.pctx.0.is_null() {
                return Err(km_err!(BoringSslError, "no PCTX!"));
            }

            // Safety: `op.pctx` is not `nullptr` and is valid.
            cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(op.pctx.0, padding.as_raw()))?;

            if let SignMode::PssPadding(digest) = mode {
                let digest_len = (kmr_common::tag::digest_len(digest)? / 8) as libc::c_int;
                // Safety: `op.pctx` is not `nullptr` and is valid.
                cvt(ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(op.pctx.0, digest_len))?;
            }

            // Safety invariant: both `pctx` and `md_ctx` are non-`nullptr` and valid pointers on
            // success.
            Ok(op)
        }
    }
}

impl crypto::AccumulatingOperation for BoringRsaDigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // Safety: `data` is a valid slice, and `self.md_ctx` is non-`nullptr` and valid.
        unsafe {
            cvt(ffi::EVP_DigestUpdate(self.md_ctx.0, data.as_ptr() as *const _, data.len()))?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut max_siglen = 0;
        // Safety: `self.md_ctx` is non-`nullptr` and valid.
        unsafe {
            cvt(ffi::EVP_DigestSignFinal(self.md_ctx.0, ptr::null_mut(), &mut max_siglen))?;
        }
        let mut buf = vec_try![0; max_siglen]?;
        let mut actual_siglen = max_siglen;
        // Safety: `self.md_ctx` is non-`nullptr` and valid, and `buf` does have `actual_siglen`
        // bytes.
        unsafe {
            cvt(ffi::EVP_DigestSignFinal(
                self.md_ctx.0,
                buf.as_mut_ptr() as *mut _,
                &mut actual_siglen,
            ))?;
        }
        buf.truncate(actual_siglen);
        Ok(buf)
    }
}

/// RSA signing operation based on BoringSSL, for undigested data.
pub struct BoringRsaUndigestSignOperation {
    rsa_key: openssl::rsa::Rsa<openssl::pkey::Private>,
    left_pad: bool,
    pending_input: Vec<u8>,
    max_size: usize,
}

impl BoringRsaUndigestSignOperation {
    fn new(key: crypto::rsa::Key, mode: SignMode) -> Result<Self, Error> {
        let rsa_key = ossl!(openssl::rsa::Rsa::private_key_from_der(&key.0))?;
        let (left_pad, max_size) = match mode {
            SignMode::NoPadding => (true, rsa_key.size() as usize),
            SignMode::Pkcs1_1_5Padding(Digest::None) => {
                (false, (rsa_key.size() as usize) - PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD)
            }
            _ => return Err(km_err!(UnsupportedPaddingMode, "sign undigested mode {:?}", mode)),
        };
        Ok(Self { rsa_key, left_pad, pending_input: Vec::new(), max_size })
    }
}

impl crypto::AccumulatingOperation for BoringRsaUndigestSignOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // OK to accumulate data as there is a size limit.
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut buf = vec_try![0; self.rsa_key.size() as usize]?;
        if self.left_pad {
            let padded_input = zero_pad_left(&self.pending_input, self.max_size)?;
            ossl!(self.rsa_key.private_encrypt(
                &padded_input,
                &mut buf,
                openssl::rsa::Padding::NONE
            ))?;
        } else {
            ossl!(self.rsa_key.private_encrypt(
                &self.pending_input,
                &mut buf,
                openssl::rsa::Padding::PKCS1
            ))?;
        }

        Ok(buf)
    }
}

fn zero_pad_left(data: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    let mut dest = vec_try![0; len]?;
    let padding_len = len - data.len();
    dest[padding_len..].copy_from_slice(data);
    Ok(dest)
}
