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

//! BoringSSL-based implementation of elliptic curve functionality.
use crate::types::{EvpMdCtx, EvpPkeyCtx};
use crate::{cvt, cvt_p, digest_into_openssl, openssl_err, openssl_last_err, ossl};
#[cfg(soong)]
use bssl_sys as ffi;
use core::ops::DerefMut;
use core::ptr;
use foreign_types::ForeignType;
use kmr_common::{
    crypto,
    crypto::{ec, ec::Key, AccumulatingOperation, CurveType, OpaqueOr},
    explicit, km_err, vec_try, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint,
    keymint::{Digest, EcCurve},
};
use openssl::hash::MessageDigest;
use Box;
use Vec;

#[cfg(soong)]
fn private_key_from_der_for_group(
    der: &[u8],
    group: &openssl::ec::EcGroupRef,
) -> Result<openssl::ec::EcKey<openssl::pkey::Private>, openssl::error::ErrorStack> {
    // This method is an Android modification to the rust-openssl crate.
    openssl::ec::EcKey::private_key_from_der_for_group(der, group)
}

#[cfg(not(soong))]
fn private_key_from_der_for_group(
    der: &[u8],
    _group: &openssl::ec::EcGroupRef,
) -> Result<openssl::ec::EcKey<openssl::pkey::Private>, openssl::error::ErrorStack> {
    // This doesn't work if the encoded data is missing the curve.
    openssl::ec::EcKey::private_key_from_der(der)
}

/// [`crypto::Ec`] implementation based on BoringSSL.
pub struct BoringEc {
    /// Zero-sized private field to force use of [`default()`] for initialization.
    _priv: core::marker::PhantomData<()>,
}

impl core::default::Default for BoringEc {
    fn default() -> Self {
        ffi::init();
        Self {
            _priv: core::marker::PhantomData,
        }
    }
}

impl crypto::Ec for BoringEc {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        curve: ec::NistCurve,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let ec_key = ossl!(openssl::ec::EcKey::<openssl::pkey::Private>::generate(
            nist_curve_to_group(curve)?.as_ref()
        ))?;
        let nist_key = ec::NistKey(ossl!(ec_key.private_key_to_der())?);
        let key = match curve {
            ec::NistCurve::P224 => Key::P224(nist_key),
            ec::NistCurve::P256 => Key::P256(nist_key),
            ec::NistCurve::P384 => Key::P384(nist_key),
            ec::NistCurve::P521 => Key::P521(nist_key),
        };
        Ok(crypto::KeyMaterial::Ec(
            curve.into(),
            CurveType::Nist,
            key.into(),
        ))
    }

    fn generate_ed25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let pkey = ossl!(openssl::pkey::PKey::generate_ed25519())?;
        let key = ossl!(pkey.raw_private_key())?;
        let key: [u8; ec::CURVE25519_PRIV_KEY_LEN] = key.try_into().map_err(|e| {
            km_err!(
                UnsupportedKeySize,
                "generated Ed25519 key of unexpected size: {:?}",
                e
            )
        })?;
        let key = Key::Ed25519(ec::Ed25519Key(key));
        Ok(crypto::KeyMaterial::Ec(
            EcCurve::Curve25519,
            CurveType::EdDsa,
            key.into(),
        ))
    }

    fn generate_x25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let pkey = ossl!(openssl::pkey::PKey::generate_x25519())?;
        let key = ossl!(pkey.raw_private_key())?;
        let key: [u8; ec::CURVE25519_PRIV_KEY_LEN] = key.try_into().map_err(|e| {
            km_err!(
                UnsupportedKeySize,
                "generated X25519 key of unexpected size: {:?}",
                e
            )
        })?;
        let key = Key::X25519(ec::X25519Key(key));
        Ok(crypto::KeyMaterial::Ec(
            EcCurve::Curve25519,
            CurveType::Xdh,
            key.into(),
        ))
    }

    fn nist_public_key(&self, key: &ec::NistKey, curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
        let group = nist_curve_to_group(curve)?;
        let ec_key = ossl!(private_key_from_der_for_group(&key.0, group.as_ref()))?;
        let pt = ec_key.public_key();
        let mut bn_ctx = ossl!(openssl::bn::BigNumContext::new())?;
        ossl!(pt.to_bytes(
            group.as_ref(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            bn_ctx.deref_mut()
        ))
    }

    fn ed25519_public_key(&self, key: &ec::Ed25519Key) -> Result<Vec<u8>, Error> {
        let pkey = ossl!(openssl::pkey::PKey::private_key_from_raw_bytes(
            &key.0,
            openssl::pkey::Id::ED25519
        ))?;
        ossl!(pkey.raw_public_key())
    }

    fn x25519_public_key(&self, key: &ec::X25519Key) -> Result<Vec<u8>, Error> {
        let pkey = ossl!(openssl::pkey::PKey::private_key_from_raw_bytes(
            &key.0,
            openssl::pkey::Id::X25519
        ))?;
        ossl!(pkey.raw_public_key())
    }

    fn begin_agree(&self, key: OpaqueOr<Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        // Maximum size for a `SubjectPublicKeyInfo` that holds an EC public key is:
        //
        // 30 LL  SEQUENCE + len (SubjectPublicKeyInfo)
        // 30 LL  SEQUENCE + len (AlgorithmIdentifier)
        // 06 07  OID + len
        //     2a8648ce3d0201  (ecPublicKey OID)
        // 06 08  OID + len
        //     2a8648ce3d030107 (P-256 curve OID, which is the longest)
        // 03 42  BIT STRING + len
        //     00  zero pad bits
        //     04  uncompressed
        //     ...  66 bytes of P-521 X coordinate
        //     ...  66 bytes of P-521 Y coordinate
        //
        // Round up a bit just in case.
        let max_size = 164;
        Ok(Box::new(BoringEcAgreeOperation {
            key,
            pending_input: Vec::new(),
            max_size,
        }))
    }

    fn begin_sign(
        &self,
        key: OpaqueOr<Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let curve = key.curve();
        match key {
            Key::P224(key) | Key::P256(key) | Key::P384(key) | Key::P521(key) => {
                let curve = ec::NistCurve::try_from(curve)?;
                if let Some(digest) = digest_into_openssl(digest) {
                    Ok(Box::new(BoringEcDigestSignOperation::new(
                        key, curve, digest,
                    )?))
                } else {
                    Ok(Box::new(BoringEcUndigestSignOperation::new(key, curve)?))
                }
            }
            Key::Ed25519(key) => Ok(Box::new(BoringEd25519SignOperation::new(key)?)),
            Key::X25519(_) => Err(km_err!(
                IncompatibleAlgorithm,
                "X25519 key not valid for signing"
            )),
        }
    }
}

/// ECDH operation based on BoringSSL.
pub struct BoringEcAgreeOperation {
    key: Key,
    pending_input: Vec<u8>, // Limited to `max_size` below.
    // Size of a `SubjectPublicKeyInfo` holding peer public key.
    max_size: usize,
}

impl crypto::AccumulatingOperation for BoringEcAgreeOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let peer_key = ossl!(openssl::pkey::PKey::public_key_from_der(
            &self.pending_input
        ))?;
        match &self.key {
            Key::P224(key) | Key::P256(key) | Key::P384(key) | Key::P521(key) => {
                let group = nist_key_to_group(&self.key)?;
                let ec_key = ossl!(private_key_from_der_for_group(&key.0, group.as_ref()))?;
                let pkey = ossl!(openssl::pkey::PKey::from_ec_key(ec_key))?;
                let mut deriver = ossl!(openssl::derive::Deriver::new(&pkey))?;
                ossl!(deriver.set_peer(&peer_key))
                    .map_err(|e| km_err!(InvalidArgument, "peer key invalid: {:?}", e))?;
                let derived = ossl!(deriver.derive_to_vec())?;
                Ok(derived)
            }
            #[cfg(soong)]
            Key::X25519(key) => {
                // The BoringSSL `EVP_PKEY` interface does not support X25519, so need to invoke the
                // `ffi:X25519()` method directly. First need to extract the raw peer key from the
                // `SubjectPublicKeyInfo` it arrives in.
                let peer_key = ossl!(openssl::pkey::PKey::public_key_from_der(
                    &self.pending_input
                ))?;
                let peer_key_type = peer_key.id();
                if peer_key_type != openssl::pkey::Id::X25519 {
                    return Err(km_err!(
                        InvalidArgument,
                        "peer key for {:?} not supported with X25519",
                        peer_key_type
                    ));
                }
                let peer_key_data = ossl!(peer_key.raw_public_key())?;
                if peer_key_data.len() != ffi::X25519_PUBLIC_VALUE_LEN as usize {
                    return Err(km_err!(
                        UnsupportedKeySize,
                        "peer raw key invalid length {}",
                        peer_key_data.len()
                    ));
                }

                let mut sig = vec_try![0; ffi::X25519_SHARED_KEY_LEN as usize]?;
                // Safety: all pointer arguments need to point to 32-byte memory areas, enforced
                // above and in the definition of [`ec::X25519Key`].
                let result = unsafe {
                    ffi::X25519(
                        sig.as_mut_ptr(),
                        &key.0 as *const u8,
                        peer_key_data.as_ptr(),
                    )
                };
                if result == 1 {
                    Ok(sig)
                } else {
                    Err(super::openssl_last_err())
                }
            }
            #[cfg(not(soong))]
            Key::X25519(_) => Err(km_err!(UnsupportedEcCurve, "X25519 not supported in cargo")),
            Key::Ed25519(_) => Err(km_err!(
                IncompatibleAlgorithm,
                "Ed25519 key not valid for agreement"
            )),
        }
    }
}

/// ECDSA signing operation based on BoringSSL, when an external digest is used.
pub struct BoringEcDigestSignOperation {
    // Safety: `pkey` internally holds a pointer to BoringSSL-allocated data (`EVP_PKEY`),
    // as do both of the raw pointers.  This means that this item stays valid under moves,
    // because the FFI-allocated data doesn't move.
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,

    // Safety invariant: both `pctx` and `md_ctx` are non-`nullptr` and valid once item is
    // constructed.
    md_ctx: EvpMdCtx,
    pctx: EvpPkeyCtx,
}

impl Drop for BoringEcDigestSignOperation {
    fn drop(&mut self) {
        // Safety: `EVP_MD_CTX_free()` handles `nullptr`, so it's fine to drop a partly-constructed
        // item.  `pctx` is owned by the `md_ctx`, so no need to explicitly free it.
        unsafe {
            ffi::EVP_MD_CTX_free(self.md_ctx.0);
        }
    }
}

impl BoringEcDigestSignOperation {
    fn new(key: ec::NistKey, curve: ec::NistCurve, digest: MessageDigest) -> Result<Self, Error> {
        let group = nist_curve_to_group(curve)?;
        let ec_key = ossl!(private_key_from_der_for_group(&key.0, group.as_ref()))?;
        let pkey = ossl!(openssl::pkey::PKey::from_ec_key(ec_key))?;

        // Safety: each of the raw pointers have to be non-nullptr (and thus valid, as BoringSSL
        // emits only valid pointers or nullptr) to get to the point where they're used.
        unsafe {
            let mut op = BoringEcDigestSignOperation {
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
            // Safety invariant: both `pctx` and `md_ctx` are non-`nullptr` and valid on success.
            Ok(op)
        }
    }
}

impl crypto::AccumulatingOperation for BoringEcDigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // Safety: `data` is a valid slice, and `self.md_ctx` is non-`nullptr` and valid.
        unsafe {
            cvt(ffi::EVP_DigestUpdate(
                self.md_ctx.0,
                data.as_ptr() as *const _,
                data.len(),
            ))?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut max_siglen = 0;
        // Safety: `self.md_ctx` is non-`nullptr` and valid.
        unsafe {
            cvt(ffi::EVP_DigestSignFinal(
                self.md_ctx.0,
                ptr::null_mut(),
                &mut max_siglen,
            ))?;
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

/// ECDSA signing operation based on BoringSSL, when data is undigested.
pub struct BoringEcUndigestSignOperation {
    ec_key: openssl::ec::EcKey<openssl::pkey::Private>,
    pending_input: Vec<u8>,
    max_size: usize,
}

impl BoringEcUndigestSignOperation {
    fn new(key: ec::NistKey, curve: ec::NistCurve) -> Result<Self, Error> {
        let group = nist_curve_to_group(curve)?;
        let ec_key = ossl!(private_key_from_der_for_group(&key.0, group.as_ref()))?;
        // Input to an undigested EC signing operation must be smaller than key size.
        Ok(Self {
            ec_key,
            pending_input: Vec::new(),
            max_size: curve.coord_len(),
        })
    }
}

impl crypto::AccumulatingOperation for BoringEcUndigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // For ECDSA signing, extra data beyond the maximum size is ignored (rather than being
        // rejected via the `max_input_size()` trait method).
        let max_extra_data = self.max_size - self.pending_input.len();
        if max_extra_data > 0 {
            let len = core::cmp::min(max_extra_data, data.len());
            self.pending_input.try_extend_from_slice(&data[..len])?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        // BoringSSL doesn't support `EVP_PKEY` use without digest, so use low-level ECDSA
        // functionality.
        let sig = ossl!(openssl::ecdsa::EcdsaSig::sign(
            &self.pending_input,
            &self.ec_key
        ))?;
        let sig = ossl!(sig.to_der())?;
        Ok(sig)
    }
}

/// EdDSA signing operation based on BoringSSL for Ed25519.
pub struct BoringEd25519SignOperation {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    pending_input: Vec<u8>,
}

impl BoringEd25519SignOperation {
    fn new(key: ec::Ed25519Key) -> Result<Self, Error> {
        let pkey = ossl!(openssl::pkey::PKey::private_key_from_raw_bytes(
            &key.0,
            openssl::pkey::Id::ED25519
        ))?;
        Ok(Self {
            pkey,
            pending_input: Vec::new(),
        })
    }
}

impl crypto::AccumulatingOperation for BoringEd25519SignOperation {
    fn max_input_size(&self) -> Option<usize> {
        // Ed25519 has an internal digest so could theoretically take arbitrary amounts of
        // data. However, BoringSSL does not support incremental data feeding for Ed25519 so
        // instead impose a message size limit (as required by the KeyMint HAL spec).
        Some(ec::MAX_ED25519_MSG_SIZE)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // OK to accumulate data as there is a size limit.
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut signer = ossl!(openssl::sign::Signer::new_without_digest(&self.pkey))?;
        let sig = ossl!(signer.sign_oneshot_to_vec(&self.pending_input))?;
        Ok(sig)
    }
}

fn nist_curve_to_group(curve: ec::NistCurve) -> Result<openssl::ec::EcGroup, Error> {
    use openssl::nid::Nid;
    openssl::ec::EcGroup::from_curve_name(match curve {
        ec::NistCurve::P224 => Nid::SECP224R1,
        ec::NistCurve::P256 => Nid::X9_62_PRIME256V1,
        ec::NistCurve::P384 => Nid::SECP384R1,
        ec::NistCurve::P521 => Nid::SECP521R1,
    })
    .map_err(openssl_err!("failed to determine EcGroup"))
}

fn nist_key_to_group(key: &ec::Key) -> Result<openssl::ec::EcGroup, Error> {
    use openssl::nid::Nid;
    openssl::ec::EcGroup::from_curve_name(match key {
        ec::Key::P224(_) => Nid::SECP224R1,
        ec::Key::P256(_) => Nid::X9_62_PRIME256V1,
        ec::Key::P384(_) => Nid::SECP384R1,
        ec::Key::P521(_) => Nid::SECP521R1,
        ec::Key::Ed25519(_) | ec::Key::X25519(_) => {
            return Err(km_err!(
                UnsupportedEcCurve,
                "no NIST group for curve25519 key"
            ))
        }
    })
    .map_err(openssl_err!("failed to determine EcGroup"))
}
