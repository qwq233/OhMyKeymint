// Copyright 2025, The Android Open Source Project
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

//! BoringSSL-based implementation of ML-DSA functionality.

use crate::{initialized_boxed_struct, initialized_struct, FfiMutSlice, FfiSlice};
use kmr_common::crypto::{self, mldsa::Key, AccumulatingOperation, MlDsa, OpaqueOr};
use kmr_common::{explicit, vec_try, Error};
use std::boxed::Box;
use std::vec::Vec;

/// Size of a message representative.
const MU_BYTES: usize = bssl_sys::MLDSA_MU_BYTES as usize;

/// The number of bytes in an encoded ML-DSA-65 public key.
const PUBLIC_KEY_BYTES_65: usize = bssl_sys::MLDSA65_PUBLIC_KEY_BYTES as usize;

/// The number of bytes in an encoded ML-DSA-65 signature.
pub const SIGNATURE_BYTES_65: usize = bssl_sys::MLDSA65_SIGNATURE_BYTES as usize;

/// The number of bytes in an encoded ML-DSA-87 public key.
const PUBLIC_KEY_BYTES_87: usize = bssl_sys::MLDSA87_PUBLIC_KEY_BYTES as usize;

/// The number of bytes in an encoded ML-DSA-87 signature.
pub const SIGNATURE_BYTES_87: usize = bssl_sys::MLDSA87_SIGNATURE_BYTES as usize;

/// Generate an allocation error at the current line.
macro_rules! alloc_err {
    { $text:literal } => { kmr_common::km_err_new!($crate::ErrorKind::Alloc($text)) }
}

/// [`kmr_common::crypto::MlDsa`] implementation based on BoringSSL.
pub struct BoringMlDsa;

enum BoringPrivateKey {
    MlDsa65(Box<bssl_sys::MLDSA65_private_key>),
    MlDsa87(Box<bssl_sys::MLDSA87_private_key>),
}

impl TryFrom<&Key> for BoringPrivateKey {
    type Error = Error;

    fn try_from(key: &Key) -> Result<Self, Error> {
        match key {
            // Safety: `priv_key` is the correct size via the type system and is always fully
            // written on success.  `seed` is valid for the duration of the FFI call.
            Key::MlDsa65(seed) => unsafe {
                initialized_boxed_struct(|priv_key| {
                    let ok = bssl_sys::MLDSA65_private_key_from_seed(
                        priv_key,
                        seed.as_ffi_ptr(),
                        seed.len(),
                    );
                    if ok == 1 {
                        Ok(())
                    } else {
                        Err(alloc_err!("ML-DSA-65 private key"))
                    }
                })
            }
            .map(Self::MlDsa65),

            // Safety: `priv_key` is the correct size via the type system and is always fully
            // written on success.  `seed` is valid for the duration of the FFI call.
            Key::MlDsa87(seed) => unsafe {
                initialized_boxed_struct(|priv_key| {
                    let ok = bssl_sys::MLDSA87_private_key_from_seed(
                        priv_key,
                        seed.as_ffi_ptr(),
                        seed.len(),
                    );
                    if ok == 1 {
                        Ok(())
                    } else {
                        Err(alloc_err!("ML-DSA-87 private key"))
                    }
                })
            }
            .map(Self::MlDsa87),
        }
    }
}

fn to_public_key_65(
    priv_key: &bssl_sys::MLDSA65_private_key,
) -> Result<Box<bssl_sys::MLDSA65_public_key>, Error> {
    // Safety: `pub_key` is the correct size via the type system and is always fully written on
    // success. `priv_key` is valid for the duration of the FFI call.
    unsafe {
        initialized_boxed_struct(|pub_key| {
            bssl_sys::MLDSA65_public_from_private(pub_key, priv_key);
            Ok(())
        })
    }
}

fn to_public_key_87(
    priv_key: &bssl_sys::MLDSA87_private_key,
) -> Result<Box<bssl_sys::MLDSA87_public_key>, Error> {
    // Safety: `pub_key` is the correct size via the type system and is always fully written on
    // success. `priv_key` is valid for the duration of the FFI call.
    unsafe {
        initialized_boxed_struct(|pub_key| {
            bssl_sys::MLDSA87_public_from_private(pub_key, priv_key);
            Ok(())
        })
    }
}

impl BoringPrivateKey {
    fn to_public_key(&self) -> Result<BoringPublicKey, Error> {
        match self {
            Self::MlDsa65(priv_key) => to_public_key_65(priv_key).map(BoringPublicKey::MlDsa65),
            Self::MlDsa87(priv_key) => to_public_key_87(priv_key).map(BoringPublicKey::MlDsa87),
        }
    }
}

enum BoringPublicKey {
    MlDsa65(Box<bssl_sys::MLDSA65_public_key>),
    MlDsa87(Box<bssl_sys::MLDSA87_public_key>),
}

impl BoringPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::MlDsa65(pub_key) => {
                let mut buf = vec_try![0; PUBLIC_KEY_BYTES_65]?;
                // Safety: `cbb` is the correct size via the type system and is always fully written
                // on success. `buf` is valid for the duration of the call and the use of `cbb`
                // below.
                let mut cbb = unsafe {
                    initialized_struct(|cbb| {
                        let ok = bssl_sys::CBB_init_fixed(cbb, buf.as_mut_ptr(), buf.len());
                        if ok == 1 {
                            Ok(())
                        } else {
                            Err(alloc_err!("ML-DSA-65 public key"))
                        }
                    })
                }?;
                // Safety: `cbb` refers to `buf` which is valid for the duration of the FFI
                // call. `pub_key` is also valid for the duration of the call.
                let ok = unsafe { bssl_sys::MLDSA65_marshal_public_key(&mut cbb, &**pub_key) };
                if ok == 1 {
                    Ok(buf)
                } else {
                    Err(alloc_err!("ML-DSA-65 public key"))
                }
            }
            Self::MlDsa87(pub_key) => {
                let mut buf = vec_try![0; PUBLIC_KEY_BYTES_87]?;
                // Safety: `cbb` is the correct size via the type system and is always fully written
                // on success. `buf` is valid for the duration of the call and the use of `cbb`
                // below.
                let mut cbb = unsafe {
                    initialized_struct(|cbb| {
                        let ok = bssl_sys::CBB_init_fixed(cbb, buf.as_mut_ptr(), buf.len());
                        if ok == 1 {
                            Ok(())
                        } else {
                            Err(alloc_err!("ML-DSA-87 public key"))
                        }
                    })
                }?;
                // Safety: `cbb` refers to `buf` which is valid for the duration of the FFI
                // call. `pub_key` is also valid for the duration of the call.
                let ok = unsafe { bssl_sys::MLDSA87_marshal_public_key(&mut cbb, &**pub_key) };
                if ok == 1 {
                    Ok(buf)
                } else {
                    Err(alloc_err!("ML-DSA-87 public key"))
                }
            }
        }
    }
}

impl MlDsa for BoringMlDsa {
    fn subject_public_key(&self, key: &OpaqueOr<Key>) -> Result<Vec<u8>, Error> {
        let key = explicit!(key)?;
        let bssl_key = BoringPrivateKey::try_from(key)?;
        bssl_key.to_public_key()?.to_bytes()
    }

    fn begin_sign(&self, key: OpaqueOr<Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let bssl_key = BoringPrivateKey::try_from(&key)?;
        let op = match bssl_key {
            BoringPrivateKey::MlDsa65(priv_key) => {
                let pub_key = to_public_key_65(&priv_key)?;
                // Safety: `prehash` is the correct size via the type system and is always fully
                // written on success. `pub_key` is valid for the duration of the FFI call.
                let prehash = unsafe {
                    initialized_struct(|prehash: *mut bssl_sys::MLDSA65_prehash| {
                        let ok = bssl_sys::MLDSA65_prehash_init(
                            &mut (*prehash),
                            &*pub_key,
                            core::ptr::null(),
                            0,
                        );
                        if ok == 1 {
                            Ok(())
                        } else {
                            Err(alloc_err!("ML-DSA-65 prehash"))
                        }
                    })
                }?;
                BoringMlDsaSignOperation::MlDsa65(priv_key, prehash)
            }
            BoringPrivateKey::MlDsa87(priv_key) => {
                let pub_key = to_public_key_87(&priv_key)?;
                // Safety: `prehash` is the correct size via the type system and is always fully
                // written on success. `pub_key` is valid for the duration of the FFI call.
                let prehash = unsafe {
                    initialized_struct(|prehash: *mut bssl_sys::MLDSA87_prehash| {
                        let ok = bssl_sys::MLDSA87_prehash_init(
                            &mut (*prehash),
                            &*pub_key,
                            core::ptr::null(),
                            0,
                        );
                        if ok == 1 {
                            Ok(())
                        } else {
                            Err(alloc_err!("ML-DSA-87 prehash"))
                        }
                    })
                }?;
                BoringMlDsaSignOperation::MlDsa87(priv_key, prehash)
            }
        };
        Ok(Box::new(op))
    }
}

/// ML-DSA signing operation based on BoringSSL.
enum BoringMlDsaSignOperation {
    MlDsa65(
        Box<bssl_sys::MLDSA65_private_key>,
        bssl_sys::MLDSA65_prehash,
    ),
    MlDsa87(
        Box<bssl_sys::MLDSA87_private_key>,
        bssl_sys::MLDSA87_prehash,
    ),
}

impl crypto::AccumulatingOperation for BoringMlDsaSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // Safety: `prehash` and `data` are both valid for the duration of the FFI call.
        unsafe {
            match self {
                Self::MlDsa65(_k, prehash) => {
                    bssl_sys::MLDSA65_prehash_update(&mut *prehash, data.as_ffi_ptr(), data.len());
                }
                Self::MlDsa87(_k, prehash) => {
                    bssl_sys::MLDSA87_prehash_update(&mut *prehash, data.as_ffi_ptr(), data.len());
                }
            }
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut mu = [0u8; MU_BYTES];
        match *self {
            Self::MlDsa65(priv_key, mut prehash) => {
                // Safety: `prehash` and `mu` are both valid for the duration of the FFI call.
                unsafe { bssl_sys::MLDSA65_prehash_finalize(mu.as_mut_ffi_ptr(), &mut prehash) };
                let mut sig = vec_try![0u8; SIGNATURE_BYTES_65]?;
                // Safety: `sig`, `priv_key` and `mut` are all valid for the duration of the FFI
                // call.
                let ok = unsafe {
                    bssl_sys::MLDSA65_sign_message_representative(
                        sig.as_mut_ffi_ptr(),
                        &*priv_key,
                        mu.as_ffi_ptr(),
                    )
                };
                if ok == 1 {
                    Ok(sig)
                } else {
                    Err(alloc_err!("ML-DSA-65 sign"))
                }
            }
            Self::MlDsa87(priv_key, mut prehash) => {
                // Safety: `prehash` and `mu` are both valid for the duration of the FFI call.
                unsafe { bssl_sys::MLDSA87_prehash_finalize(mu.as_mut_ffi_ptr(), &mut prehash) };
                let mut sig = vec_try![0u8; SIGNATURE_BYTES_87]?;
                // Safety: `sig`, `priv_key` and `mut` are all valid for the duration of the FFI
                // call.
                let ok = unsafe {
                    bssl_sys::MLDSA87_sign_message_representative(
                        sig.as_mut_ffi_ptr(),
                        &*priv_key,
                        mu.as_ffi_ptr(),
                    )
                };
                if ok == 1 {
                    Ok(sig)
                } else {
                    Err(alloc_err!("ML-DSA-87 sign"))
                }
            }
        }
    }
}
