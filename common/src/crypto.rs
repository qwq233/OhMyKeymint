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

//! Abstractions and related types for accessing cryptographic primitives
//! and related functionality.

// derive(N) generates a method that is missing a docstring.
#![allow(missing_docs)]

use crate::{km_err, vec_try, vec_try_with_capacity, Error, FallibleAllocExt};
use core::convert::{From, TryInto};
use enumn::N;
use kmr_derive::AsCborValue;
use kmr_wire::keymint::{Algorithm, Digest, EcCurve};
use kmr_wire::{cbor, cbor_type_error, AsCborValue, CborError, KeySizeInBits, RsaExponent};
use log::error;
use spki::SubjectPublicKeyInfoRef;
use zeroize::ZeroizeOnDrop;

pub mod aes;
pub mod des;
pub mod ec;
pub mod hmac;
pub mod rsa;
mod traits;
pub use traits::*;

/// Size of SHA-256 output in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// Length of the expected initialization vector.
pub const GCM_IV_LENGTH: usize = 12;
/// Length of the expected AEAD TAG.
pub const TAG_LENGTH: usize = 16;
/// Length of an AES 256 key in bytes.
pub const AES_256_KEY_LENGTH: usize = 32;
/// Length of an AES 128 key in bytes.
pub const AES_128_KEY_LENGTH: usize = 16;
/// Length of the expected salt for key from password generation.
pub const SALT_LENGTH: usize = 16;
/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// Older versions of keystore produced IVs with four extra
/// ignored zero bytes at the end; recognise and trim those.
pub const LEGACY_IV_LENGTH: usize = 16;

/// Function that mimics `slice.to_vec()` but which detects allocation failures.  This version emits
/// `CborError` (instead of the `Error` that `crate::try_to_vec` emits).
#[inline]
pub fn try_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, CborError> {
    let mut v = vec_try_with_capacity!(s.len()).map_err(|_e| CborError::AllocationFailed)?;
    v.extend_from_slice(s);
    Ok(v)
}

/// Milliseconds since an arbitrary epoch.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MillisecondsSinceEpoch(pub i64);

impl From<MillisecondsSinceEpoch> for kmr_wire::secureclock::Timestamp {
    fn from(value: MillisecondsSinceEpoch) -> Self {
        kmr_wire::secureclock::Timestamp {
            milliseconds: value.0,
        }
    }
}

/// Information for key generation.
#[derive(Clone)]
pub enum KeyGenInfo {
    /// Generate an AES key of the given size.
    Aes(aes::Variant),
    /// Generate a 3-DES key.
    TripleDes,
    /// Generate an HMAC key of the given size.
    Hmac(KeySizeInBits),
    /// Generate an RSA keypair of the given size using the given exponent.
    Rsa(KeySizeInBits, RsaExponent),
    /// Generate a NIST EC keypair using the given curve.
    NistEc(ec::NistCurve),
    /// Generate an Ed25519 keypair.
    Ed25519,
    /// Generate an X25519 keypair.
    X25519,
}

/// Type of elliptic curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum CurveType {
    /// NIST curve.
    Nist = 0,
    /// EdDSA curve.
    EdDsa = 1,
    /// XDH curve.
    Xdh = 2,
}

/// Raw key material used for deriving other keys.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct RawKeyMaterial(pub Vec<u8>);

/// Opaque key material whose structure is only known/accessible to the crypto implementation.
/// The contents of this are assumed to be encrypted (and so are not `ZeroizeOnDrop`).
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueKeyMaterial(pub Vec<u8>);

/// Wrapper that holds either a key of explicit type `T`, or an opaque blob of key material.
#[derive(Clone, PartialEq, Eq)]
pub enum OpaqueOr<T> {
    /// Explicit key material of the given type, available in plaintext.
    Explicit(T),
    /// Opaque key material, either encrypted or an opaque key handle.
    Opaque(OpaqueKeyMaterial),
}

/// Macro to provide `impl From<SomeKey> for OpaqueOr<SomeKey>`, so that explicit key material
/// automatically converts into the equivalent `OpaqueOr` variant.
macro_rules! opaque_from_key {
    { $t:ty } => {
        impl From<$t> for OpaqueOr<$t> {
            fn from(k: $t) -> Self {
                Self::Explicit(k)
            }
        }
    }
}

opaque_from_key!(aes::Key);
opaque_from_key!(des::Key);
opaque_from_key!(hmac::Key);
opaque_from_key!(rsa::Key);
opaque_from_key!(ec::Key);

impl<T> From<OpaqueKeyMaterial> for OpaqueOr<T> {
    fn from(k: OpaqueKeyMaterial) -> Self {
        Self::Opaque(k)
    }
}

/// Key material that is held in plaintext (or is alternatively an opaque blob that is only
/// known/accessible to the crypto implementation, indicated by the `OpaqueOr::Opaque` variant).
#[derive(Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// AES symmetric key.
    Aes(OpaqueOr<aes::Key>),
    /// 3-DES symmetric key.
    TripleDes(OpaqueOr<des::Key>),
    /// HMAC symmetric key.
    Hmac(OpaqueOr<hmac::Key>),
    /// RSA asymmetric key.
    Rsa(OpaqueOr<rsa::Key>),
    /// Elliptic curve asymmetric key.
    Ec(EcCurve, CurveType, OpaqueOr<ec::Key>),
}

/// Macro that extracts the explicit key from an [`OpaqueOr`] wrapper.
#[macro_export]
macro_rules! explicit {
    { $key:expr } => {
        if let $crate::crypto::OpaqueOr::Explicit(k) = $key {
            Ok(k)
        } else {
            Err($crate::km_err!(IncompatibleKeyFormat, "Expected explicit key but found opaque key!"))
        }
    }
}

impl KeyMaterial {
    /// Indicate whether the key material is for an asymmetric key.
    pub fn is_asymmetric(&self) -> bool {
        match self {
            Self::Aes(_) | Self::TripleDes(_) | Self::Hmac(_) => false,
            Self::Ec(_, _, _) | Self::Rsa(_) => true,
        }
    }

    /// Indicate whether the key material is for a symmetric key.
    pub fn is_symmetric(&self) -> bool {
        !self.is_asymmetric()
    }

    /// Return the public key information as an ASN.1 DER encodable `SubjectPublicKeyInfo`, as
    /// described in RFC 5280 section 4.1.
    ///
    /// ```asn1
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///    algorithm            AlgorithmIdentifier,
    ///    subjectPublicKey     BIT STRING  }
    ///
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///    algorithm               OBJECT IDENTIFIER,
    ///    parameters              ANY DEFINED BY algorithm OPTIONAL  }
    /// ```
    ///
    /// Returns `None` for a symmetric key.
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        ec: &dyn Ec,
        rsa: &dyn Rsa,
    ) -> Result<Option<SubjectPublicKeyInfoRef<'a>>, Error> {
        Ok(match self {
            Self::Rsa(key) => Some(key.subject_public_key_info(buf, rsa)?),
            Self::Ec(curve, curve_type, key) => {
                Some(key.subject_public_key_info(buf, ec, curve, curve_type)?)
            }
            _ => None,
        })
    }
}

/// Manual implementation of [`Debug`] that skips emitting plaintext key material.
impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aes(k) => match k {
                OpaqueOr::Explicit(aes::Key::Aes128(_)) => f.write_str("Aes128(...)"),
                OpaqueOr::Explicit(aes::Key::Aes192(_)) => f.write_str("Aes192(...)"),
                OpaqueOr::Explicit(aes::Key::Aes256(_)) => f.write_str("Aes256(...)"),
                OpaqueOr::Opaque(_) => f.write_str("Aes(opaque)"),
            },
            Self::TripleDes(_) => f.write_str("TripleDes(...)"),
            Self::Hmac(_) => f.write_str("Hmac(...)"),
            Self::Rsa(_) => f.write_str("Rsa(...)"),
            Self::Ec(c, _, _) => f.write_fmt(format_args!("Ec({:?}, ...)", c)),
        }
    }
}

impl AsCborValue for KeyMaterial {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let mut a = match value {
            cbor::value::Value::Array(a) if a.len() == 3 => a,
            _ => return cbor_type_error(&value, "arr len 3"),
        };
        let raw_key_value = a.remove(2);
        let opaque = match a.remove(1) {
            cbor::value::Value::Bool(b) => b,
            v => return cbor_type_error(&v, "bool"),
        };
        let algo: i32 = match a.remove(0) {
            cbor::value::Value::Integer(i) => i.try_into()?,
            v => return cbor_type_error(&v, "uint"),
        };

        match algo {
            x if x == Algorithm::Aes as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                if opaque {
                    Ok(Self::Aes(OpaqueKeyMaterial(raw_key).into()))
                } else {
                    match aes::Key::new(raw_key) {
                        Ok(k) => Ok(Self::Aes(k.into())),
                        Err(_e) => Err(CborError::UnexpectedItem("bstr", "bstr len 16/24/32")),
                    }
                }
            }
            x if x == Algorithm::TripleDes as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                if opaque {
                    Ok(Self::TripleDes(OpaqueKeyMaterial(raw_key).into()))
                } else {
                    Ok(Self::TripleDes(
                        des::Key(
                            raw_key
                                .try_into()
                                .map_err(|_e| CborError::UnexpectedItem("bstr", "bstr len 24"))?,
                        )
                        .into(),
                    ))
                }
            }
            x if x == Algorithm::Hmac as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                if opaque {
                    Ok(Self::Hmac(OpaqueKeyMaterial(raw_key).into()))
                } else {
                    Ok(Self::Hmac(hmac::Key(raw_key).into()))
                }
            }
            x if x == Algorithm::Rsa as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                if opaque {
                    Ok(Self::Rsa(OpaqueKeyMaterial(raw_key).into()))
                } else {
                    Ok(Self::Rsa(rsa::Key(raw_key).into()))
                }
            }
            x if x == Algorithm::Ec as i32 => {
                let mut a = match raw_key_value {
                    cbor::value::Value::Array(a) if a.len() == 3 => a,
                    _ => return cbor_type_error(&raw_key_value, "arr len 2"),
                };
                let raw_key_value = a.remove(2);
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                let curve_type = CurveType::from_cbor_value(a.remove(1))?;
                let curve = <EcCurve>::from_cbor_value(a.remove(0))?;
                if opaque {
                    Ok(Self::Ec(
                        curve,
                        curve_type,
                        OpaqueKeyMaterial(raw_key).into(),
                    ))
                } else {
                    let key = match (curve, curve_type) {
                        (EcCurve::P224, CurveType::Nist) => ec::Key::P224(ec::NistKey(raw_key)),
                        (EcCurve::P256, CurveType::Nist) => ec::Key::P256(ec::NistKey(raw_key)),
                        (EcCurve::P384, CurveType::Nist) => ec::Key::P384(ec::NistKey(raw_key)),
                        (EcCurve::P521, CurveType::Nist) => ec::Key::P521(ec::NistKey(raw_key)),
                        (EcCurve::Curve25519, CurveType::EdDsa) => {
                            let key = raw_key.try_into().map_err(|_e| {
                                error!("decoding Ed25519 key of incorrect len");
                                CborError::OutOfRangeIntegerValue
                            })?;
                            ec::Key::Ed25519(ec::Ed25519Key(key))
                        }
                        (EcCurve::Curve25519, CurveType::Xdh) => {
                            let key = raw_key.try_into().map_err(|_e| {
                                error!("decoding X25519 key of incorrect len");
                                CborError::OutOfRangeIntegerValue
                            })?;
                            ec::Key::X25519(ec::X25519Key(key))
                        }
                        (_, _) => {
                            error!("Unexpected EC combination ({:?}, {:?})", curve, curve_type);
                            return Err(CborError::NonEnumValue);
                        }
                    };
                    Ok(Self::Ec(curve, curve_type, key.into()))
                }
            }
            _ => Err(CborError::UnexpectedItem("unknown enum", "algo enum")),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        let cbor_alloc_err = |_e| CborError::AllocationFailed;
        Ok(cbor::value::Value::Array(match self {
            Self::Aes(OpaqueOr::Opaque(OpaqueKeyMaterial(k))) => vec_try![
                cbor::value::Value::Integer((Algorithm::Aes as i32).into()),
                cbor::value::Value::Bool(true),
                cbor::value::Value::Bytes(try_to_vec(&k)?),
            ]
            .map_err(cbor_alloc_err)?,
            Self::TripleDes(OpaqueOr::Opaque(OpaqueKeyMaterial(k))) => vec_try![
                cbor::value::Value::Integer((Algorithm::TripleDes as i32).into()),
                cbor::value::Value::Bool(true),
                cbor::value::Value::Bytes(try_to_vec(&k)?),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Hmac(OpaqueOr::Opaque(OpaqueKeyMaterial(k))) => vec_try![
                cbor::value::Value::Integer((Algorithm::Hmac as i32).into()),
                cbor::value::Value::Bool(true),
                cbor::value::Value::Bytes(try_to_vec(&k)?),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Rsa(OpaqueOr::Opaque(OpaqueKeyMaterial(k))) => vec_try![
                cbor::value::Value::Integer((Algorithm::Rsa as i32).into()),
                cbor::value::Value::Bool(true),
                cbor::value::Value::Bytes(try_to_vec(&k)?),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Ec(curve, curve_type, OpaqueOr::Opaque(OpaqueKeyMaterial(k))) => vec_try![
                cbor::value::Value::Integer((Algorithm::Ec as i32).into()),
                cbor::value::Value::Bool(true),
                cbor::value::Value::Array(
                    vec_try![
                        cbor::value::Value::Integer((curve as i32).into()),
                        cbor::value::Value::Integer((curve_type as i32).into()),
                        cbor::value::Value::Bytes(try_to_vec(&k)?),
                    ]
                    .map_err(cbor_alloc_err)?
                ),
            ]
            .map_err(cbor_alloc_err)?,

            Self::Aes(OpaqueOr::Explicit(k)) => vec_try![
                cbor::value::Value::Integer((Algorithm::Aes as i32).into()),
                cbor::value::Value::Bool(false),
                match k {
                    aes::Key::Aes128(k) => cbor::value::Value::Bytes(try_to_vec(&k)?),
                    aes::Key::Aes192(k) => cbor::value::Value::Bytes(try_to_vec(&k)?),
                    aes::Key::Aes256(k) => cbor::value::Value::Bytes(try_to_vec(&k)?),
                },
            ]
            .map_err(cbor_alloc_err)?,

            Self::TripleDes(OpaqueOr::Explicit(k)) => vec_try![
                cbor::value::Value::Integer((Algorithm::TripleDes as i32).into()),
                cbor::value::Value::Bool(false),
                cbor::value::Value::Bytes(k.0.to_vec()),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Hmac(OpaqueOr::Explicit(k)) => vec_try![
                cbor::value::Value::Integer((Algorithm::Hmac as i32).into()),
                cbor::value::Value::Bool(false),
                cbor::value::Value::Bytes(k.0.clone()),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Rsa(OpaqueOr::Explicit(k)) => vec_try![
                cbor::value::Value::Integer((Algorithm::Rsa as i32).into()),
                cbor::value::Value::Bool(false),
                cbor::value::Value::Bytes(k.0.clone()),
            ]
            .map_err(cbor_alloc_err)?,
            Self::Ec(curve, curve_type, OpaqueOr::Explicit(k)) => vec_try![
                cbor::value::Value::Integer((Algorithm::Ec as i32).into()),
                cbor::value::Value::Bool(false),
                cbor::value::Value::Array(
                    vec_try![
                        cbor::value::Value::Integer((curve as i32).into()),
                        cbor::value::Value::Integer((curve_type as i32).into()),
                        cbor::value::Value::Bytes(k.private_key_bytes().to_vec()),
                    ]
                    .map_err(cbor_alloc_err)?,
                ),
            ]
            .map_err(cbor_alloc_err)?,
        }))
    }

    fn cddl_typename() -> Option<String> {
        Some("KeyMaterial".to_string())
    }

    fn cddl_schema() -> Option<String> {
        Some(format!(
            "&(
  ; For each variant the `bool` second entry indicates whether the bstr for the key material
  ; is opaque (true), or explicit (false).
  [{}, bool, bstr], ; {}
  [{}, bool, bstr], ; {}
  [{}, bool, bstr], ; {}
  ; An explicit RSA key is in the form of an ASN.1 DER encoding of a PKCS#1 `RSAPrivateKey`
  ; structure, as specified by RFC 3447 sections A.1.2 and 3.2.
  [{}, bool, bstr], ; {}
  ; An explicit EC key for a NIST curve is in the form of an ASN.1 DER encoding of a
  ; `ECPrivateKey` structure, as specified by RFC 5915 section 3.
  ; An explicit EC key for curve 25519 is the raw key bytes.
  [{}, bool, [EcCurve, CurveType, bstr]], ; {}
)",
            Algorithm::Aes as i32,
            "Algorithm_Aes",
            Algorithm::TripleDes as i32,
            "Algorithm_TripleDes",
            Algorithm::Hmac as i32,
            "Algorithm_Hmac",
            Algorithm::Rsa as i32,
            "Algorithm_Rsa",
            Algorithm::Ec as i32,
            "Algorithm_Ec",
        ))
    }
}

/// Direction of cipher operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymmetricOperation {
    /// Perform encryption.
    Encrypt,
    /// Perform decryption.
    Decrypt,
}

/// Extract or generate a nonce of the given size.
pub fn nonce(
    size: usize,
    caller_nonce: Option<&Vec<u8>>,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, Error> {
    match caller_nonce {
        Some(n) => match n.len() {
            l if l == size => Ok(n.clone()),
            _ => Err(km_err!(InvalidNonce, "want {} byte nonce", size)),
        },
        None => {
            let mut n = vec_try![0; size]?;
            rng.fill_bytes(&mut n);
            Ok(n)
        }
    }
}

/// Salt value used in HKDF if none provided.
const HKDF_EMPTY_SALT: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];

/// Convenience wrapper to perform one-shot HMAC-SHA256.
pub fn hmac_sha256(hmac: &dyn Hmac, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut op = hmac.begin(hmac::Key(crate::try_to_vec(key)?).into(), Digest::Sha256)?;
    op.update(data)?;
    op.finish()
}

/// Default implementation of [`Hkdf`] for any type implementing [`Hmac`].
impl<T: Hmac> Hkdf for T {
    fn extract(&self, mut salt: &[u8], ikm: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error> {
        if salt.is_empty() {
            salt = &HKDF_EMPTY_SALT[..];
        }
        let prk = hmac_sha256(self, salt, ikm)?;
        Ok(OpaqueOr::Explicit(hmac::Key::new(prk)))
    }

    fn expand(
        &self,
        prk: &OpaqueOr<hmac::Key>,
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let prk = &explicit!(prk)?.0;
        let n = out_len.div_ceil(SHA256_DIGEST_LEN);
        if n > 256 {
            return Err(km_err!(InvalidArgument, "overflow in hkdf"));
        }
        let mut t = vec_try_with_capacity!(SHA256_DIGEST_LEN)?;
        let mut okm = vec_try_with_capacity!(n * SHA256_DIGEST_LEN)?;
        let n = n as u8;
        for idx in 0..n {
            let mut input = vec_try_with_capacity!(t.len() + info.len() + 1)?;
            input.extend_from_slice(&t);
            input.extend_from_slice(info);
            input.push(idx + 1);

            t = hmac_sha256(self, prk, &input)?;
            okm.try_extend_from_slice(&t)?;
        }
        okm.truncate(out_len);
        Ok(okm)
    }
}

/// Default implementation of [`Ckdf`] for any type implementing [`AesCmac`].
impl<T: AesCmac> Ckdf for T {
    fn ckdf(
        &self,
        key: &OpaqueOr<aes::Key>,
        label: &[u8],
        chunks: &[&[u8]],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let key = explicit!(key)?;
        // Note: the variables i and l correspond to i and L in the standard.  See page 12 of
        // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf.

        let blocks: u32 = out_len.div_ceil(aes::BLOCK_SIZE) as u32;
        let l = (out_len * 8) as u32; // in bits
        let net_order_l = l.to_be_bytes();
        let zero_byte: [u8; 1] = [0];
        let mut output = vec_try![0; out_len]?;
        let mut output_pos = 0;

        for i in 1u32..=blocks {
            // Data to mac is (i:u32 || label || 0x00:u8 || context || L:u32), with integers in
            // network order.
            let mut op = self.begin(key.clone().into())?;
            let net_order_i = i.to_be_bytes();
            op.update(&net_order_i[..])?;
            op.update(label)?;
            op.update(&zero_byte[..])?;
            for chunk in chunks {
                op.update(chunk)?;
            }
            op.update(&net_order_l[..])?;

            let data = op.finish()?;
            let copy_len = core::cmp::min(data.len(), output.len() - output_pos);
            output[output_pos..output_pos + copy_len].clone_from_slice(&data[..copy_len]);
            output_pos += copy_len;
        }
        if output_pos != output.len() {
            return Err(km_err!(
                InvalidArgument,
                "finished at {} before end of output at {}",
                output_pos,
                output.len()
            ));
        }
        Ok(output)
    }
}
