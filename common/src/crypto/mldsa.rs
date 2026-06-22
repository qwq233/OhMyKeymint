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

//! Functionality related to ML-DSA support.

use super::{KeyMaterial, OpaqueOr};
use crate::{km_err, Error, FallibleAllocExt};
use der::asn1::BitStringRef;
use kmr_wire::keymint::MlDsaVariant;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use std::vec::Vec;

#[cfg(test)]
mod tests;

/// OID value for ML-DSA-65; see RFC 9881 s2.
pub const OID_65: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// OID value for ML-DSA-87; see RFC 9881 s2.
pub const OID_87: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// Size of private key seed in bytes (for all variants).
pub const SEED_SIZE: usize = 32;

/// Size of ML-DSA-65 private key in bytes.
pub const PRIVATE_KEY_65_SIZE: usize = 4032;

/// Size of ML-DSA-87 private key in bytes.
pub const PRIVATE_KEY_87_SIZE: usize = 4896;

/// Return the OID value corresponding to this variant.
pub fn variant_to_oid(variant: MlDsaVariant) -> pkcs8::ObjectIdentifier {
    match variant {
        MlDsaVariant::MlDsa65 => OID_65,
        MlDsaVariant::MlDsa87 => OID_87,
    }
}

/// ML-DSA private key material.
#[derive(Clone, PartialEq, Eq)]
pub enum Key {
    /// ML-DSA-65 private key in seed form.
    MlDsa65([u8; SEED_SIZE]),
    /// ML-DSA-87 private key in seed form.
    MlDsa87([u8; SEED_SIZE]),
}

impl OpaqueOr<Key> {
    /// Encode into `buf` the public key information as an ASN.1 DER encodable
    /// `SubjectPublicKeyInfo`, as described in RFC 5280 section 4.1.
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
    /// The contents are described in RFC 9881 s2 and s4.
    /// - The `AlgorithmIdentifier` has an `algorithm` OID of 2.16.840.1.101.3.4.3.{18,19}.
    /// - The `parameters` "MUST be absent".
    /// - The `subjectPublicKey` contains the public key.
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        variant: MlDsaVariant,
        mldsa: &dyn super::MlDsa,
    ) -> Result<SubjectPublicKeyInfoRef<'a>, Error> {
        buf.try_extend_from_slice(&mldsa.subject_public_key(self)?)?;
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: variant_to_oid(variant),
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(buf).unwrap(),
        })
    }
}

impl Key {
    /// Return the private key material.
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Key::MlDsa65(key) => key,
            Key::MlDsa87(key) => key,
        }
    }

    /// Return the variant.
    pub fn variant(&self) -> MlDsaVariant {
        match self {
            Key::MlDsa65(_) => MlDsaVariant::MlDsa65,
            Key::MlDsa87(_) => MlDsaVariant::MlDsa87,
        }
    }
}

/// Import an ML-DSA key in raw format.
pub fn import_raw_key(data: &[u8], variant: MlDsaVariant) -> Result<KeyMaterial, Error> {
    let seed = <[u8; SEED_SIZE]>::try_from(data)
        .map_err(|_e| km_err!(UnsupportedKeySize, "ML-DSA key seeds must be 32 bytes"))?;
    let key = match variant {
        MlDsaVariant::MlDsa65 => Key::MlDsa65(seed),
        MlDsaVariant::MlDsa87 => Key::MlDsa87(seed),
    };
    Ok(KeyMaterial::MlDsa(variant, OpaqueOr::Explicit(key)))
}

// ML-DSA-65 PKCS#8 private key seed prefix.
const PKCS8_SEED_65_PREFIX: [u8; 22] = [
    0x30, 0x34, // SEQUENCE len x34 {
    0x02, 0x01, 0x00, // INTEGER 0 (Version)
    0x30, 0x0b, // SEQUENCE len 11 (privateKeyAlgorithm) {
    0x06, 0x09, // OBJECT_IDENTIFIER len 9
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, //  2.16.840.1.101.3.4.3.18
    // }
    0x04, 0x22, // OCTET STRING len 34
    0x80, 0x20, // tag 0 primitive len 32
          // followed by 32 bytes of seed data
];

// ML-DSA-87 PKCS#8 private key seed prefix.
const PKCS8_SEED_87_PREFIX: [u8; 22] = [
    0x30, 0x34, // SEQUENCE len x34 {
    0x02, 0x01, 0x00, // INTEGER 0 (Version)
    0x30, 0x0b, // SEQUENCE len 11 (privateKeyAlgorithm) {
    0x06, 0x09, // OBJECT_IDENTIFIER len 9
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, //  2.16.840.1.101.3.4.3.19
    // }
    0x04, 0x22, // OCTET STRING len 34
    0x80, 0x20, // tag 0 primitive len 32
          // followed by 32 bytes of seed data
];

/// Import an ML-DSA key in PKCS#8 format.  Only the `seed` version of the `CHOICE` is supported.
pub fn import_pkcs8_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    // The PKCS#8 private key format in RFC 9881 section 6 includes an ASN.1 `CHOICE` with three
    // possibilities: seed, expandedKey, or both.
    //
    // We only support the seed format, and as the inner seed has a fixed length (32-bytes) there is
    // no need to do ASN.1 parsing; we can just check for the expected length and prefix.
    if data.len() == PKCS8_SEED_65_PREFIX.len() + SEED_SIZE
        && data[..PKCS8_SEED_65_PREFIX.len()] == PKCS8_SEED_65_PREFIX
    {
        let seed = <[u8; SEED_SIZE]>::try_from(&data[PKCS8_SEED_65_PREFIX.len()..])
            .map_err(|_e| km_err!(UnsupportedKeySize, "ML-DSA key seeds must be 32 bytes"))?;
        Ok(KeyMaterial::MlDsa(
            MlDsaVariant::MlDsa65,
            OpaqueOr::Explicit(Key::MlDsa65(seed)),
        ))
    } else if data.len() == PKCS8_SEED_87_PREFIX.len() + SEED_SIZE
        && data[..PKCS8_SEED_87_PREFIX.len()] == PKCS8_SEED_87_PREFIX
    {
        let seed = <[u8; SEED_SIZE]>::try_from(&data[PKCS8_SEED_87_PREFIX.len()..])
            .map_err(|_e| km_err!(UnsupportedKeySize, "ML-DSA key seeds must be 32 bytes"))?;
        Ok(KeyMaterial::MlDsa(
            MlDsaVariant::MlDsa87,
            OpaqueOr::Explicit(Key::MlDsa87(seed)),
        ))
    } else {
        Err(km_err!(
            InvalidArgument,
            "PKCS#8 ML-DSA seed data not recognized"
        ))
    }
}
