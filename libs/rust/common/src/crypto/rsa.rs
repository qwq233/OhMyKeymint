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

//! Functionality related to RSA.

use super::{KeyMaterial, KeySizeInBits, OpaqueOr, RsaExponent};
use crate::{der_err, km_err, tag, try_to_vec, Error, FallibleAllocExt};
use der::{asn1::BitStringRef, Decode, Encode};
use kmr_wire::keymint::{Digest, KeyParam, PaddingMode};
use pkcs1::RsaPrivateKey;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use zeroize::ZeroizeOnDrop;

/// Overhead for PKCS#1 v1.5 signature padding of undigested messages.  Digested messages have
/// additional overhead, for the digest algorithmIdentifier required by PKCS#1.
pub const PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD: usize = 11;

/// OID value for PKCS#1-encoded RSA keys held in PKCS#8 and X.509; see RFC 3447 A.1.
pub const X509_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// OID value for PKCS#1 signature with SHA-256 and RSA, see RFC 4055 s5.
pub const SHA256_PKCS1_SIGNATURE_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// An RSA key, in the form of an ASN.1 DER encoding of an PKCS#1 `RSAPrivateKey` structure,
/// as specified by RFC 3447 sections A.1.2 and 3.2:
///
/// ```asn1
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- d mod (p-1)
///     exponent2         INTEGER,  -- d mod (q-1)
///     coefficient       INTEGER,  -- (inverse of q) mod p
///     otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
///
/// OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
///
/// OtherPrimeInfo ::= SEQUENCE {
///     prime             INTEGER,  -- ri
///     exponent          INTEGER,  -- di
///     coefficient       INTEGER   -- ti
/// }
/// ```
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Key(pub Vec<u8>);

impl Key {
    /// Return the `subjectPublicKey` that holds an ASN.1 DER-encoded `SEQUENCE`
    /// as per RFC 3279 section 2.3.1:
    ///     ```asn1
    ///     RSAPublicKey ::= SEQUENCE {
    ///        modulus            INTEGER,    -- n
    ///        publicExponent     INTEGER  }  -- e
    ///     ```
    pub fn subject_public_key(&self) -> Result<Vec<u8>, Error> {
        let rsa_pvt_key = RsaPrivateKey::from_der(self.0.as_slice())
            .map_err(|e| der_err!(e, "failed to parse RsaPrivateKey"))?;

        let rsa_pub_key = rsa_pvt_key.public_key();
        let mut encoded_data = Vec::<u8>::new();
        rsa_pub_key
            .encode_to_vec(&mut encoded_data)
            .map_err(|e| der_err!(e, "failed to encode RSA PublicKey"))?;
        Ok(encoded_data)
    }

    /// Size of the key in bytes.
    pub fn size(&self) -> usize {
        let rsa_pvt_key = match RsaPrivateKey::from_der(self.0.as_slice()) {
            Ok(k) => k,
            Err(e) => {
                log::error!("failed to determine RSA key length: {:?}", e);
                return 0;
            }
        };
        let len = u32::from(rsa_pvt_key.modulus.len());
        len as usize
    }
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
    /// For RSA keys, the contents are described in RFC 3279 section 2.3.1.
    ///
    /// - The `AlgorithmIdentifier` has an algorithm OID of 1.2.840.113549.1.1.1.
    /// - The `AlgorithmIdentifier` has `NULL` parameters.
    /// - The `subjectPublicKey` bit string holds an ASN.1 DER-encoded `SEQUENCE`:
    ///     ```asn1
    ///     RSAPublicKey ::= SEQUENCE {
    ///        modulus            INTEGER,    -- n
    ///        publicExponent     INTEGER  }  -- e
    ///     ```
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        rsa: &dyn super::Rsa,
    ) -> Result<SubjectPublicKeyInfoRef<'a>, Error> {
        let pub_key = rsa.subject_public_key(self)?;
        buf.try_extend_from_slice(&pub_key)?;
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier { oid: X509_OID, parameters: Some(der::AnyRef::NULL) },
            subject_public_key: BitStringRef::from_bytes(buf)
                .map_err(|e| km_err!(UnknownError, "invalid bitstring: {e:?}"))?,
        })
    }
}

/// RSA decryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionMode {
    /// No padding.
    NoPadding,
    /// RSA-OAEP padding.
    OaepPadding {
        /// Digest to use for the message
        msg_digest: Digest,
        /// Digest to use in the MGF1 function.
        mgf_digest: Digest,
    },
    /// PKCS#1 v1.5 padding.
    Pkcs1_1_5Padding,
}

impl DecryptionMode {
    /// Determine the [`DecryptionMode`] from parameters.
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(DecryptionMode::NoPadding),
            PaddingMode::RsaOaep => {
                let msg_digest = tag::get_digest(params)?;
                let mgf_digest = tag::get_mgf_digest(params)?;
                Ok(DecryptionMode::OaepPadding { msg_digest, mgf_digest })
            }
            PaddingMode::RsaPkcs115Encrypt => Ok(DecryptionMode::Pkcs1_1_5Padding),
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA decryption",
                padding
            )),
        }
    }
}

/// RSA signature mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    /// No padding.
    NoPadding,
    /// RSA-PSS signature scheme using the given digest.
    PssPadding(Digest),
    /// PKCS#1 v1.5 padding using the given digest.
    Pkcs1_1_5Padding(Digest),
}

impl SignMode {
    /// Determine the [`SignMode`] from parameters.
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(SignMode::NoPadding),
            PaddingMode::RsaPss => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::PssPadding(digest))
            }
            PaddingMode::RsaPkcs115Sign => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::Pkcs1_1_5Padding(digest))
            }
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA signing",
                padding
            )),
        }
    }
}

/// Import an RSA key in PKCS#8 format, also returning the key size in bits and public exponent.
pub fn import_pkcs8_key(data: &[u8]) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
    let key_info = pkcs8::PrivateKeyInfo::try_from(data)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse PKCS#8 RSA key"))?;
    if key_info.algorithm.oid != X509_OID {
        return Err(km_err!(
            InvalidArgument,
            "unexpected OID {:?} for PKCS#1 RSA key import",
            key_info.algorithm.oid
        ));
    }
    // For RSA, the inner private key is an ASN.1 `RSAPrivateKey`, as per PKCS#1 (RFC 3447 A.1.2).
    import_pkcs1_key(key_info.private_key)
}

/// Import an RSA key in PKCS#1 format, also returning the key size in bits and public exponent.
pub fn import_pkcs1_key(
    private_key: &[u8],
) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
    let key = Key(try_to_vec(private_key)?);

    // Need to parse it to find size/exponent.
    let parsed_key = pkcs1::RsaPrivateKey::try_from(private_key)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse inner PKCS#1 key"))?;
    let key_size = parsed_key.modulus.as_bytes().len() as u32 * 8;

    let pub_exponent_bytes = parsed_key.public_exponent.as_bytes();
    if pub_exponent_bytes.len() > 8 {
        return Err(km_err!(
            InvalidArgument,
            "public exponent of length {} too big",
            pub_exponent_bytes.len()
        ));
    }
    let offset = 8 - pub_exponent_bytes.len();
    let mut pub_exponent_arr = [0u8; 8];
    pub_exponent_arr[offset..].copy_from_slice(pub_exponent_bytes);
    let pub_exponent = u64::from_be_bytes(pub_exponent_arr);

    Ok((KeyMaterial::Rsa(key.into()), KeySizeInBits(key_size), RsaExponent(pub_exponent)))
}
