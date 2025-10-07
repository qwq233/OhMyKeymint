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

//! Functionality related to elliptic curve support.

use super::{CurveType, KeyMaterial, OpaqueOr};
use crate::{der_err, km_err, try_to_vec, vec_try, Error, FallibleAllocExt};
use der::{asn1::BitStringRef, AnyRef, Decode, Encode, Sequence};
use kmr_wire::{coset, keymint::EcCurve, rpc, KeySizeInBits};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use zeroize::ZeroizeOnDrop;

/// Size (in bytes) of a curve 25519 private key.
pub const CURVE25519_PRIV_KEY_LEN: usize = 32;

/// Maximum message size for Ed25519 Signing operations.
pub const MAX_ED25519_MSG_SIZE: usize = 16 * 1024;

/// Marker value used to indicate that a public key is for RKP test mode.
pub const RKP_TEST_KEY_CBOR_MARKER: i64 = -70000;

/// Initial byte of SEC1 public key encoding that indicates an uncompressed point.
pub const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// OID value for general-use NIST EC keys held in PKCS#8 and X.509; see RFC 5480 s2.1.1.
pub const X509_NIST_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// OID value for Ed25519 keys held in PKCS#8 and X.509; see RFC 8410 s3.
pub const X509_ED25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID value for X25519 keys held in PKCS#8 and X.509; see RFC 8410 s3.
pub const X509_X25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

/// OID value for PKCS#1 signature with SHA-256 and ECDSA, see RFC 5758 s3.2.
pub const ECDSA_SHA256_SIGNATURE_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// OID value in `AlgorithmIdentifier.parameters` for P-224; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P224_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.33");

/// OID value in `AlgorithmIdentifier.parameters` for P-256; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P256_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// OID value in `AlgorithmIdentifier.parameters` for P-384; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P384_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// OID value in `AlgorithmIdentifier.parameters` for P-521; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P521_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// Subset of `EcCurve` values that are NIST curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum NistCurve {
    /// P-224
    P224 = 0,
    /// P-256
    P256 = 1,
    /// P-384
    P384 = 2,
    /// P-521
    P521 = 3,
}

impl NistCurve {
    /// Curve coordinate size in bytes.
    pub fn coord_len(&self) -> usize {
        match self {
            NistCurve::P224 => 28,
            NistCurve::P256 => 32,
            NistCurve::P384 => 48,
            NistCurve::P521 => 66,
        }
    }
}

impl From<NistCurve> for EcCurve {
    fn from(nist: NistCurve) -> EcCurve {
        match nist {
            NistCurve::P224 => EcCurve::P224,
            NistCurve::P256 => EcCurve::P256,
            NistCurve::P384 => EcCurve::P384,
            NistCurve::P521 => EcCurve::P521,
        }
    }
}

impl TryFrom<EcCurve> for NistCurve {
    type Error = Error;
    fn try_from(curve: EcCurve) -> Result<NistCurve, Error> {
        match curve {
            EcCurve::P224 => Ok(NistCurve::P224),
            EcCurve::P256 => Ok(NistCurve::P256),
            EcCurve::P384 => Ok(NistCurve::P384),
            EcCurve::P521 => Ok(NistCurve::P521),
            EcCurve::Curve25519 => Err(km_err!(InvalidArgument, "curve 25519 is not a NIST curve")),
        }
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
    /// For NIST curve EC keys, the contents are described in RFC 5480 section 2.1.
    /// - The `AlgorithmIdentifier` has an `algorithm` OID of 1.2.840.10045.2.1.
    /// - The `AlgorithmIdentifier` has `parameters` that hold an OID identifying the curve, here
    ///   one of:
    ///    - P-224: 1.3.132.0.33
    ///    - P-256: 1.2.840.10045.3.1.7
    ///    - P-384: 1.3.132.0.34
    ///    - P-521: 1.3.132.0.35
    /// - The `subjectPublicKey` bit string holds an ASN.1 DER-encoded `OCTET STRING` that contains
    ///   a SEC-1 encoded public key.  The first byte indicates the format:
    ///    - 0x04: uncompressed, followed by x || y coordinates
    ///    - 0x03: compressed, followed by x coordinate (and with a odd y coordinate)
    ///    - 0x02: compressed, followed by x coordinate (and with a even y coordinate)
    ///
    /// For Ed25519 keys, the contents of the `AlgorithmIdentifier` are described in RFC 8410
    /// section 3.
    /// - The `algorithm` has an OID of 1.3.101.112.
    /// - The `parameters` are absent.
    ///
    /// The `subjectPublicKey` holds the raw key bytes.
    ///
    /// For X25519 keys, the contents of the `AlgorithmIdentifier` are described in RFC 8410
    /// section 3.
    /// - The `algorithm` has an OID of 1.3.101.110.
    /// - The `parameters` are absent.
    ///
    /// The `subjectPublicKey` holds the raw key bytes.
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
        curve: &EcCurve,
        curve_type: &CurveType,
    ) -> Result<SubjectPublicKeyInfoRef<'a>, Error> {
        buf.try_extend_from_slice(&ec.subject_public_key(self)?)?;
        let (oid, parameters) = match curve_type {
            CurveType::Nist => {
                let nist_curve: NistCurve = (*curve).try_into()?;
                let params_oid = match nist_curve {
                    NistCurve::P224 => &ALGO_PARAM_P224_OID,
                    NistCurve::P256 => &ALGO_PARAM_P256_OID,
                    NistCurve::P384 => &ALGO_PARAM_P384_OID,
                    NistCurve::P521 => &ALGO_PARAM_P521_OID,
                };
                (X509_NIST_OID, Some(AnyRef::from(params_oid)))
            }
            CurveType::EdDsa => (X509_ED25519_OID, None),
            CurveType::Xdh => (X509_X25519_OID, None),
        };
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier { oid, parameters },
            subject_public_key: BitStringRef::from_bytes(buf).unwrap(),
        })
    }

    /// Generate a `COSE_Key` for the public key.
    pub fn public_cose_key(
        &self,
        ec: &dyn super::Ec,
        curve: EcCurve,
        curve_type: CurveType,
        purpose: CoseKeyPurpose,
        key_id: Option<Vec<u8>>,
        test_mode: rpc::TestMode,
    ) -> Result<coset::CoseKey, Error> {
        let nist_algo = match purpose {
            CoseKeyPurpose::Agree => coset::iana::Algorithm::ECDH_ES_HKDF_256,
            CoseKeyPurpose::Sign => coset::iana::Algorithm::ES256,
        };

        let pub_key = ec.subject_public_key(self)?;
        let mut builder = match curve_type {
            CurveType::Nist => {
                let nist_curve: NistCurve = curve.try_into()?;
                let (x, y) = coordinates_from_pub_key(pub_key, nist_curve)?;
                let cose_nist_curve = match nist_curve {
                    NistCurve::P224 => {
                        // P-224 is not supported by COSE: there is no value in the COSE Elliptic
                        // Curve registry for it.
                        return Err(km_err!(Unimplemented, "no COSE support for P-224"));
                    }
                    NistCurve::P256 => coset::iana::EllipticCurve::P_256,
                    NistCurve::P384 => coset::iana::EllipticCurve::P_384,
                    NistCurve::P521 => coset::iana::EllipticCurve::P_521,
                };
                coset::CoseKeyBuilder::new_ec2_pub_key(cose_nist_curve, x, y).algorithm(nist_algo)
            }
            CurveType::EdDsa => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::Ed25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(pub_key),
                )
                .algorithm(coset::iana::Algorithm::EdDSA),
            CurveType::Xdh => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::X25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(pub_key),
                )
                .algorithm(coset::iana::Algorithm::ECDH_ES_HKDF_256),
        };

        if let Some(key_id) = key_id {
            builder = builder.key_id(key_id);
        }
        if test_mode == rpc::TestMode(true) {
            builder = builder.param(RKP_TEST_KEY_CBOR_MARKER, coset::cbor::value::Value::Null);
        }
        Ok(builder.build())
    }
}

/// Elliptic curve private key material.
#[derive(Clone, PartialEq, Eq)]
pub enum Key {
    /// P-224 private key.
    P224(NistKey),
    /// P-256 private key.
    P256(NistKey),
    /// P-384 private key.
    P384(NistKey),
    /// P-521 private key.
    P521(NistKey),
    /// Ed25519 private key.
    Ed25519(Ed25519Key),
    /// X25519 private key.
    X25519(X25519Key),
}

/// Indication of the purpose for a COSE key.
pub enum CoseKeyPurpose {
    /// ECDH key agreement.
    Agree,
    /// ECDSA signature generation.
    Sign,
}

impl Key {
    /// Return the private key material.
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Key::P224(key) => &key.0,
            Key::P256(key) => &key.0,
            Key::P384(key) => &key.0,
            Key::P521(key) => &key.0,
            Key::Ed25519(key) => &key.0,
            Key::X25519(key) => &key.0,
        }
    }

    /// Return the type of curve.
    pub fn curve_type(&self) -> CurveType {
        match self {
            Key::P224(_) | Key::P256(_) | Key::P384(_) | Key::P521(_) => CurveType::Nist,
            Key::Ed25519(_) => CurveType::EdDsa,
            Key::X25519(_) => CurveType::Xdh,
        }
    }

    /// Return the curve.
    pub fn curve(&self) -> EcCurve {
        match self {
            Key::P224(_) => EcCurve::P224,
            Key::P256(_) => EcCurve::P256,
            Key::P384(_) => EcCurve::P384,
            Key::P521(_) => EcCurve::P521,
            Key::Ed25519(_) => EcCurve::Curve25519,
            Key::X25519(_) => EcCurve::Curve25519,
        }
    }
}

/// A NIST EC key, in the form of an ASN.1 DER encoding of a `ECPrivateKey` structure,
/// as specified by RFC 5915 section 3:
///
/// ```asn1
/// ECPrivateKey ::= SEQUENCE {
///    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///    privateKey     OCTET STRING,
///    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///    publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct NistKey(pub Vec<u8>);

/// Helper function to return the (x,y) coordinates, given the public key as a SEC-1 encoded
/// uncompressed point. 0x04: uncompressed, followed by x || y coordinates.
pub fn coordinates_from_pub_key(
    pub_key: Vec<u8>,
    curve: NistCurve,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let coord_len = curve.coord_len();
    if pub_key.len() != (1 + 2 * coord_len) {
        return Err(km_err!(
            UnsupportedKeySize,
            "unexpected SEC1 pubkey len of {} for {:?}",
            pub_key.len(),
            curve
        ));
    }
    if pub_key[0] != SEC1_UNCOMPRESSED_PREFIX {
        return Err(km_err!(
            UnsupportedKeySize,
            "unexpected SEC1 pubkey initial byte {} for {:?}",
            pub_key[0],
            curve
        ));
    }
    Ok((
        try_to_vec(&pub_key[1..1 + coord_len])?,
        try_to_vec(&pub_key[1 + coord_len..])?,
    ))
}

/// An Ed25519 private key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Ed25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

/// An X25519 private key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct X25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

/// Return the OID used in an `AlgorithmIdentifier` for signatures produced by this curve.
pub fn curve_to_signing_oid(curve: EcCurve) -> pkcs8::ObjectIdentifier {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => ECDSA_SHA256_SIGNATURE_OID,
        EcCurve::Curve25519 => X509_ED25519_OID,
    }
}

/// Return the key size for a curve.
pub fn curve_to_key_size(curve: EcCurve) -> KeySizeInBits {
    KeySizeInBits(match curve {
        EcCurve::P224 => 224,
        EcCurve::P256 => 256,
        EcCurve::P384 => 384,
        EcCurve::P521 => 521,
        EcCurve::Curve25519 => 256,
    })
}

/// Import an NIST EC key in SEC1 ECPrivateKey format.
pub fn import_sec1_private_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let ec_key = sec1::EcPrivateKey::from_der(data)
        .map_err(|e| der_err!(e, "failed to parse ECPrivateKey"))?;
    let ec_parameters = ec_key.parameters.ok_or_else(|| {
        km_err!(
            InvalidArgument,
            "sec1 formatted EC private key didn't have a parameters field"
        )
    })?;
    let parameters_oid = ec_parameters.named_curve().ok_or_else(|| {
        km_err!(
            InvalidArgument,
            "couldn't retrieve parameters oid from sec1 ECPrivateKey formatted ec key parameters"
        )
    })?;
    let algorithm = AlgorithmIdentifier {
        oid: X509_NIST_OID,
        parameters: Some(AnyRef::from(&parameters_oid)),
    };
    let pkcs8_key = pkcs8::PrivateKeyInfo::new(algorithm, data);
    import_pkcs8_key_impl(&pkcs8_key)
}

/// Import an EC key in PKCS#8 format.
pub fn import_pkcs8_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key_info = pkcs8::PrivateKeyInfo::try_from(data)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse PKCS#8 EC key"))?;
    import_pkcs8_key_impl(&key_info)
}

/// Import a `pkcs8::PrivateKeyInfo` EC key.
fn import_pkcs8_key_impl(key_info: &pkcs8::PrivateKeyInfo) -> Result<KeyMaterial, Error> {
    let algo_params = key_info.algorithm.parameters;
    match key_info.algorithm.oid {
        X509_NIST_OID => {
            let algo_params = algo_params.ok_or_else(|| {
                km_err!(
                    InvalidArgument,
                    "missing PKCS#8 parameters for NIST curve import under OID {:?}",
                    key_info.algorithm.oid
                )
            })?;
            let curve_oid = algo_params
                .decode_as()
                .map_err(|_e| km_err!(InvalidArgument, "imported key has no OID parameter"))?;
            let (curve, key) = match curve_oid {
                ALGO_PARAM_P224_OID => (
                    EcCurve::P224,
                    Key::P224(NistKey(try_to_vec(key_info.private_key)?)),
                ),
                ALGO_PARAM_P256_OID => (
                    EcCurve::P256,
                    Key::P256(NistKey(try_to_vec(key_info.private_key)?)),
                ),
                ALGO_PARAM_P384_OID => (
                    EcCurve::P384,
                    Key::P384(NistKey(try_to_vec(key_info.private_key)?)),
                ),
                ALGO_PARAM_P521_OID => (
                    EcCurve::P521,
                    Key::P521(NistKey(try_to_vec(key_info.private_key)?)),
                ),
                oid => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "imported key has unknown OID {:?}",
                        oid,
                    ))
                }
            };
            Ok(KeyMaterial::Ec(curve, CurveType::Nist, key.into()))
        }
        X509_ED25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(
                    InvalidArgument,
                    "unexpected PKCS#8 parameters for Ed25519 import"
                ))
            } else {
                // For Ed25519 the PKCS#8 `privateKey` field holds a `CurvePrivateKey`
                // (RFC 8410 s7) that is an OCTET STRING holding the raw key.  As this is DER,
                // this is just a 2 byte prefix (0x04 = OCTET STRING, 0x20 = length of raw key).
                if key_info.private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || key_info.private_key[0] != 0x04
                    || key_info.private_key[1] != 0x20
                {
                    return Err(km_err!(
                        InvalidArgument,
                        "unexpected CurvePrivateKey contents"
                    ));
                }
                import_raw_ed25519_key(&key_info.private_key[2..])
            }
        }
        X509_X25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(
                    InvalidArgument,
                    "unexpected PKCS#8 parameters for X25519 import",
                ))
            } else {
                // For X25519 the PKCS#8 `privateKey` field holds a `CurvePrivateKey`
                // (RFC 8410 s7) that is an OCTET STRING holding the raw key.  As this is DER,
                // this is just a 2 byte prefix (0x04 = OCTET STRING, 0x20 = length of raw key).
                if key_info.private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || key_info.private_key[0] != 0x04
                    || key_info.private_key[1] != 0x20
                {
                    return Err(km_err!(
                        InvalidArgument,
                        "unexpected CurvePrivateKey contents"
                    ));
                }
                import_raw_x25519_key(&key_info.private_key[2..])
            }
        }
        _ => Err(km_err!(
            InvalidArgument,
            "unexpected OID {:?} for PKCS#8 EC key import",
            key_info.algorithm.oid,
        )),
    }
}

/// Import a 32-byte raw Ed25519 key.
pub fn import_raw_ed25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(
            InvalidInputLength,
            "import Ed25519 key of incorrect len {}",
            data.len()
        )
    })?;
    Ok(KeyMaterial::Ec(
        EcCurve::Curve25519,
        CurveType::EdDsa,
        Key::Ed25519(Ed25519Key(key)).into(),
    ))
}

/// Import a 32-byte raw X25519 key.
pub fn import_raw_x25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(
            InvalidInputLength,
            "import X25519 key of incorrect len {}",
            data.len()
        )
    })?;
    Ok(KeyMaterial::Ec(
        EcCurve::Curve25519,
        CurveType::Xdh,
        Key::X25519(X25519Key(key)).into(),
    ))
}

/// Convert a signature as emitted from the `Ec` trait into the form needed for
/// a `COSE_Sign1`.
pub fn to_cose_signature(curve: EcCurve, sig: Vec<u8>) -> Result<Vec<u8>, Error> {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => {
            // NIST curve signatures are emitted as a DER-encoded `SEQUENCE`.
            let der_sig = NistSignature::from_der(&sig)
                .map_err(|e| km_err!(EncodingError, "failed to parse DER signature: {:?}", e))?;
            // COSE expects signature of (r||s) with each value left-padded with zeros to coordinate
            // size.
            let nist_curve = NistCurve::try_from(curve)?;
            let l = nist_curve.coord_len();
            let mut sig = vec_try![0; 2 * l]?;
            let r = der_sig.r.as_bytes();
            let s = der_sig.s.as_bytes();
            let r_offset = l - r.len();
            let s_offset = l + l - s.len();
            sig[r_offset..r_offset + r.len()].copy_from_slice(r);
            sig[s_offset..s_offset + s.len()].copy_from_slice(s);
            Ok(sig)
        }
        EcCurve::Curve25519 => {
            // Ed25519 signatures can be used as-is (RFC 8410 section 6)
            Ok(sig)
        }
    }
}

/// Convert a signature as used in a `COSE_Sign1` into the form needed for the `Ec` trait.
pub fn from_cose_signature(curve: EcCurve, sig: &[u8]) -> Result<Vec<u8>, Error> {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => {
            // COSE signatures are (r||s) with each value left-padded with zeros to coordinate size.
            let nist_curve = NistCurve::try_from(curve)?;
            let l = nist_curve.coord_len();
            if sig.len() != 2 * l {
                return Err(km_err!(
                    EncodingError,
                    "unexpected len {} for {:?} COSE signature value",
                    sig.len(),
                    nist_curve
                ));
            }

            // NIST curve signatures need to be emitted as a DER-encoded `SEQUENCE`.
            let der_sig = NistSignature {
                r: der::asn1::UintRef::new(&sig[..l])
                    .map_err(|e| km_err!(EncodingError, "failed to build INTEGER: {:?}", e))?,
                s: der::asn1::UintRef::new(&sig[l..])
                    .map_err(|e| km_err!(EncodingError, "failed to build INTEGER: {:?}", e))?,
            };
            der_sig.to_der().map_err(|e| {
                km_err!(
                    EncodingError,
                    "failed to encode signature SEQUENCE: {:?}",
                    e
                )
            })
        }
        EcCurve::Curve25519 => {
            // Ed25519 signatures can be used as-is (RFC 8410 section 6)
            try_to_vec(sig)
        }
    }
}

/// DER-encoded signature from a NIST curve (RFC 3279 section 2.2.3):
/// ```asn1
/// Ecdsa-Sig-Value  ::=  SEQUENCE  {
///      r     INTEGER,
///      s     INTEGER
/// }
/// ```
#[derive(Sequence)]
struct NistSignature<'a> {
    r: der::asn1::UintRef<'a>,
    s: der::asn1::UintRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sig_decode() {
        let sig_data = hex::decode("3045022001b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b022100fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6").unwrap();
        let sig = NistSignature::from_der(&sig_data).expect("sequence should decode");
        assert_eq!(
            hex::encode(sig.r.as_bytes()),
            "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b"
        );
        assert_eq!(
            hex::encode(sig.s.as_bytes()),
            "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        );
    }

    #[test]
    fn test_longer_sig_transmute() {
        let nist_sig_data = hex::decode(concat!(
            "30", // SEQUENCE
            "45", // len
            "02", // INTEGER
            "20", // len = 32
            "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
            "02", // INTEGER
            "21", // len = 33 (high bit set so leading zero needed)
            "00fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        ))
        .unwrap();
        let cose_sig_data = to_cose_signature(EcCurve::P256, nist_sig_data.clone()).unwrap();
        assert_eq!(
            concat!(
                "01b309d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
                "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
            ),
            hex::encode(&cose_sig_data),
        );
        let got_nist_sig = from_cose_signature(EcCurve::P256, &cose_sig_data).unwrap();
        assert_eq!(got_nist_sig, nist_sig_data);
    }

    #[test]
    fn test_short_sig_transmute() {
        let nist_sig_data = hex::decode(concat!(
            "30", // SEQUENCE
            "43", // len x44
            "02", // INTEGER
            "1e", // len = 30
            "09d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
            "02", // INTEGER
            "21", // len = 33 (high bit set so leading zero needed)
            "00fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
        ))
        .unwrap();
        let cose_sig_data = to_cose_signature(EcCurve::P256, nist_sig_data.clone()).unwrap();
        assert_eq!(
            concat!(
                "000009d5eeffa5d550bde27630f9fc7f08492e4617bc158da08b913414cf675b",
                "fcdca2e77d036c33fa78f4a892b98569358d83c047a7d8a74ce6fe12fbf919c6"
            ),
            hex::encode(&cose_sig_data),
        );
        let got_nist_sig = from_cose_signature(EcCurve::P256, &cose_sig_data).unwrap();
        assert_eq!(got_nist_sig, nist_sig_data);
    }

    #[test]
    fn test_sec1_ec_import() {
        // Key data created with:
        // ```
        // openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
        // ```
        let key_data = hex::decode(concat!(
            "3077",   // SEQUENCE len x77 (ECPrivateKey)
            "020101", // INTEGER 1 = (ecPrivkeyVer1)
            "0420",   // OCTET STRING len x20 (privateKey)
            "a6a30ca3dc87b58763736400e7e86260",
            "9e8311f41e6b89888c33753218168517",
            "a00a",             // [0] len x0a (parameters)
            "0608",             // OBJECT IDENTIFIER len 8 (NamedCurve)
            "2a8648ce3d030107", // 1.2.840.10045.3.1.7=secp256r1
            "a144",             // [1] len x44 (publicKey)
            "0342",             // BIT STRING len x42
            "00",               // no pad bits
            "0481e4ce20d8be3dd40b940b3a3ba3e8",
            "cf5a3f2156eceb4debb8fce83cbe4a48",
            "bd576a03eebf77d329a438fcdc509f37",
            "1f092cad41e2ecf9f25cd82f31500f33",
            "8e"
        ))
        .unwrap();
        let key = import_sec1_private_key(&key_data).expect("SEC1 parse failed");
        if let KeyMaterial::Ec(curve, curve_type, _key) = key {
            assert_eq!(curve, EcCurve::P256);
            assert_eq!(curve_type, CurveType::Nist);
        } else {
            panic!("unexpected key type");
        }
    }
}
