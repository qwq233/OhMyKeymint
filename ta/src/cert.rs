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

//! Generation of certificates and attestation extensions.

use crate::keys::SigningInfo;
use core::time::Duration;
use der::asn1::{OctetStringRef, SetOfVec};
use der::{asn1::Null, oid::AssociatedOid, Enumerated, Sequence};
use der::{Decode, Encode, EncodeValue, ErrorKind, Length};
use flagset::FlagSet;
use kmr_common::crypto::KeyMaterial;
use kmr_common::{
    crypto, der_err, get_tag_value, km_err, tag, try_to_vec, vec_try_with_capacity, Error,
    ErrorKind as CommonErrorKind,
};
use kmr_common::{get_bool_tag_value, get_opt_tag_value, FallibleAllocExt};
use kmr_wire::{
    keymint,
    keymint::{
        from_raw_tag_value, raw_tag_value, DateTime, ErrorCode, KeyCharacteristics, KeyParam,
        KeyPurpose, Tag,
    },
    KeySizeInBits, RsaExponent,
};
use spki::ObjectIdentifier;
use std::{borrow::Cow, vec::Vec};
use x509_cert::der as x509_der;
use x509_cert::der::asn1::{
    Any as X509Any, BitString as X509BitString, GeneralizedTime as X509GeneralizedTime,
    OctetString as X509OctetString, UtcTime as X509UtcTime,
};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned as X509AlgorithmIdentifierOwned,
    ObjectIdentifier as X509ObjectIdentifier,
    SubjectPublicKeyInfoOwned as X509SubjectPublicKeyInfoOwned,
};
use x509_cert::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::pkix::{constraints::BasicConstraints, KeyUsage, KeyUsages},
    ext::Extension,
    name::RdnSequence,
    time::{Time, Validity},
};

/// OID value for the Android Attestation extension.
pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const X509_KEY_USAGE_OID: X509ObjectIdentifier = X509ObjectIdentifier::new_unwrap("2.5.29.15");
const X509_BASIC_CONSTRAINTS_OID: X509ObjectIdentifier =
    X509ObjectIdentifier::new_unwrap("2.5.29.19");
const X509_ATTESTATION_EXTENSION_OID: X509ObjectIdentifier =
    X509ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// Empty value to use in the `RootOfTrust.verifiedBootKey` field in attestations
/// if an empty value was passed to the bootloader.
const EMPTY_BOOT_KEY: [u8; 32] = [0u8; 32];

pub(crate) fn x509_der_error(err: x509_der::Error, context: core::fmt::Arguments<'_>) -> Error {
    log::warn!("{}: {:?} at {:?}", context, err, err.position());
    Error::from(CommonErrorKind::Der(ErrorKind::Failed))
}

/// Build an ASN.1 DER-encodable `Certificate`.
pub(crate) fn certificate(tbs_cert: TbsCertificate, sig_val: &[u8]) -> Result<Certificate, Error> {
    Ok(Certificate {
        signature_algorithm: tbs_cert.signature.clone(),
        tbs_certificate: tbs_cert,
        signature: X509BitString::new(0, sig_val)
            .map_err(|e| x509_der_error(e, format_args!("failed to build BitString")))?,
    })
}

/// Build an ASN.1 DER-encodable `tbsCertificate`.
pub(crate) fn tbs_certificate<'a>(
    info: &'a Option<SigningInfo>,
    spki_der: &[u8],
    key_usage_ext_bits: &'a [u8],
    basic_constraint_ext_val: Option<&'a [u8]>,
    attestation_ext: Option<&'a [u8]>,
    chars: &'a [KeyParam],
    params: &'a [KeyParam],
) -> Result<TbsCertificate, Error> {
    let cert_serial = tag::get_cert_serial(params)?;
    let cert_subject = tag::get_cert_subject(params)?;
    let not_before = get_tag_value!(params, CertificateNotBefore, ErrorCode::MissingNotBefore)?;
    let not_after = get_tag_value!(params, CertificateNotAfter, ErrorCode::MissingNotAfter)?;

    // Determine the contents of the `AlgorithmIdentifier`, as an OID and parameters:
    // - RSA: RFC 4055 section 5 requires `NULL` parameters.
    // - ECDSA: RFC 5758 section 3.2 requires parameters be omitted.
    // - EdDSA: RFC 8410 section 3 requires parameters be omitted.
    // - ML-DSA: RFC 9881 section 2 requires parameters be omitted.
    let (sig_alg_oid, parameters) = match info {
        Some(info) => match info.signing_key {
            KeyMaterial::Rsa(_) => (
                crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                Some(X509Any::null()),
            ),
            KeyMaterial::Ec(curve, _, _) => (crypto::ec::curve_to_signing_oid(curve), None),
            KeyMaterial::MlDsa(variant, _) => (crypto::mldsa::variant_to_oid(variant), None),
            _ => {
                return Err(km_err!(
                    UnsupportedAlgorithm,
                    "unexpected cert signing key type"
                ));
            }
        },
        None => {
            // No signing key, so signature will be empty, but we still need a value here.
            match tag::get_algorithm(params)? {
                keymint::Algorithm::Rsa => (
                    crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                    Some(X509Any::null()),
                ),
                keymint::Algorithm::Ec => (
                    crypto::ec::curve_to_signing_oid(tag::get_ec_curve(chars)?),
                    None,
                ),
                keymint::Algorithm::MlDsa => {
                    let variant = tag::get_mldsa_variant(chars)?;
                    (crypto::mldsa::variant_to_oid(variant), None)
                }
                alg => {
                    return Err(km_err!(
                        UnsupportedAlgorithm,
                        "unexpected algorithm for public key {alg:?}",
                    ))
                }
            }
        }
    };
    let sig_alg_oid = x509_oid(sig_alg_oid)?;
    let spki = <X509SubjectPublicKeyInfoOwned as x509_der::Decode>::from_der(spki_der)
        .map_err(|e| x509_der_error(e, format_args!("failed to parse SubjectPublicKeyInfo")))?;
    let cert_issuer = match &info {
        Some(info) => &info.issuer_subject,
        None => cert_subject,
    };

    // Build certificate extensions
    let key_usage_extension = Extension {
        extn_id: X509_KEY_USAGE_OID,
        critical: true,
        extn_value: X509OctetString::new(key_usage_ext_bits)
            .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
    };

    let mut cert_extensions = vec_try_with_capacity!(3)?;
    cert_extensions.push(key_usage_extension); // capacity enough

    if let Some(basic_constraint_ext_val) = basic_constraint_ext_val {
        let basic_constraint_ext = Extension {
            extn_id: X509_BASIC_CONSTRAINTS_OID,
            critical: true,
            extn_value: X509OctetString::new(basic_constraint_ext_val)
                .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
        };
        cert_extensions.push(basic_constraint_ext); // capacity enough
    }

    if let Some(attest_extn_val) = attestation_ext {
        let attest_ext = Extension {
            extn_id: X509_ATTESTATION_EXTENSION_OID,
            critical: false,
            extn_value: X509OctetString::new(attest_extn_val)
                .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
        };
        cert_extensions.push(attest_ext) // capacity enough
    }

    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(cert_serial).map_err(|e| {
            x509_der_error(
                e,
                format_args!("failed to build serial number for {cert_serial:?}"),
            )
        })?,
        signature: X509AlgorithmIdentifierOwned {
            oid: sig_alg_oid,
            parameters,
        },
        issuer: <RdnSequence as x509_der::Decode>::from_der(cert_issuer)
            .map_err(|e| x509_der_error(e, format_args!("failed to build issuer")))?,
        validity: Validity {
            not_before: validity_time_from_datetime(not_before)?,
            not_after: validity_time_from_datetime(not_after)?,
        },
        subject: <RdnSequence as x509_der::Decode>::from_der(cert_subject)
            .map_err(|e| x509_der_error(e, format_args!("failed to build subject")))?,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(cert_extensions),
    })
}

/// Extract the Subject field from a `keymint::Certificate` as DER-encoded data.
pub(crate) fn extract_subject(cert: &keymint::Certificate) -> Result<Vec<u8>, Error> {
    let cert = <x509_cert::Certificate as x509_der::Decode>::from_der(&cert.encoded_certificate)
        .map_err(|e| km_err!(EncodingError, "failed to parse certificate: {e:?}"))?;
    let subject_data = x509_der::Encode::to_der(&cert.tbs_certificate.subject)
        .map_err(|e| km_err!(EncodingError, "failed to DER-encode subject: {e:?}"))?;
    Ok(subject_data)
}

fn x509_oid(oid: ObjectIdentifier) -> Result<X509ObjectIdentifier, Error> {
    X509ObjectIdentifier::from_bytes(oid.as_bytes())
        .map_err(|_| Error::from(CommonErrorKind::Der(ErrorKind::OidMalformed)))
}

/// Construct x.509-cert::time::Time from `DateTime`.
/// RFC 5280 section 4.1.2.5 requires that UtcTime is used up to 2049
/// and GeneralizedTime from 2050 onwards
fn validity_time_from_datetime(when: DateTime) -> Result<Time, Error> {
    let dt_err = |_| Error::from(CommonErrorKind::Der(ErrorKind::DateTime));
    let secs_since_epoch: i64 = when.ms_since_epoch / 1000;

    if when.ms_since_epoch >= 0 {
        const MAX_UTC_TIME: Duration = Duration::from_secs(2524608000); // 2050-01-01T00:00:00Z

        let duration = Duration::from_secs(u64::try_from(secs_since_epoch).map_err(dt_err)?);
        if duration >= MAX_UTC_TIME {
            Ok(Time::GeneralTime(
                X509GeneralizedTime::from_unix_duration(duration).map_err(|e| {
                    x509_der_error(e, format_args!("failed to build GeneralTime for {when:?}"))
                })?,
            ))
        } else {
            Ok(Time::UtcTime(
                X509UtcTime::from_unix_duration(duration).map_err(|e| {
                    x509_der_error(e, format_args!("failed to build UtcTime for {when:?}"))
                })?,
            ))
        }
    } else {
        // TODO: cope with negative offsets from Unix Epoch.
        Ok(Time::GeneralTime(
            X509GeneralizedTime::from_unix_duration(Duration::from_secs(0)).map_err(|e| {
                x509_der_error(
                    e,
                    format_args!("failed to build GeneralizedTime(0) for {when:?}"),
                )
            })?,
        ))
    }
}

pub(crate) fn asn1_der_encode<T: Encode>(obj: &T) -> Result<Vec<u8>, der::Error> {
    let mut encoded_data = Vec::<u8>::new();
    obj.encode_to_vec(&mut encoded_data)?;
    Ok(encoded_data)
}

pub(crate) fn x509_der_encode<T: x509_der::Encode>(obj: &T) -> Result<Vec<u8>, x509_der::Error> {
    let mut encoded_data = Vec::<u8>::new();
    x509_der::Encode::encode_to_vec(obj, &mut encoded_data)?;
    Ok(encoded_data)
}

/// Build key usage extension bits.
pub(crate) fn key_usage_extension_bits(params: &[KeyParam]) -> KeyUsage {
    // Build `KeyUsage` bitmask based on allowed purposes for the key.
    let mut key_usage_bits = FlagSet::<KeyUsages>::default();
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign | KeyPurpose::Verify => {
                    key_usage_bits |= KeyUsages::DigitalSignature;
                }
                KeyPurpose::Decrypt | KeyPurpose::Encrypt => {
                    key_usage_bits |= KeyUsages::DataEncipherment;
                    key_usage_bits |= KeyUsages::KeyEncipherment;
                }
                KeyPurpose::WrapKey => {
                    key_usage_bits |= KeyUsages::KeyEncipherment;
                }
                KeyPurpose::AgreeKey => {
                    key_usage_bits |= KeyUsages::KeyAgreement;
                }
                KeyPurpose::AttestKey => {
                    key_usage_bits |= KeyUsages::KeyCertSign;
                }
            }
        }
    }
    KeyUsage(key_usage_bits)
}

/// Build basic constraints extension value
pub(crate) fn basic_constraints_ext_value(ca_required: bool) -> BasicConstraints {
    BasicConstraints {
        ca: ca_required,
        path_len_constraint: None,
    }
}

/// Attestation extension contents
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   SecurityLevel,
///     keyMintVersion             INTEGER,
///     keymintSecurityLevel       SecurityLevel,
///     attestationChallenge       OCTET_STRING,
///     uniqueId                   OCTET_STRING,
///     softwareEnforced           AuthorizationList,
///     hardwareEnforced           AuthorizationList,
/// }
/// ```
#[derive(Debug, Clone, Sequence, PartialEq)]
pub(crate) struct AttestationExtension<'a> {
    attestation_version: i32,
    attestation_security_level: SecurityLevel,
    keymint_version: i32,
    keymint_security_level: SecurityLevel,
    #[asn1(type = "OCTET STRING")]
    attestation_challenge: &'a [u8],
    #[asn1(type = "OCTET STRING")]
    unique_id: &'a [u8],
    sw_enforced: AuthorizationList<'a>,
    hw_enforced: AuthorizationList<'a>,
}

impl AssociatedOid for AttestationExtension<'_> {
    const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
}

/// Security level enumeration
/// ```asn1
/// SecurityLevel ::= ENUMERATED {
///     Software                   (0),
///     TrustedEnvironment         (1),
///     StrongBox                  (2),
/// }
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated, PartialEq)]
enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    Strongbox = 2,
}

/// Build an ASN.1 DER-encoded attestation extension.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attestation_extension<'a>(
    keymint_version: i32,
    challenge: &'a [u8],
    app_id: &'a [u8],
    security_level: keymint::SecurityLevel,
    attestation_ids: Option<&'a crate::AttestationIdInfo>,
    params: &'a [KeyParam],
    chars: &'a [KeyCharacteristics],
    unique_id: &'a Vec<u8>,
    boot_info: &'a keymint::BootInfo,
    additional_attestation_info: &'a [KeyParam],
) -> Result<AttestationExtension<'a>, Error> {
    let mut sw_chars: &[KeyParam] = &[];
    let mut hw_chars: &[KeyParam] = &[];
    for characteristic in chars.iter() {
        match characteristic.security_level {
            keymint::SecurityLevel::Keystore | keymint::SecurityLevel::Software => {
                sw_chars = &characteristic.authorizations
            }
            l if l == security_level => hw_chars = &characteristic.authorizations,
            l => {
                return Err(km_err!(
                    InvalidTag,
                    "found characteristics for unexpected security level {l:?}",
                ))
            }
        }
    }
    let (sw_params, hw_params): (&[KeyParam], &[KeyParam]) = match security_level {
        keymint::SecurityLevel::Software => (params, &[]),
        _ => (&[], params),
    };
    let sw_enforced = AuthorizationList::new(
        sw_chars,
        sw_params,
        attestation_ids,
        None,
        Some(app_id),
        additional_attestation_info,
    )?;
    let hw_enforced = AuthorizationList::new(
        hw_chars,
        hw_params,
        attestation_ids,
        Some(RootOfTrust::from(boot_info)),
        None,
        &[],
    )?;
    let sec_level = SecurityLevel::try_from(security_level as u32)
        .map_err(|_| km_err!(InvalidArgument, "invalid security level {security_level:?}"))?;
    let ext = AttestationExtension {
        attestation_version: keymint_version,
        attestation_security_level: sec_level,
        keymint_version,
        keymint_security_level: sec_level,
        attestation_challenge: challenge,
        unique_id,
        sw_enforced,
        hw_enforced,
    };
    Ok(ext)
}

/// Struct for creating ASN.1 DER-serialized `AuthorizationList`. The fields in the ASN.1
/// sequence are categorized into four fields in the struct based on their usage.
/// ```asn1
/// AuthorizationList ::= SEQUENCE {
///     purpose                    [1] EXPLICIT SET OF INTEGER OPTIONAL,
///     algorithm                  [2] EXPLICIT INTEGER OPTIONAL,
///     keySize                    [3] EXPLICIT INTEGER OPTIONAL,
///     blockMode                  [4] EXPLICIT SET OF INTEGER OPTIONAL,  -- Symmetric keys only
///     digest                     [5] EXPLICIT SET OF INTEGER OPTIONAL,
///     padding                    [6] EXPLICIT SET OF INTEGER OPTIONAL,
///     callerNonce                [7] EXPLICIT NULL OPTIONAL,  -- Symmetric keys only
///     minMacLength               [8] EXPLICIT INTEGER OPTIONAL,  -- Symmetric keys only
///     ecCurve                    [10] EXPLICIT INTEGER OPTIONAL,
///     mlDsaVariant               [11] EXPLICIT INTEGER OPTIONAL,
///     rsaPublicExponent          [200] EXPLICIT INTEGER OPTIONAL,
///     mgfDigest                  [203] EXPLICIT SET OF INTEGER OPTIONAL,
///     rollbackResistance         [303] EXPLICIT NULL OPTIONAL,
///     earlyBootOnly              [305] EXPLICIT NULL OPTIONAL,
///     activeDateTime             [400] EXPLICIT INTEGER OPTIONAL,
///     originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
///     usageExpireDateTime        [402] EXPLICIT INTEGER OPTIONAL,
///     usageCountLimit            [405] EXPLICIT INTEGER OPTIONAL,
///     userSecureId               [502] EXPLICIT INTEGER OPTIONAL,  -- Only used on key import
///     noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
///     userAuthType               [504] EXPLICIT INTEGER OPTIONAL,
///     authTimeout                [505] EXPLICIT INTEGER OPTIONAL,
///     allowWhileOnBody           [506] EXPLICIT NULL OPTIONAL,
///     trustedUserPresenceReq     [507] EXPLICIT NULL OPTIONAL,
///     trustedConfirmationReq     [508] EXPLICIT NULL OPTIONAL,
///     unlockedDeviceReq          [509] EXPLICIT NULL OPTIONAL,
///     creationDateTime           [701] EXPLICIT INTEGER OPTIONAL,
///     origin                     [702] EXPLICIT INTEGER OPTIONAL,
///     rootOfTrust                [704] EXPLICIT RootOfTrust OPTIONAL,
///     osVersion                  [705] EXPLICIT INTEGER OPTIONAL,
///     osPatchLevel               [706] EXPLICIT INTEGER OPTIONAL,
///     attestationApplicationId   [709] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdBrand         [710] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdDevice        [711] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdProduct       [712] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdSerial        [713] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdImei          [714] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdMeid          [715] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdModel         [717] EXPLICIT OCTET_STRING OPTIONAL,
///     vendorPatchLevel           [718] EXPLICIT INTEGER OPTIONAL,
///     bootPatchLevel             [719] EXPLICIT INTEGER OPTIONAL,
///     deviceUniqueAttestation    [720] EXPLICIT NULL OPTIONAL,
///     attestationIdSecondImei    [723] EXPLICIT OCTET_STRING OPTIONAL,
///     -- moduleHash contains a SHA-256 hash of DER-encoded `Modules`
///     moduleHash                 [724] EXPLICIT OCTET_STRING OPTIONAL,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationList<'a> {
    pub auths: Cow<'a, [KeyParam]>,
    /// Whether to include `UserSecureId` value if found in `auths` when encoding.
    pub encode_sid: bool,
    pub ids: AttestationIds<'a>,
    pub rot_info: Option<Vec<u8>>,
    pub app_id: Option<Cow<'a, [u8]>>,
    pub module_hash: Option<Cow<'a, [u8]>>,
}

/// Tags used in `AuthorizationList` in the schema-defined order.
const AUTHORIZATION_LIST_TAGS: &[Tag] = &[
    Tag::Purpose,
    Tag::Algorithm,
    Tag::KeySize,
    Tag::BlockMode,
    Tag::Digest,
    Tag::Padding,
    Tag::CallerNonce,
    Tag::MinMacLength,
    Tag::EcCurve,
    Tag::MlDsaVariant,
    Tag::RsaPublicExponent,
    Tag::RsaOaepMgfDigest,
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::ActiveDatetime,
    Tag::OriginationExpireDatetime,
    Tag::UsageExpireDatetime,
    Tag::UsageCountLimit,
    Tag::UserSecureId,
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::AllowWhileOnBody,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::CreationDatetime,
    Tag::Origin,
    Tag::RootOfTrust,
    Tag::OsVersion,
    Tag::OsPatchlevel,
    Tag::AttestationApplicationId,
    Tag::AttestationIdBrand,
    Tag::AttestationIdDevice,
    Tag::AttestationIdProduct,
    Tag::AttestationIdSerial,
    Tag::AttestationIdImei,
    Tag::AttestationIdMeid,
    Tag::AttestationIdManufacturer,
    Tag::AttestationIdModel,
    Tag::VendorPatchlevel,
    Tag::BootPatchlevel,
    Tag::DeviceUniqueAttestation,
    Tag::AttestationIdSecondImei,
    Tag::ModuleHash,
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationIds<'a> {
    brand: Option<Cow<'a, [u8]>>,
    device: Option<Cow<'a, [u8]>>,
    product: Option<Cow<'a, [u8]>>,
    serial: Option<Cow<'a, [u8]>>,
    imei: Option<Cow<'a, [u8]>>,
    imei2: Option<Cow<'a, [u8]>>,
    meid: Option<Cow<'a, [u8]>>,
    manufacturer: Option<Cow<'a, [u8]>>,
    model: Option<Cow<'a, [u8]>>,
}

impl AttestationIds<'_> {
    fn new_from_key_params<'a>(keygen_params: &'a [KeyParam]) -> Result<AttestationIds<'a>, Error> {
        let mut ids = AttestationIds::default();
        for param in keygen_params {
            match param {
                KeyParam::AttestationIdBrand(v) => match ids.brand {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag brand")),
                    None => ids.brand = Some(v.into()),
                },
                KeyParam::AttestationIdDevice(v) => match ids.device {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag device")),
                    None => ids.device = Some(v.into()),
                },
                KeyParam::AttestationIdProduct(v) => match ids.product {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag product")),
                    None => ids.product = Some(v.into()),
                },
                KeyParam::AttestationIdSerial(v) => match ids.serial {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag serial")),
                    None => ids.serial = Some(v.into()),
                },
                KeyParam::AttestationIdImei(v) => match ids.imei {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag imei")),
                    None => ids.imei = Some(v.into()),
                },
                KeyParam::AttestationIdSecondImei(v) => match ids.imei2 {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag imei2")),
                    None => ids.imei2 = Some(v.into()),
                },
                KeyParam::AttestationIdMeid(v) => match ids.meid {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag meid")),
                    None => ids.meid = Some(v.into()),
                },
                KeyParam::AttestationIdManufacturer(v) => match ids.manufacturer {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag manufacturer")),
                    None => ids.manufacturer = Some(v.into()),
                },
                KeyParam::AttestationIdModel(v) => match ids.model {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag model")),
                    None => ids.model = Some(v.into()),
                },
                // Ignore all others.
                _ => (),
            }
        }
        Ok(ids)
    }

    fn is_empty(&self) -> bool {
        *self == AttestationIds::default()
    }

    fn check_match(&mut self, wanted: &crate::AttestationIdInfo) -> Result<(), Error> {
        if self
            .brand
            .as_ref()
            .is_some_and(|brand| *brand != wanted.brand)
        {
            self.brand = Some(wanted.brand.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdBrand, reseting to {:?}",
                wanted.brand
            );
        }
        if self
            .device
            .as_ref()
            .is_some_and(|device| *device != wanted.device)
        {
            self.device = Some(wanted.device.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdDevice, reseting to {:?}",
                wanted.device
            );
        }
        if self
            .product
            .as_ref()
            .is_some_and(|product| *product != wanted.product)
        {
            self.product = Some(wanted.product.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdProduct, reseting to {:?}",
                wanted.product
            );
        }
        if self
            .serial
            .as_ref()
            .is_some_and(|serial| *serial != wanted.serial)
        {
            self.serial = Some(wanted.serial.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdSerial, reseting to {:?}",
                wanted.serial
            );
        }
        if self.imei.as_ref().is_some_and(|imei| *imei != wanted.imei) {
            self.imei = Some(wanted.imei.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdImei, reseting to {:?}",
                wanted.imei
            );
        }
        if wanted.imei2.is_empty() {
            self.imei2 = None;
        } else if self
            .imei2
            .as_ref()
            .is_some_and(|imei2| *imei2 != wanted.imei2)
        {
            self.imei2 = Some(wanted.imei2.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdSecondImei, reseting to {:?}",
                wanted.imei2
            );
        }
        if self.meid.as_ref().is_some_and(|meid| *meid != wanted.meid) {
            self.meid = Some(wanted.meid.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdMeid, reseting to {:?}",
                wanted.meid
            );
        }
        if self
            .manufacturer
            .as_ref()
            .is_some_and(|mfr| *mfr != wanted.manufacturer)
        {
            self.manufacturer = Some(wanted.manufacturer.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdManufacturer, reseting to {:?}",
                wanted.manufacturer
            );
        }
        if self
            .model
            .as_ref()
            .is_some_and(|model| *model != wanted.model)
        {
            self.model = Some(wanted.model.clone().into());
            log::info!(
                "attestation ID mismatch for AttestationIdModel, reseting to {:?}",
                wanted.model
            );
        }
        Ok(())
    }
}

impl<'a> AuthorizationList<'a> {
    /// Build an `AuthorizationList` ready for serialization. This constructor will fail if device
    /// ID attestation is required but the relevant IDs are missing or mismatched.  Any
    /// `UserSecureId` values included in `auths` will be ignored on encoding.
    fn new(
        auths: &'a [KeyParam],
        keygen_params: &'a [KeyParam],
        attestation_ids: Option<&crate::AttestationIdInfo>,
        rot_info: Option<RootOfTrust>,
        app_id: Option<&'a [u8]>,
        additional_attestation_info: &'a [KeyParam],
    ) -> Result<Self, Error> {
        let mut requested_ids = AttestationIds::new_from_key_params(keygen_params)?;
        if !requested_ids.is_empty() {
            match attestation_ids {
                None => return Err(km_err!(CannotAttestIds, "no attestation IDs provisioned")),
                Some(attestation_ids) => requested_ids.check_match(attestation_ids)?,
            }
        }
        let encoded_rot = if let Some(rot) = rot_info {
            Some(
                rot.to_der()
                    .map_err(|e| der_err!(e, "failed to encode RoT"))?,
            )
        } else {
            None
        };
        let module_hash = get_opt_tag_value!(additional_attestation_info, ModuleHash)?;
        Ok(Self {
            auths: auths.into(),
            encode_sid: false,
            ids: requested_ids,
            rot_info: encoded_rot,
            app_id: app_id.map(Into::into),
            module_hash: module_hash.map(Into::into),
        })
    }

    /// Build an `AuthorizationList` using a set of key parameters.
    ///
    /// The checks for the attestation ids are not run here in contrast to `AuthorizationList::new`
    /// because this method is used to construct an `AuthorizationList` in the decode path rather
    /// than in the encode path.
    ///
    /// Any (single) `UserSecureId` value in `key_params` will be included when the
    /// `AuthorizationList` is DER-encoded.
    ///
    /// Note: decode path is currently used only by `KeyMintTa::import_wrapped_key` functionality,
    /// which only uses `auth` field of `AuthorizationList`. Decoding for the whole
    /// `AuthorizationList` is added here for the completeness and anticipating a future use case of
    /// decoding the attestation extension from an X.509 certificate.
    fn new_from_key_params(key_params: Vec<KeyParam>) -> Result<Self, der::Error> {
        let mut auths = Vec::new();
        let mut ids = AttestationIds::default();
        let mut rot: Option<Vec<u8>> = None;
        let mut attest_app_id: Option<Cow<'a, [u8]>> = None;
        let mut module_hash: Option<Cow<'a, [u8]>> = None;

        // Divide key parameters into key characteristics and key generation parameters.
        for param in key_params {
            match param {
                KeyParam::RootOfTrust(encoded_rot) => rot = Some(encoded_rot),
                KeyParam::AttestationApplicationId(app_id) => attest_app_id = Some(app_id.into()),
                KeyParam::AttestationIdBrand(v) => ids.brand = Some(v.into()),
                KeyParam::AttestationIdDevice(v) => ids.device = Some(v.into()),
                KeyParam::AttestationIdProduct(v) => ids.product = Some(v.into()),
                KeyParam::AttestationIdSerial(v) => ids.serial = Some(v.into()),
                KeyParam::AttestationIdImei(v) => ids.imei = Some(v.into()),
                KeyParam::AttestationIdSecondImei(v) => ids.imei2 = Some(v.into()),
                KeyParam::AttestationIdMeid(v) => ids.meid = Some(v.into()),
                KeyParam::AttestationIdManufacturer(v) => ids.manufacturer = Some(v.into()),
                KeyParam::AttestationIdModel(v) => ids.model = Some(v.into()),
                KeyParam::ModuleHash(hash) => module_hash = Some(hash.into()),
                _ => auths.try_push(param).map_err(der_alloc_err)?,
            }
        }
        Ok(AuthorizationList {
            auths: auths.into(),
            encode_sid: true,
            ids,
            rot_info: rot,
            app_id: attest_app_id,
            module_hash,
        })
    }
}

/// Convert an error into a `der::Error` indicating allocation failure.
#[inline]
fn der_alloc_err<T>(_e: T) -> der::Error {
    der::Error::new(der::ErrorKind::Overlength, der::Length::ZERO)
}

/// Implementation of [`der::DecodeValue`] which constructs an AuthorizationList from bytes.
impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
    type Error = der::Error;

    fn decode_value<R: der::Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        // TODO: define a MAX_SIZE for AuthorizationList and check whether the actual length from
        // the length field of header is less than the MAX_SIZE

        // Check for an empty sequence
        if header.length().is_zero() {
            return Ok(AuthorizationList {
                auths: Vec::new().into(),
                encode_sid: true,
                ids: AttestationIds::default(),
                rot_info: None,
                app_id: None,
                module_hash: None,
            });
        }
        if decoder.remaining_len() < header.length() {
            return Err(decoder.error(der::ErrorKind::Incomplete {
                expected_len: header.length(),
                actual_len: decoder.remaining_len(),
            }));
        }

        let mut key_params = Vec::new();
        let mut non_consumed_tag: Option<Tag> = None;
        for &tag in AUTHORIZATION_LIST_TAGS {
            if non_consumed_tag.is_none() {
                non_consumed_tag = decode_tag_from_bytes(decoder)?;
            }
            if non_consumed_tag == Some(tag) {
                non_consumed_tag = None;
                // Decode the length of the inner encoding
                let inner_len = Length::decode(decoder)?;
                if decoder.remaining_len() < inner_len {
                    return Err(decoder.error(der::ErrorKind::Incomplete {
                        expected_len: inner_len,
                        actual_len: decoder.remaining_len(),
                    }));
                }
                let next_tlv = decoder.tlv_bytes()?;
                decode_value_from_bytes(tag, next_tlv, &mut key_params)?;
            }
        }
        if non_consumed_tag.is_some() {
            return Err(decoder.error(der::ErrorKind::Incomplete {
                expected_len: Length::ZERO,
                actual_len: decoder.remaining_len(),
            }));
        }

        // Process the key params and construct the `AuthorizationList`
        AuthorizationList::new_from_key_params(key_params)
    }
}

// Macros to decode key parameters from their ASN.1 encoding in one of the forms:
//   field    [<tag>] EXPLICIT SET OF INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT NULL OPTIONAL
//   field    [<tag>] EXPLICIT OCTET STRING OPTIONAL
// There are three different variants for the INTEGER type.

macro_rules! key_params_from_asn1_set_of_integer {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let vals = SetOfVec::<i32>::from_der($tlv_bytes)?;
        for val in vals.into_vec() {
            $key_params.try_push(KeyParam::$variant(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Set})?)).map_err(der_alloc_err)?;
        }
    }
}

macro_rules! key_param_from_asn1_integer {
    {$variant:ident, $int_type:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = $int_type::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Integer})?)).map_err(der_alloc_err)?;
    }
}

macro_rules! key_param_from_asn1_integer_newtype {
    {$variant:ident, $int_type:ident, $newtype:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = $int_type::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant($newtype(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Integer})?))).map_err(der_alloc_err)?;
    }
}

macro_rules! key_param_from_asn1_null {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        Null::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant).map_err(der_alloc_err)?;
    };
}

macro_rules! key_param_from_asn1_integer_datetime {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = i64::from_der($tlv_bytes)?;
        $key_params
            .try_push(KeyParam::$variant(DateTime{ms_since_epoch: val}))
            .map_err(der_alloc_err)?;
    };
}

macro_rules! key_param_from_asn1_octet_string {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = <&OctetStringRef>::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant(try_to_vec(val.as_bytes())
                                                .map_err(der_alloc_err)?)).map_err(der_alloc_err)?;
    };
}

fn decode_value_from_bytes(
    tag: keymint::Tag,
    tlv_bytes: &[u8],
    key_params: &mut Vec<KeyParam>,
) -> Result<(), der::Error> {
    match tag {
        Tag::Purpose => {
            key_params_from_asn1_set_of_integer!(Purpose, tlv_bytes, key_params);
        }
        Tag::Algorithm => {
            key_param_from_asn1_integer!(Algorithm, i32, tlv_bytes, key_params);
        }
        Tag::KeySize => {
            key_param_from_asn1_integer_newtype!(
                KeySize,
                u32,
                KeySizeInBits,
                tlv_bytes,
                key_params
            );
        }
        Tag::BlockMode => {
            key_params_from_asn1_set_of_integer!(BlockMode, tlv_bytes, key_params);
        }
        Tag::Digest => {
            key_params_from_asn1_set_of_integer!(Digest, tlv_bytes, key_params);
        }
        Tag::Padding => {
            key_params_from_asn1_set_of_integer!(Padding, tlv_bytes, key_params);
        }
        Tag::CallerNonce => {
            key_param_from_asn1_null!(CallerNonce, tlv_bytes, key_params);
        }
        Tag::MinMacLength => {
            key_param_from_asn1_integer!(MinMacLength, u32, tlv_bytes, key_params);
        }
        Tag::EcCurve => {
            key_param_from_asn1_integer!(EcCurve, i32, tlv_bytes, key_params);
        }
        Tag::MlDsaVariant => {
            key_param_from_asn1_integer!(MlDsaVariant, i32, tlv_bytes, key_params);
        }
        Tag::RsaPublicExponent => {
            key_param_from_asn1_integer_newtype!(
                RsaPublicExponent,
                u64,
                RsaExponent,
                tlv_bytes,
                key_params
            );
        }
        Tag::RsaOaepMgfDigest => {
            key_params_from_asn1_set_of_integer!(RsaOaepMgfDigest, tlv_bytes, key_params);
        }
        Tag::RollbackResistance => {
            key_param_from_asn1_null!(RollbackResistance, tlv_bytes, key_params);
        }
        Tag::EarlyBootOnly => {
            key_param_from_asn1_null!(EarlyBootOnly, tlv_bytes, key_params);
        }
        Tag::ActiveDatetime => {
            key_param_from_asn1_integer_datetime!(ActiveDatetime, tlv_bytes, key_params);
        }
        Tag::OriginationExpireDatetime => {
            key_param_from_asn1_integer_datetime!(OriginationExpireDatetime, tlv_bytes, key_params);
        }
        Tag::UsageExpireDatetime => {
            key_param_from_asn1_integer_datetime!(UsageExpireDatetime, tlv_bytes, key_params);
        }
        Tag::UsageCountLimit => {
            key_param_from_asn1_integer!(UsageCountLimit, u32, tlv_bytes, key_params);
        }
        Tag::UserSecureId => {
            // Note that the `UserSecureId` tag has tag type `ULONG_REP` indicating that it can be
            // repeated, but the ASN.1 schema for `AuthorizationList` has this field as having type
            // `INTEGER` not `SET OF INTEGER`. This reflects the special usage of `UserSecureId`
            // in `importWrappedKey()` processing.
            key_param_from_asn1_integer!(UserSecureId, u64, tlv_bytes, key_params);
        }
        Tag::NoAuthRequired => {
            key_param_from_asn1_null!(NoAuthRequired, tlv_bytes, key_params);
        }
        Tag::UserAuthType => {
            key_param_from_asn1_integer!(UserAuthType, u32, tlv_bytes, key_params);
        }
        Tag::AuthTimeout => {
            key_param_from_asn1_integer!(AuthTimeout, u32, tlv_bytes, key_params);
        }
        Tag::AllowWhileOnBody => {
            key_param_from_asn1_null!(AllowWhileOnBody, tlv_bytes, key_params);
        }
        Tag::TrustedUserPresenceRequired => {
            key_param_from_asn1_null!(TrustedUserPresenceRequired, tlv_bytes, key_params);
        }
        Tag::TrustedConfirmationRequired => {
            key_param_from_asn1_null!(TrustedConfirmationRequired, tlv_bytes, key_params);
        }
        Tag::UnlockedDeviceRequired => {
            key_param_from_asn1_null!(UnlockedDeviceRequired, tlv_bytes, key_params);
        }
        Tag::CreationDatetime => {
            key_param_from_asn1_integer_datetime!(CreationDatetime, tlv_bytes, key_params);
        }
        Tag::Origin => {
            key_param_from_asn1_integer!(Origin, i32, tlv_bytes, key_params);
        }
        Tag::RootOfTrust => {
            key_params
                .try_push(KeyParam::RootOfTrust(
                    try_to_vec(tlv_bytes).map_err(der_alloc_err)?,
                ))
                .map_err(der_alloc_err)?;
        }
        Tag::OsVersion => {
            key_param_from_asn1_integer!(OsVersion, u32, tlv_bytes, key_params);
        }
        Tag::OsPatchlevel => {
            key_param_from_asn1_integer!(OsPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::AttestationApplicationId => {
            key_param_from_asn1_octet_string!(AttestationApplicationId, tlv_bytes, key_params);
        }
        Tag::AttestationIdBrand => {
            key_param_from_asn1_octet_string!(AttestationIdBrand, tlv_bytes, key_params);
        }
        Tag::AttestationIdDevice => {
            key_param_from_asn1_octet_string!(AttestationIdDevice, tlv_bytes, key_params);
        }
        Tag::AttestationIdProduct => {
            key_param_from_asn1_octet_string!(AttestationIdProduct, tlv_bytes, key_params);
        }
        Tag::AttestationIdSerial => {
            key_param_from_asn1_octet_string!(AttestationIdSerial, tlv_bytes, key_params);
        }
        Tag::AttestationIdImei => {
            key_param_from_asn1_octet_string!(AttestationIdImei, tlv_bytes, key_params);
        }
        Tag::AttestationIdSecondImei => {
            key_param_from_asn1_octet_string!(AttestationIdSecondImei, tlv_bytes, key_params);
        }
        Tag::AttestationIdMeid => {
            key_param_from_asn1_octet_string!(AttestationIdMeid, tlv_bytes, key_params);
        }
        Tag::AttestationIdManufacturer => {
            key_param_from_asn1_octet_string!(AttestationIdManufacturer, tlv_bytes, key_params);
        }
        Tag::AttestationIdModel => {
            key_param_from_asn1_octet_string!(AttestationIdModel, tlv_bytes, key_params);
        }
        Tag::VendorPatchlevel => {
            key_param_from_asn1_integer!(VendorPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::BootPatchlevel => {
            key_param_from_asn1_integer!(BootPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::DeviceUniqueAttestation => {
            key_param_from_asn1_null!(DeviceUniqueAttestation, tlv_bytes, key_params);
        }
        Tag::ModuleHash => {
            key_param_from_asn1_octet_string!(ModuleHash, tlv_bytes, key_params);
        }
        _ => {
            // Note: `der::Error` or `der::ErrorKind` is not expressive enough for decoding
            // tags in high tag form. Documentation of this error kind does not match this
            // situation. But we use the `der::ErrorKind` as close as possible.
            return Err(der::ErrorKind::TagNumberInvalid.into());
        }
    }
    Ok(())
}

/// Decode the tag of a field in AuthorizationList.
fn decode_tag_from_bytes<'a, R: der::Reader<'a>>(
    decoder: &mut R,
) -> Result<Option<keymint::Tag>, der::Error> {
    // Avoid reading for tags beyond the size of the encoded AuthorizationList
    if decoder.remaining_len() == Length::ZERO {
        return Ok(None);
    }
    let b1 = decoder.read_byte()?;
    if b1 & 0b11100000 != 0b10100000 {
        // KeyMint tags should be encoded as context-specific (0b10......) constructed
        // (0b..1.....) ASN.1 tag values.
        return Err(der::ErrorKind::TagNumberInvalid.into());
    }
    let b1 = b1 & 0b00011111u8;
    let raw_tag = if b1 == 0b00011111u8 {
        // High tag form, read the next byte
        let b2 = decoder.read_byte()?;
        if b2 & 0x80u8 == 0x80u8 {
            // Encoded tag length is 3, read the next byte
            let b3 = decoder.read_byte()?;
            let tag_byte: u16 = ((b2 ^ 0x80u8) as u16) << 7;
            (tag_byte | b3 as u16) as u32
        } else {
            b2 as u32
        }
    } else {
        b1 as u32
    };
    let tag = from_raw_tag_value(raw_tag);
    if tag == Tag::Invalid {
        // Note: der::Error or der::ErrorKind is not expressive enough for decoding tags
        // in high tag form. Documentation of this error kind does not match this situation.
        // Find a better way to express the error.
        Err(der::ErrorKind::TagNumberInvalid.into())
    } else {
        Ok(Some(tag))
    }
}

// Macros to extract key characteristics for ASN.1 encoding into one of the forms:
//   field    [<tag>] EXPLICIT SET OF INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT NULL OPTIONAL
//   field    [<tag>] EXPLICIT OCTET STRING OPTIONAL
// together with an extra variant that deals with OCTET STRING values that must match
// a provisioned attestation ID value.
macro_rules! asn1_set_of_integer {
    { $params:expr, $variant:ident } => {
        {
            let mut results = Vec::new();
            for param in $params.as_ref() {
                if let KeyParam::$variant(v) = param {
                    results.try_push(v.clone()).map_err(der_alloc_err)?;
                }
            }
            if !results.is_empty() {
                // The input key characteristics have been sorted and so are in numerical order, but
                // may contain duplicates that need to be weeded out.
                let mut set = der::asn1::SetOfVec::new();
                let mut prev_val = None;
                for val in results {
                    let val = val as i64;
                    if let Some(prev) = prev_val {
                        if prev == val {
                            continue; // skip duplicate
                        }
                    }
                    set.insert_ordered(val)?;
                    prev_val = Some(val);
                }
                Some(ExplicitTaggedValue::new(Tag::$variant, set))
            } else {
                None
            }
        }
    }
}
macro_rules! asn1_integer {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, *val as i64))
        } else {
            None
        }
    }
}
macro_rules! asn1_integer_newtype {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, val.0 as i64))
        } else {
            None
        }
    }
}
macro_rules! asn1_integer_datetime {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, val.ms_since_epoch))
        } else {
            None
        }
    }
}
macro_rules! asn1_null {
    { $params:expr, $variant:ident } => {
        if get_bool_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, ()))
        } else {
            None
        }
    }
}

fn asn1_octet_string(
    tag: Tag,
    val: Option<&[u8]>,
) -> der::Result<Option<ExplicitTaggedValue<&OctetStringRef>>> {
    match val {
        Some(val) => Ok(Some(ExplicitTaggedValue::new(
            tag,
            OctetStringRef::new(val)?,
        ))),
        None => Ok(None),
    }
}

fn asn1_root_of_trust(
    tag: Tag,
    rot: Option<&[u8]>,
) -> der::Result<Option<ExplicitTaggedValue<RootOfTrust<'_>>>> {
    match rot {
        Some(rot) => Ok(Some(ExplicitTaggedValue::new(
            tag,
            RootOfTrust::from_der(rot)?,
        ))),
        None => Ok(None),
    }
}

fn asn1_val<T: Encode>(
    val: Option<ExplicitTaggedValue<T>>,
    writer: &mut impl der::Writer,
) -> der::Result<()> {
    match val {
        Some(val) => val.encode(writer),
        None => Ok(()),
    }
}

fn asn1_len<T: Encode>(val: Option<ExplicitTaggedValue<T>>) -> der::Result<Length> {
    match val {
        Some(val) => val.encoded_len(),
        None => Ok(Length::ZERO),
    }
}

impl<'a> Sequence<'a> for AuthorizationList<'a> {}

impl EncodeValue for AuthorizationList<'_> {
    fn value_len(&self) -> der::Result<Length> {
        asn1_len(asn1_set_of_integer!(self.auths, Purpose))?
            + asn1_len(asn1_integer!(self.auths, Algorithm))?
            + asn1_len(asn1_integer_newtype!(self.auths, KeySize))?
            + asn1_len(asn1_set_of_integer!(self.auths, BlockMode))?
            + asn1_len(asn1_set_of_integer!(self.auths, Digest))?
            + asn1_len(asn1_set_of_integer!(self.auths, Padding))?
            + asn1_len(asn1_null!(self.auths, CallerNonce))?
            + asn1_len(asn1_integer!(self.auths, MinMacLength))?
            + asn1_len(asn1_integer!(self.auths, EcCurve))?
            + asn1_len(asn1_integer!(self.auths, MlDsaVariant))?
            + asn1_len(asn1_integer_newtype!(self.auths, RsaPublicExponent))?
            + asn1_len(asn1_set_of_integer!(self.auths, RsaOaepMgfDigest))?
            + asn1_len(asn1_null!(self.auths, RollbackResistance))?
            + asn1_len(asn1_null!(self.auths, EarlyBootOnly))?
            + asn1_len(asn1_integer_datetime!(self.auths, ActiveDatetime))?
            + asn1_len(asn1_integer_datetime!(
                self.auths,
                OriginationExpireDatetime
            ))?
            + asn1_len(asn1_integer_datetime!(self.auths, UsageExpireDatetime))?
            + asn1_len(asn1_integer!(self.auths, UsageCountLimit))?
            + if self.encode_sid {
                asn1_len(asn1_integer!(self.auths, UserSecureId))?
            } else {
                Length::ZERO
            }
            + asn1_len(asn1_null!(self.auths, NoAuthRequired))?
            + asn1_len(asn1_integer!(self.auths, UserAuthType))?
            + asn1_len(asn1_integer!(self.auths, AuthTimeout))?
            + asn1_len(asn1_null!(self.auths, AllowWhileOnBody))?
            + asn1_len(asn1_null!(self.auths, TrustedUserPresenceRequired))?
            + asn1_len(asn1_null!(self.auths, TrustedConfirmationRequired))?
            + asn1_len(asn1_null!(self.auths, UnlockedDeviceRequired))?
            + asn1_len(asn1_integer_datetime!(self.auths, CreationDatetime))?
            + asn1_len(asn1_integer!(self.auths, Origin))?
            + asn1_len(asn1_root_of_trust(
                Tag::RootOfTrust,
                self.rot_info.as_deref(),
            )?)?
            + asn1_len(asn1_integer!(self.auths, OsVersion))?
            + asn1_len(asn1_integer!(self.auths, OsPatchlevel))?
            + asn1_len(asn1_octet_string(
                Tag::AttestationApplicationId,
                self.app_id.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdBrand,
                self.ids.brand.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdDevice,
                self.ids.device.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdProduct,
                self.ids.product.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdSerial,
                self.ids.serial.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdImei,
                self.ids.imei.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdMeid,
                self.ids.meid.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdManufacturer,
                self.ids.manufacturer.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdModel,
                self.ids.model.as_deref(),
            )?)?
            + asn1_len(asn1_integer!(self.auths, VendorPatchlevel))?
            + asn1_len(asn1_integer!(self.auths, BootPatchlevel))?
            + asn1_len(asn1_null!(self.auths, DeviceUniqueAttestation))?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdSecondImei,
                self.ids.imei2.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::ModuleHash,
                self.module_hash.as_deref(),
            )?)?
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        asn1_val(asn1_set_of_integer!(self.auths, Purpose), writer)?;
        asn1_val(asn1_integer!(self.auths, Algorithm), writer)?;
        asn1_val(asn1_integer_newtype!(self.auths, KeySize), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, BlockMode), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, Digest), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, Padding), writer)?;
        asn1_val(asn1_null!(self.auths, CallerNonce), writer)?;
        asn1_val(asn1_integer!(self.auths, MinMacLength), writer)?;
        asn1_val(asn1_integer!(self.auths, EcCurve), writer)?;
        asn1_val(asn1_integer!(self.auths, MlDsaVariant), writer)?;
        asn1_val(asn1_integer_newtype!(self.auths, RsaPublicExponent), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, RsaOaepMgfDigest), writer)?;
        asn1_val(asn1_null!(self.auths, RollbackResistance), writer)?;
        asn1_val(asn1_null!(self.auths, EarlyBootOnly), writer)?;
        asn1_val(asn1_integer_datetime!(self.auths, ActiveDatetime), writer)?;
        asn1_val(
            asn1_integer_datetime!(self.auths, OriginationExpireDatetime),
            writer,
        )?;
        asn1_val(
            asn1_integer_datetime!(self.auths, UsageExpireDatetime),
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, UsageCountLimit), writer)?;
        // Note that `UserSecureId` is only included in the extension for
        // importWrappedKey() cases.
        if self.encode_sid {
            asn1_val(asn1_integer!(self.auths, UserSecureId), writer)?;
        }
        asn1_val(asn1_null!(self.auths, NoAuthRequired), writer)?;
        asn1_val(asn1_integer!(self.auths, UserAuthType), writer)?;
        asn1_val(asn1_integer!(self.auths, AuthTimeout), writer)?;
        asn1_val(asn1_null!(self.auths, AllowWhileOnBody), writer)?;
        asn1_val(asn1_null!(self.auths, TrustedUserPresenceRequired), writer)?;
        asn1_val(asn1_null!(self.auths, TrustedConfirmationRequired), writer)?;
        asn1_val(asn1_null!(self.auths, UnlockedDeviceRequired), writer)?;
        asn1_val(asn1_integer_datetime!(self.auths, CreationDatetime), writer)?;
        asn1_val(asn1_integer!(self.auths, Origin), writer)?;
        // Root of trust info is a special case (not in key characteristics).
        asn1_val(
            asn1_root_of_trust(Tag::RootOfTrust, self.rot_info.as_deref())?,
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, OsVersion), writer)?;
        asn1_val(asn1_integer!(self.auths, OsPatchlevel), writer)?;
        // Attestation application ID is a special case (not in key characteristics).
        asn1_val(
            asn1_octet_string(Tag::AttestationApplicationId, self.app_id.as_deref())?,
            writer,
        )?;
        // Accuracy of attestation IDs has already been checked, so just copy across.
        asn1_val(
            asn1_octet_string(Tag::AttestationIdBrand, self.ids.brand.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdDevice, self.ids.device.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdProduct, self.ids.product.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdSerial, self.ids.serial.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdImei, self.ids.imei.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdMeid, self.ids.meid.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(
                Tag::AttestationIdManufacturer,
                self.ids.manufacturer.as_deref(),
            )?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdModel, self.ids.model.as_deref())?,
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, VendorPatchlevel), writer)?;
        asn1_val(asn1_integer!(self.auths, BootPatchlevel), writer)?;
        asn1_val(asn1_null!(self.auths, DeviceUniqueAttestation), writer)?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdSecondImei, self.ids.imei2.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::ModuleHash, self.module_hash.as_deref())?,
            writer,
        )?;
        Ok(())
    }
}

struct ExplicitTaggedValue<T: Encode> {
    pub tag: u32,
    pub val: T,
}

impl<T: Encode> ExplicitTaggedValue<T> {
    fn new(tag: Tag, val: T) -> ExplicitTaggedValue<T> {
        ExplicitTaggedValue {
            tag: raw_tag_value(tag),
            val,
        }
    }

    fn explicit_tag_len(&self) -> der::Result<der::Length> {
        match self.tag {
            0..=0x1e => Ok(der::Length::ONE),
            0x1f..=0x7f => Ok(der::Length::new(2)),
            0x80..=0x3fff => Ok(der::Length::new(3)),
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }

    fn explicit_tag_encode(&self, encoder: &mut dyn der::Writer) -> der::Result<()> {
        match self.tag {
            0..=0x1e => {
                // b101vvvvv is context-specific+constructed
                encoder.write_byte(0b10100000u8 | (self.tag as u8))
            }
            0x1f..=0x7f => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte(self.tag as u8)
            }
            0x80..=0x3fff => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte((self.tag >> 7) as u8 | 0x80u8)?;
                encoder.write_byte((self.tag & 0x007f) as u8)
            }
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }
}

/// The der library explicitly does not support `TagNumber` values bigger than 31,
/// which are required here.  Work around this by manually providing the encoding functionality.
impl<T: Encode> Encode for ExplicitTaggedValue<T> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_len() + inner_len.encoded_len()? + inner_len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_encode(encoder)?;
        inner_len.encode(encoder)?;
        self.val.encode(encoder)
    }
}

/// Root of Trust ASN.1 structure
/// ```asn1
///  * RootOfTrust ::= SEQUENCE {
///  *     verifiedBootKey            OCTET_STRING,
///  *     deviceLocked               BOOLEAN,
///  *     verifiedBootState          VerifiedBootState,
///  *     verifiedBootHash           OCTET_STRING,
///  * }
/// ```
#[derive(Debug, Clone, Sequence)]
struct RootOfTrust<'a> {
    #[asn1(type = "OCTET STRING")]
    verified_boot_key: &'a [u8],
    device_locked: bool,
    verified_boot_state: VerifiedBootState,
    #[asn1(type = "OCTET STRING")]
    verified_boot_hash: &'a [u8],
}

impl<'a> From<&'a keymint::BootInfo> for RootOfTrust<'a> {
    fn from(info: &keymint::BootInfo) -> RootOfTrust<'_> {
        let verified_boot_key: &[u8] = if info.verified_boot_key.is_empty() {
            // If an empty verified boot key was passed by the boot loader, set the verified boot
            // key in the attestation to all zeroes.
            &EMPTY_BOOT_KEY[..]
        } else {
            &info.verified_boot_key[..]
        };
        RootOfTrust {
            verified_boot_key,
            device_locked: info.device_boot_locked,
            verified_boot_state: info.verified_boot_state.into(),
            verified_boot_hash: &info.verified_boot_hash[..],
        }
    }
}

/// Verified Boot State as ASN.1 ENUMERATED type.
///```asn1
///  * VerifiedBootState ::= ENUMERATED {
///  *     Verified                   (0),
///  *     SelfSigned                 (1),
///  *     Unverified                 (2),
///  *     Failed                     (3),
///  * }
///```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated)]
enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl From<keymint::VerifiedBootState> for VerifiedBootState {
    fn from(state: keymint::VerifiedBootState) -> VerifiedBootState {
        match state {
            keymint::VerifiedBootState::Verified => VerifiedBootState::Verified,
            keymint::VerifiedBootState::SelfSigned => VerifiedBootState::SelfSigned,
            keymint::VerifiedBootState::Unverified => VerifiedBootState::Unverified,
            keymint::VerifiedBootState::Failed => VerifiedBootState::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationIdInfo, KeyMintHalVersion};
    use std::vec;

    #[test]
    fn test_rsa_signature_algorithm_has_null_parameters() {
        let spki_der = hex::decode("3012300d06092a864886f70d0101010500030100").unwrap();
        let params = [
            KeyParam::Algorithm(keymint::Algorithm::Rsa),
            KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
            KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: 0 }),
        ];
        let tbs_cert = tbs_certificate(&None, &spki_der, &[], None, None, &[], &params).unwrap();
        assert_eq!(
            hex::encode(
                x509_der::Encode::to_der(tbs_cert.signature.parameters.as_ref().unwrap()).unwrap()
            ),
            "0500"
        );
    }

    #[test]
    fn test_attest_ext_encode_decode() {
        let sec_level = SecurityLevel::TrustedEnvironment;
        let ext = AttestationExtension {
            attestation_version: KeyMintHalVersion::V3 as i32,
            attestation_security_level: sec_level,
            keymint_version: KeyMintHalVersion::V3 as i32,
            keymint_security_level: sec_level,
            attestation_challenge: b"abc",
            unique_id: b"xxx",
            sw_enforced: AuthorizationList::new(&[], &[], None, None, None, &[]).unwrap(),
            hw_enforced: AuthorizationList::new(
                &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
                &[],
                None,
                Some(RootOfTrust {
                    verified_boot_key: &[0xbbu8; 32],
                    device_locked: false,
                    verified_boot_state: VerifiedBootState::Unverified,
                    verified_boot_hash: &[0xee; 32],
                }),
                None,
                &[],
            )
            .unwrap(),
        };
        let got = ext.to_der().unwrap();
        let want = concat!(
            "3071",   // SEQUENCE
            "0202",   // INTEGER len 2
            "012c",   // 300
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironment)
            "0202",   // INTEGER len 2
            "012c",   // 300
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironement)
            "0403",   // BYTE STRING len 3
            "616263", // b"abc"
            "0403",   // BYTE STRING len 3
            "787878", // b"xxx"
            "3000",   // SEQUENCE len 0
            "3055",   // SEQUENCE len 55
            "a203",   // EXPLICIT [2]
            "0201",   // INTEGER len 1
            "03",     // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        assert_eq!(hex::encode(&got), want);
        let mut parsed = AttestationExtension::from_der(&got).unwrap();
        parsed.sw_enforced.encode_sid = false;
        parsed.hw_enforced.encode_sid = false;
        assert_eq!(parsed, ext);
    }

    #[test]
    fn test_explicit_tagged_value() {
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 2, val: 16 }.to_der().unwrap()),
            "a203020110"
        );
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 2, val: () }.to_der().unwrap()),
            "a2020500"
        );
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 503, val: 16 }.to_der().unwrap()),
            "bf837703020110"
        );
    }

    #[test]
    fn test_authorization_list_tags_ordered_by_raw_value() {
        assert!(AUTHORIZATION_LIST_TAGS
            .iter()
            .map(|tag| raw_tag_value(*tag))
            .is_sorted());
    }

    #[test]
    fn test_authorization_list_tags_are_unique() {
        let mut deduped = AUTHORIZATION_LIST_TAGS.to_vec();
        deduped.dedup();
        assert_eq!(AUTHORIZATION_LIST_TAGS.len(), deduped.len())
    }

    #[test]
    fn test_authorization_list_encode_decode() {
        let additional_attestation_info = [KeyParam::ModuleHash(vec![0xaa; 32])];
        let authorization_list = AuthorizationList::new(
            &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &additional_attestation_info,
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        let want: &str = concat!(
            "307b", // SEQUENCE len 123
            "a203", // EXPLICIT [2]
            "0201", // INTEGER len 1
            "03",   // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "bf8554",
            "22",   // EXPLICIT [724] len 34
            "0420", // OCTET STRING len 32
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        // encode
        assert_eq!(hex::encode(&got), want);
        // decode from encoded
        let mut parsed = AuthorizationList::from_der(got.as_slice()).unwrap();
        parsed.encode_sid = false;
        assert_eq!(parsed, authorization_list);
    }

    #[test]
    fn test_authorization_list_user_secure_id_encode() {
        // Create an authorization list that includes multiple values for SecureUserId.
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Algorithm(keymint::Algorithm::Ec),
                KeyParam::UserSecureId(42),
                KeyParam::UserSecureId(43),
                KeyParam::UserSecureId(44),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        // The `SecureUserId` values are *not* included in the generated output.
        let want: &str = concat!(
            "3055", // SEQUENCE len 55
            "a203", // EXPLICIT [2]
            "0201", // INTEGER len 1
            "03",   // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        // encode
        assert_eq!(hex::encode(got), want);
    }

    #[test]
    fn test_authorization_list_user_secure_id_decode() {
        // Create a DER-encoded `AuthorizationList` that includes a `UserSecureId` value.
        let input = hex::decode(concat!(
            "305c",   // SEQUENCE
            "a203",   // EXPLICIT [2] len 3
            "0201",   // INTEGER len 1
            "03",     // 3 (Algorithm::Ec)
            "bf8376", // EXPLICIT [502]
            "03",     // len 3
            "0201",   // INTEGER len 1
            "02",     // 2
            "bf8540", // EXPLICIT [704]
            "4c",     // len 0x4c
            "304a",   // SEQUENCE len x4a
            "0420",   // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ))
        .unwrap();
        let mut got = AuthorizationList::from_der(&input).unwrap();
        got.encode_sid = false;

        let want = AuthorizationList::new(
            &[
                KeyParam::Algorithm(keymint::Algorithm::Ec),
                KeyParam::UserSecureId(2),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();

        assert_eq!(got, want);
    }

    #[test]
    fn test_authz_list_resets_mismatched_attestation_id() {
        let attestation_ids = AttestationIdInfo {
            brand: b"good".to_vec(),
            device: vec![],
            product: vec![],
            serial: vec![],
            imei: vec![],
            imei2: vec![],
            meid: vec![],
            manufacturer: vec![],
            model: vec![],
        };
        let keygen_params = [KeyParam::AttestationIdBrand(b"bad".to_vec())];
        let authz_list =
            AuthorizationList::new(&[], &keygen_params, Some(&attestation_ids), None, None, &[])
                .unwrap();

        assert_eq!(authz_list.ids.brand.as_deref(), Some(b"good".as_slice()));
        assert_eq!(
            hex::encode(authz_list.to_der().unwrap()),
            "300abf8546060404676f6f64"
        );
    }

    #[test]
    fn test_authz_list_omits_empty_second_imei() {
        let attestation_ids = AttestationIdInfo {
            brand: vec![],
            device: vec![],
            product: vec![],
            serial: vec![],
            imei: vec![],
            imei2: vec![],
            meid: vec![],
            manufacturer: vec![],
            model: vec![],
        };
        let keygen_params = [KeyParam::AttestationIdSecondImei(vec![])];
        let authz_list =
            AuthorizationList::new(&[], &keygen_params, Some(&attestation_ids), None, None, &[])
                .unwrap();

        assert!(authz_list.ids.imei2.is_none());
        assert_eq!(hex::encode(authz_list.to_der().unwrap()), "3000");
    }

    #[test]
    fn test_authorization_list_dup_encode() {
        use kmr_wire::keymint::Digest;
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Digest(Digest::None),
                KeyParam::Digest(Digest::Sha1),
                KeyParam::Digest(Digest::Sha1), // duplicate value
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        assert!(AuthorizationList::from_der(got.as_slice()).is_ok());
    }

    #[test]
    fn test_authorization_list_order_fail() {
        use kmr_wire::keymint::Digest;
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Digest(Digest::Sha1),
                KeyParam::Digest(Digest::None),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        assert!(authorization_list.to_der().is_err());
    }

    #[test]
    fn test_decode_tag_from_bytes() {
        use der::Reader;
        let tests = [
            (
                "a2", // context-specific constructed tag=2
                Ok(Some(Tag::Algorithm)),
            ),
            (
                "be", // context-specific constructed tag=30 (not a KeyMint tag value)
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf1f", // context-specific constructed tag=31 (not a KeyMint tag value)
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf8377", // context-specific constructed tag=503=0x1F7
                Ok(Some(Tag::NoAuthRequired)),
            ),
            (
                "9f8377", // context-specific *primitive* tag=503=0x1F7
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "7f8377", // *application* constructed tag=503=0x1F7
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bfc000", // context-specific constructed tag=16384=0x4000
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf8148", // context-specific constructed tag=200=0xC8
                Ok(Some(Tag::RsaPublicExponent)),
            ),
            (
                "68", // application constructed tag=16
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
        ];
        for (input_hex, want) in tests {
            let input = hex::decode(input_hex).unwrap();
            let mut reader = der::SliceReader::new(&input).unwrap();
            let got = decode_tag_from_bytes(&mut reader);
            assert_eq!(got, want, "for {input_hex}");
            if got.is_ok() {
                assert_eq!(reader.remaining_len(), der::Length::ZERO, "for {input_hex}");
            }
        }
    }
}
