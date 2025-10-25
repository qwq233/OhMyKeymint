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

//! Helper functionality for working with tags.

use crate::{
    crypto,
    crypto::{rsa::DecryptionMode, *},
    km_err, try_to_vec, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{
        Algorithm, BlockMode, Digest, EcCurve, ErrorCode, KeyCharacteristics, KeyFormat, KeyParam,
        KeyPurpose, PaddingMode, SecurityLevel, Tag, DEFAULT_CERT_SERIAL, DEFAULT_CERT_SUBJECT,
    },
    KeySizeInBits,
};
use log::{info, warn};

mod info;
pub use info::*;
pub mod legacy;
#[cfg(test)]
mod tests;

/// The set of tags that are directly copied from key generation/import parameters to
/// key characteristics without being checked.
pub const UNPOLICED_COPYABLE_TAGS: &[Tag] = &[
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::MaxUsesPerBoot,
    Tag::UserSecureId, // repeatable
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::StorageKey,
];

/// Indication of whether secure storage is available.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SecureStorage {
    /// Device has secure storage.
    Available,
    /// Device does not have secure storage.
    Unavailable,
}

/// Macro to retrieve a copy of the (single) value of a tag in a collection of `KeyParam`s.  There
/// can be only one.  Only works for variants whose data type implements `Copy`.
#[macro_export]
macro_rules! get_tag_value {
    { $params:expr, $variant:ident, $err:expr } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(*v);
                }
            }
            match count {
                0 => Err($crate::km_verr!($err, "missing tag {}", stringify!($variant))),
                1 => Ok(result.unwrap()),  /* safe: count=1 => exists */
                _ => Err($crate::km_verr!($err, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to retrieve the value of an optional single-valued tag in a collection of `KeyParam`s.  It
/// may or may not be present, but multiple instances of the tag are assumed to be invalid.
#[macro_export]
macro_rules! get_opt_tag_value {
    { $params:expr, $variant:ident } => {
        get_opt_tag_value!($params, $variant, InvalidTag)
    };
    { $params:expr, $variant:ident, $dup_error:ident } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v);
                }
            }
            match count {
                0 => Ok(None),
                1 => Ok(Some(result.unwrap())),  /* safe: count=1 => exists */
                _ => Err($crate::km_err!($dup_error, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

#[macro_export]
macro_rules! modify_tag_value {
    { $params:expr, $variant:ident, $new_value:expr } => {
        modify_tag_value!($params, $variant, $new_value, InvalidTag)
    };
    { $params:expr, $variant:ident, $new_value:expr, $dup_error:ident  } => {
        {
            let mut found = false;
            for param in $params.iter_mut() {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    if (found) {
                        return Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant)));
                    }
                    *v = $new_value;
                    found = true;
                }
            }
            if found {
                Ok(())
            } else {
                Err($crate::km_err!(InvalidTag, "missing tag {}", stringify!($variant)))
            }
        }
    };
}

/// Macro to retrieve a `bool` tag value, returning `false` if the tag is absent
#[macro_export]
macro_rules! get_bool_tag_value {
    { $params:expr, $variant:ident } => {
        {
            let mut count = 0;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant = param {
                    count += 1;
                }
            }
            match count {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to check a collection of `KeyParam`s holds a value matching the given value.
#[macro_export]
macro_rules! contains_tag_value {
    { $params:expr, $variant:ident, $value:expr } => {
        {
            let mut found = false;
            for param in $params {
                if let kmr_wire::keymint::KeyParam::$variant(v) = param {
                    if *v == $value {
                        found = true;
                    }
                }
            }
            found
        }
    }
}

/// Check that a set of [`KeyParam`]s is valid when considered as key characteristics.
pub fn characteristics_valid(characteristics: &[KeyParam]) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in characteristics {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if info(tag)?.characteristic == Characteristic::NotKeyCharacteristic {
            return Err(km_err!(
                InvalidKeyBlob,
                "tag {:?} is not a valid key characteristic",
                tag,
            ));
        }
    }
    Ok(())
}

/// Copy anything in `src` that matches `tags` into `dest`.  Fails if any non-repeatable
/// tags occur more than once with a different value.
pub fn transcribe_tags(
    dest: &mut Vec<KeyParam>,
    src: &[KeyParam],
    tags: &[Tag],
) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in src {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if tags.iter().any(|t| *t == tag) {
            dest.try_push(param.clone())?;
        }
    }
    Ok(())
}

/// Get the configured algorithm from a set of parameters.
pub fn get_algorithm(params: &[KeyParam]) -> Result<Algorithm, Error> {
    get_tag_value!(params, Algorithm, ErrorCode::UnsupportedAlgorithm)
}

/// Get the configured block mode from a set of parameters.
pub fn get_block_mode(params: &[KeyParam]) -> Result<BlockMode, Error> {
    get_tag_value!(params, BlockMode, ErrorCode::UnsupportedBlockMode)
}

/// Get the configured padding mode from a set of parameters.
pub fn get_padding_mode(params: &[KeyParam]) -> Result<PaddingMode, Error> {
    get_tag_value!(params, Padding, ErrorCode::UnsupportedPaddingMode)
}

/// Get the configured digest from a set of parameters.
pub fn get_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)
}

/// Get the configured elliptic curve from a set of parameters.
pub fn get_ec_curve(params: &[KeyParam]) -> Result<EcCurve, Error> {
    get_tag_value!(params, EcCurve, ErrorCode::UnsupportedKeySize)
}

/// Get the configured MGF digest from a set of parameters.  If no MGF digest is specified,
/// a default value of SHA1 is returned.
pub fn get_mgf_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    Ok(*get_opt_tag_value!(params, RsaOaepMgfDigest)?.unwrap_or(&Digest::Sha1))
}

/// Get the certificate serial number from a set of parameters, falling back to default value of 1
/// if not specified
pub fn get_cert_serial(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSerial)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SERIAL))
}

/// Return the set of key parameters at the provided security level.
pub fn characteristics_at(
    chars: &[KeyCharacteristics],
    sec_level: SecurityLevel,
) -> Result<&[KeyParam], Error> {
    let mut result: Option<&[KeyParam]> = None;
    for chars in chars {
        if chars.security_level != sec_level {
            continue;
        }
        if result.is_none() {
            result = Some(&chars.authorizations);
        } else {
            return Err(km_err!(
                InvalidKeyBlob,
                "multiple key characteristics at {:?}",
                sec_level
            ));
        }
    }
    result.ok_or_else(|| {
        km_err!(
            InvalidKeyBlob,
            "no parameters at security level {:?} found",
            sec_level
        )
    })
}

/// Get the certificate subject from a set of parameters, falling back to a default if not
/// specified.
pub fn get_cert_subject(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSubject)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SUBJECT))
}

/// Build the parameters that are used as the hidden input to KEK derivation calculations:
/// - `ApplicationId(data)` if present
/// - `ApplicationData(data)` if present
/// - `RootOfTrust(rot)` where `rot` is a hardcoded root of trust
pub fn hidden(params: &[KeyParam], rot: &[u8]) -> Result<Vec<KeyParam>, Error> {
    let mut results = vec_try_with_capacity!(3)?;
    if let Ok(Some(app_id)) = get_opt_tag_value!(params, ApplicationId) {
        results.push(KeyParam::ApplicationId(try_to_vec(app_id)?));
    }
    if let Ok(Some(app_data)) = get_opt_tag_value!(params, ApplicationData) {
        results.push(KeyParam::ApplicationData(try_to_vec(app_data)?));
    }
    results.push(KeyParam::RootOfTrust(try_to_vec(rot)?));
    Ok(results)
}

/// Build the set of key characteristics for a key that is about to be generated,
/// checking parameter validity along the way. Also return the information needed for key
/// generation.
pub fn extract_key_gen_characteristics(
    secure_storage: SecureStorage,
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyCharacteristics>, KeyGenInfo), Error> {
    let keygen_info = match get_algorithm(params)? {
        Algorithm::Rsa => check_rsa_gen_params(params, sec_level),
        Algorithm::Ec => check_ec_gen_params(params, sec_level),
        Algorithm::Aes => check_aes_gen_params(params, sec_level),
        Algorithm::TripleDes => check_3des_gen_params(params),
        Algorithm::Hmac => check_hmac_gen_params(params, sec_level),
    }?;
    Ok((
        extract_key_characteristics(secure_storage, params, &[], sec_level)?,
        keygen_info,
    ))
}

/// Build the set of key characteristics for a key that is about to be imported,
/// checking parameter validity along the way.
pub fn extract_key_import_characteristics(
    imp: &crypto::Implementation,
    secure_storage: SecureStorage,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyCharacteristics>, KeyMaterial), Error> {
    let (deduced_params, key_material) = match get_algorithm(params)? {
        Algorithm::Rsa => {
            check_rsa_import_params(&*imp.rsa, params, sec_level, key_format, key_data)
        }
        Algorithm::Ec => check_ec_import_params(&*imp.ec, params, sec_level, key_format, key_data),
        Algorithm::Aes => {
            check_aes_import_params(&*imp.aes, params, sec_level, key_format, key_data)
        }
        Algorithm::TripleDes => check_3des_import_params(&*imp.des, params, key_format, key_data),
        Algorithm::Hmac => {
            check_hmac_import_params(&*imp.hmac, params, sec_level, key_format, key_data)
        }
    }?;
    Ok((
        extract_key_characteristics(secure_storage, params, &deduced_params, sec_level)?,
        key_material,
    ))
}

/// Build the set of key characteristics for a key that is about to be generated or imported,
/// checking parameter validity along the way. The `extra_params` argument provides additional
/// parameters on top of `params`, such as those deduced from imported key material.
fn extract_key_characteristics(
    secure_storage: SecureStorage,
    params: &[KeyParam],
    extra_params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<Vec<KeyCharacteristics>, Error> {
    // Separately accumulate any characteristics that are policed by Keystore.
    let mut chars = Vec::new();
    let mut keystore_chars = Vec::new();
    for param in params.iter().chain(extra_params) {
        let tag = param.tag();

        // Input params should not contain anything that KeyMint adds itself.
        if AUTO_ADDED_CHARACTERISTICS.contains(&tag) {
            return Err(km_err!(
                InvalidTag,
                "KeyMint-added tag included on key generation/import"
            ));
        }

        if sec_level == SecurityLevel::Strongbox
            && [Tag::MaxUsesPerBoot, Tag::RollbackResistance].contains(&tag)
        {
            // StrongBox does not support tags that require per-key storage.
            return Err(km_err!(
                InvalidTag,
                "tag {:?} not allowed in StrongBox",
                param.tag()
            ));
        }

        // UsageCountLimit is peculiar. If its value is > 1, it should be Keystore-enforced.
        // If its value is = 1, then it is KeyMint-enforced if secure storage is available,
        // and Keystore-enforced otherwise.
        if let KeyParam::UsageCountLimit(use_limit) = param {
            match (use_limit, secure_storage) {
                (1, SecureStorage::Available) => {
                    chars.try_push(KeyParam::UsageCountLimit(*use_limit))?
                }
                (1, SecureStorage::Unavailable) | (_, _) => {
                    keystore_chars.try_push(KeyParam::UsageCountLimit(*use_limit))?
                }
            }
        }

        if KEYMINT_ENFORCED_CHARACTERISTICS.contains(&tag) {
            chars.try_push(param.clone())?;
        } else if KEYSTORE_ENFORCED_CHARACTERISTICS.contains(&tag) {
            keystore_chars.try_push(param.clone())?;
        }
    }

    reject_incompatible_auth(&chars)?;

    // Use the same sort order for tags as was previously used.
    chars.sort_by(legacy::param_compare);
    keystore_chars.sort_by(legacy::param_compare);

    let mut result = Vec::new();
    result.try_push(KeyCharacteristics {
        security_level: sec_level,
        authorizations: chars,
    })?;
    if !keystore_chars.is_empty() {
        result.try_push(KeyCharacteristics {
            security_level: SecurityLevel::Keystore,
            authorizations: keystore_chars,
        })?;
    }
    Ok(result)
}

/// Check that an RSA key size is valid.
fn check_rsa_key_size(key_size: KeySizeInBits, sec_level: SecurityLevel) -> Result<(), Error> {
    // StrongBox only supports 2048-bit keys.
    match key_size {
        KeySizeInBits(512) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(768) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(1024) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(2048) => Ok(()),
        KeySizeInBits(3072) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(4096) if sec_level != SecurityLevel::Strongbox => Ok(()),
        _ => Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE {:?} bits for RSA",
            key_size
        )),
    }
}

/// Check RSA key generation parameter validity.
fn check_rsa_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    // For key generation, size and public exponent must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    check_rsa_key_size(key_size, sec_level)?;
    let public_exponent = get_tag_value!(params, RsaPublicExponent, ErrorCode::InvalidArgument)?;

    check_rsa_params(params)?;
    Ok(KeyGenInfo::Rsa(key_size, public_exponent))
}

/// Check RSA key import parameter validity. Return the key material along with any key generation
/// parameters that have been deduced from the key material (but which are not present in the input
/// key parameters).
fn check_rsa_import_params(
    rsa: &dyn Rsa,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    // Deduce key size and exponent from import data.
    if key_format != KeyFormat::Pkcs8 {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect PKCS8",
            key_format
        ));
    }
    let (key, key_size, public_exponent) = rsa.import_pkcs8_key(key_data, params)?;

    // If key size or exponent are explicitly specified, they must match. If they were not
    // specified, we emit them.
    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?} for PKCS8 import",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }
    match get_opt_tag_value!(params, RsaPublicExponent)? {
        Some(param_public_exponent) => {
            if *param_public_exponent != public_exponent {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified RSA_PUBLIC_EXPONENT {:?} != actual exponent {:?} for PKCS8 import",
                    param_public_exponent,
                    public_exponent,
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::RsaPublicExponent(public_exponent))?,
    }
    check_rsa_key_size(key_size, sec_level)?;

    check_rsa_params(params)?;
    Ok((deduced_chars, key))
}

/// Check the parameter validity for an RSA key that is about to be generated or imported.
fn check_rsa_params(params: &[KeyParam]) -> Result<(), Error> {
    let mut seen_attest = false;
    let mut seen_non_attest = false;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign | KeyPurpose::Decrypt | KeyPurpose::WrapKey => {
                    seen_non_attest = true
                }
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify | KeyPurpose::Encrypt => {} // public key operations
                KeyPurpose::AgreeKey => {
                    warn!("Generating RSA key with invalid purpose {:?}", purpose)
                }
            }
        }
    }
    if seen_attest && seen_non_attest {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }
    Ok(())
}

/// Check EC key generation parameter validity.
fn check_ec_gen_params(params: &[KeyParam], sec_level: SecurityLevel) -> Result<KeyGenInfo, Error> {
    // For key generation, the curve must be explicitly specified.
    let ec_curve = get_ec_curve(params)?;

    let purpose = check_ec_params(ec_curve, params, sec_level)?;
    let keygen_info = match (ec_curve, purpose) {
        (EcCurve::Curve25519, Some(KeyPurpose::Sign)) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, Some(KeyPurpose::AttestKey)) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, Some(KeyPurpose::AgreeKey)) => KeyGenInfo::X25519,
        (EcCurve::Curve25519, _) => {
            return Err(km_err!(
                IncompatiblePurpose,
                "curve25519 keys with invalid purpose {:?}",
                purpose
            ))
        }
        (EcCurve::P224, _) => KeyGenInfo::NistEc(ec::NistCurve::P224),
        (EcCurve::P256, _) => KeyGenInfo::NistEc(ec::NistCurve::P256),
        (EcCurve::P384, _) => KeyGenInfo::NistEc(ec::NistCurve::P384),
        (EcCurve::P521, _) => KeyGenInfo::NistEc(ec::NistCurve::P521),
    };
    Ok(keygen_info)
}

/// Find the first purpose value in the parameters.
pub fn primary_purpose(params: &[KeyParam]) -> Result<KeyPurpose, Error> {
    params
        .iter()
        .find_map(|param| {
            if let KeyParam::Purpose(purpose) = param {
                Some(*purpose)
            } else {
                None
            }
        })
        .ok_or_else(|| km_err!(IncompatiblePurpose, "no purpose found for key!"))
}

/// Check EC key import parameter validity. Return the key material along with any key generation
/// parameters that have been deduced from the key material (but which are not present in the input
/// key parameters).
fn check_ec_import_params(
    ec: &dyn Ec,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    // Curve25519 can be imported as PKCS8 or raw; all other curves must be PKCS8.
    // If we need to disinguish between Ed25519 and X25519, we need to examine the purpose for the
    // key -- look for `AgreeKey` as it cannot be combined with other purposes.
    let (key, curve) = match key_format {
        KeyFormat::Raw if get_ec_curve(params)? == EcCurve::Curve25519 => {
            // Raw key import must specify the curve (and the only valid option is Curve25519
            // currently).
            if primary_purpose(params)? == KeyPurpose::AgreeKey {
                (
                    ec.import_raw_x25519_key(key_data, params)?,
                    EcCurve::Curve25519,
                )
            } else {
                (
                    ec.import_raw_ed25519_key(key_data, params)?,
                    EcCurve::Curve25519,
                )
            }
        }
        KeyFormat::Pkcs8 => {
            let key = ec.import_pkcs8_key(key_data, params)?;
            let curve = match &key {
                KeyMaterial::Ec(curve, CurveType::Nist, _) => *curve,
                KeyMaterial::Ec(EcCurve::Curve25519, CurveType::EdDsa, _) => {
                    if primary_purpose(params)? == KeyPurpose::AgreeKey {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "can't use EdDSA key for key agreement"
                        ));
                    }
                    EcCurve::Curve25519
                }
                KeyMaterial::Ec(EcCurve::Curve25519, CurveType::Xdh, _) => {
                    if primary_purpose(params)? != KeyPurpose::AgreeKey {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "can't use XDH key for signing"
                        ));
                    }
                    EcCurve::Curve25519
                }
                _ => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "unexpected key type from EC import"
                    ))
                }
            };
            (key, curve)
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeyFormat,
                "invalid import format ({:?}) for EC key",
                key_format,
            ));
        }
    };

    // If curve was explicitly specified, it must match. If not specified, populate it in the
    // deduced characteristics.
    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, EcCurve)? {
        Some(specified_curve) => {
            if *specified_curve != curve {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "imported EC key claimed curve {:?} but is {:?}",
                    specified_curve,
                    curve
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::EcCurve(curve))?,
    }

    // If key size was explicitly specified, it must match. If not specified, populate it in the
    // deduced characteristics.
    let key_size = ec::curve_to_key_size(curve);
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?} for PKCS8 import",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }

    check_ec_params(curve, params, sec_level)?;
    Ok((deduced_chars, key))
}

/// Check the parameter validity for an EC key that is about to be generated or imported.
fn check_ec_params(
    curve: EcCurve,
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<Option<KeyPurpose>, Error> {
    if sec_level == SecurityLevel::Strongbox && curve != EcCurve::P256 {
        return Err(km_err!(
            UnsupportedEcCurve,
            "invalid curve ({:?}) for StrongBox",
            curve
        ));
    }

    // Key size is not needed, but if present should match the curve.
    if let Some(key_size) = get_opt_tag_value!(params, KeySize)? {
        match curve {
            EcCurve::P224 if *key_size == KeySizeInBits(224) => {}
            EcCurve::P256 if *key_size == KeySizeInBits(256) => {}
            EcCurve::P384 if *key_size == KeySizeInBits(384) => {}
            EcCurve::P521 if *key_size == KeySizeInBits(521) => {}
            EcCurve::Curve25519 if *key_size == KeySizeInBits(256) => {}
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "invalid curve ({:?}) / key size ({:?}) combination",
                    curve,
                    key_size
                ))
            }
        }
    }

    let mut seen_attest = false;
    let mut seen_sign = false;
    let mut seen_agree = false;
    let mut primary_purpose = None;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign => seen_sign = true,
                KeyPurpose::AgreeKey => seen_agree = true,
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify => {}
                _ => warn!("Generating EC key with invalid purpose {:?}", purpose),
            }
            if primary_purpose.is_none() {
                primary_purpose = Some(*purpose);
            }
        }
    }
    // Keys with Purpose::ATTEST_KEY must have no other purpose.
    if seen_attest && (seen_sign || seen_agree) {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }
    // Curve25519 keys must be either signing/attesting keys (Ed25519), or key agreement
    // keys (X25519), not both.
    if curve == EcCurve::Curve25519 && seen_agree && (seen_sign || seen_attest) {
        return Err(km_err!(
            IncompatiblePurpose,
            "curve25519 keys must be either SIGN/ATTEST_KEY or AGREE_KEY, not both"
        ));
    }

    Ok(primary_purpose)
}

/// Check AES key generation parameter validity.
fn check_aes_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    // For key generation, the size must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;

    let keygen_info = match key_size {
        KeySizeInBits(128) => KeyGenInfo::Aes(aes::Variant::Aes128),
        KeySizeInBits(256) => KeyGenInfo::Aes(aes::Variant::Aes256),
        KeySizeInBits(192) if sec_level != SecurityLevel::Strongbox => {
            KeyGenInfo::Aes(aes::Variant::Aes192)
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeySize,
                "unsupported KEY_SIZE {:?} bits for AES",
                key_size
            ))
        }
    };

    check_aes_params(params)?;
    Ok(keygen_info)
}

/// Check AES key import parameter validity. Return the key material along with any key generation
/// parameters that have been deduced from the key material (but which are not present in the input
/// key parameters).
fn check_aes_import_params(
    aes: &dyn Aes,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = aes.import_key(key_data, params)?;
    if key_size == KeySizeInBits(192) && sec_level == SecurityLevel::Strongbox {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE=192 bits for AES on StrongBox",
        ));
    }
    let deduced_chars = require_matching_key_size(params, key_size)?;

    check_aes_params(params)?;
    Ok((deduced_chars, key))
}

/// Check the parameter validity for an AES key that is about to be generated or imported.
fn check_aes_params(params: &[KeyParam]) -> Result<(), Error> {
    let gcm_support = params
        .iter()
        .any(|p| *p == KeyParam::BlockMode(BlockMode::Gcm));
    if gcm_support {
        let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if (min_mac_len % 8 != 0) || !(96..=128).contains(&min_mac_len) {
            return Err(km_err!(
                UnsupportedMinMacLength,
                "unsupported MIN_MAC_LENGTH {} bits",
                min_mac_len
            ));
        }
    }
    Ok(())
}

/// Check triple DES key generation parameter validity.
fn check_3des_gen_params(params: &[KeyParam]) -> Result<KeyGenInfo, Error> {
    // For key generation, the size (168) must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    if key_size != KeySizeInBits(168) {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE {:?} bits for TRIPLE_DES",
            key_size
        ));
    }
    Ok(KeyGenInfo::TripleDes)
}

/// Check triple DES key import parameter validity. Return the key material along with any key
/// generation parameters that have been deduced from the key material (but which are not present in
/// the input key parameters).
fn check_3des_import_params(
    des: &dyn Des,
    params: &[KeyParam],
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let key = des.import_key(key_data, params)?;
    // If the key size is specified as a parameter, it must be 168. Note that this
    // is not equal to 8 x 24 (the data size).
    let deduced_chars = require_matching_key_size(params, des::KEY_SIZE_BITS)?;

    Ok((deduced_chars, key))
}

/// Check HMAC key generation parameter validity.
fn check_hmac_gen_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<KeyGenInfo, Error> {
    // For key generation the size must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    check_hmac_params(params, sec_level, key_size)?;
    Ok(KeyGenInfo::Hmac(key_size))
}

/// Build the set of key characteristics for an HMAC key that is about to be imported,
/// checking parameter validity along the way.
fn check_hmac_import_params(
    hmac: &dyn Hmac,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, KeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = hmac.import_key(key_data, params)?;
    let deduced_chars = require_matching_key_size(params, key_size)?;

    check_hmac_params(params, sec_level, key_size)?;
    Ok((deduced_chars, key))
}

/// Check the parameter validity for an HMAC key that is about to be generated or imported.
fn check_hmac_params(
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_size: KeySizeInBits,
) -> Result<(), Error> {
    if sec_level == SecurityLevel::Strongbox {
        hmac::valid_strongbox_hal_size(key_size)?;
    } else {
        hmac::valid_hal_size(key_size)?;
    }
    let digest = get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)?;
    if digest == Digest::None {
        return Err(km_err!(
            UnsupportedDigest,
            "unsupported digest {:?}",
            digest
        ));
    }

    let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
    if (min_mac_len % 8 != 0) || !(64..=512).contains(&min_mac_len) {
        return Err(km_err!(
            UnsupportedMinMacLength,
            "unsupported MIN_MAC_LENGTH {:?} bits",
            min_mac_len
        ));
    }
    Ok(())
}

/// Check for `KeyFormat::RAW`.
fn require_raw(key_format: KeyFormat) -> Result<(), Error> {
    if key_format != KeyFormat::Raw {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect RAW",
            key_format
        ));
    }
    Ok(())
}

/// Check or populate a `Tag::KEY_SIZE` value.
fn require_matching_key_size(
    params: &[KeyParam],
    key_size: KeySizeInBits,
) -> Result<Vec<KeyParam>, Error> {
    let mut deduced_chars = Vec::new();
    match get_opt_tag_value!(params, KeySize)? {
        Some(param_key_size) => {
            if *param_key_size != key_size {
                return Err(km_err!(
                    ImportParameterMismatch,
                    "specified KEY_SIZE {:?} bits != actual key size {:?}",
                    param_key_size,
                    key_size
                ));
            }
        }
        None => deduced_chars.try_push(KeyParam::KeySize(key_size))?,
    }
    Ok(deduced_chars)
}

/// Return an error if any of the `exclude` tags are found in `params`.
fn reject_tags(params: &[KeyParam], exclude: &[Tag]) -> Result<(), Error> {
    for param in params {
        if exclude.contains(&param.tag()) {
            return Err(km_err!(InvalidTag, "tag {:?} not allowed", param.tag()));
        }
    }
    Ok(())
}

/// Return an error if non-None padding found.
fn reject_some_padding(params: &[KeyParam]) -> Result<(), Error> {
    if let Some(padding) = get_opt_tag_value!(params, Padding)? {
        if *padding != PaddingMode::None {
            return Err(km_err!(InvalidTag, "padding {:?} not allowed", padding));
        }
    }
    Ok(())
}

/// Return an error if non-None digest found.
fn reject_some_digest(params: &[KeyParam]) -> Result<(), Error> {
    if let Some(digest) = get_opt_tag_value!(params, Digest)? {
        if *digest != Digest::None {
            return Err(km_err!(InvalidTag, "digest {:?} not allowed", digest));
        }
    }
    Ok(())
}

/// Reject incompatible combinations of authentication tags.
fn reject_incompatible_auth(params: &[KeyParam]) -> Result<(), Error> {
    let mut seen_user_secure_id = false;
    let mut seen_auth_type = false;
    let mut seen_no_auth = false;

    for param in params {
        match param {
            KeyParam::UserSecureId(_sid) => seen_user_secure_id = true,
            KeyParam::UserAuthType(_atype) => seen_auth_type = true,
            KeyParam::NoAuthRequired => seen_no_auth = true,
            _ => {}
        }
    }

    if seen_no_auth {
        if seen_user_secure_id {
            return Err(km_err!(
                InvalidTag,
                "found both NO_AUTH_REQUIRED and USER_SECURE_ID"
            ));
        }
        if seen_auth_type {
            return Err(km_err!(
                InvalidTag,
                "found both NO_AUTH_REQUIRED and USER_AUTH_TYPE"
            ));
        }
    }
    if seen_user_secure_id && !seen_auth_type {
        return Err(km_err!(
            InvalidTag,
            "found USER_SECURE_ID but no USER_AUTH_TYPE"
        ));
    }
    Ok(())
}

/// Indication of which parameters on a `begin` need to be checked against key authorizations.
struct BeginParamsToCheck {
    block_mode: bool,
    padding: bool,
    digest: bool,
    mgf_digest: bool,
}

/// Check that an operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
pub fn check_begin_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    // General checks for all algorithms.
    let algo = get_algorithm(chars)?;
    let valid_purpose = matches!(
        (algo, purpose),
        (Algorithm::Aes, KeyPurpose::Encrypt)
            | (Algorithm::Aes, KeyPurpose::Decrypt)
            | (Algorithm::TripleDes, KeyPurpose::Encrypt)
            | (Algorithm::TripleDes, KeyPurpose::Decrypt)
            | (Algorithm::Hmac, KeyPurpose::Sign)
            | (Algorithm::Hmac, KeyPurpose::Verify)
            | (Algorithm::Ec, KeyPurpose::Sign)
            | (Algorithm::Ec, KeyPurpose::AttestKey)
            | (Algorithm::Ec, KeyPurpose::AgreeKey)
            | (Algorithm::Rsa, KeyPurpose::Sign)
            | (Algorithm::Rsa, KeyPurpose::Decrypt)
            | (Algorithm::Rsa, KeyPurpose::AttestKey)
    );
    if !valid_purpose {
        return Err(km_err!(
            UnsupportedPurpose,
            "invalid purpose {:?} for {:?} key",
            purpose,
            algo
        ));
    }
    if !contains_tag_value!(chars, Purpose, purpose) {
        return Err(km_err!(
            IncompatiblePurpose,
            "purpose {:?} not in key characteristics",
            purpose
        ));
    }
    if get_bool_tag_value!(chars, StorageKey)? {
        return Err(km_err!(StorageKeyUnsupported, "attempt to use storage key",));
    }
    let nonce = get_opt_tag_value!(params, Nonce)?;
    if get_bool_tag_value!(chars, CallerNonce)? {
        // Caller-provided nonces are allowed.
    } else if nonce.is_some() && purpose == KeyPurpose::Encrypt {
        return Err(km_err!(
            CallerNonceProhibited,
            "caller nonce not allowed for encryption"
        ));
    }

    // Further algorithm-specific checks.
    let check = match algo {
        Algorithm::Rsa => check_begin_rsa_params(chars, purpose, params),
        Algorithm::Ec => check_begin_ec_params(chars, purpose, params),
        Algorithm::Aes => check_begin_aes_params(chars, params, nonce.map(|v| v.as_ref())),
        Algorithm::TripleDes => check_begin_3des_params(params, nonce.map(|v| v.as_ref())),
        Algorithm::Hmac => check_begin_hmac_params(chars, purpose, params),
    }?;

    // For various parameters, if they are specified in the begin parameters and they
    // are relevant for the algorithm, then the same value must also exist in the key
    // characteristics. Also, there can be only one distinct value in the parameters.
    if check.block_mode {
        if let Some(bmode) = get_opt_tag_value!(params, BlockMode, UnsupportedBlockMode)? {
            if !contains_tag_value!(chars, BlockMode, *bmode) {
                return Err(km_err!(
                    IncompatibleBlockMode,
                    "block mode {:?} not in key characteristics {:?}",
                    bmode,
                    chars,
                ));
            }
        }
    }
    if check.padding {
        if let Some(pmode) = get_opt_tag_value!(params, Padding, UnsupportedPaddingMode)? {
            if !contains_tag_value!(chars, Padding, *pmode) {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding mode {:?} not in key characteristics {:?}",
                    pmode,
                    chars,
                ));
            }
        }
    }
    if check.digest {
        if let Some(digest) = get_opt_tag_value!(params, Digest, UnsupportedDigest)? {
            if !contains_tag_value!(chars, Digest, *digest) {
                return Err(km_err!(
                    IncompatibleDigest,
                    "digest {:?} not in key characteristics",
                    digest,
                ));
            }
        }
    }
    if check.mgf_digest {
        let mut mgf_digest_to_find =
            get_opt_tag_value!(params, RsaOaepMgfDigest, UnsupportedMgfDigest)?;

        let chars_have_mgf_digest = chars
            .iter()
            .any(|param| matches!(param, KeyParam::RsaOaepMgfDigest(_)));
        if chars_have_mgf_digest && mgf_digest_to_find.is_none() {
            // The key characteristics include an explicit set of MGF digests, but the begin()
            // operation is using the default SHA1.  Check that this default is in the
            // characteristics.
            mgf_digest_to_find = Some(&Digest::Sha1);
        }

        if let Some(mgf_digest) = mgf_digest_to_find {
            if !contains_tag_value!(chars, RsaOaepMgfDigest, *mgf_digest) {
                return Err(km_err!(
                    IncompatibleMgfDigest,
                    "MGF digest {:?} not in key characteristics",
                    mgf_digest,
                ));
            }
        }
    }
    Ok(())
}

/// Indicate whether a [`KeyPurpose`] is for encryption/decryption.
fn for_encryption(purpose: KeyPurpose) -> bool {
    purpose == KeyPurpose::Encrypt
        || purpose == KeyPurpose::Decrypt
        || purpose == KeyPurpose::WrapKey
}

/// Indicate whether a [`KeyPurpose`] is for signing.
fn for_signing(purpose: KeyPurpose) -> bool {
    purpose == KeyPurpose::Sign
}

/// Check that an RSA operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_rsa_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    let padding = get_padding_mode(params)?;
    let mut digest = None;
    if for_signing(purpose) || (for_encryption(purpose) && padding == PaddingMode::RsaOaep) {
        digest = Some(get_digest(params)?);
    }
    if for_signing(purpose) && padding == PaddingMode::None && digest != Some(Digest::None) {
        return Err(km_err!(
            IncompatibleDigest,
            "unpadded RSA sign requires Digest::None not {:?}",
            digest
        ));
    }
    match padding {
        PaddingMode::None => {}
        PaddingMode::RsaOaep if for_encryption(purpose) => {
            if digest.is_none() || digest == Some(Digest::None) {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-OAEP"));
            }
            let mgf_digest = get_mgf_digest(params)?;
            if mgf_digest == Digest::None {
                return Err(km_err!(
                    UnsupportedMgfDigest,
                    "MGF digest cannot be NONE for RSA-OAEP"
                ));
            }
        }
        PaddingMode::RsaPss if for_signing(purpose) => {
            if let Some(digest) = digest {
                let key_size_bits = get_tag_value!(chars, KeySize, ErrorCode::InvalidArgument)?;
                let d = digest_len(digest)?;
                if key_size_bits < KeySizeInBits(2 * d + 9) {
                    return Err(km_err!(
                        IncompatibleDigest,
                        "key size {:?} < 2*8*D={} + 9",
                        key_size_bits,
                        d
                    ));
                }
            } else {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-PSS"));
            }
        }
        PaddingMode::RsaPkcs115Encrypt if for_encryption(purpose) => {
            if digest.is_some() && digest != Some(Digest::None) {
                warn!(
                    "ignoring digest {:?} provided for PKCS#1 v1.5 encryption/decryption",
                    digest
                );
            }
        }
        PaddingMode::RsaPkcs115Sign if for_signing(purpose) => {
            if digest.is_none() {
                return Err(km_err!(
                    IncompatibleDigest,
                    "digest required for RSA-PKCS_1_5_SIGN"
                ));
            }
        }
        _ => {
            return Err(km_err!(
                UnsupportedPaddingMode,
                "purpose {:?} incompatible with padding {:?}",
                purpose,
                padding
            ))
        }
    }

    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: true,
        digest: true,
        mgf_digest: true,
    })
}

/// Check that an EC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_ec_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    let curve = get_ec_curve(chars)?;
    if purpose == KeyPurpose::Sign {
        let digest = get_digest(params)?;
        if digest == Digest::Md5 {
            return Err(km_err!(
                UnsupportedDigest,
                "Digest::MD5 unsupported for EC signing"
            ));
        }
        if curve == EcCurve::Curve25519 && digest != Digest::None {
            return Err(km_err!(
                UnsupportedDigest,
                "Ed25519 only supports Digest::None not {:?}",
                digest
            ));
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: false,
        digest: true,
        mgf_digest: false,
    })
}

/// Check that an AES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_aes_params(
    chars: &[KeyParam],
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::RsaOaepMgfDigest])?;
    reject_some_digest(params)?;
    let bmode = get_block_mode(params)?;
    let padding = get_padding_mode(params)?;

    if bmode == BlockMode::Gcm {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > 128 {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }
    match bmode {
        BlockMode::Gcm | BlockMode::Ctr => match padding {
            PaddingMode::None => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
        BlockMode::Ecb | BlockMode::Cbc => match padding {
            PaddingMode::None | PaddingMode::Pkcs7 => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
    }

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 16 => {}
            BlockMode::Ctr if nonce.len() == 16 => {}
            BlockMode::Gcm if nonce.len() == 12 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: true,
        padding: true,
        digest: false,
        mgf_digest: false,
    })
}

/// Check that a 3-DES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_3des_params(
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::RsaOaepMgfDigest])?;
    reject_some_digest(params)?;
    let bmode = get_block_mode(params)?;
    let _padding = get_padding_mode(params)?;

    match bmode {
        BlockMode::Cbc | BlockMode::Ecb => {}
        _ => {
            return Err(km_err!(
                UnsupportedBlockMode,
                "block mode {:?} not valid for 3-DES",
                bmode
            ))
        }
    }

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 8 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: true,
        padding: true,
        digest: false,
        mgf_digest: false,
    })
}

/// Check that an HMAC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_hmac_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::BlockMode, Tag::RsaOaepMgfDigest])?;
    reject_some_padding(params)?;
    let digest = get_digest(params)?;
    if purpose == KeyPurpose::Sign {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > digest_len(digest)? {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }

    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: false,
        digest: true,
        mgf_digest: false,
    })
}

/// Return the length in bits of a [`Digest`] function.
pub fn digest_len(digest: Digest) -> Result<u32, Error> {
    match digest {
        Digest::Md5 => Ok(128),
        Digest::Sha1 => Ok(160),
        Digest::Sha224 => Ok(224),
        Digest::Sha256 => Ok(256),
        Digest::Sha384 => Ok(384),
        Digest::Sha512 => Ok(512),
        _ => Err(km_err!(IncompatibleDigest, "invalid digest {:?}", digest)),
    }
}

/// Check the required key params for an RSA wrapping key used in secure import and return the
/// [`DecryptionMode`] constructed from the processed key characteristics.
pub fn check_rsa_wrapping_key_params(
    chars: &[KeyParam],
    params: &[KeyParam],
) -> Result<DecryptionMode, Error> {
    // Check the purpose of the wrapping key
    if !contains_tag_value!(chars, Purpose, KeyPurpose::WrapKey) {
        return Err(km_err!(
            IncompatiblePurpose,
            "no wrap key purpose for the wrapping key"
        ));
    }
    let padding_mode = get_tag_value!(params, Padding, ErrorCode::IncompatiblePaddingMode)?;
    if padding_mode != PaddingMode::RsaOaep {
        return Err(km_err!(
            IncompatiblePaddingMode,
            "invalid padding mode {:?} for RSA wrapping key",
            padding_mode
        ));
    }
    let msg_digest = get_tag_value!(params, Digest, ErrorCode::IncompatibleDigest)?;
    if msg_digest != Digest::Sha256 {
        return Err(km_err!(
            IncompatibleDigest,
            "invalid digest {:?} for RSA wrapping key",
            padding_mode
        ));
    }
    let opt_mgf_digest = get_opt_tag_value!(params, RsaOaepMgfDigest)?;
    if opt_mgf_digest == Some(&Digest::None) {
        return Err(km_err!(
            UnsupportedMgfDigest,
            "MGF digest cannot be NONE for RSA-OAEP"
        ));
    }

    if !contains_tag_value!(chars, Padding, padding_mode) {
        return Err(km_err!(
            IncompatiblePaddingMode,
            "padding mode {:?} not in key characteristics {:?}",
            padding_mode,
            chars,
        ));
    }
    if !contains_tag_value!(chars, Digest, msg_digest) {
        return Err(km_err!(
            IncompatibleDigest,
            "digest {:?} not in key characteristics {:?}",
            msg_digest,
            chars,
        ));
    }

    if let Some(mgf_digest) = opt_mgf_digest {
        // MGF digest explicitly specified, check it is in key characteristics.
        if !contains_tag_value!(chars, RsaOaepMgfDigest, *mgf_digest) {
            return Err(km_err!(
                IncompatibleDigest,
                "MGF digest {:?} not in key characteristics {:?}",
                mgf_digest,
                chars,
            ));
        }
    }
    let mgf_digest = opt_mgf_digest.unwrap_or(&Digest::Sha1);

    let rsa_oaep_decrypt_mode = DecryptionMode::OaepPadding {
        msg_digest,
        mgf_digest: *mgf_digest,
    };
    Ok(rsa_oaep_decrypt_mode)
}

/// Calculate the [Luhn checksum](https://en.wikipedia.org/wiki/Luhn_algorithm) of the given number.
fn luhn_checksum(mut val: u64) -> u64 {
    let mut ii = 0;
    let mut sum_digits = 0;
    while val != 0 {
        let curr_digit = val % 10;
        let multiplier = if ii % 2 == 0 { 2 } else { 1 };
        let digit_multiplied = curr_digit * multiplier;
        sum_digits += (digit_multiplied % 10) + (digit_multiplied / 10);
        val /= 10;
        ii += 1;
    }
    (10 - (sum_digits % 10)) % 10
}

/// Derive an IMEI value from a first IMEI value, by incrementing by one and re-calculating
/// the Luhn checksum.  Return an empty vector on any failure.
pub fn increment_imei(imei: &[u8]) -> Vec<u8> {
    if imei.is_empty() {
        info!("empty IMEI");
        return Vec::new();
    }

    // Expect ASCII digits.
    let imei: &str = match core::str::from_utf8(imei) {
        Ok(v) => v,
        Err(_) => {
            warn!("IMEI is not UTF-8");
            return Vec::new();
        }
    };
    let imei: u64 = match imei.parse() {
        Ok(v) => v,
        Err(_) => {
            warn!("IMEI is not numeric");
            return Vec::new();
        }
    };

    // Drop trailing checksum digit, increment, and restore checksum.
    let imei2 = (imei / 10) + 1;
    let imei2 = (imei2 * 10) + luhn_checksum(imei2);

    // Convert back to bytes.
    std::format!("{}", imei2).into_bytes()
}
