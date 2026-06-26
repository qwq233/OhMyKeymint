// Copyright 2020, The Android Open Source Project
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

//! This module implements utility functions used by the Keystore 2.0 service
//! implementation.

use crate::android::content::pm::IPackageManagerNative::{IPackageManagerNative, LOCATION_SYSTEM};
use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, Certificate::Certificate, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
    KeyCharacteristics::KeyCharacteristics, KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter as KmKeyParameter, KeyParameterValue::KeyParameterValue,
    MlDsaVariant::MlDsaVariant as AidlMlDsaVariant, SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::system::keystore2::{
    Authorization::Authorization, Domain::Domain, KeyDescriptor::KeyDescriptor,
    ResponseCode::ResponseCode,
};
use crate::err as ks_err;
use crate::keymaster::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, ZVec};
use crate::keymaster::error::{map_km_error, map_ks_error, Error, ErrorCode};
use crate::keymaster::key_parameter::KeyParameter;
use crate::keymaster::permission;
use crate::keymaster::permission::{KeyPerm, KeyPermSet, KeystorePerm};
use crate::keymaster::sw_keyblob;
use crate::plat::utils as user_utils;
pub use crate::watchdog;
use crate::{
    consts,
    keymaster::{
        db::{KeyType, KeystoreDB},
        keymint_device::KeyMintDevice,
    },
};
use anyhow::{anyhow, Context, Result};
use kmr_wire::keymint::{self, KeyParam};
use kmr_wire::{KeySizeInBits, ValueNotRecognized};
use log::{debug, error, info, warn};
use rsbinder::{
    get_calling_uid, hub, FromIBinder, ProcessState, SIBinder, Status, StatusCode, Strong,
};
use std::iter::IntoIterator;
use std::thread::sleep;
use std::time::Duration;

#[cfg(test)]
mod tests;

/// Newtype holding an integer that represents an Android user ID, corresponding to a user/human
/// profile (i.e. *not* to a specific UNIX uid assigned to a particular app).
///
/// This type uses an `i32` as the underlying integer type in order to match the Rust type used for
/// AIDL `int` values, which are used to specify user IDs (recall that AIDL has no unsigned integer
/// types, like Java).  However, other libraries (e.g. the `rustutils` crate) use `u32`,
/// necessitating some casts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AndroidUserId(pub i32);

/// Newtype holding an integer that represents a per-app uid value (i.e. *not* a user/human user
/// ID).
///
/// The underlying integer type is `i64` to encompass both AIDL `int` and `long` values, as both
/// types are used to hold uid values in different places on Keystore's external interfaces.  This
/// also copes with other libraries (e.g. `binder` and `libc`) which use `u32` for uid values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppUid(pub i64);

impl AppUid {
    /// Return the user/human profile user ID corresponding to this uid.
    pub fn owning_user(&self) -> AndroidUserId {
        AndroidUserId(user_utils::multiuser_get_user_id(self.0 as u32) as i32)
    }

    /// Get the calling uid for the current thread.
    pub fn calling() -> Self {
        Self(get_calling_uid() as i64)
    }
}

/// Uid for the system.
pub const AID_SYSTEM: AppUid = AppUid(1000);

/// A secure user ID ("sid") corresponding to an `AndroidUserId` that has been registered with a
/// secure authenticator instance.
///
/// The underlying integer type is `i64` to match the AIDL `long` types used in authenticator
/// HALs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureUserId(pub i64);

/// A per-operation authentication challenge value.
///
/// The underlying integer type is `i64` to match the AIDL `long` type that is:
/// - returned by KeyMint in `BeginResult`
/// - passed on by `keystore2` in the `OperationChallenge` AIDL type on the
///   `IKeystoreService` AIDL interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Challenge(pub i64);

/// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to GeneralizedTime
/// 999912312359559, which is 253402300799000 ms from Jan 1, 1970.
pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given keystore permission.
pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    permission::check_keystore_permission(perm, None)
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given grant permission.
pub fn check_grant_permission(access_vec: KeyPermSet, key: &KeyDescriptor) -> anyhow::Result<()> {
    permission::check_grant_permission(access_vec, key, None)
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given key permission.
pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    permission::check_key_permission(perm, key, access_vector.as_ref(), None)
}

/// This function checks whether a given tag corresponds to the access of device identifiers.
pub fn is_device_id_attestation_tag(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::ATTESTATION_ID_IMEI
            | Tag::ATTESTATION_ID_MEID
            | Tag::ATTESTATION_ID_SERIAL
            | Tag::DEVICE_UNIQUE_ATTESTATION
            | Tag::ATTESTATION_ID_SECOND_IMEI
    )
}

/// This function checks whether a given tag corresponds to the access of any IMEI attestation.
pub fn is_imei_attestation_tag(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::ATTESTATION_ID_IMEI | Tag::ATTESTATION_ID_SECOND_IMEI
    )
}

/// This function checks whether the calling app has the Android permissions needed to attest device
/// identifiers. It throws an error if the permissions cannot be verified or if the caller doesn't
/// have the right permissions. Otherwise it returns silently.
pub fn check_device_attestation_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.READ_PRIVILEGED_PHONE_STATE",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

/// This function checks whether the calling app has the Android permissions needed to attest the
/// device-unique identifier. It throws an error if the permissions cannot be verified or if the
/// caller doesn't have the right permissions. Otherwise it returns silently.
pub fn check_unique_id_attestation_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.REQUEST_UNIQUE_ID_ATTESTATION",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

/// This function checks whether the calling app has the Android permissions needed to manage
/// users. Only callers that can manage users are allowed to get a list of apps affected
/// by a user's SID changing.
/// It throws an error if the permissions cannot be verified or if the caller doesn't
/// have the right permissions. Otherwise it returns silently.
pub fn check_get_app_uids_affected_by_sid_permissions() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.MANAGE_USERS",
        Error::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

/// This function checks whether the calling app has the Android permission needed to dump
/// Keystore state to logcat.
pub fn check_dump_permission() -> anyhow::Result<()> {
    check_android_permission(
        "android.permission.DUMP",
        Error::Rc(ResponseCode::PERMISSION_DENIED),
    )
}

fn check_android_permission(permission: &str, err: Error) -> anyhow::Result<()> {
    let app_id = user_utils::multiuser_get_app_id(AppUid::calling().0 as u32);
    match app_id {
        consts::AID_ROOT | 1000 | consts::AID_KEYSTORE => Ok(()),
        _ => Err(err).context(ks_err!(
            "caller does not have the '{permission}' permission"
        )),
    }
}

/// Converts a set of key characteristics as returned from KeyMint into the internal
/// representation of the keystore service.
pub fn key_characteristics_to_internal(
    key_characteristics: Vec<KeyCharacteristics>,
) -> Vec<KeyParameter> {
    key_characteristics
        .into_iter()
        .flat_map(|aidl_key_char| {
            let sec_level = aidl_key_char.securityLevel;
            aidl_key_char
                .authorizations
                .into_iter()
                .map(move |aidl_kp| KeyParameter::new(aidl_kp.into(), sec_level))
        })
        .collect()
}

/// Import a keyblob that is of the format used by the software C++ KeyMint implementation.  After
/// successful import, invoke both the `new_blob_handler` and `km_op` closures. On success a tuple
/// of the `km_op`s result and the optional upgraded blob is returned.
fn import_keyblob_and_perform_op<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    inner_keyblob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    let (format, key_material, mut chars) = sw_keyblob::export_key(inner_keyblob, upgrade_params)?;
    debug!(
        "importing {format:?} key material (len={}) with original chars={chars:?}",
        key_material.len(),
    );
    let asymmetric = chars.iter().any(|kp| {
        kp.tag == Tag::ALGORITHM
            && (kp.value == KeyParameterValue::Algorithm(Algorithm::RSA)
                || (kp.value == KeyParameterValue::Algorithm(Algorithm::EC)))
    });

    // Combine the characteristics of the previous keyblob with the upgrade parameters (which might
    // include special things like APPLICATION_ID / APPLICATION_DATA).
    chars.extend_from_slice(upgrade_params);

    // Now filter out values from the existing keyblob that shouldn't be set on import, either
    // because they are per-operation parameter or because they are auto-added by KeyMint itself.
    let mut import_params: Vec<KmKeyParameter> = chars
        .into_iter()
        .filter(|kp| {
            !matches!(
                kp.tag,
                Tag::ORIGIN
                    | Tag::ROOT_OF_TRUST
                    | Tag::OS_VERSION
                    | Tag::OS_PATCHLEVEL
                    | Tag::UNIQUE_ID
                    | Tag::ATTESTATION_CHALLENGE
                    | Tag::ATTESTATION_APPLICATION_ID
                    | Tag::ATTESTATION_ID_BRAND
                    | Tag::ATTESTATION_ID_DEVICE
                    | Tag::ATTESTATION_ID_PRODUCT
                    | Tag::ATTESTATION_ID_SERIAL
                    | Tag::ATTESTATION_ID_IMEI
                    | Tag::ATTESTATION_ID_MEID
                    | Tag::ATTESTATION_ID_MANUFACTURER
                    | Tag::ATTESTATION_ID_MODEL
                    | Tag::VENDOR_PATCHLEVEL
                    | Tag::BOOT_PATCHLEVEL
                    | Tag::DEVICE_UNIQUE_ATTESTATION
                    | Tag::ATTESTATION_ID_SECOND_IMEI
                    | Tag::NONCE
                    | Tag::MAC_LENGTH
                    | Tag::CERTIFICATE_SERIAL
                    | Tag::CERTIFICATE_SUBJECT
                    | Tag::CERTIFICATE_NOT_BEFORE
                    | Tag::CERTIFICATE_NOT_AFTER
            )
        })
        .collect();

    // Now that any previous values have been removed, add any additional parameters that needed for
    // import. In particular, if we are generating/importing an asymmetric key, we need to make sure
    // that NOT_BEFORE and NOT_AFTER are present.
    if asymmetric {
        import_params.push(KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_BEFORE,
            value: KeyParameterValue::DateTime(0),
        });
        import_params.push(KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_AFTER,
            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
        });
    }
    debug!("import parameters={import_params:?}");

    let creation_result = {
        let _wp = watchdog::watch(
            "utils::import_keyblob_and_perform_op: calling IKeyMintDevice::importKey",
        );
        map_km_error(km_dev.importKey(&import_params, format, &key_material, None))
    }
    .context(ks_err!("Upgrade failed."))?;

    // Note that the importKey operation will produce key characteristics that may be different
    // than are already stored in Keystore's SQL database.  In particular, the KeyMint
    // implementation will now mark the key as `Origin::IMPORTED` not `Origin::GENERATED`, and
    // the security level for characteristics will now be `TRUSTED_ENVIRONMENT` not `SOFTWARE`.
    //
    // However, the DB metadata still accurately reflects the original origin of the key, and
    // so we leave the values as-is (and so any `KeyInfo` retrieved in the Java layer will get the
    // same results before and after import).
    //
    // Note that this also applies to the `USAGE_COUNT_LIMIT` parameter -- if the key has already
    // been used, then the DB version of the parameter will be (and will continue to be) lower
    // than the original count bound to the keyblob. This means that Keystore's policing of
    // usage counts will continue where it left off.

    new_blob_handler(&creation_result.keyBlob).context(ks_err!("calling new_blob_handler."))?;

    km_op(&creation_result.keyBlob)
        .map(|v| (v, Some(creation_result.keyBlob)))
        .context(ks_err!("Calling km_op after upgrade."))
}

/// Upgrade a keyblob then invoke both the `new_blob_handler` and the `km_op` closures.  On success
/// a tuple of the `km_op`s result and the optional upgraded blob is returned.
fn upgrade_keyblob_and_perform_op<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    let upgraded_blob = {
        let _wp = watchdog::watch(
            "utils::upgrade_keyblob_and_perform_op: calling IKeyMintDevice::upgradeKey.",
        );
        map_km_error(km_dev.upgradeKey(key_blob, upgrade_params))
    }
    .context(ks_err!("Upgrade failed."))?;

    new_blob_handler(&upgraded_blob).context(ks_err!("calling new_blob_handler."))?;

    km_op(&upgraded_blob)
        .map(|v| (v, Some(upgraded_blob)))
        .context(ks_err!("Calling km_op after upgrade."))
}

/// This function can be used to upgrade key blobs on demand. The return value of
/// `km_op` is inspected and if ErrorCode::KEY_REQUIRES_UPGRADE is encountered,
/// an attempt is made to upgrade the key blob. On success `new_blob_handler` is called
/// with the upgraded blob as argument. Then `km_op` is called a second time with the
/// upgraded blob as argument. On success a tuple of the `km_op`s result and the
/// optional upgraded blob is returned.
pub fn upgrade_keyblob_if_required_with<T, KmOp, NewBlobHandler>(
    km_dev: &dyn IKeyMintDevice,
    km_dev_version: i32,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    match km_op(key_blob) {
        Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => upgrade_keyblob_and_perform_op(
            km_dev,
            key_blob,
            upgrade_params,
            km_op,
            new_blob_handler,
        ),
        Err(Error::Km(ErrorCode::INVALID_KEY_BLOB))
            if km_dev_version >= KeyMintDevice::KEY_MINT_V1 =>
        {
            // A KeyMint (not Keymaster via km_compat) device says that this is an invalid keyblob.
            //
            // This may be because the keyblob was created before an Android upgrade, and as part of
            // the device upgrade the underlying Keymaster/KeyMint implementation has been upgraded.
            //
            // If that's the case, there are three possible scenarios:
            if key_blob.starts_with(consts::KEYMASTER_BLOB_HW_PREFIX) {
                // 1) The keyblob was created in hardware by the km_compat C++ code, using a prior
                //    Keymaster implementation, and wrapped.
                //
                //    In this case, the keyblob will have the km_compat magic prefix, including the
                //    marker that indicates that this was a hardware-backed key.
                //
                //    The inner keyblob should still be recognized by the hardware implementation, so
                //    strip the prefix and attempt a key upgrade.
                info!("found apparent km_compat(Keymaster) HW blob, attempt strip-and-upgrade");
                let inner_keyblob = &key_blob[consts::KEYMASTER_BLOB_HW_PREFIX.len()..];
                upgrade_keyblob_and_perform_op(
                    km_dev,
                    inner_keyblob,
                    upgrade_params,
                    km_op,
                    new_blob_handler,
                )
            } else if crate::keymaster::flags::import_previously_emulated_keys()
                && key_blob.starts_with(consts::KEYMASTER_BLOB_SW_PREFIX)
            {
                // 2) The keyblob was created in software by the km_compat C++ code because a prior
                //    Keymaster implementation did not support ECDH (which was only added in KeyMint).
                //
                //    In this case, the keyblob with have the km_compat magic prefix, but with the
                //    marker that indicates that this was a software-emulated key.
                //
                //    The inner keyblob should be in the format produced by the C++ reference
                //    implementation of KeyMint.  Extract the key material and import it into the
                //    current KeyMint device.
                info!("found apparent km_compat(Keymaster) SW blob, attempt strip-and-import");
                let inner_keyblob = &key_blob[consts::KEYMASTER_BLOB_SW_PREFIX.len()..];
                import_keyblob_and_perform_op(
                    km_dev,
                    inner_keyblob,
                    upgrade_params,
                    km_op,
                    new_blob_handler,
                )
            } else {
                Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(ks_err!("Calling km_op"))
            }
        }
        r => r.map(|v| (v, None)).context(ks_err!("Calling km_op.")),
    }
}

/// Converts a set of key characteristics from the internal representation into a set of
/// Authorizations as they are used to convey key characteristics to the clients of keystore.
pub fn key_parameters_to_authorizations(parameters: Vec<KeyParameter>) -> Vec<Authorization> {
    parameters
        .into_iter()
        .map(|p| p.into_authorization())
        .collect()
}

macro_rules! check_bool {
    {
        $val:expr
    } => {
        if let KeyParameterValue::BoolValue(true) = $val {
            Ok(())
        } else {
            Err(ValueNotRecognized::Bool)
        }
    }
}

pub fn key_parameter_conversion_error_code(error: ValueNotRecognized) -> ErrorCode {
    match error {
        ValueNotRecognized::KeyPurpose => ErrorCode::UNSUPPORTED_PURPOSE,
        ValueNotRecognized::Algorithm => ErrorCode::UNSUPPORTED_ALGORITHM,
        ValueNotRecognized::BlockMode => ErrorCode::UNSUPPORTED_BLOCK_MODE,
        ValueNotRecognized::PaddingMode => ErrorCode::UNSUPPORTED_PADDING_MODE,
        ValueNotRecognized::Digest => ErrorCode::UNSUPPORTED_DIGEST,
        ValueNotRecognized::KeyFormat => ErrorCode::UNSUPPORTED_KEY_FORMAT,
        ValueNotRecognized::EcCurve => ErrorCode::UNSUPPORTED_EC_CURVE,
        ValueNotRecognized::MlDsaVariant => {
            ErrorCode(kmr_wire::keymint::ErrorCode::UnsupportedMlDsaVariant as i32)
        }
        _ => ErrorCode::INVALID_ARGUMENT,
    }
}

impl HardwareAuthToken {
    pub fn to_km(&self) -> Result<kmr_wire::keymint::HardwareAuthToken, Error> {
        Ok(kmr_wire::keymint::HardwareAuthToken {
            challenge: self.challenge,
            user_id: self.userId,
            authenticator_id: self.authenticatorId,
            authenticator_type: kmr_wire::keymint::HardwareAuthenticatorType::try_from(
                self.authenticatorType.0,
            )
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))?,
            timestamp: kmr_wire::secureclock::Timestamp {
                milliseconds: self.timestamp.milliSeconds,
            },
            mac: self.mac.clone(),
        })
    }
}

impl KmKeyParameter {
    pub fn to_km(self) -> Result<KeyParam> {
        self.to_km_optional(KeyMintDevice::KEY_MINT_V5)
            .map_err(|error| anyhow!("Failed to convert key parameter: {error:?}"))?
            .ok_or_else(|| anyhow!(ks_err!("Invalid tag")))
    }

    pub fn to_km_optional(
        self,
        km_dev_version: i32,
    ) -> std::result::Result<Option<KeyParam>, ValueNotRecognized> {
        let tag = match keymint::Tag::try_from(self.tag.0) {
            Ok(tag) => tag,
            Err(_) => return Ok(None),
        };
        let value = self.value;

        Ok(match tag {
            keymint::Tag::Invalid => None,
            keymint::Tag::Purpose => match value {
                KeyParameterValue::KeyPurpose(v) => Some(KeyParam::Purpose(
                    kmr_wire::keymint::KeyPurpose::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::KeyPurpose),
            },
            keymint::Tag::Algorithm => match value {
                KeyParameterValue::Algorithm(v) => {
                    let algorithm = kmr_wire::keymint::Algorithm::try_from(v.0)?;
                    if km_dev_version < KeyMintDevice::KEY_MINT_V5
                        && algorithm == kmr_wire::keymint::Algorithm::MlDsa
                    {
                        return Err(ValueNotRecognized::Algorithm);
                    }
                    Some(KeyParam::Algorithm(algorithm))
                }
                _ => return Err(ValueNotRecognized::Algorithm),
            },
            keymint::Tag::KeySize => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::KeySize(KeySizeInBits(v as u32))),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::BlockMode => match value {
                KeyParameterValue::BlockMode(v) => Some(KeyParam::BlockMode(
                    kmr_wire::keymint::BlockMode::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::BlockMode),
            },
            keymint::Tag::Digest => match value {
                KeyParameterValue::Digest(v) => {
                    Some(KeyParam::Digest(kmr_wire::keymint::Digest::try_from(v.0)?))
                }
                _ => return Err(ValueNotRecognized::Digest),
            },
            keymint::Tag::Padding => match value {
                KeyParameterValue::PaddingMode(v) => Some(KeyParam::Padding(
                    kmr_wire::keymint::PaddingMode::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::PaddingMode),
            },
            keymint::Tag::CallerNonce => {
                check_bool!(value)?;
                Some(KeyParam::CallerNonce)
            }
            keymint::Tag::MinMacLength => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MinMacLength(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::EcCurve => match value {
                KeyParameterValue::EcCurve(v) => {
                    let curve = kmr_wire::keymint::EcCurve::try_from(v.0)?;
                    if km_dev_version < KeyMintDevice::KEY_MINT_V2
                        && curve == kmr_wire::keymint::EcCurve::Curve25519
                    {
                        return Err(ValueNotRecognized::EcCurve);
                    }
                    Some(KeyParam::EcCurve(curve))
                }
                _ => return Err(ValueNotRecognized::EcCurve),
            },
            keymint::Tag::MlDsaVariant if km_dev_version < KeyMintDevice::KEY_MINT_V5 => None,
            keymint::Tag::MlDsaVariant => match value {
                KeyParameterValue::MlDsaVariant(v) => Some(KeyParam::MlDsaVariant(
                    kmr_wire::keymint::MlDsaVariant::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::MlDsaVariant),
            },
            keymint::Tag::RsaPublicExponent => match value {
                KeyParameterValue::LongInteger(v) => {
                    Some(KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(v as u64)))
                }
                _ => return Err(ValueNotRecognized::LongInteger),
            },
            keymint::Tag::IncludeUniqueId => {
                check_bool!(value)?;
                Some(KeyParam::IncludeUniqueId)
            }
            keymint::Tag::RsaOaepMgfDigest => match value {
                KeyParameterValue::Digest(v) => Some(KeyParam::RsaOaepMgfDigest(
                    kmr_wire::keymint::Digest::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::Digest),
            },
            keymint::Tag::BootloaderOnly => {
                check_bool!(value)?;
                Some(KeyParam::BootloaderOnly)
            }
            keymint::Tag::RollbackResistance => {
                check_bool!(value)?;
                Some(KeyParam::RollbackResistance)
            }
            keymint::Tag::HardwareType => return Err(ValueNotRecognized::Tag),
            keymint::Tag::EarlyBootOnly => {
                check_bool!(value)?;
                Some(KeyParam::EarlyBootOnly)
            }
            keymint::Tag::ActiveDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::ActiveDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::OriginationExpireDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::OriginationExpireDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::UsageExpireDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::UsageExpireDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::MinSecondsBetweenOps => return Err(ValueNotRecognized::Tag),
            keymint::Tag::MaxUsesPerBoot => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MaxUsesPerBoot(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UsageCountLimit => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::UsageCountLimit(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UserId => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::UserId(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UserSecureId => match value {
                KeyParameterValue::LongInteger(v) => Some(KeyParam::UserSecureId(v as u64)),
                _ => return Err(ValueNotRecognized::LongInteger),
            },
            keymint::Tag::NoAuthRequired => {
                check_bool!(value)?;
                Some(KeyParam::NoAuthRequired)
            }
            keymint::Tag::UserAuthType => match value {
                KeyParameterValue::HardwareAuthenticatorType(v) => {
                    Some(KeyParam::UserAuthType(v.0 as u32))
                }
                _ => return Err(ValueNotRecognized::HardwareAuthenticatorType),
            },
            keymint::Tag::AuthTimeout => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::AuthTimeout(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::AllowWhileOnBody => {
                check_bool!(value)?;
                Some(KeyParam::AllowWhileOnBody)
            }
            keymint::Tag::TrustedUserPresenceRequired => {
                check_bool!(value)?;
                Some(KeyParam::TrustedUserPresenceRequired)
            }
            keymint::Tag::TrustedConfirmationRequired => {
                check_bool!(value)?;
                Some(KeyParam::TrustedConfirmationRequired)
            }
            keymint::Tag::UnlockedDeviceRequired => {
                check_bool!(value)?;
                Some(KeyParam::UnlockedDeviceRequired)
            }
            keymint::Tag::ApplicationId => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::ApplicationId(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::ApplicationData => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::ApplicationData(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::CreationDatetime => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CreationDatetime(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::Origin => match value {
                KeyParameterValue::Origin(v) => Some(KeyParam::Origin(
                    kmr_wire::keymint::KeyOrigin::try_from(v.0)?,
                )),
                _ => return Err(ValueNotRecognized::KeyOrigin),
            },
            keymint::Tag::RootOfTrust => match value {
                KeyParameterValue::Blob(v) => Some(KeyParam::RootOfTrust(v)),
                _ => return Err(ValueNotRecognized::Blob),
            },
            keymint::Tag::OsVersion => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::OsVersion(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::OsPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::OsPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::UniqueId => return Err(ValueNotRecognized::Tag),
            keymint::Tag::AttestationChallenge => {
                blob_param(value, KeyParam::AttestationChallenge)?
            }
            keymint::Tag::AttestationApplicationId => {
                blob_param(value, KeyParam::AttestationApplicationId)?
            }
            keymint::Tag::AttestationIdBrand => blob_param(value, KeyParam::AttestationIdBrand)?,
            keymint::Tag::AttestationIdDevice => blob_param(value, KeyParam::AttestationIdDevice)?,
            keymint::Tag::AttestationIdProduct => {
                blob_param(value, KeyParam::AttestationIdProduct)?
            }
            keymint::Tag::AttestationIdSerial => blob_param(value, KeyParam::AttestationIdSerial)?,
            keymint::Tag::AttestationIdImei => blob_param(value, KeyParam::AttestationIdImei)?,
            keymint::Tag::AttestationIdMeid => blob_param(value, KeyParam::AttestationIdMeid)?,
            keymint::Tag::AttestationIdManufacturer => {
                blob_param(value, KeyParam::AttestationIdManufacturer)?
            }
            keymint::Tag::AttestationIdModel => blob_param(value, KeyParam::AttestationIdModel)?,
            keymint::Tag::VendorPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::VendorPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::BootPatchlevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::BootPatchlevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::DeviceUniqueAttestation => {
                check_bool!(value)?;
                Some(KeyParam::DeviceUniqueAttestation)
            }
            keymint::Tag::IdentityCredentialKey => return Err(ValueNotRecognized::Tag),
            keymint::Tag::StorageKey => {
                check_bool!(value)?;
                Some(KeyParam::StorageKey)
            }
            keymint::Tag::AttestationIdSecondImei
                if km_dev_version < KeyMintDevice::KEY_MINT_V3 =>
            {
                None
            }
            keymint::Tag::AttestationIdSecondImei => {
                blob_param(value, KeyParam::AttestationIdSecondImei)?
            }
            keymint::Tag::AssociatedData => return Err(ValueNotRecognized::Tag),
            keymint::Tag::Nonce => blob_param(value, KeyParam::Nonce)?,
            keymint::Tag::MacLength => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MacLength(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::ResetSinceIdRotation => {
                check_bool!(value)?;
                Some(KeyParam::ResetSinceIdRotation)
            }
            keymint::Tag::ConfirmationToken => return Err(ValueNotRecognized::Tag),
            keymint::Tag::CertificateSerial => blob_param(value, KeyParam::CertificateSerial)?,
            keymint::Tag::CertificateSubject => blob_param(value, KeyParam::CertificateSubject)?,
            keymint::Tag::CertificateNotBefore => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CertificateNotBefore(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::CertificateNotAfter => match value {
                KeyParameterValue::DateTime(ms_since_epoch) => {
                    Some(KeyParam::CertificateNotAfter(keymint::DateTime {
                        ms_since_epoch,
                    }))
                }
                _ => return Err(ValueNotRecognized::DateTime),
            },
            keymint::Tag::MaxBootLevel => match value {
                KeyParameterValue::Integer(v) => Some(KeyParam::MaxBootLevel(v as u32)),
                _ => return Err(ValueNotRecognized::Integer),
            },
            keymint::Tag::ModuleHash if km_dev_version < KeyMintDevice::KEY_MINT_V4 => None,
            keymint::Tag::ModuleHash => blob_param(value, KeyParam::ModuleHash)?,
        })
    }
}

pub fn key_parameters_to_km(
    parameters: &[KmKeyParameter],
    km_dev_version: i32,
) -> std::result::Result<Vec<KeyParam>, ValueNotRecognized> {
    parameters
        .iter()
        .cloned()
        .try_fold(Vec::new(), |mut result, param| {
            if let Some(param) = param.to_km_optional(km_dev_version)? {
                result.push(param);
            }
            Ok(result)
        })
}

fn blob_param(
    value: KeyParameterValue,
    f: impl FnOnce(Vec<u8>) -> KeyParam,
) -> std::result::Result<Option<KeyParam>, ValueNotRecognized> {
    match value {
        KeyParameterValue::Blob(v) => Ok(Some(f(v))),
        _ => Err(ValueNotRecognized::Blob),
    }
}

pub fn key_creation_result_to_aidl(
    result: kmr_wire::keymint::KeyCreationResult,
    km_dev_version: i32,
) -> Result<KeyCreationResult, rsbinder::Status> {
    let certificates: Vec<Certificate> = result
        .certificate_chain
        .iter()
        .map(|c| Certificate {
            encodedCertificate: c.encoded_certificate.clone(),
        })
        .collect();

    let key_characteristics: Result<Vec<KeyCharacteristics>, rsbinder::Status> = result
        .key_characteristics
        .iter()
        .map(|kc| {
            let params = key_params_to_aidl(&kc.authorizations, km_dev_version)
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;

            Ok(KeyCharacteristics {
                authorizations: params,
                securityLevel: SecurityLevel(kc.security_level as i32),
            })
        })
        .collect();

    Ok(KeyCreationResult {
        keyBlob: result.key_blob,
        keyCharacteristics: key_characteristics?,
        certificateChain: certificates,
    })
}

pub fn key_params_to_aidl(params: &[KeyParam], km_dev_version: i32) -> Result<Vec<KmKeyParameter>> {
    params
        .iter()
        .cloned()
        .map(|param| key_param_to_aidl(param, km_dev_version))
        .collect()
}

pub fn key_param_to_aidl(kp: KeyParam, km_dev_version: i32) -> Result<KmKeyParameter> {
    let mut tag = Tag(kp.tag() as i32);
    let value = match kp {
        KeyParam::Purpose(v) => KeyParameterValue::KeyPurpose(
            crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose(v as i32),
        ),
        KeyParam::Algorithm(v) => KeyParameterValue::Algorithm(Algorithm(v as i32)),
        KeyParam::KeySize(KeySizeInBits(v)) => KeyParameterValue::Integer(v as i32),
        KeyParam::BlockMode(v) => KeyParameterValue::BlockMode(
            crate::android::hardware::security::keymint::BlockMode::BlockMode(v as i32),
        ),
        KeyParam::Digest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::Padding(v) => KeyParameterValue::PaddingMode(
            crate::android::hardware::security::keymint::PaddingMode::PaddingMode(v as i32),
        ),
        KeyParam::CallerNonce => KeyParameterValue::BoolValue(true),
        KeyParam::MinMacLength(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::EcCurve(v) => KeyParameterValue::EcCurve(
            crate::android::hardware::security::keymint::EcCurve::EcCurve(v as i32),
        ),
        KeyParam::MlDsaVariant(v) if km_dev_version < KeyMintDevice::KEY_MINT_V5 => {
            error!("TA emitted ML_DSA_VARIANT tag but HAL v5 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Integer(v as i32)
        }
        KeyParam::MlDsaVariant(v) => KeyParameterValue::MlDsaVariant(AidlMlDsaVariant(v as i32)),
        KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(v)) => {
            KeyParameterValue::LongInteger(v as i64)
        }
        KeyParam::IncludeUniqueId => KeyParameterValue::BoolValue(true),
        KeyParam::RsaOaepMgfDigest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::BootloaderOnly
        | KeyParam::RollbackResistance
        | KeyParam::EarlyBootOnly
        | KeyParam::NoAuthRequired
        | KeyParam::AllowWhileOnBody
        | KeyParam::TrustedUserPresenceRequired
        | KeyParam::TrustedConfirmationRequired
        | KeyParam::UnlockedDeviceRequired
        | KeyParam::DeviceUniqueAttestation
        | KeyParam::StorageKey
        | KeyParam::ResetSinceIdRotation => KeyParameterValue::BoolValue(true),
        KeyParam::ActiveDatetime(v)
        | KeyParam::OriginationExpireDatetime(v)
        | KeyParam::UsageExpireDatetime(v)
        | KeyParam::CreationDatetime(v)
        | KeyParam::CertificateNotBefore(v)
        | KeyParam::CertificateNotAfter(v) => KeyParameterValue::DateTime(v.ms_since_epoch),
        KeyParam::MaxUsesPerBoot(v)
        | KeyParam::UsageCountLimit(v)
        | KeyParam::UserId(v)
        | KeyParam::AuthTimeout(v)
        | KeyParam::OsVersion(v)
        | KeyParam::OsPatchlevel(v)
        | KeyParam::VendorPatchlevel(v)
        | KeyParam::BootPatchlevel(v)
        | KeyParam::MacLength(v)
        | KeyParam::MaxBootLevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::UserAuthType(v) => {
            KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(v as i32))
        }
        KeyParam::UserSecureId(v) => KeyParameterValue::LongInteger(v as i64),
        KeyParam::ApplicationId(v)
        | KeyParam::ApplicationData(v)
        | KeyParam::RootOfTrust(v)
        | KeyParam::AttestationChallenge(v)
        | KeyParam::AttestationApplicationId(v)
        | KeyParam::AttestationIdBrand(v)
        | KeyParam::AttestationIdDevice(v)
        | KeyParam::AttestationIdProduct(v)
        | KeyParam::AttestationIdSerial(v)
        | KeyParam::AttestationIdImei(v)
        | KeyParam::AttestationIdMeid(v)
        | KeyParam::AttestationIdManufacturer(v)
        | KeyParam::AttestationIdModel(v)
        | KeyParam::Nonce(v)
        | KeyParam::CertificateSerial(v)
        | KeyParam::CertificateSubject(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdSecondImei(v) if km_dev_version < KeyMintDevice::KEY_MINT_V3 => {
            error!("TA emitted ATTESTATION_ID_SECOND_IMEI tag but HAL v3 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KeyParam::AttestationIdSecondImei(v) => KeyParameterValue::Blob(v),
        KeyParam::ModuleHash(v) if km_dev_version < KeyMintDevice::KEY_MINT_V4 => {
            error!("TA emitted MODULE_HASH tag but HAL v4 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KeyParam::ModuleHash(v) => KeyParameterValue::Blob(v),
        KeyParam::Origin(v) => KeyParameterValue::Origin(
            crate::android::hardware::security::keymint::KeyOrigin::KeyOrigin(v as i32),
        ),
    };

    Ok(KmKeyParameter { tag, value })
}

#[allow(clippy::unnecessary_cast)]
/// This returns the current time (in milliseconds) as an instance of a monotonic clock,
/// by invoking the system call since Rust does not support getting monotonic time instance
/// as an integer.
pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid because it comes from a reference, and clock_gettime doesn't
    // retain it beyond the call.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    current_time.tv_sec as i64 * 1000 + (current_time.tv_nsec as i64 / 1_000_000)
}

/// AID offset for uid space partitioning.
pub const AID_USER_OFFSET: u32 = user_utils::AID_USER_OFFSET;

/// AID of the keystore process itself, used for keys that
/// keystore generates for its own use.
pub const AID_KEYSTORE: AppUid = AppUid(consts::AID_KEYSTORE as i64);

/// Merges and filters two lists of key descriptors. The first input list, legacy_descriptors,
/// is assumed to not be sorted or filtered. As such, all key descriptors in that list whose
/// alias is less than, or equal to, start_past_alias (if provided) will be removed.
/// This list will then be merged with the second list, db_descriptors. The db_descriptors list
/// is assumed to be sorted and filtered so the output list will be sorted prior to returning.
/// The returned value is a list of KeyDescriptor objects whose alias is greater than
/// start_past_alias, sorted and de-duplicated.
#[cfg(test)]
fn merge_and_filter_key_entry_lists(
    legacy_descriptors: &[KeyDescriptor],
    db_descriptors: &[KeyDescriptor],
    start_past_alias: Option<&str>,
) -> Vec<KeyDescriptor> {
    let mut result: Vec<KeyDescriptor> = match start_past_alias {
        Some(past_alias) => legacy_descriptors
            .iter()
            .filter(|kd| {
                if let Some(alias) = &kd.alias {
                    alias.as_str() > past_alias
                } else {
                    false
                }
            })
            .cloned()
            .collect(),
        None => legacy_descriptors.to_vec(),
    };

    result.extend_from_slice(db_descriptors);
    result.sort_unstable();
    result.dedup();
    result
}

pub(crate) fn estimate_safe_amount_to_return(
    domain: Domain,
    namespace: i64,
    start_past_alias: Option<&str>,
    key_descriptors: &[KeyDescriptor],
    response_size_limit: usize,
) -> usize {
    let mut count = 0;
    let mut bytes: usize = 0;
    // Estimate the transaction size to avoid returning more items than what
    // could fit in a binder transaction.
    for kd in key_descriptors.iter() {
        // 4 bytes for the Domain enum
        // 8 bytes for the Namespace long.
        bytes += 4 + 8;
        // Size of the alias string. Includes 4 bytes for length encoding.
        if let Some(alias) = &kd.alias {
            bytes += 4 + alias.len();
        }
        // Size of the blob. Includes 4 bytes for length encoding.
        if let Some(blob) = &kd.blob {
            bytes += 4 + blob.len();
        }
        // The binder transaction size limit is 1M. Empirical measurements show
        // that the binder overhead is 60% (to be confirmed). So break after
        // 350KB and return a partial list.
        if bytes > response_size_limit {
            warn!(
                "{domain:?}:{namespace}: Key descriptors list ({} items after {start_past_alias:?}) \
                 may exceed binder size, returning {count} items est. {bytes} bytes",
                key_descriptors.len(),
            );
            break;
        }
        count += 1;
    }
    count
}

/// Estimate for maximum size of a Binder response in bytes.
pub(crate) const RESPONSE_SIZE_LIMIT: usize = 358400;

/// List all key aliases for a given domain + namespace. whose alias is greater
/// than start_past_alias (if provided).
pub fn list_key_entries(
    db: &mut KeystoreDB,
    domain: Domain,
    namespace: i64,
    start_past_alias: Option<&str>,
) -> Result<Vec<KeyDescriptor>> {
    let key_descriptors: Vec<KeyDescriptor> = db
        .list_past_alias(domain, namespace, KeyType::Client, start_past_alias)
        .context(ks_err!("Trying to list keystore database past alias."))?;

    let safe_amount_to_return = estimate_safe_amount_to_return(
        domain,
        namespace,
        start_past_alias,
        &key_descriptors,
        RESPONSE_SIZE_LIMIT,
    );
    Ok(key_descriptors[..safe_amount_to_return].to_vec())
}

/// Count all key aliases for a given domain + namespace.
pub fn count_key_entries(db: &mut KeystoreDB, domain: Domain, namespace: i64) -> Result<i32> {
    Ok(db.count_keys(domain, namespace, KeyType::Client)? as i32)
}

/// For params remove sensitive data before returning a string for logging
pub fn log_security_safe_params(params: &[KmKeyParameter]) -> Vec<KmKeyParameter> {
    params
        .iter()
        .filter(|kp| kp.tag != Tag::APPLICATION_ID && kp.tag != Tag::APPLICATION_DATA)
        .cloned()
        .collect::<Vec<KmKeyParameter>>()
}

/// Trait implemented by objects that can be used to decrypt cipher text using AES-GCM.
pub trait AesGcm {
    /// Deciphers `data` using the initialization vector `iv` and AEAD tag `tag`
    /// and AES-GCM. The implementation provides the key material and selects
    /// the implementation variant, e.g., AES128 or AES265.
    fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec>;

    /// Encrypts `data` and returns the ciphertext, the initialization vector `iv`
    /// and AEAD tag `tag`. The implementation provides the key material and selects
    /// the implementation variant, e.g., AES128 or AES265.
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

/// Marks an object as AES-GCM key.
pub trait AesGcmKey {
    /// Provides access to the raw key material.
    fn key(&self) -> &[u8];
}

impl<T: AesGcmKey> AesGcm for T {
    fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec> {
        aes_gcm_decrypt(data, iv, tag, self.key()).context(ks_err!("Decryption failed"))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        aes_gcm_encrypt(plaintext, self.key()).context(ks_err!("Encryption failed."))
    }
}

/// Get the Binder interface identified by `name`, retrying any failures up to the given
/// `retry_count`.
pub fn retry_get_interface<T: FromIBinder + ?Sized>(
    name: &str,
    retry_count: usize,
) -> Result<Strong<T>, StatusCode> {
    let mut attempts = 0;
    let mut wait_time = Duration::from_secs(1);
    loop {
        let err = match hub::get_interface(name) {
            Ok(res) => {
                if attempts > 1 {
                    info!("Success on get_interface({name}) after {attempts} failures!");
                }
                return Ok(res);
            }
            Err(e) => e,
        };
        attempts += 1;
        error!("Failed (attempt {attempts} of {retry_count}) to get_interface {name}: {err:?}");
        if attempts >= retry_count {
            error!("Give up retrying after {attempts} failures, return final error: {err:?}");
            return Err(err);
        }
        info!("Blocking wait {wait_time:?} before retry of get_interface({name})");
        sleep(wait_time);
        wait_time *= 2;
    }
}

/// Information about a specific app.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppInfo {
    /// The target SDK for the app, if known.
    ///
    /// If a uid corresponds to multiple packages, this will be the lowest value across those
    /// packages.
    pub target_sdk: Option<i32>,
    /// Whether the app is a system app.
    ///
    /// If a uid corresponds to multiple packages, this will be true if any of those packages
    /// are system apps.
    pub is_system_app: bool,
}

const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
const PM_GET_LOCATION_FLAGS_ANDROID_12_14: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 4;
const PM_GET_TARGET_SDK_ANDROID_12_14: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 5;
const PM_GET_LOCATION_FLAGS_ANDROID_15_16: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 5;
const PM_GET_TARGET_SDK_ANDROID_15_16: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageManagerNativeLayout {
    Android12To14,
    Android15Or16,
    Android17,
}

fn package_manager_native_layout(android_major: Option<i32>) -> PackageManagerNativeLayout {
    match android_major {
        Some(version) if version >= 17 => PackageManagerNativeLayout::Android17,
        Some(15 | 16) | None => PackageManagerNativeLayout::Android15Or16,
        _ => PackageManagerNativeLayout::Android12To14,
    }
}

/// Return information about the given app.
///
/// Involves round-trips to PackageManager.
pub fn app_info_for_uid(uid: AppUid) -> AppInfo {
    let app_id = user_utils::multiuser_get_app_id(uid.0 as u32);
    let app_info = AppInfo {
        target_sdk: None,
        is_system_app: matches!(app_id, consts::AID_ROOT | 1000 | consts::AID_KEYSTORE),
    };

    if !ProcessState::is_initialized() {
        return app_info;
    }

    let pm: Strong<dyn IPackageManagerNative> =
        match hub::get_interface(PACKAGE_MANAGER_NATIVE_SERVICE) {
            Ok(pm) => pm,
            Err(e) => {
                warn!("failed to connect to PackageManager: {e:?}");
                return app_info;
            }
        };

    match package_manager_native_layout(kmr_common::android_version::android_major_version()) {
        layout @ (PackageManagerNativeLayout::Android12To14
        | PackageManagerNativeLayout::Android15Or16) => {
            app_info_for_uid_legacy_pm(&pm, uid, app_info, layout)
        }
        PackageManagerNativeLayout::Android17 => app_info_for_uid_android_17_pm(&pm, uid, app_info),
    }
}

fn app_info_for_uid_android_17_pm(
    pm: &Strong<dyn IPackageManagerNative>,
    uid: AppUid,
    mut app_info: AppInfo,
) -> AppInfo {
    let pkg_infos = match pm.getPackageInfoWithSigningInfoForUid(uid.0 as i32) {
        Ok(Some(infos)) => infos,
        Ok(None) => {
            warn!("no package info for {uid:?}");
            return app_info;
        }
        Err(e) => {
            warn!("failed to get package info for {uid:?}: {e:?}");
            return app_info;
        }
    };

    for pkg_info in pkg_infos.into_iter().flatten() {
        let pkg_name = pkg_info.r#packageName.as_str();
        if pkg_name.is_empty() {
            continue;
        }
        update_app_info_with_target_sdk(
            uid,
            pkg_name,
            pm.getTargetSdkVersionForPackage(pkg_name),
            &mut app_info,
        );
        if !app_info.is_system_app {
            update_app_info_with_location_flags(
                uid,
                pkg_name,
                pm.getLocationFlags(pkg_name),
                &mut app_info,
            );
        }
    }

    app_info
}

fn app_info_for_uid_legacy_pm(
    pm: &Strong<dyn IPackageManagerNative>,
    uid: AppUid,
    mut app_info: AppInfo,
    layout: PackageManagerNativeLayout,
) -> AppInfo {
    let pkg_names = match pm.getNamesForUids(&[uid.0 as i32]) {
        Ok(names) => names,
        Err(e) => {
            warn!("failed to get package names for {uid:?}: {e:?}");
            return app_info;
        }
    };

    let binder = match hub::get_service(PACKAGE_MANAGER_NATIVE_SERVICE) {
        Some(binder) => binder,
        None => {
            warn!("failed to connect to PackageManager service binder");
            return app_info;
        }
    };

    for pkg_name in pkg_names.iter().filter(|name| !name.is_empty()) {
        let pkg_name = pkg_name.as_str();
        update_app_info_with_target_sdk(
            uid,
            pkg_name,
            package_manager_native_get_i32_for_package(
                &binder,
                legacy_pm_get_target_sdk_transaction(layout),
                pkg_name,
                "target SDK version",
            ),
            &mut app_info,
        );
        if !app_info.is_system_app {
            update_app_info_with_location_flags(
                uid,
                pkg_name,
                package_manager_native_get_i32_for_package(
                    &binder,
                    legacy_pm_get_location_flags_transaction(layout),
                    pkg_name,
                    "location flags",
                ),
                &mut app_info,
            );
        }
    }

    app_info
}

fn legacy_pm_get_location_flags_transaction(
    layout: PackageManagerNativeLayout,
) -> rsbinder::TransactionCode {
    match layout {
        PackageManagerNativeLayout::Android12To14 => PM_GET_LOCATION_FLAGS_ANDROID_12_14,
        PackageManagerNativeLayout::Android15Or16 => PM_GET_LOCATION_FLAGS_ANDROID_15_16,
        PackageManagerNativeLayout::Android17 => unreachable!("Android 17 uses generated AIDL"),
    }
}

fn legacy_pm_get_target_sdk_transaction(
    layout: PackageManagerNativeLayout,
) -> rsbinder::TransactionCode {
    match layout {
        PackageManagerNativeLayout::Android12To14 => PM_GET_TARGET_SDK_ANDROID_12_14,
        PackageManagerNativeLayout::Android15Or16 => PM_GET_TARGET_SDK_ANDROID_15_16,
        PackageManagerNativeLayout::Android17 => unreachable!("Android 17 uses generated AIDL"),
    }
}

fn update_app_info_with_target_sdk<E: std::fmt::Debug>(
    uid: AppUid,
    pkg_name: &str,
    target_sdk: std::result::Result<i32, E>,
    app_info: &mut AppInfo,
) {
    match target_sdk {
        Err(e) => warn!("failed to get target SDK version for {uid:?} '{pkg_name}': {e:?}"),
        Ok(target_sdk) if target_sdk <= 0 => {
            warn!("unexpected target SDK version {target_sdk} for {uid:?} '{pkg_name}'");
        }
        Ok(target_sdk) => match app_info.target_sdk {
            Some(prev_lowest) if target_sdk < prev_lowest => {
                app_info.target_sdk = Some(target_sdk);
            }
            None => app_info.target_sdk = Some(target_sdk),
            _ => {}
        },
    }
}

fn update_app_info_with_location_flags<E: std::fmt::Debug>(
    uid: AppUid,
    pkg_name: &str,
    location_flags: std::result::Result<i32, E>,
    app_info: &mut AppInfo,
) {
    match location_flags {
        Err(e) => warn!("failed to get location flags for {uid:?} '{pkg_name}': {e:?}"),
        Ok(flags) if flags & LOCATION_SYSTEM != 0 => app_info.is_system_app = true,
        Ok(_) => {}
    }
}

fn package_manager_native_get_i32_for_package(
    binder: &SIBinder,
    transaction: rsbinder::TransactionCode,
    package_name: &str,
    label: &str,
) -> Result<i32> {
    let proxy = binder
        .as_proxy()
        .context("PackageManager binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare PackageManager transaction")?;
    data.write(package_name)
        .with_context(|| format!("failed to write PackageManager {label} package name"))?;

    let mut reply = proxy
        .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)
        .with_context(|| format!("PackageManager {label} transact failed"))?
        .with_context(|| format!("PackageManager {label} returned no reply"))?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .with_context(|| format!("failed to decode PackageManager {label} status"))?;
    if !status.is_ok() {
        return Err(anyhow::Error::new(status))
            .with_context(|| format!("PackageManager {label} returned non-ok status"));
    }

    reply
        .read()
        .with_context(|| format!("failed to decode PackageManager {label} result"))
}

/// Clear the current thread's `errno` value.
fn errno_clear() {
    // SAFETY: Writes to the thread's errno address should never fail
    unsafe { *libc::__errno() = 0 }
}

/// Return the current thread's `errno` value.
fn errno_read() -> libc::c_int {
    // SAFETY: Reads from the thread's errno address should never fail
    unsafe { *libc::__errno() }
}

/// A safe wrapper around [`libc::getpriority()`] for the current thread.
///
/// See: `man getpriority`
fn getpriority() -> Option<libc::c_int> {
    errno_clear();

    // SAFETY: `errno` is cleared before calling the function and checked upon return.
    let result = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };

    let errno = errno_read();
    if errno == 0 {
        Some(result)
    } else {
        warn!("getpriority() failed (errno={errno})");
        None
    }
}

/// A best-effort safe wrapper around [`libc::setpriority()`] for the current thread.
/// Failures are logged but not returned.
///
/// See: `man setpriority`
fn setpriority(prio: libc::c_int) {
    errno_clear();

    // SAFETY: `setpriority` doesn't take pointers; `errno` is cleared before calling and checked
    // upon return.
    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, prio) };
    if result != 0 {
        let errno = errno_read();
        warn!("setpriority() failed (errno={errno})");
    }
}

/// Set the priority of the current thread, but only if the thread's current priority
/// is worse (has a higher numeric value, which means it is nicer to other threads).
///
/// This is best-effort and non-atomic; it does not attempt to cope with other threads
/// changing the current thread's priority in between get and set.
pub fn self_renice(niceness: i32) {
    let Some(current) = getpriority() else { return };
    if current > niceness {
        info!("setting niceness {niceness} from current {current}");
        setpriority(niceness)
    }
}

/// Enable logging in unit tests.
#[cfg(test)]
pub fn init_test_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_test")
            .with_max_level(log::LevelFilter::Debug),
    );
}

/// Enable logging in unit tests at a specific level
#[cfg(test)]
pub fn init_test_logging_at(max_level: log::LevelFilter) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_test")
            .with_max_level(max_level),
    );
}
