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

//! Utility functions tests.

use super::*;
use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, EcCurve::EcCurve, HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyParameter::KeyParameter as KmKeyParameter, KeyParameterValue::KeyParameterValue,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use anyhow::Result;
use kmr_wire::keymint::{KeyParam, MlDsaVariant};
use kmr_wire::{KeySizeInBits, ValueNotRecognized};

#[test]
fn check_device_attestation_permissions_test() -> Result<()> {
    check_device_attestation_permissions().or_else(|error| {
        match error.root_cause().downcast_ref::<Error>() {
            // Expected: the context for this test might not be allowed to attest device IDs.
            Some(Error::Km(ErrorCode::CANNOT_ATTEST_IDS)) => Ok(()),
            // Other errors are unexpected
            _ => Err(error),
        }
    })
}

#[test]
fn user_auth_type_accepts_aidl_authenticator_union() {
    let param = KmKeyParameter {
        tag: Tag::USER_AUTH_TYPE,
        value: KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::FINGERPRINT),
    };

    assert_eq!(param.to_km().unwrap(), KeyParam::UserAuthType(2));
}

#[test]
fn user_auth_type_rejects_integer_union() {
    let param = KmKeyParameter {
        tag: Tag::USER_AUTH_TYPE,
        value: KeyParameterValue::Integer(2),
    };

    assert!(param.to_km().is_err());
}

#[test]
fn user_auth_type_returns_aidl_authenticator_union() {
    let param = key_param_to_aidl(KeyParam::UserAuthType(2), KeyMintDevice::KEY_MINT_V5).unwrap();

    assert_eq!(param.tag, Tag::USER_AUTH_TYPE);
    assert_eq!(
        param.value,
        KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::FINGERPRINT)
    );
}

#[test]
fn ml_dsa_variant_accepts_aidl_variant_union() {
    let param = KmKeyParameter {
        tag: Tag::ML_DSA_VARIANT,
        value: KeyParameterValue::MlDsaVariant(
            crate::android::hardware::security::keymint::MlDsaVariant::MlDsaVariant::ML_DSA_65,
        ),
    };

    assert_eq!(
        param.to_km().unwrap(),
        KeyParam::MlDsaVariant(MlDsaVariant::MlDsa65)
    );
}

#[test]
fn enum_key_parameters_reject_integer_union() {
    let cases = [
        Tag::PURPOSE,
        Tag::ALGORITHM,
        Tag::BLOCK_MODE,
        Tag::DIGEST,
        Tag::PADDING,
        Tag::EC_CURVE,
        Tag::RSA_OAEP_MGF_DIGEST,
        Tag::ORIGIN,
        Tag::ML_DSA_VARIANT,
        Tag::USER_AUTH_TYPE,
    ];

    for tag in cases {
        assert!(
            KmKeyParameter {
                tag,
                value: KeyParameterValue::Integer(0),
            }
            .to_km()
            .is_err(),
            "{tag:?}"
        );
    }
}

#[test]
fn unknown_key_parameter_tags_are_dropped() {
    let params = [
        KmKeyParameter {
            tag: Tag(0x6f00_0001),
            value: KeyParameterValue::Integer(0),
        },
        KmKeyParameter {
            tag: Tag::KEY_SIZE,
            value: KeyParameterValue::Integer(256),
        },
    ];

    assert_eq!(
        key_parameters_to_km(&params, KeyMintDevice::KEY_MINT_V5).unwrap(),
        vec![KeyParam::KeySize(KeySizeInBits(256))]
    );
}

#[test]
fn key_parameters_follow_keymint_profile() {
    let params = [
        KmKeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm::ML_DSA),
        },
        KmKeyParameter {
            tag: Tag::ML_DSA_VARIANT,
            value: KeyParameterValue::MlDsaVariant(
                crate::android::hardware::security::keymint::MlDsaVariant::MlDsaVariant::ML_DSA_65,
            ),
        },
    ];

    assert!(matches!(
        key_parameters_to_km(&params, KeyMintDevice::KEY_MINT_V4),
        Err(ValueNotRecognized::Algorithm)
    ));
    assert_eq!(
        key_parameters_to_km(&params[1..], KeyMintDevice::KEY_MINT_V4).unwrap(),
        Vec::<KeyParam>::new()
    );
    assert_eq!(
        key_parameters_to_km(&params, KeyMintDevice::KEY_MINT_V5).unwrap(),
        vec![
            KeyParam::Algorithm(kmr_wire::keymint::Algorithm::MlDsa),
            KeyParam::MlDsaVariant(MlDsaVariant::MlDsa65),
        ]
    );

    let curve25519 = [KmKeyParameter {
        tag: Tag::EC_CURVE,
        value: KeyParameterValue::EcCurve(EcCurve::CURVE_25519),
    }];
    assert!(matches!(
        key_parameters_to_km(&curve25519, KeyMintDevice::KEY_MINT_V1),
        Err(ValueNotRecognized::EcCurve)
    ));
    assert_eq!(
        key_parameters_to_km(&curve25519, KeyMintDevice::KEY_MINT_V2).unwrap(),
        vec![KeyParam::EcCurve(kmr_wire::keymint::EcCurve::Curve25519)]
    );

    let second_imei = [KmKeyParameter {
        tag: Tag::ATTESTATION_ID_SECOND_IMEI,
        value: KeyParameterValue::Blob(vec![1]),
    }];
    assert!(
        key_parameters_to_km(&second_imei, KeyMintDevice::KEY_MINT_V2)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        key_parameters_to_km(&second_imei, KeyMintDevice::KEY_MINT_V3).unwrap(),
        vec![KeyParam::AttestationIdSecondImei(vec![1])]
    );

    let module_hash = [KmKeyParameter {
        tag: Tag::MODULE_HASH,
        value: KeyParameterValue::Blob(vec![2]),
    }];
    assert!(
        key_parameters_to_km(&module_hash, KeyMintDevice::KEY_MINT_V3)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        key_parameters_to_km(&module_hash, KeyMintDevice::KEY_MINT_V4).unwrap(),
        vec![KeyParam::ModuleHash(vec![2])]
    );
}

#[test]
fn key_params_to_aidl_follow_keymint_profile() {
    let ml_dsa = key_param_to_aidl(
        KeyParam::MlDsaVariant(MlDsaVariant::MlDsa65),
        KeyMintDevice::KEY_MINT_V4,
    )
    .unwrap();
    assert_eq!(ml_dsa.tag, Tag::INVALID);
    assert_eq!(
        ml_dsa.value,
        KeyParameterValue::Integer(MlDsaVariant::MlDsa65 as i32)
    );

    let ml_dsa = key_param_to_aidl(
        KeyParam::MlDsaVariant(MlDsaVariant::MlDsa65),
        KeyMintDevice::KEY_MINT_V5,
    )
    .unwrap();
    assert_eq!(ml_dsa.tag, Tag::ML_DSA_VARIANT);
    assert_eq!(
        ml_dsa.value,
        KeyParameterValue::MlDsaVariant(
            crate::android::hardware::security::keymint::MlDsaVariant::MlDsaVariant::ML_DSA_65,
        )
    );

    let second_imei = key_param_to_aidl(
        KeyParam::AttestationIdSecondImei(vec![1]),
        KeyMintDevice::KEY_MINT_V2,
    )
    .unwrap();
    assert_eq!(second_imei.tag, Tag::INVALID);
    assert_eq!(second_imei.value, KeyParameterValue::Blob(vec![1]));

    let second_imei = key_param_to_aidl(
        KeyParam::AttestationIdSecondImei(vec![1]),
        KeyMintDevice::KEY_MINT_V3,
    )
    .unwrap();
    assert_eq!(second_imei.tag, Tag::ATTESTATION_ID_SECOND_IMEI);
    assert_eq!(second_imei.value, KeyParameterValue::Blob(vec![1]));

    let module_hash =
        key_param_to_aidl(KeyParam::ModuleHash(vec![2]), KeyMintDevice::KEY_MINT_V3).unwrap();
    assert_eq!(module_hash.tag, Tag::INVALID);
    assert_eq!(module_hash.value, KeyParameterValue::Blob(vec![2]));

    let module_hash =
        key_param_to_aidl(KeyParam::ModuleHash(vec![2]), KeyMintDevice::KEY_MINT_V4).unwrap();
    assert_eq!(module_hash.tag, Tag::MODULE_HASH);
    assert_eq!(module_hash.value, KeyParameterValue::Blob(vec![2]));
}

#[test]
fn invalid_enum_values_use_upstream_error_codes() {
    assert!(matches!(
        (KmKeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm(999)),
        })
        .to_km_optional(KeyMintDevice::KEY_MINT_V5),
        Err(ValueNotRecognized::Algorithm)
    ));

    let cases = [
        (
            ValueNotRecognized::KeyPurpose,
            ErrorCode::UNSUPPORTED_PURPOSE,
        ),
        (
            ValueNotRecognized::Algorithm,
            ErrorCode::UNSUPPORTED_ALGORITHM,
        ),
        (
            ValueNotRecognized::BlockMode,
            ErrorCode::UNSUPPORTED_BLOCK_MODE,
        ),
        (
            ValueNotRecognized::PaddingMode,
            ErrorCode::UNSUPPORTED_PADDING_MODE,
        ),
        (ValueNotRecognized::Digest, ErrorCode::UNSUPPORTED_DIGEST),
        (
            ValueNotRecognized::KeyFormat,
            ErrorCode::UNSUPPORTED_KEY_FORMAT,
        ),
        (ValueNotRecognized::EcCurve, ErrorCode::UNSUPPORTED_EC_CURVE),
        (
            ValueNotRecognized::MlDsaVariant,
            ErrorCode(kmr_wire::keymint::ErrorCode::UnsupportedMlDsaVariant as i32),
        ),
        (ValueNotRecognized::Bool, ErrorCode::INVALID_ARGUMENT),
    ];

    for (error, expected) in cases {
        assert_eq!(key_parameter_conversion_error_code(error), expected);
    }
}

#[test]
fn unsupported_known_key_parameters_return_tag_error() {
    let cases = [
        (
            Tag::HARDWARE_TYPE,
            KeyParameterValue::SecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
        ),
        (Tag::MIN_SECONDS_BETWEEN_OPS, KeyParameterValue::Integer(30)),
        (Tag::UNIQUE_ID, KeyParameterValue::Blob(vec![1])),
        (
            Tag::IDENTITY_CREDENTIAL_KEY,
            KeyParameterValue::BoolValue(true),
        ),
        (Tag::ASSOCIATED_DATA, KeyParameterValue::Blob(vec![2])),
        (Tag::CONFIRMATION_TOKEN, KeyParameterValue::Blob(vec![3])),
    ];

    for (tag, value) in cases {
        assert!(matches!(
            KmKeyParameter { tag, value }.to_km_optional(KeyMintDevice::KEY_MINT_V5),
            Err(ValueNotRecognized::Tag)
        ));
    }
}

#[test]
fn bool_key_parameters_require_true_bool_union() {
    let cases = [
        (Tag::CALLER_NONCE, KeyParam::CallerNonce),
        (Tag::INCLUDE_UNIQUE_ID, KeyParam::IncludeUniqueId),
        (Tag::BOOTLOADER_ONLY, KeyParam::BootloaderOnly),
        (Tag::ROLLBACK_RESISTANCE, KeyParam::RollbackResistance),
        (Tag::EARLY_BOOT_ONLY, KeyParam::EarlyBootOnly),
        (Tag::NO_AUTH_REQUIRED, KeyParam::NoAuthRequired),
        (Tag::ALLOW_WHILE_ON_BODY, KeyParam::AllowWhileOnBody),
        (
            Tag::TRUSTED_USER_PRESENCE_REQUIRED,
            KeyParam::TrustedUserPresenceRequired,
        ),
        (
            Tag::TRUSTED_CONFIRMATION_REQUIRED,
            KeyParam::TrustedConfirmationRequired,
        ),
        (
            Tag::UNLOCKED_DEVICE_REQUIRED,
            KeyParam::UnlockedDeviceRequired,
        ),
        (
            Tag::DEVICE_UNIQUE_ATTESTATION,
            KeyParam::DeviceUniqueAttestation,
        ),
        (Tag::STORAGE_KEY, KeyParam::StorageKey),
        (Tag::RESET_SINCE_ID_ROTATION, KeyParam::ResetSinceIdRotation),
    ];

    for (tag, expected) in cases {
        assert_eq!(
            KmKeyParameter {
                tag,
                value: KeyParameterValue::BoolValue(true),
            }
            .to_km()
            .unwrap(),
            expected,
            "{tag:?}"
        );
        assert!(
            KmKeyParameter {
                tag,
                value: KeyParameterValue::BoolValue(false),
            }
            .to_km()
            .is_err(),
            "{tag:?}"
        );
        assert!(
            KmKeyParameter {
                tag,
                value: KeyParameterValue::Integer(0),
            }
            .to_km()
            .is_err(),
            "{tag:?}"
        );
    }
}

fn create_key_descriptors_from_aliases(key_aliases: &[&str]) -> Vec<KeyDescriptor> {
    key_aliases
        .iter()
        .map(|key_alias| KeyDescriptor {
            domain: Domain::APP,
            nspace: 0,
            alias: Some(key_alias.to_string()),
            blob: None,
        })
        .collect::<Vec<KeyDescriptor>>()
}

fn aliases_from_key_descriptors(key_descriptors: &[KeyDescriptor]) -> Vec<String> {
    key_descriptors
        .iter()
        .map(|kd| {
            if let Some(alias) = &kd.alias {
                String::from(alias)
            } else {
                String::from("")
            }
        })
        .collect::<Vec<String>>()
}

#[test]
fn test_safe_amount_to_return() -> Result<()> {
    let key_aliases = vec!["key1", "key2", "key3"];
    let key_descriptors = create_key_descriptors_from_aliases(&key_aliases);

    assert_eq!(
        estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 20),
        1
    );
    assert_eq!(
        estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 50),
        2
    );
    assert_eq!(
        estimate_safe_amount_to_return(Domain::APP, 1017, None, &key_descriptors, 100),
        3
    );
    Ok(())
}

#[test]
fn test_merge_and_sort_lists_without_filtering() -> Result<()> {
    let legacy_key_aliases = vec!["key_c", "key_a", "key_b"];
    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
    let db_key_aliases = vec!["key_a", "key_d"];
    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
    let result =
        merge_and_filter_key_entry_lists(&legacy_key_descriptors, &db_key_descriptors, None);
    assert_eq!(
        aliases_from_key_descriptors(&result),
        vec!["key_a", "key_b", "key_c", "key_d"]
    );
    Ok(())
}

#[test]
fn test_merge_and_sort_lists_with_filtering() -> Result<()> {
    let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
    let db_key_aliases = vec!["key_c", "key_g"];
    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
    let result = merge_and_filter_key_entry_lists(
        &legacy_key_descriptors,
        &db_key_descriptors,
        Some("key_b"),
    );
    assert_eq!(
        aliases_from_key_descriptors(&result),
        vec!["key_c", "key_e", "key_f", "key_g"]
    );
    Ok(())
}

#[test]
fn test_merge_and_sort_lists_with_filtering_and_dups() -> Result<()> {
    let legacy_key_aliases = vec!["key_f", "key_a", "key_e", "key_b"];
    let legacy_key_descriptors = create_key_descriptors_from_aliases(&legacy_key_aliases);
    let db_key_aliases = vec!["key_d", "key_e", "key_g"];
    let db_key_descriptors = create_key_descriptors_from_aliases(&db_key_aliases);
    let result = merge_and_filter_key_entry_lists(
        &legacy_key_descriptors,
        &db_key_descriptors,
        Some("key_c"),
    );
    assert_eq!(
        aliases_from_key_descriptors(&result),
        vec!["key_d", "key_e", "key_f", "key_g"]
    );
    Ok(())
}

#[test]
fn test_list_key_parameters_with_filter_on_security_sensitive_info() -> Result<()> {
    let params = vec![
        KmKeyParameter {
            tag: Tag::APPLICATION_ID,
            value: KeyParameterValue::Integer(0),
        },
        KmKeyParameter {
            tag: Tag::APPLICATION_DATA,
            value: KeyParameterValue::Integer(0),
        },
        KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_AFTER,
            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
        },
        KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_BEFORE,
            value: KeyParameterValue::DateTime(0),
        },
    ];
    let wanted = vec![
        KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_AFTER,
            value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
        },
        KmKeyParameter {
            tag: Tag::CERTIFICATE_NOT_BEFORE,
            value: KeyParameterValue::DateTime(0),
        },
    ];

    assert_eq!(log_security_safe_params(&params), wanted);
    Ok(())
}

#[test]
fn test_app_info_for_uid() -> Result<()> {
    init_test_logging();
    assert_eq!(
        app_info_for_uid(AppUid(999_999)),
        AppInfo {
            target_sdk: None,
            is_system_app: false
        }
    );

    // Try retrieving some system uids; these generally map to a "shared:<pkgname>" that does not
    // have target SDK information.
    for uid in [
        AID_SYSTEM,   // AID_SYSTEM => "shared:android.uid.system"
        AppUid(1001), // AID_RADIO => "shared:android.uid.phone"
        AppUid(1073), // AID_NETWORK_STACK => "shared:android.uid.networkstack"
    ] {
        let app_info = app_info_for_uid(uid);
        log::info!("{uid:?} => {app_info:?}");
    }
    Ok(())
}

#[test]
fn test_package_manager_native_layout() {
    assert_eq!(
        package_manager_native_layout(Some(12)),
        PackageManagerNativeLayout::Android12To14
    );
    assert_eq!(
        package_manager_native_layout(Some(14)),
        PackageManagerNativeLayout::Android12To14
    );
    assert_eq!(
        package_manager_native_layout(Some(15)),
        PackageManagerNativeLayout::Android15Or16
    );
    assert_eq!(
        package_manager_native_layout(Some(16)),
        PackageManagerNativeLayout::Android15Or16
    );
    assert_eq!(
        package_manager_native_layout(Some(17)),
        PackageManagerNativeLayout::Android17
    );
    assert_eq!(
        package_manager_native_layout(Some(18)),
        PackageManagerNativeLayout::Android17
    );
    assert_eq!(
        package_manager_native_layout(None),
        PackageManagerNativeLayout::Android15Or16
    );
    assert_eq!(
        legacy_pm_transactions(PackageManagerNativeLayout::Android12To14),
        (
            rsbinder::FIRST_CALL_TRANSACTION + 5,
            rsbinder::FIRST_CALL_TRANSACTION + 4
        )
    );
    assert_eq!(
        legacy_pm_transactions(PackageManagerNativeLayout::Android15Or16),
        (
            rsbinder::FIRST_CALL_TRANSACTION + 6,
            rsbinder::FIRST_CALL_TRANSACTION + 5
        )
    );
}
