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
    HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyParameter::KeyParameter as KmKeyParameter, KeyParameterValue::KeyParameterValue, Tag::Tag,
};
use anyhow::Result;
use kmr_wire::keymint::KeyParam;

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
fn user_auth_type_returns_aidl_authenticator_union() {
    let param = key_param_to_aidl(KeyParam::UserAuthType(2)).unwrap();

    assert_eq!(param.tag, Tag::USER_AUTH_TYPE);
    assert_eq!(
        param.value,
        KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::FINGERPRINT)
    );
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
        legacy_pm_get_location_flags_transaction(PackageManagerNativeLayout::Android12To14),
        rsbinder::FIRST_CALL_TRANSACTION + 4
    );
    assert_eq!(
        legacy_pm_get_target_sdk_transaction(PackageManagerNativeLayout::Android12To14),
        rsbinder::FIRST_CALL_TRANSACTION + 5
    );
    assert_eq!(
        legacy_pm_get_location_flags_transaction(PackageManagerNativeLayout::Android15Or16),
        rsbinder::FIRST_CALL_TRANSACTION + 5
    );
    assert_eq!(
        legacy_pm_get_target_sdk_transaction(PackageManagerNativeLayout::Android15Or16),
        rsbinder::FIRST_CALL_TRANSACTION + 6
    );
}
