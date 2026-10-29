use super::*;

fn tx(offset: u32) -> u32 {
    rsbinder::FIRST_CALL_TRANSACTION + offset
}

type MethodLayout<'a, T> = (&'a [Option<i32>], &'a [(u32, T)], u32);

#[test]
fn authorization_method_codes_follow_supported_layouts() {
    const CURRENT_CASES: &[(u32, AuthorizationMethod)] = &[
        (authorization_tx::r#addAuthToken, AuthorizationMethod::AddAuthToken),
        (authorization_tx::r#onDeviceUnlocked, AuthorizationMethod::OnDeviceUnlocked),
        (authorization_tx::r#onDeviceLocked, AuthorizationMethod::OnDeviceLocked),
        (authorization_tx::r#onUserStorageLocked, AuthorizationMethod::OnUserStorageLocked),
        (
            authorization_tx::r#onWeakUnlockMethodsExpired,
            AuthorizationMethod::OnWeakUnlockMethodsExpired,
        ),
        (
            authorization_tx::r#onNonLskfUnlockMethodsExpired,
            AuthorizationMethod::OnNonLskfUnlockMethodsExpired,
        ),
        (
            authorization_tx::r#getAuthTokensForCredStore,
            AuthorizationMethod::GetAuthTokensForCredStore,
        ),
        (authorization_tx::r#getLastAuthTime, AuthorizationMethod::GetLastAuthTime),
    ];
    let android_12_to_14_cases = [
        (tx(0), AuthorizationMethod::AddAuthToken),
        (tx(1), AuthorizationMethod::LegacyOnLockScreenEvent),
        (tx(2), AuthorizationMethod::GetAuthTokensForCredStore),
    ];
    let android_15_to_16_cases = [
        (tx(0), AuthorizationMethod::AddAuthToken),
        (tx(1), AuthorizationMethod::OnDeviceUnlocked),
        (tx(2), AuthorizationMethod::OnDeviceLocked),
        (tx(3), AuthorizationMethod::OnWeakUnlockMethodsExpired),
        (tx(4), AuthorizationMethod::OnNonLskfUnlockMethodsExpired),
        (tx(5), AuthorizationMethod::GetAuthTokensForCredStore),
        (tx(6), AuthorizationMethod::GetLastAuthTime),
    ];

    let layouts: [MethodLayout<'_, AuthorizationMethod>; 3] = [
        (&[Some(17), None], CURRENT_CASES, u32::MAX),
        (&[Some(12), Some(13), Some(14)], &android_12_to_14_cases, tx(3)),
        (&[Some(15), Some(16)], &android_15_to_16_cases, tx(7)),
    ];
    for (versions, cases, invalid_code) in layouts {
        for &version in versions {
            for &(code, expected) in cases {
                assert_eq!(
                    authorization_method_from_code_for(version, code),
                    Some(expected),
                    "version={version:?} code={code}"
                );
            }
            assert_eq!(
                authorization_method_from_code_for(version, invalid_code),
                None,
                "version={version:?} out of range"
            );
        }
    }
}

#[test]
fn maintenance_method_codes_follow_supported_layouts() {
    const CURRENT_CASES: &[(u32, MaintenanceMethod)] = &[
        (maintenance_tx::r#onUserAdded, MaintenanceMethod::OnUserAdded),
        (maintenance_tx::r#initUserSuperKeys, MaintenanceMethod::InitUserSuperKeys),
        (maintenance_tx::r#onUserRemoved, MaintenanceMethod::OnUserRemoved),
        (maintenance_tx::r#onUserLskfRemoved, MaintenanceMethod::OnUserLskfRemoved),
        (maintenance_tx::r#clearNamespace, MaintenanceMethod::ClearNamespace),
        (maintenance_tx::r#earlyBootEnded, MaintenanceMethod::EarlyBootEnded),
        (maintenance_tx::r#migrateKeyNamespace, MaintenanceMethod::MigrateKeyNamespace),
        (maintenance_tx::r#deleteAllKeys, MaintenanceMethod::DeleteAllKeys),
        (maintenance_tx::r#getAppUidsAffectedBySid, MaintenanceMethod::GetAppUidsAffectedBySid),
    ];
    let android_12_to_14_cases = [
        (tx(0), MaintenanceMethod::OnUserAdded),
        (tx(1), MaintenanceMethod::OnUserRemoved),
        (tx(2), MaintenanceMethod::OnUserPasswordChanged),
        (tx(3), MaintenanceMethod::ClearNamespace),
        (tx(4), MaintenanceMethod::GetState),
        (tx(5), MaintenanceMethod::EarlyBootEnded),
        (tx(6), MaintenanceMethod::OnDeviceOffBody),
        (tx(7), MaintenanceMethod::MigrateKeyNamespace),
        (tx(8), MaintenanceMethod::DeleteAllKeys),
    ];
    let android_15_cases = [
        (tx(0), MaintenanceMethod::OnUserAdded),
        (tx(1), MaintenanceMethod::InitUserSuperKeys),
        (tx(2), MaintenanceMethod::OnUserRemoved),
        (tx(3), MaintenanceMethod::OnUserLskfRemoved),
        (tx(4), MaintenanceMethod::OnUserPasswordChanged),
        (tx(5), MaintenanceMethod::ClearNamespace),
        (tx(6), MaintenanceMethod::EarlyBootEnded),
        (tx(7), MaintenanceMethod::MigrateKeyNamespace),
        (tx(8), MaintenanceMethod::DeleteAllKeys),
        (tx(9), MaintenanceMethod::GetAppUidsAffectedBySid),
    ];

    let layouts: [MethodLayout<'_, MaintenanceMethod>; 3] = [
        (&[Some(16), Some(17), None], CURRENT_CASES, u32::MAX),
        (&[Some(12), Some(13), Some(14)], &android_12_to_14_cases, tx(9)),
        (&[Some(15)], &android_15_cases, tx(10)),
    ];
    for (versions, cases, invalid_code) in layouts {
        for &version in versions {
            for &(code, expected) in cases {
                assert_eq!(
                    maintenance_method_from_code_for(version, code),
                    Some(expected),
                    "version={version:?} code={code}"
                );
            }
            assert_eq!(
                maintenance_method_from_code_for(version, invalid_code),
                None,
                "version={version:?} out of range"
            );
        }
    }
}

#[test]
fn service_method_codes_follow_supported_layouts() {
    const CURRENT_CASES: &[(u32, ServiceMethod)] = &[
        (service_tx::r#getSecurityLevel, ServiceMethod::GetSecurityLevel),
        (service_tx::r#getKeyEntry, ServiceMethod::GetKeyEntry),
        (service_tx::r#updateSubcomponent, ServiceMethod::UpdateSubcomponent),
        (service_tx::r#listEntries, ServiceMethod::ListEntries),
        (service_tx::r#deleteKey, ServiceMethod::DeleteKey),
        (service_tx::r#grant, ServiceMethod::Grant),
        (service_tx::r#ungrant, ServiceMethod::Ungrant),
        (service_tx::r#getNumberOfEntries, ServiceMethod::GetNumberOfEntries),
        (service_tx::r#listEntriesBatched, ServiceMethod::ListEntriesBatched),
        (
            service_tx::r#getSupplementaryAttestationInfo,
            ServiceMethod::GetSupplementaryAttestationInfo,
        ),
    ];
    let android_12_to_13_cases = [
        (tx(0), ServiceMethod::GetSecurityLevel),
        (tx(1), ServiceMethod::GetKeyEntry),
        (tx(2), ServiceMethod::UpdateSubcomponent),
        (tx(3), ServiceMethod::ListEntries),
        (tx(4), ServiceMethod::DeleteKey),
        (tx(5), ServiceMethod::Grant),
        (tx(6), ServiceMethod::Ungrant),
    ];
    let android_14_to_15_cases = [
        (tx(0), ServiceMethod::GetSecurityLevel),
        (tx(1), ServiceMethod::GetKeyEntry),
        (tx(2), ServiceMethod::UpdateSubcomponent),
        (tx(3), ServiceMethod::ListEntries),
        (tx(4), ServiceMethod::DeleteKey),
        (tx(5), ServiceMethod::Grant),
        (tx(6), ServiceMethod::Ungrant),
        (tx(7), ServiceMethod::GetNumberOfEntries),
        (tx(8), ServiceMethod::ListEntriesBatched),
    ];

    let layouts: [MethodLayout<'_, ServiceMethod>; 3] = [
        (&[Some(16), Some(17), None], CURRENT_CASES, u32::MAX),
        (&[Some(12), Some(13)], &android_12_to_13_cases, tx(7)),
        (&[Some(14), Some(15)], &android_14_to_15_cases, tx(9)),
    ];
    for (versions, cases, invalid_code) in layouts {
        for &version in versions {
            for &(code, expected) in cases {
                assert_eq!(
                    service_method_from_code_for(version, code),
                    Some(expected),
                    "version={version:?} code={code}"
                );
            }
            assert_eq!(
                service_method_from_code_for(version, invalid_code),
                None,
                "version={version:?} out of range"
            );
        }
    }
}

#[test]
fn security_level_method_codes_follow_generated_aidl_constants() {
    let cases = [
        (security_level_tx::r#createOperation, SecurityLevelMethod::CreateOperation),
        (security_level_tx::r#generateKey, SecurityLevelMethod::GenerateKey),
        (security_level_tx::r#importKey, SecurityLevelMethod::ImportKey),
        (security_level_tx::r#importWrappedKey, SecurityLevelMethod::ImportWrappedKey),
        (
            security_level_tx::r#convertStorageKeyToEphemeral,
            SecurityLevelMethod::ConvertStorageKeyToEphemeral,
        ),
        (security_level_tx::r#deleteKey, SecurityLevelMethod::DeleteKey),
    ];

    for (code, expected) in cases {
        assert_eq!(security_level_method_from_code(code), Some(expected));
    }

    assert_eq!(security_level_method_from_code(u32::MAX), None);
    assert_eq!(security_level_method_from_code(AIDL_GET_INTERFACE_HASH_TRANSACTION), None);
    assert_eq!(security_level_method_from_code(AIDL_GET_INTERFACE_VERSION_TRANSACTION), None);
}

#[test]
fn operation_method_codes_follow_generated_aidl_constants() {
    let cases = [
        (operation_tx::r#updateAad, OperationMethod::UpdateAad),
        (operation_tx::r#update, OperationMethod::Update),
        (operation_tx::r#finish, OperationMethod::Finish),
        (operation_tx::r#abort, OperationMethod::Abort),
    ];

    for (code, expected) in cases {
        assert_eq!(operation_method_from_code(code), Some(expected));
    }

    assert_eq!(operation_method_from_code(u32::MAX), None);
    assert_eq!(operation_method_from_code(AIDL_GET_INTERFACE_HASH_TRANSACTION), None);
    assert_eq!(operation_method_from_code(AIDL_GET_INTERFACE_VERSION_TRANSACTION), None);
}

#[test]
fn aidl_metadata_codes_are_not_business_methods() {
    assert_eq!(
        aidl_metadata_method_from_code(AIDL_GET_INTERFACE_HASH_TRANSACTION),
        Some(AidlMetadataMethod::GetInterfaceHash)
    );
    assert_eq!(
        aidl_metadata_method_from_code(AIDL_GET_INTERFACE_VERSION_TRANSACTION),
        Some(AidlMetadataMethod::GetInterfaceVersion)
    );
    assert_eq!(aidl_metadata_method_from_code(u32::MAX), None);
}
