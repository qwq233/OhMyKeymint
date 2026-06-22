use crate::android::security::authorization::IKeystoreAuthorization::transactions as authorization_tx;
use crate::android::security::maintenance::IKeystoreMaintenance::transactions as maintenance_tx;
use crate::android::system::keystore2::IKeystoreOperation::transactions as operation_tx;
use crate::android::system::keystore2::IKeystoreSecurityLevel::transactions as security_level_tx;
use crate::android::system::keystore2::IKeystoreService::transactions as service_tx;
use crate::config::InterceptConfig;

pub const KEYSTORE_AUTHORIZATION_INTERFACE: &str =
    "android.security.authorization.IKeystoreAuthorization";
pub const KEYSTORE_MAINTENANCE_INTERFACE: &str =
    "android.security.maintenance.IKeystoreMaintenance";
pub const KEYSTORE_SERVICE_INTERFACE: &str = "android.system.keystore2.IKeystoreService";
pub const KEYSTORE_SECURITY_LEVEL_INTERFACE: &str =
    "android.system.keystore2.IKeystoreSecurityLevel";
pub const KEYSTORE_OPERATION_INTERFACE: &str = "android.system.keystore2.IKeystoreOperation";

pub const AIDL_GET_INTERFACE_HASH_TRANSACTION: u32 =
    kmr_common::consts::AIDL_GET_INTERFACE_HASH_TRANSACTION;
pub const AIDL_GET_INTERFACE_VERSION_TRANSACTION: u32 =
    kmr_common::consts::AIDL_GET_INTERFACE_VERSION_TRANSACTION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AidlMetadataMethod {
    GetInterfaceHash,
    GetInterfaceVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationMethod {
    AddAuthToken,
    LegacyOnLockScreenEvent,
    OnDeviceUnlocked,
    OnDeviceLocked,
    OnUserStorageLocked,
    OnWeakUnlockMethodsExpired,
    OnNonLskfUnlockMethodsExpired,
    GetAuthTokensForCredStore,
    GetLastAuthTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceMethod {
    OnUserAdded,
    InitUserSuperKeys,
    OnUserRemoved,
    OnUserLskfRemoved,
    OnUserPasswordChanged,
    ClearNamespace,
    GetState,
    EarlyBootEnded,
    OnDeviceOffBody,
    MigrateKeyNamespace,
    DeleteAllKeys,
    GetAppUidsAffectedBySid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMethod {
    GetSecurityLevel,
    GetKeyEntry,
    UpdateSubcomponent,
    ListEntries,
    DeleteKey,
    Grant,
    Ungrant,
    GetNumberOfEntries,
    ListEntriesBatched,
    GetSupplementaryAttestationInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevelMethod {
    CreateOperation,
    GenerateKey,
    ImportKey,
    ImportWrappedKey,
    ConvertStorageKeyToEphemeral,
    DeleteKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMethod {
    UpdateAad,
    Update,
    Finish,
    Abort,
}

pub fn aidl_metadata_method_from_code(code: u32) -> Option<AidlMetadataMethod> {
    match code {
        AIDL_GET_INTERFACE_HASH_TRANSACTION => Some(AidlMetadataMethod::GetInterfaceHash),
        AIDL_GET_INTERFACE_VERSION_TRANSACTION => Some(AidlMetadataMethod::GetInterfaceVersion),
        _ => None,
    }
}

fn transaction_offset(code: u32) -> Option<u32> {
    code.checked_sub(rsbinder::FIRST_CALL_TRANSACTION)
}

pub fn authorization_method_from_code_for(
    android_major_version: Option<i32>,
    code: u32,
) -> Option<AuthorizationMethod> {
    match android_major_version {
        Some(version) if version <= 14 => match transaction_offset(code)? {
            0 => Some(AuthorizationMethod::AddAuthToken),
            1 => Some(AuthorizationMethod::LegacyOnLockScreenEvent),
            2 => Some(AuthorizationMethod::GetAuthTokensForCredStore),
            _ => None,
        },
        Some(15 | 16) => match transaction_offset(code)? {
            0 => Some(AuthorizationMethod::AddAuthToken),
            1 => Some(AuthorizationMethod::OnDeviceUnlocked),
            2 => Some(AuthorizationMethod::OnDeviceLocked),
            3 => Some(AuthorizationMethod::OnWeakUnlockMethodsExpired),
            4 => Some(AuthorizationMethod::OnNonLskfUnlockMethodsExpired),
            5 => Some(AuthorizationMethod::GetAuthTokensForCredStore),
            6 => Some(AuthorizationMethod::GetLastAuthTime),
            _ => None,
        },
        _ => current_authorization_method_from_code(code),
    }
}

pub fn authorization_method_from_code(code: u32) -> Option<AuthorizationMethod> {
    authorization_method_from_code_for(kmr_common::android_version::android_major_version(), code)
}

fn current_authorization_method_from_code(code: u32) -> Option<AuthorizationMethod> {
    match code {
        authorization_tx::r#addAuthToken => Some(AuthorizationMethod::AddAuthToken),
        authorization_tx::r#onDeviceUnlocked => Some(AuthorizationMethod::OnDeviceUnlocked),
        authorization_tx::r#onDeviceLocked => Some(AuthorizationMethod::OnDeviceLocked),
        authorization_tx::r#onUserStorageLocked => Some(AuthorizationMethod::OnUserStorageLocked),
        authorization_tx::r#onWeakUnlockMethodsExpired => {
            Some(AuthorizationMethod::OnWeakUnlockMethodsExpired)
        }
        authorization_tx::r#onNonLskfUnlockMethodsExpired => {
            Some(AuthorizationMethod::OnNonLskfUnlockMethodsExpired)
        }
        authorization_tx::r#getAuthTokensForCredStore => {
            Some(AuthorizationMethod::GetAuthTokensForCredStore)
        }
        authorization_tx::r#getLastAuthTime => Some(AuthorizationMethod::GetLastAuthTime),
        _ => None,
    }
}

pub fn maintenance_method_from_code_for(
    android_major_version: Option<i32>,
    code: u32,
) -> Option<MaintenanceMethod> {
    match android_major_version {
        Some(version) if version <= 14 => match transaction_offset(code)? {
            0 => Some(MaintenanceMethod::OnUserAdded),
            1 => Some(MaintenanceMethod::OnUserRemoved),
            2 => Some(MaintenanceMethod::OnUserPasswordChanged),
            3 => Some(MaintenanceMethod::ClearNamespace),
            4 => Some(MaintenanceMethod::GetState),
            5 => Some(MaintenanceMethod::EarlyBootEnded),
            6 => Some(MaintenanceMethod::OnDeviceOffBody),
            7 => Some(MaintenanceMethod::MigrateKeyNamespace),
            8 => Some(MaintenanceMethod::DeleteAllKeys),
            _ => None,
        },
        Some(15) => match transaction_offset(code)? {
            0 => Some(MaintenanceMethod::OnUserAdded),
            1 => Some(MaintenanceMethod::InitUserSuperKeys),
            2 => Some(MaintenanceMethod::OnUserRemoved),
            3 => Some(MaintenanceMethod::OnUserLskfRemoved),
            4 => Some(MaintenanceMethod::OnUserPasswordChanged),
            5 => Some(MaintenanceMethod::ClearNamespace),
            6 => Some(MaintenanceMethod::EarlyBootEnded),
            7 => Some(MaintenanceMethod::MigrateKeyNamespace),
            8 => Some(MaintenanceMethod::DeleteAllKeys),
            9 => Some(MaintenanceMethod::GetAppUidsAffectedBySid),
            _ => None,
        },
        _ => current_maintenance_method_from_code(code),
    }
}

pub fn maintenance_method_from_code(code: u32) -> Option<MaintenanceMethod> {
    maintenance_method_from_code_for(kmr_common::android_version::android_major_version(), code)
}

fn current_maintenance_method_from_code(code: u32) -> Option<MaintenanceMethod> {
    match code {
        maintenance_tx::r#onUserAdded => Some(MaintenanceMethod::OnUserAdded),
        maintenance_tx::r#initUserSuperKeys => Some(MaintenanceMethod::InitUserSuperKeys),
        maintenance_tx::r#onUserRemoved => Some(MaintenanceMethod::OnUserRemoved),
        maintenance_tx::r#onUserLskfRemoved => Some(MaintenanceMethod::OnUserLskfRemoved),
        maintenance_tx::r#clearNamespace => Some(MaintenanceMethod::ClearNamespace),
        maintenance_tx::r#earlyBootEnded => Some(MaintenanceMethod::EarlyBootEnded),
        maintenance_tx::r#migrateKeyNamespace => Some(MaintenanceMethod::MigrateKeyNamespace),
        maintenance_tx::r#deleteAllKeys => Some(MaintenanceMethod::DeleteAllKeys),
        maintenance_tx::r#getAppUidsAffectedBySid => {
            Some(MaintenanceMethod::GetAppUidsAffectedBySid)
        }
        _ => None,
    }
}

pub fn service_method_from_code_for(
    android_major_version: Option<i32>,
    code: u32,
) -> Option<ServiceMethod> {
    match android_major_version {
        Some(12 | 13) => match transaction_offset(code)? {
            0 => Some(ServiceMethod::GetSecurityLevel),
            1 => Some(ServiceMethod::GetKeyEntry),
            2 => Some(ServiceMethod::UpdateSubcomponent),
            3 => Some(ServiceMethod::ListEntries),
            4 => Some(ServiceMethod::DeleteKey),
            5 => Some(ServiceMethod::Grant),
            6 => Some(ServiceMethod::Ungrant),
            _ => None,
        },
        Some(14 | 15) => match transaction_offset(code)? {
            0 => Some(ServiceMethod::GetSecurityLevel),
            1 => Some(ServiceMethod::GetKeyEntry),
            2 => Some(ServiceMethod::UpdateSubcomponent),
            3 => Some(ServiceMethod::ListEntries),
            4 => Some(ServiceMethod::DeleteKey),
            5 => Some(ServiceMethod::Grant),
            6 => Some(ServiceMethod::Ungrant),
            7 => Some(ServiceMethod::GetNumberOfEntries),
            8 => Some(ServiceMethod::ListEntriesBatched),
            _ => None,
        },
        _ => current_service_method_from_code(code),
    }
}

pub fn service_method_from_code(code: u32) -> Option<ServiceMethod> {
    service_method_from_code_for(kmr_common::android_version::android_major_version(), code)
}

fn current_service_method_from_code(code: u32) -> Option<ServiceMethod> {
    match code {
        service_tx::r#getSecurityLevel => Some(ServiceMethod::GetSecurityLevel),
        service_tx::r#getKeyEntry => Some(ServiceMethod::GetKeyEntry),
        service_tx::r#updateSubcomponent => Some(ServiceMethod::UpdateSubcomponent),
        service_tx::r#listEntries => Some(ServiceMethod::ListEntries),
        service_tx::r#deleteKey => Some(ServiceMethod::DeleteKey),
        service_tx::r#grant => Some(ServiceMethod::Grant),
        service_tx::r#ungrant => Some(ServiceMethod::Ungrant),
        service_tx::r#getNumberOfEntries => Some(ServiceMethod::GetNumberOfEntries),
        service_tx::r#listEntriesBatched => Some(ServiceMethod::ListEntriesBatched),
        service_tx::r#getSupplementaryAttestationInfo => {
            Some(ServiceMethod::GetSupplementaryAttestationInfo)
        }
        _ => None,
    }
}

pub fn security_level_method_from_code(code: u32) -> Option<SecurityLevelMethod> {
    match code {
        security_level_tx::r#createOperation => Some(SecurityLevelMethod::CreateOperation),
        security_level_tx::r#generateKey => Some(SecurityLevelMethod::GenerateKey),
        security_level_tx::r#importKey => Some(SecurityLevelMethod::ImportKey),
        security_level_tx::r#importWrappedKey => Some(SecurityLevelMethod::ImportWrappedKey),
        security_level_tx::r#convertStorageKeyToEphemeral => {
            Some(SecurityLevelMethod::ConvertStorageKeyToEphemeral)
        }
        security_level_tx::r#deleteKey => Some(SecurityLevelMethod::DeleteKey),
        _ => None,
    }
}

pub fn operation_method_from_code(code: u32) -> Option<OperationMethod> {
    match code {
        operation_tx::r#updateAad => Some(OperationMethod::UpdateAad),
        operation_tx::r#update => Some(OperationMethod::Update),
        operation_tx::r#finish => Some(OperationMethod::Finish),
        operation_tx::r#abort => Some(OperationMethod::Abort),
        _ => None,
    }
}

pub fn is_omk_service_route_enabled(method: ServiceMethod, intercept: &InterceptConfig) -> bool {
    match method {
        ServiceMethod::GetSecurityLevel => intercept.get_security_level,
        ServiceMethod::GetKeyEntry => intercept.get_key_entry,
        ServiceMethod::UpdateSubcomponent => intercept.update_subcomponent,
        ServiceMethod::ListEntries => intercept.list_entries,
        ServiceMethod::DeleteKey => intercept.delete_key,
        ServiceMethod::Grant => intercept.grant,
        ServiceMethod::Ungrant => intercept.ungrant,
        ServiceMethod::GetNumberOfEntries => intercept.get_number_of_entries,
        ServiceMethod::ListEntriesBatched => intercept.list_entries_batched,
        ServiceMethod::GetSupplementaryAttestationInfo => {
            intercept.get_supplementary_attestation_info
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(offset: u32) -> u32 {
        rsbinder::FIRST_CALL_TRANSACTION + offset
    }

    #[test]
    fn authorization_method_codes_follow_current_generated_aidl_constants() {
        let cases = [
            (
                authorization_tx::r#addAuthToken,
                AuthorizationMethod::AddAuthToken,
            ),
            (
                authorization_tx::r#onDeviceUnlocked,
                AuthorizationMethod::OnDeviceUnlocked,
            ),
            (
                authorization_tx::r#onDeviceLocked,
                AuthorizationMethod::OnDeviceLocked,
            ),
            (
                authorization_tx::r#onUserStorageLocked,
                AuthorizationMethod::OnUserStorageLocked,
            ),
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
            (
                authorization_tx::r#getLastAuthTime,
                AuthorizationMethod::GetLastAuthTime,
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                authorization_method_from_code_for(Some(17), code),
                Some(expected)
            );
            assert_eq!(
                authorization_method_from_code_for(None, code),
                Some(expected)
            );
        }

        assert_eq!(authorization_method_from_code_for(Some(17), u32::MAX), None);
    }

    #[test]
    fn authorization_method_codes_follow_android_12_to_14_layout() {
        let cases = [
            (0, AuthorizationMethod::AddAuthToken),
            (1, AuthorizationMethod::LegacyOnLockScreenEvent),
            (2, AuthorizationMethod::GetAuthTokensForCredStore),
        ];

        for version in [Some(12), Some(13), Some(14)] {
            for (offset, expected) in cases {
                assert_eq!(
                    authorization_method_from_code_for(version, tx(offset)),
                    Some(expected)
                );
            }
            assert_eq!(authorization_method_from_code_for(version, tx(3)), None);
        }
    }

    #[test]
    fn authorization_method_codes_follow_android_15_to_16_layout() {
        let cases = [
            (0, AuthorizationMethod::AddAuthToken),
            (1, AuthorizationMethod::OnDeviceUnlocked),
            (2, AuthorizationMethod::OnDeviceLocked),
            (3, AuthorizationMethod::OnWeakUnlockMethodsExpired),
            (4, AuthorizationMethod::OnNonLskfUnlockMethodsExpired),
            (5, AuthorizationMethod::GetAuthTokensForCredStore),
            (6, AuthorizationMethod::GetLastAuthTime),
        ];

        for version in [Some(15), Some(16)] {
            for (offset, expected) in cases {
                assert_eq!(
                    authorization_method_from_code_for(version, tx(offset)),
                    Some(expected)
                );
            }
            assert_eq!(authorization_method_from_code_for(version, tx(7)), None);
        }
    }

    #[test]
    fn maintenance_method_codes_follow_current_generated_aidl_constants() {
        let cases = [
            (
                maintenance_tx::r#onUserAdded,
                MaintenanceMethod::OnUserAdded,
            ),
            (
                maintenance_tx::r#initUserSuperKeys,
                MaintenanceMethod::InitUserSuperKeys,
            ),
            (
                maintenance_tx::r#onUserRemoved,
                MaintenanceMethod::OnUserRemoved,
            ),
            (
                maintenance_tx::r#onUserLskfRemoved,
                MaintenanceMethod::OnUserLskfRemoved,
            ),
            (
                maintenance_tx::r#clearNamespace,
                MaintenanceMethod::ClearNamespace,
            ),
            (
                maintenance_tx::r#earlyBootEnded,
                MaintenanceMethod::EarlyBootEnded,
            ),
            (
                maintenance_tx::r#migrateKeyNamespace,
                MaintenanceMethod::MigrateKeyNamespace,
            ),
            (
                maintenance_tx::r#deleteAllKeys,
                MaintenanceMethod::DeleteAllKeys,
            ),
            (
                maintenance_tx::r#getAppUidsAffectedBySid,
                MaintenanceMethod::GetAppUidsAffectedBySid,
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                maintenance_method_from_code_for(Some(17), code),
                Some(expected)
            );
            assert_eq!(maintenance_method_from_code_for(None, code), Some(expected));
        }

        assert_eq!(maintenance_method_from_code_for(Some(17), u32::MAX), None);
    }

    #[test]
    fn maintenance_method_codes_follow_android_12_to_14_layout() {
        let cases = [
            (0, MaintenanceMethod::OnUserAdded),
            (1, MaintenanceMethod::OnUserRemoved),
            (2, MaintenanceMethod::OnUserPasswordChanged),
            (3, MaintenanceMethod::ClearNamespace),
            (4, MaintenanceMethod::GetState),
            (5, MaintenanceMethod::EarlyBootEnded),
            (6, MaintenanceMethod::OnDeviceOffBody),
            (7, MaintenanceMethod::MigrateKeyNamespace),
            (8, MaintenanceMethod::DeleteAllKeys),
        ];

        for version in [Some(12), Some(13), Some(14)] {
            for (offset, expected) in cases {
                assert_eq!(
                    maintenance_method_from_code_for(version, tx(offset)),
                    Some(expected)
                );
            }
            assert_eq!(maintenance_method_from_code_for(version, tx(9)), None);
        }
    }

    #[test]
    fn maintenance_method_codes_follow_android_15_layout() {
        let cases = [
            (0, MaintenanceMethod::OnUserAdded),
            (1, MaintenanceMethod::InitUserSuperKeys),
            (2, MaintenanceMethod::OnUserRemoved),
            (3, MaintenanceMethod::OnUserLskfRemoved),
            (4, MaintenanceMethod::OnUserPasswordChanged),
            (5, MaintenanceMethod::ClearNamespace),
            (6, MaintenanceMethod::EarlyBootEnded),
            (7, MaintenanceMethod::MigrateKeyNamespace),
            (8, MaintenanceMethod::DeleteAllKeys),
            (9, MaintenanceMethod::GetAppUidsAffectedBySid),
        ];

        for (offset, expected) in cases {
            assert_eq!(
                maintenance_method_from_code_for(Some(15), tx(offset)),
                Some(expected)
            );
        }
        assert_eq!(maintenance_method_from_code_for(Some(15), tx(10)), None);
    }

    #[test]
    fn service_method_codes_follow_current_generated_aidl_constants() {
        let cases = [
            (
                service_tx::r#getSecurityLevel,
                ServiceMethod::GetSecurityLevel,
            ),
            (service_tx::r#getKeyEntry, ServiceMethod::GetKeyEntry),
            (
                service_tx::r#updateSubcomponent,
                ServiceMethod::UpdateSubcomponent,
            ),
            (service_tx::r#listEntries, ServiceMethod::ListEntries),
            (service_tx::r#deleteKey, ServiceMethod::DeleteKey),
            (service_tx::r#grant, ServiceMethod::Grant),
            (service_tx::r#ungrant, ServiceMethod::Ungrant),
            (
                service_tx::r#getNumberOfEntries,
                ServiceMethod::GetNumberOfEntries,
            ),
            (
                service_tx::r#listEntriesBatched,
                ServiceMethod::ListEntriesBatched,
            ),
            (
                service_tx::r#getSupplementaryAttestationInfo,
                ServiceMethod::GetSupplementaryAttestationInfo,
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(service_method_from_code_for(Some(17), code), Some(expected));
            assert_eq!(service_method_from_code_for(None, code), Some(expected));
        }

        assert_eq!(service_method_from_code_for(Some(17), u32::MAX), None);
    }

    #[test]
    fn service_method_codes_follow_android_12_to_13_layout() {
        let cases = [
            (0, ServiceMethod::GetSecurityLevel),
            (1, ServiceMethod::GetKeyEntry),
            (2, ServiceMethod::UpdateSubcomponent),
            (3, ServiceMethod::ListEntries),
            (4, ServiceMethod::DeleteKey),
            (5, ServiceMethod::Grant),
            (6, ServiceMethod::Ungrant),
        ];

        for version in [Some(12), Some(13)] {
            for (offset, expected) in cases {
                assert_eq!(
                    service_method_from_code_for(version, tx(offset)),
                    Some(expected)
                );
            }
            assert_eq!(service_method_from_code_for(version, tx(7)), None);
        }
    }

    #[test]
    fn service_method_codes_follow_android_14_to_15_layout() {
        let cases = [
            (0, ServiceMethod::GetSecurityLevel),
            (1, ServiceMethod::GetKeyEntry),
            (2, ServiceMethod::UpdateSubcomponent),
            (3, ServiceMethod::ListEntries),
            (4, ServiceMethod::DeleteKey),
            (5, ServiceMethod::Grant),
            (6, ServiceMethod::Ungrant),
            (7, ServiceMethod::GetNumberOfEntries),
            (8, ServiceMethod::ListEntriesBatched),
        ];

        for version in [Some(14), Some(15)] {
            for (offset, expected) in cases {
                assert_eq!(
                    service_method_from_code_for(version, tx(offset)),
                    Some(expected)
                );
            }
            assert_eq!(service_method_from_code_for(version, tx(9)), None);
        }
    }

    #[test]
    fn security_level_method_codes_follow_generated_aidl_constants() {
        let cases = [
            (
                security_level_tx::r#createOperation,
                SecurityLevelMethod::CreateOperation,
            ),
            (
                security_level_tx::r#generateKey,
                SecurityLevelMethod::GenerateKey,
            ),
            (
                security_level_tx::r#importKey,
                SecurityLevelMethod::ImportKey,
            ),
            (
                security_level_tx::r#importWrappedKey,
                SecurityLevelMethod::ImportWrappedKey,
            ),
            (
                security_level_tx::r#convertStorageKeyToEphemeral,
                SecurityLevelMethod::ConvertStorageKeyToEphemeral,
            ),
            (
                security_level_tx::r#deleteKey,
                SecurityLevelMethod::DeleteKey,
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(security_level_method_from_code(code), Some(expected));
        }

        assert_eq!(security_level_method_from_code(u32::MAX), None);
        assert_eq!(
            security_level_method_from_code(AIDL_GET_INTERFACE_HASH_TRANSACTION),
            None
        );
        assert_eq!(
            security_level_method_from_code(AIDL_GET_INTERFACE_VERSION_TRANSACTION),
            None
        );
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
        assert_eq!(
            operation_method_from_code(AIDL_GET_INTERFACE_HASH_TRANSACTION),
            None
        );
        assert_eq!(
            operation_method_from_code(AIDL_GET_INTERFACE_VERSION_TRANSACTION),
            None
        );
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
}
