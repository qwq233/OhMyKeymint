use crate::android::security::authorization::IKeystoreAuthorization::transactions as authorization_tx;
use crate::android::security::maintenance::IKeystoreMaintenance::transactions as maintenance_tx;
use crate::android::system::keystore2::IKeystoreOperation::transactions as operation_tx;
use crate::android::system::keystore2::IKeystoreSecurityLevel::transactions as security_level_tx;
use crate::android::system::keystore2::IKeystoreService::transactions as service_tx;
use crate::config::InterceptConfig;

#[cfg(test)]
mod tests;

pub const KEYSTORE_AUTHORIZATION_INTERFACE: &str =
    "android.security.authorization.IKeystoreAuthorization";
pub const KEYSTORE_MAINTENANCE_INTERFACE: &str =
    "android.security.maintenance.IKeystoreMaintenance";
pub const KEYSTORE_SERVICE_INTERFACE: &str = "android.system.keystore2.IKeystoreService";
pub const KEYSTORE_SECURITY_LEVEL_INTERFACE: &str =
    "android.system.keystore2.IKeystoreSecurityLevel";
pub const KEYSTORE_OPERATION_INTERFACE: &str = "android.system.keystore2.IKeystoreOperation";
pub const KNOWN_KEYSTORE_INTERFACES: [&str; 5] = [
    KEYSTORE_AUTHORIZATION_INTERFACE,
    KEYSTORE_MAINTENANCE_INTERFACE,
    KEYSTORE_SERVICE_INTERFACE,
    KEYSTORE_SECURITY_LEVEL_INTERFACE,
    KEYSTORE_OPERATION_INTERFACE,
];

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
        Some(version @ 12..=15) => match transaction_offset(code)? {
            0 => Some(ServiceMethod::GetSecurityLevel),
            1 => Some(ServiceMethod::GetKeyEntry),
            2 => Some(ServiceMethod::UpdateSubcomponent),
            3 => Some(ServiceMethod::ListEntries),
            4 => Some(ServiceMethod::DeleteKey),
            5 => Some(ServiceMethod::Grant),
            6 => Some(ServiceMethod::Ungrant),
            7 if version >= 14 => Some(ServiceMethod::GetNumberOfEntries),
            8 if version >= 14 => Some(ServiceMethod::ListEntriesBatched),
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
