use crate::android::system::keystore2::IKeystoreOperation::transactions as operation_tx;
use crate::android::system::keystore2::IKeystoreSecurityLevel::transactions as security_level_tx;
use crate::android::system::keystore2::IKeystoreService::transactions as service_tx;
use crate::config::InterceptConfig;

pub const KEYSTORE_SERVICE_INTERFACE: &str = "android.system.keystore2.IKeystoreService";
pub const KEYSTORE_SECURITY_LEVEL_INTERFACE: &str =
    "android.system.keystore2.IKeystoreSecurityLevel";
pub const KEYSTORE_OPERATION_INTERFACE: &str = "android.system.keystore2.IKeystoreOperation";

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

pub fn service_method_from_code(code: u32) -> Option<ServiceMethod> {
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

    #[test]
    fn service_method_codes_follow_generated_aidl_constants() {
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
            assert_eq!(service_method_from_code(code), Some(expected));
        }

        assert_eq!(service_method_from_code(u32::MAX), None);
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
    }
}
