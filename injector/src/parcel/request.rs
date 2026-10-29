use super::{parse_typed_request, RequestEnvelope};
use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec;
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::identify::{
    authorization_method_from_code, maintenance_method_from_code, operation_method_from_code,
    security_level_method_from_code, service_method_from_code, AuthorizationMethod,
    MaintenanceMethod, OperationMethod, SecurityLevelMethod, ServiceMethod,
    KEYSTORE_AUTHORIZATION_INTERFACE, KEYSTORE_MAINTENANCE_INTERFACE, KEYSTORE_OPERATION_INTERFACE,
    KEYSTORE_SECURITY_LEVEL_INTERFACE, KEYSTORE_SERVICE_INTERFACE,
};
use anyhow::{bail, Result};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum ParsedAuthorizationRequest {
    AddAuthToken {
        auth_token: HardwareAuthToken,
    },
    OnDeviceUnlocked {
        user_id: i32,
        password: Option<Vec<u8>>,
    },
    OnDeviceLocked {
        user_id: i32,
        unlocking_sids: Vec<i64>,
        weak_unlock_enabled: bool,
    },
    OnUserStorageLocked {
        user_id: i32,
    },
    OnWeakUnlockMethodsExpired {
        user_id: i32,
    },
    OnNonLskfUnlockMethodsExpired {
        user_id: i32,
    },
    GetAuthTokensForCredStore {
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    },
    GetLastAuthTime {
        secure_user_id: i64,
        auth_types: Vec<HardwareAuthenticatorType>,
    },
}

impl ParsedAuthorizationRequest {
    pub fn method(&self) -> AuthorizationMethod {
        match self {
            Self::AddAuthToken { .. } => AuthorizationMethod::AddAuthToken,
            Self::OnDeviceUnlocked { .. } => AuthorizationMethod::OnDeviceUnlocked,
            Self::OnDeviceLocked { .. } => AuthorizationMethod::OnDeviceLocked,
            Self::OnUserStorageLocked { .. } => AuthorizationMethod::OnUserStorageLocked,
            Self::OnWeakUnlockMethodsExpired { .. } => {
                AuthorizationMethod::OnWeakUnlockMethodsExpired
            }
            Self::OnNonLskfUnlockMethodsExpired { .. } => {
                AuthorizationMethod::OnNonLskfUnlockMethodsExpired
            }
            Self::GetAuthTokensForCredStore { .. } => {
                AuthorizationMethod::GetAuthTokensForCredStore
            }
            Self::GetLastAuthTime { .. } => AuthorizationMethod::GetLastAuthTime,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParsedMaintenanceRequest {
    OnUserAdded { user_id: i32 },
    InitUserSuperKeys { user_id: i32, password: Vec<u8>, allow_existing: bool },
    OnUserRemoved { user_id: i32 },
    OnUserLskfRemoved { user_id: i32 },
    OnUserPasswordChanged { user_id: i32, password: Option<Vec<u8>> },
    ClearNamespace { domain: Domain, nspace: i64 },
    GetState { user_id: i32 },
    EarlyBootEnded,
    OnDeviceOffBody,
    MigrateKeyNamespace { source: KeyDescriptor, destination: KeyDescriptor },
    DeleteAllKeys,
    GetAppUidsAffectedBySid { user_id: i32, sid: i64 },
}

impl ParsedMaintenanceRequest {
    pub fn method(&self) -> MaintenanceMethod {
        match self {
            Self::OnUserAdded { .. } => MaintenanceMethod::OnUserAdded,
            Self::InitUserSuperKeys { .. } => MaintenanceMethod::InitUserSuperKeys,
            Self::OnUserRemoved { .. } => MaintenanceMethod::OnUserRemoved,
            Self::OnUserLskfRemoved { .. } => MaintenanceMethod::OnUserLskfRemoved,
            Self::OnUserPasswordChanged { .. } => MaintenanceMethod::OnUserPasswordChanged,
            Self::ClearNamespace { .. } => MaintenanceMethod::ClearNamespace,
            Self::GetState { .. } => MaintenanceMethod::GetState,
            Self::EarlyBootEnded => MaintenanceMethod::EarlyBootEnded,
            Self::OnDeviceOffBody => MaintenanceMethod::OnDeviceOffBody,
            Self::MigrateKeyNamespace { .. } => MaintenanceMethod::MigrateKeyNamespace,
            Self::DeleteAllKeys => MaintenanceMethod::DeleteAllKeys,
            Self::GetAppUidsAffectedBySid { .. } => MaintenanceMethod::GetAppUidsAffectedBySid,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParsedServiceRequest {
    GetSecurityLevel {
        security_level: SecurityLevel,
    },
    GetKeyEntry {
        key: KeyDescriptor,
    },
    UpdateSubcomponent {
        key: KeyDescriptor,
        public_cert: Option<Vec<u8>>,
        certificate_chain: Option<Vec<u8>>,
    },
    ListEntries {
        domain: Domain,
        nspace: i64,
    },
    DeleteKey {
        key: KeyDescriptor,
    },
    Grant {
        key: KeyDescriptor,
        grantee_uid: i32,
        access_vector: i32,
    },
    Ungrant {
        key: KeyDescriptor,
        grantee_uid: i32,
    },
    GetNumberOfEntries {
        domain: Domain,
        nspace: i64,
    },
    ListEntriesBatched {
        domain: Domain,
        nspace: i64,
        starting_past_alias: Option<String>,
    },
    GetSupplementaryAttestationInfo {
        tag: Tag,
    },
}

impl ParsedServiceRequest {
    pub fn method(&self) -> ServiceMethod {
        match self {
            Self::GetSecurityLevel { .. } => ServiceMethod::GetSecurityLevel,
            Self::GetKeyEntry { .. } => ServiceMethod::GetKeyEntry,
            Self::UpdateSubcomponent { .. } => ServiceMethod::UpdateSubcomponent,
            Self::ListEntries { .. } => ServiceMethod::ListEntries,
            Self::DeleteKey { .. } => ServiceMethod::DeleteKey,
            Self::Grant { .. } => ServiceMethod::Grant,
            Self::Ungrant { .. } => ServiceMethod::Ungrant,
            Self::GetNumberOfEntries { .. } => ServiceMethod::GetNumberOfEntries,
            Self::ListEntriesBatched { .. } => ServiceMethod::ListEntriesBatched,
            Self::GetSupplementaryAttestationInfo { .. } => {
                ServiceMethod::GetSupplementaryAttestationInfo
            }
        }
    }
}

#[derive(Debug)]
pub enum ParsedSecurityLevelRequest {
    CreateOperation {
        key: KeyDescriptor,
        operation_parameters: Vec<KeyParameter>,
        forced: bool,
    },
    GenerateKey {
        key: KeyDescriptor,
        attestation_key: Option<KeyDescriptor>,
        params: Vec<KeyParameter>,
        flags: i32,
        entropy: Vec<u8>,
    },
    ImportKey {
        key: KeyDescriptor,
        attestation_key: Option<KeyDescriptor>,
        params: Vec<KeyParameter>,
        flags: i32,
        key_data: Vec<u8>,
    },
    ImportWrappedKey {
        key: KeyDescriptor,
        wrapping_key: KeyDescriptor,
        masking_key: Option<Vec<u8>>,
        params: Vec<KeyParameter>,
        authenticators: Vec<AuthenticatorSpec>,
    },
    ConvertStorageKeyToEphemeral {
        storage_key: KeyDescriptor,
    },
    DeleteKey {
        key: KeyDescriptor,
    },
}

impl ParsedSecurityLevelRequest {
    pub fn method(&self) -> SecurityLevelMethod {
        match self {
            Self::CreateOperation { .. } => SecurityLevelMethod::CreateOperation,
            Self::GenerateKey { .. } => SecurityLevelMethod::GenerateKey,
            Self::ImportKey { .. } => SecurityLevelMethod::ImportKey,
            Self::ImportWrappedKey { .. } => SecurityLevelMethod::ImportWrappedKey,
            Self::ConvertStorageKeyToEphemeral { .. } => {
                SecurityLevelMethod::ConvertStorageKeyToEphemeral
            }
            Self::DeleteKey { .. } => SecurityLevelMethod::DeleteKey,
        }
    }
}

#[derive(Debug)]
pub enum ParsedOperationRequest {
    UpdateAad { aad_input: Vec<u8> },
    Update { input: Vec<u8> },
    Finish { input: Option<Vec<u8>>, signature: Option<Vec<u8>> },
    Abort,
}

impl ParsedOperationRequest {
    pub fn method(&self) -> OperationMethod {
        match self {
            Self::UpdateAad { .. } => OperationMethod::UpdateAad,
            Self::Update { .. } => OperationMethod::Update,
            Self::Finish { .. } => OperationMethod::Finish,
            Self::Abort => OperationMethod::Abort,
        }
    }
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_authorization_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedAuthorizationRequest> {
    parse_authorization_request_with_resolver(
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        authorization_method_from_code,
    )
}

unsafe fn parse_authorization_request_with_resolver(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
    method_from_code: impl FnOnce(u32) -> Option<AuthorizationMethod>,
) -> Result<ParsedAuthorizationRequest> {
    let (mut parcel, method) = parse_typed_request(
        RequestEnvelope { data, data_size, offsets, offsets_size, code },
        KEYSTORE_AUTHORIZATION_INTERFACE,
        "IKeystoreAuthorization",
        method_from_code,
    )?;

    Ok(match method {
        AuthorizationMethod::AddAuthToken => {
            ParsedAuthorizationRequest::AddAuthToken { auth_token: parcel.read()? }
        }
        AuthorizationMethod::LegacyOnLockScreenEvent => {
            let event: i32 = parcel.read()?;
            let user_id: i32 = parcel.read()?;
            let password: Option<Vec<u8>> = parcel.read()?;
            let unlocking_sids: Option<Vec<i64>> = parcel.read()?;
            match event {
                0 => ParsedAuthorizationRequest::OnDeviceUnlocked { user_id, password },
                1 => ParsedAuthorizationRequest::OnDeviceLocked {
                    user_id,
                    unlocking_sids: unlocking_sids.unwrap_or_default(),
                    weak_unlock_enabled: false,
                },
                _ => bail!("unknown IKeystoreAuthorization onLockScreenEvent event {event}"),
            }
        }
        AuthorizationMethod::OnDeviceUnlocked => ParsedAuthorizationRequest::OnDeviceUnlocked {
            user_id: parcel.read()?,
            password: parcel.read()?,
        },
        AuthorizationMethod::OnDeviceLocked => ParsedAuthorizationRequest::OnDeviceLocked {
            user_id: parcel.read()?,
            unlocking_sids: parcel.read()?,
            weak_unlock_enabled: parcel.read()?,
        },
        AuthorizationMethod::OnUserStorageLocked => {
            ParsedAuthorizationRequest::OnUserStorageLocked { user_id: parcel.read()? }
        }
        AuthorizationMethod::OnWeakUnlockMethodsExpired => {
            ParsedAuthorizationRequest::OnWeakUnlockMethodsExpired { user_id: parcel.read()? }
        }
        AuthorizationMethod::OnNonLskfUnlockMethodsExpired => {
            ParsedAuthorizationRequest::OnNonLskfUnlockMethodsExpired { user_id: parcel.read()? }
        }
        AuthorizationMethod::GetAuthTokensForCredStore => {
            ParsedAuthorizationRequest::GetAuthTokensForCredStore {
                challenge: parcel.read()?,
                secure_user_id: parcel.read()?,
                auth_token_max_age_millis: parcel.read()?,
            }
        }
        AuthorizationMethod::GetLastAuthTime => ParsedAuthorizationRequest::GetLastAuthTime {
            secure_user_id: parcel.read()?,
            auth_types: parcel.read()?,
        },
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_maintenance_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedMaintenanceRequest> {
    parse_maintenance_request_with_resolver(
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        maintenance_method_from_code,
    )
}

unsafe fn parse_maintenance_request_with_resolver(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
    method_from_code: impl FnOnce(u32) -> Option<MaintenanceMethod>,
) -> Result<ParsedMaintenanceRequest> {
    let (mut parcel, method) = parse_typed_request(
        RequestEnvelope { data, data_size, offsets, offsets_size, code },
        KEYSTORE_MAINTENANCE_INTERFACE,
        "IKeystoreMaintenance",
        method_from_code,
    )?;

    Ok(match method {
        MaintenanceMethod::OnUserAdded => {
            ParsedMaintenanceRequest::OnUserAdded { user_id: parcel.read()? }
        }
        MaintenanceMethod::InitUserSuperKeys => ParsedMaintenanceRequest::InitUserSuperKeys {
            user_id: parcel.read()?,
            password: parcel.read()?,
            allow_existing: parcel.read()?,
        },
        MaintenanceMethod::OnUserRemoved => {
            ParsedMaintenanceRequest::OnUserRemoved { user_id: parcel.read()? }
        }
        MaintenanceMethod::OnUserLskfRemoved => {
            ParsedMaintenanceRequest::OnUserLskfRemoved { user_id: parcel.read()? }
        }
        MaintenanceMethod::OnUserPasswordChanged => {
            ParsedMaintenanceRequest::OnUserPasswordChanged {
                user_id: parcel.read()?,
                password: parcel.read()?,
            }
        }
        MaintenanceMethod::ClearNamespace => ParsedMaintenanceRequest::ClearNamespace {
            domain: parcel.read()?,
            nspace: parcel.read()?,
        },
        MaintenanceMethod::GetState => {
            ParsedMaintenanceRequest::GetState { user_id: parcel.read()? }
        }
        MaintenanceMethod::EarlyBootEnded => ParsedMaintenanceRequest::EarlyBootEnded,
        MaintenanceMethod::OnDeviceOffBody => ParsedMaintenanceRequest::OnDeviceOffBody,
        MaintenanceMethod::MigrateKeyNamespace => ParsedMaintenanceRequest::MigrateKeyNamespace {
            source: parcel.read()?,
            destination: parcel.read()?,
        },
        MaintenanceMethod::DeleteAllKeys => ParsedMaintenanceRequest::DeleteAllKeys,
        MaintenanceMethod::GetAppUidsAffectedBySid => {
            ParsedMaintenanceRequest::GetAppUidsAffectedBySid {
                user_id: parcel.read()?,
                sid: parcel.read()?,
            }
        }
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_service_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedServiceRequest> {
    let (mut parcel, method) = parse_typed_request(
        RequestEnvelope { data, data_size, offsets, offsets_size, code },
        KEYSTORE_SERVICE_INTERFACE,
        "IKeystoreService",
        service_method_from_code,
    )?;

    Ok(match method {
        ServiceMethod::GetSecurityLevel => {
            ParsedServiceRequest::GetSecurityLevel { security_level: parcel.read()? }
        }
        ServiceMethod::GetKeyEntry => ParsedServiceRequest::GetKeyEntry { key: parcel.read()? },
        ServiceMethod::UpdateSubcomponent => ParsedServiceRequest::UpdateSubcomponent {
            key: parcel.read()?,
            public_cert: parcel.read()?,
            certificate_chain: parcel.read()?,
        },
        ServiceMethod::ListEntries => {
            ParsedServiceRequest::ListEntries { domain: parcel.read()?, nspace: parcel.read()? }
        }
        ServiceMethod::DeleteKey => ParsedServiceRequest::DeleteKey { key: parcel.read()? },
        ServiceMethod::Grant => ParsedServiceRequest::Grant {
            key: parcel.read()?,
            grantee_uid: parcel.read()?,
            access_vector: parcel.read()?,
        },
        ServiceMethod::Ungrant => {
            ParsedServiceRequest::Ungrant { key: parcel.read()?, grantee_uid: parcel.read()? }
        }
        ServiceMethod::GetNumberOfEntries => ParsedServiceRequest::GetNumberOfEntries {
            domain: parcel.read()?,
            nspace: parcel.read()?,
        },
        ServiceMethod::ListEntriesBatched => ParsedServiceRequest::ListEntriesBatched {
            domain: parcel.read()?,
            nspace: parcel.read()?,
            starting_past_alias: parcel.read()?,
        },
        ServiceMethod::GetSupplementaryAttestationInfo => {
            ParsedServiceRequest::GetSupplementaryAttestationInfo { tag: parcel.read()? }
        }
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_security_level_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedSecurityLevelRequest> {
    let (mut parcel, method) = parse_typed_request(
        RequestEnvelope { data, data_size, offsets, offsets_size, code },
        KEYSTORE_SECURITY_LEVEL_INTERFACE,
        "IKeystoreSecurityLevel",
        security_level_method_from_code,
    )?;

    Ok(match method {
        SecurityLevelMethod::CreateOperation => ParsedSecurityLevelRequest::CreateOperation {
            key: parcel.read()?,
            operation_parameters: parcel.read()?,
            forced: parcel.read()?,
        },
        SecurityLevelMethod::GenerateKey => ParsedSecurityLevelRequest::GenerateKey {
            key: parcel.read()?,
            attestation_key: parcel.read()?,
            params: parcel.read()?,
            flags: parcel.read()?,
            entropy: parcel.read()?,
        },
        SecurityLevelMethod::ImportKey => ParsedSecurityLevelRequest::ImportKey {
            key: parcel.read()?,
            attestation_key: parcel.read()?,
            params: parcel.read()?,
            flags: parcel.read()?,
            key_data: parcel.read()?,
        },
        SecurityLevelMethod::ImportWrappedKey => ParsedSecurityLevelRequest::ImportWrappedKey {
            key: parcel.read()?,
            wrapping_key: parcel.read()?,
            masking_key: parcel.read()?,
            params: parcel.read()?,
            authenticators: parcel.read()?,
        },
        SecurityLevelMethod::ConvertStorageKeyToEphemeral => {
            ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key: parcel.read()? }
        }
        SecurityLevelMethod::DeleteKey => {
            ParsedSecurityLevelRequest::DeleteKey { key: parcel.read()? }
        }
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_operation_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedOperationRequest> {
    let (mut parcel, method) = parse_typed_request(
        RequestEnvelope { data, data_size, offsets, offsets_size, code },
        KEYSTORE_OPERATION_INTERFACE,
        "IKeystoreOperation",
        operation_method_from_code,
    )?;

    Ok(match method {
        OperationMethod::UpdateAad => {
            ParsedOperationRequest::UpdateAad { aad_input: parcel.read()? }
        }
        OperationMethod::Update => ParsedOperationRequest::Update { input: parcel.read()? },
        OperationMethod::Finish => {
            ParsedOperationRequest::Finish { input: parcel.read()?, signature: parcel.read()? }
        }
        OperationMethod::Abort => ParsedOperationRequest::Abort,
    })
}
