use std::mem::size_of;

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{
    Deserialize, FromIBinder, Parcel, Serialize, SerializeOption, Status, StatusCode, Strong,
    NON_NULL_PARCELABLE_FLAG,
};

use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec;
use crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse;
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation;
use crate::android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::KeyParameters::KeyParameters;
use crate::android::system::keystore2::OperationChallenge::OperationChallenge;
use crate::hook::binder::{
    flat_binder_object, BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE, BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_WEAK_HANDLE,
};
use crate::identify::{
    authorization_method_from_code, maintenance_method_from_code, operation_method_from_code,
    security_level_method_from_code, service_method_from_code, AuthorizationMethod,
    MaintenanceMethod, OperationMethod, SecurityLevelMethod, ServiceMethod,
    KEYSTORE_AUTHORIZATION_INTERFACE, KEYSTORE_MAINTENANCE_INTERFACE, KEYSTORE_OPERATION_INTERFACE,
    KEYSTORE_SECURITY_LEVEL_INTERFACE, KEYSTORE_SERVICE_INTERFACE,
};

#[derive(Debug)]
pub struct OwnedReply {
    parcel: Parcel,
    pub offsets: Box<[usize]>,
}

impl OwnedReply {
    pub fn data_size(&self) -> usize {
        self.parcel.data_size()
    }

    pub fn offsets_size(&self) -> usize {
        self.offsets.len() * size_of::<usize>()
    }

    pub fn data_ptr(&self) -> *const u8 {
        self.parcel.as_ptr()
    }

    pub fn data_mut_ptr(&mut self) -> *mut u8 {
        self.parcel.as_mut_ptr()
    }
}

#[derive(Debug, Clone)]
pub struct ReplyBinderCarrier {
    pub bytes: Vec<u8>,
    pub is_object: bool,
}

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
    OnUserAdded {
        user_id: i32,
    },
    InitUserSuperKeys {
        user_id: i32,
        password: Vec<u8>,
        allow_existing: bool,
    },
    OnUserRemoved {
        user_id: i32,
    },
    OnUserLskfRemoved {
        user_id: i32,
    },
    ClearNamespace {
        domain: Domain,
        nspace: i64,
    },
    EarlyBootEnded,
    MigrateKeyNamespace {
        source: KeyDescriptor,
        destination: KeyDescriptor,
    },
    DeleteAllKeys,
    GetAppUidsAffectedBySid {
        user_id: i32,
        sid: i64,
    },
}

impl ParsedMaintenanceRequest {
    pub fn method(&self) -> MaintenanceMethod {
        match self {
            Self::OnUserAdded { .. } => MaintenanceMethod::OnUserAdded,
            Self::InitUserSuperKeys { .. } => MaintenanceMethod::InitUserSuperKeys,
            Self::OnUserRemoved { .. } => MaintenanceMethod::OnUserRemoved,
            Self::OnUserLskfRemoved { .. } => MaintenanceMethod::OnUserLskfRemoved,
            Self::ClearNamespace { .. } => MaintenanceMethod::ClearNamespace,
            Self::EarlyBootEnded => MaintenanceMethod::EarlyBootEnded,
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
    UpdateAad {
        aad_input: Vec<u8>,
    },
    Update {
        input: Vec<u8>,
    },
    Finish {
        input: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
    },
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
    let (mut parcel, method) = parse_typed_request(
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        KEYSTORE_AUTHORIZATION_INTERFACE,
        "IKeystoreAuthorization",
        authorization_method_from_code,
    )?;

    let parsed = match method {
        AuthorizationMethod::AddAuthToken => ParsedAuthorizationRequest::AddAuthToken {
            auth_token: parcel.read()?,
        },
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
            ParsedAuthorizationRequest::OnUserStorageLocked {
                user_id: parcel.read()?,
            }
        }
        AuthorizationMethod::OnWeakUnlockMethodsExpired => {
            ParsedAuthorizationRequest::OnWeakUnlockMethodsExpired {
                user_id: parcel.read()?,
            }
        }
        AuthorizationMethod::OnNonLskfUnlockMethodsExpired => {
            ParsedAuthorizationRequest::OnNonLskfUnlockMethodsExpired {
                user_id: parcel.read()?,
            }
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
    };

    Ok(parsed)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn peek_request_interface(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<String> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_request_interface(&mut parcel)
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
    let (mut parcel, method) = parse_typed_request(
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        KEYSTORE_MAINTENANCE_INTERFACE,
        "IKeystoreMaintenance",
        maintenance_method_from_code,
    )?;

    let parsed = match method {
        MaintenanceMethod::OnUserAdded => ParsedMaintenanceRequest::OnUserAdded {
            user_id: parcel.read()?,
        },
        MaintenanceMethod::InitUserSuperKeys => ParsedMaintenanceRequest::InitUserSuperKeys {
            user_id: parcel.read()?,
            password: parcel.read()?,
            allow_existing: parcel.read()?,
        },
        MaintenanceMethod::OnUserRemoved => ParsedMaintenanceRequest::OnUserRemoved {
            user_id: parcel.read()?,
        },
        MaintenanceMethod::OnUserLskfRemoved => ParsedMaintenanceRequest::OnUserLskfRemoved {
            user_id: parcel.read()?,
        },
        MaintenanceMethod::ClearNamespace => ParsedMaintenanceRequest::ClearNamespace {
            domain: parcel.read()?,
            nspace: parcel.read()?,
        },
        MaintenanceMethod::EarlyBootEnded => ParsedMaintenanceRequest::EarlyBootEnded,
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
    };

    Ok(parsed)
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
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        KEYSTORE_SERVICE_INTERFACE,
        "IKeystoreService",
        service_method_from_code,
    )?;

    let parsed = match method {
        ServiceMethod::GetSecurityLevel => ParsedServiceRequest::GetSecurityLevel {
            security_level: parcel.read()?,
        },
        ServiceMethod::GetKeyEntry => ParsedServiceRequest::GetKeyEntry {
            key: parcel.read()?,
        },
        ServiceMethod::UpdateSubcomponent => ParsedServiceRequest::UpdateSubcomponent {
            key: parcel.read()?,
            public_cert: parcel.read()?,
            certificate_chain: parcel.read()?,
        },
        ServiceMethod::ListEntries => ParsedServiceRequest::ListEntries {
            domain: parcel.read()?,
            nspace: parcel.read()?,
        },
        ServiceMethod::DeleteKey => ParsedServiceRequest::DeleteKey {
            key: parcel.read()?,
        },
        ServiceMethod::Grant => ParsedServiceRequest::Grant {
            key: parcel.read()?,
            grantee_uid: parcel.read()?,
            access_vector: parcel.read()?,
        },
        ServiceMethod::Ungrant => ParsedServiceRequest::Ungrant {
            key: parcel.read()?,
            grantee_uid: parcel.read()?,
        },
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
            ParsedServiceRequest::GetSupplementaryAttestationInfo {
                tag: parcel.read()?,
            }
        }
    };

    Ok(parsed)
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
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        KEYSTORE_SECURITY_LEVEL_INTERFACE,
        "IKeystoreSecurityLevel",
        security_level_method_from_code,
    )?;

    let parsed = match method {
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
            ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral {
                storage_key: parcel.read()?,
            }
        }
        SecurityLevelMethod::DeleteKey => ParsedSecurityLevelRequest::DeleteKey {
            key: parcel.read()?,
        },
    };

    Ok(parsed)
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
        data,
        data_size,
        offsets,
        offsets_size,
        code,
        KEYSTORE_OPERATION_INTERFACE,
        "IKeystoreOperation",
        operation_method_from_code,
    )?;

    let parsed = match method {
        OperationMethod::UpdateAad => ParsedOperationRequest::UpdateAad {
            aad_input: parcel.read()?,
        },
        OperationMethod::Update => ParsedOperationRequest::Update {
            input: parcel.read()?,
        },
        OperationMethod::Finish => ParsedOperationRequest::Finish {
            input: parcel.read()?,
            signature: parcel.read()?,
        },
        OperationMethod::Abort => ParsedOperationRequest::Abort,
    };

    Ok(parsed)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_success_reply<T: Deserialize>(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<T> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    parcel.read().context("failed to decode reply payload")
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_reply_status(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<Status> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    parcel.read().context("failed to decode binder status")
}

pub fn parse_owned_success_reply<T: Deserialize>(reply: &mut OwnedReply) -> Result<T> {
    unsafe {
        parse_success_reply(
            reply.data_mut_ptr(),
            reply.data_size(),
            if reply.offsets.is_empty() {
                std::ptr::null_mut()
            } else {
                reply.offsets.as_mut_ptr()
            },
            reply.offsets_size(),
        )
    }
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_direct_binder_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_reply_binder_carrier(&mut parcel, data)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_key_entry_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;
    read_sized_reply_payload(&mut parcel, "key-entry binder carrier", |sub_parcel| {
        read_reply_binder_carrier(sub_parcel, data)
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_key_entry_reply_metadata(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<crate::android::system::keystore2::KeyMetadata::KeyMetadata> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;
    read_sized_reply_payload(&mut parcel, "key-entry metadata payload", |sub_parcel| {
        read_reply_binder_carrier(sub_parcel, data).and_then(|_| {
            sub_parcel
                .read()
                .context("failed to decode key-entry metadata payload")
        })
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_create_operation_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "create-operation")?;
    read_sized_reply_payload(
        &mut parcel,
        "create-operation binder carrier",
        |sub_parcel| read_reply_binder_carrier(sub_parcel, data),
    )
}

pub fn build_get_security_level_reply(
    binder: Strong<dyn IKeystoreSecurityLevel>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    let binder_offset = parcel.data_position();
    parcel.write(&binder)?;
    Ok(owned_reply_from_parcel(parcel, [binder_offset]))
}

fn build_sized_parcelable_reply<F>(write_payload: F) -> Result<OwnedReply>
where
    F: FnOnce(&mut Parcel, &mut Option<usize>) -> std::result::Result<(), StatusCode>,
{
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    parcel.sized_write(|sub_parcel| write_payload(sub_parcel, &mut binder_offset))?;
    Ok(owned_reply_from_parcel(parcel, binder_offset))
}

pub fn build_key_entry_reply(reply: KeyEntryResponse) -> Result<OwnedReply> {
    let KeyEntryResponse {
        r#iSecurityLevel,
        r#metadata,
    } = reply;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        match r#iSecurityLevel.as_ref() {
            Some(binder) => {
                *binder_offset = Some(sub_parcel.data_position());
                sub_parcel.write(&Some(binder.clone()))?;
            }
            None => {
                let none: Option<Strong<dyn IKeystoreSecurityLevel>> = None;
                sub_parcel.write(&none)?;
            }
        }
        sub_parcel.write(&r#metadata)?;
        Ok(())
    })
}

pub fn build_key_entry_reply_with_carrier_bytes(
    metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "key-entry",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreSecurityLevel>(sub_parcel)?;
            sub_parcel.write(&metadata)?;
            Ok(span)
        },
    )
}

pub fn build_create_operation_reply(reply: CreateOperationResponse) -> Result<OwnedReply> {
    let CreateOperationResponse {
        r#iOperation,
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
    } = reply;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        match r#iOperation.as_ref() {
            Some(binder) => {
                *binder_offset = Some(sub_parcel.data_position());
                sub_parcel.write(&Some(binder.clone()))?;
            }
            None => {
                let none: Option<Strong<dyn IKeystoreOperation>> = None;
                sub_parcel.write(&none)?;
            }
        }
        sub_parcel.write(&r#operationChallenge)?;
        sub_parcel.write(&r#parameters)?;
        sub_parcel.write(&r#upgradedBlob)?;
        Ok(())
    })
}

pub fn build_create_operation_reply_with_carrier_bytes(
    operation_challenge: Option<OperationChallenge>,
    parameters: Option<KeyParameters>,
    upgraded_blob: Option<Vec<u8>>,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "create-operation",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreOperation>(sub_parcel)?;
            sub_parcel.write(&operation_challenge)?;
            sub_parcel.write(&parameters)?;
            sub_parcel.write(&upgraded_blob)?;
            Ok(span)
        },
    )
}

pub fn build_plain_reply<T: Serialize>(value: &T) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(value)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn build_void_reply() -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn build_status_reply(status: &Status) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(status)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn contains_keystore_authorization_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_AUTHORIZATION_INTERFACE)
}

pub fn contains_keystore_maintenance_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_MAINTENANCE_INTERFACE)
}

pub fn contains_keystore_service_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_SERVICE_INTERFACE)
}

pub fn contains_keystore_security_level_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_SECURITY_LEVEL_INTERFACE)
}

pub fn contains_keystore_operation_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_OPERATION_INTERFACE)
}

pub fn contains_known_keystore_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_AUTHORIZATION_INTERFACE)
        || contains_utf16_token(parcel, KEYSTORE_MAINTENANCE_INTERFACE)
        || contains_utf16_token(parcel, KEYSTORE_SERVICE_INTERFACE)
        || contains_utf16_token(parcel, KEYSTORE_SECURITY_LEVEL_INTERFACE)
        || contains_utf16_token(parcel, KEYSTORE_OPERATION_INTERFACE)
}

fn owned_reply_from_parcel(parcel: Parcel, offsets: impl IntoIterator<Item = usize>) -> OwnedReply {
    let offsets: Vec<usize> = offsets.into_iter().collect();
    OwnedReply {
        parcel,
        offsets: offsets.into_boxed_slice(),
    }
}

fn read_request_interface(parcel: &mut Parcel) -> Result<String> {
    let _: i32 = parcel.read().context("missing strict mode header")?;
    let _: i32 = parcel.read().context("missing work source header")?;
    let _: u32 = parcel.read().context("missing interface marker")?;
    parcel.read().context("missing interface token")
}

unsafe fn parse_typed_request<M>(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
    expected_interface: &str,
    interface_name: &str,
    method_from_code: fn(u32) -> Option<M>,
) -> Result<(Parcel, M)> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    if interface != expected_interface {
        bail!("unexpected interface token: {}", interface);
    }

    let method = method_from_code(code)
        .ok_or_else(|| anyhow!("unknown {interface_name} transaction code {code}"))?;
    Ok((parcel, method))
}

fn read_ok_status(parcel: &mut Parcel) -> Result<()> {
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    Ok(())
}

fn read_non_null_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<()> {
    let flag: i32 = parcel
        .read()
        .with_context(|| format!("failed to decode {label} parcelable flag"))?;
    if flag != NON_NULL_PARCELABLE_FLAG {
        bail!("unexpected {label} parcelable flag: {flag}");
    }
    Ok(())
}

fn read_sized_reply_payload<T>(
    parcel: &mut Parcel,
    label: &str,
    mut read_payload: impl FnMut(&mut Parcel) -> Result<T>,
) -> Result<T> {
    let mut value = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_payload(sub_parcel) {
            Ok(payload) => value = Some(payload),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    value.ok_or_else(|| anyhow!("missing {label}"))
}

fn read_reply_binder_carrier(parcel: &mut Parcel, base: *mut u8) -> Result<ReplyBinderCarrier> {
    let start = parcel.data_position();
    let binder_len = size_of::<flat_binder_object>() + size_of::<i32>();
    let end = start
        .checked_add(binder_len)
        .ok_or_else(|| anyhow!("binder carrier length overflow"))?;
    if end > parcel.data_size() {
        bail!(
            "binder carrier truncated: end {} exceeds parcel size {}",
            end,
            parcel.data_size()
        );
    }

    let flat = unsafe { std::ptr::read_unaligned(base.add(start) as *const flat_binder_object) };
    parcel.set_data_position(end);

    let bytes = unsafe { std::slice::from_raw_parts(base.add(start), end - start) }.to_vec();
    Ok(ReplyBinderCarrier {
        bytes,
        is_object: binder_carrier_is_object(&flat),
    })
}

fn binder_carrier_is_object(flat: &flat_binder_object) -> bool {
    match flat.hdr.type_ {
        BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER => unsafe {
            flat.handle_or_ptr.binder != 0 && flat.cookie != 0
        },
        BINDER_TYPE_HANDLE | BINDER_TYPE_WEAK_HANDLE => unsafe { flat.handle_or_ptr.handle != 0 },
        _ => false,
    }
}

fn build_parcelable_reply_with_carrier_bytes(
    label: &str,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
    write_body: impl FnOnce(&mut Parcel) -> rsbinder::Result<(usize, usize)>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    let mut binder_len = 0usize;
    parcel.sized_write(|sub_parcel| {
        let (start, end) = write_body(sub_parcel)?;
        binder_offset = Some(start);
        binder_len = end - start;
        Ok(())
    })?;
    if carrier_bytes.len() != binder_len {
        bail!(
            "{label} carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }

    let start =
        binder_offset.ok_or_else(|| anyhow!("{label} carrier binder offset was not recorded"))?;
    let mut reply = owned_reply_from_parcel(parcel, carrier_is_object.then_some(start));
    unsafe {
        std::ptr::copy_nonoverlapping(
            carrier_bytes.as_ptr(),
            reply.data_mut_ptr().add(start),
            carrier_bytes.len(),
        );
    }
    Ok(reply)
}

fn write_none_binder_placeholder<T>(parcel: &mut Parcel) -> rsbinder::Result<(usize, usize)>
where
    T: FromIBinder + SerializeOption + ?Sized,
{
    let none: Option<Strong<T>> = None;
    let start = parcel.data_position();
    parcel.write(&none)?;
    let end = parcel.data_position();
    Ok((start, end))
}

unsafe fn parcel_from_ipc_parts(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Parcel {
    let data = if data_size == 0 {
        std::ptr::NonNull::<u8>::dangling().as_ptr()
    } else {
        data
    };
    let offsets = if offsets_size == 0 {
        std::ptr::NonNull::<usize>::dangling().as_ptr()
    } else {
        offsets
    };

    Parcel::from_ipc_parts(
        data,
        data_size,
        offsets as *mut u64,
        offsets_size / size_of::<usize>(),
        noop_free_buffer,
    )
}

fn noop_free_buffer(
    _parcel: Option<&Parcel>,
    _data: u64,
    _data_size: usize,
    _offsets: u64,
    _offsets_size: usize,
) -> rsbinder::Result<()> {
    Ok(())
}

fn contains_utf16_token(parcel: &[u8], token: &str) -> bool {
    let encoded: Vec<u8> = token
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    parcel
        .windows(encoded.len())
        .any(|window| window == encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
    use crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse;
    use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
    use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
    use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
    use crate::android::system::keystore2::OperationChallenge::OperationChallenge;

    fn raw_parts(reply: &mut OwnedReply) -> (*mut u8, usize, *mut usize, usize) {
        (
            reply.data_mut_ptr(),
            reply.data_size(),
            if reply.offsets.is_empty() {
                std::ptr::null_mut()
            } else {
                reply.offsets.as_mut_ptr()
            },
            reply.offsets_size(),
        )
    }

    fn build_request(interface: &str, payload_token: Option<&str>) -> OwnedReply {
        let mut parcel = Parcel::new();
        parcel.write(&0i32).unwrap();
        parcel.write(&0i32).unwrap();
        parcel.write(&0u32).unwrap();
        parcel.write(&interface.to_string()).unwrap();
        if let Some(payload_token) = payload_token {
            parcel.write(&payload_token.to_string()).unwrap();
        }
        owned_reply_from_parcel(parcel, std::iter::empty::<usize>())
    }

    #[test]
    fn request_interface_peek_uses_header_token_only() {
        let mut request = build_request(
            KEYSTORE_SERVICE_INTERFACE,
            Some(KEYSTORE_AUTHORIZATION_INTERFACE),
        );
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
        assert!(contains_keystore_authorization_interface(unsafe {
            std::slice::from_raw_parts(data, data_size)
        }));
        let interface = unsafe { peek_request_interface(data, data_size, offsets, offsets_size) }
            .expect("request interface should parse");
        assert_eq!(interface, KEYSTORE_SERVICE_INTERFACE);
    }

    #[test]
    fn plain_reply_round_trip() {
        let value = vec![1u8, 2, 3, 4];
        let mut reply = build_plain_reply(&value).expect("plain reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: Vec<u8> =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn service_plain_replies_round_trip() {
        let descriptors = vec![
            KeyDescriptor {
                domain: crate::android::system::keystore2::Domain::Domain::APP,
                nspace: 10001,
                alias: Some("alpha".to_string()),
                blob: None,
            },
            KeyDescriptor {
                domain: crate::android::system::keystore2::Domain::Domain::GRANT,
                nspace: 42,
                alias: None,
                blob: None,
            },
        ];
        let mut list_reply =
            build_plain_reply(&descriptors).expect("descriptor list reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut list_reply);
        let parsed: Vec<KeyDescriptor> =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].alias.as_deref(), Some("alpha"));
        assert_eq!(
            parsed[1].domain,
            crate::android::system::keystore2::Domain::Domain::GRANT
        );

        let count = 7i32;
        let mut count_reply = build_plain_reply(&count).expect("count reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut count_reply);
        let parsed_count: i32 =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert_eq!(parsed_count, count);
    }

    #[test]
    fn key_entry_reply_round_trip_without_binder() {
        let response = KeyEntryResponse {
            r#iSecurityLevel: None,
            r#metadata: KeyMetadata {
                r#key: KeyDescriptor {
                    domain: crate::android::system::keystore2::Domain::Domain::APP,
                    nspace: 42,
                    alias: Some("alias".to_string()),
                    blob: None,
                },
                r#keySecurityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
                r#authorizations: Vec::new(),
                r#certificate: Some(vec![1, 2, 3]),
                r#certificateChain: Some(vec![4, 5, 6]),
                r#modificationTimeMs: 7,
            },
        };
        let mut reply = build_key_entry_reply(response).expect("key entry reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: KeyEntryResponse =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert!(parsed.r#iSecurityLevel.is_none());
        assert_eq!(parsed.r#metadata.r#key.nspace, 42);
        assert_eq!(
            parsed.r#metadata.r#certificate.as_deref(),
            Some(&[1, 2, 3][..])
        );
    }

    #[test]
    fn create_operation_reply_round_trip_without_binder() {
        let response = CreateOperationResponse {
            r#iOperation: None,
            r#operationChallenge: Some(OperationChallenge { challenge: 0x1234 }),
            r#parameters: None,
            r#upgradedBlob: Some(vec![9, 8, 7]),
        };
        let mut reply = build_create_operation_reply(response)
            .expect("create operation reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: CreateOperationResponse =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert!(parsed.r#iOperation.is_none());
        assert_eq!(
            parsed
                .r#operationChallenge
                .map(|challenge| challenge.challenge),
            Some(0x1234)
        );
        assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[9, 8, 7][..]));
    }

    #[test]
    fn create_operation_carrier_reply_preserves_operation_challenge() {
        let carrier = vec![0u8; size_of::<flat_binder_object>() + size_of::<i32>()];
        let mut reply = build_create_operation_reply_with_carrier_bytes(
            Some(OperationChallenge { challenge: 0x5678 }),
            None,
            Some(vec![1, 2, 3]),
            &carrier,
            false,
        )
        .expect("create operation carrier reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: CreateOperationResponse =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert!(parsed.r#iOperation.is_none());
        assert_eq!(
            parsed
                .r#operationChallenge
                .map(|challenge| challenge.challenge),
            Some(0x5678)
        );
        assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[1, 2, 3][..]));
    }
}
