use std::mem::size_of;

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{
    Deserialize, Parcel, Serialize, Status, StatusCode, Strong, NON_NULL_PARCELABLE_FLAG,
};

use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
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
    operation_method_from_code, security_level_method_from_code, service_method_from_code,
    OperationMethod, SecurityLevelMethod, ServiceMethod, KEYSTORE_OPERATION_INTERFACE,
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

pub unsafe fn parse_service_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedServiceRequest> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    if interface != KEYSTORE_SERVICE_INTERFACE {
        bail!("unexpected interface token: {}", interface);
    }

    let method = service_method_from_code(code)
        .ok_or_else(|| anyhow!("unknown IKeystoreService transaction code {}", code))?;

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

pub unsafe fn parse_security_level_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedSecurityLevelRequest> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    if interface != KEYSTORE_SECURITY_LEVEL_INTERFACE {
        bail!("unexpected interface token: {}", interface);
    }

    let method = security_level_method_from_code(code)
        .ok_or_else(|| anyhow!("unknown IKeystoreSecurityLevel transaction code {}", code))?;

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

pub unsafe fn parse_operation_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
) -> Result<ParsedOperationRequest> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    if interface != KEYSTORE_OPERATION_INTERFACE {
        bail!("unexpected interface token: {}", interface);
    }

    let method = operation_method_from_code(code)
        .ok_or_else(|| anyhow!("unknown IKeystoreOperation transaction code {}", code))?;

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

pub unsafe fn parse_success_reply<T: Deserialize>(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<T> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    parcel.read().context("failed to decode reply payload")
}

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

pub unsafe fn extract_direct_binder_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    read_reply_binder_carrier(&mut parcel, data)
}

pub unsafe fn extract_key_entry_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;

    let mut carrier = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_reply_binder_carrier(sub_parcel, data) {
            Ok(value) => carrier = Some(value),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    carrier.ok_or_else(|| anyhow!("missing key-entry binder carrier"))
}

pub unsafe fn parse_key_entry_reply_metadata(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<crate::android::system::keystore2::KeyMetadata::KeyMetadata> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;

    let mut metadata = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_reply_binder_carrier(sub_parcel, data)
            .and_then(|_| {
                sub_parcel
                    .read()
                    .context("failed to decode key-entry metadata payload")
            }) {
            Ok(value) => metadata = Some(value),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    metadata.ok_or_else(|| anyhow!("missing key-entry metadata payload"))
}

pub unsafe fn extract_create_operation_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    read_non_null_parcelable_flag(&mut parcel, "create-operation")?;

    let mut carrier = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_reply_binder_carrier(sub_parcel, data) {
            Ok(value) => carrier = Some(value),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    carrier.ok_or_else(|| anyhow!("missing create-operation binder carrier"))
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

pub fn build_key_entry_reply(reply: KeyEntryResponse) -> Result<OwnedReply> {
    let KeyEntryResponse {
        r#iSecurityLevel,
        r#metadata,
    } = reply;
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    parcel.sized_write(|sub_parcel| {
        match r#iSecurityLevel.as_ref() {
            Some(binder) => {
                binder_offset = Some(sub_parcel.data_position());
                sub_parcel.write(&Some(binder.clone()))?;
            }
            None => {
                let none: Option<Strong<dyn IKeystoreSecurityLevel>> = None;
                sub_parcel.write(&none)?;
            }
        }
        sub_parcel.write(&r#metadata)?;
        Ok(())
    })?;
    Ok(owned_reply_from_parcel(parcel, binder_offset))
}

pub fn build_key_entry_reply_with_carrier_bytes(
    metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    let mut binder_len = 0usize;
    parcel.sized_write(|sub_parcel| {
        let none: Option<Strong<dyn IKeystoreSecurityLevel>> = None;
        let start = sub_parcel.data_position();
        sub_parcel.write(&none)?;
        let end = sub_parcel.data_position();
        binder_offset = Some(start);
        binder_len = end - start;
        sub_parcel.write(&metadata)?;
        Ok(())
    })?;
    if carrier_bytes.len() != binder_len {
        bail!(
            "key-entry carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }
    let mut reply = owned_reply_from_parcel(
        parcel,
        carrier_is_object.then_some(
            binder_offset.expect("binder offset should be recorded for key-entry carrier"),
        ),
    );
    let start = binder_offset.expect("binder offset should be recorded for key-entry carrier");
    unsafe {
        std::ptr::copy_nonoverlapping(
            carrier_bytes.as_ptr(),
            reply.data_mut_ptr().add(start),
            carrier_bytes.len(),
        );
    }
    Ok(reply)
}

pub fn build_create_operation_reply(reply: CreateOperationResponse) -> Result<OwnedReply> {
    let CreateOperationResponse {
        r#iOperation,
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
    } = reply;
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    parcel.sized_write(|sub_parcel| {
        match r#iOperation.as_ref() {
            Some(binder) => {
                binder_offset = Some(sub_parcel.data_position());
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
    })?;
    Ok(owned_reply_from_parcel(parcel, binder_offset))
}

pub fn build_create_operation_reply_with_carrier_bytes(
    operation_challenge: Option<OperationChallenge>,
    parameters: Option<KeyParameters>,
    upgraded_blob: Option<Vec<u8>>,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    let mut binder_len = 0usize;
    parcel.sized_write(|sub_parcel| {
        let none: Option<Strong<dyn IKeystoreOperation>> = None;
        let start = sub_parcel.data_position();
        sub_parcel.write(&none)?;
        let end = sub_parcel.data_position();
        binder_offset = Some(start);
        binder_len = end - start;
        sub_parcel.write(&operation_challenge)?;
        sub_parcel.write(&parameters)?;
        sub_parcel.write(&upgraded_blob)?;
        Ok(())
    })?;
    if carrier_bytes.len() != binder_len {
        bail!(
            "create-operation carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }
    let mut reply = owned_reply_from_parcel(
        parcel,
        carrier_is_object.then_some(
            binder_offset.expect("binder offset should be recorded for create-operation carrier"),
        ),
    );
    let start =
        binder_offset.expect("binder offset should be recorded for create-operation carrier");
    unsafe {
        std::ptr::copy_nonoverlapping(
            carrier_bytes.as_ptr(),
            reply.data_mut_ptr().add(start),
            carrier_bytes.len(),
        );
    }
    Ok(reply)
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
    contains_utf16_token(parcel, KEYSTORE_SERVICE_INTERFACE)
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

fn read_non_null_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<()> {
    let flag: i32 = parcel
        .read()
        .with_context(|| format!("failed to decode {label} parcelable flag"))?;
    if flag != NON_NULL_PARCELABLE_FLAG {
        bail!("unexpected {label} parcelable flag: {flag}");
    }
    Ok(())
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
            r#operationChallenge: None,
            r#parameters: None,
            r#upgradedBlob: Some(vec![9, 8, 7]),
        };
        let mut reply = build_create_operation_reply(response)
            .expect("create operation reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: CreateOperationResponse =
            unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
        assert!(parsed.r#iOperation.is_none());
        assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[9, 8, 7][..]));
    }
}
