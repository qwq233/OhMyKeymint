use super::*;
use crate::android::hardware::security::keymint::{
    HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyParameter::KeyParameter,
    KeyParameterValue::{KeyParameterValue, Tag as KeyParameterValueTag},
    SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use crate::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec,
    IKeystoreSecurityLevel::KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING,
    KeyDescriptor::KeyDescriptor,
};
use crate::identify::{AuthorizationMethod, MaintenanceMethod};
use rsbinder::{Parcel, StatusCode, NON_NULL_PARCELABLE_FLAG};

mod authorization;
mod maintenance;
mod operation;
mod security_level;
mod serialization;
mod service;

fn raw_parts(parcel: &mut Vec<u8>) -> (*mut u8, usize, *mut usize, usize) {
    (parcel.as_mut_ptr(), parcel.len(), std::ptr::null_mut(), 0)
}

fn tx(offset: u32) -> u32 {
    rsbinder::FIRST_CALL_TRANSACTION + offset
}

fn build_request_with_payload(interface: &str, write_payload: impl FnOnce(&mut Parcel)) -> Vec<u8> {
    build_request_with_marker(interface, rsbinder::INTERFACE_HEADER, write_payload)
}

fn request_bytes(parcel: &mut Parcel) -> Vec<u8> {
    let original_position = parcel.data_position();
    parcel.set_data_position(0);
    let mut bytes = Vec::new();
    while bytes.len() < parcel.data_size() {
        let chunk: [u8; 4] = parcel.try_into().unwrap();
        bytes.extend_from_slice(&chunk);
    }
    bytes.truncate(parcel.data_size());
    parcel.set_data_position(original_position);
    bytes
}

fn build_request_with_marker(
    interface: &str,
    marker: u32,
    write_payload: impl FnOnce(&mut Parcel),
) -> Vec<u8> {
    let mut parcel = Parcel::new();
    parcel.write(&0i32).unwrap();
    parcel.write(&0i32).unwrap();
    parcel.write(&marker).unwrap();
    parcel.write(&interface.to_string()).unwrap();
    write_payload(&mut parcel);
    request_bytes(&mut parcel)
}

fn parse_maintenance_request_for_android(
    android_major_version: Option<i32>,
    code: rsbinder::TransactionCode,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedMaintenanceRequest> {
    let mut request = build_request_with_payload(KEYSTORE_MAINTENANCE_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe {
        parse_maintenance_request_with_resolver(
            data,
            data_size,
            offsets,
            offsets_size,
            code,
            |code| crate::identify::maintenance_method_from_code_for(android_major_version, code),
        )
    }
}

fn parse_authorization_request_as_method(
    method: AuthorizationMethod,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedAuthorizationRequest> {
    let mut request = build_request_with_payload(KEYSTORE_AUTHORIZATION_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe {
        parse_authorization_request_with_resolver(
            data,
            data_size,
            offsets,
            offsets_size,
            rsbinder::FIRST_CALL_TRANSACTION,
            |_| Some(method),
        )
    }
}

fn parse_maintenance_request_as_method(
    method: MaintenanceMethod,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedMaintenanceRequest> {
    let mut request = build_request_with_payload(KEYSTORE_MAINTENANCE_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe {
        parse_maintenance_request_with_resolver(
            data,
            data_size,
            offsets,
            offsets_size,
            rsbinder::FIRST_CALL_TRANSACTION,
            |_| Some(method),
        )
    }
}

fn blob_key_descriptor(blob: Option<Vec<u8>>) -> KeyDescriptor {
    KeyDescriptor {
        domain: crate::android::system::keystore2::Domain::Domain::BLOB,
        nspace: 0,
        alias: None,
        blob,
    }
}

fn parse_security_level_key_request(
    code: rsbinder::TransactionCode,
    key: &KeyDescriptor,
) -> ParsedSecurityLevelRequest {
    let mut request = build_request_with_payload(KEYSTORE_SECURITY_LEVEL_INTERFACE, |parcel| {
        parcel.write(key).unwrap();
    });
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe { parse_security_level_request(data, data_size, offsets, offsets_size, code) }
        .expect("security-level key request should parse")
}

fn parse_security_level_request_with_payload(
    code: rsbinder::TransactionCode,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedSecurityLevelRequest> {
    let mut request = build_request_with_payload(KEYSTORE_SECURITY_LEVEL_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe { parse_security_level_request(data, data_size, offsets, offsets_size, code) }
}

fn parse_service_request_with_payload(
    code: rsbinder::TransactionCode,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedServiceRequest> {
    let mut request = build_request_with_payload(KEYSTORE_SERVICE_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe { parse_service_request(data, data_size, offsets, offsets_size, code) }
}

fn parse_operation_request_with_payload(
    code: rsbinder::TransactionCode,
    write_payload: impl FnOnce(&mut Parcel),
) -> Result<ParsedOperationRequest> {
    let mut request = build_request_with_payload(KEYSTORE_OPERATION_INTERFACE, write_payload);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);
    unsafe { parse_operation_request(data, data_size, offsets, offsets_size, code) }
}

fn assert_status_code<T>(result: Result<T>, expected: StatusCode) {
    let error = match result {
        Ok(_) => panic!("request should fail"),
        Err(error) => error,
    };
    let status = error.chain().find_map(|cause| cause.downcast_ref::<StatusCode>().copied());
    assert_eq!(status, Some(expected));
}

fn write_single_blob_key_parameter_array(parcel: &mut Parcel, tag: Tag, blob_len: i32) {
    parcel.write(&1i32).unwrap();
    parcel.write(&NON_NULL_PARCELABLE_FLAG).unwrap();
    parcel
        .sized_write(|sub_parcel| {
            sub_parcel.write(&tag)?;
            sub_parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
            sub_parcel.write(&KeyParameterValueTag::r#blob.0)?;
            sub_parcel.write(&blob_len)?;
            Ok(())
        })
        .unwrap();
}
