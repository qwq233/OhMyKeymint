use super::*;
use crate::android::hardware::security::keymint::{
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use crate::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, IKeystoreOperation::IKeystoreOperation,
    KeyDescriptor::KeyDescriptor, KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata,
    KeyParameters::KeyParameters, OperationChallenge::OperationChallenge,
};

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

fn null_operation_carrier_bytes() -> Vec<u8> {
    let mut parcel = Parcel::new();
    let (start, end) =
        write_none_binder_placeholder::<dyn IKeystoreOperation>(&mut parcel).unwrap();
    let bytes = parcel_bytes(&mut parcel).unwrap();
    bytes[start..end].to_vec()
}

fn assert_status_code<T>(result: Result<T>, expected: StatusCode) {
    let error = match result {
        Ok(_) => panic!("request should fail"),
        Err(error) => error,
    };
    let status = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StatusCode>().copied());
    assert_eq!(status, Some(expected));
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
fn create_operation_reply_rejects_missing_binder() {
    let response = CreateOperationResponse {
        r#iOperation: None,
        r#operationChallenge: Some(OperationChallenge { challenge: 0x1234 }),
        r#parameters: None,
        r#upgradedBlob: Some(vec![9, 8, 7]),
    };
    assert_status_code(
        build_create_operation_reply(response),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn create_operation_carrier_reply_preserves_operation_challenge() {
    let carrier = null_operation_carrier_bytes();
    let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut reply = build_create_operation_reply_with_carrier_bytes(
        Some(OperationChallenge { challenge: 0x5678 }),
        Some(KeyParameters {
            keyParameter: vec![KeyParameter {
                tag: Tag::NONCE,
                value: KeyParameterValue::Blob(nonce.clone()),
            }],
        }),
        Some(vec![1, 2, 3]),
        &carrier,
        false,
    )
    .expect("create operation carrier reply should serialize");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut parcel = unsafe { parcel_from_ipc_parts(data, data_size, offsets, offsets_size) };
    read_ok_status(&mut parcel).unwrap();
    read_non_null_parcelable_flag(&mut parcel, "create-operation").unwrap();
    let parsed: (
        Option<OperationChallenge>,
        Option<KeyParameters>,
        Option<Vec<u8>>,
    ) = read_sized_reply_payload(&mut parcel, "create-operation test payload", |sub_parcel| {
        read_reply_binder_carrier(sub_parcel, data)?;
        Ok((sub_parcel.read()?, sub_parcel.read()?, sub_parcel.read()?))
    })
    .unwrap();
    assert_eq!(parsed.0.map(|challenge| challenge.challenge), Some(0x5678));
    let parsed_nonce = parsed.1.as_ref().and_then(|parameters| {
        parameters.keyParameter.iter().find_map(|parameter| {
            if parameter.tag == Tag::NONCE {
                match &parameter.value {
                    KeyParameterValue::Blob(value) => Some(value.as_slice()),
                    _ => None,
                }
            } else {
                None
            }
        })
    });
    assert_eq!(parsed_nonce, Some(nonce.as_slice()));
    assert_eq!(parsed.2.as_deref(), Some(&[1, 2, 3][..]));
}
