use super::*;

#[test]
fn create_operation_accepts_empty_params() {
    let key = blob_key_descriptor(None);
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#createOperation,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&false).unwrap();
        },
    )
    .expect("empty createOperation params should parse");
    let ParsedSecurityLevelRequest::CreateOperation { operation_parameters, .. } = parsed else {
        panic!("createOperation request should parse");
    };
    assert!(operation_parameters.is_empty());
}

#[test]
fn create_operation_preserves_begin_metadata_params() {
    let key = blob_key_descriptor(None);
    let params = vec![
        KeyParameter { tag: Tag::ASSOCIATED_DATA, value: KeyParameterValue::Blob(vec![1]) },
        KeyParameter { tag: Tag::CONFIRMATION_TOKEN, value: KeyParameterValue::Blob(vec![2]) },
        KeyParameter { tag: Tag::MIN_SECONDS_BETWEEN_OPS, value: KeyParameterValue::Integer(30) },
        KeyParameter {
            tag: Tag::HARDWARE_TYPE,
            value: KeyParameterValue::SecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
        },
        KeyParameter { tag: Tag::UNIQUE_ID, value: KeyParameterValue::Blob(vec![3]) },
        KeyParameter {
            tag: Tag::IDENTITY_CREDENTIAL_KEY,
            value: KeyParameterValue::BoolValue(true),
        },
    ];
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#createOperation,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&params).unwrap();
            parcel.write(&false).unwrap();
        },
    )
    .expect("begin metadata createOperation params should parse");
    let ParsedSecurityLevelRequest::CreateOperation { operation_parameters, .. } = parsed else {
        panic!("createOperation request should parse");
    };
    assert_eq!(operation_parameters, params);
}

#[test]
fn generate_key_preserves_empty_params_entropy_and_flags() {
    let key = blob_key_descriptor(None);
    let flags = KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING;
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&Option::<KeyDescriptor>::None).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&flags).unwrap();
            parcel.write(&Vec::<u8>::new()).unwrap();
        },
    )
    .expect("empty generateKey params should parse");
    let ParsedSecurityLevelRequest::GenerateKey { params, flags: parsed_flags, entropy, .. } =
        parsed
    else {
        panic!("generateKey request should parse");
    };
    assert!(params.is_empty());
    assert_eq!(parsed_flags, flags);
    assert!(entropy.is_empty());
}

#[test]
fn generate_key_preserves_empty_attestation_blob() {
    let key = blob_key_descriptor(None);
    let attestation_key = blob_key_descriptor(Some(Vec::new()));
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&Some(attestation_key)).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&0i32).unwrap();
            parcel.write(&Vec::<u8>::new()).unwrap();
        },
    )
    .expect("empty optional attestation-key blob should parse");
    let ParsedSecurityLevelRequest::GenerateKey { attestation_key, .. } = parsed else {
        panic!("generateKey request should parse");
    };
    assert_eq!(attestation_key.and_then(|descriptor| descriptor.blob), Some(Vec::new()));
}

#[test]
fn import_key_preserves_empty_params_data_and_flags() {
    let key = blob_key_descriptor(None);
    let flags = KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING;
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importKey,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&Option::<KeyDescriptor>::None).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&flags).unwrap();
            parcel.write(&Vec::<u8>::new()).unwrap();
        },
    )
    .expect("empty importKey params should parse");
    let ParsedSecurityLevelRequest::ImportKey { params, flags: parsed_flags, key_data, .. } =
        parsed
    else {
        panic!("importKey request should parse");
    };
    assert!(params.is_empty());
    assert_eq!(parsed_flags, flags);
    assert!(key_data.is_empty());
}

#[test]
fn import_wrapped_key_preserves_empty_arrays_and_blobs() {
    let key = blob_key_descriptor(None);
    let wrapped_key = KeyDescriptor {
        domain: crate::android::system::keystore2::Domain::Domain::APP,
        nspace: 0,
        alias: Some("wrapped".to_string()),
        blob: Some(Vec::new()),
    };
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importWrappedKey,
        |parcel| {
            parcel.write(&wrapped_key).unwrap();
            parcel.write(&key).unwrap();
            parcel.write(&Option::<Vec<u8>>::None).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&Vec::<AuthenticatorSpec>::new()).unwrap();
        },
    )
    .expect("absent importWrappedKey masking key should parse");
    let ParsedSecurityLevelRequest::ImportWrappedKey {
        masking_key, params, authenticators, ..
    } = parsed
    else {
        panic!("importWrappedKey request should parse");
    };
    assert_eq!(masking_key, None);
    assert!(params.is_empty());
    assert!(authenticators.is_empty());

    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importWrappedKey,
        |parcel| {
            parcel.write(&wrapped_key).unwrap();
            parcel.write(&key).unwrap();
            parcel.write(&Some(Vec::<u8>::new())).unwrap();
            parcel.write(&Vec::<KeyParameter>::new()).unwrap();
            parcel.write(&Vec::<AuthenticatorSpec>::new()).unwrap();
        },
    )
    .expect("empty importWrappedKey values should parse");
    let ParsedSecurityLevelRequest::ImportWrappedKey {
        key,
        masking_key,
        params,
        authenticators,
        ..
    } = parsed
    else {
        panic!("importWrappedKey request should parse");
    };
    assert_eq!(key.blob, Some(Vec::new()));
    assert_eq!(masking_key, Some(Vec::new()));
    assert!(params.is_empty());
    assert!(authenticators.is_empty());
}

#[test]
fn key_parameter_blob_preserves_empty_application_values() {
    let key = blob_key_descriptor(None);
    for tag in [Tag::APPLICATION_ID, Tag::APPLICATION_DATA] {
        let parsed = parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&Option::<KeyDescriptor>::None).unwrap();
                write_single_blob_key_parameter_array(parcel, tag, 0);
                parcel.write(&0i32).unwrap();
                parcel.write(&Vec::<u8>::new()).unwrap();
            },
        )
        .expect("empty KeyParameterValue::Blob should parse");
        let ParsedSecurityLevelRequest::GenerateKey { params, .. } = parsed else {
            panic!("generateKey request should parse");
        };
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].tag, tag);
        assert_eq!(params[0].value, KeyParameterValue::Blob(Vec::new()));
    }
}
