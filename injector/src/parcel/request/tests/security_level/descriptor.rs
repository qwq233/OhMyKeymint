use super::*;

#[test]
fn security_level_blob_descriptor_preserves_null_and_empty() {
    let parsed = parse_security_level_key_request(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
        &blob_key_descriptor(Some(Vec::new())),
    );
    let ParsedSecurityLevelRequest::DeleteKey { key } = parsed else {
        panic!("deleteKey request should parse as DeleteKey");
    };
    assert_eq!(key.domain, crate::android::system::keystore2::Domain::Domain::BLOB);
    assert_eq!(key.blob, Some(Vec::new()));

    let parsed = parse_security_level_key_request(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#convertStorageKeyToEphemeral,
        &blob_key_descriptor(Some(Vec::new())),
    );
    let ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key } = parsed else {
        panic!("convertStorageKeyToEphemeral request should parse");
    };
    assert_eq!(storage_key.domain, crate::android::system::keystore2::Domain::Domain::BLOB);
    assert_eq!(storage_key.blob, Some(Vec::new()));

    let parsed = parse_security_level_key_request(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
        &blob_key_descriptor(None),
    );
    let ParsedSecurityLevelRequest::DeleteKey { key } = parsed else {
        panic!("deleteKey request should parse as DeleteKey");
    };
    assert_eq!(key.blob, None);
}

#[test]
fn security_level_request_accepts_trailing_payload() {
    let key = blob_key_descriptor(None);
    let parsed = parse_security_level_request_with_payload(
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
        |parcel| {
            parcel.write(&key).unwrap();
            parcel.write(&0x4f4d4bi32).unwrap();
        },
    )
    .expect("security-level request with trailing payload should parse");
    let ParsedSecurityLevelRequest::DeleteKey { key } = parsed else {
        panic!("deleteKey request should parse as DeleteKey");
    };
    assert_eq!(key.blob, None);
}
