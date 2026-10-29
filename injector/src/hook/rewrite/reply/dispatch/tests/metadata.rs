use super::*;

fn operation_info() -> SyntheticTargetInfo {
    SyntheticTargetInfo {
        kind: SyntheticTargetKind::Operation,
        caller: Some(CallerInfo { uid: 10002, sid: String::new(), pid: 2000 }),
        native_generation: None,
        operation: None,
    }
}

fn metadata_reply(
    target: LocalBinderTarget,
    code: rsbinder::TransactionCode,
    request: rsbinder::Parcel,
) -> SyntheticReply {
    let (tr, _data) = transaction_for_parcel(target, code, request);
    unsafe {
        build_synthetic_br_transaction_reply(&tr, target, operation_info(), None, "BR_TRANSACTION")
    }
    .expect("metadata request should be handled")
}

#[test]
fn synthetic_metadata_version_matches_keystore2_contract() {
    let target = LocalBinderTarget { ptr: 0x6234, cookie: 0xa678 };
    let request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    let reply = metadata_reply(target, identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION, request);
    let SyntheticReply::Parcel(mut reply) = reply else {
        panic!("metadata version should return a parcel reply");
    };
    let version: i32 =
        parcel::parse_owned_success_reply(&mut reply).expect("metadata version should parse");
    assert_eq!(
        version,
        keystore2_aidl_metadata().expect("keystore2 metadata should resolve").version
    );
}

#[test]
fn synthetic_metadata_rejects_wrong_interface() {
    let target = LocalBinderTarget { ptr: 0x7234, cookie: 0xb678 };
    let request = request_parcel(identify::KEYSTORE_SERVICE_INTERFACE);
    let reply = metadata_reply(target, identify::AIDL_GET_INTERFACE_HASH_TRANSACTION, request);
    assert_synthetic_status(reply, StatusCode::BadType);
}

#[test]
fn synthetic_metadata_rejects_bad_interface_marker() {
    for (index, code) in [
        identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION,
        identify::AIDL_GET_INTERFACE_HASH_TRANSACTION,
    ]
    .into_iter()
    .enumerate()
    {
        let target =
            LocalBinderTarget { ptr: 0x7254 + index as u64, cookie: 0xb698 + index as u64 };
        let request = request_parcel_with_marker(identify::KEYSTORE_OPERATION_INTERFACE, 0);
        assert_synthetic_status(metadata_reply(target, code, request), StatusCode::BadType);
    }
}

#[test]
fn synthetic_metadata_accepts_trailing_payload_for_version_and_hash() {
    let expected = keystore2_aidl_metadata().expect("keystore2 metadata should resolve");

    for (index, label, code) in [
        (0, "operation version", identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION),
        (1, "operation hash", identify::AIDL_GET_INTERFACE_HASH_TRANSACTION),
    ] {
        let target = LocalBinderTarget { ptr: 0x7334 + index, cookie: 0xb778 + index };
        let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        request.write(&0x4f4d4bi32).unwrap();
        let reply = metadata_reply(target, code, request);
        let SyntheticReply::Parcel(mut reply) = reply else {
            panic!("{label} should return a parcel reply");
        };

        if code == identify::AIDL_GET_INTERFACE_HASH_TRANSACTION {
            let hash: String = parcel::parse_owned_success_reply(&mut reply)
                .unwrap_or_else(|error| panic!("{label} hash should parse: {error:#}"));
            assert_eq!(hash, expected.hash, "{label}");
        } else {
            let version: i32 = parcel::parse_owned_success_reply(&mut reply)
                .unwrap_or_else(|error| panic!("{label} version should parse: {error:#}"));
            assert_eq!(version, expected.version, "{label}");
        }
    }
}
