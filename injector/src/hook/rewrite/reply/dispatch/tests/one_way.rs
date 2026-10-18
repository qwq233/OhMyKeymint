use super::*;

#[test]
fn one_way_synthetic_operation_abort_finalizes_mapping() {
    let _guard = route_state_test_guard();

    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![9],
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let caller = CallerInfo {
        uid: 10002,
        sid: "u:r:untrusted_app:s0:c123,c456".into(),
        pid: 2000,
    };
    let (carrier, _) = register_synthetic_operation_carrier(backend, true, &caller)
        .expect("operation carrier should register");
    let target = carrier_target(&carrier);
    let service_specific_error = |reply: SyntheticReply| -> i32 {
        let SyntheticReply::Parcel(mut reply) = reply else {
            panic!("expected status parcel reply");
        };
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");
        assert_eq!(
            status.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        status.service_specific_error()
    };

    let abort_request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    let (mut abort_tr, _abort_data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        abort_request,
    );
    abort_tr.flags |= crate::hook::binder::TF_ONE_WAY;

    let abort_reply = unsafe { handle_synthetic_br_transaction(&abort_tr, None, "BR_TRANSACTION") }
        .expect("one-way abort should be consumed");
    assert!(matches!(abort_reply, SyntheticReply::NoReply));
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_operation_target(target).is_none());

    let mut update_request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    update_request.write(&vec![1u8]).unwrap();
    let (update_tr, _update_data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
        update_request,
    );
    let update_reply =
        unsafe { handle_synthetic_br_transaction(&update_tr, None, "BR_TRANSACTION") }
            .expect("post-abort update should be handled");
    assert_eq!(
        service_specific_error(update_reply),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );

    let abort_again_request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    let (abort_again_tr, _abort_again_data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        abort_again_request,
    );
    let abort_again_reply =
        unsafe { handle_synthetic_br_transaction(&abort_again_tr, None, "BR_TRANSACTION") }
            .expect("post-abort abort should be handled");
    assert_eq!(
        service_specific_error(abort_again_reply),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );
}

#[test]
fn one_way_dispatch_policy_allows_side_effects() {
    assert!(can_execute_one_way(
        SyntheticTargetKind::Operation,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#update
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::Operation,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#finish
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::Operation,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::Operation,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#updateAad
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importKey
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#importWrappedKey
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#createOperation
    ));
    assert!(!can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#convertStorageKeyToEphemeral
    ));
    assert!(can_execute_one_way(
        SyntheticTargetKind::SecurityLevel,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey
    ));
}
