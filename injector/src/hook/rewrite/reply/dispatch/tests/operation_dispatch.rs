use super::*;

#[test]
fn synthetic_operation_missing_args_keep_not_enough_data_status() {
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![5, 6, 7],
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: Some(Arc::new(backend)),
            finalized: false,
        },
    );

    for (label, code) in [
        (
            "updateAad",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#updateAad,
        ),
        (
            "update",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
        ),
        (
            "finish",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#finish,
        ),
    ] {
        let request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        let (tr, _data) = transaction_for_parcel(target, code, request);
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerInfo {
                uid: 10002,
                sid: String::new(),
                pid: 2000,
            }),
            native_generation: None,
            operation: None,
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .unwrap_or_else(|error| panic!("{label} missing args should be handled: {error:#}"));
        assert_synthetic_status(reply, StatusCode::NotEnoughData);
        assert!(
            lookup_operation_target(target).is_some(),
            "{label} missing args must not finalize the operation"
        );
    }
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn synthetic_operation_trailing_abort_finalizes_operation() {
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x1334,
        cookie: 0x5778,
    };
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![5, 6, 7],
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: Some(Arc::new(backend)),
            finalized: false,
        },
    );

    let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    request.write(&0x4f4d4bi32).unwrap();
    let (tr, _data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        request,
    );
    let info = SyntheticTargetInfo {
        kind: SyntheticTargetKind::Operation,
        caller: Some(CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        }),
        native_generation: None,
        operation: None,
    };

    let reply =
        unsafe { build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION") }
            .expect("trailing abort should be handled without fallback");
    assert_synthetic_ok_reply(reply, "trailing abort");
    assert!(
        lookup_operation_target(target).is_none(),
        "trailing abort must finalize the operation"
    );
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
}

#[test]
fn synthetic_operation_bad_interface_marker_rejects_abort() {
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x1335,
        cookie: 0x5779,
    };
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![5, 6, 7],
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: Some(Arc::new(backend)),
            finalized: false,
        },
    );

    let request = request_parcel_with_marker(identify::KEYSTORE_OPERATION_INTERFACE, 0);
    let (tr, _data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        request,
    );
    let info = SyntheticTargetInfo {
        kind: SyntheticTargetKind::Operation,
        caller: Some(CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        }),
        native_generation: None,
        operation: None,
    };

    let reply =
        unsafe { build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION") }
            .expect("bad abort marker should be handled");
    assert_synthetic_status(reply, StatusCode::BadType);
    assert!(
        lookup_operation_target(target).is_some(),
        "bad marker abort must not finalize the operation"
    );
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn synthetic_operation_dispatch_uses_registered_caller_identity() {
    let _guard = route_state_test_guard();

    for (index, label, code) in [
        (
            0,
            "updateAad",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#updateAad,
        ),
        (
            1,
            "update",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
        ),
        (
            2,
            "finish",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#finish,
        ),
        (
            3,
            "abort",
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        ),
    ] {
        let target = LocalBinderTarget {
            ptr: 0x1434 + index,
            cookie: 0x5878 + index,
        };
        let aborts = Arc::new(AtomicUsize::new(0));
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![5, 6, 7],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: Some(Arc::new(backend)),
                finalized: false,
            },
        );

        let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        match label {
            "updateAad" | "update" => request.write(&vec![1u8]).unwrap(),
            "finish" => {
                request.write(&None::<Vec<u8>>).unwrap();
                request.write(&None::<Vec<u8>>).unwrap();
            }
            "abort" => {}
            _ => unreachable!("covered operation test method"),
        }
        let (mut tr, _data) = transaction_for_parcel(target, code, request);
        tr.sender_euid = 99999;
        tr.sender_pid = 3456;
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerInfo {
                uid: 10002,
                sid: String::new(),
                pid: 2000,
            }),
            native_generation: None,
            operation: None,
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .unwrap_or_else(|error| panic!("{label} should be handled: {error:#}"));
        assert_synthetic_ok_reply(reply, label);

        if label == "abort" {
            assert_eq!(aborts.load(Ordering::SeqCst), 1);
            assert!(
                lookup_operation_target(target).is_none(),
                "abort should clear the operation mapping"
            );
        }
    }
}

#[test]
fn tracked_operation_pending_call_uses_transaction_caller_identity() {
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x1534,
        cookie: 0x5978,
    };
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: None,
            finalized: false,
        },
    );

    let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    request.write(&vec![1u8]).unwrap();
    let (mut tr, _data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
        request,
    );
    tr.sender_euid = 99999;
    tr.sender_pid = 3456;

    let fd = 37;
    let rewritten = unsafe { handle_br_transaction(fd, &mut tr, None, "BR_TRANSACTION") };
    assert!(!rewritten);
    let Some(Some(PendingCall::Operation(pending))) = take_top_pending(fd) else {
        panic!("tracked operation should still enqueue a pending operation call");
    };
    assert_eq!(pending.target, target);
    assert_eq!(pending.caller.uid, 99999);
    assert!(matches!(
        pending.request,
        ParsedOperationRequest::Update { .. }
    ));
}

#[test]
fn synthetic_unexpected_null_parse_errors_are_status_replies() {
    let _guard = route_state_test_guard();

    let operation_target = LocalBinderTarget {
        ptr: 0x2237,
        cookie: 0x6681,
    };
    let operation_info = SyntheticTargetInfo {
        kind: SyntheticTargetKind::Operation,
        caller: Some(CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        }),
        native_generation: None,
        operation: None,
    };
    for length in [-1i32, -2i32] {
        let mut invalid_input_request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        invalid_input_request.write(&length).unwrap();
        let (invalid_input_tr, _invalid_input_data) = transaction_for_parcel(
            operation_target,
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
            invalid_input_request,
        );
        let reply = unsafe {
            build_synthetic_br_transaction_reply(
                &invalid_input_tr,
                operation_target,
                operation_info.clone(),
                None,
                "BR_TRANSACTION",
            )
        }
        .expect("invalid operation update should be handled");
        assert_synthetic_exception_reply(reply, ExceptionCode::NullPointer);
    }

    let security_level_target = LocalBinderTarget {
        ptr: 0x2238,
        cookie: 0x6682,
    };
    let mut invalid_key_request = request_parcel(identify::KEYSTORE_SECURITY_LEVEL_INTERFACE);
    invalid_key_request.write(&2i32).unwrap();
    let (invalid_key_tr, _invalid_key_data) = transaction_for_parcel(
        security_level_target,
        crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
        invalid_key_request,
    );
    let reply = unsafe {
        build_synthetic_br_transaction_reply(
            &invalid_key_tr,
            security_level_target,
            SyntheticTargetInfo {
                kind: SyntheticTargetKind::SecurityLevel,
                caller: None,
                native_generation: None,
                operation: None,
            },
            None,
            "BR_TRANSACTION",
        )
    }
    .expect("invalid key presence flag should be handled");
    assert_synthetic_exception_reply(reply, ExceptionCode::NullPointer);
}

#[test]
fn synthetic_operation_unexpected_interface_returns_bad_type_status() {
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x3234,
        cookie: 0x7678,
    };
    let request = request_parcel(identify::KEYSTORE_SERVICE_INTERFACE);
    let (tr, _data) = transaction_for_parcel(
        target,
        crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
        request,
    );
    let info = SyntheticTargetInfo {
        kind: SyntheticTargetKind::Operation,
        caller: Some(CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        }),
        native_generation: None,
        operation: None,
    };

    let reply =
        unsafe { build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION") }
            .expect("unexpected interface should be handled without fallback");
    assert_synthetic_status(reply, StatusCode::BadType);
}

#[test]
fn synthetic_transaction_caller_uses_registered_sid_when_secctx_is_absent() {
    let fallback = CallerInfo {
        uid: 10002,
        sid: "u:r:untrusted_app:s0:c123,c456".into(),
        pid: 2000,
    };
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.sender_euid = 10002;
    tr.sender_pid = 3456;

    let caller = synthetic_transaction_caller(Some(&fallback), &tr, None);
    assert_eq!(caller.uid, 10002);
    assert_eq!(caller.pid, 3456);
    assert_eq!(caller.sid, fallback.sid);

    let caller = synthetic_transaction_caller(
        Some(&fallback),
        &tr,
        Some("u:r:platform_app:s0:c1,c2".to_string()),
    );
    assert_eq!(caller.sid, "u:r:platform_app:s0:c1,c2");

    tr.sender_euid = -1;
    tr.sender_pid = 0;
    let caller = synthetic_transaction_caller(Some(&fallback), &tr, None);
    assert_eq!(
        (caller.uid, caller.pid, caller.sid),
        (10002, 2000, fallback.sid)
    );

    tr.sender_pid = -1;
    let caller = synthetic_transaction_caller(None, &tr, None);
    assert_eq!((caller.uid, caller.pid, caller.sid.as_str()), (0, -1, ""));
}
