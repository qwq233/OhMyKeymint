use super::*;

#[test]
fn system_invalid_update_aad_preserves_native_reply() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::System,
            aad_allowed: false,
            backend: None,
            finalized: false,
        },
    );

    let reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::UpdateAad {
            aad_input: vec![1, 2, 3],
        },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("updateAad rewrite should succeed");
    assert!(
        reply.is_none(),
        "system invalid updateAad should preserve the original native reply parcel"
    );
    assert_eq!(
        lookup_operation_target(target).unwrap().route,
        RouteTarget::System
    );
}

#[test]
fn omk_invalid_update_aad_returns_business_error() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();

    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![1, 2, 3],
        aborts: Arc::new(AtomicUsize::new(0)),
        update_aad_status: Some(Status::new_service_specific_error(7, None)),
    });
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: false,
            backend: Some(Arc::new(backend)),
            finalized: false,
        },
    );

    let reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::UpdateAad {
            aad_input: vec![1, 2, 3],
        },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("updateAad rewrite should succeed")
    .expect("OMK invalid updateAad should return an OMK-owned reply");
    let mut reply = reply;
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("invalid updateAad reply should deserialize to a binder status");
    assert_eq!(
        status.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(status.service_specific_error(), 7);
    assert_eq!(
        lookup_operation_target(target).unwrap().route,
        RouteTarget::Omk
    );
}

#[test]
fn omk_route_operation_transaction_error_uses_omk_status_mapping() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![1, 2, 3],
        aborts: Arc::new(AtomicUsize::new(0)),
        update_aad_status: Some(StatusCode::UnknownTransaction.into()),
    });
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: false,
            backend: Some(Arc::new(backend)),
            finalized: false,
        },
    );

    let reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::UpdateAad {
            aad_input: vec![1, 2, 3],
        },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("transaction status should be normalized into a reply")
    .expect("OMK transaction status should return an OMK-owned reply");
    // A transport-level failure talking to the OMK operation backend is
    // reported as a service-specific SYSTEM_ERROR, matching AOSP keystore2.
    let mut reply = reply;
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");
    assert_eq!(
        parsed.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(
        parsed.service_specific_error(),
        ResponseCode::SYSTEM_ERROR.0
    );
}
