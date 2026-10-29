use super::*;

#[test]
fn omk_route_finish_rejects_late_cleanup_abort() {
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
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

    let reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Finish { input: Some(vec![1, 2, 3]), signature: None },
        caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
        target,
        route: RouteTarget::Omk,
    })
    .expect("finish rewrite should succeed")
    .expect("OMK finish should return an OMK-owned reply");
    let mut reply = reply;
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let output: Option<Vec<u8>> =
        unsafe { parcel::parse_success_reply(data, data_size, offsets, offsets_size) }
            .expect("finish reply should deserialize");

    assert_eq!(output.as_deref(), Some(&[5, 6, 7][..]));
    let target_info =
        lookup_operation_target(target).expect("finish should keep a finalized cleanup tombstone");
    assert_eq!(target_info.route, RouteTarget::Omk);
    assert!(target_info.finalized);
    assert!(target_info.backend.is_none());

    let cleanup_reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Abort,
        caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
        target,
        route: RouteTarget::Omk,
    })
    .expect("cleanup abort rewrite should succeed")
    .expect("cleanup abort should return an OMK-owned reply");
    let mut cleanup_reply = cleanup_reply;
    let (cleanup_data, cleanup_data_size, cleanup_offsets, cleanup_offsets_size) =
        raw_parts(&mut cleanup_reply);
    let cleanup_status = unsafe {
        parcel::parse_reply_status(
            cleanup_data,
            cleanup_data_size,
            cleanup_offsets,
            cleanup_offsets_size,
        )
    }
    .expect("cleanup abort reply should deserialize");

    assert_eq!(cleanup_status.exception_code(), rsbinder::ExceptionCode::ServiceSpecific);
    assert_eq!(
        cleanup_status.service_specific_error(),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );
    assert_eq!(
        aborts.load(Ordering::SeqCst),
        0,
        "finalized cleanup should not abort the already-finished backend again"
    );
    assert!(
        lookup_operation_target(target).is_none(),
        "cleanup abort should clear the finalized tombstone"
    );
}

#[test]
fn omk_route_abort_clears_operation_mapping() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
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

    let reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Abort,
        caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
        target,
        route: RouteTarget::Omk,
    })
    .expect("abort rewrite should succeed")
    .expect("OMK abort should return an OMK-owned reply");
    let mut reply = reply;
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("abort reply should deserialize");

    assert!(status.is_ok());
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_operation_target(target).is_none(), "abort should clear the operation mapping");
}
