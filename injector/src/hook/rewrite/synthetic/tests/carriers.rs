use super::*;

fn no_carrier_operation_target() -> (
    LocalBinderTarget,
    parcel::OwnedReply,
    Arc<AtomicUsize>,
    CallerInfo,
) {
    ensure_binder_process_state();
    let aborts = Arc::new(AtomicUsize::new(0));
    let caller = CallerInfo {
        uid: 10002,
        sid: "u:r:untrusted_app:s0:c123,c456".into(),
        pid: 2000,
    };
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![9, 9, 9],
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let mut reply = build_no_carrier_create_operation_reply(
        CreateOperationResponse {
            r#iOperation: Some(backend),
            r#operationChallenge: None,
            r#parameters: None,
            r#upgradedBlob: Some(vec![7, 7]),
        },
        true,
        &caller,
        true,
    )
    .expect("no-carrier createOperation reply should serialize");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let carrier = unsafe {
        parcel::extract_create_operation_reply_carrier(data, data_size, offsets, offsets_size)
    }
    .expect("synthetic operation carrier should parse");
    (carrier_target(&carrier), reply, aborts, caller)
}

#[test]
fn no_carrier_omk_key_entry_reply_uses_synthetic_security_level_mapping() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();

    let security_level = SecurityLevel::TRUSTED_ENVIRONMENT;
    let metadata = KeyMetadata {
        key: KeyDescriptor {
            domain: Domain::KEY_ID,
            nspace: 0x1234,
            alias: None,
            blob: None,
        },
        keySecurityLevel: security_level,
        authorizations: vec![],
        certificate: None,
        certificateChain: None,
        modificationTimeMs: 0,
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: "u:r:untrusted_app:s0:c123,c456".into(),
        pid: 2000,
    };

    let mut reply = build_no_carrier_omk_key_entry_reply(
        KeyEntryResponse {
            r#iSecurityLevel: Some(fake_system_security_level_backend()),
            metadata,
        },
        &caller,
    )
    .expect("no-carrier OMK key-entry reply should serialize");
    let (reply_data, reply_data_size, reply_offsets, reply_offsets_size) = raw_parts(&mut reply);
    let (carrier, parsed_metadata) = unsafe {
        parcel::parse_key_entry_reply(
            reply_data,
            reply_data_size,
            reply_offsets,
            reply_offsets_size,
        )
    }
    .expect("rewritten key-entry metadata should parse");
    assert_eq!(parsed_metadata.r#key.nspace, 0x1234);
    assert_eq!(parsed_metadata.r#keySecurityLevel, security_level);

    let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
        .expect("synthetic security-level carrier should expose a native target");
    assert!(lookup_native_binder(target).is_some());
    assert_eq!(
        lookup_synthetic_target(target),
        Some(SyntheticTargetKind::SecurityLevel)
    );
    let synthetic_info =
        lookup_synthetic_target_info(target).expect("synthetic target should be tracked");
    assert_eq!(synthetic_info.kind, SyntheticTargetKind::SecurityLevel);
    assert!(synthetic_info.caller.is_none());
    let target_info = tracker::lookup_security_level_target(target)
        .expect("synthetic security-level target should be tracked");
    assert_eq!(target_info.security_level, security_level);
}

#[test]
fn no_carrier_create_operation_registers_native_mapping_and_caller() {
    let _guard = route_state_test_guard();
    let (target, _reply, _, caller) = no_carrier_operation_target();

    assert!(lookup_native_binder(target).is_some());
    assert_eq!(
        lookup_synthetic_target(target),
        Some(SyntheticTargetKind::Operation)
    );
    let target_info = lookup_native_operation_state(target)
        .expect("synthetic operation target should be tracked");
    assert!(target_info.aad_allowed);
    assert!(!target_info.is_finalized());
    let synthetic_info =
        lookup_synthetic_target_info(target).expect("synthetic target should be tracked");
    let synthetic_caller = synthetic_info
        .caller
        .as_ref()
        .expect("synthetic operation target should keep caller fallback");
    assert_eq!(synthetic_caller.sid, caller.sid);
    assert_eq!(synthetic_caller.uid, caller.uid);
    assert!(synthetic_info.native_generation.is_some());
}

#[test]
fn synthetic_operation_carrier_forwards_update() {
    let _guard = route_state_test_guard();
    let (target, _reply, _, _) = no_carrier_operation_target();
    let mut reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Update {
            input: vec![4, 5, 6],
        },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("synthetic update rewrite should succeed")
    .expect("synthetic update should return an OMK-owned reply");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let output: Option<Vec<u8>> =
        unsafe { parcel::parse_success_reply(data, data_size, offsets, offsets_size) }
            .expect("synthetic update reply should deserialize");
    assert_eq!(output.as_deref(), Some(&[9, 9, 9][..]));
}

#[test]
fn synthetic_operation_abort_keeps_tombstone_returning_invalid_handle() {
    let _guard = route_state_test_guard();
    let (target, _reply, aborts, _) = no_carrier_operation_target();
    let mut reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Abort,
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("synthetic abort rewrite should succeed")
    .expect("synthetic abort should return an OMK-owned reply");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("synthetic abort reply should deserialize");
    assert!(status.is_ok());
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_native_operation_state(target)
        .unwrap()
        .is_finalized());
    assert_eq!(
        lookup_synthetic_target(target),
        Some(SyntheticTargetKind::Operation)
    );

    let mut reply = build_operation_reply_rewrite(&PendingOperationCall {
        request: ParsedOperationRequest::Update {
            input: b"after_abort".to_vec(),
        },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        target,
        route: RouteTarget::Omk,
    })
    .expect("stale synthetic update rewrite should succeed")
    .expect("stale synthetic update should return a native-style error");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("stale update reply should deserialize");
    assert_eq!(
        status.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(
        status.service_specific_error(),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );
}

#[test]
fn one_way_create_operation_aborts_without_publishing_carrier() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();

    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: Vec::new(),
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let reply = build_no_carrier_create_operation_reply(
        CreateOperationResponse {
            r#iOperation: Some(backend),
            r#operationChallenge: None,
            r#parameters: None,
            r#upgradedBlob: None,
        },
        false,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
        false,
    )
    .expect("one-way createOperation should execute and discard its operation");

    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(reply.native_operation.is_none());
    assert_eq!(reply.offsets_size(), 0);
    assert!(OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .is_empty());
    assert!(SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .is_empty());
    assert!(NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .is_empty());
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .is_empty());
    assert!(OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .is_empty());
}

#[test]
fn synthetic_operation_release_aborts_once_and_clears_mapping() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();

    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![9, 9, 9],
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

    assert!(lookup_native_operation_state(target).is_some());
    assert_eq!(
        lookup_synthetic_target(target),
        Some(SyntheticTargetKind::Operation)
    );

    observe_synthetic_operation_release(target);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(
        lookup_native_operation_state(target).is_none(),
        "release should clear the live operation mapping"
    );
    assert!(lookup_synthetic_target(target).is_none());

    observe_synthetic_operation_release(target);
    assert_eq!(
        aborts.load(Ordering::SeqCst),
        1,
        "repeated release must not abort twice"
    );
}

#[test]
fn raw_create_operation_reply_still_does_not_register_operation_mapping() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();

    let omk_operation = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![9, 9, 9],
        aborts: Arc::new(AtomicUsize::new(0)),
        update_aad_status: None,
    });
    let mut reply = parcel::build_create_operation_reply(CreateOperationResponse {
        r#iOperation: Some(omk_operation),
        r#operationChallenge: None,
        r#parameters: None,
        r#upgradedBlob: Some(vec![7, 7]),
    })
    .expect("direct OMK createOperation reply should serialize");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed: CreateOperationResponse =
        unsafe { parcel::parse_success_reply(data, data_size, offsets, offsets_size) }
            .expect("direct OMK createOperation reply should parse");

    assert!(parsed.r#iOperation.is_some());
    assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[7, 7][..]));
    assert!(
        OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned")
            .is_empty(),
        "direct OMK replies should not register a fake system carrier mapping"
    );
}
