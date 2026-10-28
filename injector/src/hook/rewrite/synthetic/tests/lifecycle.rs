use super::*;

#[test]
fn completion_before_acquire_finishes_publication() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 10);
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(take_operation_publication_probe(Instant::now()).is_none());

    let acquire_pending =
        std::thread::spawn(move || mark_operation_publication_acquire_pending(target, 10))
            .join()
            .expect("cross-thread publication update should not panic");
    assert_eq!(acquire_pending, Some(retirement));
    mark_operation_publication_acquire_committed(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(take_ready_operation_publication_probe().is_none());
}

#[test]
fn acquire_before_completion_finishes_publication() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = publication_retirement(target);
    bind_operation_publication_connection(retirement, 11);
    assert_eq!(
        mark_operation_publication_acquire_pending(target, 11),
        Some(retirement)
    );
    mark_operation_publication_acquire_committed(retirement);
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));

    mark_operation_publication_completed(retirement, binder_token(11));
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(take_ready_operation_publication_probe().is_none());
}

#[test]
fn cancelled_acquire_requeues_publication_probe() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 12);
    let probe = take_ready_operation_publication_probe().unwrap();
    assert_eq!(
        mark_operation_publication_acquire_pending(target, 12),
        Some(retirement)
    );
    let requeued_at = Instant::now();
    assert_eq!(
        finish_operation_publication_probe(probe, Ok(false), requeued_at),
        None
    );

    cancel_operation_publication_acquire_pending(retirement);
    let probe = take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY)
        .unwrap();
    assert_eq!(probe.target, target);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(retirement)
    );
}

#[test]
fn retired_connection_waits_for_committed_acquire() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 13);
    let probe = take_ready_operation_publication_probe().unwrap();
    assert_eq!(
        mark_operation_publication_acquire_pending(target, 13),
        Some(retirement)
    );

    retire_binder_connection_publications(13);
    assert!(operation_publication_acquire_is_pending(probe));
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Err(libc::ESTALE)),
        None
    );
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    mark_operation_publication_acquire_committed(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
}

#[test]
fn retired_connection_reclaims_abandoned_publication() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    complete_test_publication(target, 14);

    retire_binder_connection_publications(14);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
}

#[test]
fn pending_operation_publications_are_bounded() {
    let _guard = route_state_test_guard();
    for _ in 0..MAX_PENDING_OPERATION_PUBLICATIONS {
        register_operation_publication(allocate_test_target()).unwrap();
    }
    assert!(register_operation_publication(allocate_test_target()).is_err());
    clear_operation_state_for_tests();
}

#[test]
fn intercepted_operation_transaction_does_not_replace_acquire_ack() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: Vec::new(),
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let (_, retirement) = register_synthetic_operation_carrier(
        backend,
        false,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
    )
    .expect("synthetic operation carrier should register");
    let target = retirement.target;
    bind_operation_publication_connection(retirement, 26);
    mark_operation_publication_completed(retirement, binder_token(26));
    assert_eq!(
        mark_operation_publication_acquire_pending(target, 26),
        Some(retirement)
    );
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));

    let request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
    let (tr, _data) = transaction_for_parcel(
        target,
        identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION,
        request,
    );
    assert!(unsafe { handle_synthetic_br_transaction(&tr, None, "BR_TRANSACTION") }.is_some());
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    let acquired = lookup_native_binder(target).expect("host should own the published Binder");

    mark_operation_publication_acquire_committed(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(lookup_native_binder(target).is_none());
    assert!(lookup_native_operation_state(target).is_some());
    assert_eq!(
        lookup_synthetic_target(target),
        Some(SyntheticTargetKind::Operation)
    );
    drop(acquired);
    assert!(lookup_native_operation_state(target).is_none());
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn local_operation_publication_handoff_releases_initial_strong() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: Vec::new(),
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let (_, retirement) = register_synthetic_operation_carrier(
        backend,
        false,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
    )
    .expect("synthetic operation carrier should register");
    let target = retirement.target;
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    let acquired = lookup_native_binder(target).expect("host should own the published Binder");

    finish_local_operation_publication(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(lookup_native_binder(target).is_none());
    assert!(lookup_native_operation_state(target).is_some());
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
    drop(acquired);
    assert!(lookup_native_operation_state(target).is_none());
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_publication_with_live_node_waits_for_acquire() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 27);
    let in_flight_probe = take_ready_operation_publication_probe().unwrap();
    retire_synthetic_operation_target(target);
    let requeued_at = Instant::now();
    assert_eq!(
        finish_operation_publication_probe(in_flight_probe, Ok(true), requeued_at),
        None
    );
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert_eq!(
        mark_operation_publication_acquire_pending(target, 27),
        Some(retirement)
    );
    mark_operation_publication_acquire_committed(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(
        take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY)
            .is_none()
    );
}

#[test]
fn terminal_publication_without_node_is_reclaimed() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 28);
    let probe = take_ready_operation_publication_probe().unwrap();
    retire_synthetic_operation_target(target);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(retirement)
    );
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
}

#[test]
fn native_retirement_releases_unfinished_publication() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: Vec::new(),
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let (_, retirement) = register_synthetic_operation_carrier(
        backend,
        false,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
    )
    .expect("synthetic operation carrier should register");
    let target = retirement.target;
    bind_operation_publication_connection(retirement, 27);
    mark_operation_publication_completed(retirement, binder_token(27));

    release_native_operation_initial_strong(retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .iter()
        .all(|probe| probe.target != target));
    assert!(lookup_native_operation_state(target).is_none());
    assert!(lookup_synthetic_target(target).is_none());
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_reply_retires_backend_before_native_publication() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: Vec::new(),
        aborts: aborts.clone(),
        update_aad_status: None,
    });
    let (_, retirement) = register_synthetic_operation_carrier(
        backend,
        false,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
    )
    .expect("synthetic operation carrier should register");
    let target = retirement.target;
    bind_operation_publication_connection(retirement, 29);
    mark_operation_publication_completed(retirement, binder_token(29));
    assert!(take_operation_publication_probe(Instant::now()).is_none());

    retire_synthetic_operation_retirement(retirement);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_native_operation_state(target).is_none());
    assert!(lookup_synthetic_target(target).is_none());
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
    assert!(lookup_native_binder(target).is_some());

    let probe = take_operation_publication_probe(Instant::now())
        .expect("terminal retirement should make the queued probe immediately ready");
    assert_eq!(probe.target, target);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(retirement)
    );
    drop_synthetic_operation_retirement(retirement);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_native_binder(target).is_none());
}

#[test]
fn failed_handoff_retires_userdata_after_initial_native_reference_is_released() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let aborts = Arc::new(AtomicUsize::new(0));
    let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
        update_output: vec![1, 2, 3],
        aborts: Arc::clone(&aborts),
        update_aad_status: Some(Status::new_service_specific_error(
            ResponseCode::OPERATION_BUSY.0,
            None,
        )),
    });
    let (_, retirement) = register_synthetic_operation_carrier(
        backend,
        true,
        &CallerInfo {
            uid: 10002,
            sid: String::new(),
            pid: 2000,
        },
    )
    .unwrap();
    let native = lookup_native_binder(retirement.target).unwrap();
    let state = lookup_native_operation_state(retirement.target).unwrap();
    let mut busy = build_native_operation_reply(
        &ParsedOperationRequest::UpdateAad { aad_input: vec![1] },
        &state,
    )
    .unwrap();
    let (data, size, offsets, offsets_size) = raw_parts(&mut busy);
    // SAFETY: The owned reply keeps these data and offsets buffers live for
    // parsing.
    let status = unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap();
    assert_eq!(
        status.service_specific_error(),
        ResponseCode::OPERATION_BUSY.0
    );
    assert!(!state.is_finalized());
    finish_local_operation_publication(retirement);
    assert!(lookup_native_binder(retirement.target).is_none());
    retire_synthetic_operation_retirement(retirement);
    assert!(state.is_finalized());
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    let mut late =
        build_native_operation_reply(&ParsedOperationRequest::Update { input: vec![1] }, &state)
            .unwrap();
    let (data, size, offsets, offsets_size) = raw_parts(&mut late);
    // SAFETY: The owned reply keeps these data and offsets buffers live for
    // parsing.
    let status = unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap();
    assert_eq!(
        status.service_specific_error(),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );
    drop(native);
    drop(state);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
}
