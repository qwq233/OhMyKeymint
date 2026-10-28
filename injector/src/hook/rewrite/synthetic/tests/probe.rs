use super::*;

#[test]
fn operation_publication_probe_skips_a_deferred_front_entry() {
    let _guard = route_state_test_guard();
    let deferred = allocate_test_target();
    register_operation_publication(deferred).unwrap();
    let deferred_retirement = complete_test_publication(deferred, 20);
    let probe = take_ready_operation_publication_probe().unwrap();
    let requeued_at = Instant::now();
    assert_eq!(
        finish_operation_publication_probe(probe, Ok(true), requeued_at),
        None
    );

    let ready = allocate_test_target();
    register_operation_publication(ready).unwrap();
    let ready_retirement = complete_test_publication(ready, 21);
    let probe =
        take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_PROBE_GRACE * 2)
            .unwrap();
    assert_eq!(probe.target, ready);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(ready_retirement)
    );

    let probe = take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY)
        .unwrap();
    assert_eq!(probe.target, deferred);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(deferred_retirement)
    );
    clear_operation_state_for_tests();
}

#[test]
fn publication_probe_requeue_is_lock_free_and_acquire_safe() {
    let _guard = route_state_test_guard();
    let stale = allocate_test_target();
    register_operation_publication(stale).unwrap();
    let stale_retirement = complete_test_publication(stale, 20);
    assert_eq!(
        mark_operation_publication_acquire_pending(stale, 20),
        Some(stale_retirement)
    );
    mark_operation_publication_acquire_committed(stale_retirement);

    let live = allocate_test_target();
    register_operation_publication(live).unwrap();
    let live_retirement = complete_test_publication(live, 21);
    let first = take_ready_operation_publication_probe().unwrap();
    assert_eq!(first.target, live);
    assert!(OPERATION_PUBLICATIONS.try_lock().is_ok());
    let requeued_at = Instant::now();
    assert_eq!(
        finish_operation_publication_probe(first, Ok(true), requeued_at),
        None
    );
    assert!(take_operation_publication_probe(
        requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY / 2
    )
    .is_none());

    let probe = take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY)
        .unwrap();
    assert_eq!(
        mark_operation_publication_acquire_pending(live, 21),
        Some(live_retirement)
    );
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        None
    );
    mark_operation_publication_acquire_committed(live_retirement);
    assert!(!OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&live));
}

#[test]
fn missing_operation_node_reclaims_publication_without_lock() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 24);
    assert!(take_operation_publication_probe(Instant::now()).is_none());
    let probe = take_ready_operation_publication_probe().unwrap();
    assert!(OPERATION_PUBLICATIONS.try_lock().is_ok());
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
fn transient_node_query_error_requeues_publication() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    register_operation_publication(target).unwrap();
    let retirement = complete_test_publication(target, 25);
    let probe = take_ready_operation_publication_probe().unwrap();
    let requeued_at = Instant::now();
    assert_eq!(
        finish_operation_publication_probe(probe, Err(libc::EIO), requeued_at),
        None
    );
    assert_eq!(
        OPERATION_PUBLICATION_PROBES
            .lock()
            .expect("operation publication probe queue poisoned")
            .iter()
            .filter(|probe| probe.target == target)
            .count(),
        1
    );
    let probe =
        take_operation_publication_probe(requeued_at + OPERATION_PUBLICATION_REPROBE_DELAY * 2)
            .unwrap();
    assert_eq!(probe.query_failures, 1);
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(retirement)
    );
}

#[test]
fn persistent_node_query_errors_back_off_without_retiring_backend() {
    let _guard = route_state_test_guard();
    ensure_binder_process_state();
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
    mark_operation_publication_completed(retirement, binder_token(26));
    let mut attempt_at = Instant::now() + OPERATION_PUBLICATION_PROBE_GRACE;

    for failure in 1..=OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT + 2 {
        let probe = take_operation_publication_probe(attempt_at).unwrap();
        assert_eq!(probe.target, retirement.target);
        assert_eq!(
            finish_operation_publication_probe(probe, Err(libc::EPERM), attempt_at),
            None
        );
        let queued = OPERATION_PUBLICATION_PROBES
            .lock()
            .expect("operation publication probe queue poisoned")
            .iter()
            .find(|probe| probe.target == retirement.target)
            .copied()
            .unwrap();
        let expected_failures = failure.min(OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT);
        assert_eq!(queued.query_failures, expected_failures);
        assert_eq!(
            queued.not_before.duration_since(attempt_at),
            OPERATION_PUBLICATION_REPROBE_DELAY
                .saturating_mul(1u32 << u32::from(expected_failures))
        );
        attempt_at = queued.not_before;
    }

    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&retirement.target));
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
    assert!(lookup_native_operation_state(retirement.target).is_some());
    assert_eq!(
        lookup_synthetic_target(retirement.target),
        Some(SyntheticTargetKind::Operation)
    );
    assert!(lookup_native_binder(retirement.target).is_some());
    let probe = take_operation_publication_probe(attempt_at).unwrap();
    assert_eq!(
        finish_operation_publication_probe_for_test(probe, Ok(false)),
        Some(retirement)
    );
    drop_synthetic_operation_retirement(retirement);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(lookup_native_operation_state(retirement.target).is_none());
    assert!(lookup_synthetic_target(retirement.target).is_none());
    assert!(lookup_native_binder(retirement.target).is_none());
}
