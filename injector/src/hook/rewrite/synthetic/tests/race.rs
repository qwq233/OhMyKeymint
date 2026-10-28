use super::*;

#[test]
fn stale_operation_retirement_does_not_remove_reused_target_generation() {
    let _guard = route_state_test_guard();
    let target = allocate_test_target();
    let first = register_operation_publication_for_test(target);
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .insert(
            target,
            SyntheticTargetInfo {
                kind: SyntheticTargetKind::Operation,
                caller: None,
                native_generation: Some(first.generation),
                operation: None,
            },
        );
    drop_synthetic_operation_retirement(first);

    let second = register_operation_publication_for_test(target);
    OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .insert(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: false,
                backend: None,
                finalized: false,
            },
        );
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .insert(
            target,
            SyntheticTargetInfo {
                kind: SyntheticTargetKind::Operation,
                caller: None,
                native_generation: Some(second.generation),
                operation: None,
            },
        );
    mark_operation_publication_completed(second, binder_token(15));

    drop_synthetic_operation_retirement(first);
    assert_eq!(publication_retirement(target), second);
    assert!(OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .contains_key(&target));
    assert_eq!(
        SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned")
            .get(&target)
            .and_then(|info| info.native_generation),
        Some(second.generation)
    );
    assert!(OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .iter()
        .any(|probe| probe.target == target && probe.generation == second.generation));
}

#[test]
fn stale_probe_does_not_reclaim_reused_target_generation() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x6400,
        cookie: 0x7400,
    };
    register_operation_publication(target).unwrap();
    complete_test_publication(target, 23);
    let stale = take_ready_operation_publication_probe().unwrap();
    assert_eq!(stale.target, target);

    register_operation_publication(target).unwrap();
    complete_test_publication(target, 23);
    assert_eq!(
        finish_operation_publication_probe_for_test(stale, Ok(false)),
        None
    );
    assert!(OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target));
}
