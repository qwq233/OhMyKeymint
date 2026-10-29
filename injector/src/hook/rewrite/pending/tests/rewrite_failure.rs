use super::*;

#[test]
fn service_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };
    let pending = |route| {
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry { key: sample_key_descriptor() },
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route,
        })
    };

    assert!(!pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::Omk)));
    assert!(pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::System)));
}

#[test]
fn security_level_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };
    let pending = |route| {
        PendingCall::SecurityLevel(PendingSecurityLevelCall {
            request: ParsedSecurityLevelRequest::CreateOperation {
                key: sample_key_descriptor(),
                operation_parameters: vec![],
                forced: false,
            },
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route,
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        })
    };

    assert!(!pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::Omk)));
    assert!(pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::System)));
}

#[test]
fn operation_rewrite_failure_uses_pending_route_after_mapping_retirement() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget { ptr: 0x1111, cookie: 0x2222 };
    for route in [RouteTarget::System, RouteTarget::Omk] {
        remember_operation_target(
            target,
            OperationTargetInfo { route, aad_allowed: true, backend: None, finalized: false },
        );
        let pending = PendingCall::Operation(PendingOperationCall {
            request: ParsedOperationRequest::Update { input: vec![1] },
            caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
            target,
            route,
        });
        forget_operation_target(target);
        assert_eq!(
            pending_preserves_system_on_rewrite_failure(&pending),
            route == RouteTarget::System
        );
    }
}

#[test]
fn mirror_rewrite_failure_uses_actual_caller_and_config_snapshot() {
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };
    for in_scope in [false, true] {
        let mut cfg = config::InjectorConfig::default();
        cfg.filter.enabled = !in_scope;
        let cfg = Arc::new(cfg);
        let authorization = PendingCall::Authorization(PendingAuthorizationCall {
            request: ParsedAuthorizationRequest::AddAuthToken { auth_token: Default::default() },
            method: AuthorizationMethod::AddAuthToken,
            caller: caller.clone(),
            config: Arc::clone(&cfg),
        });
        let maintenance = PendingCall::Maintenance(PendingMaintenanceCall {
            request: ParsedMaintenanceRequest::OnUserAdded { user_id: 10 },
            caller: caller.clone(),
            route: RouteTarget::System,
            config: cfg,
        });
        assert_eq!(pending_preserves_system_on_rewrite_failure(&authorization), !in_scope);
        assert_eq!(pending_preserves_system_on_rewrite_failure(&maintenance), !in_scope);
    }
}

#[test]
fn migration_rewrite_failure_preserves_only_system_route() {
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };
    let request = ParsedMaintenanceRequest::MigrateKeyNamespace {
        source: sample_key_descriptor(),
        destination: sample_key_descriptor(),
    };
    let pending = |route| {
        PendingCall::Maintenance(PendingMaintenanceCall {
            request: request.clone(),
            caller: caller.clone(),
            route,
            config: Arc::new(config::InjectorConfig::default()),
        })
    };

    assert!(pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::System)));
    assert!(!pending_preserves_system_on_rewrite_failure(&pending(RouteTarget::Omk)));
}
