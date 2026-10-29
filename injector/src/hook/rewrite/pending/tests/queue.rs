use super::*;

#[test]
fn owned_outbound_reply_clears_tf_status_code() {
    let fd = 31;
    clear_outbound_reply_buffers(fd);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.flags = crate::hook::binder::TF_STATUS_CODE;
    let reply = parcel::build_void_reply().expect("void reply should build");
    let data_size = reply.data_size();
    let offsets_size = reply.offsets_size();
    let data = reply.data_ptr() as libc::c_ulong;
    let offsets = reply.offsets.as_ptr() as libc::c_ulong;

    unsafe { install_outbound_reply(fd, &mut tr, reply) };

    assert_eq!(tr.flags & crate::hook::binder::TF_STATUS_CODE, 0);
    assert_eq!(tr.data_size, data_size);
    assert_eq!(tr.offsets_size, offsets_size);
    assert_eq!(unsafe { tr.data.ptr.buffer }, data);
    assert_eq!(unsafe { tr.data.ptr.offsets }, if offsets_size == 0 { 0 } else { offsets });
    clear_outbound_reply_buffers(fd);
}

#[test]
fn outbound_reply_cleanup_is_isolated_by_binder_fd() {
    let first_fd = 32;
    let second_fd = 33;
    clear_outbound_reply_buffers(first_fd);
    clear_outbound_reply_buffers(second_fd);

    let mut first_tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    unsafe {
        install_outbound_reply(
            first_fd,
            &mut first_tr,
            parcel::build_void_reply().expect("first reply should build"),
        )
    };

    let target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
    let retirement = NativeBinderRetirement { target, generation: 1 };
    let mut second_reply = parcel::build_void_reply().expect("second reply should build");
    second_reply.native_operation = Some(retirement);
    let mut second_tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    unsafe { install_outbound_reply(second_fd, &mut second_tr, second_reply) };
    let second_data = unsafe { second_tr.data.ptr.buffer as usize };

    clear_outbound_reply_buffers(first_fd);
    assert_eq!(commit_bc_reply(second_fd, None, second_data), Some(retirement));
    clear_outbound_reply_buffers(second_fd);
}

#[test]
fn pending_reply_queue_consumes_nested_requests_from_the_top() {
    let _guard = route_state_test_guard();
    let fd = 38;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    assert!(take_top_pending(fd).is_none());

    push_pending_frame(fd);
    assert!(matches!(take_top_pending(fd), Some(None)));

    push_pending_frame(fd);
    replace_top_pending(
        fd,
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
            caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        }),
    );

    push_pending_frame(fd);
    replace_top_pending(
        fd,
        PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry { key: sample_key_descriptor() },
            caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        }),
    );

    let Some(Some(PendingCall::Service(first))) = take_top_pending(fd) else {
        panic!("top call should be a service request");
    };
    assert_eq!(first.request.method(), ServiceMethod::GetKeyEntry);

    let Some(Some(PendingCall::Service(second))) = take_top_pending(fd) else {
        panic!("outer call should be a service request");
    };
    assert_eq!(second.request.method(), ServiceMethod::GetSecurityLevel);
    assert!(take_top_pending(fd).is_none());

    let legacy = PendingCall::Authorization(PendingAuthorizationCall {
        request: ParsedAuthorizationRequest::OnDeviceUnlocked { user_id: 10, password: None },
        method: AuthorizationMethod::LegacyOnLockScreenEvent,
        caller: CallerInfo { uid: 1000, sid: String::new(), pid: 2000 },
        config: Arc::new(config::InjectorConfig::default()),
    });
    assert_eq!(legacy.reply_log_context().1, "LegacyOnLockScreenEvent");
}

#[test]
fn pending_reply_queue_claims_only_the_matching_binder_fd() {
    let _guard = route_state_test_guard();
    let first_fd = 39;
    let second_fd = 40;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    push_pending_frame(first_fd);
    push_pending_frame(second_fd);

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let first_frame = unsafe { handle_bc_reply(first_fd, &mut tr, true) };
    assert!(first_frame.is_some());
    assert_eq!(pending_reply_frame_claims_for_test(first_fd), vec![true]);
    assert_eq!(pending_reply_frame_claims_for_test(second_fd), vec![false]);

    abort_bc_reply(first_fd, first_frame, 0);
    let second_frame = unsafe { handle_bc_reply(second_fd, &mut tr, true) };
    assert!(second_frame.is_some());
    abort_bc_reply(second_fd, second_frame, 0);
    assert!(PENDING_REPLY_QUEUE.with(|slot| slot.borrow().is_empty()));
}

#[test]
fn native_reply_sentinel_preserves_the_outer_pending_frame() {
    let _guard = route_state_test_guard();
    let fd = 41;
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    push_pending_frame(fd);
    push_pending_frame(fd);

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let native_frame = unsafe { handle_bc_reply(fd, &mut tr, false) };
    assert!(native_frame.is_some());
    assert_eq!(pending_reply_frame_claims_for_test(fd), vec![false, true]);

    abort_bc_reply(fd, native_frame, 0);
    assert_eq!(pending_reply_frame_claims_for_test(fd), vec![false]);
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
}

#[test]
fn payload_preflight_follows_unclaimed_reply_order() {
    let _guard = route_state_test_guard();
    let connection = 42;
    push_pending_frame(connection);
    replace_top_pending(connection, PendingCall::Service(PendingServiceCall {
        request: ParsedServiceRequest::GetSecurityLevel {
            security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT,
        },
        caller: CallerInfo { uid: 10002, sid: String::new(), pid: 2000 },
        packages: Vec::new(),
        route: RouteTarget::System,
    }));
    push_pending_frame(connection);
    assert!(!pending_reply_requires_payload(connection, 0));
    assert!(pending_reply_requires_payload(connection, 1));
    // SAFETY: All fields and union members contain integer types that permit zero.
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    // SAFETY: The top frame has no pending call and returns before inspecting the
    // empty payload.
    let frame = unsafe { handle_bc_reply(connection, &mut tr, false) };
    assert!(pending_reply_requires_payload(connection, 0));
    abort_bc_reply(connection, frame, 0);
}

#[test]
fn precomputed_service_reply_is_moved_only_once() {
    let mut reply = PrecomputedServiceReply::Serialized(Box::new(Some(
        parcel::build_plain_reply(&7i64).unwrap(),
    )));
    let mut serialized = build_precomputed_service_reply(&mut reply).unwrap();
    assert_eq!(parcel::parse_owned_success_reply::<i64>(&mut serialized).unwrap(), 7);
    assert!(build_precomputed_service_reply(&mut reply).is_err());
}

#[test]
fn native_reply_trust_requires_matching_callback_output() {
    let _guard = route_state_test_guard();
    let connection = 43;
    let target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
    push_native_pending_frame(connection, target);
    let data = [0u8; 4];
    // SAFETY: All fields and union members contain integer types that permit zero.
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = data.len();
    tr.data.ptr.buffer = data.as_ptr() as libc::c_ulong;
    assert!(!pending_reply_has_trusted_payload(connection, 0, &tr));
    remember_native_reply(target, data.as_ptr() as usize, data.len());
    assert!(pending_reply_has_trusted_payload(connection, 0, &tr));
    tr.data.ptr.buffer = 1;
    assert!(!pending_reply_has_trusted_payload(connection, 0, &tr));
    tr.data.ptr.buffer = data.as_ptr() as libc::c_ulong;
    tr.offsets_size = std::mem::size_of::<usize>();
    assert!(!pending_reply_has_trusted_payload(connection, 0, &tr));
    tr.offsets_size = 0;
    tr.flags = crate::hook::binder::TF_STATUS_CODE;
    assert!(!pending_reply_has_trusted_payload(connection, 0, &tr));
}
