use super::*;

#[test]
fn native_request_offsets_admit_base_transactions_only() {
    assert_eq!(native_request_offsets(1, 0), Some([].as_slice()));
    assert_eq!(native_request_offsets(rsbinder::SHELL_COMMAND_TRANSACTION, 3), Some([].as_slice()));
    assert_eq!(
        native_request_offsets(rsbinder::DUMP_TRANSACTION, 1),
        Some(DUMP_OBJECT_OFFSETS.as_slice())
    );
    assert!(native_request_offsets(1, 1).is_none());
    assert!(native_request_offsets(rsbinder::DUMP_TRANSACTION, 2).is_none());
}

#[test]
fn legacy_aparcel_matches_android_12_13_aarch64_layout() {
    assert_eq!(size_of::<usize>(), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, binder), 0);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, parcel), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, owns_parcel), 16);
    assert_eq!(size_of::<LegacyAParcel>(), 24);
}

#[test]
fn receiving_interface_uses_native_descriptor_and_releases_promotions() {
    unsafe extern "C" fn fail_query(
        _: *mut c_void,
        _: u32,
        _: *const c_void,
        _: *mut c_void,
        _: u32,
    ) -> i32 {
        rsbinder::StatusCode::BadValue.into()
    }
    unsafe extern "C" fn fail_promotion(_: *mut c_void, _: *const c_void) -> bool {
        false
    }
    let mut api = unsafe { NativeBinderApi::load() }.unwrap();
    let native = create_native_binder_with_api(&api, NativeBinderKind::SecurityLevel).unwrap();
    let debug_count: unsafe extern "C" fn(*mut c_void) -> i32 = unsafe {
        load_symbol(open_library(b"libbinder_ndk.so\0").unwrap(), b"AIBinder_debugGetRefCount\0")
    }
    .unwrap();
    let before = unsafe { debug_count(native.raw_ptr()) };
    let state = unsafe { (api.ipc_thread_state_self)() };
    let flags = unsafe { (api.ipc_thread_state_get_last_transaction_binder_flags)(state) };
    assert!(unsafe {
        local_binder_interface_matches_with_api(
            &api,
            native.target(),
            crate::identify::KEYSTORE_SECURITY_LEVEL_INTERFACE,
        )
    }
    .unwrap());
    assert!(!unsafe {
        local_binder_interface_matches_with_api(
            &api,
            native.target(),
            crate::identify::KEYSTORE_MAINTENANCE_INTERFACE,
        )
    }
    .unwrap());
    assert_eq!(unsafe { debug_count(native.raw_ptr()) }, before);
    assert_eq!(unsafe { (api.ipc_thread_state_get_last_transaction_binder_flags)(state) }, flags);

    api.platform_binder_on_transact = Some(fail_query);
    assert!(unsafe { local_binder_interface_matches_with_api(&api, native.target(), "unused") }
        .is_err());
    assert_eq!(unsafe { debug_count(native.raw_ptr()) }, before);
    api.attempt_inc_strong = Some(fail_promotion);
    assert!(!unsafe {
        local_binder_interface_matches_with_api(
            &api,
            LocalBinderTarget { ptr: native.target().ptr, cookie: 1 },
            "unused",
        )
    }
    .unwrap());
    api.attempt_inc_strong = None;
    assert!(unsafe { local_binder_interface_matches_with_api(&api, native.target(), "unused") }
        .is_err());
}
