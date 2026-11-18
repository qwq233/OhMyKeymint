// SPDX-License-Identifier: Apache-2.0

//! Device-library loading and optional platform symbols for the upstream Rust runtime.

use crate::{
    binder_exception_t, binder_status_t, AIBinder, AIBinder_Class, AIBinder_DeathRecipient,
    AIBinder_DeathRecipient_onBinderUnlinked, AIBinder_handleShellCommand, AParcel,
};
use libc::{c_char, c_void, pid_t, sockaddr, socklen_t, uid_t};
use std::sync::OnceLock;

#[allow(bad_style)]
mod types {
    include!(concat!(env!("OUT_DIR"), "/platform.rs"));
}

pub use types::{
    ABinderRpc_Accessor, ABinderRpc_AccessorProvider,
    ABinderRpc_AccessorProviderUserData_deleteCallback,
    ABinderRpc_AccessorProvider_getAccessorCallback, ABinderRpc_ConnectionInfo,
    ABinderRpc_ConnectionInfoProvider, ABinderRpc_ConnectionInfoProviderUserData_delete,
    AServiceManager_PermissionType,
};

/// Device API level, cached after its first native query.
pub fn api_level() -> i32 {
    type Function = unsafe extern "C" fn() -> i32;
    static LEVEL: OnceLock<i32> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        // SAFETY: This query has a zero-argument C ABI returning an integer API level.
        let function: Function = unsafe { native_symbol(b"android_get_device_api_level\0") }
            .expect("device API level unavailable");
        // SAFETY: The query takes no arguments and the cached library stays loaded.
        unsafe { function() }
    })
}

/// Invoke the Android 13 Rust dump callback contract.
///
/// # Safety
/// The callback and arguments must satisfy the original AIBinder_onDump contract.
pub unsafe fn android13_dump(
    callback: unsafe extern "C" fn(*mut AIBinder, i32, *mut *const c_char, u32) -> binder_status_t,
    binder: *mut AIBinder,
    fd: i32,
    args: *mut *const c_char,
    count: u32,
) -> binder_status_t {
    // Android 13's Rust callback rejects null even for an empty NDK argument vector.
    if args.is_null() {
        return crate::android_c_interface_StatusCode::UNEXPECTED_NULL as binder_status_t;
    }
    // SAFETY: The caller retains the Binder, borrowed fd, and argument array.
    unsafe { callback(binder, fd, args, count) }
}

/// Resolve a C++ member or conversion function from the device Binder libraries.
///
/// # Safety
/// `T` must be a function pointer. Calls must use the full native ABI, including
/// non-trivial returns; an ABI adapter may retain the pointer solely as an address.
pub unsafe fn native_symbol<T: Copy>(name: &[u8]) -> Result<T, String> {
    static LIBRARY: OnceLock<Result<libloading::Library, libloading::Error>> = OnceLock::new();
    // SAFETY: The process already uses the device Binder runtime; this library stays loaded.
    let library = LIBRARY.get_or_init(|| unsafe { libloading::Library::new("libbinder_ndk.so") });
    let library = library.as_ref().map_err(ToString::to_string)?;
    // SAFETY: T is a function pointer; the caller guarantees calls use the full native ABI.
    unsafe { library.get::<T>(name) }.map(|symbol| *symbol).map_err(|error| error.to_string())
}

// AOSP Android 13 parcel_internal.h; newer releases provide the view function.
#[repr(C)]
struct LegacyAParcel {
    binder: *const c_void,
    parcel: *mut c_void,
    owns_parcel: u8,
}

/// View a valid NDK Parcel without changing its ownership.
///
/// # Safety
/// `parcel` must be a live device AParcel with the stated Binder and ownership origin.
pub unsafe fn platform_parcel(
    parcel: *const AParcel,
    expected_binder: *const c_void,
    owns_parcel: bool,
) -> Result<*mut c_void, String> {
    type View = unsafe extern "C" fn(*const AParcel) -> *mut c_void;
    static VIEW: OnceLock<Result<View, String>> = OnceLock::new();
    // SAFETY: The exported view takes a live AParcel and returns its borrowed native Parcel.
    let view = VIEW
        .get_or_init(|| unsafe { native_symbol(b"_Z26AParcel_viewPlatformParcelPK7AParcel\0") });
    if let Ok(view) = view {
        // SAFETY: The caller supplies a live device AParcel.
        let result = unsafe { view(parcel) };
        return if result.is_null() { Err("null platform Parcel".into()) } else { Ok(result) };
    }
    if api_level() != 33 || parcel.is_null() {
        return Err("platform Parcel view unavailable".into());
    }
    // SAFETY: The caller supplies a live AParcel; API 33 has this fixed AOSP field layout.
    let legacy = unsafe { &*parcel.cast::<LegacyAParcel>() };
    if legacy.binder != expected_binder
        || legacy.owns_parcel != u8::from(owns_parcel)
        || legacy.parcel.is_null()
        || !(legacy.parcel as usize).is_multiple_of(std::mem::align_of::<usize>())
    {
        return Err("invalid Android 13 AParcel origin".into());
    }
    Ok(legacy.parcel)
}

macro_rules! forward_platform {
    ($($name:ident => $symbol:ident($($arg:ident: $ty:ty),* $(,)?) -> $result:ty;)*) => {
        $(
            /// Forward to the matching device NDK declaration.
            ///
            /// # Safety
            /// Arguments must satisfy the original API's pointer and ownership requirements.
            pub unsafe fn $name($($arg: $ty),*) -> $result {
                type Function = unsafe extern "C" fn($($ty),*) -> $result;
                static FUNCTION: OnceLock<Function> = OnceLock::new();
                // SAFETY: The generated wrapper types match the complete NDK function ABI.
                let function = FUNCTION.get_or_init(|| unsafe {
                    native_symbol(concat!(stringify!($symbol), "\0").as_bytes())
                }.expect(concat!("device API unavailable: ", stringify!($symbol))));
                // SAFETY: The caller fulfills the original NDK pointer/ownership contract.
                unsafe { function($($arg),*) }
            }
            pub use self::$name as $symbol;
        )*
    };
}

pub mod exports {
    use super::*;

    forward_platform! {
        a_parcel_marshal => AParcel_marshal(parcel: *const AParcel, buffer: *mut u8, start: usize, len: usize) -> binder_status_t;
        a_parcel_unmarshal => AParcel_unmarshal(parcel: *mut AParcel, buffer: *const u8, len: usize) -> binder_status_t;
        a_parcel_mark_sensitive => AParcel_markSensitive(parcel: *const AParcel) -> ();
        a_ibinder_death_recipient_set_on_unlinked => AIBinder_DeathRecipient_setOnUnlinked(recipient: *mut AIBinder_DeathRecipient, callback: AIBinder_DeathRecipient_onBinderUnlinked) -> ();
        a_ibinder_set_requesting_sid => AIBinder_setRequestingSid(binder: *mut AIBinder, enable: bool) -> ();
        a_ibinder_get_calling_sid => AIBinder_getCallingSid() -> *const c_char;
        a_ibinder_mark_system_stability => AIBinder_markSystemStability(binder: *mut AIBinder) -> ();
        a_ibinder_mark_vintf_stability => AIBinder_markVintfStability(binder: *mut AIBinder) -> ();
        a_service_manager_add_service => AServiceManager_addService(binder: *mut AIBinder, instance: *const c_char) -> binder_exception_t;
        a_service_manager_register_lazy_service => AServiceManager_registerLazyService(binder: *mut AIBinder, instance: *const c_char) -> binder_status_t;
        a_service_manager_force_lazy_services_persist => AServiceManager_forceLazyServicesPersist(persist: bool) -> ();
        a_service_manager_get_service => AServiceManager_getService(instance: *const c_char) -> *mut AIBinder;
        a_service_manager_check_service => AServiceManager_checkService(instance: *const c_char) -> *mut AIBinder;
        a_service_manager_wait_for_service => AServiceManager_waitForService(instance: *const c_char) -> *mut AIBinder;
        a_service_manager_is_declared => AServiceManager_isDeclared(instance: *const c_char) -> bool;
        a_service_manager_for_each_declared_instance => AServiceManager_forEachDeclaredInstance(interface: *const c_char, context: *mut c_void, callback: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>) -> ();
        a_service_manager_check_service_access => AServiceManager_checkServiceAccess(caller_sid: *const c_char, caller_debug_pid: pid_t, caller_uid: uid_t, instance: *const c_char, permission: AServiceManager_PermissionType) -> bool;
        a_binder_process_start_thread_pool => ABinderProcess_startThreadPool() -> ();
        a_binder_process_set_thread_pool_max_thread_count => ABinderProcess_setThreadPoolMaxThreadCount(count: u32) -> bool;
        a_binder_process_join_thread_pool => ABinderProcess_joinThreadPool() -> ();
        a_binder_rpc_accessor_new => ABinderRpc_Accessor_new(instance: *const c_char, provider: ABinderRpc_ConnectionInfoProvider, data: *mut c_void, on_delete: ABinderRpc_ConnectionInfoProviderUserData_delete) -> *mut ABinderRpc_Accessor;
        a_binder_rpc_accessor_delete => ABinderRpc_Accessor_delete(accessor: *mut ABinderRpc_Accessor) -> ();
        a_binder_rpc_accessor_as_binder => ABinderRpc_Accessor_asBinder(accessor: *mut ABinderRpc_Accessor) -> *mut AIBinder;
        a_binder_rpc_accessor_from_binder => ABinderRpc_Accessor_fromBinder(instance: *const c_char, binder: *mut AIBinder) -> *mut ABinderRpc_Accessor;
        a_binder_rpc_accessor_delegate_accessor => ABinderRpc_Accessor_delegateAccessor(instance: *const c_char, binder: *mut AIBinder, delegator: *mut *mut AIBinder) -> binder_status_t;
        a_binder_rpc_connection_info_new => ABinderRpc_ConnectionInfo_new(address: *const sockaddr, len: socklen_t) -> *mut ABinderRpc_ConnectionInfo;
        a_binder_rpc_register_accessor_provider => ABinderRpc_registerAccessorProvider(provider: ABinderRpc_AccessorProvider_getAccessorCallback, instances: *const *const c_char, count: usize, data: *mut c_void, on_delete: ABinderRpc_AccessorProviderUserData_deleteCallback) -> *mut ABinderRpc_AccessorProvider;
        a_binder_rpc_unregister_accessor_provider => ABinderRpc_unregisterAccessorProvider(provider: *mut ABinderRpc_AccessorProvider) -> ();
    }

    /// Preserve the Rust runtime's platform-specific shell callback registration.
    ///
    /// # Safety
    /// The class and callback must satisfy the original NDK declaration.
    pub unsafe fn a_ibinder_class_set_handle_shell_command(
        class: *mut AIBinder_Class,
        callback: AIBinder_handleShellCommand,
    ) {
        if api_level() < 37 {
            return;
        }
        type Function = unsafe extern "C" fn(*mut AIBinder_Class, AIBinder_handleShellCommand);
        static FUNCTION: OnceLock<Function> = OnceLock::new();
        // SAFETY: The symbol has the original class/callback ABI.
        let function = FUNCTION.get_or_init(|| {
            unsafe { native_symbol(b"AIBinder_Class_setHandleShellCommand\0") }
                .expect("device API unavailable: AIBinder_Class_setHandleShellCommand")
        });
        // SAFETY: The caller supplies a live class and valid callback.
        unsafe { function(class, callback) };
    }

    pub use self::a_ibinder_class_set_handle_shell_command as AIBinder_Class_setHandleShellCommand;

    /// Register diagnostic function names when supported by this device.
    ///
    /// # Safety
    /// The class and string-pointer array must satisfy the NDK declaration.
    pub unsafe fn set_transaction_code_to_function_name_map(
        class: *mut AIBinder_Class,
        names: *const *const c_char,
        len: usize,
    ) {
        if api_level() >= 36 {
            type Function = unsafe extern "C" fn(*mut AIBinder_Class, *const *const c_char, usize);
            static FUNCTION: OnceLock<Option<Function>> = OnceLock::new();
            // SAFETY: The symbol has the declared class/string-array/count ABI.
            if let Some(function) = FUNCTION.get_or_init(|| unsafe {
                native_symbol(b"AIBinder_Class_setTransactionCodeToFunctionNameMap\0").ok()
            }) {
                // SAFETY: The caller supplies a valid class and string-pointer array.
                unsafe { function(class, names, len) };
            }
        }
    }

    pub use self::set_transaction_code_to_function_name_map as AIBinder_Class_setTransactionCodeToFunctionNameMap;

    /// Set RT inheritance without requiring an absent optional symbol to disable it.
    ///
    /// # Safety
    /// The Binder must be live for the duration of this call.
    pub unsafe fn set_inherit_rt(binder: *mut AIBinder, enable: bool) {
        type Function = unsafe extern "C" fn(*mut AIBinder, bool);
        static FUNCTION: OnceLock<Option<Function>> = OnceLock::new();
        // SAFETY: The symbol has the declared AIBinder/bool ABI.
        let function =
            FUNCTION.get_or_init(|| unsafe { native_symbol(b"AIBinder_setInheritRt\0").ok() });
        if !enable && function.is_none() {
            return;
        }
        // SAFETY: The caller retains the live Binder required by this NDK setter.
        unsafe { function.expect("device RT inheritance API unavailable")(binder, enable) };
    }

    pub use self::set_inherit_rt as AIBinder_setInheritRt;

    macro_rules! stability_query {
        ($($name:ident => $symbol:ident;)*) => {$(
            /// Query optional platform stability metadata.
            ///
            /// # Safety
            /// The Binder must be live for the duration of this call.
            pub unsafe fn $name(binder: *mut AIBinder) -> bool {
                if api_level() < 37 {
                    return false;
                }
                type Function = unsafe extern "C" fn(*mut AIBinder) -> bool;
                static FUNCTION: OnceLock<Option<Function>> = OnceLock::new();
                // SAFETY: Each listed query has the declared AIBinder/bool-result ABI.
                match FUNCTION.get_or_init(|| unsafe {
                    native_symbol(concat!(stringify!($symbol), "\0").as_bytes()).ok()
                }) {
                    // SAFETY: The caller retains the live Binder required by this query.
                    Some(function) => unsafe { function(binder) },
                    None => false,
                }
            }
            pub use self::$name as $symbol;
        )*};
    }

    stability_query! {
        requires_vintf_declaration => AIBinder_requiresVintfDeclaration;
        is_vendor_stable => AIBinder_isVendorStable;
        is_system_stable => AIBinder_isSystemStable;
    }
}

pub use exports::{
    is_system_stable, is_vendor_stable, requires_vintf_declaration,
    set_transaction_code_to_function_name_map,
};
