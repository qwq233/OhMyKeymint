/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::binder::AsNative;
use crate::error::{status_result, Result};
use crate::proxy::SpIBinder;
use crate::sys;

use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;

use libc::{sockaddr, sockaddr_un, sockaddr_vm, socklen_t};
use std::{mem, ptr};

/// Rust wrapper around ABinderRpc_Accessor objects for RPC binder service management.
///
/// Dropping the `Accessor` will drop the underlying object and the binder it owns.
#[derive(Debug)]
pub struct Accessor {
    accessor: *mut sys::ABinderRpc_Accessor,
}

/// Socket connection info required for libbinder to connect to a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionInfo {
    /// For vsock connection
    Vsock(sockaddr_vm),
    /// For unix domain socket connection
    Unix(sockaddr_un),
}

/// Safety: A `Accessor` is a wrapper around `ABinderRpc_Accessor` which is
/// `Sync` and `Send`. As
/// `ABinderRpc_Accessor` is threadsafe, this structure is too.
/// The Fn owned the Accessor has `Sync` and `Send` properties
unsafe impl Send for Accessor {}

/// Safety: A `Accessor` is a wrapper around `ABinderRpc_Accessor` which is
/// `Sync` and `Send`. As `ABinderRpc_Accessor` is threadsafe, this structure is too.
/// The Fn owned the Accessor has `Sync` and `Send` properties
unsafe impl Sync for Accessor {}

impl Accessor {
    /// Create a new accessor that will call the given callback when its
    /// connection info is required.
    /// The callback object and all objects it captures are owned by the Accessor
    /// and will be deleted some time after the Accessor is Dropped. If the callback
    /// is being called when the Accessor is Dropped, the callback will not be deleted
    /// immediately.
    pub fn new<F>(instance: &str, callback: F) -> Accessor
    where
        F: Fn(&str) -> Option<ConnectionInfo> + Send + Sync + 'static,
    {
        let callback: *mut c_void = Box::into_raw(Box::new(callback)) as *mut c_void;
        let inst = CString::new(instance).unwrap();

        // Safety: The function pointer is a valid connection_info callback.
        // This call returns an owned `ABinderRpc_Accessor` pointer which
        // must be destroyed via `ABinderRpc_Accessor_delete` when no longer
        // needed.
        // When the underlying ABinderRpc_Accessor is deleted, it will call
        // the cookie_decr_refcount callback to release its strong ref.
        let accessor = unsafe {
            sys::ABinderRpc_Accessor_new(
                inst.as_ptr(),
                Some(Self::connection_info::<F>),
                callback,
                Some(Self::cookie_decr_refcount::<F>),
            )
        };

        Accessor { accessor }
    }

    /// Creates a new Accessor instance based on an existing Accessor's binder.
    /// This is useful when the Accessor instance is hosted in another process
    /// that has the permissions to create the socket connection FD.
    ///
    /// The `instance` argument must match the instance that the original Accessor
    /// is responsible for.
    /// `instance` must not contain null bytes and is used to create a CString to
    /// pass through FFI.
    /// The `binder` argument must be a valid binder from an Accessor
    pub fn from_binder(instance: &str, binder: SpIBinder) -> Option<Accessor> {
        let inst = CString::new(instance).unwrap();

        // Safety: All `SpIBinder` objects (the `binder` argument) hold a valid pointer
        // to an `AIBinder` that is guaranteed to remain valid for the lifetime of the
        // SpIBinder. `ABinderRpc_Accessor_fromBinder` creates a new pointer to that binder
        // that it is responsible for.
        // The `inst` argument is a new CString that will copied by
        // `ABinderRpc_Accessor_fromBinder` and not modified.
        let accessor =
            unsafe { sys::ABinderRpc_Accessor_fromBinder(inst.as_ptr(), binder.as_raw()) };
        if accessor.is_null() {
            return None;
        }
        Some(Accessor { accessor })
    }

    /// Get the underlying binder for this Accessor for when it needs to be either
    /// registered with service manager or sent to another process.
    pub fn as_binder(&self) -> Option<SpIBinder> {
        // Safety: `ABinderRpc_Accessor_asBinder` returns either a null pointer or a
        // valid pointer to an owned `AIBinder`. Either of these values is safe to
        // pass to `SpIBinder::from_raw`.
        unsafe { SpIBinder::from_raw(sys::ABinderRpc_Accessor_asBinder(self.accessor)) }
    }

    /// Release the underlying ABinderRpc_Accessor pointer for use with the ndk API
    /// This gives up ownership of the ABinderRpc_Accessor and it is the responsibility of
    /// the caller to delete it with ABinderRpc_Accessor_delete
    ///
    /// # Safety
    ///
    /// - The returned `ABinderRpc_Accessor` pointer is now owned by the caller, who must
    ///   call `ABinderRpc_Accessor_delete` to delete the object.
    /// - This `Accessor` object is now useless after `release` so it can be dropped.
    unsafe fn release(mut self) -> *mut sys::ABinderRpc_Accessor {
        if self.accessor.is_null() {
            log::error!("Attempting to release an Accessor that was already released");
            return ptr::null_mut();
        }
        let ptr = self.accessor;
        self.accessor = ptr::null_mut();
        ptr
    }

    /// Callback invoked from C++ when the connection info is needed.
    ///
    /// # Safety
    ///
    /// - The `instance` parameter must be a non-null pointer to a valid C string for
    ///   CStr::from_ptr. The memory must contain a valid null terminator at the end of
    ///   the string within isize::MAX from the pointer. The memory must not be mutated for
    ///   the duration of this function  call and must be valid for reads from the pointer
    ///   to the null terminator.
    /// - The `cookie` parameter must be the cookie for a `Box<F>` and
    ///   the caller must hold a ref-count to it.
    unsafe extern "C" fn connection_info<F>(
        instance: *const c_char,
        cookie: *mut c_void,
    ) -> *mut binder_ndk_sys::ABinderRpc_ConnectionInfo
    where
        F: Fn(&str) -> Option<ConnectionInfo> + Send + Sync + 'static,
    {
        if cookie.is_null() || instance.is_null() {
            log::error!("Cookie({cookie:p}) or instance({instance:p}) is null!");
            return ptr::null_mut();
        }
        // Safety: The caller promises that `cookie` is for a Box<F>.
        let callback = unsafe { (cookie as *const F).as_ref().unwrap() };

        // Safety: The caller in libbinder_ndk will have already verified this is a valid
        // C string
        let inst = unsafe {
            match CStr::from_ptr(instance).to_str() {
                Ok(s) => s,
                Err(err) => {
                    log::error!("Failed to get a valid C string! {err:?}");
                    return ptr::null_mut();
                }
            }
        };

        let connection = match callback(inst) {
            Some(con) => con,
            None => {
                return ptr::null_mut();
            }
        };

        match connection {
            ConnectionInfo::Vsock(addr) => {
                // Safety: The sockaddr is being copied in the NDK API
                unsafe {
                    sys::ABinderRpc_ConnectionInfo_new(
                        &addr as *const sockaddr_vm as *const sockaddr,
                        mem::size_of::<sockaddr_vm>() as socklen_t,
                    )
                }
            }
            ConnectionInfo::Unix(addr) => {
                // Safety: The sockaddr is being copied in the NDK API
                // The cast is from sockaddr_un* to sockaddr*.
                unsafe {
                    sys::ABinderRpc_ConnectionInfo_new(
                        &addr as *const sockaddr_un as *const sockaddr,
                        mem::size_of::<sockaddr_un>() as socklen_t,
                    )
                }
            }
        }
    }

    /// Callback that drops the `Box<F>`.
    /// This is invoked from C++ when a binder is unlinked.
    ///
    /// # Safety
    ///
    /// - The `cookie` parameter must be the cookie for a `Box<F>` and
    ///   the owner must give up a ref-count to it.
    unsafe extern "C" fn cookie_decr_refcount<F>(cookie: *mut c_void)
    where
        F: Fn(&str) -> Option<ConnectionInfo> + Send + Sync + 'static,
    {
        // Safety: The caller promises that `cookie` is for a Box<F>.
        unsafe { std::mem::drop(Box::from_raw(cookie as *mut F)) };
    }
}

impl Drop for Accessor {
    fn drop(&mut self) {
        if self.accessor.is_null() {
            // This Accessor was already released.
            return;
        }
        // Safety: `self.accessor` is always a valid, owned
        // `ABinderRpc_Accessor` pointer returned by
        // `ABinderRpc_Accessor_new` when `self` was created. This delete
        // method can only be called once when `self` is dropped.
        unsafe {
            sys::ABinderRpc_Accessor_delete(self.accessor);
        }
    }
}

/// Register a new service with the default service manager.
///
/// Registers the given binder object with the given identifier. If successful,
/// this service can then be retrieved using that identifier.
///
/// This function will panic if the identifier contains a 0 byte (NUL).
pub fn delegate_accessor(name: &str, mut binder: SpIBinder) -> Result<SpIBinder> {
    let instance = CString::new(name).unwrap();
    let mut delegator = ptr::null_mut();
    let status =
    // Safety: `AServiceManager_addService` expects valid `AIBinder` and C
    // string pointers. Caller retains ownership of both pointers.
    // `AServiceManager_addService` creates a new strong reference and copies
    // the string, so both pointers need only be valid until the call returns.
        unsafe { sys::ABinderRpc_Accessor_delegateAccessor(instance.as_ptr(),
            binder.as_native_mut(), &mut delegator) };

    status_result(status)?;

    // Safety: `delegator` is either null or a valid, owned pointer at this
    // point, so can be safely passed to `SpIBinder::from_raw`.
    Ok(unsafe { SpIBinder::from_raw(delegator).expect("Expected valid binder at this point") })
}

/// Rust wrapper around ABinderRpc_AccessorProvider objects for RPC binder service management.
///
/// Dropping the `AccessorProvider` will drop/unregister the underlying object.
#[derive(Debug)]
pub struct AccessorProvider {
    accessor_provider: *mut sys::ABinderRpc_AccessorProvider,
}

/// Safety: A `AccessorProvider` is a wrapper around `ABinderRpc_AccessorProvider` which is
/// `Sync` and `Send`. As
/// `ABinderRpc_AccessorProvider` is threadsafe, this structure is too.
/// The Fn owned the AccessorProvider has `Sync` and `Send` properties
unsafe impl Send for AccessorProvider {}

/// Safety: A `AccessorProvider` is a wrapper around `ABinderRpc_AccessorProvider` which is
/// `Sync` and `Send`. As `ABinderRpc_AccessorProvider` is threadsafe, this structure is too.
/// The Fn owned the AccessorProvider has `Sync` and `Send` properties
unsafe impl Sync for AccessorProvider {}

impl AccessorProvider {
    /// Create a new `AccessorProvider` that will give libbinder `Accessors` in order to
    /// connect to binder services over sockets.
    ///
    /// `instances` is a list of all instances that this `AccessorProvider` is responsible for.
    /// It is declaring these instances as available to this process and will return
    /// `Accessor` objects for them when libbinder calls the `provider` callback.
    /// `provider` is the callback that libbinder will call when a service is being requested.
    /// The callback takes a `&str` argument representing the service that is being requested.
    /// See the `ABinderRpc_AccessorProvider_getAccessorCallback` for the C++ equivalent.
    pub fn new<F>(instances: &[String], provider: F) -> Option<AccessorProvider>
    where
        F: Fn(&str) -> Option<Accessor> + Send + Sync + 'static,
    {
        let callback: *mut c_void = Box::into_raw(Box::new(provider)) as *mut c_void;
        let c_str_instances: Vec<CString> =
            instances.iter().map(|s| CString::new(s.as_bytes()).unwrap()).collect();
        let mut c_instances: Vec<*const c_char> =
            c_str_instances.iter().map(|s| s.as_ptr()).collect();
        let num_instances: usize = c_instances.len();
        // Safety:
        // - The function pointer for the first argument is a valid `get_accessor` callback.
        // - This call returns an owned `ABinderRpc_AccessorProvider` pointer which
        //   must be destroyed via `ABinderRpc_unregisterAccessorProvider` when no longer
        //   needed.
        // - When the underlying ABinderRpc_AccessorProvider is deleted, it will call
        //   the `cookie_decr_refcount` callback on the `callback` pointer to release its
        //   strong ref.
        // - The `c_instances` vector is not modified by the function
        let accessor_provider = unsafe {
            sys::ABinderRpc_registerAccessorProvider(
                Some(Self::get_accessor::<F>),
                c_instances.as_mut_ptr(),
                num_instances,
                callback,
                Some(Self::accessor_cookie_decr_refcount::<F>),
            )
        };

        if accessor_provider.is_null() {
            return None;
        }
        Some(AccessorProvider { accessor_provider })
    }

    /// Callback invoked from C++ when an Accessor is needed.
    ///
    /// # Safety
    ///
    /// - libbinder guarantees the `instance` argument is a valid C string if it's not null.
    /// - The `cookie` pointer is same pointer that we pass to ABinderRpc_registerAccessorProvider
    ///   in AccessorProvider.new() which is the closure that we will delete with
    ///   self.accessor_cookie_decr_refcount when unregistering the AccessorProvider.
    unsafe extern "C" fn get_accessor<F>(
        instance: *const c_char,
        cookie: *mut c_void,
    ) -> *mut binder_ndk_sys::ABinderRpc_Accessor
    where
        F: Fn(&str) -> Option<Accessor> + Send + Sync + 'static,
    {
        if cookie.is_null() || instance.is_null() {
            log::error!("Cookie({cookie:p}) or instance({instance:p}) is null!");
            return ptr::null_mut();
        }
        // Safety: The caller promises that `cookie` is for a Box<F>.
        let callback = unsafe { (cookie as *const F).as_ref().unwrap() };

        let inst = {
            // Safety: The caller in libbinder_ndk will have already verified this is a valid
            // C string
            match unsafe { CStr::from_ptr(instance) }.to_str() {
                Ok(s) => s,
                Err(err) => {
                    log::error!("Failed to get a valid C string! {err:?}");
                    return ptr::null_mut();
                }
            }
        };

        match callback(inst) {
            Some(a) => {
                // Safety: This is giving up ownership of this ABinderRpc_Accessor
                // to the caller of this function (libbinder) and it is responsible
                // for deleting it.
                unsafe { a.release() }
            }
            None => ptr::null_mut(),
        }
    }

    /// Callback that decrements the ref-count.
    /// This is invoked from C++ when the provider is unregistered.
    ///
    /// # Safety
    ///
    /// - The `cookie` parameter must be the cookie for a `Box<F>` and
    ///   the owner must give up a ref-count to it.
    unsafe extern "C" fn accessor_cookie_decr_refcount<F>(cookie: *mut c_void)
    where
        F: Fn(&str) -> Option<Accessor> + Send + Sync + 'static,
    {
        // Safety: The caller promises that `cookie` is for a Box<F>.
        unsafe { std::mem::drop(Box::from_raw(cookie as *mut F)) };
    }
}

impl Drop for AccessorProvider {
    fn drop(&mut self) {
        // Safety: `self.accessor_provider` is always a valid, owned
        // `ABinderRpc_AccessorProvider` pointer returned by
        // `ABinderRpc_registerAccessorProvider` when `self` was created. This delete
        // method can only be called once when `self` is dropped.
        unsafe {
            sys::ABinderRpc_unregisterAccessorProvider(self.accessor_provider);
        }
    }
}
