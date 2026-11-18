// SPDX-License-Identifier: Apache-2.0

//! OMK extensions kept separate from the upstream Binder implementation.

use crate::binder::{AsNative, InterfaceClass, InterfaceClassMethods};
use crate::binder_impl::{AssociateClass, Binder, Remotable};
use crate::{sys, SpIBinder, StatusCode};
use native::CppStrong;
use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::sync::{LazyLock, Mutex};

mod native;
mod parcel;
pub mod rpc;
pub use crate::sys::compat::api_level;

pub use parcel::{
    callback_parcel_view, calling_thread_state, enforce_interface, init_native_apis,
    last_transaction_flags, local_binder_interface_matches, local_binder_receiver,
    owned_parcel_view, parcel_bytes, with_calling_thread_state, with_enforced_interface,
    with_parcel_position, with_preserved_thread_state, write_decode_error, LocalBinderReceiver,
    LocalTransactionReply, ParcelView,
};

/// Linux Binder UAPI from the configured NDK, without duplicated struct definitions.
pub use crate::sys::driver;

/// Construct a class with an Android 13 dump adapter before its first instance exists.
///
/// # Safety
/// callback must accept exactly the userdata belonging to Binder<T>.
pub unsafe fn dump_interface_class<T: Remotable>(
    callback: unsafe extern "C" fn(*mut sys::AIBinder, i32, *mut *const c_char, u32) -> i32,
) -> InterfaceClass {
    let class = InterfaceClass::new::<Binder<T>>();
    if api_level() == 33 {
        let raw: *const sys::AIBinder_Class = class.into();
        // SAFETY: This fresh class has no instances, and callback matches T.
        unsafe { sys::AIBinder_Class_setOnDump(raw.cast_mut(), Some(callback)) };
    }
    class
}

/// Forward a raw dump to an observed peer, otherwise invoke the Android 13 Rust callback.
///
/// # Safety
/// binder must be a live Binder<T>; fd is borrowed and args covers count C strings.
pub unsafe fn dispatch_android13_dump<T: Remotable>(
    binder: *mut sys::AIBinder,
    fd: i32,
    args: *mut *const c_char,
    count: u32,
    peer: fn(&T) -> Option<SpIBinder>,
) -> i32 {
    // SAFETY: Binder<T>::new stores a Box<T> as this class's userdata.
    let object = unsafe { &*sys::AIBinder_getUserData(binder).cast::<T>() };
    if let Some(peer) = peer(object) {
        // SAFETY: The strong peer and borrowed fd/arguments stay live through the synchronous dump.
        return unsafe { sys::AIBinder_dump(peer.as_native().cast_mut(), fd, args, count) };
    }
    // SAFETY: T matches the installed class; this helper preserves the original callback inputs.
    unsafe {
        sys::compat::android13_dump(
            <Binder<T> as InterfaceClassMethods>::on_dump,
            binder,
            fd,
            args,
            count,
        )
    }
}

const _: () = {
    assert!(std::mem::size_of::<usize>() == 8);
    assert!(std::mem::size_of::<driver::binder_write_read>() == 48);
    assert!(std::mem::size_of::<driver::binder_transaction_data>() == 64);
    assert!(std::mem::size_of::<driver::binder_transaction_data_secctx>() == 72);
    assert!(std::mem::size_of::<driver::binder_transaction_data_sg>() == 72);
    assert!(std::mem::size_of::<driver::flat_binder_object>() == 24);
    assert!(std::mem::offset_of!(driver::binder_transaction_data, sender_euid) == 28);
};

/// Whether the device's native Binder process state already exists.
pub fn process_state_is_initialized() -> bool {
    // SAFETY: This zero-argument factory returns sp<ProcessState> through the native ABI adapter.
    unsafe { CppStrong::call(b"_ZN7android12ProcessState10selfOrNullEv\0", 0, 0) }.is_ok()
}

/// Retrieve a service using the platform's lazy-service start and waiting behavior.
pub fn get_service_once(name: &str) -> Result<Option<SpIBinder>, StatusCode> {
    let name = CString::new(name).map_err(|_| StatusCode::BAD_VALUE)?;
    // SAFETY: name is NUL-terminated; from_raw adopts the NDK's returned strong reference or null.
    Ok(unsafe { SpIBinder::from_raw(sys::AServiceManager_getService(name.as_ptr())) })
}

/// Associate a descriptor with an untyped remote interface.
pub fn associate_descriptor(binder: &SpIBinder, descriptor: &str) -> Result<(), StatusCode> {
    static CLASSES: LazyLock<Mutex<HashMap<String, InterfaceClass>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let mut binder = binder.clone();
    if let Some(class) = binder.get_class() {
        return if class.get_descriptor() == descriptor {
            Ok(())
        } else {
            Err(StatusCode::BAD_TYPE)
        };
    }
    if descriptor.as_bytes().contains(&0) {
        return Err(StatusCode::BAD_VALUE);
    }
    let class = {
        let mut classes = CLASSES.lock().expect("descriptor class cache poisoned");
        *classes.entry(descriptor.to_owned()).or_insert_with(|| {
            let descriptor = CString::new(descriptor).expect("descriptor was checked for NUL");
            // SAFETY: The NDK copies the descriptor and retains static Binder<()> callbacks.
            let class = unsafe {
                let class = sys::AIBinder_Class_define(
                    descriptor.as_ptr(),
                    Some(<Binder<()> as InterfaceClassMethods>::on_create),
                    Some(<Binder<()> as InterfaceClassMethods>::on_destroy),
                    Some(<Binder<()> as InterfaceClassMethods>::on_transact),
                );
                assert!(!class.is_null(), "AIBinder_Class_define returned null");
                sys::AIBinder_Class_setOnDump(
                    class,
                    Some(<Binder<()> as InterfaceClassMethods>::on_dump),
                );
                sys::AIBinder_Class_setHandleShellCommand(
                    class,
                    Some(<Binder<()> as InterfaceClassMethods>::on_shell_command),
                );
                class
            };
            // SAFETY: Class creation returned a non-null, process-lifetime NDK class above.
            unsafe { InterfaceClass::from_ptr(class) }
        })
    };
    if binder.associate_class(class)
        || binder.get_class().is_some_and(|class| class.get_descriptor() == descriptor)
    {
        Ok(())
    } else {
        Err(StatusCode::BAD_TYPE)
    }
}

#[cfg(test)]
mod tests {
    use super::{dispatch_android13_dump, dump_interface_class};
    use crate::binder::{AsNative, InterfaceClass, InterfaceClassMethods};
    use crate::binder_impl::Binder;
    use crate::{sys, SpIBinder, StatusCode};
    use std::ffi::{c_char, CStr};
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;

    #[test]
    fn android13_dump_preserves_peer_status_fd_and_arguments() {
        static PEER: Mutex<Option<SpIBinder>> = Mutex::new(None);
        static CALLS: Mutex<Vec<(i32, Vec<Vec<u8>>)>> = Mutex::new(Vec::new());
        const PEER_STATUS: i32 = -1234567;

        unsafe extern "C" fn dump(
            _: *mut sys::AIBinder,
            fd: i32,
            args: *mut *const c_char,
            count: u32,
        ) -> i32 {
            let mut values = Vec::new();
            for index in 0..count as usize {
                // SAFETY: The synchronous caller retains count valid C strings.
                values.push(unsafe { CStr::from_ptr(*args.add(index)) }.to_bytes().to_vec());
            }
            CALLS.lock().unwrap().push((fd, values));
            PEER_STATUS
        }

        let instance = |class: InterfaceClass| {
            let class: *const sys::AIBinder_Class = class.into();
            // SAFETY: This class uses Binder<()> callbacks and owns a matching Box<()>.
            unsafe {
                SpIBinder::from_raw(sys::AIBinder_new(class, Box::into_raw(Box::new(())).cast()))
            }
            .unwrap()
        };
        let class = InterfaceClass::new::<Binder<()>>();
        let raw: *const sys::AIBinder_Class = class.into();
        // SAFETY: No instance exists yet; dump accepts this class's callback inputs.
        unsafe { sys::AIBinder_Class_setOnDump(raw.cast_mut(), Some(dump)) };
        let peer = instance(class);
        let receiver = instance(InterfaceClass::new::<Binder<()>>());
        let fd = std::fs::File::open("/dev/null").unwrap();
        let raw_receiver = receiver.as_native().cast_mut();
        let mut args = [c"--test".as_ptr(), c"value".as_ptr()];
        let raw_fd = fd.as_raw_fd();
        // SAFETY: Compare against the device NDK, including its native status pruning.
        let peer_status = unsafe {
            sys::AIBinder_dump(peer.as_native().cast_mut(), raw_fd, args.as_mut_ptr(), 2)
        };
        CALLS.lock().unwrap().clear();
        // SAFETY: The local receiver, fd, and argument storage remain live for each callback.
        unsafe {
            assert_eq!(
                dispatch_android13_dump::<()>(
                    raw_receiver,
                    raw_fd,
                    std::ptr::null_mut(),
                    0,
                    |_| None
                ),
                StatusCode::UNEXPECTED_NULL as i32
            );
            assert_eq!(
                dispatch_android13_dump::<()>(raw_receiver, raw_fd, args.as_mut_ptr(), 2, |_| None),
                0
            );
            *PEER.lock().unwrap() = Some(peer);
            for (pointer, count) in [(std::ptr::null_mut(), 0), (args.as_mut_ptr(), 2)] {
                assert_eq!(
                    dispatch_android13_dump::<()>(raw_receiver, raw_fd, pointer, count, |_| PEER
                        .lock()
                        .unwrap()
                        .clone()),
                    peer_status
                );
            }
        }
        PEER.lock().unwrap().take();
        assert_eq!(
            *CALLS.lock().unwrap(),
            vec![
                (raw_fd, Vec::<Vec<u8>>::new()),
                (raw_fd, vec![b"--test".to_vec(), b"value".to_vec()])
            ]
        );

        // SAFETY: dump matches Binder<()> and is installed before class publication.
        let class = unsafe { dump_interface_class::<()>(dump) };
        let receiver = instance(class);
        // SAFETY: These are valid inputs to the device's native dump dispatcher.
        let status = unsafe {
            sys::AIBinder_dump(receiver.as_native().cast_mut(), raw_fd, args.as_mut_ptr(), 2)
        };
        assert_eq!(status, if super::api_level() == 33 { peer_status } else { 0 });
        if super::api_level() != 33 {
            // SAFETY: The upstream callback permits null with zero arguments on API 34+.
            assert_eq!(
                unsafe {
                    <Binder<()> as InterfaceClassMethods>::on_dump(
                        receiver.as_native().cast_mut(),
                        raw_fd,
                        std::ptr::null_mut(),
                        0,
                    )
                },
                0
            );
        }
        assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    }
}
