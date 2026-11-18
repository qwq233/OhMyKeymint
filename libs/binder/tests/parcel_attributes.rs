#![cfg(not(android_ndk))]

use binder::binder_impl::{Binder, BorrowedParcel, IBinderInternal, Parcel, Remotable};
use binder::ext::{local_binder_receiver, owned_parcel_view, LocalBinderReceiver};
use binder::unstable_api::AsNative;
use binder::{binder_fn_get_class, Interface, ParcelFileDescriptor, StatusCode};
use binder_ndk_sys as sys;
use std::ffi::{c_void, CStr};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

#[test]
fn callback_output_keeps_fd_restrictions_during_native_forwarding() {
    type GetAllowFds = unsafe extern "C" fn(*const sys::AParcel) -> bool;
    type PushAllowFds = unsafe extern "C" fn(*mut c_void, bool) -> bool;
    type RestoreAllowFds = unsafe extern "C" fn(*mut c_void, bool);
    struct Receiver {
        identity: OnceLock<usize>,
        peer: Option<LocalBinderReceiver>,
        calls: AtomicUsize,
    }
    impl Remotable for Receiver {
        fn get_descriptor() -> &'static str {
            "test.ParcelAttributes"
        }
        fn on_transact(
            &self,
            code: u32,
            input: &BorrowedParcel<'_>,
            output: &mut BorrowedParcel<'_>,
        ) -> Result<(), StatusCode> {
            // SAFETY: These are the exact NDK and Parcel member-function ABIs.
            let get: GetAllowFds = unsafe {
                sys::compat::native_symbol(b"AParcel_getAllowFds\0").expect("native Parcel API")
            };
            if let Some(peer) = &self.peer {
                // SAFETY: output is this receiver's live borrowed native callback Parcel.
                let native = unsafe {
                    sys::compat::platform_parcel(
                        output.as_native(),
                        *self.identity.get().unwrap() as *const c_void,
                        false,
                    )
                }
                .expect("callback Parcel origin");
                // SAFETY: Both symbols take the live native Parcel and a boolean.
                let push: PushAllowFds = unsafe {
                    sys::compat::native_symbol(b"_ZN7android6Parcel12pushAllowFdsEb\0")
                        .expect("native Parcel API")
                };
                // SAFETY: The restore symbol has the declared native member-function ABI.
                let restore: RestoreAllowFds = unsafe {
                    sys::compat::native_symbol(b"_ZN7android6Parcel15restoreAllowFdsEb\0")
                        .expect("native Parcel API")
                };
                // SAFETY: output retains native throughout push, forwarding and restoration.
                let saved = unsafe { push(native, false) };
                // SAFETY: get only reads this live callback AParcel.
                let before = unsafe { get(output.as_native()) };
                let result = if code == 3 {
                    peer.default_callback(input, output, *self.identity.get().unwrap(), code, 0)
                } else {
                    peer.transact_callback_into(
                        input,
                        output,
                        *self.identity.get().unwrap(),
                        code,
                        0,
                    )
                };
                // SAFETY: The same callback AParcel remains live after forwarding.
                let after = unsafe { get(output.as_native()) };
                // SAFETY: saved was returned by push for this exact Parcel.
                unsafe { restore(native, saved) };
                assert!(!before);
                assert!(!after);
                return result;
            }
            // SAFETY: output is the real incoming callback AParcel, not an owned fixture.
            assert!(!unsafe { get(output.as_native()) });
            self.calls.fetch_add(1, Ordering::SeqCst);
            if code == 1 {
                output.write(&ParcelFileDescriptor::new(std::fs::File::open("/dev/null").unwrap()))
            } else {
                output.write(&17_i32)
            }
        }
        fn on_dump(&self, _: &mut dyn std::io::Write, _: &[&CStr]) -> Result<(), StatusCode> {
            Ok(())
        }
        #[cfg(not(android_ndk))]
        fn on_shell_command(
            &self,
            _: &mut dyn std::io::Read,
            _: &mut dyn std::io::Write,
            _: &mut dyn std::io::Write,
            _: &[&CStr],
        ) -> Result<(), StatusCode> {
            Ok(())
        }
        binder_fn_get_class!(Binder<Self>);
    }
    let source =
        Binder::new(Receiver { identity: OnceLock::new(), peer: None, calls: AtomicUsize::new(0) });
    source.identity.set(source.as_binder().as_native() as usize).unwrap();
    let mut flattened = Parcel::new();
    flattened.write(&source).unwrap();
    let view = owned_parcel_view(&flattened).unwrap();
    assert!(view.bytes.len() >= mem::size_of::<sys::driver::flat_binder_object>());
    // SAFETY: The source remains owned and its complete native flat object is readable.
    let target = unsafe {
        std::ptr::read_unaligned(view.bytes.as_ptr().cast::<sys::driver::flat_binder_object>())
    };
    assert_eq!(target.hdr.type_, sys::driver::BINDER_TYPE_BINDER);
    // SAFETY: Both fields come from the still-retained source's native serialization.
    let peer = unsafe {
        local_binder_receiver(
            target.__bindgen_anon_1.binder as usize,
            target.cookie as usize,
            Receiver::get_descriptor(),
        )
    }
    .unwrap()
    .unwrap();
    let forwarded = Binder::new(Receiver {
        identity: OnceLock::new(),
        peer: Some(peer),
        calls: AtomicUsize::new(0),
    });
    forwarded.identity.set(forwarded.as_binder().as_native() as usize).unwrap();
    let forwarded = forwarded.as_binder();
    let rejected = forwarded.submit_transact(1, forwarded.prepare_transact().unwrap(), 0);
    assert_eq!(rejected.err(), Some(StatusCode::FDS_NOT_ALLOWED));
    let reply = forwarded.submit_transact(2, forwarded.prepare_transact().unwrap(), 0).unwrap();
    assert_eq!(reply.read::<i32>().unwrap(), 17);
    let unknown = forwarded.submit_transact(3, forwarded.prepare_transact().unwrap(), 0);
    assert_eq!(unknown.err(), Some(StatusCode::UNKNOWN_TRANSACTION));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}
