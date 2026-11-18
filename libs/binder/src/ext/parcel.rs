// SPDX-License-Identifier: Apache-2.0

use super::native;
use crate::binder_impl::{BorrowedParcel, Parcel};
use crate::unstable_api::AsNative;
use crate::{error, sys, SpIBinder, StatusCode};
use std::ffi::c_void;
use std::sync::OnceLock;

type Data = unsafe extern "C" fn(*const c_void) -> *const u8;
type ThreadSelf = unsafe extern "C" fn() -> *mut c_void;
type ThreadFlags = unsafe extern "C" fn(*const c_void) -> u32;
type OnTransact = unsafe extern "C" fn(*mut c_void, u32, *const c_void, *mut c_void, u32) -> i32;
type Promote = unsafe extern "C" fn(*mut c_void, *const c_void) -> bool;
type RefBase = unsafe extern "C" fn(*const c_void) -> *mut c_void;
type Release = unsafe extern "C" fn(*const c_void, *const c_void);
type EnforceInterface = unsafe extern "C" fn(*const c_void, *const u16, usize, *mut c_void) -> bool;
type GetStrict = unsafe extern "C" fn(*const c_void) -> i32;
type SetStrict = unsafe extern "C" fn(*mut c_void, i32);
type GetWorkSource = unsafe extern "C" fn(*const c_void) -> u32;
type SetWorkSource = unsafe extern "C" fn(*mut c_void, u32) -> i64;
type RestoreWorkSource = unsafe extern "C" fn(*mut c_void, i64);
type PropagateWorkSource = unsafe extern "C" fn(*const c_void) -> bool;
type ClearPropagateWorkSource = unsafe extern "C" fn(*mut c_void);

struct InterfaceApi {
    enforce: EnforceInterface,
    get_strict: GetStrict,
    set_strict: SetStrict,
    get_work_source: GetWorkSource,
    set_work_source: SetWorkSource,
    set_propagating_work_source: SetWorkSource,
    restore_work_source: RestoreWorkSource,
    propagates_work_source: PropagateWorkSource,
    clear_propagate_work_source: ClearPropagateWorkSource,
}

impl InterfaceApi {
    fn load() -> Result<Self, StatusCode> {
        // SAFETY: Each fixed symbol below uses its corresponding field's AOSP member-function ABI.
        Ok(Self {
            enforce: unsafe {
                native::native_function(
                    b"_ZNK7android6Parcel16enforceInterfaceEPKDsmPNS_14IPCThreadStateE\0",
                )
            }?,
            get_strict: unsafe {
                native::native_function(b"_ZNK7android14IPCThreadState19getStrictModePolicyEv\0")
            }?,
            set_strict: unsafe {
                native::native_function(b"_ZN7android14IPCThreadState19setStrictModePolicyEi\0")
            }?,
            get_work_source: unsafe {
                native::native_function(
                    b"_ZNK7android14IPCThreadState23getCallingWorkSourceUidEv\0",
                )
            }?,
            set_work_source: unsafe {
                native::native_function(
                    b"_ZN7android14IPCThreadState41setCallingWorkSourceUidWithoutPropagationEj\0",
                )
            }?,
            restore_work_source: unsafe {
                native::native_function(
                    b"_ZN7android14IPCThreadState24restoreCallingWorkSourceEl\0",
                )
            }?,
            set_propagating_work_source: unsafe {
                native::native_function(b"_ZN7android14IPCThreadState23setCallingWorkSourceUidEj\0")
            }?,
            propagates_work_source: unsafe {
                native::native_function(
                    b"_ZNK7android14IPCThreadState25shouldPropagateWorkSourceEv\0",
                )
            }?,
            clear_propagate_work_source: unsafe {
                native::native_function(
                    b"_ZN7android14IPCThreadState24clearPropagateWorkSourceEv\0",
                )
            }?,
        })
    }
}

fn interface_api() -> Result<&'static InterfaceApi, StatusCode> {
    static API: OnceLock<Result<InterfaceApi, StatusCode>> = OnceLock::new();
    API.get_or_init(InterfaceApi::load).as_ref().map_err(|error| *error)
}

struct RestoreThread<'a> {
    api: &'a InterfaceApi,
    thread: *mut c_void,
    strict: i32,
    work_source: i64,
    propagates: bool,
}

impl RestoreThread<'_> {
    fn capture() -> Result<Self, StatusCode> {
        let interface_api = interface_api()?;
        // SAFETY: self() returns this thread's live IPCThreadState; getters use that receiver.
        let (thread, strict, uid, propagates) = unsafe {
            let thread = (api()?.thread_self)();
            (
                thread,
                (interface_api.get_strict)(thread),
                (interface_api.get_work_source)(thread),
                (interface_api.propagates_work_source)(thread),
            )
        };
        // The native token includes the propagation bit as well as the UID.
        // SAFETY: The receiver belongs to this thread and uid came from its native getter.
        let work_source = unsafe { (interface_api.set_work_source)(thread, uid) };
        Ok(Self { api: interface_api, thread, strict, work_source, propagates })
    }
}

impl Drop for RestoreThread<'_> {
    fn drop(&mut self) {
        // SAFETY: This guard stays on the captured thread and restores its native snapshot.
        unsafe {
            (self.api.set_strict)(self.thread, self.strict);
            (self.api.restore_work_source)(self.thread, self.work_source);
            // AOSP's unset UID sign-extends into the token's propagation bit.
            if !self.propagates {
                (self.api.clear_propagate_work_source)(self.thread);
            }
        }
    }
}

/// Run on this thread and restore its StrictMode and complete WorkSource state afterward.
pub fn with_preserved_thread_state<T>(invoke: impl FnOnce() -> T) -> Result<T, StatusCode> {
    let _thread = RestoreThread::capture()?;
    Ok(invoke())
}

/// Capture the header state without querying kernel caller identity.
pub fn calling_thread_state() -> Result<(i32, u32, bool), StatusCode> {
    let interface = interface_api()?;
    // SAFETY: All getters use this thread's live native receiver.
    unsafe {
        let thread = (api()?.thread_self)();
        Ok((
            (interface.get_strict)(thread),
            (interface.get_work_source)(thread),
            (interface.propagates_work_source)(thread),
        ))
    }
}

/// Apply authenticated forwarding attributes for one dispatch and restore them afterward.
pub fn with_calling_thread_state<T>(
    state: (i32, u32, bool),
    invoke: impl FnOnce() -> T,
) -> Result<T, StatusCode> {
    let saved = RestoreThread::capture()?;
    // SAFETY: The guard and setters all refer to this thread's native state.
    unsafe {
        (saved.api.set_strict)(saved.thread, state.0);
        (saved.api.set_propagating_work_source)(saved.thread, state.1);
        if !state.2 {
            (saved.api.clear_propagate_work_source)(saved.thread);
        }
    }
    Ok(invoke())
}

/// Consume a self-owned kernel request's interface header using the device Binder ABI.
pub fn enforce_interface(parcel: &Parcel, expected: &str) -> Result<(), StatusCode> {
    with_enforced_interface(parcel, expected, |_| Ok(()))
}

/// Keep the device-enforced header state active throughout a dispatch.
pub fn with_enforced_interface<T>(
    parcel: &Parcel,
    expected: &str,
    invoke: impl FnOnce(&BorrowedParcel<'_>) -> Result<T, StatusCode>,
) -> Result<T, StatusCode> {
    let restore = RestoreThread::capture()?;
    let expected: Vec<u16> = expected.encode_utf16().collect();
    let native = platform(parcel.borrowed_ref(), 0, true)?;
    // SAFETY: Parcel, UTF-16 descriptor and captured thread remain live throughout the call.
    if unsafe { (restore.api.enforce)(native, expected.as_ptr(), expected.len(), restore.thread) } {
        invoke(parcel.borrowed_ref())
    } else {
        Err(StatusCode::BAD_TYPE)
    }
}

struct NativeParcelApi {
    data: Data,
    thread_self: ThreadSelf,
    thread_flags: ThreadFlags,
    transact: OnTransact,
    base_transact: OnTransact,
    promote: Promote,
    ref_base: RefBase,
    release: Release,
}

impl NativeParcelApi {
    fn load() -> Result<Self, StatusCode> {
        // SAFETY: Each fixed symbol below uses its corresponding field's AOSP member-function ABI.
        Ok(Self {
            data: unsafe { native::native_function(b"_ZNK7android6Parcel4dataEv\0") }?,
            thread_self: unsafe {
                native::native_function(b"_ZN7android14IPCThreadState4selfEv\0")
            }?,
            thread_flags: unsafe {
                native::native_function(
                    b"_ZNK7android14IPCThreadState29getLastTransactionBinderFlagsEv\0",
                )
            }?,
            transact: unsafe {
                native::native_function(b"_ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j\0")
            }?,
            base_transact: unsafe {
                native::native_function(b"_ZN7android7BBinder10onTransactEjRKNS_6ParcelEPS1_j\0")
            }?,
            promote: unsafe {
                native::native_function(
                    b"_ZN7android7RefBase12weakref_type16attemptIncStrongEPKv\0",
                )
            }?,
            ref_base: unsafe {
                native::native_function(b"_ZNK7android7RefBase12weakref_type7refBaseEv\0")
            }?,
            release: unsafe { native::native_function(b"_ZNK7android7RefBase9decStrongEPKv\0") }?,
        })
    }
}

fn api() -> Result<&'static NativeParcelApi, StatusCode> {
    static API: OnceLock<Result<NativeParcelApi, StatusCode>> = OnceLock::new();
    API.get_or_init(NativeParcelApi::load).as_ref().map_err(|error| *error)
}

fn platform(
    parcel: &BorrowedParcel<'_>,
    binder: usize,
    owns: bool,
) -> Result<*mut c_void, StatusCode> {
    // SAFETY: BorrowedParcel owns a live AParcel view; compat validates the legacy ownership origin.
    unsafe { sys::compat::platform_parcel(parcel.as_native(), binder as *const c_void, owns) }
        .map_err(|error| {
            log::error!("native Parcel view failed: {error}");
            StatusCode::BAD_VALUE
        })
}

/// A borrowed view that never acquires its embedded Binder objects or file descriptors.
pub struct ParcelView<'a> {
    pub bytes: &'a [u8],
    data: *const u8,
}

impl ParcelView<'_> {
    /// The original native address, including null for an empty Parcel.
    pub fn data_ptr(&self) -> *const u8 {
        self.data
    }
}

fn view<'a>(
    parcel: &'a BorrowedParcel<'_>,
    binder: usize,
    owns: bool,
) -> Result<ParcelView<'a>, StatusCode> {
    let api = api()?;
    let platform = platform(parcel, binder, owns)?;
    let size = usize::try_from(parcel.get_data_size()).map_err(|_| StatusCode::BAD_VALUE)?;
    // SAFETY: platform borrows the live input Parcel and the accessor does not mutate it.
    let data = unsafe { (api.data)(platform) };
    if size > i32::MAX as usize || (size != 0 && data.is_null()) {
        return Err(StatusCode::BAD_VALUE);
    }
    // SAFETY: Nonempty data is non-null and native dataSize bytes stay valid for the Parcel borrow.
    let bytes = if size == 0 { &[] } else { unsafe { std::slice::from_raw_parts(data, size) } };
    Ok(ParcelView { bytes, data })
}

/// Copy a self-owned native Parcel's bytes while retaining its original object ownership.
pub fn parcel_bytes(parcel: &Parcel) -> Result<Vec<u8>, StatusCode> {
    Ok(owned_parcel_view(parcel)?.bytes.to_vec())
}

/// Borrow a self-owned Parcel without adopting its embedded objects.
pub fn owned_parcel_view(parcel: &Parcel) -> Result<ParcelView<'_>, StatusCode> {
    view(parcel.borrowed_ref(), 0, true)
}

/// Borrow a native callback Parcel whose NDK Binder identity is known.
pub fn callback_parcel_view<'a>(
    parcel: &'a BorrowedParcel<'_>,
    binder: usize,
) -> Result<ParcelView<'a>, StatusCode> {
    view(parcel, binder, false)
}

/// Read the current native transaction flags without initiating a Binder transaction.
pub fn last_transaction_flags() -> Result<u32, StatusCode> {
    let api = api()?;
    // SAFETY: self() supplies this thread's live receiver to its native flags getter.
    Ok(unsafe { (api.thread_flags)((api.thread_self)()) })
}

/// Resolve mandatory device APIs before publishing an intercepted receiver.
pub fn init_native_apis() -> Result<(), StatusCode> {
    api()?;
    interface_api()?;
    let parcel = Parcel::new();
    platform(parcel.borrowed_ref(), 0, true)?;
    Ok(())
}

struct LocalStrongRef {
    base: usize,
    id: usize,
    api: &'static NativeParcelApi,
}

impl Drop for LocalStrongRef {
    fn drop(&mut self) {
        // SAFETY: This owner consumes exactly the strong reference promoted with the same id.
        unsafe { (self.api.release)(self.base as *const c_void, self.id as *const c_void) };
    }
}

/// An owned device BBinder, independent of the injector's Rust Binder class.
pub struct LocalBinderReceiver {
    cookie: usize,
    binder: SpIBinder,
}

/// An owned local reply and the device dispatch result, separate from setup failures.
pub struct LocalTransactionReply {
    pub parcel: Parcel,
    pub status: Result<(), StatusCode>,
}

struct RestorePosition<'a, 'b> {
    parcel: &'a BorrowedParcel<'b>,
    position: i32,
}

/// Apply the same decode-error boundary as the upstream Bn dispatcher macro.
pub fn write_decode_error(
    error: StatusCode,
    output: &mut BorrowedParcel<'_>,
) -> Result<(), StatusCode> {
    match error {
        StatusCode::UNEXPECTED_NULL => {
            output.write(&crate::Status::new_exception(crate::ExceptionCode::NULL_POINTER, None))
        }
        error => Err(error),
    }
}

impl Drop for RestorePosition<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: Replaying a const request does not resize it, so its saved position stays valid.
        if let Err(error) = unsafe { self.parcel.set_data_position(self.position) } {
            log::error!("failed to restore observed request cursor: {error}");
        }
    }
}

/// Read a native Parcel at a checked position and restore the caller's cursor afterward.
pub fn with_parcel_position<T>(
    parcel: &BorrowedParcel<'_>,
    position: i32,
    read: impl FnOnce() -> T,
) -> Result<T, StatusCode> {
    let _restore = RestorePosition { parcel, position: parcel.get_data_position() };
    if !(0..=parcel.get_data_size()).contains(&position) {
        return Err(StatusCode::BAD_VALUE);
    }
    // SAFETY: position lies inside the live Parcel, whose saved cursor is restored by the guard.
    unsafe { parcel.set_data_position(position)? };
    Ok(read())
}

impl LocalBinderReceiver {
    /// Delegate an unknown user transaction to the device's base Binder dispatcher.
    pub fn default_callback(
        &self,
        input: &BorrowedParcel<'_>,
        output: &mut BorrowedParcel<'_>,
        callback_binder: usize,
        code: u32,
        flags: u32,
    ) -> Result<(), StatusCode> {
        let input = platform(input, callback_binder, false)?;
        let output = platform(output, callback_binder, false)?;
        // SAFETY: The strong local receiver and callback Parcels outlive the native base call.
        unsafe {
            error::status_result((api()?.base_transact)(
                self.cookie as *mut c_void,
                code,
                input,
                output,
                flags,
            ))
        }
    }
    /// Stable while this receiver retains the original local Binder.
    pub fn identity(&self) -> usize {
        self.cookie
    }

    /// Use the original Binder through its NDK owner without changing the caller's thread context.
    pub fn with_binder<T>(&self, invoke: impl FnOnce(SpIBinder) -> T) -> Result<T, StatusCode> {
        with_preserved_thread_state(|| invoke(self.binder.clone()))
    }

    /// Replay the complete original callback request through the device virtual dispatcher.
    pub fn transact_callback(
        &self,
        input: &BorrowedParcel<'_>,
        callback_binder: usize,
        code: u32,
        flags: u32,
    ) -> Result<LocalTransactionReply, StatusCode> {
        let output = Parcel::new();
        let reply = platform(output.borrowed_ref(), 0, true)?;
        let status = self.transact_callback_to(input, callback_binder, code, flags, reply)?;
        Ok(LocalTransactionReply { parcel: output, status })
    }

    /// Replay into the original callback output without changing its native Parcel attributes.
    pub fn transact_callback_into(
        &self,
        input: &BorrowedParcel<'_>,
        output: &mut BorrowedParcel<'_>,
        callback_binder: usize,
        code: u32,
        flags: u32,
    ) -> Result<(), StatusCode> {
        let reply = platform(output, callback_binder, false)?;
        self.transact_callback_to(input, callback_binder, code, flags, reply)?
    }

    fn transact_callback_to(
        &self,
        input: &BorrowedParcel<'_>,
        callback_binder: usize,
        code: u32,
        flags: u32,
        reply: *mut c_void,
    ) -> Result<Result<(), StatusCode>, StatusCode> {
        let api = api()?;
        let _thread = RestoreThread::capture()?;
        let _position = RestorePosition { parcel: input, position: input.get_data_position() };
        let input = platform(input, callback_binder, false)?;
        // SAFETY: The owned receiver and both native Parcels stay live for the synchronous call.
        let status = unsafe {
            error::status_result((api.transact)(
                self.cookie as *mut c_void,
                code,
                input,
                reply,
                flags,
            ))
        };
        Ok(status)
    }
}

/// Check a driver-held local Binder's native virtual descriptor.
///
/// # Safety
/// The weak pointer and cookie must identify the same live local receiver, retained by the driver
/// or by a caller-owned strong Binder reference throughout this call.
pub unsafe fn local_binder_interface_matches(
    weak: usize,
    cookie: usize,
    expected: &str,
) -> Result<bool, StatusCode> {
    // SAFETY: The caller supplies the live receiver pair required by local_binder_receiver.
    Ok(unsafe { local_binder_receiver(weak, cookie, expected) }?.is_some())
}

/// Promote and validate a driver-held receiver without releasing it between those steps.
///
/// # Safety
/// The weak pointer and cookie must identify the same live local receiver, retained by the driver
/// or by a caller-owned strong Binder reference throughout this call.
pub unsafe fn local_binder_receiver(
    weak: usize,
    cookie: usize,
    expected: &str,
) -> Result<Option<LocalBinderReceiver>, StatusCode> {
    let api = api()?;
    if weak == 0 || cookie == 0 {
        return Ok(None);
    }
    let id = (api as *const NativeParcelApi).cast::<c_void>();
    // SAFETY: The driver still holds this receiver's weak reference; id has a stable static address.
    if !unsafe { (api.promote)(weak as *mut c_void, id) } {
        return Ok(None);
    }
    let _promotion = LocalStrongRef {
        // SAFETY: A successful promotion keeps this weak reference's RefBase alive.
        base: unsafe { (api.ref_base)(weak as *const c_void) } as usize,
        id: id as usize,
        api,
    };
    let _thread = RestoreThread::capture()?;
    // SAFETY: The temporary promotion retains the original IBinder throughout conversion.
    let binder = unsafe { native::binder_from_platform(cookie as *mut c_void)? };
    let matches = super::associate_descriptor(&binder, expected).is_ok();
    Ok(matches.then_some(LocalBinderReceiver { cookie, binder }))
}
