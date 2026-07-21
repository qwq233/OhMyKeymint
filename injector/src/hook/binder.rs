use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CStr};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    LazyLock, Mutex, OnceLock,
};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info, warn};

const PARCEL_PREVIEW_CHARS: usize = 50;
const B_TYPE_LARGE: u32 = 0x85;

pub(crate) const BINDER_WRITE_READ: u32 = 0xc0306201;
pub(crate) const BC_TRANSACTION_NR: u32 = 0;
pub(crate) const BC_REPLY_NR: u32 = 1;
pub(crate) const BC_ACQUIRE_RESULT_NR: u32 = 2;
pub(crate) const BC_FREE_BUFFER_NR: u32 = 3;
pub(crate) const BC_INCREFS_DONE_NR: u32 = 8;
pub(crate) const BC_ACQUIRE_DONE_NR: u32 = 9;
pub(crate) const BC_TRANSACTION_SG_NR: u32 = 17;
pub(crate) const BC_REPLY_SG_NR: u32 = 18;
pub(crate) const BR_TRANSACTION_NR: u32 = 2;
pub(crate) const BR_REPLY_NR: u32 = 3;
pub(crate) const BR_DEAD_REPLY_NR: u32 = 5;
pub(crate) const BR_TRANSACTION_COMPLETE_NR: u32 = 6;
pub(crate) const BR_INCREFS_NR: u32 = 7;
pub(crate) const BR_ACQUIRE_NR: u32 = 8;
pub(crate) const BR_RELEASE_NR: u32 = 9;
pub(crate) const BR_DECREFS_NR: u32 = 10;
pub(crate) const BR_ATTEMPT_ACQUIRE_NR: u32 = 11;
pub(crate) const BR_NOOP_NR: u32 = 12;
pub(crate) const BR_FAILED_REPLY_NR: u32 = 17;
pub(crate) const BR_FROZEN_REPLY_NR: u32 = 18;
pub(crate) const BR_ONEWAY_SPAM_SUSPECT_NR: u32 = 19;
pub(crate) const BR_TRANSACTION_PENDING_FROZEN_NR: u32 = 20;
pub(crate) const TF_ONE_WAY: u32 = 0x01;
pub(crate) const TF_STATUS_CODE: u32 = 0x08;
pub(crate) const BINDER_TYPE_BINDER: u32 = b_pack_chars(b's', b'b', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_WEAK_BINDER: u32 = b_pack_chars(b'w', b'b', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_HANDLE: u32 = b_pack_chars(b's', b'h', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_WEAK_HANDLE: u32 = b_pack_chars(b'w', b'h', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_FD: u32 = b_pack_chars(b'f', b'd', b'*', B_TYPE_LARGE as u8);
const FLAT_BINDER_FLAG_TXN_SECURITY_CTX: u32 = 0x1000;

pub(crate) fn vintf_stability_wire() -> i32 {
    if matches!(
        kmr_common::android_version::android_major_version(),
        Some(version) if version <= 12
    ) {
        0x3f00_0001
    } else {
        0x3f
    }
}

const fn b_pack_chars(c1: u8, c2: u8, c3: u8, c4: u8) -> u32 {
    ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
}

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, type_: u32, nr: u32, size: usize) -> u32 {
    (dir << IOC_DIRSHIFT)
        | (type_ << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_object_header {
    pub type_: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union flat_binder_object_handle_or_ptr {
    pub binder: libc::c_ulong,
    pub handle: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct flat_binder_object {
    pub hdr: binder_object_header,
    pub flags: u32,
    pub handle_or_ptr: flat_binder_object_handle_or_ptr,
    pub cookie: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_ptr_cookie {
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_pri_ptr_cookie {
    pub priority: i32,
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct binder_node_debug_info {
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
    pub has_strong_ref: u32,
    pub has_weak_ref: u32,
}

pub(crate) const BINDER_GET_NODE_DEBUG_INFO: u32 = ioc(
    IOC_READ | IOC_WRITE,
    b'b' as u32,
    11,
    size_of::<binder_node_debug_info>(),
);

pub(crate) const BR_NOOP_CMD: u32 = ioc(IOC_NONE, b'r' as u32, BR_NOOP_NR, 0);
pub(crate) const BR_TRANSACTION_COMPLETE_CMD: u32 =
    ioc(IOC_NONE, b'r' as u32, BR_TRANSACTION_COMPLETE_NR, 0);
#[cfg(test)]
pub(crate) const BR_TRANSACTION_CMD: u32 = ioc(
    IOC_READ,
    b'r' as u32,
    BR_TRANSACTION_NR,
    size_of::<binder_transaction_data>(),
);
pub(crate) const BC_ACQUIRE_RESULT_CMD: u32 = ioc(
    IOC_WRITE,
    b'c' as u32,
    BC_ACQUIRE_RESULT_NR,
    size_of::<i32>(),
);
pub(crate) const BC_FREE_BUFFER_CMD: u32 = ioc(
    IOC_WRITE,
    b'c' as u32,
    BC_FREE_BUFFER_NR,
    size_of::<libc::c_ulong>(),
);
pub(crate) const BC_REPLY_CMD: u32 = ioc(
    IOC_WRITE,
    b'c' as u32,
    BC_REPLY_NR,
    size_of::<binder_transaction_data>(),
);
pub(crate) const BC_INCREFS_DONE_CMD: u32 = ioc(
    IOC_WRITE,
    b'c' as u32,
    BC_INCREFS_DONE_NR,
    size_of::<binder_ptr_cookie>(),
);
pub(crate) const BC_ACQUIRE_DONE_CMD: u32 = ioc(
    IOC_WRITE,
    b'c' as u32,
    BC_ACQUIRE_DONE_NR,
    size_of::<binder_ptr_cookie>(),
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LocalBinderTarget {
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
}

struct NativeBinderUserData {
    target: OnceLock<LocalBinderTarget>,
    retirement_generation: std::sync::atomic::AtomicU64,
    retire_on_destroy: AtomicBool,
}

impl NativeBinderUserData {
    fn new() -> Self {
        Self {
            target: OnceLock::new(),
            retirement_generation: std::sync::atomic::AtomicU64::new(0),
            retire_on_destroy: AtomicBool::new(false),
        }
    }
}

#[derive(Clone, Copy)]
enum NativeBinderKind {
    SecurityLevel,
    Operation,
}

impl NativeBinderKind {
    fn label(self) -> &'static str {
        match self {
            Self::SecurityLevel => "security-level",
            Self::Operation => "operation",
        }
    }
}

type BinderOnCreate = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type BinderOnDestroy = unsafe extern "C" fn(*mut c_void);
type BinderOnTransact = unsafe extern "C" fn(*mut c_void, u32, *const c_void, *mut c_void) -> i32;
type ClassDefine = unsafe extern "C" fn(
    *const c_char,
    BinderOnCreate,
    BinderOnDestroy,
    BinderOnTransact,
) -> *mut c_void;
type BinderNew = unsafe extern "C" fn(*const c_void, *mut c_void) -> *mut c_void;
type BinderRef = unsafe extern "C" fn(*mut c_void);
type BinderGetUserData = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type BinderGetCallingUid = unsafe extern "C" fn() -> libc::uid_t;
type BinderGetCallingPid = unsafe extern "C" fn() -> libc::pid_t;
type BinderSetRequestingSid = unsafe extern "C" fn(*mut c_void, bool);
type ParcelCreate = unsafe extern "C" fn() -> *mut c_void;
type ParcelDelete = unsafe extern "C" fn(*mut c_void);
type ParcelWriteStrongBinder = unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32;
type ParcelGetDataSize = unsafe extern "C" fn(*const c_void) -> i32;
type ParcelViewPlatformConst = unsafe extern "C" fn(*const c_void) -> *const c_void;
type ParcelViewPlatformMut = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type PlatformParcelData = unsafe extern "C" fn(*const c_void) -> *const u8;
type PlatformParcelDataSize = unsafe extern "C" fn(*const c_void) -> usize;
type PlatformParcelObjectsCount = unsafe extern "C" fn(*const c_void) -> usize;
type PlatformParcelWrite = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> i32;
type IpcThreadStateSelf = unsafe extern "C" fn() -> *mut c_void;
type IpcThreadStateGetCallingSid = unsafe extern "C" fn(*const c_void) -> *const c_char;
type IpcThreadStateGetLastTransactionBinderFlags = unsafe extern "C" fn(*const c_void) -> u32;

// Exact AOSP Android 12/13 libs/binder/ndk/parcel_internal.h layout.
// Android 14+ exposes AParcel_viewPlatformParcel and never uses this fallback.
#[repr(C)]
struct LegacyAParcel {
    binder: *const c_void,
    parcel: *mut c_void,
    owns_parcel: u8,
}

struct NativeBinderApi {
    security_level_class: usize,
    operation_class: usize,
    binder_new: BinderNew,
    binder_dec_strong: BinderRef,
    binder_get_user_data: BinderGetUserData,
    binder_get_calling_uid: BinderGetCallingUid,
    binder_get_calling_pid: BinderGetCallingPid,
    binder_set_requesting_sid: BinderSetRequestingSid,
    binder_mark_vintf_stability: BinderRef,
    parcel_create: ParcelCreate,
    parcel_delete: ParcelDelete,
    parcel_write_strong_binder: ParcelWriteStrongBinder,
    parcel_get_data_size: ParcelGetDataSize,
    parcel_view_platform_const: Option<ParcelViewPlatformConst>,
    parcel_view_platform_mut: Option<ParcelViewPlatformMut>,
    legacy_aparcel_layout: bool,
    platform_parcel_data: PlatformParcelData,
    platform_parcel_data_size: PlatformParcelDataSize,
    platform_parcel_objects_count: PlatformParcelObjectsCount,
    platform_parcel_write: PlatformParcelWrite,
    ipc_thread_state_self: IpcThreadStateSelf,
    ipc_thread_state_get_calling_sid: IpcThreadStateGetCallingSid,
    ipc_thread_state_get_last_transaction_binder_flags: IpcThreadStateGetLastTransactionBinderFlags,
}

pub(crate) struct NativeBinder {
    _binder: RawBinder,
    user_data: usize,
    target: LocalBinderTarget,
    carrier: Box<[u8]>,
}

impl NativeBinder {
    pub(crate) fn target(&self) -> LocalBinderTarget {
        self.target
    }

    pub(crate) fn carrier(&self) -> &[u8] {
        &self.carrier
    }

    pub(crate) fn raw_ptr(&self) -> *mut c_void {
        self._binder.binder as *mut c_void
    }

    pub(crate) fn arm_retirement(&self, generation: u64) {
        unsafe {
            let user_data = &*(self.user_data as *const NativeBinderUserData);
            user_data
                .retirement_generation
                .store(generation, Ordering::Relaxed);
            user_data.retire_on_destroy.store(true, Ordering::Release);
        }
    }

    pub(crate) fn disarm_retirement(&self) {
        unsafe {
            (*(self.user_data as *const NativeBinderUserData))
                .retire_on_destroy
                .store(false, Ordering::Release);
        }
    }
}

struct RawBinder {
    binder: usize,
    dec_strong: BinderRef,
}

impl Drop for RawBinder {
    fn drop(&mut self) {
        unsafe {
            (self.dec_strong)(self.binder as *mut c_void);
        }
    }
}

struct RawParcel {
    parcel: *mut c_void,
    delete: ParcelDelete,
}

impl NativeBinderApi {
    unsafe fn view_platform_const(
        &self,
        parcel: *const c_void,
        expected_binder: *const c_void,
        expected_owns_parcel: bool,
    ) -> *const c_void {
        if let Some(view) = self.parcel_view_platform_const {
            return view(parcel);
        }
        if !self.legacy_aparcel_layout || parcel.is_null() {
            return std::ptr::null();
        }
        let parcel = &*(parcel as *const LegacyAParcel);
        if parcel.binder != expected_binder
            || parcel.owns_parcel != u8::from(expected_owns_parcel)
            || parcel.parcel.is_null()
            || !(parcel.parcel as usize).is_multiple_of(std::mem::align_of::<usize>())
        {
            return std::ptr::null();
        }
        parcel.parcel
    }

    unsafe fn view_platform_mut(
        &self,
        parcel: *mut c_void,
        expected_binder: *const c_void,
        expected_owns_parcel: bool,
    ) -> *mut c_void {
        if let Some(view) = self.parcel_view_platform_mut {
            return view(parcel);
        }
        if !self.legacy_aparcel_layout || parcel.is_null() {
            return std::ptr::null_mut();
        }
        let parcel = &*(parcel as *const LegacyAParcel);
        if parcel.binder != expected_binder
            || parcel.owns_parcel != u8::from(expected_owns_parcel)
            || parcel.parcel.is_null()
            || !(parcel.parcel as usize).is_multiple_of(std::mem::align_of::<usize>())
        {
            return std::ptr::null_mut();
        }
        parcel.parcel
    }
}

impl Drop for RawParcel {
    fn drop(&mut self) {
        unsafe {
            (self.delete)(self.parcel);
        }
    }
}

static NATIVE_BINDER_API: OnceLock<std::result::Result<NativeBinderApi, String>> = OnceLock::new();
static NATIVE_BINDER_RETIREMENTS: LazyLock<Mutex<VecDeque<NativeBinderRetirement>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBinderRetirement {
    pub target: LocalBinderTarget,
    pub generation: u64,
}

const SECURITY_LEVEL_DESCRIPTOR: &[u8] = b"android.system.keystore2.IKeystoreSecurityLevel\0";
const OPERATION_DESCRIPTOR: &[u8] = b"android.system.keystore2.IKeystoreOperation\0";

unsafe extern "C" fn native_binder_on_create(args: *mut c_void) -> *mut c_void {
    args
}

unsafe extern "C" fn native_binder_on_destroy(user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    let user_data = Box::from_raw(user_data as *mut NativeBinderUserData);
    if user_data.retire_on_destroy.load(Ordering::Acquire) {
        if let Some(target) = user_data.target.get().copied() {
            let generation = user_data.retirement_generation.load(Ordering::Relaxed);
            NATIVE_BINDER_RETIREMENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(NativeBinderRetirement { target, generation });
        }
    }
}

unsafe extern "C" fn native_binder_on_transact(
    binder: *mut c_void,
    code: u32,
    input: *const c_void,
    output: *mut c_void,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        native_binder_on_transact_inner(binder, code, input, output)
    })) {
        Ok(status) => status,
        Err(_) => {
            error!("native synthetic Binder callback panicked; returning FAILED_TRANSACTION");
            rsbinder::StatusCode::FailedTransaction.into()
        }
    }
}

unsafe fn native_binder_on_transact_inner(
    binder: *mut c_void,
    code: u32,
    input: *const c_void,
    output: *mut c_void,
) -> i32 {
    let api = match native_binder_api() {
        Ok(api) => api,
        Err(error) => {
            error!("native synthetic Binder API unavailable in callback: {error:#}");
            return rsbinder::StatusCode::FailedTransaction.into();
        }
    };
    let user_data = (api.binder_get_user_data)(binder) as *const NativeBinderUserData;
    let Some(target) = user_data
        .as_ref()
        .and_then(|data| data.target.get())
        .copied()
    else {
        error!("native synthetic Binder callback has no registered target");
        return rsbinder::StatusCode::InvalidOperation.into();
    };
    if input.is_null() {
        return rsbinder::StatusCode::BadValue.into();
    }
    let input_platform = api.view_platform_const(input, binder, false);
    if input_platform.is_null() {
        return rsbinder::StatusCode::BadValue.into();
    }
    if (api.platform_parcel_objects_count)(input_platform) != 0 {
        warn!(
            "native synthetic Binder target ptr=0x{:x} cookie=0x{:x} received an object-bearing request; returning BAD_TYPE",
            target.ptr, target.cookie
        );
        return rsbinder::StatusCode::BadType.into();
    }

    let output_platform = if output.is_null() {
        std::ptr::null_mut()
    } else {
        api.view_platform_mut(output, binder, false)
    };
    if output_platform.is_null() || std::ptr::eq(input_platform, output_platform) {
        return rsbinder::StatusCode::BadValue.into();
    }
    let input_size = (api.platform_parcel_data_size)(input_platform);
    let aparcel_input_size = (api.parcel_get_data_size)(input);
    if aparcel_input_size < 0 || aparcel_input_size as usize != input_size {
        return rsbinder::StatusCode::BadValue.into();
    }
    if (api.parcel_get_data_size)(output) != 0
        || (api.platform_parcel_data_size)(output_platform) != 0
        || (api.platform_parcel_objects_count)(output_platform) != 0
    {
        return rsbinder::StatusCode::BadValue.into();
    }
    let input_data = (api.platform_parcel_data)(input_platform);
    if input_size != 0 && input_data.is_null() {
        return rsbinder::StatusCode::BadValue.into();
    }

    let state = (api.ipc_thread_state_self)();
    let (calling_sid, one_way) = if state.is_null() {
        (None, false)
    } else {
        let sid = (api.ipc_thread_state_get_calling_sid)(state);
        let calling_sid =
            (!sid.is_null()).then(|| CStr::from_ptr(sid).to_string_lossy().into_owned());
        let one_way = ((api.ipc_thread_state_get_last_transaction_binder_flags)(state)
            & super::binder::TF_ONE_WAY)
            != 0;
        (calling_sid, one_way)
    };
    let tr = binder_transaction_data {
        target: binder_transaction_data_target { ptr: target.ptr },
        cookie: target.cookie,
        code,
        flags: if one_way { TF_ONE_WAY } else { 0 },
        sender_pid: (api.binder_get_calling_pid)(),
        sender_euid: (api.binder_get_calling_uid)() as i32,
        data_size: input_size,
        offsets_size: 0,
        data: binder_transaction_data_data {
            ptr: binder_transaction_data_data_ptr {
                buffer: input_data as libc::c_ulong,
                offsets: 0,
            },
        },
    };
    let reply =
        super::rewrite::handle_synthetic_br_transaction(&tr, calling_sid, "native onTransact")
            .unwrap_or(super::rewrite::SyntheticReply::Status(
                rsbinder::StatusCode::UnknownTransaction.into(),
            ));
    write_native_binder_reply(api, output, output_platform, reply)
}

unsafe fn write_platform_bytes(api: &NativeBinderApi, parcel: *mut c_void, bytes: &[u8]) -> i32 {
    if bytes.is_empty() {
        return 0;
    }
    (api.platform_parcel_write)(parcel, bytes.as_ptr() as *const c_void, bytes.len())
}

unsafe fn write_native_binder_reply(
    api: &NativeBinderApi,
    output: *mut c_void,
    output_platform: *mut c_void,
    reply: super::rewrite::SyntheticReply,
) -> i32 {
    match reply {
        super::rewrite::SyntheticReply::Status(status) => status,
        super::rewrite::SyntheticReply::NoReply => 0,
        super::rewrite::SyntheticReply::Parcel(mut reply) => {
            if output.is_null() || output_platform.is_null() {
                return rsbinder::StatusCode::BadValue.into();
            }
            let data = std::slice::from_raw_parts(reply.data_ptr(), reply.data_size());
            let mut cursor = 0usize;
            for &offset in reply.offsets.iter() {
                if offset < cursor || offset > data.len() {
                    return rsbinder::StatusCode::BadValue.into();
                }
                let status = write_platform_bytes(api, output_platform, &data[cursor..offset]);
                if status != 0 {
                    return status;
                }
                let Some(target) = parse_local_binder_target_from_parcel_bytes(&data[offset..])
                else {
                    return rsbinder::StatusCode::BadType.into();
                };
                let Some(native) = super::rewrite::lookup_native_binder(target) else {
                    return rsbinder::StatusCode::DeadObject.into();
                };
                let carrier_len = native.carrier().len();
                let Some(end) = offset.checked_add(carrier_len) else {
                    return rsbinder::StatusCode::BadValue.into();
                };
                if end > data.len() {
                    return rsbinder::StatusCode::BadValue.into();
                }
                if &data[offset..end] != native.carrier() {
                    return rsbinder::StatusCode::BadType.into();
                }
                let status = (api.parcel_write_strong_binder)(output, native.raw_ptr());
                if status != 0 {
                    return status;
                }
                cursor = end;
            }
            let status = write_platform_bytes(api, output_platform, &data[cursor..]);
            if status != 0 {
                return status;
            }
            if (api.platform_parcel_data_size)(output_platform) != data.len() {
                return rsbinder::StatusCode::BadValue.into();
            }
            if (api.platform_parcel_objects_count)(output_platform) != reply.offsets.len() {
                return rsbinder::StatusCode::BadValue.into();
            }
            if (api.parcel_get_data_size)(output) != data.len() as i32 {
                return rsbinder::StatusCode::BadValue.into();
            }

            if let Some(target) = reply.native_operation_target.take() {
                super::rewrite::finish_local_operation_publication(target);
            }
            0
        }
    }
}

pub(crate) fn take_native_binder_retirement() -> Option<NativeBinderRetirement> {
    NATIVE_BINDER_RETIREMENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop_front()
}

#[cfg(test)]
pub(crate) fn clear_native_binder_retirements_for_test() {
    NATIVE_BINDER_RETIREMENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

fn dl_error() -> String {
    unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            "unknown dynamic linker error".to_string()
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    }
}

unsafe fn open_library(name: &'static [u8]) -> Result<usize> {
    let handle = libc::dlopen(
        name.as_ptr() as *const c_char,
        libc::RTLD_NOW | libc::RTLD_LOCAL,
    );
    if handle.is_null() {
        bail!(
            "failed to load {}: {}",
            CStr::from_bytes_with_nul(name)?.to_string_lossy(),
            dl_error()
        );
    }
    Ok(handle as usize)
}

unsafe fn load_symbol<T: Copy>(handle: usize, name: &'static [u8]) -> Result<T> {
    let symbol = find_symbol(handle, name).ok_or_else(|| {
        anyhow!(
            "failed to resolve {}: {}",
            CStr::from_bytes_with_nul(name)
                .map(|name| name.to_string_lossy())
                .unwrap_or_else(|_| "<invalid symbol>".into()),
            dl_error()
        )
    })?;
    Ok(symbol)
}

unsafe fn find_symbol<T: Copy>(handle: usize, name: &'static [u8]) -> Option<T> {
    let symbol = libc::dlsym(handle as *mut c_void, name.as_ptr() as *const c_char);
    if symbol.is_null() {
        return None;
    }
    if size_of::<T>() != size_of::<*mut c_void>() {
        return None;
    }
    Some(std::mem::transmute_copy(&symbol))
}

impl NativeBinderApi {
    unsafe fn load() -> Result<Self> {
        // These handles intentionally stay open for the process lifetime.
        let binder_ndk = open_library(b"libbinder_ndk.so\0")?;
        let binder = open_library(b"libbinder.so\0")?;

        let class_define: ClassDefine = load_symbol(binder_ndk, b"AIBinder_Class_define\0")?;
        let binder_new = load_symbol(binder_ndk, b"AIBinder_new\0")?;
        let binder_dec_strong = load_symbol(binder_ndk, b"AIBinder_decStrong\0")?;
        let binder_get_user_data = load_symbol(binder_ndk, b"AIBinder_getUserData\0")?;
        let binder_get_calling_uid = load_symbol(binder_ndk, b"AIBinder_getCallingUid\0")?;
        let binder_get_calling_pid = load_symbol(binder_ndk, b"AIBinder_getCallingPid\0")?;
        let binder_set_requesting_sid = load_symbol(binder_ndk, b"AIBinder_setRequestingSid\0")?;
        let binder_mark_vintf_stability =
            load_symbol(binder_ndk, b"AIBinder_markVintfStability\0")?;
        let parcel_create = load_symbol(binder_ndk, b"AParcel_create\0")?;
        let parcel_delete = load_symbol(binder_ndk, b"AParcel_delete\0")?;
        let parcel_write_strong_binder = load_symbol(binder_ndk, b"AParcel_writeStrongBinder\0")?;
        let parcel_get_data_size = load_symbol(binder_ndk, b"AParcel_getDataSize\0")?;
        let parcel_view_platform_const =
            find_symbol(binder_ndk, b"_Z26AParcel_viewPlatformParcelPK7AParcel\0");
        let parcel_view_platform_mut =
            find_symbol(binder_ndk, b"_Z26AParcel_viewPlatformParcelP7AParcel\0");
        let legacy_aparcel_layout =
            parcel_view_platform_const.is_none() || parcel_view_platform_mut.is_none();
        if legacy_aparcel_layout
            && !matches!(
                kmr_common::android_version::android_major_version(),
                Some(12 | 13)
            )
        {
            bail!("AParcel_viewPlatformParcel is unavailable outside Android 12/13");
        }
        let platform_parcel_data = load_symbol(binder, b"_ZNK7android6Parcel4dataEv\0")?;
        let platform_parcel_data_size = load_symbol(binder, b"_ZNK7android6Parcel8dataSizeEv\0")?;
        let platform_parcel_objects_count =
            load_symbol(binder, b"_ZNK7android6Parcel12objectsCountEv\0")?;
        let platform_parcel_write = load_symbol(binder, b"_ZN7android6Parcel5writeEPKvm\0")?;
        let ipc_thread_state_self = load_symbol(binder, b"_ZN7android14IPCThreadState4selfEv\0")?;
        let ipc_thread_state_get_calling_sid =
            load_symbol(binder, b"_ZNK7android14IPCThreadState13getCallingSidEv\0")?;
        let ipc_thread_state_get_last_transaction_binder_flags = load_symbol(
            binder,
            b"_ZNK7android14IPCThreadState29getLastTransactionBinderFlagsEv\0",
        )?;

        let security_level_class = class_define(
            SECURITY_LEVEL_DESCRIPTOR.as_ptr() as *const c_char,
            native_binder_on_create,
            native_binder_on_destroy,
            native_binder_on_transact,
        );
        if security_level_class.is_null() {
            bail!("failed to define native IKeystoreSecurityLevel Binder class");
        }
        let operation_class = class_define(
            OPERATION_DESCRIPTOR.as_ptr() as *const c_char,
            native_binder_on_create,
            native_binder_on_destroy,
            native_binder_on_transact,
        );
        if operation_class.is_null() {
            bail!("failed to define native IKeystoreOperation Binder class");
        }
        let api = Self {
            security_level_class: security_level_class as usize,
            operation_class: operation_class as usize,
            binder_new,
            binder_dec_strong,
            binder_get_user_data,
            binder_get_calling_uid,
            binder_get_calling_pid,
            binder_set_requesting_sid,
            binder_mark_vintf_stability,
            parcel_create,
            parcel_delete,
            parcel_write_strong_binder,
            parcel_get_data_size,
            parcel_view_platform_const,
            parcel_view_platform_mut,
            legacy_aparcel_layout,
            platform_parcel_data,
            platform_parcel_data_size,
            platform_parcel_objects_count,
            platform_parcel_write,
            ipc_thread_state_self,
            ipc_thread_state_get_calling_sid,
            ipc_thread_state_get_last_transaction_binder_flags,
        };
        for kind in [NativeBinderKind::SecurityLevel, NativeBinderKind::Operation] {
            drop(create_native_binder_with_api(&api, kind).with_context(|| {
                format!("native {} Binder carrier preflight failed", kind.label())
            })?);
        }
        Ok(api)
    }
}

fn native_binder_api() -> Result<&'static NativeBinderApi> {
    match NATIVE_BINDER_API
        .get_or_init(|| unsafe { NativeBinderApi::load().map_err(|error| format!("{error:#}")) })
    {
        Ok(api) => Ok(api),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

fn create_native_binder_with_api(
    api: &NativeBinderApi,
    kind: NativeBinderKind,
) -> Result<NativeBinder> {
    let user_data = Box::into_raw(Box::new(NativeBinderUserData::new()));
    let class = match kind {
        NativeBinderKind::SecurityLevel => api.security_level_class,
        NativeBinderKind::Operation => api.operation_class,
    };
    let binder = unsafe { (api.binder_new)(class as *const c_void, user_data as *mut c_void) };
    if binder.is_null() {
        unsafe {
            drop(Box::from_raw(user_data));
        }
        bail!(
            "AIBinder_new returned null for native {} carrier",
            kind.label()
        );
    }
    let binder = RawBinder {
        binder: binder as usize,
        dec_strong: api.binder_dec_strong,
    };

    unsafe {
        (api.binder_set_requesting_sid)(binder.binder as *mut c_void, true);
        (api.binder_mark_vintf_stability)(binder.binder as *mut c_void);
    }

    let parcel = unsafe { (api.parcel_create)() };
    if parcel.is_null() {
        bail!(
            "AParcel_create returned null for native {} carrier",
            kind.label()
        );
    }
    let parcel = RawParcel {
        parcel,
        delete: api.parcel_delete,
    };
    let status =
        unsafe { (api.parcel_write_strong_binder)(parcel.parcel, binder.binder as *mut c_void) };
    if status != 0 {
        bail!(
            "AParcel_writeStrongBinder failed for native {} carrier: {status}",
            kind.label()
        );
    }

    let data_size = unsafe { (api.parcel_get_data_size)(parcel.parcel) };
    let expected_size = size_of::<flat_binder_object>() + size_of::<i32>();
    if data_size < 0 || data_size as usize != expected_size {
        bail!(
            "unexpected native {} carrier size: expected {expected_size}, got {data_size}",
            kind.label()
        );
    }
    let platform = unsafe { api.view_platform_const(parcel.parcel, std::ptr::null(), true) };
    if platform.is_null() {
        bail!(
            "AParcel_viewPlatformParcel returned null for native {} carrier",
            kind.label()
        );
    }
    if unsafe { (api.platform_parcel_data_size)(platform) } != data_size as usize {
        bail!(
            "native {} carrier AParcel/platform Parcel size mismatch",
            kind.label()
        );
    }
    let data = unsafe { (api.platform_parcel_data)(platform) };
    if data.is_null() {
        bail!("native {} carrier has null data", kind.label());
    }
    let carrier = unsafe { std::slice::from_raw_parts(data, data_size as usize) }.to_vec();
    let object = unsafe { std::ptr::read_unaligned(carrier.as_ptr() as *const flat_binder_object) };
    if object.hdr.type_ != BINDER_TYPE_BINDER {
        bail!(
            "native {} carrier has unexpected object type 0x{:x}",
            kind.label(),
            object.hdr.type_
        );
    }
    if (object.flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX) == 0 {
        bail!(
            "native {} carrier does not request caller SID",
            kind.label()
        );
    }
    let ptr = unsafe { object.handle_or_ptr.binder };
    if ptr == 0 || object.cookie == 0 {
        bail!("native {} carrier has null ptr/cookie", kind.label());
    }
    let stability = unsafe {
        std::ptr::read_unaligned(carrier.as_ptr().add(size_of::<flat_binder_object>()) as *const i32)
    };
    let expected_stability = vintf_stability_wire();
    if stability != expected_stability {
        bail!(
            "native {} carrier stability mismatch: expected 0x{expected_stability:x}, got 0x{stability:x}",
            kind.label()
        );
    }

    let target = LocalBinderTarget {
        ptr,
        cookie: object.cookie,
    };
    unsafe {
        (*user_data)
            .target
            .set(target)
            .map_err(|_| anyhow!("native {} target was already initialized", kind.label()))?;
    }
    Ok(NativeBinder {
        _binder: binder,
        user_data: user_data as usize,
        target,
        carrier: carrier.into_boxed_slice(),
    })
}

pub(crate) fn create_native_security_level_binder() -> Result<NativeBinder> {
    create_native_binder_with_api(native_binder_api()?, NativeBinderKind::SecurityLevel)
}

pub(crate) fn create_native_operation_binder() -> Result<NativeBinder> {
    create_native_binder_with_api(native_binder_api()?, NativeBinderKind::Operation)
}

#[repr(C)]
pub(crate) struct binder_write_read {
    pub write_size: libc::size_t,
    pub write_consumed: libc::size_t,
    pub write_buffer: libc::c_ulong,
    pub read_size: libc::size_t,
    pub read_consumed: libc::size_t,
    pub read_buffer: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union binder_transaction_data_target {
    pub handle: u32,
    pub ptr: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union binder_transaction_data_data {
    pub ptr: binder_transaction_data_data_ptr,
    pub buf: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_data_ptr {
    pub buffer: libc::c_ulong,
    pub offsets: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data {
    pub target: binder_transaction_data_target,
    pub cookie: libc::c_ulong,
    pub code: u32,
    pub flags: u32,
    pub sender_pid: i32,
    pub sender_euid: i32,
    pub data_size: libc::size_t,
    pub offsets_size: libc::size_t,
    pub data: binder_transaction_data_data,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_secctx {
    pub transaction_data: binder_transaction_data,
    pub secctx: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_sg {
    pub transaction_data: binder_transaction_data,
    pub buffers_size: libc::size_t,
}

pub(crate) fn _ioc_dir(cmd: u32) -> u32 {
    (cmd >> 30) & 0x3
}

pub(crate) fn _ioc_nr(cmd: u32) -> u32 {
    cmd & 0xFF
}

pub(crate) fn _ioc_size(cmd: u32) -> usize {
    ((cmd >> 16) & 0x3FFF) as usize
}

pub(crate) unsafe fn parse_secctx_sid(secctx: libc::c_ulong) -> Option<String> {
    if secctx == 0 {
        return None;
    }

    let ptr = secctx as *const c_char;
    if ptr.is_null() {
        return None;
    }

    Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
}

pub(crate) unsafe fn log_write_transaction(command_name: &str, tr: &binder_transaction_data) {
    info!(
        "<<< {} | target: {}, code: 0x{:x}, flags: 0x{:x}{}{}, data_size: {}, offsets_size: {}, parcel: {}",
        command_name,
        format_target(tr),
        tr.code,
        tr.flags,
        if (tr.flags & TF_ONE_WAY) != 0 { ", oneway" } else { "" },
        if command_name.contains("REPLY") { ", reply" } else { "" },
        tr.data_size,
        tr.offsets_size,
        preview_transaction_parcel(tr),
    );
}

pub(crate) unsafe fn preview_transaction_parcel(tr: &binder_transaction_data) -> String {
    let data_size = tr.data_size;
    if data_size == 0 {
        return "<empty>".to_string();
    }

    let buffer = tr.data.ptr.buffer as *const u8;
    if buffer.is_null() {
        return "<null>".to_string();
    }

    let preview_len = data_size.min(128);
    let bytes = std::slice::from_raw_parts(buffer, preview_len);
    let mut preview = String::new();

    for byte in bytes {
        for ch in byte.escape_ascii() {
            if preview.chars().count() >= PARCEL_PREVIEW_CHARS {
                preview.push('…');
                return preview;
            }
            preview.push(ch as char);
        }
    }

    if data_size > preview_len {
        preview.push('…');
    }

    if preview.is_empty() {
        "<binary>".to_string()
    } else {
        preview
    }
}

pub(crate) unsafe fn describe_transaction_objects(tr: &binder_transaction_data) -> String {
    let offsets_size = tr.offsets_size;
    if offsets_size == 0 {
        return "[]".to_string();
    }

    let offsets_ptr = tr.data.ptr.offsets as *const usize;
    if offsets_ptr.is_null() {
        return "[<null offsets>]".to_string();
    }

    let count = offsets_size / size_of::<usize>();
    if count == 0 {
        return "[]".to_string();
    }

    let data_size = tr.data_size;
    let offsets = std::slice::from_raw_parts(offsets_ptr, count);
    let bytes = match transaction_data_bytes(tr) {
        Some(bytes) => bytes,
        None => return "[<null data>]".to_string(),
    };

    let mut out = Vec::with_capacity(count);
    for &offset in offsets {
        let object_size = size_of::<flat_binder_object>();
        if offset > data_size || data_size.saturating_sub(offset) < object_size {
            out.push(format!("{{offset={}, invalid=true}}", offset));
            continue;
        }

        let object =
            std::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const flat_binder_object);
        let type_name = match object.hdr.type_ {
            BINDER_TYPE_BINDER => "BINDER",
            BINDER_TYPE_WEAK_BINDER => "WEAK_BINDER",
            BINDER_TYPE_HANDLE => "HANDLE",
            BINDER_TYPE_WEAK_HANDLE => "WEAK_HANDLE",
            other => {
                out.push(format!(
                    "{{offset={}, type=0x{:x}, flags=0x{:x}, handle_or_ptr=0x{:x}, cookie=0x{:x}}}",
                    offset, other, object.flags, object.handle_or_ptr.binder, object.cookie
                ));
                continue;
            }
        };

        let stability_offset = offset + object_size;
        let stability = if data_size.saturating_sub(stability_offset) >= size_of::<i32>() {
            Some(std::ptr::read_unaligned(
                bytes.as_ptr().add(stability_offset) as *const i32,
            ))
        } else {
            None
        };

        out.push(format!(
            "{{offset={}, type={}, flags=0x{:x}, handle=0x{:x}, ptr=0x{:x}, cookie=0x{:x}, stability={}}}",
            offset,
            type_name,
            object.flags,
            object.handle_or_ptr.handle,
            object.handle_or_ptr.binder,
            object.cookie,
            stability
                .map(|value| format!("0x{:x}", value))
                .unwrap_or_else(|| "<missing>".to_string())
        ));
    }

    format!("[{}]", out.join(", "))
}

pub(crate) unsafe fn format_target(tr: &binder_transaction_data) -> String {
    let handle = tr.target.handle;
    if handle != 0 {
        format!("handle:{}", handle)
    } else {
        format!("ptr:0x{:x}", tr.target.ptr)
    }
}

pub(crate) unsafe fn transaction_data_bytes<'a>(tr: &binder_transaction_data) -> Option<&'a [u8]> {
    let data_size = tr.data_size;
    if data_size == 0 {
        return Some(&[]);
    }

    let buffer = tr.data.ptr.buffer as *const u8;
    if buffer.is_null() {
        return None;
    }

    Some(std::slice::from_raw_parts(buffer, data_size))
}

pub(crate) unsafe fn parse_local_binder_target_from_parcel_bytes(
    bytes: &[u8],
) -> Option<LocalBinderTarget> {
    if bytes.len() < size_of::<flat_binder_object>() {
        return None;
    }

    let object = std::ptr::read_unaligned(bytes.as_ptr() as *const flat_binder_object);
    if !matches!(
        object.hdr.type_,
        BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER
    ) {
        return None;
    }

    let ptr = object.handle_or_ptr.binder;
    if ptr == 0 || object.cookie == 0 {
        return None;
    }

    Some(LocalBinderTarget {
        ptr,
        cookie: object.cookie,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_aparcel_matches_android_12_13_aarch64_layout() {
        assert_eq!(size_of::<usize>(), 8);
        assert_eq!(std::mem::offset_of!(LegacyAParcel, binder), 0);
        assert_eq!(std::mem::offset_of!(LegacyAParcel, parcel), 8);
        assert_eq!(std::mem::offset_of!(LegacyAParcel, owns_parcel), 16);
        assert_eq!(size_of::<LegacyAParcel>(), 24);
    }
}
