use super::{
    binder_transaction_data, binder_transaction_data_data, binder_transaction_data_data_ptr,
    binder_transaction_data_target, flat_binder_object,
    parse_local_binder_target_from_parcel_bytes, vintf_stability_wire, LocalBinderTarget,
    BINDER_TYPE_BINDER, FLAT_BINDER_FLAG_TXN_SECURITY_CTX, TF_ONE_WAY,
};
use crate::hook::rewrite::{NativeOperationState, SyntheticTargetKind};
use anyhow::{anyhow, bail, Context, Result};
use log::{error, warn};
use std::ffi::{c_char, c_void, CStr};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

#[cfg(test)]
mod tests;

struct NativeBinderUserData {
    kind: NativeBinderKind,
    operation: OnceLock<Arc<NativeOperationState>>,
    target: OnceLock<LocalBinderTarget>,
    retirement_generation: std::sync::atomic::AtomicU64,
    retire_on_destroy: AtomicBool,
}

impl NativeBinderUserData {
    fn new(kind: NativeBinderKind) -> Self {
        Self {
            kind,
            operation: OnceLock::new(),
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
    pub(in crate::hook) fn set_operation_state(
        &self,
        state: Arc<NativeOperationState>,
    ) -> Result<()> {
        // SAFETY: self._binder keeps the Binder and its boxed userdata alive for this
        // borrow; OnceLock synchronizes the shared state update.
        unsafe { &*(self.user_data as *const NativeBinderUserData) }
            .operation
            .set(state)
            .map_err(|_| anyhow!("native operation state was already initialized"))
    }
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

    pub(crate) fn retirement_generation(&self) -> u64 {
        unsafe {
            (*(self.user_data as *const NativeBinderUserData))
                .retirement_generation
                .load(Ordering::Relaxed)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBinderRetirement {
    pub target: LocalBinderTarget,
    pub generation: u64,
}

const SECURITY_LEVEL_DESCRIPTOR: &[u8] = b"android.system.keystore2.IKeystoreSecurityLevel\0";
const OPERATION_DESCRIPTOR: &[u8] = b"android.system.keystore2.IKeystoreOperation\0";
const DUMP_OBJECT_OFFSETS: [usize; 1] = [0];

fn native_request_offsets(code: u32, object_count: usize) -> Option<&'static [usize]> {
    match (code, object_count) {
        (_, 0) => Some(&[]),
        (rsbinder::SHELL_COMMAND_TRANSACTION, _) => Some(&[]),
        (rsbinder::DUMP_TRANSACTION, 1) => Some(&DUMP_OBJECT_OFFSETS),
        _ => None,
    }
}

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
            let retirement = NativeBinderRetirement { target, generation };
            if catch_unwind(AssertUnwindSafe(|| {
                crate::hook::rewrite::retire_native_operation_target(retirement)
            }))
            .is_err()
            {
                error!(
                    "native synthetic operation retirement panicked ptr=0x{:x} cookie=0x{:x} generation={}",
                    target.ptr, target.cookie, generation
                );
            }
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
    // SAFETY: Binder keeps its boxed userdata alive throughout this callback.
    let Some(user_data) = (unsafe { user_data.as_ref() }) else {
        return rsbinder::StatusCode::InvalidOperation.into();
    };
    let Some(target) = user_data.target.get().copied() else {
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
    let object_count = (api.platform_parcel_objects_count)(input_platform);
    let Some(input_offsets) = native_request_offsets(code, object_count) else {
        warn!(
            "native synthetic Binder target ptr=0x{:x} cookie=0x{:x} received unsupported objects code=0x{:x} count={}; returning BAD_TYPE",
            target.ptr, target.cookie, code, object_count
        );
        return rsbinder::StatusCode::BadType.into();
    };

    let state = (api.ipc_thread_state_self)();
    let (calling_sid, one_way) = if state.is_null() {
        (None, false)
    } else {
        let sid = (api.ipc_thread_state_get_calling_sid)(state);
        let calling_sid =
            (!sid.is_null()).then(|| CStr::from_ptr(sid).to_string_lossy().into_owned());
        let one_way = ((api.ipc_thread_state_get_last_transaction_binder_flags)(state)
            & super::TF_ONE_WAY)
            != 0;
        (calling_sid, one_way)
    };

    let output_platform = if one_way || output.is_null() {
        std::ptr::null_mut()
    } else {
        api.view_platform_mut(output, binder, false)
    };
    if !one_way && (output_platform.is_null() || std::ptr::eq(input_platform, output_platform)) {
        return rsbinder::StatusCode::BadValue.into();
    }
    let input_size = (api.platform_parcel_data_size)(input_platform);
    let aparcel_input_size = (api.parcel_get_data_size)(input);
    if aparcel_input_size < 0 || aparcel_input_size as usize != input_size {
        return rsbinder::StatusCode::BadValue.into();
    }
    if !one_way
        && ((api.parcel_get_data_size)(output) != 0
            || (api.platform_parcel_data_size)(output_platform) != 0
            || (api.platform_parcel_objects_count)(output_platform) != 0)
    {
        return rsbinder::StatusCode::BadValue.into();
    }
    let input_data = (api.platform_parcel_data)(input_platform);
    if input_size != 0 && input_data.is_null() {
        return rsbinder::StatusCode::BadValue.into();
    }

    let tr = binder_transaction_data {
        target: binder_transaction_data_target { ptr: target.ptr },
        cookie: target.cookie,
        code,
        flags: if one_way { TF_ONE_WAY } else { 0 },
        sender_pid: (api.binder_get_calling_pid)(),
        sender_euid: (api.binder_get_calling_uid)() as i32,
        data_size: input_size,
        offsets_size: std::mem::size_of_val(input_offsets),
        data: binder_transaction_data_data {
            ptr: binder_transaction_data_data_ptr {
                buffer: input_data as libc::c_ulong,
                offsets: if input_offsets.is_empty() {
                    0
                } else {
                    input_offsets.as_ptr() as libc::c_ulong
                },
            },
        },
    };
    let reply = crate::hook::rewrite::handle_native_br_transaction(
        &tr,
        match user_data.kind {
            NativeBinderKind::SecurityLevel => SyntheticTargetKind::SecurityLevel,
            NativeBinderKind::Operation => SyntheticTargetKind::Operation,
        },
        user_data.operation.get().map(Arc::as_ref),
        calling_sid,
        "native onTransact",
    );
    let status = write_native_binder_reply(api, output, output_platform, reply);
    // SAFETY: libbinder owns output_platform for this callback. The null check
    // below guards each parcel API call, which only inspects the live parcel.
    unsafe {
        if status == 0
            && !output_platform.is_null()
            && (api.platform_parcel_objects_count)(output_platform) == 0
        {
            crate::hook::rewrite::remember_native_reply(
                target,
                (api.platform_parcel_data)(output_platform) as usize,
                (api.platform_parcel_data_size)(output_platform),
            );
        }
    }
    status
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
    reply: crate::hook::rewrite::SyntheticReply,
) -> i32 {
    match reply {
        crate::hook::rewrite::SyntheticReply::Status(status) => status,
        crate::hook::rewrite::SyntheticReply::NoReply => 0,
        crate::hook::rewrite::SyntheticReply::Parcel(mut reply) => {
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
                let native = match reply.native_operation {
                    Some(retirement) if retirement.target == target => {
                        crate::hook::rewrite::lookup_native_binder_for(retirement)
                    }
                    Some(_) => None,
                    None => crate::hook::rewrite::lookup_native_binder(target),
                };
                let Some(native) = native else {
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

            if let Some(retirement) = reply.native_operation.take() {
                crate::hook::rewrite::finish_local_operation_publication(retirement);
            }
            0
        }
    }
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
    let user_data = Box::into_raw(Box::new(NativeBinderUserData::new(kind)));
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
