#![allow(non_camel_case_types, non_upper_case_globals)]

use std::ffi::CStr;
use std::mem;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::OnceLock;

pub type pid_t = libc::pid_t;
pub type selabel_handle = c_void;

pub const SELINUX_CB_LOG: c_uint = 0;
pub const SELABEL_CTX_ANDROID_KEYSTORE2_KEY: c_uint = 6;
const SELABEL_OPT_PATH: c_int = 3;

pub type LogCallback = unsafe extern "C" fn(c_int, *const c_char) -> c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub union selinux_callback {
    pub func_log: Option<LogCallback>,
}

#[repr(C)]
struct selinux_opt {
    type_: c_int,
    value: *const c_char,
}

type GetCon = unsafe extern "C" fn(*mut *mut c_char) -> c_int;
type FreeCon = unsafe extern "C" fn(*mut c_char);
type SetCon = unsafe extern "C" fn(*const c_char) -> c_int;
type CheckAccess = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
) -> c_int;
type SelabelOpen = unsafe extern "C" fn(c_uint, *const selinux_opt, c_uint) -> *mut selabel_handle;
type SelabelLookup =
    unsafe extern "C" fn(*mut selabel_handle, *mut *mut c_char, *const c_char, c_int) -> c_int;
type SelabelClose = unsafe extern "C" fn(*mut selabel_handle);
type AndroidKeystore2Handle = unsafe extern "C" fn() -> *mut selabel_handle;
type SelinuxSetCallback = unsafe extern "C" fn(c_int, selinux_callback);

struct LibSelinux {
    getcon: GetCon,
    freecon: FreeCon,
    setcon: SetCon,
    selinux_check_access: CheckAccess,
    selabel_open: SelabelOpen,
    selabel_lookup: SelabelLookup,
    selabel_close: SelabelClose,
    android_keystore2_handle: Option<AndroidKeystore2Handle>,
    selinux_set_callback: Option<SelinuxSetCallback>,
    selinux_log_callback: Option<LogCallback>,
}

static LIB_SELINUX: OnceLock<Option<LibSelinux>> = OnceLock::new();

pub unsafe extern "C" fn selinux_log_callback(_type_: c_int, _fmt: *const c_char) -> c_int {
    0
}

pub unsafe fn getcon(con: *mut *mut c_char) -> c_int {
    if con.is_null() {
        return fail(libc::EINVAL);
    }

    match libselinux() {
        Some(lib) => unsafe { (lib.getcon)(con) },
        None => fail(libc::ENOENT),
    }
}

pub unsafe fn freecon(con: *mut c_char) {
    if con.is_null() {
        return;
    }

    match libselinux() {
        Some(lib) => unsafe { (lib.freecon)(con) },
        None => unsafe { libc::free(con.cast()) },
    }
}

pub unsafe fn setcon(con: *const c_char) -> c_int {
    if con.is_null() {
        return fail(libc::EINVAL);
    }

    match libselinux() {
        Some(lib) => unsafe { (lib.setcon)(con) },
        None => fail(libc::ENOENT),
    }
}

pub unsafe fn selinux_set_callback(callback_type: c_int, cb: selinux_callback) {
    let Some(lib) = libselinux() else {
        return;
    };
    let Some(set_callback) = lib.selinux_set_callback else {
        return;
    };

    let cb = if callback_type == SELINUX_CB_LOG as c_int {
        let Some(log_callback) = lib.selinux_log_callback else {
            return;
        };
        selinux_callback {
            func_log: Some(log_callback),
        }
    } else {
        cb
    };

    unsafe { set_callback(callback_type, cb) };
}

pub unsafe fn selinux_android_keystore2_key_context_handle() -> *mut selabel_handle {
    let Some(lib) = libselinux() else {
        fail(libc::ENOENT);
        return ptr::null_mut();
    };

    if let Some(android_keystore2_handle) = lib.android_keystore2_handle {
        return unsafe { android_keystore2_handle() };
    }

    let options = existing_keystore2_key_context_options();
    let (options_ptr, options_len) = if options.is_empty() {
        (ptr::null(), 0)
    } else {
        let len = match c_uint::try_from(options.len()) {
            Ok(len) => len,
            Err(_) => {
                fail(libc::EOVERFLOW);
                return ptr::null_mut();
            }
        };
        (options.as_ptr(), len)
    };

    unsafe { (lib.selabel_open)(SELABEL_CTX_ANDROID_KEYSTORE2_KEY, options_ptr, options_len) }
}

pub unsafe fn selabel_lookup(
    handle: *mut selabel_handle,
    con: *mut *mut c_char,
    key: *const c_char,
    key_type: c_int,
) -> c_int {
    if handle.is_null() || con.is_null() || key.is_null() {
        return fail(libc::EINVAL);
    }

    match libselinux() {
        Some(lib) => unsafe { (lib.selabel_lookup)(handle, con, key, key_type) },
        None => fail(libc::ENOENT),
    }
}

pub unsafe fn selabel_close(handle: *mut selabel_handle) {
    if handle.is_null() {
        return;
    }

    if let Some(lib) = libselinux() {
        unsafe { (lib.selabel_close)(handle) };
    }
}

pub unsafe fn selinux_check_access(
    source: *const c_char,
    target: *const c_char,
    tclass: *const c_char,
    perm: *const c_char,
    auditdata: *mut c_void,
) -> c_int {
    if source.is_null() || target.is_null() || tclass.is_null() || perm.is_null() {
        return fail(libc::EINVAL);
    }

    match libselinux() {
        Some(lib) => unsafe { (lib.selinux_check_access)(source, target, tclass, perm, auditdata) },
        None => fail(libc::ENOENT),
    }
}

fn libselinux() -> Option<&'static LibSelinux> {
    LIB_SELINUX.get_or_init(load_libselinux).as_ref()
}

fn load_libselinux() -> Option<LibSelinux> {
    let handle = open_first(&[c"libselinux.so", c"libselinux.so.1", c"libselinux"]);
    if handle.is_null() {
        set_errno(libc::ENOENT);
        return None;
    }

    let lib = unsafe {
        LibSelinux {
            getcon: required_symbol(handle, c"getcon")?,
            freecon: required_symbol(handle, c"freecon")?,
            setcon: required_symbol(handle, c"setcon")?,
            selinux_check_access: required_symbol(handle, c"selinux_check_access")?,
            selabel_open: required_symbol(handle, c"selabel_open")?,
            selabel_lookup: required_symbol(handle, c"selabel_lookup")?,
            selabel_close: required_symbol(handle, c"selabel_close")?,
            android_keystore2_handle: optional_symbol(
                handle,
                c"selinux_android_keystore2_key_context_handle",
            ),
            selinux_set_callback: optional_symbol(handle, c"selinux_set_callback"),
            selinux_log_callback: optional_symbol(handle, c"selinux_log_callback"),
        }
    };

    Some(lib)
}

fn open_first(names: &[&CStr]) -> *mut c_void {
    for name in names {
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            return handle;
        }
    }
    ptr::null_mut()
}

unsafe fn required_symbol<T: Copy>(handle: *mut c_void, name: &CStr) -> Option<T> {
    optional_symbol(handle, name).or_else(|| {
        unsafe { libc::dlclose(handle) };
        set_errno(libc::ENOSYS);
        None
    })
}

unsafe fn optional_symbol<T: Copy>(handle: *mut c_void, name: &CStr) -> Option<T> {
    let symbol = unsafe { libc::dlsym(handle, name.as_ptr()) };
    if symbol.is_null() {
        None
    } else {
        Some(unsafe { mem::transmute_copy(&symbol) })
    }
}

fn existing_keystore2_key_context_options() -> Vec<selinux_opt> {
    const PATHS: &[&[&CStr]] = &[
        &[
            c"/system/etc/selinux/plat_keystore2_key_contexts",
            c"/plat_keystore2_key_contexts",
        ],
        &[
            c"/system_ext/etc/selinux/system_ext_keystore2_key_contexts",
            c"/system_ext_keystore2_key_contexts",
        ],
        &[
            c"/product/etc/selinux/product_keystore2_key_contexts",
            c"/product_keystore2_key_contexts",
        ],
        &[
            c"/vendor/etc/selinux/vendor_keystore2_key_contexts",
            c"/vendor_keystore2_key_contexts",
        ],
    ];

    PATHS
        .iter()
        .filter_map(|alts| {
            alts.iter()
                .copied()
                .find(|path| unsafe { libc::access(path.as_ptr(), libc::R_OK) == 0 })
                .map(|path| selinux_opt {
                    type_: SELABEL_OPT_PATH,
                    value: path.as_ptr(),
                })
        })
        .collect()
}

fn fail(errno: c_int) -> c_int {
    set_errno(errno);
    -1
}

fn set_errno(errno: c_int) {
    unsafe {
        *errno_location() = errno;
    }
}

unsafe fn errno_location() -> *mut c_int {
    unsafe { libc::__errno() }
}
