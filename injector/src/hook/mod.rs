use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::AtomicPtr;
use std::sync::OnceLock;

pub(crate) mod binder;
mod install;
mod intercept;
pub(crate) mod rewrite;

static OLD_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// # Safety
///
/// Called by the installed ioctl hook with the same ABI and pointer validity
/// requirements as libc ioctl. `arg` must be valid for the request being made.
pub unsafe extern "C" fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    intercept::new_ioctl(fd, request, arg)
}

pub fn init_hook() -> anyhow::Result<()> {
    install::init_hook()
}
