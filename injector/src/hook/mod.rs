use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::AtomicPtr;
use std::sync::Once;

pub(crate) mod binder;
mod install;
mod intercept;
mod rewrite;

static OLD_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INIT: Once = Once::new();

pub unsafe extern "C" fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    intercept::new_ioctl(fd, request, arg)
}

pub fn init_hook() {
    install::init_hook()
}
