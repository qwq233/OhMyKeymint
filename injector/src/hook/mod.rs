use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::AtomicPtr;
use std::sync::OnceLock;

pub(crate) mod binder;
mod install;
mod intercept;
pub(crate) mod rewrite;

static OLD_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_FDSAN_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP2: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_DUP3: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static OLD_FCNTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INIT: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BinderFdToken {
    pub fd: c_int,
    pub generation: u64,
    pub connection: BinderStateKey,
}

pub(super) type BinderStateKey = u64;

pub fn init_hook() -> anyhow::Result<()> {
    install::init_hook()
}
