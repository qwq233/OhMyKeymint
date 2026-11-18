// SPDX-License-Identifier: Apache-2.0

use crate::{sys, SpIBinder, StatusCode};
use std::ffi::c_void;
use std::mem::{self, MaybeUninit};

// AOSP sp<T> contains one pointer; its non-trivial C++ return still uses x8.
#[repr(C)]
pub(super) struct NativeStrong {
    pointer: *mut c_void,
}

const _: () = assert!(mem::size_of::<NativeStrong>() == 8 && mem::align_of::<NativeStrong>() == 8);

/// Resolve a device function with its complete native ABI.
///
/// # Safety
/// `T` must be a function pointer. Calls must use the symbol's full native ABI,
/// including its C++ receiver and any non-trivial return convention.
pub(super) unsafe fn native_function<T: Copy>(name: &[u8]) -> Result<T, StatusCode> {
    if sys::compat::api_level() < 33 {
        return Err(StatusCode::INVALID_OPERATION);
    }
    // SAFETY: The caller supplies the ABI; the sys OnceLock keeps the library loaded.
    unsafe { sys::compat::native_symbol(name) }.map_err(|error| {
        log::error!("native Binder API unavailable: {error}");
        StatusCode::INVALID_OPERATION
    })
}

/// One native sp reference to a verified RefBase-derived Binder type.
pub(super) struct CppStrong {
    raw: NativeStrong,
}

// SAFETY: Native Binder objects use thread-safe reference counting.
unsafe impl Send for CppStrong {}
// SAFETY: The owned sp slot remains immutable until drop.
unsafe impl Sync for CppStrong {}

impl CppStrong {
    /// # Safety
    /// The symbol and arguments must match a non-trivial AArch64 sp return.
    pub(super) unsafe fn call(name: &[u8], arg0: usize, arg1: usize) -> Result<Self, StatusCode> {
        // SAFETY: The caller provides the ABI; this pointer is used only as an assembly address.
        let address: unsafe extern "C" fn() = unsafe { native_function(name)? };
        // SAFETY: The caller guarantees the same native ABI for this address and arguments.
        unsafe { Self::call_address(address as *const (), arg0, arg1) }
    }

    unsafe fn call_address(
        address: *const (),
        arg0: usize,
        arg1: usize,
    ) -> Result<Self, StatusCode> {
        // SAFETY: decStrong takes a RefBase receiver and the reference's opaque identity.
        let _: unsafe extern "C" fn(*const c_void, *const c_void) =
            unsafe { native_function(b"_ZNK7android7RefBase9decStrongEPKv\0")? };
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86_64",
            target_arch = "x86"
        ))]
        {
            let mut result = MaybeUninit::<NativeStrong>::uninit();
            // SAFETY: Each target passes writable storage using its non-trivial C++ return ABI.
            // Without nostack, Rust aligns the stack for calls; clobber_abi covers caller-saved registers.
            unsafe {
                #[cfg(target_arch = "aarch64")]
                std::arch::asm!(
                    "blr x16",
                    in("x16") address,
                    in("x8") result.as_mut_ptr(),
                    in("x0") arg0,
                    in("x1") arg1,
                    clobber_abi("C"),
                );
                #[cfg(target_arch = "arm")]
                std::arch::asm!(
                    "blx r12",
                    in("r12") address,
                    in("r0") result.as_mut_ptr(),
                    in("r1") arg0,
                    in("r2") arg1,
                    clobber_abi("C"),
                );
                #[cfg(target_arch = "x86_64")]
                std::arch::asm!(
                    "call rax",
                    in("rax") address,
                    in("rdi") result.as_mut_ptr(),
                    in("rsi") arg0,
                    in("rdx") arg1,
                    clobber_abi("C"),
                );
                #[cfg(target_arch = "x86")]
                std::arch::asm!(
                    "sub esp, 16",
                    "mov [esp], eax",
                    "mov [esp + 4], ecx",
                    "mov [esp + 8], edx",
                    "call edi",
                    // The callee pops the hidden return pointer; the caller pops the rest.
                    "add esp, 12",
                    in("edi") address,
                    in("eax") result.as_mut_ptr(),
                    in("ecx") arg0,
                    in("edx") arg1,
                    clobber_abi("C"),
                );
                let owner = Self { raw: result.assume_init() };
                if owner.as_ptr().is_null() {
                    Err(StatusCode::NO_INIT)
                } else {
                    Ok(owner)
                }
            }
        }
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86_64",
            target_arch = "x86"
        )))]
        {
            let _ = (address, arg0, arg1);
            Err(StatusCode::INVALID_OPERATION)
        }
    }

    pub(super) fn from_binder(binder: &SpIBinder) -> Result<Self, StatusCode> {
        // SAFETY: The address is passed to the non-trivial sp return adapter, never called as T.
        let function: unsafe extern "C" fn() =
            unsafe { native_function(b"_Z25AIBinder_toPlatformBinderP8AIBinder\0")? };
        // SAFETY: binder holds a live AIBinder and the adapter supplies the native sp return slot.
        unsafe { Self::call_address(function as *const (), binder.as_raw() as usize, 0) }
    }

    /// Convert an actual IBinder strong reference into its NDK owner.
    ///
    /// # Safety
    /// The stored native object must be sp<IBinder>, not another RefBase-derived sp.
    pub(super) unsafe fn to_binder(&self) -> Result<SpIBinder, StatusCode> {
        // SAFETY: The caller guarantees an IBinder; self retains its native strong reference.
        unsafe { binder_from_platform(self.as_ptr()) }
    }

    pub(super) fn as_ptr(&self) -> *mut c_void {
        self.raw.pointer
    }

    pub(super) fn as_slot(&self) -> *const NativeStrong {
        &self.raw
    }
}

/// # Safety
/// pointer must identify an IBinder retained by a strong reference throughout this call.
pub(super) unsafe fn binder_from_platform(pointer: *mut c_void) -> Result<SpIBinder, StatusCode> {
    // SAFETY: The conversion borrows an sp slot and creates a separate NDK strong reference.
    let function: unsafe extern "C" fn(*const NativeStrong) -> *mut sys::AIBinder = unsafe {
        native_function(b"_Z27AIBinder_fromPlatformBinderRKN7android2spINS_7IBinderEEE\0")?
    };
    let borrowed = NativeStrong { pointer };
    // SAFETY: The caller retains pointer. This borrowed slot has no CppStrong destructor.
    unsafe { SpIBinder::from_raw(function(&borrowed)) }.ok_or(StatusCode::UNEXPECTED_NULL)
}

impl Drop for CppStrong {
    fn drop(&mut self) {
        let pointer = self.as_ptr();
        if pointer.is_null() {
            return;
        }
        // SAFETY: This is RefBase::decStrong's receiver/id ABI, checked before adopting the sp.
        let release: unsafe extern "C" fn(*const c_void, *const c_void) =
            unsafe { native_function(b"_ZNK7android7RefBase9decStrongEPKv\0") }
                .expect("native release was checked before adoption");
        // SAFETY: The live sp owns one strong reference. These device classes have one virtual
        // RefBase at the Itanium vptr[-3] offset; release consumes that reference exactly once.
        unsafe {
            let vtable = pointer.cast::<*const isize>().read();
            let offset = vtable.offset(-3).read();
            release(pointer.cast::<u8>().offset(offset).cast(), self.as_slot().cast());
        }
    }
}
