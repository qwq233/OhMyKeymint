/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust API for interacting with a remote binder service.

use crate::binder::{
    AsNative, FromIBinder, IBinder, IBinderInternal, Interface, InterfaceClass, Strong,
    TransactionCode, TransactionFlags,
};
use crate::error::{status_result, Result, StatusCode};
use crate::parcel::{
    BorrowedParcel, Deserialize, DeserializeArray, DeserializeOption, Parcel, Serialize,
    SerializeArray, SerializeOption,
};
use crate::sys;
#[cfg(feature = "android_ndk_compat_symbols")]
use crate::sys::compat as binder_rs_ndk_compat;

use std::cmp::Ordering;
use std::ffi::c_void;
use std::fmt;
use std::mem;
use std::ptr;
use std::sync::Arc;

use std::ffi::CString;
use std::os::fd::AsRawFd;

/// A strong reference to a Binder remote object.
///
/// This struct encapsulates the generic C++ `sp<IBinder>` class. This wrapper
/// is untyped; typed interface access is implemented by the AIDL compiler.
pub struct SpIBinder(ptr::NonNull<sys::AIBinder>);

impl fmt::Debug for SpIBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("SpIBinder")
    }
}

/// Safety: An `SpIBinder` is an immutable handle to a C++ IBinder, which is
/// thread-safe.
unsafe impl Send for SpIBinder {}

/// Safety: An `SpIBinder` is an immutable handle to a C++ IBinder, which is
/// thread-safe.
unsafe impl Sync for SpIBinder {}

impl SpIBinder {
    /// Create an `SpIBinder` wrapper object from a raw `AIBinder` pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe iff `ptr` is a null pointer or a valid pointer
    /// to an `AIBinder`.
    ///
    /// In the non-null case, this method conceptually takes ownership of a strong
    /// reference to the object, so `AIBinder_incStrong` must have been called
    /// on the pointer before passing it to this constructor. This is generally
    /// done by Binder NDK methods that return an `AIBinder`, but care should be
    /// taken to ensure this invariant.
    ///
    /// All `SpIBinder` objects that are constructed will hold a valid pointer
    /// to an `AIBinder`, which will remain valid for the entire lifetime of the
    /// `SpIBinder` (we keep a strong reference, and only decrement on drop).
    pub(crate) unsafe fn from_raw(ptr: *mut sys::AIBinder) -> Option<Self> {
        ptr::NonNull::new(ptr).map(Self)
    }

    /// Extract a raw `AIBinder` pointer from this wrapper.
    ///
    /// This method should _only_ be used for testing. Do not try to use the NDK
    /// interface directly for anything else.
    ///
    /// # Safety
    ///
    /// The resulting pointer is valid only as long as the SpIBinder is alive.
    /// The SpIBinder object retains ownership of the AIBinder and the caller
    /// should not attempt to free the returned pointer.
    pub unsafe fn as_raw(&self) -> *mut sys::AIBinder {
        self.0.as_ptr()
    }

    /// Return true if this binder object is hosted in a different process than
    /// the current one.
    pub fn is_remote(&self) -> bool {
        // Safety: `SpIBinder` guarantees that it always contains a valid
        // `AIBinder` pointer.
        unsafe { sys::AIBinder_isRemote(self.as_native()) }
    }

    /// Try to convert this Binder object into a trait object for the given
    /// Binder interface.
    ///
    /// If this object does not implement the expected interface, the error
    /// `StatusCode::BAD_TYPE` is returned.
    pub fn into_interface<I: FromIBinder + Interface + ?Sized>(self) -> Result<Strong<I>> {
        FromIBinder::try_from(self)
    }

    /// Return the interface class of this binder object, if associated with
    /// one.
    pub fn get_class(&mut self) -> Option<InterfaceClass> {
        // Safety: `SpIBinder` guarantees that it always contains a valid
        // `AIBinder` pointer. `AIBinder_getClass` returns either a null
        // pointer or a valid pointer to an `AIBinder_Class`. After mapping
        // null to None, we can safely construct an `InterfaceClass` if the
        // pointer was non-null.
        unsafe {
            let class = sys::AIBinder_getClass(self.as_native_mut());
            class.as_ref().map(|p| InterfaceClass::from_ptr(p))
        }
    }

    /// Creates a new weak reference to this binder object.
    pub fn downgrade(&mut self) -> WpIBinder {
        WpIBinder::new(self)
    }

    /// Returns true if this binder object requires a VINTF declaration.
    #[cfg(not(android_ndk))]
    pub fn requires_vintf_declaration(&self) -> bool {
        #[cfg(feature = "android_ndk_compat_symbols")]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            binder_rs_ndk_compat::requires_vintf_declaration(self.as_raw())
        }
        #[cfg(not(feature = "android_ndk_compat_symbols"))]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            sys::AIBinder_requiresVintfDeclaration(self.as_raw())
        }
    }

    /// Returns true if this binder object is vendor stable.
    #[cfg(not(android_ndk))]
    pub fn is_vendor_stable(&self) -> bool {
        #[cfg(feature = "android_ndk_compat_symbols")]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            binder_rs_ndk_compat::is_vendor_stable(self.as_raw())
        }
        #[cfg(not(feature = "android_ndk_compat_symbols"))]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            sys::AIBinder_isVendorStable(self.as_raw())
        }
    }

    /// Returns true if this binder object is system stable.
    #[cfg(not(android_ndk))]
    pub fn is_system_stable(&self) -> bool {
        #[cfg(feature = "android_ndk_compat_symbols")]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            binder_rs_ndk_compat::is_system_stable(self.as_raw())
        }
        #[cfg(not(feature = "android_ndk_compat_symbols"))]
        // Safety: `self.as_raw()` returns a valid `AIBinder` pointer.
        unsafe {
            sys::AIBinder_isSystemStable(self.as_raw())
        }
    }
}

pub mod unstable_api {
    use super::{sys, SpIBinder};

    /// A temporary API to allow the client to create a `SpIBinder` from a `sys::AIBinder`. This is
    /// needed to bridge RPC binder, which doesn't have Rust API yet.
    /// TODO(b/184872979): remove once the Rust API is created.
    ///
    /// # Safety
    ///
    /// See `SpIBinder::from_raw`.
    pub unsafe fn new_spibinder(ptr: *mut sys::AIBinder) -> Option<SpIBinder> {
        // Safety: The caller makes the same guarantees as this requires.
        unsafe { SpIBinder::from_raw(ptr) }
    }
}

/// An object that can be associate with an [`InterfaceClass`].
pub trait AssociateClass {
    /// Check if this object is a valid object for the given interface class
    /// `I`.
    ///
    /// Returns `Some(self)` if this is a valid instance of the interface, and
    /// `None` otherwise.
    ///
    /// Classes constructed by `InterfaceClass` are unique per type, so
    /// repeatedly calling this method for the same `InterfaceClass` is allowed.
    fn associate_class(&mut self, class: InterfaceClass) -> bool;
}

impl AssociateClass for SpIBinder {
    fn associate_class(&mut self, class: InterfaceClass) -> bool {
        // Safety: `SpIBinder` guarantees that it always contains a valid
        // `AIBinder` pointer. An `InterfaceClass` can always be converted
        // into a valid `AIBinder_Class` pointer, so these parameters are
        // always safe.
        unsafe { sys::AIBinder_associateClass(self.as_native_mut(), class.into()) }
    }
}

impl Ord for SpIBinder {
    fn cmp(&self, other: &Self) -> Ordering {
        // Safety: SpIBinder always holds a valid `AIBinder` pointer, so this
        // pointer is always safe to pass to `AIBinder_lt` (null is also safe to
        // pass to this function, but we should never do that).
        let less_than = unsafe { sys::AIBinder_lt(self.0.as_ptr(), other.0.as_ptr()) };
        // Safety: SpIBinder always holds a valid `AIBinder` pointer, so this
        // pointer is always safe to pass to `AIBinder_lt` (null is also safe to
        // pass to this function, but we should never do that).
        let greater_than = unsafe { sys::AIBinder_lt(other.0.as_ptr(), self.0.as_ptr()) };
        if !less_than && !greater_than {
            Ordering::Equal
        } else if less_than {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for SpIBinder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SpIBinder {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for SpIBinder {}

impl Clone for SpIBinder {
    fn clone(&self) -> Self {
        // Safety: Cloning a strong reference must increment the reference
        // count. We are guaranteed by the `SpIBinder` constructor
        // invariants that `self.0` is always a valid `AIBinder` pointer.
        unsafe {
            sys::AIBinder_incStrong(self.0.as_ptr());
        }
        Self(self.0)
    }
}

impl Drop for SpIBinder {
    // We hold a strong reference to the IBinder in SpIBinder and need to give up
    // this reference on drop.
    fn drop(&mut self) {
        // Safety: SpIBinder always holds a valid `AIBinder` pointer, so we
        // know this pointer is safe to pass to `AIBinder_decStrong` here.
        unsafe {
            sys::AIBinder_decStrong(self.as_native_mut());
        }
    }
}

impl<T: AsNative<sys::AIBinder>> IBinderInternal for T {
    fn prepare_transact(&self) -> Result<Parcel> {
        let mut input = ptr::null_mut();
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. It is safe to cast from an
        // immutable pointer to a mutable pointer here, because
        // `AIBinder_prepareTransaction` only calls immutable `AIBinder`
        // methods but the parameter is unfortunately not marked as const.
        //
        // After the call, input will be either a valid, owned `AParcel`
        // pointer, or null.
        let status = unsafe {
            sys::AIBinder_prepareTransaction(self.as_native() as *mut sys::AIBinder, &mut input)
        };

        status_result(status)?;

        // Safety: At this point, `input` is either a valid, owned `AParcel`
        // pointer, or null. `OwnedParcel::from_raw` safely handles both cases,
        // taking ownership of the parcel.
        unsafe { Parcel::from_raw(input).ok_or(StatusCode::UNEXPECTED_NULL) }
    }

    fn submit_transact(
        &self,
        code: TransactionCode,
        data: Parcel,
        flags: TransactionFlags,
    ) -> Result<Parcel> {
        let mut reply = ptr::null_mut();
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. Although `IBinder::transact` is
        // not a const method, it is still safe to cast our immutable
        // pointer to mutable for the call. First, `IBinder::transact` is
        // thread-safe, so concurrency is not an issue. The only way that
        // `transact` can affect any visible, mutable state in the current
        // process is by calling `onTransact` for a local service. However,
        // in order for transactions to be thread-safe, this method must
        // dynamically lock its data before modifying it. We enforce this
        // property in Rust by requiring `Sync` for remotable objects and
        // only providing `on_transact` with an immutable reference to
        // `self`.
        //
        // This call takes ownership of the `data` parcel pointer, and
        // passes ownership of the `reply` out parameter to its caller. It
        // does not affect ownership of the `binder` parameter.
        let status = unsafe {
            sys::AIBinder_transact(
                self.as_native() as *mut sys::AIBinder,
                code,
                &mut data.into_raw(),
                &mut reply,
                flags,
            )
        };
        status_result(status)?;

        // Safety: `reply` is either a valid `AParcel` pointer or null
        // after the call to `AIBinder_transact` above, so we can
        // construct a `Parcel` out of it. `AIBinder_transact` passes
        // ownership of the `reply` parcel to Rust, so we need to
        // construct an owned variant.
        unsafe { Parcel::from_raw(reply).ok_or(StatusCode::UNEXPECTED_NULL) }
    }

    fn is_binder_alive(&self) -> bool {
        // Safety: `SpIBinder` guarantees that `self` always contains a valid
        // pointer to an `AIBinder`.
        //
        // This call does not affect ownership of its pointer parameter.
        unsafe { sys::AIBinder_isAlive(self.as_native()) }
    }

    #[cfg(not(any(android_vndk, android_ndk)))]
    fn set_requesting_sid(&mut self, enable: bool) {
        // Safety: `SpIBinder` guarantees that `self` always contains a valid
        // pointer to an `AIBinder`.
        //
        // This call does not affect ownership of its pointer parameter.
        unsafe { sys::AIBinder_setRequestingSid(self.as_native_mut(), enable) };
    }

    fn set_inherit_rt(&mut self, enable: bool) {
        // Safety: `SpIBinder` guarantees that `self` always contains a valid
        // pointer to an `AIBinder`.
        //
        // This call does not affect ownership of its pointer parameter.
        unsafe { sys::AIBinder_setInheritRt(self.as_native_mut(), enable) };
    }

    fn dump<F: AsRawFd>(&mut self, fp: &F, args: &[&str]) -> Result<()> {
        let args: Vec<_> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
        let mut arg_ptrs: Vec<_> = args.iter().map(|a| a.as_ptr()).collect();
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. `AsRawFd` guarantees that the
        // file descriptor parameter is always be a valid open file. The
        // `args` pointer parameter is a valid pointer to an array of C
        // strings that will outlive the call since `args` lives for the
        // whole function scope.
        //
        // This call does not affect ownership of its binder pointer
        // parameter and does not take ownership of the file or args array
        // parameters.
        let status = unsafe {
            sys::AIBinder_dump(
                self.as_native_mut(),
                fp.as_raw_fd(),
                arg_ptrs.as_mut_ptr(),
                arg_ptrs.len().try_into().unwrap(),
            )
        };
        status_result(status)
    }

    fn get_extension(&mut self) -> Result<Option<SpIBinder>> {
        let mut out = ptr::null_mut();
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. After this call, the `out`
        // parameter will be either null, or a valid pointer to an
        // `AIBinder`.
        //
        // This call passes ownership of the out pointer to its caller
        // (assuming it is set to a non-null value).
        let status = unsafe { sys::AIBinder_getExtension(self.as_native_mut(), &mut out) };
        // Safety: The call above guarantees that `out` is either null or a
        // valid, owned pointer to an `AIBinder`, both of which are safe to
        // pass to `SpIBinder::from_raw`.
        let ibinder = unsafe { SpIBinder::from_raw(out) };

        status_result(status)?;
        Ok(ibinder)
    }
}

impl<T: AsNative<sys::AIBinder>> IBinder for T {
    fn link_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()> {
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. `recipient` can always be
        // converted into a valid pointer to an
        // `AIBinder_DeathRecipient`.
        //
        // The cookie is also the correct pointer, and by calling new_cookie,
        // we have created a new ref-count to the cookie, which linkToDeath
        // takes ownership of. Once the DeathRecipient is unlinked for any
        // reason (including if this call fails), the onUnlinked callback
        // will consume that ref-count.
        status_result(unsafe {
            sys::AIBinder_linkToDeath(
                self.as_native_mut(),
                recipient.as_native_mut(),
                recipient.new_cookie(),
            )
        })
    }

    fn unlink_to_death(&mut self, recipient: &mut DeathRecipient) -> Result<()> {
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`. `recipient` can always be
        // converted into a valid pointer to an
        // `AIBinder_DeathRecipient`. Any value is safe to pass as the
        // cookie, although we depend on this value being set by
        // `get_cookie` when the death recipient callback is called.
        status_result(unsafe {
            sys::AIBinder_unlinkToDeath(
                self.as_native_mut(),
                recipient.as_native_mut(),
                recipient.get_cookie(),
            )
        })
    }

    fn ping_binder(&mut self) -> Result<()> {
        // Safety: `SpIBinder` guarantees that `self` always contains a
        // valid pointer to an `AIBinder`.
        //
        // This call does not affect ownership of its pointer parameter.
        let status = unsafe { sys::AIBinder_ping(self.as_native_mut()) };
        status_result(status)
    }
}

impl Serialize for SpIBinder {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        parcel.write_binder(Some(self))
    }
}

impl SerializeOption for SpIBinder {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        parcel.write_binder(this)
    }
}

impl SerializeArray for SpIBinder {}

impl Deserialize for SpIBinder {
    type UninitType = Option<Self>;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        Some(value)
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<SpIBinder> {
        parcel.read_binder().transpose().unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeOption for SpIBinder {
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<SpIBinder>> {
        parcel.read_binder()
    }
}

impl DeserializeArray for SpIBinder {}

/// A weak reference to a Binder remote object.
///
/// This struct encapsulates the generic C++ `wp<IBinder>` class. This wrapper
/// is untyped; typed interface access is implemented by the AIDL compiler.
pub struct WpIBinder(ptr::NonNull<sys::AIBinder_Weak>);

impl fmt::Debug for WpIBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("WpIBinder")
    }
}

/// Safety: A `WpIBinder` is an immutable handle to a C++ IBinder, which is
/// thread-safe.
unsafe impl Send for WpIBinder {}

/// Safety: A `WpIBinder` is an immutable handle to a C++ IBinder, which is
/// thread-safe.
unsafe impl Sync for WpIBinder {}

impl WpIBinder {
    /// Create a new weak reference from an object that can be converted into a
    /// raw `AIBinder` pointer.
    fn new<B: AsNative<sys::AIBinder>>(binder: &mut B) -> WpIBinder {
        // Safety: `SpIBinder` guarantees that `binder` always contains a valid
        // pointer to an `AIBinder`.
        let ptr = unsafe { sys::AIBinder_Weak_new(binder.as_native_mut()) };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null pointer from AIBinder_Weak_new"))
    }

    /// Promote this weak reference to a strong reference to the binder object.
    pub fn promote(&self) -> Option<SpIBinder> {
        // Safety: `WpIBinder` always contains a valid weak reference, so we can
        // pass this pointer to `AIBinder_Weak_promote`. Returns either null or
        // an AIBinder owned by the caller, both of which are valid to pass to
        // `SpIBinder::from_raw`.
        unsafe {
            let ptr = sys::AIBinder_Weak_promote(self.0.as_ptr());
            SpIBinder::from_raw(ptr)
        }
    }
}

impl Clone for WpIBinder {
    fn clone(&self) -> Self {
        // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer, so
        // this pointer is always safe to pass to `AIBinder_Weak_clone`
        // (although null is also a safe value to pass to this API).
        //
        // We get ownership of the returned pointer, so can construct a new
        // WpIBinder object from it.
        let ptr = unsafe { sys::AIBinder_Weak_clone(self.0.as_ptr()) };
        Self(ptr::NonNull::new(ptr).expect("Unexpected null pointer from AIBinder_Weak_clone"))
    }
}

impl Ord for WpIBinder {
    fn cmp(&self, other: &Self) -> Ordering {
        // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer, so
        // this pointer is always safe to pass to `AIBinder_Weak_lt` (null is
        // also safe to pass to this function, but we should never do that).
        let less_than = unsafe { sys::AIBinder_Weak_lt(self.0.as_ptr(), other.0.as_ptr()) };
        // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer, so
        // this pointer is always safe to pass to `AIBinder_Weak_lt` (null is
        // also safe to pass to this function, but we should never do that).
        let greater_than = unsafe { sys::AIBinder_Weak_lt(other.0.as_ptr(), self.0.as_ptr()) };
        if !less_than && !greater_than {
            Ordering::Equal
        } else if less_than {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for WpIBinder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WpIBinder {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for WpIBinder {}

impl Drop for WpIBinder {
    fn drop(&mut self) {
        // Safety: WpIBinder always holds a valid `AIBinder_Weak` pointer, so we
        // know this pointer is safe to pass to `AIBinder_Weak_delete` here.
        unsafe {
            sys::AIBinder_Weak_delete(self.0.as_ptr());
        }
    }
}

/// Rust wrapper around DeathRecipient objects.
///
/// The cookie in this struct represents an `Arc<F>` for the owned callback.
/// This struct owns a ref-count of it, and so does every binder that we
/// have been linked with.
///
/// Dropping the `DeathRecipient` will `unlink_to_death` any binders it is
/// currently linked to.
#[repr(C)]
pub struct DeathRecipient {
    recipient: *mut sys::AIBinder_DeathRecipient,
    cookie: *mut c_void,
    vtable: &'static DeathRecipientVtable,
}

struct DeathRecipientVtable {
    cookie_incr_refcount: unsafe extern "C" fn(*mut c_void),
    cookie_decr_refcount: unsafe extern "C" fn(*mut c_void),
}

/// Safety: A `DeathRecipient` is a wrapper around `AIBinder_DeathRecipient` and
/// a pointer to a `Fn` which is `Sync` and `Send` (the cookie field). As
/// `AIBinder_DeathRecipient` is threadsafe, this structure is too.
unsafe impl Send for DeathRecipient {}

/// Safety: A `DeathRecipient` is a wrapper around `AIBinder_DeathRecipient` and
/// a pointer to a `Fn` which is `Sync` and `Send` (the cookie field). As
/// `AIBinder_DeathRecipient` is threadsafe, this structure is too.
unsafe impl Sync for DeathRecipient {}

impl DeathRecipient {
    /// Create a new death recipient that will call the given callback when its
    /// associated object dies.
    pub fn new<F>(callback: F) -> DeathRecipient
    where
        F: Fn() + Send + Sync + 'static,
    {
        let callback: *const F = Arc::into_raw(Arc::new(callback));
        // Safety: The function pointer is a valid death recipient callback.
        //
        // This call returns an owned `AIBinder_DeathRecipient` pointer which
        // must be destroyed via `AIBinder_DeathRecipient_delete` when no longer
        // needed.
        let recipient = unsafe { sys::AIBinder_DeathRecipient_new(Some(Self::binder_died::<F>)) };
        // Safety: The function pointer is a valid onUnlinked callback.
        //
        // All uses of linkToDeath in this file correctly increment the
        // ref-count that this onUnlinked callback will decrement.
        unsafe {
            sys::AIBinder_DeathRecipient_setOnUnlinked(
                recipient,
                Some(Self::cookie_decr_refcount::<F>),
            );
        }
        DeathRecipient {
            recipient,
            cookie: callback as *mut c_void,
            vtable: &DeathRecipientVtable {
                cookie_incr_refcount: Self::cookie_incr_refcount::<F>,
                cookie_decr_refcount: Self::cookie_decr_refcount::<F>,
            },
        }
    }

    /// Increment the ref-count for the cookie and return it.
    ///
    /// # Safety
    ///
    /// The caller must handle the returned ref-count correctly.
    unsafe fn new_cookie(&self) -> *mut c_void {
        // Safety: `cookie_incr_refcount` points to
        // `Self::cookie_incr_refcount`, and `self.cookie` is the cookie for an
        // Arc<F>.
        unsafe {
            (self.vtable.cookie_incr_refcount)(self.cookie);
        }

        // Return a raw pointer with ownership of a ref-count
        self.cookie
    }

    /// Get the opaque cookie that identifies this death recipient.
    ///
    /// This cookie will be used to link and unlink this death recipient to a
    /// binder object and will be passed to the `binder_died` callback as an
    /// opaque userdata pointer.
    fn get_cookie(&self) -> *mut c_void {
        self.cookie
    }

    /// Callback invoked from C++ when the binder object dies.
    ///
    /// # Safety
    ///
    /// The `cookie` parameter must be the cookie for an `Arc<F>` and
    /// the caller must hold a ref-count to it.
    unsafe extern "C" fn binder_died<F>(cookie: *mut c_void)
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Safety: The caller promises that `cookie` is for an Arc<F>.
        let callback = unsafe { (cookie as *const F).as_ref().unwrap() };
        callback();
    }

    /// Callback that decrements the ref-count.
    /// This is invoked from C++ when a binder is unlinked.
    ///
    /// # Safety
    ///
    /// The `cookie` parameter must be the cookie for an `Arc<F>` and
    /// the owner must give up a ref-count to it.
    unsafe extern "C" fn cookie_decr_refcount<F>(cookie: *mut c_void)
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Safety: The caller promises that `cookie` is for an Arc<F>.
        drop(unsafe { Arc::from_raw(cookie as *const F) });
    }

    /// Callback that increments the ref-count.
    ///
    /// # Safety
    ///
    /// The `cookie` parameter must be the cookie for an `Arc<F>` and
    /// the owner must handle the created ref-count properly.
    unsafe extern "C" fn cookie_incr_refcount<F>(cookie: *mut c_void)
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Safety: The caller promises that `cookie` is for an Arc<F>.
        let arc = mem::ManuallyDrop::new(unsafe { Arc::from_raw(cookie as *const F) });
        mem::forget(Arc::clone(&arc));
    }
}

/// Safety: A `DeathRecipient` is always constructed with a valid raw pointer to
/// an `AIBinder_DeathRecipient`, so it is always type-safe to extract this
/// pointer.
unsafe impl AsNative<sys::AIBinder_DeathRecipient> for DeathRecipient {
    fn as_native(&self) -> *const sys::AIBinder_DeathRecipient {
        self.recipient
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder_DeathRecipient {
        self.recipient
    }
}

impl Drop for DeathRecipient {
    fn drop(&mut self) {
        // Safety: `self.recipient` is always a valid, owned
        // `AIBinder_DeathRecipient` pointer returned by
        // `AIBinder_DeathRecipient_new` when `self` was created. This delete
        // method can only be called once when `self` is dropped.
        unsafe {
            sys::AIBinder_DeathRecipient_delete(self.recipient);
        }

        // Safety: We own a ref-count to the cookie, and so does every linked
        // binder. This call gives up our ref-count. The linked binders should
        // already have given up their ref-count, or should do so shortly.
        unsafe {
            (self.vtable.cookie_decr_refcount)(self.cookie);
        }
    }
}

/// Generic interface to remote binder objects.
///
/// Corresponds to the C++ `BpInterface` class.
pub trait Proxy: Sized + Interface {
    /// The Binder interface descriptor string.
    ///
    /// This string is a unique identifier for a Binder interface, and should be
    /// the same between all implementations of that interface.
    fn get_descriptor() -> &'static str;

    /// Create a new interface from the given proxy, if it matches the expected
    /// type of this interface.
    fn from_binder(binder: SpIBinder) -> Result<Self>;
}

/// Safety: This is a convenience method that wraps `AsNative` for `SpIBinder`
/// to allow invocation of `IBinder` methods directly from `Interface` objects.
/// It shares the same safety as the implementation for `SpIBinder`.
unsafe impl<T: Proxy> AsNative<sys::AIBinder> for T {
    fn as_native(&self) -> *const sys::AIBinder {
        self.as_binder().as_native()
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder {
        self.as_binder().as_native_mut()
    }
}

/// Safety: `SpIBinder` guarantees that `binder` always contains a valid pointer
/// to an `AIBinder`, so we can trivially extract this pointer here.
unsafe impl AsNative<sys::AIBinder> for SpIBinder {
    fn as_native(&self) -> *const sys::AIBinder {
        self.0.as_ptr()
    }

    fn as_native_mut(&mut self) -> *mut sys::AIBinder {
        self.0.as_ptr()
    }
}
