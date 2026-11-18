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

//! Container for messages that are sent via binder.

use crate::binder::AsNative;
use crate::error::{status_result, Result, StatusCode};
use crate::proxy::SpIBinder;
use crate::sys;

use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ptr::{self, NonNull};

mod file_descriptor;
mod parcelable;
mod parcelable_holder;

pub use self::file_descriptor::ParcelFileDescriptor;
pub use self::parcelable::{
    Deserialize, DeserializeArray, DeserializeOption, Parcelable, Serialize, SerializeArray,
    SerializeOption, UnstructuredParcelable, NON_NULL_PARCELABLE_FLAG, NULL_PARCELABLE_FLAG,
};
pub use self::parcelable_holder::{ParcelableHolder, ParcelableMetadata};

/// Container for a message (data and object references) that can be sent
/// through Binder.
///
/// A Parcel can contain both serialized data that will be deserialized on the
/// other side of the IPC, and references to live Binder objects that will
/// result in the other side receiving a proxy Binder connected with the
/// original Binder in the Parcel.
///
/// This type represents a parcel that is owned by Rust code.
#[repr(transparent)]
pub struct Parcel {
    ptr: NonNull<sys::AParcel>,
}

/// Safety: This type guarantees that it owns the AParcel and that all access to
/// the AParcel happens through the Parcel, so it is ok to send across threads.
///
/// It would not be okay to implement Sync, because that would allow you to call
/// the reading methods from several threads in parallel, which would be a data
/// race on the cursor position inside the AParcel.
unsafe impl Send for Parcel {}

/// Container for a message (data and object references) that can be sent
/// through Binder.
///
/// This object is a borrowed variant of [`Parcel`]. It is a separate type from
/// `&mut Parcel` because it is not valid to `mem::swap` two parcels.
#[repr(transparent)]
pub struct BorrowedParcel<'a> {
    ptr: NonNull<sys::AParcel>,
    _lifetime: PhantomData<&'a mut Parcel>,
}

impl Parcel {
    /// Create a new empty `Parcel`.
    pub fn new() -> Parcel {
        // Safety: If `AParcel_create` succeeds, it always returns
        // a valid pointer. If it fails, the process will crash.
        let ptr = unsafe { sys::AParcel_create() };
        Self { ptr: NonNull::new(ptr).expect("AParcel_create returned null pointer") }
    }

    /// Create an owned reference to a parcel object from a raw pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe if the raw pointer parameter is either null
    /// (resulting in `None`), or a valid pointer to an `AParcel` object. The
    /// parcel object must be owned by the caller prior to this call, as this
    /// constructor takes ownership of the parcel and will destroy it on drop.
    ///
    /// Additionally, the caller must guarantee that it is valid to take
    /// ownership of the AParcel object. All future access to the AParcel
    /// must happen through this `Parcel`.
    ///
    /// Because `Parcel` implements `Send`, the pointer must never point to any
    /// thread-local data, e.g., a variable on the stack, either directly or
    /// indirectly.
    pub unsafe fn from_raw(ptr: *mut sys::AParcel) -> Option<Parcel> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    /// Create a new `Parcel` with the raw bytes from the buffer.
    pub fn unmarshal(buffer: &[u8]) -> Parcel {
        let parcel = Self::new();

        // Safety: The validity of the raw pointer to an `AParcel` is verified in the
        // constructor `new`. Providing the raw byte array pointer is also safe since
        // `AParcel_unmarshal` only borrows the data buffer (it accepts only a const
        // pointer and deep copies all the data internally). Also, by specifying the
        // array length with `.len()`, this ensures that `AParcel_unmarshal` only
        // accesses a valid memory area.
        status_result(unsafe {
            sys::AParcel_unmarshal(parcel.ptr.as_ptr(), buffer.as_ptr(), buffer.len())
        })
        .expect("AParcel_unmarshal failed");

        parcel
    }

    /// Consume the parcel, transferring ownership to the caller.
    pub(crate) fn into_raw(self) -> *mut sys::AParcel {
        let ptr = self.ptr.as_ptr();
        let _ = ManuallyDrop::new(self);
        ptr
    }

    /// Get a borrowed view into the contents of this `Parcel`.
    pub fn borrowed(&mut self) -> BorrowedParcel<'_> {
        // Safety: The raw pointer is a valid pointer to an AParcel, and the
        // lifetime of the returned `BorrowedParcel` is tied to `self`, so the
        // borrow checker will ensure that the `AParcel` can only be accessed
        // via the `BorrowParcel` until it goes out of scope.
        BorrowedParcel { ptr: self.ptr, _lifetime: PhantomData }
    }

    /// Get an immutable borrowed view into the contents of this `Parcel`.
    pub fn borrowed_ref(&self) -> &BorrowedParcel<'_> {
        // Safety: Parcel and BorrowedParcel are both represented in the same
        // way as a NonNull<sys::AParcel> due to their use of repr(transparent),
        // so casting references as done here is valid.
        unsafe { &*(self as *const Parcel as *const BorrowedParcel<'_>) }
    }
}

impl Default for Parcel {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Parcel {
    fn clone(&self) -> Self {
        let mut new_parcel = Self::new();
        new_parcel
            .borrowed()
            .append_all_from(self.borrowed_ref())
            .expect("Failed to append from Parcel");
        new_parcel
    }
}

impl<'a> BorrowedParcel<'a> {
    /// Create a borrowed reference to a parcel object from a raw pointer.
    ///
    /// # Safety
    ///
    /// This constructor is safe if the raw pointer parameter is either null
    /// (resulting in `None`), or a valid pointer to an `AParcel` object.
    ///
    /// Since the raw pointer is not restricted by any lifetime, the lifetime on
    /// the returned `BorrowedParcel` object can be chosen arbitrarily by the
    /// caller. The caller must ensure it is valid to mutably borrow the AParcel
    /// for the duration of the lifetime that the caller chooses. Note that
    /// since this is a mutable borrow, it must have exclusive access to the
    /// AParcel for the duration of the borrow.
    pub unsafe fn from_raw(ptr: *mut sys::AParcel) -> Option<BorrowedParcel<'a>> {
        Some(Self { ptr: NonNull::new(ptr)?, _lifetime: PhantomData })
    }

    /// Get a sub-reference to this reference to the parcel.
    pub fn reborrow(&mut self) -> BorrowedParcel<'_> {
        // Safety: The raw pointer is a valid pointer to an AParcel, and the
        // lifetime of the returned `BorrowedParcel` is tied to `self`, so the
        // borrow checker will ensure that the `AParcel` can only be accessed
        // via the `BorrowParcel` until it goes out of scope.
        BorrowedParcel { ptr: self.ptr, _lifetime: PhantomData }
    }
}

/// Safety: The `Parcel` constructors guarantee that a `Parcel` object will
/// always contain a valid pointer to an `AParcel`.
unsafe impl AsNative<sys::AParcel> for Parcel {
    fn as_native(&self) -> *const sys::AParcel {
        self.ptr.as_ptr()
    }

    fn as_native_mut(&mut self) -> *mut sys::AParcel {
        self.ptr.as_ptr()
    }
}

/// Safety: The `BorrowedParcel` constructors guarantee that a `BorrowedParcel`
/// object will always contain a valid pointer to an `AParcel`.
unsafe impl AsNative<sys::AParcel> for BorrowedParcel<'_> {
    fn as_native(&self) -> *const sys::AParcel {
        self.ptr.as_ptr()
    }

    fn as_native_mut(&mut self) -> *mut sys::AParcel {
        self.ptr.as_ptr()
    }
}

// Data serialization methods
impl BorrowedParcel<'_> {
    /// Data written to parcelable is zero'd before being deleted or reallocated.
    #[cfg(not(android_ndk))]
    pub fn mark_sensitive(&mut self) {
        // Safety: guaranteed to have a parcel object, and this method never fails
        unsafe { sys::AParcel_markSensitive(self.as_native()) }
    }

    /// Write a type that implements [`Serialize`] to the parcel.
    pub fn write<S: Serialize + ?Sized>(&mut self, parcelable: &S) -> Result<()> {
        parcelable.serialize(self)
    }

    /// Writes the length of a slice to the parcel.
    ///
    /// This is used in AIDL-generated client side code to indicate the
    /// allocated space for an output array parameter.
    pub fn write_slice_size<T>(&mut self, slice: Option<&[T]>) -> Result<()> {
        if let Some(slice) = slice {
            let len: i32 = slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?;
            self.write(&len)
        } else {
            self.write(&-1i32)
        }
    }

    /// Perform a series of writes to the parcel, prepended with the length
    /// (in bytes) of the written data.
    ///
    /// The length `0i32` will be written to the parcel first, followed by the
    /// writes performed by the callback. The initial length will then be
    /// updated to the length of all data written by the callback, plus the
    /// size of the length elemement itself (4 bytes).
    ///
    /// # Examples
    ///
    /// After the following call:
    ///
    /// ```
    /// # use binder::{Binder, Interface, Parcel};
    /// # let mut parcel = Parcel::new();
    /// parcel.sized_write(|subparcel| {
    ///     subparcel.write(&1u32)?;
    ///     subparcel.write(&2u32)?;
    ///     subparcel.write(&3u32)
    /// });
    /// ```
    ///
    /// `parcel` will contain the following:
    ///
    /// ```ignore
    /// [16i32, 1u32, 2u32, 3u32]
    /// ```
    pub fn sized_write<F>(&mut self, f: F) -> Result<()>
    where
        for<'b> F: FnOnce(&'b mut WritableSubParcel<'b>) -> Result<()>,
    {
        let start = self.get_data_position();
        self.write(&0i32)?;
        {
            let mut subparcel = WritableSubParcel(self.reborrow());
            f(&mut subparcel)?;
        }
        let end = self.get_data_position();
        // Safety: start is less than the current size of the parcel data
        // buffer, because we just got it with `get_data_position`.
        unsafe {
            self.set_data_position(start)?;
        }
        assert!(end >= start);
        self.write(&(end - start))?;
        // Safety: end is less than the current size of the parcel data
        // buffer, because we just got it with `get_data_position`.
        unsafe {
            self.set_data_position(end)?;
        }
        Ok(())
    }

    /// Returns the current position in the parcel data.
    pub fn get_data_position(&self) -> i32 {
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`, and this call is otherwise safe.
        unsafe { sys::AParcel_getDataPosition(self.as_native()) }
    }

    /// Returns the total size of the parcel.
    pub fn get_data_size(&self) -> i32 {
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`, and this call is otherwise safe.
        unsafe { sys::AParcel_getDataSize(self.as_native()) }
    }

    /// Move the current read/write position in the parcel.
    ///
    /// # Safety
    ///
    /// This method is safe if `pos` is less than the current size of the parcel
    /// data buffer. Otherwise, we are relying on correct bounds checking in the
    /// Parcel C++ code on every subsequent read or write to this parcel. If all
    /// accesses are bounds checked, this call is still safe, but we can't rely
    /// on that.
    pub unsafe fn set_data_position(&self, pos: i32) -> Result<()> {
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`, and the caller guarantees that `pos` is within bounds.
        status_result(unsafe { sys::AParcel_setDataPosition(self.as_native(), pos) })
    }

    /// Append a subset of another parcel.
    ///
    /// This appends `size` bytes of data from `other` starting at offset
    /// `start` to the current parcel, or returns an error if not possible.
    pub fn append_from(
        &mut self,
        other: &impl AsNative<sys::AParcel>,
        start: i32,
        size: i32,
    ) -> Result<()> {
        // Safety: `Parcel::appendFrom` from C++ checks that `start`
        // and `size` are in bounds, and returns an error otherwise.
        // Both `self` and `other` always contain valid pointers.
        let status = unsafe {
            sys::AParcel_appendFrom(other.as_native(), self.as_native_mut(), start, size)
        };
        status_result(status)
    }

    /// Append the contents of another parcel.
    pub fn append_all_from(&mut self, other: &impl AsNative<sys::AParcel>) -> Result<()> {
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`, and this call is otherwise safe.
        let size = unsafe { sys::AParcel_getDataSize(other.as_native()) };
        self.append_from(other, 0, size)
    }
}

/// A segment of a writable parcel, used for [`BorrowedParcel::sized_write`].
pub struct WritableSubParcel<'a>(BorrowedParcel<'a>);

impl WritableSubParcel<'_> {
    /// Write a type that implements [`Serialize`] to the sub-parcel.
    pub fn write<S: Serialize + ?Sized>(&mut self, parcelable: &S) -> Result<()> {
        parcelable.serialize(&mut self.0)
    }
}

impl Parcel {
    /// Data written to parcelable is zero'd before being deleted or reallocated.
    #[cfg(not(android_ndk))]
    pub fn mark_sensitive(&mut self) {
        self.borrowed().mark_sensitive()
    }

    /// Write a type that implements [`Serialize`] to the parcel.
    pub fn write<S: Serialize + ?Sized>(&mut self, parcelable: &S) -> Result<()> {
        self.borrowed().write(parcelable)
    }

    /// Writes the length of a slice to the parcel.
    ///
    /// This is used in AIDL-generated client side code to indicate the
    /// allocated space for an output array parameter.
    pub fn write_slice_size<T>(&mut self, slice: Option<&[T]>) -> Result<()> {
        self.borrowed().write_slice_size(slice)
    }

    /// Perform a series of writes to the parcel, prepended with the length
    /// (in bytes) of the written data.
    ///
    /// The length `0i32` will be written to the parcel first, followed by the
    /// writes performed by the callback. The initial length will then be
    /// updated to the length of all data written by the callback, plus the
    /// size of the length elemement itself (4 bytes).
    ///
    /// # Examples
    ///
    /// After the following call:
    ///
    /// ```
    /// # use binder::{Binder, Interface, Parcel};
    /// # let mut parcel = Parcel::new();
    /// parcel.sized_write(|subparcel| {
    ///     subparcel.write(&1u32)?;
    ///     subparcel.write(&2u32)?;
    ///     subparcel.write(&3u32)
    /// });
    /// ```
    ///
    /// `parcel` will contain the following:
    ///
    /// ```ignore
    /// [16i32, 1u32, 2u32, 3u32]
    /// ```
    pub fn sized_write<F>(&mut self, f: F) -> Result<()>
    where
        for<'b> F: FnOnce(&'b mut WritableSubParcel<'b>) -> Result<()>,
    {
        self.borrowed().sized_write(f)
    }

    /// Returns the current position in the parcel data.
    pub fn get_data_position(&self) -> i32 {
        self.borrowed_ref().get_data_position()
    }

    /// Returns the total size of the parcel.
    pub fn get_data_size(&self) -> i32 {
        self.borrowed_ref().get_data_size()
    }

    /// Move the current read/write position in the parcel.
    ///
    /// # Safety
    ///
    /// This method is safe if `pos` is less than the current size of the parcel
    /// data buffer. Otherwise, we are relying on correct bounds checking in the
    /// Parcel C++ code on every subsequent read or write to this parcel. If all
    /// accesses are bounds checked, this call is still safe, but we can't rely
    /// on that.
    pub unsafe fn set_data_position(&self, pos: i32) -> Result<()> {
        // Safety: We have the same safety requirements as
        // `BorrowedParcel::set_data_position`.
        unsafe { self.borrowed_ref().set_data_position(pos) }
    }

    /// Append a subset of another parcel.
    ///
    /// This appends `size` bytes of data from `other` starting at offset
    /// `start` to the current parcel, or returns an error if not possible.
    pub fn append_from(
        &mut self,
        other: &impl AsNative<sys::AParcel>,
        start: i32,
        size: i32,
    ) -> Result<()> {
        self.borrowed().append_from(other, start, size)
    }

    /// Append the contents of another parcel.
    pub fn append_all_from(&mut self, other: &impl AsNative<sys::AParcel>) -> Result<()> {
        self.borrowed().append_all_from(other)
    }
}

// Data deserialization methods
impl BorrowedParcel<'_> {
    /// Attempt to read a type that implements [`Deserialize`] from this parcel.
    pub fn read<D: Deserialize>(&self) -> Result<D> {
        D::deserialize(self)
    }

    /// Attempt to read a type that implements [`Deserialize`] from this parcel
    /// onto an existing value. This operation will overwrite the old value
    /// partially or completely, depending on how much data is available.
    pub fn read_onto<D: Deserialize>(&self, x: &mut D) -> Result<()> {
        x.deserialize_from(self)
    }

    /// Safely read a sized parcelable.
    ///
    /// Read the size of a parcelable, compute the end position
    /// of that parcelable, then build a sized readable sub-parcel
    /// and call a closure with the sub-parcel as its parameter.
    /// The closure can keep reading data from the sub-parcel
    /// until it runs out of input data. The closure is responsible
    /// for calling `ReadableSubParcel::has_more_data` to check for
    /// more data before every read, at least until Rust generators
    /// are stabilized.
    /// After the closure returns, skip to the end of the current
    /// parcelable regardless of how much the closure has read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let mut parcelable = Default::default();
    /// parcel.sized_read(|subparcel| {
    ///     if subparcel.has_more_data() {
    ///         parcelable.a = subparcel.read()?;
    ///     }
    ///     if subparcel.has_more_data() {
    ///         parcelable.b = subparcel.read()?;
    ///     }
    ///     Ok(())
    /// });
    /// ```
    ///
    pub fn sized_read<F>(&self, f: F) -> Result<()>
    where
        for<'b> F: FnOnce(ReadableSubParcel<'b>) -> Result<()>,
    {
        let start = self.get_data_position();
        let parcelable_size: i32 = self.read()?;
        if parcelable_size < 4 {
            return Err(StatusCode::BAD_VALUE);
        }

        let end = start.checked_add(parcelable_size).ok_or(StatusCode::BAD_VALUE)?;
        if end > self.get_data_size() {
            return Err(StatusCode::NOT_ENOUGH_DATA);
        }

        let subparcel = ReadableSubParcel {
            parcel: BorrowedParcel { ptr: self.ptr, _lifetime: PhantomData },
            end_position: end,
        };
        f(subparcel)?;

        // Advance the data position to the actual end,
        // in case the closure read less data than was available.
        //
        // Safety: end must be less than the current size of the parcel, because
        // we checked above against `get_data_size`.
        unsafe {
            self.set_data_position(end)?;
        }

        Ok(())
    }

    /// Read a vector size from the parcel and resize the given output vector to
    /// be correctly sized for that amount of data.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_out_vec<D: Default + Deserialize>(&self, out_vec: &mut Vec<D>) -> Result<()> {
        let len: i32 = self.read()?;

        if len < 0 {
            return Err(StatusCode::UNEXPECTED_NULL);
        }

        // usize in Rust may be 16-bit, so i32 may not fit
        let len = len.try_into().unwrap();
        out_vec.resize_with(len, Default::default);

        Ok(())
    }

    /// Read a vector size from the parcel and either create a correctly sized
    /// vector for that amount of data or set the output parameter to None if
    /// the vector should be null.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_nullable_out_vec<D: Default + Deserialize>(
        &self,
        out_vec: &mut Option<Vec<D>>,
    ) -> Result<()> {
        let len: i32 = self.read()?;

        if len < 0 {
            *out_vec = None;
        } else {
            // usize in Rust may be 16-bit, so i32 may not fit
            let len = len.try_into().unwrap();
            let mut vec = Vec::with_capacity(len);
            vec.resize_with(len, Default::default);
            *out_vec = Some(vec);
        }

        Ok(())
    }
}

/// A segment of a readable parcel, used for [`Parcel::sized_read`].
pub struct ReadableSubParcel<'a> {
    parcel: BorrowedParcel<'a>,
    end_position: i32,
}

impl ReadableSubParcel<'_> {
    /// Read a type that implements [`Deserialize`] from the sub-parcel.
    pub fn read<D: Deserialize>(&self) -> Result<D> {
        D::deserialize(&self.parcel)
    }

    /// Check if the sub-parcel has more data to read
    pub fn has_more_data(&self) -> bool {
        self.parcel.get_data_position() < self.end_position
    }
}

impl Parcel {
    /// Attempt to read a type that implements [`Deserialize`] from this parcel.
    pub fn read<D: Deserialize>(&self) -> Result<D> {
        self.borrowed_ref().read()
    }

    /// Attempt to read a type that implements [`Deserialize`] from this parcel
    /// onto an existing value. This operation will overwrite the old value
    /// partially or completely, depending on how much data is available.
    pub fn read_onto<D: Deserialize>(&self, x: &mut D) -> Result<()> {
        self.borrowed_ref().read_onto(x)
    }

    /// Safely read a sized parcelable.
    ///
    /// Read the size of a parcelable, compute the end position
    /// of that parcelable, then build a sized readable sub-parcel
    /// and call a closure with the sub-parcel as its parameter.
    /// The closure can keep reading data from the sub-parcel
    /// until it runs out of input data. The closure is responsible
    /// for calling `ReadableSubParcel::has_more_data` to check for
    /// more data before every read, at least until Rust generators
    /// are stabilized.
    /// After the closure returns, skip to the end of the current
    /// parcelable regardless of how much the closure has read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let mut parcelable = Default::default();
    /// parcel.sized_read(|subparcel| {
    ///     if subparcel.has_more_data() {
    ///         parcelable.a = subparcel.read()?;
    ///     }
    ///     if subparcel.has_more_data() {
    ///         parcelable.b = subparcel.read()?;
    ///     }
    ///     Ok(())
    /// });
    /// ```
    ///
    pub fn sized_read<F>(&self, f: F) -> Result<()>
    where
        for<'b> F: FnOnce(ReadableSubParcel<'b>) -> Result<()>,
    {
        self.borrowed_ref().sized_read(f)
    }

    /// Read a vector size from the parcel and resize the given output vector to
    /// be correctly sized for that amount of data.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_out_vec<D: Default + Deserialize>(&self, out_vec: &mut Vec<D>) -> Result<()> {
        self.borrowed_ref().resize_out_vec(out_vec)
    }

    /// Read a vector size from the parcel and either create a correctly sized
    /// vector for that amount of data or set the output parameter to None if
    /// the vector should be null.
    ///
    /// This method is used in AIDL-generated server side code for methods that
    /// take a mutable slice reference parameter.
    pub fn resize_nullable_out_vec<D: Default + Deserialize>(
        &self,
        out_vec: &mut Option<Vec<D>>,
    ) -> Result<()> {
        self.borrowed_ref().resize_nullable_out_vec(out_vec)
    }

    /// Marshals the raw bytes of the Parcel to a buffer.
    ///
    /// The parcel must not contain any binders or file descriptors.
    ///
    /// The data you retrieve here must not be placed in any kind of persistent
    /// storage. (on local disk, across a network, etc). For that, you should
    /// use standard serialization or another kind of general serialization
    /// mechanism. The Parcel marshalled representation is highly optimized for
    /// local IPC, and as such does not attempt to maintain compatibility with
    /// data created in different versions of the platform.
    pub fn marshal(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; self.get_data_size() as usize];

        // Safety: `Parcel` always contains a valid pointer to an `AParcel`, by
        // specifying the length length `.len()`, `AParcel_marshal` ensures it
        // only writes to an expected, valid memory area.
        status_result(unsafe {
            sys::AParcel_marshal(self.ptr.as_ptr(), buffer.as_mut_ptr(), 0, buffer.len())
        })
        .expect("Failed to marshal");

        buffer
    }
}

// Internal APIs
impl BorrowedParcel<'_> {
    pub(crate) fn write_binder(&mut self, binder: Option<&SpIBinder>) -> Result<()> {
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`. `AsNative` for `Option<SpIBinder`> will either return
        // null or a valid pointer to an `AIBinder`, both of which are
        // valid, safe inputs to `AParcel_writeStrongBinder`.
        //
        // This call does not take ownership of the binder. However, it does
        // require a mutable pointer, which we cannot extract from an
        // immutable reference, so we clone the binder, incrementing the
        // refcount before the call. The refcount will be immediately
        // decremented when this temporary is dropped.
        unsafe {
            status_result(sys::AParcel_writeStrongBinder(
                self.as_native_mut(),
                binder.cloned().as_native_mut(),
            ))
        }
    }

    pub(crate) fn read_binder(&self) -> Result<Option<SpIBinder>> {
        let mut binder = ptr::null_mut();
        // Safety: `BorrowedParcel` always contains a valid pointer to an
        // `AParcel`. We pass a valid, mutable out pointer to the `binder`
        // parameter. After this call, `binder` will be either null or a
        // valid pointer to an `AIBinder` owned by the caller.
        let status = unsafe { sys::AParcel_readStrongBinder(self.as_native(), &mut binder) };

        status_result(status)?;

        // Safety: `binder` is either null or a valid, owned pointer at this
        // point, so can be safely passed to `SpIBinder::from_raw`.
        Ok(unsafe { SpIBinder::from_raw(binder) })
    }
}

impl Drop for Parcel {
    fn drop(&mut self) {
        // Run the C++ Parcel complete object destructor
        //
        // Safety: `Parcel` always contains a valid pointer to an
        // `AParcel`. Since we own the parcel, we can safely delete it
        // here.
        unsafe { sys::AParcel_delete(self.ptr.as_ptr()) }
    }
}

impl fmt::Debug for Parcel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parcel").finish()
    }
}

impl fmt::Debug for BorrowedParcel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedParcel").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write() {
        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        assert_eq!(parcel.read::<bool>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<i8>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<u16>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<i32>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<u32>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<i64>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<u64>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<f32>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<f64>(), Err(StatusCode::NOT_ENOUGH_DATA));
        assert_eq!(parcel.read::<Option<String>>(), Ok(None));
        assert_eq!(parcel.read::<String>(), Err(StatusCode::UNEXPECTED_NULL));

        assert_eq!(parcel.borrowed_ref().read_binder().err(), Some(StatusCode::BAD_TYPE));

        parcel.write(&1i32).unwrap();

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            parcel.set_data_position(start).unwrap();
        }

        let i: i32 = parcel.read().unwrap();
        assert_eq!(i, 1i32);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_read_data() {
        let mut parcel = Parcel::new();
        let str_start = parcel.get_data_position();

        parcel.write(&b"Hello, Binder!\0"[..]).unwrap();
        // Skip over string length
        // SAFETY: str_start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(str_start).is_ok());
        }
        assert_eq!(parcel.read::<i32>().unwrap(), 15);
        let start = parcel.get_data_position();

        assert!(parcel.read::<bool>().unwrap());

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<i8>().unwrap(), 72i8);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u16>().unwrap(), 25928);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<i32>().unwrap(), 1819043144);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 1819043144);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<i64>().unwrap(), 4764857262830019912);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u64>().unwrap(), 4764857262830019912);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<f32>().unwrap(), 1143139100000000000000000000.0);
        assert_eq!(parcel.read::<f32>().unwrap(), 40.043392);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<f64>().unwrap(), 34732488246.197815);

        // Skip back to before the string length
        // SAFETY: str_start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(str_start).is_ok());
        }

        assert_eq!(parcel.read::<Vec<u8>>().unwrap(), b"Hello, Binder!\0");
    }

    #[test]
    fn test_utf8_utf16_conversions() {
        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        assert!(parcel.write("Hello, Binder!").is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert_eq!(parcel.read::<Option<String>>().unwrap().unwrap(), "Hello, Binder!",);
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert!(parcel.write("Embedded null \0 inside a string").is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert_eq!(
            parcel.read::<Option<String>>().unwrap().unwrap(),
            "Embedded null \0 inside a string",
        );
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert!(parcel.write(&["str1", "str2", "str3"][..]).is_ok());
        assert!(parcel
            .write(&[String::from("str4"), String::from("str5"), String::from("str6"),][..])
            .is_ok());

        let s1 = "Hello, Binder!";
        let s2 = "This is a utf8 string.";
        let s3 = "Some more text here.";

        assert!(parcel.write(&[s1, s2, s3][..]).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<Vec<String>>().unwrap(), ["str1", "str2", "str3"]);
        assert_eq!(parcel.read::<Vec<String>>().unwrap(), ["str4", "str5", "str6"]);
        assert_eq!(parcel.read::<Vec<String>>().unwrap(), [s1, s2, s3]);
    }

    #[test]
    fn test_sized_write() {
        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        let arr = [1i32, 2i32, 3i32];

        parcel
            .sized_write(|subparcel| subparcel.write(&arr[..]))
            .expect("Could not perform sized write");

        // i32 sub-parcel length + i32 array length + 3 i32 elements
        let expected_len = 20i32;

        assert_eq!(parcel.get_data_position(), start + expected_len);

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            parcel.set_data_position(start).unwrap();
        }

        assert_eq!(expected_len, parcel.read().unwrap(),);

        assert_eq!(parcel.read::<Vec<i32>>().unwrap(), &arr,);
    }

    #[test]
    fn test_append_from() {
        let mut parcel1 = Parcel::new();
        parcel1.write(&42i32).expect("Could not perform write");

        let mut parcel2 = Parcel::new();
        assert_eq!(Ok(()), parcel2.append_all_from(&parcel1));
        assert_eq!(4, parcel2.get_data_size());
        assert_eq!(Ok(()), parcel2.append_all_from(&parcel1));
        assert_eq!(8, parcel2.get_data_size());
        // SAFETY: 0 is less than the current size of the parcel data buffer, because the parcel is not
        // empty.
        unsafe {
            parcel2.set_data_position(0).unwrap();
        }
        assert_eq!(Ok(42), parcel2.read::<i32>());
        assert_eq!(Ok(42), parcel2.read::<i32>());

        let mut parcel2 = Parcel::new();
        assert_eq!(Ok(()), parcel2.append_from(&parcel1, 0, 2));
        assert_eq!(Ok(()), parcel2.append_from(&parcel1, 2, 2));
        assert_eq!(4, parcel2.get_data_size());
        // SAFETY: 0 is less than the current size of the parcel data buffer, because the parcel is not
        // empty.
        unsafe {
            parcel2.set_data_position(0).unwrap();
        }
        assert_eq!(Ok(42), parcel2.read::<i32>());

        let mut parcel2 = Parcel::new();
        assert_eq!(Ok(()), parcel2.append_from(&parcel1, 0, 2));
        assert_eq!(2, parcel2.get_data_size());
        // SAFETY: 0 is less than the current size of the parcel data buffer, because the parcel is not
        // empty.
        unsafe {
            parcel2.set_data_position(0).unwrap();
        }
        assert_eq!(Err(StatusCode::NOT_ENOUGH_DATA), parcel2.read::<i32>());

        let mut parcel2 = Parcel::new();
        assert_eq!(Err(StatusCode::BAD_VALUE), parcel2.append_from(&parcel1, 4, 2));
        assert_eq!(Err(StatusCode::BAD_VALUE), parcel2.append_from(&parcel1, 2, 4));
        assert_eq!(Err(StatusCode::BAD_VALUE), parcel2.append_from(&parcel1, -1, 4));
        assert_eq!(Err(StatusCode::BAD_VALUE), parcel2.append_from(&parcel1, 2, -1));
    }

    #[test]
    fn test_marshal() {
        let mut parcel1 = Parcel::new();
        parcel1.write(&42i32).unwrap();
        parcel1.write(&52i32).unwrap();
        parcel1.write(&62i32).unwrap();
        parcel1.write(&72i32).unwrap();
        let buffer = parcel1.marshal();

        assert_eq!(16, buffer.len());
        assert_eq!(Vec::from("\x2a\0\0\0\x34\0\0\0\x3e\0\0\0\x48\0\0\0"), buffer);
    }

    #[test]
    fn test_unmarshal() {
        // arrange
        let mut parcel1 = Parcel::new();
        parcel1.write(&42i32).unwrap();
        parcel1.write(&52i32).unwrap();
        parcel1.write(&62i32).unwrap();
        parcel1.write(&72i32).unwrap();

        let buffer = parcel1.marshal();

        // action
        let parcel2 = Parcel::unmarshal(&buffer);
        assert_eq!(16, parcel2.get_data_size());

        // SAFETY: 0 is less than the current size of the parcel data buffer, because the parcel is not
        // empty.
        unsafe {
            parcel2.set_data_position(0).unwrap();
        }
        drop(buffer); // Make sure the new parcel does not depend on this.

        // assert
        assert_eq!(Ok(42i32), parcel2.read::<i32>());
        assert_eq!(Ok(52i32), parcel2.read::<i32>());
        assert_eq!(Ok(62i32), parcel2.read::<i32>());
        assert_eq!(Ok(72i32), parcel2.read::<i32>());
    }
}
