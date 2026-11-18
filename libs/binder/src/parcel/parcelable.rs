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

use crate::binder::{AsNative, FromIBinder, Interface, Stability, Strong};
use crate::error::{status_result, status_t, Result, Status, StatusCode};
use crate::parcel::BorrowedParcel;
use crate::proxy::SpIBinder;
use crate::sys;

use std::ffi::{c_char, c_void};
use std::mem::{self, ManuallyDrop};
use std::ptr;
use std::slice;

/// Super-trait for structured Binder parcelables, i.e. those generated from AIDL.
///
/// This trait is equivalent `android::Parcelable` in C++,
/// and defines a common interface that all parcelables need
/// to implement.
pub trait Parcelable {
    /// Internal serialization function for parcelables.
    ///
    /// This method is mainly for internal use.
    /// `Serialize::serialize` and its variants are generally
    /// preferred over this function, since the former also
    /// prepend a header.
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()>;

    /// Internal deserialization function for parcelables.
    ///
    /// This method is mainly for internal use.
    /// `Deserialize::deserialize` and its variants are generally
    /// preferred over this function, since the former also
    /// parse the additional header.
    fn read_from_parcel(&mut self, parcel: &BorrowedParcel<'_>) -> Result<()>;
}

/// Super-trait for unstructured Binder parcelables, i.e. those implemented manually.
///
/// These differ from structured parcelables in that they may not have a reasonable default value
/// and so aren't required to implement `Default`.
pub trait UnstructuredParcelable: Sized {
    /// Internal serialization function for parcelables.
    ///
    /// This method is mainly for internal use. `Serialize::serialize` and its variants are
    /// generally preferred over calling this function, since the former also prepend a header.
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()>;

    /// Internal deserialization function for parcelables.
    ///
    /// This method is mainly for internal use. `Deserialize::deserialize` and its variants are
    /// generally preferred over calling this function, since the former also parse the additional
    /// header.
    fn from_parcel(parcel: &BorrowedParcel<'_>) -> Result<Self>;

    /// Internal deserialization function for parcelables.
    ///
    /// This method is mainly for internal use. `Deserialize::deserialize_from` and its variants are
    /// generally preferred over calling this function, since the former also parse the additional
    /// header.
    fn read_from_parcel(&mut self, parcel: &BorrowedParcel<'_>) -> Result<()> {
        *self = Self::from_parcel(parcel)?;
        Ok(())
    }
}

/// A struct whose instances can be written to a [`crate::parcel::Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Serialize {
    /// Serialize this instance into the given [`crate::parcel::Parcel`].
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()>;
}

/// A struct whose instances can be restored from a [`crate::parcel::Parcel`].
// Might be able to hook this up as a serde backend in the future?
pub trait Deserialize: Sized {
    /// Type for the uninitialized value of this type. Will be either `Self`
    /// if the type implements `Default`, `Option<Self>` otherwise.
    type UninitType;

    /// Assert at compile-time that `Self` and `Self::UninitType` have the same
    /// size and alignment. This will either fail to compile or evaluate to `true`.
    /// The only two macros that work here are `panic!` and `assert!`, so we cannot
    /// use `assert_eq!`.
    const ASSERT_UNINIT_SIZE_AND_ALIGNMENT: bool = {
        assert!(core::mem::size_of::<Self>() == core::mem::size_of::<Self::UninitType>());
        assert!(core::mem::align_of::<Self>() == core::mem::align_of::<Self::UninitType>());
        true
    };

    /// Return an uninitialized or default-initialized value for this type.
    fn uninit() -> Self::UninitType;

    /// Convert an initialized value of type `Self` into `Self::UninitType`.
    fn from_init(value: Self) -> Self::UninitType;

    /// Deserialize an instance from the given [`crate::parcel::Parcel`].
    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self>;

    /// Deserialize an instance from the given [`crate::parcel::Parcel`] onto the
    /// current object. This operation will overwrite the old value
    /// partially or completely, depending on how much data is available.
    fn deserialize_from(&mut self, parcel: &BorrowedParcel<'_>) -> Result<()> {
        *self = Self::deserialize(parcel)?;
        Ok(())
    }
}

/// Helper trait for types that can be serialized as arrays.
/// Defaults to calling Serialize::serialize() manually for every element,
/// but can be overridden for custom implementations like `writeByteArray`.
// Until specialization is stabilized in Rust, we need this to be a separate
// trait because it's the only way to have a default implementation for a method.
// We want the default implementation for most types, but an override for
// a few special ones like `readByteArray` for `u8`.
pub trait SerializeArray: Serialize + Sized {
    /// Serialize an array of this type into the given parcel.
    fn serialize_array(slice: &[Self], parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // Safety: Safe FFI, slice will always be a safe pointer to pass.
        let res = unsafe {
            sys::AParcel_writeParcelableArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const c_void,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
                Some(serialize_element::<Self>),
            )
        };
        status_result(res)
    }
}

/// Callback to serialize an element of a generic parcelable array.
///
/// # Safety
///
/// We are relying on binder_ndk to not overrun our slice. As long as it
/// doesn't provide an index larger than the length of the original slice in
/// serialize_array, this operation is safe. The index provided is zero-based.
unsafe extern "C" fn serialize_element<T: Serialize>(
    parcel: *mut sys::AParcel,
    array: *const c_void,
    index: usize,
) -> status_t {
    // Safety: The caller guarantees that `array` is a valid pointer of the
    // appropriate type.
    let slice: &[T] = unsafe { slice::from_raw_parts(array.cast(), index + 1) };

    // Safety: The caller must give us a parcel pointer which is either null or
    // valid at least for the duration of this function call. We don't keep the
    // resulting value beyond the function.
    let mut parcel = match unsafe { BorrowedParcel::from_raw(parcel) } {
        None => return StatusCode::UNEXPECTED_NULL as status_t,
        Some(p) => p,
    };

    slice[index].serialize(&mut parcel).err().unwrap_or(StatusCode::OK) as status_t
}

/// Helper trait for types that can be deserialized as arrays.
/// Defaults to calling Deserialize::deserialize() manually for every element,
/// but can be overridden for custom implementations like `readByteArray`.
pub trait DeserializeArray: Deserialize {
    /// Deserialize an array of type from the given parcel.
    fn deserialize_array(parcel: &BorrowedParcel<'_>) -> Result<Option<Vec<Self>>> {
        let mut vec: Option<Vec<Self::UninitType>> = None;
        // Safety: Safe FFI, vec is the correct opaque type expected by
        // allocate_vec and deserialize_element.
        let res = unsafe {
            sys::AParcel_readParcelableArray(
                parcel.as_native(),
                &mut vec as *mut _ as *mut c_void,
                Some(allocate_vec::<Self>),
                Some(deserialize_element::<Self>),
            )
        };
        status_result(res)?;
        // Safety: We are assuming that the NDK correctly initialized every
        // element of the vector by now, so we know that all the
        // UninitTypes are now properly initialized. We can transmute from
        // Vec<T::UninitType> to Vec<T> because T::UninitType has the same
        // alignment and size as T, so the pointer to the vector allocation
        // will be compatible.
        let vec: Option<Vec<Self>> = unsafe { mem::transmute(vec) };
        Ok(vec)
    }
}

/// Callback to deserialize a parcelable element.
///
/// # Safety
///
/// The opaque array data pointer must be a mutable pointer to an
/// `Option<Vec<T::UninitType>>` with at least enough elements for `index` to be valid
/// (zero-based).
unsafe extern "C" fn deserialize_element<T: Deserialize>(
    parcel: *const sys::AParcel,
    array: *mut c_void,
    index: usize,
) -> status_t {
    // Safety: The caller guarantees that `array` is a valid pointer of the
    // appropriate type.
    let vec = unsafe { &mut *(array as *mut Option<Vec<T::UninitType>>) };
    let vec = match vec {
        Some(v) => v,
        None => return StatusCode::BAD_INDEX as status_t,
    };

    // Safety: The caller must give us a parcel pointer which is either null or
    // valid at least for the duration of this function call. We don't keep the
    // resulting value beyond the function.
    let parcel = match unsafe { BorrowedParcel::from_raw(parcel as *mut _) } {
        None => return StatusCode::UNEXPECTED_NULL as status_t,
        Some(p) => p,
    };
    let element = match parcel.read() {
        Ok(e) => e,
        Err(code) => return code as status_t,
    };
    vec[index] = T::from_init(element);
    StatusCode::OK as status_t
}

/// Flag that specifies that the following parcelable is present.
///
/// This is the Rust equivalent of `Parcel::kNonNullParcelableFlag`
/// from `include/binder/Parcel.h` in C++.
pub const NON_NULL_PARCELABLE_FLAG: i32 = 1;

/// Flag that specifies that the following parcelable is absent.
///
/// This is the Rust equivalent of `Parcel::kNullParcelableFlag`
/// from `include/binder/Parcel.h` in C++.
pub const NULL_PARCELABLE_FLAG: i32 = 0;

/// Helper trait for types that can be nullable when serialized.
// We really need this trait instead of implementing `Serialize for Option<T>`
// because of the Rust orphan rule which prevents us from doing
// `impl Serialize for Option<&dyn IFoo>` for AIDL interfaces.
// Instead we emit `impl SerializeOption for dyn IFoo` which is allowed.
// We also use it to provide a default implementation for AIDL-generated
// parcelables.
pub trait SerializeOption: Serialize {
    /// Serialize an Option of this type into the given parcel.
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        if let Some(inner) = this {
            parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
            parcel.write(inner)
        } else {
            parcel.write(&NULL_PARCELABLE_FLAG)
        }
    }
}

/// Helper trait for types that can be nullable when deserialized.
pub trait DeserializeOption: Deserialize {
    /// Deserialize an Option of this type from the given parcel.
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        let null: i32 = parcel.read()?;
        if null == NULL_PARCELABLE_FLAG {
            Ok(None)
        } else {
            parcel.read().map(Some)
        }
    }

    /// Deserialize an Option of this type from the given parcel onto the
    /// current object. This operation will overwrite the current value
    /// partially or completely, depending on how much data is available.
    fn deserialize_option_from(this: &mut Option<Self>, parcel: &BorrowedParcel<'_>) -> Result<()> {
        *this = Self::deserialize_option(parcel)?;
        Ok(())
    }
}

/// Callback to allocate a vector for parcel array read functions.
///
/// This variant is for APIs which use an out buffer pointer.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<T::UninitType>>`. `buffer` will be assigned a mutable pointer
/// to the allocated vector data if this function returns true. `buffer` must be a valid pointer.
unsafe extern "C" fn allocate_vec_with_buffer<T: Deserialize>(
    data: *mut c_void,
    len: i32,
    buffer: *mut *mut T,
) -> bool {
    // Safety: We have the same safety requirements as `allocate_vec` for `data`.
    let res = unsafe { allocate_vec::<T>(data, len) };
    // Safety: The caller guarantees that `data` is a valid mutable pointer to the appropriate type.
    let vec = unsafe { &mut *(data as *mut Option<Vec<T::UninitType>>) };
    if let Some(new_vec) = vec {
        // Safety: The caller guarantees that `buffer` is a valid pointer.
        unsafe {
            *buffer = new_vec.as_mut_ptr() as *mut T;
        }
    }
    res
}

/// Callback to allocate a vector for parcel array read functions.
///
/// # Safety
///
/// The opaque data pointer passed to the array read function must be a mutable
/// pointer to an `Option<Vec<T::UninitType>>`.
unsafe extern "C" fn allocate_vec<T: Deserialize>(data: *mut c_void, len: i32) -> bool {
    // Safety: The caller guarantees that `data` is a valid mutable pointer to the appropriate type.
    let vec = unsafe { &mut *(data as *mut Option<Vec<T::UninitType>>) };
    if len < 0 {
        *vec = None;
        return true;
    }

    // Assert at compile time that `T` and `T::UninitType` have the same size and alignment.
    let _ = T::ASSERT_UNINIT_SIZE_AND_ALIGNMENT;
    let mut new_vec: Vec<T::UninitType> = Vec::with_capacity(len as usize);
    new_vec.resize_with(len as usize, T::uninit);

    // Safety: The caller guarantees that vec is a valid mutable pointer to the appropriate type.
    unsafe {
        ptr::write(vec, Some(new_vec));
    }
    true
}

macro_rules! parcelable_primitives {
    {
        $(
            impl $trait:ident for $ty:ty = $fn:path;
        )*
    } => {
        $(impl_parcelable!{$trait, $ty, $fn})*
    };
}

/// Safety: All elements in the vector must be properly initialized.
unsafe fn vec_assume_init<T: Deserialize>(vec: Vec<T::UninitType>) -> Vec<T> {
    // Assert at compile time that `T` and `T::UninitType` have the same size and alignment.
    let _ = T::ASSERT_UNINIT_SIZE_AND_ALIGNMENT;

    let mut vec = ManuallyDrop::new(vec);
    // Safety: We can convert from Vec<T::UninitType> to Vec<T> because
    // T::UninitType has the same alignment and size as T, so the pointer to the
    // vector allocation will be compatible.
    unsafe { Vec::from_raw_parts(vec.as_mut_ptr().cast(), vec.len(), vec.capacity()) }
}

macro_rules! impl_parcelable {
    {Serialize, $ty:ty, $write_fn:path} => {
        impl Serialize for $ty {
            fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`, and any `$ty` literal value is safe to pass to
                // `$write_fn`.
                unsafe {
                    status_result($write_fn(parcel.as_native_mut(), *self))
                }
            }
        }
    };

    {Deserialize, $ty:ty, $read_fn:path} => {
        impl Deserialize for $ty {
            type UninitType = Self;
            fn uninit() -> Self::UninitType { Self::UninitType::default() }
            fn from_init(value: Self) -> Self::UninitType { value }
            fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
                let mut val = Self::default();
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. We pass a valid, mutable pointer to `val`, a
                // literal of type `$ty`, and `$read_fn` will write the
                // value read into `val` if successful
                unsafe {
                    status_result($read_fn(parcel.as_native(), &mut val))?
                };
                Ok(val)
            }
        }
    };

    {SerializeArray, $ty:ty, $write_array_fn:path} => {
        impl SerializeArray for $ty {
            fn serialize_array(slice: &[Self], parcel: &mut BorrowedParcel<'_>) -> Result<()> {
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. If the slice is > 0 length, `slice.as_ptr()`
                // will be a valid pointer to an array of elements of type
                // `$ty`. If the slice length is 0, `slice.as_ptr()` may be
                // dangling, but this is safe since the pointer is not
                // dereferenced if the length parameter is 0.
                let status = unsafe {
                    $write_array_fn(
                        parcel.as_native_mut(),
                        slice.as_ptr(),
                        slice
                            .len()
                            .try_into()
                            .or(Err(StatusCode::BAD_VALUE))?,
                    )
                };
                status_result(status)
            }
        }
    };

    {DeserializeArray, $ty:ty, $read_array_fn:path} => {
        impl DeserializeArray for $ty {
            fn deserialize_array(parcel: &BorrowedParcel<'_>) -> Result<Option<Vec<Self>>> {
                let mut vec: Option<Vec<Self::UninitType>> = None;
                // Safety: `Parcel` always contains a valid pointer to an
                // `AParcel`. `allocate_vec<T>` expects the opaque pointer to
                // be of type `*mut Option<Vec<T::UninitType>>`, so `&mut vec` is
                // correct for it.
                let status = unsafe {
                    $read_array_fn(
                        parcel.as_native(),
                        &mut vec as *mut _ as *mut c_void,
                        Some(allocate_vec_with_buffer),
                    )
                };
                status_result(status)?;
                // Safety: We are assuming that the NDK correctly
                // initialized every element of the vector by now, so we
                // know that all the UninitTypes are now properly
                // initialized.
                let vec: Option<Vec<Self>> = unsafe {
                    vec.map(|vec| vec_assume_init(vec))
                };
                Ok(vec)
            }
        }
    };
}

impl<T: DeserializeOption> DeserializeArray for Option<T> {}
impl<T: SerializeOption> SerializeArray for Option<T> {}

parcelable_primitives! {
    impl Serialize for bool = sys::AParcel_writeBool;
    impl Deserialize for bool = sys::AParcel_readBool;

    // This is only safe because `Option<Vec<u8>>` is interchangeable with
    // `Option<Vec<i8>>` (what the allocator function actually allocates.
    impl DeserializeArray for u8 = sys::AParcel_readByteArray;

    impl Serialize for i8 = sys::AParcel_writeByte;
    impl Deserialize for i8 = sys::AParcel_readByte;
    impl SerializeArray for i8 = sys::AParcel_writeByteArray;
    impl DeserializeArray for i8 = sys::AParcel_readByteArray;

    impl Serialize for u16 = sys::AParcel_writeChar;
    impl Deserialize for u16 = sys::AParcel_readChar;
    impl SerializeArray for u16 = sys::AParcel_writeCharArray;
    impl DeserializeArray for u16 = sys::AParcel_readCharArray;

    // This is only safe because `Option<Vec<i16>>` is interchangeable with
    // `Option<Vec<u16>>` (what the allocator function actually allocates.
    impl DeserializeArray for i16 = sys::AParcel_readCharArray;

    impl Serialize for u32 = sys::AParcel_writeUint32;
    impl Deserialize for u32 = sys::AParcel_readUint32;
    impl SerializeArray for u32 = sys::AParcel_writeUint32Array;
    impl DeserializeArray for u32 = sys::AParcel_readUint32Array;

    impl Serialize for i32 = sys::AParcel_writeInt32;
    impl Deserialize for i32 = sys::AParcel_readInt32;
    impl SerializeArray for i32 = sys::AParcel_writeInt32Array;
    impl DeserializeArray for i32 = sys::AParcel_readInt32Array;

    impl Serialize for u64 = sys::AParcel_writeUint64;
    impl Deserialize for u64 = sys::AParcel_readUint64;
    impl SerializeArray for u64 = sys::AParcel_writeUint64Array;
    impl DeserializeArray for u64 = sys::AParcel_readUint64Array;

    impl Serialize for i64 = sys::AParcel_writeInt64;
    impl Deserialize for i64 = sys::AParcel_readInt64;
    impl SerializeArray for i64 = sys::AParcel_writeInt64Array;
    impl DeserializeArray for i64 = sys::AParcel_readInt64Array;

    impl Serialize for f32 = sys::AParcel_writeFloat;
    impl Deserialize for f32 = sys::AParcel_readFloat;
    impl SerializeArray for f32 = sys::AParcel_writeFloatArray;
    impl DeserializeArray for f32 = sys::AParcel_readFloatArray;

    impl Serialize for f64 = sys::AParcel_writeDouble;
    impl Deserialize for f64 = sys::AParcel_readDouble;
    impl SerializeArray for f64 = sys::AParcel_writeDoubleArray;
    impl DeserializeArray for f64 = sys::AParcel_readDoubleArray;
}

impl SerializeArray for bool {}
impl DeserializeArray for bool {}

impl Serialize for u8 {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        (*self as i8).serialize(parcel)
    }
}

impl Deserialize for u8 {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        i8::deserialize(parcel).map(|v| v as u8)
    }
}

impl SerializeArray for u8 {
    fn serialize_array(slice: &[Self], parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // Safety: `Parcel` always contains a valid pointer to an
        // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
        // valid pointer to an array of elements of type `$ty`. If the slice
        // length is 0, `slice.as_ptr()` may be dangling, but this is safe
        // since the pointer is not dereferenced if the length parameter is
        // 0.
        let status = unsafe {
            sys::AParcel_writeByteArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const i8,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl Serialize for i16 {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        (*self as u16).serialize(parcel)
    }
}

impl Deserialize for i16 {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        u16::deserialize(parcel).map(|v| v as i16)
    }
}

impl SerializeArray for i16 {
    fn serialize_array(slice: &[Self], parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // Safety: `Parcel` always contains a valid pointer to an
        // `AParcel`. If the slice is > 0 length, `slice.as_ptr()` will be a
        // valid pointer to an array of elements of type `$ty`. If the slice
        // length is 0, `slice.as_ptr()` may be dangling, but this is safe
        // since the pointer is not dereferenced if the length parameter is
        // 0.
        let status = unsafe {
            sys::AParcel_writeCharArray(
                parcel.as_native_mut(),
                slice.as_ptr() as *const u16,
                slice.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
            )
        };
        status_result(status)
    }
}

impl SerializeOption for str {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        match this {
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. If the string pointer is null,
            // `AParcel_writeString` requires that the length is -1 to
            // indicate that we want to serialize a null string.
            None => unsafe {
                status_result(sys::AParcel_writeString(parcel.as_native_mut(), ptr::null(), -1))
            },
            // Safety: `Parcel` always contains a valid pointer to an
            // `AParcel`. `AParcel_writeString` assumes that we pass a utf-8
            // string pointer of `length` bytes, which is what str in Rust
            // is. The docstring for `AParcel_writeString` says that the
            // string input should be null-terminated, but it doesn't
            // actually rely on that fact in the code. If this ever becomes
            // necessary, we will need to null-terminate the str buffer
            // before sending it.
            Some(s) => unsafe {
                status_result(sys::AParcel_writeString(
                    parcel.as_native_mut(),
                    s.as_ptr() as *const c_char,
                    s.len().try_into().or(Err(StatusCode::BAD_VALUE))?,
                ))
            },
        }
    }
}

impl Serialize for str {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Some(self).serialize(parcel)
    }
}

impl SerializeArray for &str {}

impl Serialize for String {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Some(self.as_str()).serialize(parcel)
    }
}

impl SerializeArray for String {}

impl SerializeOption for String {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.map(String::as_str), parcel)
    }
}

impl Deserialize for Option<String> {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        let mut vec: Option<Vec<u8>> = None;
        // Safety: `Parcel` always contains a valid pointer to an `AParcel`.
        // `Option<Vec<u8>>` is equivalent to the expected `Option<Vec<i8>>`
        // for `allocate_vec`, so `vec` is safe to pass as the opaque data
        // pointer on platforms where char is signed.
        let status = unsafe {
            sys::AParcel_readString(
                parcel.as_native(),
                &mut vec as *mut _ as *mut c_void,
                Some(allocate_vec_with_buffer),
            )
        };

        status_result(status)?;
        vec.map(|mut s| {
            // The vector includes a null-terminator and we don't want the
            // string to be null-terminated for Rust.
            s.pop();
            String::from_utf8(s).or(Err(StatusCode::BAD_VALUE))
        })
        .transpose()
    }
}

impl DeserializeArray for Option<String> {}

impl Deserialize for String {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        Deserialize::deserialize(parcel).transpose().unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl DeserializeArray for String {}

impl<T: SerializeArray> Serialize for [T] {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeArray::serialize_array(self, parcel)
    }
}

impl<T: SerializeArray> Serialize for Vec<T> {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeArray::serialize_array(&self[..], parcel)
    }
}

impl<T: SerializeArray> SerializeOption for [T] {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        if let Some(v) = this {
            SerializeArray::serialize_array(v, parcel)
        } else {
            parcel.write(&-1i32)
        }
    }
}

impl<T: SerializeArray> SerializeOption for Vec<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.map(Vec::as_slice), parcel)
    }
}

impl<T: DeserializeArray> Deserialize for Vec<T> {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        DeserializeArray::deserialize_array(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))
    }
}

impl<T: DeserializeArray> DeserializeOption for Vec<T> {
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        DeserializeArray::deserialize_array(parcel)
    }
}

impl<T: SerializeArray, const N: usize> Serialize for [T; N] {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // forwards to T::serialize_array.
        SerializeArray::serialize_array(self, parcel)
    }
}

impl<T: SerializeArray, const N: usize> SerializeOption for [T; N] {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.map(|arr| &arr[..]), parcel)
    }
}

impl<T: SerializeArray, const N: usize> SerializeArray for [T; N] {}

impl<T: DeserializeArray, const N: usize> Deserialize for [T; N] {
    type UninitType = [T::UninitType; N];
    fn uninit() -> Self::UninitType {
        [(); N].map(|_| T::uninit())
    }
    fn from_init(value: Self) -> Self::UninitType {
        value.map(T::from_init)
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        let vec = DeserializeArray::deserialize_array(parcel)
            .transpose()
            .unwrap_or(Err(StatusCode::UNEXPECTED_NULL))?;
        vec.try_into().or(Err(StatusCode::BAD_VALUE))
    }
}

impl<T: DeserializeArray, const N: usize> DeserializeOption for [T; N] {
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        let vec = DeserializeArray::deserialize_array(parcel)?;
        vec.map(|v| v.try_into().or(Err(StatusCode::BAD_VALUE))).transpose()
    }
}

impl<T: DeserializeArray, const N: usize> DeserializeArray for [T; N] {}

impl Serialize for Stability {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        i32::from(*self).serialize(parcel)
    }
}

impl Deserialize for Stability {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        i32::deserialize(parcel).and_then(Stability::try_from)
    }
}

impl Serialize for Status {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        // Safety: `Parcel` always contains a valid pointer to an `AParcel`
        // and `Status` always contains a valid pointer to an `AStatus`, so
        // both parameters are valid and safe. This call does not take
        // ownership of either of its parameters.
        unsafe {
            status_result(sys::AParcel_writeStatusHeader(parcel.as_native_mut(), self.as_native()))
        }
    }
}

impl Deserialize for Status {
    type UninitType = Option<Self>;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        Some(value)
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        let mut status_ptr = ptr::null_mut();
        let ret_status =
        // Safety: `Parcel` always contains a valid pointer to an
        // `AParcel`. We pass a mutable out pointer which will be
        // assigned a valid `AStatus` pointer if the function returns
        // status OK. This function passes ownership of the status
        // pointer to the caller, if it was assigned.
            unsafe { sys::AParcel_readStatusHeader(parcel.as_native(), &mut status_ptr) };
        status_result(ret_status)?;
        // Safety: At this point, the return status of the read call was ok,
        // so we know that `status_ptr` is a valid, owned pointer to an
        // `AStatus`, from which we can safely construct a `Status` object.
        Ok(unsafe { Status::from_ptr(status_ptr) })
    }
}

impl<T: Serialize + FromIBinder + ?Sized> Serialize for Strong<T> {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Serialize::serialize(&**self, parcel)
    }
}

impl<T: SerializeOption + FromIBinder + ?Sized> SerializeOption for Strong<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.map(|b| &**b), parcel)
    }
}

impl<T: Serialize + FromIBinder + ?Sized> SerializeArray for Strong<T> {}

impl<T: FromIBinder + ?Sized> Deserialize for Strong<T> {
    type UninitType = Option<Strong<T>>;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        Some(value)
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        let ibinder: SpIBinder = parcel.read()?;
        FromIBinder::try_from(ibinder)
    }
}

#[allow(dead_code)]
struct AssertIBinder;
impl Interface for AssertIBinder {}
impl FromIBinder for AssertIBinder {
    // This is only needed so we can assert on the size of Strong<AssertIBinder>
    fn try_from(_: SpIBinder) -> Result<Strong<Self>> {
        unimplemented!()
    }
}

impl<T: FromIBinder + ?Sized> DeserializeOption for Strong<T> {
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        let ibinder: Option<SpIBinder> = parcel.read()?;
        ibinder.map(FromIBinder::try_from).transpose()
    }
}

impl<T: FromIBinder + ?Sized> DeserializeArray for Strong<T> {}

// We need these to support Option<&T> for all T
impl<T: Serialize + ?Sized> Serialize for &T {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Serialize::serialize(*self, parcel)
    }
}

impl<T: SerializeOption + ?Sized> SerializeOption for &T {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.copied(), parcel)
    }
}

impl<T: SerializeOption> Serialize for Option<T> {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(self.as_ref(), parcel)
    }
}

impl<T: DeserializeOption> Deserialize for Option<T> {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        DeserializeOption::deserialize_option(parcel)
    }

    fn deserialize_from(&mut self, parcel: &BorrowedParcel<'_>) -> Result<()> {
        DeserializeOption::deserialize_option_from(self, parcel)
    }
}

/// Implement `Serialize` trait and friends for a parcelable
///
/// This is an internal macro used by the AIDL compiler to implement
/// `Serialize`, `SerializeArray` and `SerializeOption` for
/// structured parcelables. The target type must implement the
/// `Parcelable` trait.
#[macro_export]
macro_rules! impl_serialize_for_parcelable {
    ($parcelable:ident) => {
        $crate::impl_serialize_for_parcelable!($parcelable < >);
    };
    ($parcelable:ident < $( $param:ident ),* , >) => {
        $crate::impl_serialize_for_parcelable!($parcelable < $($param),* >);
    };
    ($parcelable:ident < $( $param:ident ),* > ) => {
        impl < $($param),* > $crate::binder_impl::Serialize for $parcelable < $($param),* > {
            fn serialize(
                &self,
                parcel: &mut $crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                <Self as $crate::binder_impl::SerializeOption>::serialize_option(Some(self), parcel)
            }
        }

        impl < $($param),* > $crate::binder_impl::SerializeArray for $parcelable < $($param),* > {}

        impl < $($param),* > $crate::binder_impl::SerializeOption for $parcelable < $($param),* > {
            fn serialize_option(
                this: Option<&Self>,
                parcel: &mut $crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                if let Some(this) = this {
                    use $crate::Parcelable;
                    parcel.write(&$crate::binder_impl::NON_NULL_PARCELABLE_FLAG)?;
                    this.write_to_parcel(parcel)
                } else {
                    parcel.write(&$crate::binder_impl::NULL_PARCELABLE_FLAG)
                }
            }
        }
    };
}

/// Implement `Deserialize` trait and friends for a parcelable
///
/// This is an internal macro used by the AIDL compiler to implement
/// `Deserialize`, `DeserializeArray` and `DeserializeOption` for
/// structured parcelables. The target type must implement the
/// `Parcelable` trait.
#[macro_export]
macro_rules! impl_deserialize_for_parcelable {
    ($parcelable:ident) => {
        $crate::impl_deserialize_for_parcelable!($parcelable < >);
    };
    ($parcelable:ident < $( $param:ident ),* , >) => {
        $crate::impl_deserialize_for_parcelable!($parcelable < $($param),* >);
    };
    ($parcelable:ident < $( $param:ident ),* > ) => {
        impl < $($param: Default),* > $crate::binder_impl::Deserialize for $parcelable < $($param),* > {
            type UninitType = Self;
            fn uninit() -> Self::UninitType { Self::UninitType::default() }
            fn from_init(value: Self) -> Self::UninitType { value }
            fn deserialize(
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<Self, $crate::StatusCode> {
                $crate::binder_impl::DeserializeOption::deserialize_option(parcel)
                    .transpose()
                    .unwrap_or(core::result::Result::Err($crate::StatusCode::UNEXPECTED_NULL))
            }
            fn deserialize_from(
                &mut self,
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                let status: i32 = parcel.read()?;
                if status == $crate::binder_impl::NULL_PARCELABLE_FLAG {
                    core::result::Result::Err($crate::StatusCode::UNEXPECTED_NULL)
                } else {
                    use $crate::Parcelable;
                    self.read_from_parcel(parcel)
                }
            }
        }

        impl < $($param: Default),* > $crate::binder_impl::DeserializeArray for $parcelable < $($param),* > {}

        impl < $($param: Default),* > $crate::binder_impl::DeserializeOption for $parcelable < $($param),* > {
            fn deserialize_option(
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<Option<Self>, $crate::StatusCode> {
                let mut result = None;
                Self::deserialize_option_from(&mut result, parcel)?;
                core::result::Result::Ok(result)
            }
            fn deserialize_option_from(
                this: &mut Option<Self>,
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                let status: i32 = parcel.read()?;
                if status == $crate::binder_impl::NULL_PARCELABLE_FLAG {
                    *this = None;
                    core::result::Result::Ok(())
                } else {
                    use $crate::Parcelable;
                    this.get_or_insert_with(Self::default).read_from_parcel(parcel)
                }
            }
        }
    };
}

/// Implements `Serialize` trait and friends for an unstructured parcelable.
///
/// The target type must implement the `UnstructuredParcelable` trait.
#[macro_export]
macro_rules! impl_serialize_for_unstructured_parcelable {
    ($parcelable:ident) => {
        $crate::impl_serialize_for_unstructured_parcelable!($parcelable < >);
    };
    ($parcelable:ident < $( $param:ident ),* , >) => {
        $crate::impl_serialize_for_unstructured_parcelable!($parcelable < $($param),* >);
    };
    ($parcelable:ident < $( $param:ident ),* > ) => {
        impl < $($param),* > $crate::binder_impl::Serialize for $parcelable < $($param),* > {
            fn serialize(
                &self,
                parcel: &mut $crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                <Self as $crate::binder_impl::SerializeOption>::serialize_option(core::option::Option::Some(self), parcel)
            }
        }

        impl < $($param),* > $crate::binder_impl::SerializeArray for $parcelable < $($param),* > {}

        impl < $($param),* > $crate::binder_impl::SerializeOption for $parcelable < $($param),* > {
            fn serialize_option(
                this: core::option::Option<&Self>,
                parcel: &mut $crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                if let core::option::Option::Some(this) = this {
                    use $crate::binder_impl::UnstructuredParcelable;
                    parcel.write(&$crate::binder_impl::NON_NULL_PARCELABLE_FLAG)?;
                    this.write_to_parcel(parcel)
                } else {
                    parcel.write(&$crate::binder_impl::NULL_PARCELABLE_FLAG)
                }
            }
        }
    };
}

/// Implement `Deserialize` trait and friends for an unstructured parcelable
///
/// The target type must implement the `UnstructuredParcelable` trait.
#[macro_export]
macro_rules! impl_deserialize_for_unstructured_parcelable {
    ($parcelable:ident) => {
        $crate::impl_deserialize_for_unstructured_parcelable!($parcelable < >);
    };
    ($parcelable:ident < $( $param:ident ),* , >) => {
        $crate::impl_deserialize_for_unstructured_parcelable!($parcelable < $($param),* >);
    };
    ($parcelable:ident < $( $param:ident ),* > ) => {
        impl < $($param: Default),* > $crate::binder_impl::Deserialize for $parcelable < $($param),* > {
            type UninitType = Option<Self>;
            fn uninit() -> Self::UninitType { None }
            fn from_init(value: Self) -> Self::UninitType { Some(value) }
            fn deserialize(
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<Self, $crate::StatusCode> {
                $crate::binder_impl::DeserializeOption::deserialize_option(parcel)
                    .transpose()
                    .unwrap_or(Err($crate::StatusCode::UNEXPECTED_NULL))
            }
            fn deserialize_from(
                &mut self,
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                let status: i32 = parcel.read()?;
                if status == $crate::binder_impl::NULL_PARCELABLE_FLAG {
                    Err($crate::StatusCode::UNEXPECTED_NULL)
                } else {
                    use $crate::binder_impl::UnstructuredParcelable;
                    self.read_from_parcel(parcel)
                }
            }
        }

        impl < $($param: Default),* > $crate::binder_impl::DeserializeArray for $parcelable < $($param),* > {}

        impl < $($param: Default),* > $crate::binder_impl::DeserializeOption for $parcelable < $($param),* > {
            fn deserialize_option(
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<Option<Self>, $crate::StatusCode> {
                let present: i32 = parcel.read()?;
                match present {
                    $crate::binder_impl::NULL_PARCELABLE_FLAG => Ok(None),
                    $crate::binder_impl::NON_NULL_PARCELABLE_FLAG => {
                        use $crate::binder_impl::UnstructuredParcelable;
                        Ok(Some(Self::from_parcel(parcel)?))
                    }
                    _ => Err(StatusCode::BAD_VALUE),
                }
            }
            fn deserialize_option_from(
                this: &mut Option<Self>,
                parcel: &$crate::binder_impl::BorrowedParcel<'_>,
            ) -> core::result::Result<(), $crate::StatusCode> {
                let present: i32 = parcel.read()?;
                match present {
                    $crate::binder_impl::NULL_PARCELABLE_FLAG => {
                        *this = None;
                        Ok(())
                    }
                    $crate::binder_impl::NON_NULL_PARCELABLE_FLAG => {
                        use $crate::binder_impl::UnstructuredParcelable;
                        if let Some(this) = this {
                            this.read_from_parcel(parcel)?;
                        } else {
                            *this = Some(Self::from_parcel(parcel)?);
                        }
                        Ok(())
                    }
                    _ => Err(StatusCode::BAD_VALUE),
                }
            }
        }
    };
}

impl<T: Serialize> Serialize for Box<T> {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        Serialize::serialize(&**self, parcel)
    }
}

impl<T: Deserialize> Deserialize for Box<T> {
    type UninitType = Option<Self>;
    fn uninit() -> Self::UninitType {
        Self::UninitType::default()
    }
    fn from_init(value: Self) -> Self::UninitType {
        Some(value)
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
        Deserialize::deserialize(parcel).map(Box::new)
    }
}

impl<T: SerializeOption> SerializeOption for Box<T> {
    fn serialize_option(this: Option<&Self>, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
        SerializeOption::serialize_option(this.map(|inner| &**inner), parcel)
    }
}

impl<T: DeserializeOption> DeserializeOption for Box<T> {
    fn deserialize_option(parcel: &BorrowedParcel<'_>) -> Result<Option<Self>> {
        DeserializeOption::deserialize_option(parcel).map(|t| t.map(Box::new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parcel::Parcel;

    #[test]
    fn test_custom_parcelable() {
        #[derive(Default)]
        struct Custom(u32, bool, String, Vec<String>);

        impl Serialize for Custom {
            fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<()> {
                self.0.serialize(parcel)?;
                self.1.serialize(parcel)?;
                self.2.serialize(parcel)?;
                self.3.serialize(parcel)
            }
        }

        impl Deserialize for Custom {
            type UninitType = Self;
            fn uninit() -> Self::UninitType {
                Self::UninitType::default()
            }
            fn from_init(value: Self) -> Self::UninitType {
                value
            }

            fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self> {
                Ok(Custom(
                    parcel.read()?,
                    parcel.read()?,
                    parcel.read()?,
                    parcel.read::<Option<Vec<String>>>()?.unwrap(),
                ))
            }
        }

        let string8 = "Custom Parcelable".to_string();

        let s1 = "str1".to_string();
        let s2 = "str2".to_string();
        let s3 = "str3".to_string();

        let strs = vec![s1, s2, s3];

        let custom = Custom(123_456_789, true, string8, strs);

        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        assert!(custom.serialize(&mut parcel.borrowed()).is_ok());

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let custom2 = Custom::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(custom2.0, 123_456_789);
        assert!(custom2.1);
        assert_eq!(custom2.2, custom.2);
        assert_eq!(custom2.3, custom.3);
    }

    #[test]
    #[allow(clippy::excessive_precision)]
    fn test_slice_parcelables() {
        let bools = [true, false, false, true];

        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        assert!(bools.serialize(&mut parcel.borrowed()).is_ok());

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4);
        assert_eq!(parcel.read::<u32>().unwrap(), 1);
        assert_eq!(parcel.read::<u32>().unwrap(), 0);
        assert_eq!(parcel.read::<u32>().unwrap(), 0);
        assert_eq!(parcel.read::<u32>().unwrap(), 1);
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<bool>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [true, false, false, true]);

        let u8s = [101u8, 255, 42, 117];

        let mut parcel = Parcel::new();
        let start = parcel.get_data_position();

        assert!(parcel.write(&u8s[..]).is_ok());

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0x752aff65); // bytes

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<u8>::deserialize(parcel.borrowed_ref()).unwrap();
        assert_eq!(vec, [101, 255, 42, 117]);

        let i8s = [-128i8, 127, 42, -117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert!(parcel.write(&i8s[..]).is_ok());

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0x8b2a7f80); // bytes

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<u8>::deserialize(parcel.borrowed_ref()).unwrap();
        assert_eq!(vec, [-128i8 as u8, 127, 42, -117i8 as u8]);

        let u16s = [u16::MAX, 12_345, 42, 117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(u16s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0xffff); // u16::MAX
        assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
        assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
        assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<u16>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [u16::MAX, 12_345, 42, 117]);

        let i16s = [i16::MAX, i16::MIN, 42, -117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(i16s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0x7fff); // i16::MAX
        assert_eq!(parcel.read::<u32>().unwrap(), 0x8000); // i16::MIN
        assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
        assert_eq!(parcel.read::<u32>().unwrap(), 0xff8b); // -117

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<i16>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [i16::MAX, i16::MIN, 42, -117]);

        let u32s = [u32::MAX, 12_345, 42, 117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(u32s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0xffffffff); // u32::MAX
        assert_eq!(parcel.read::<u32>().unwrap(), 12345); // 12,345
        assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
        assert_eq!(parcel.read::<u32>().unwrap(), 117); // 117

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<u32>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [u32::MAX, 12_345, 42, 117]);

        let i32s = [i32::MAX, i32::MIN, 42, -117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(i32s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        assert_eq!(parcel.read::<u32>().unwrap(), 4); // 4 items
        assert_eq!(parcel.read::<u32>().unwrap(), 0x7fffffff); // i32::MAX
        assert_eq!(parcel.read::<u32>().unwrap(), 0x80000000); // i32::MIN
        assert_eq!(parcel.read::<u32>().unwrap(), 42); // 42
        assert_eq!(parcel.read::<u32>().unwrap(), 0xffffff8b); // -117

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<i32>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [i32::MAX, i32::MIN, 42, -117]);

        let u64s = [u64::MAX, 12_345, 42, 117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(u64s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<u64>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [u64::MAX, 12_345, 42, 117]);

        let i64s = [i64::MAX, i64::MIN, 42, -117];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(i64s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<i64>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, [i64::MAX, i64::MIN, 42, -117]);

        let f32s = [f32::NAN, f32::INFINITY, 1.23456789, f32::EPSILON];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(f32s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<f32>::deserialize(parcel.borrowed_ref()).unwrap();

        // NAN != NAN so we can't use it in the assert_eq:
        assert!(vec[0].is_nan());
        assert_eq!(vec[1..], f32s[1..]);

        let f64s = [f64::NAN, f64::INFINITY, 1.234567890123456789, f64::EPSILON];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(f64s.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<f64>::deserialize(parcel.borrowed_ref()).unwrap();

        // NAN != NAN so we can't use it in the assert_eq:
        assert!(vec[0].is_nan());
        assert_eq!(vec[1..], f64s[1..]);

        let s1 = "Hello, Binder!";
        let s2 = "This is a utf8 string.";
        let s3 = "Some more text here.";
        let s4 = "Embedded nulls \0 \0";

        let strs = [s1, s2, s3, s4];

        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }
        assert!(strs.serialize(&mut parcel.borrowed()).is_ok());
        // SAFETY: start is less than the current size of the parcel data buffer, because we haven't
        // made it any shorter since we got the position.
        unsafe {
            assert!(parcel.set_data_position(start).is_ok());
        }

        let vec = Vec::<String>::deserialize(parcel.borrowed_ref()).unwrap();

        assert_eq!(vec, strs);
    }
}
