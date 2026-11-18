/*
 * Copyright (C) 2025 The Android Open Source Project
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

use crate::{
    binder::AsNative,
    error::{status_result, StatusCode},
    impl_deserialize_for_unstructured_parcelable, impl_serialize_for_unstructured_parcelable,
    parcel::{BorrowedParcel, UnstructuredParcelable},
};
use binder_ndk_sys::{
    APersistableBundle, APersistableBundle_delete, APersistableBundle_dup,
    APersistableBundle_erase, APersistableBundle_getBoolean, APersistableBundle_getBooleanKeys,
    APersistableBundle_getBooleanVector, APersistableBundle_getBooleanVectorKeys,
    APersistableBundle_getDouble, APersistableBundle_getDoubleKeys,
    APersistableBundle_getDoubleVector, APersistableBundle_getDoubleVectorKeys,
    APersistableBundle_getInt, APersistableBundle_getIntKeys, APersistableBundle_getIntVector,
    APersistableBundle_getIntVectorKeys, APersistableBundle_getLong,
    APersistableBundle_getLongKeys, APersistableBundle_getLongVector,
    APersistableBundle_getLongVectorKeys, APersistableBundle_getPersistableBundle,
    APersistableBundle_getPersistableBundleKeys, APersistableBundle_getString,
    APersistableBundle_getStringKeys, APersistableBundle_getStringVector,
    APersistableBundle_getStringVectorKeys, APersistableBundle_isEqual, APersistableBundle_new,
    APersistableBundle_putBoolean, APersistableBundle_putBooleanVector,
    APersistableBundle_putDouble, APersistableBundle_putDoubleVector, APersistableBundle_putInt,
    APersistableBundle_putIntVector, APersistableBundle_putLong, APersistableBundle_putLongVector,
    APersistableBundle_putPersistableBundle, APersistableBundle_putString,
    APersistableBundle_putStringVector, APersistableBundle_readFromParcel, APersistableBundle_size,
    APersistableBundle_writeToParcel, APERSISTABLEBUNDLE_ALLOCATOR_FAILED,
    APERSISTABLEBUNDLE_KEY_NOT_FOUND,
};

use std::ffi::{c_char, c_void, CStr};
use std::ffi::{CString, NulError};
use std::mem::size_of;
use std::ptr::{null_mut, slice_from_raw_parts_mut, NonNull};
use zerocopy::FromZeros;

/// A mapping from string keys to values of various types.
#[derive(Debug)]
pub struct PersistableBundle(NonNull<APersistableBundle>);

impl PersistableBundle {
    /// Creates a new `PersistableBundle`.
    pub fn new() -> Self {
        // SAFETY: APersistableBundle_new doesn't actually have any safety requirements.
        let bundle = unsafe { APersistableBundle_new() };
        Self(NonNull::new(bundle).expect("Allocated APersistableBundle was null"))
    }

    /// Returns the number of mappings in the bundle.
    pub fn size(&self) -> usize {
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`.
        unsafe { APersistableBundle_size(self.0.as_ptr()) }
            .try_into()
            .expect("APersistableBundle_size returned a negative size")
    }

    /// Removes any entry with the given key.
    ///
    /// Returns an error if the given key contains a NUL character, otherwise returns whether there
    /// was any entry to remove.
    pub fn remove(&mut self, key: &str) -> Result<bool, NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call.
        Ok(unsafe { APersistableBundle_erase(self.0.as_ptr(), key.as_ptr()) != 0 })
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_bool(&mut self, key: &str, value: bool) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call.
        unsafe {
            APersistableBundle_putBoolean(self.0.as_ptr(), key.as_ptr(), value);
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_int(&mut self, key: &str, value: i32) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call.
        unsafe {
            APersistableBundle_putInt(self.0.as_ptr(), key.as_ptr(), value);
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_long(&mut self, key: &str, value: i64) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call.
        unsafe {
            APersistableBundle_putLong(self.0.as_ptr(), key.as_ptr(), value);
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_double(&mut self, key: &str, value: f64) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call.
        unsafe {
            APersistableBundle_putDouble(self.0.as_ptr(), key.as_ptr(), value);
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key or value contains a NUL character.
    pub fn insert_string(&mut self, key: &str, value: &str) -> Result<(), NulError> {
        let key = CString::new(key)?;
        let value = CString::new(value)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `CStr::as_ptr` is guaranteed
        // to be valid for the duration of this call.
        unsafe {
            APersistableBundle_putString(self.0.as_ptr(), key.as_ptr(), value.as_ptr());
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_bool_vec(&mut self, key: &str, value: &[bool]) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call, and likewise the pointer returned by
        // `value.as_ptr()` is guaranteed to be valid for at least `value.len()` values for the
        // duration of the call.
        unsafe {
            APersistableBundle_putBooleanVector(
                self.0.as_ptr(),
                key.as_ptr(),
                value.as_ptr(),
                value.len().try_into().unwrap(),
            );
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_int_vec(&mut self, key: &str, value: &[i32]) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call, and likewise the pointer returned by
        // `value.as_ptr()` is guaranteed to be valid for at least `value.len()` values for the
        // duration of the call.
        unsafe {
            APersistableBundle_putIntVector(
                self.0.as_ptr(),
                key.as_ptr(),
                value.as_ptr(),
                value.len().try_into().unwrap(),
            );
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_long_vec(&mut self, key: &str, value: &[i64]) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call, and likewise the pointer returned by
        // `value.as_ptr()` is guaranteed to be valid for at least `value.len()` values for the
        // duration of the call.
        unsafe {
            APersistableBundle_putLongVector(
                self.0.as_ptr(),
                key.as_ptr(),
                value.as_ptr(),
                value.len().try_into().unwrap(),
            );
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_double_vec(&mut self, key: &str, value: &[f64]) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call, and likewise the pointer returned by
        // `value.as_ptr()` is guaranteed to be valid for at least `value.len()` values for the
        // duration of the call.
        unsafe {
            APersistableBundle_putDoubleVector(
                self.0.as_ptr(),
                key.as_ptr(),
                value.as_ptr(),
                value.len().try_into().unwrap(),
            );
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_string_vec<'a, T: ToString + 'a>(
        &mut self,
        key: &str,
        value: impl IntoIterator<Item = &'a T>,
    ) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // We need to collect the new `CString`s into something first so that they live long enough
        // for their pointers to be valid for the `APersistableBundle_putStringVector` call below.
        let c_strings = value
            .into_iter()
            .map(|s| CString::new(s.to_string()))
            .collect::<Result<Vec<_>, NulError>>()?;
        let char_pointers = c_strings.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call, and likewise the pointer returned by
        // `value.as_ptr()` is guaranteed to be valid for at least `value.len()` values for the
        // duration of the call.
        unsafe {
            APersistableBundle_putStringVector(
                self.0.as_ptr(),
                key.as_ptr(),
                char_pointers.as_ptr(),
                char_pointers.len().try_into().unwrap(),
            );
        }
        Ok(())
    }

    /// Inserts a key-value pair into the bundle.
    ///
    /// If the key is already present then its value will be overwritten by the given value.
    ///
    /// Returns an error if the key contains a NUL character.
    pub fn insert_persistable_bundle(
        &mut self,
        key: &str,
        value: &PersistableBundle,
    ) -> Result<(), NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointers are guaranteed to be valid for the
        // lifetime of the `PersistableBundle`s. The pointer returned by `CStr::as_ptr` is
        // guaranteed to be valid for the duration of this call, and
        // `APersistableBundle_putPersistableBundle` does a deep copy so that is all that is
        // required.
        unsafe {
            APersistableBundle_putPersistableBundle(
                self.0.as_ptr(),
                key.as_ptr(),
                value.0.as_ptr(),
            );
        }
        Ok(())
    }

    /// Gets the boolean value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_bool(&self, key: &str) -> Result<Option<bool>, NulError> {
        let key = CString::new(key)?;
        let mut value = false;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call. The value pointer must be valid because it
        // comes from a reference.
        if unsafe { APersistableBundle_getBoolean(self.0.as_ptr(), key.as_ptr(), &mut value) } {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Gets the i32 value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_int(&self, key: &str) -> Result<Option<i32>, NulError> {
        let key = CString::new(key)?;
        let mut value = 0;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call. The value pointer must be valid because it
        // comes from a reference.
        if unsafe { APersistableBundle_getInt(self.0.as_ptr(), key.as_ptr(), &mut value) } {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Gets the i64 value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_long(&self, key: &str) -> Result<Option<i64>, NulError> {
        let key = CString::new(key)?;
        let mut value = 0;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call. The value pointer must be valid because it
        // comes from a reference.
        if unsafe { APersistableBundle_getLong(self.0.as_ptr(), key.as_ptr(), &mut value) } {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Gets the f64 value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_double(&self, key: &str) -> Result<Option<f64>, NulError> {
        let key = CString::new(key)?;
        let mut value = 0.0;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the duration of this call. The value pointer must be valid because it
        // comes from a reference.
        if unsafe { APersistableBundle_getDouble(self.0.as_ptr(), key.as_ptr(), &mut value) } {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Gets the string value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_string(&self, key: &str) -> Result<Option<String>, NulError> {
        let key = CString::new(key)?;
        let mut value = null_mut();
        let mut allocated_size: usize = 0;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the lifetime of `key`. The value pointer must be valid because it comes
        // from a reference.
        let value_size_bytes = unsafe {
            APersistableBundle_getString(
                self.0.as_ptr(),
                key.as_ptr(),
                &mut value,
                Some(string_allocator),
                (&raw mut allocated_size).cast(),
            )
        };
        match value_size_bytes {
            APERSISTABLEBUNDLE_KEY_NOT_FOUND => Ok(None),
            APERSISTABLEBUNDLE_ALLOCATOR_FAILED => {
                panic!("APersistableBundle_getString failed to allocate string");
            }
            _ => {
                let raw_slice = slice_from_raw_parts_mut(value.cast(), allocated_size);
                // SAFETY: The pointer was returned from string_allocator, which used
                // `Box::into_raw`, and we've got the appropriate size back from allocated_size.
                let boxed_slice: Box<[u8]> = unsafe { Box::from_raw(raw_slice) };
                assert_eq!(
                    allocated_size,
                    usize::try_from(value_size_bytes)
                        .expect("APersistableBundle_getString returned negative value size")
                        + 1
                );
                let c_string = CString::from_vec_with_nul(boxed_slice.into())
                    .expect("APersistableBundle_getString returned string missing NUL byte");
                let string = c_string
                    .into_string()
                    .expect("APersistableBundle_getString returned invalid UTF-8");
                Ok(Some(string))
            }
        }
    }

    /// Gets the vector of `T` associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    ///
    /// `get_func` should be one of the `APersistableBundle_get*Vector` functions from
    /// `binder_ndk_sys`.
    ///
    /// # Safety
    ///
    /// `get_func` must only require that the pointers it takes are valid for the duration of the
    /// call. It must allow a null pointer for the buffer, and must return the size in bytes of
    /// buffer it requires. If it is given a non-null buffer pointer it must write that number of
    /// bytes to the buffer, which must be a whole number of valid `T` values.
    unsafe fn get_vec<T: Clone>(
        &self,
        key: &str,
        default: T,
        get_func: unsafe extern "C" fn(
            *const APersistableBundle,
            *const c_char,
            *mut T,
            i32,
        ) -> i32,
    ) -> Result<Option<Vec<T>>, NulError> {
        let key = CString::new(key)?;
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the lifetime of `key`. A null pointer is allowed for the buffer.
        match unsafe { get_func(self.0.as_ptr(), key.as_ptr(), null_mut(), 0) } {
            APERSISTABLEBUNDLE_KEY_NOT_FOUND => Ok(None),
            APERSISTABLEBUNDLE_ALLOCATOR_FAILED => {
                panic!("APersistableBundle_getStringVector failed to allocate string");
            }
            required_buffer_size => {
                let mut value = vec![
                    default;
                    usize::try_from(required_buffer_size).expect(
                        "APersistableBundle_get*Vector returned invalid size"
                    ) / size_of::<T>()
                ];
                // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for
                // the lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()`
                // is guaranteed to be valid for the lifetime of `key`. The value buffer pointer is
                // valid as it comes from the Vec we just allocated.
                match unsafe {
                    get_func(
                        self.0.as_ptr(),
                        key.as_ptr(),
                        value.as_mut_ptr(),
                        (value.len() * size_of::<T>()).try_into().unwrap(),
                    )
                } {
                    APERSISTABLEBUNDLE_KEY_NOT_FOUND => {
                        panic!("APersistableBundle_get*Vector failed to find key after first finding it");
                    }
                    APERSISTABLEBUNDLE_ALLOCATOR_FAILED => {
                        panic!("APersistableBundle_getStringVector failed to allocate string");
                    }
                    _ => Ok(Some(value)),
                }
            }
        }
    }

    /// Gets the boolean vector value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_bool_vec(&self, key: &str) -> Result<Option<Vec<bool>>, NulError> {
        // SAFETY: APersistableBundle_getBooleanVector fulfils all the safety requirements of
        // `get_vec`.
        unsafe { self.get_vec(key, Default::default(), APersistableBundle_getBooleanVector) }
    }

    /// Gets the i32 vector value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_int_vec(&self, key: &str) -> Result<Option<Vec<i32>>, NulError> {
        // SAFETY: APersistableBundle_getIntVector fulfils all the safety requirements of
        // `get_vec`.
        unsafe { self.get_vec(key, Default::default(), APersistableBundle_getIntVector) }
    }

    /// Gets the i64 vector value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_long_vec(&self, key: &str) -> Result<Option<Vec<i64>>, NulError> {
        // SAFETY: APersistableBundle_getLongVector fulfils all the safety requirements of
        // `get_vec`.
        unsafe { self.get_vec(key, Default::default(), APersistableBundle_getLongVector) }
    }

    /// Gets the f64 vector value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_double_vec(&self, key: &str) -> Result<Option<Vec<f64>>, NulError> {
        // SAFETY: APersistableBundle_getDoubleVector fulfils all the safety requirements of
        // `get_vec`.
        unsafe { self.get_vec(key, Default::default(), APersistableBundle_getDoubleVector) }
    }

    /// Gets the string vector value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_string_vec(&self, key: &str) -> Result<Option<Vec<String>>, NulError> {
        if let Some(value) =
            // SAFETY: `get_string_vector_with_allocator` fulfils all the safety requirements of
            // `get_vec`.
            unsafe { self.get_vec(key, null_mut(), get_string_vector_with_allocator) }?
        {
            Ok(Some(
                value
                    .into_iter()
                    .map(|s| {
                        // SAFETY: The pointer was returned from `string_allocator`, which used
                        // `Box::into_raw`, and `APersistableBundle_getStringVector` should have
                        // written valid bytes to it including a NUL terminator in the last
                        // position.
                        let string_length = unsafe { CStr::from_ptr(s) }.count_bytes();
                        let raw_slice = slice_from_raw_parts_mut(s.cast(), string_length + 1);
                        // SAFETY: The pointer was returned from `string_allocator`, which used
                        // `Box::into_raw`, and we've got the appropriate size back by checking the
                        // length of the string.
                        let boxed_slice: Box<[u8]> = unsafe { Box::from_raw(raw_slice) };
                        let c_string = CString::from_vec_with_nul(boxed_slice.into()).expect(
                            "APersistableBundle_getStringVector returned string missing NUL byte",
                        );
                        c_string
                            .into_string()
                            .expect("APersistableBundle_getStringVector returned invalid UTF-8")
                    })
                    .collect(),
            ))
        } else {
            Ok(None)
        }
    }

    /// Gets the `PersistableBundle` value associated with the given key.
    ///
    /// Returns an error if the key contains a NUL character, or `Ok(None)` if the key doesn't exist
    /// in the bundle.
    pub fn get_persistable_bundle(&self, key: &str) -> Result<Option<Self>, NulError> {
        let key = CString::new(key)?;
        let mut value = null_mut();
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. The pointer returned by `key.as_ptr()` is guaranteed
        // to be valid for the lifetime of `key`. The value pointer must be valid because it comes
        // from a reference.
        if unsafe {
            APersistableBundle_getPersistableBundle(self.0.as_ptr(), key.as_ptr(), &mut value)
        } {
            Ok(Some(Self(NonNull::new(value).expect(
                "APersistableBundle_getPersistableBundle returned true but didn't set outBundle",
            ))))
        } else {
            Ok(None)
        }
    }

    /// Calls the appropriate `APersistableBundle_get*Keys` function for the given `value_type`,
    /// with our `string_allocator` and a null context pointer.
    ///
    /// # Safety
    ///
    /// `out_keys` must either be null or point to a buffer of at least `buffer_size_bytes` bytes,
    /// properly aligned for `T`, and not otherwise accessed for the duration of the call.
    unsafe fn get_keys_raw(
        &self,
        value_type: ValueType,
        out_keys: *mut *mut c_char,
        buffer_size_bytes: i32,
    ) -> i32 {
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. Our caller guarantees an appropriate value for
        // `out_keys` and `buffer_size_bytes`.
        unsafe {
            match value_type {
                ValueType::Boolean => APersistableBundle_getBooleanKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::Integer => APersistableBundle_getIntKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::Long => APersistableBundle_getLongKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::Double => APersistableBundle_getDoubleKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::String => APersistableBundle_getStringKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::BooleanVector => APersistableBundle_getBooleanVectorKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::IntegerVector => APersistableBundle_getIntVectorKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::LongVector => APersistableBundle_getLongVectorKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::DoubleVector => APersistableBundle_getDoubleVectorKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::StringVector => APersistableBundle_getStringVectorKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
                ValueType::PersistableBundle => APersistableBundle_getPersistableBundleKeys(
                    self.0.as_ptr(),
                    out_keys,
                    buffer_size_bytes,
                    Some(string_allocator),
                    null_mut(),
                ),
            }
        }
    }

    /// Gets all the keys associated with values of the given type.
    pub fn keys_for_type(&self, value_type: ValueType) -> Vec<String> {
        // SAFETY: A null pointer is allowed for the buffer.
        match unsafe { self.get_keys_raw(value_type, null_mut(), 0) } {
            APERSISTABLEBUNDLE_ALLOCATOR_FAILED => {
                panic!("APersistableBundle_get*Keys failed to allocate string");
            }
            required_buffer_size => {
                let required_buffer_size_usize = usize::try_from(required_buffer_size)
                    .expect("APersistableBundle_get*Keys returned invalid size");
                assert_eq!(required_buffer_size_usize % size_of::<*mut c_char>(), 0);
                let mut keys =
                    vec![null_mut(); required_buffer_size_usize / size_of::<*mut c_char>()];
                // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for
                // the lifetime of the `PersistableBundle`. The keys buffer pointer is valid as it
                // comes from the Vec we just allocated.
                if unsafe { self.get_keys_raw(value_type, keys.as_mut_ptr(), required_buffer_size) }
                    == APERSISTABLEBUNDLE_ALLOCATOR_FAILED
                {
                    panic!("APersistableBundle_get*Keys failed to allocate string");
                }
                keys.into_iter()
                    .map(|key| {
                        // SAFETY: The pointer was returned from `string_allocator`, which used
                        // `Box::into_raw`, and `APersistableBundle_getStringVector` should have
                        // written valid bytes to it including a NUL terminator in the last
                        // position.
                        let string_length = unsafe { CStr::from_ptr(key) }.count_bytes();
                        let raw_slice = slice_from_raw_parts_mut(key.cast(), string_length + 1);
                        // SAFETY: The pointer was returned from `string_allocator`, which used
                        // `Box::into_raw`, and we've got the appropriate size back by checking the
                        // length of the string.
                        let boxed_slice: Box<[u8]> = unsafe { Box::from_raw(raw_slice) };
                        let c_string = CString::from_vec_with_nul(boxed_slice.into())
                            .expect("APersistableBundle_get*Keys returned string missing NUL byte");
                        c_string
                            .into_string()
                            .expect("APersistableBundle_get*Keys returned invalid UTF-8")
                    })
                    .collect()
            }
        }
    }

    /// Returns an iterator over all keys in the bundle, along with the type of their associated
    /// value.
    pub fn keys(&self) -> impl Iterator<Item = (String, ValueType)> + use<'_> {
        [
            ValueType::Boolean,
            ValueType::Integer,
            ValueType::Long,
            ValueType::Double,
            ValueType::String,
            ValueType::BooleanVector,
            ValueType::IntegerVector,
            ValueType::LongVector,
            ValueType::DoubleVector,
            ValueType::StringVector,
            ValueType::PersistableBundle,
        ]
        .iter()
        .flat_map(|value_type| {
            self.keys_for_type(*value_type).into_iter().map(|key| (key, *value_type))
        })
    }
}

/// Wrapper around `APersistableBundle_getStringVector` to pass `string_allocator` and a null
/// context pointer.
///
/// # Safety
///
/// * `bundle` must point to a valid `APersistableBundle` which is not modified for the duration of
///   the call.
/// * `key` must point to a valid NUL-terminated C string.
/// * `buffer` must either be null or point to a buffer of at least `buffer_size_bytes` bytes,
///   properly aligned for `T`, and not otherwise accessed for the duration of the call.
unsafe extern "C" fn get_string_vector_with_allocator(
    bundle: *const APersistableBundle,
    key: *const c_char,
    buffer: *mut *mut c_char,
    buffer_size_bytes: i32,
) -> i32 {
    // SAFETY: The safety requirements are all guaranteed by our caller according to the safety
    // documentation above.
    unsafe {
        APersistableBundle_getStringVector(
            bundle,
            key,
            buffer,
            buffer_size_bytes,
            Some(string_allocator),
            null_mut(),
        )
    }
}

// SAFETY: The underlying *APersistableBundle can be moved between threads.
unsafe impl Send for PersistableBundle {}

// SAFETY: The underlying *APersistableBundle can be read from multiple threads, and we require
// `&mut PersistableBundle` for any operations which mutate it.
unsafe impl Sync for PersistableBundle {}

impl Default for PersistableBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PersistableBundle {
    fn drop(&mut self) {
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of this `PersistableBundle`.
        unsafe { APersistableBundle_delete(self.0.as_ptr()) };
    }
}

impl Clone for PersistableBundle {
    fn clone(&self) -> Self {
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`.
        let duplicate = unsafe { APersistableBundle_dup(self.0.as_ptr()) };
        Self(NonNull::new(duplicate).expect("Duplicated APersistableBundle was null"))
    }
}

impl PartialEq for PersistableBundle {
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: The wrapped `APersistableBundle` pointers are guaranteed to be valid for the
        // lifetime of the `PersistableBundle`s.
        unsafe { APersistableBundle_isEqual(self.0.as_ptr(), other.0.as_ptr()) }
    }
}

impl UnstructuredParcelable for PersistableBundle {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
        let status =
        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. `parcel.as_native_mut()` always returns a valid
        // parcel pointer.
            unsafe { APersistableBundle_writeToParcel(self.0.as_ptr(), parcel.as_native_mut()) };
        status_result(status)
    }

    fn from_parcel(parcel: &BorrowedParcel) -> Result<Self, StatusCode> {
        let mut bundle = null_mut();

        // SAFETY: The wrapped `APersistableBundle` pointer is guaranteed to be valid for the
        // lifetime of the `PersistableBundle`. `parcel.as_native()` always returns a valid parcel
        // pointer.
        let status = unsafe { APersistableBundle_readFromParcel(parcel.as_native(), &mut bundle) };
        status_result(status)?;

        Ok(Self(NonNull::new(bundle).expect(
            "APersistableBundle_readFromParcel returned success but didn't allocate bundle",
        )))
    }
}

/// Allocates a boxed slice of the given size in bytes, returns a pointer to it and writes its size
/// to `*context`.
///
/// # Safety
///
/// `context` must either be null or point to a `usize` to which we can write.
unsafe extern "C" fn string_allocator(size: i32, context: *mut c_void) -> *mut c_char {
    let Ok(size) = size.try_into() else {
        return null_mut();
    };
    let Ok(boxed_slice) = <[c_char]>::new_box_zeroed_with_elems(size) else {
        return null_mut();
    };
    if !context.is_null() {
        // SAFETY: The caller promised that `context` is either null or points to a `usize` to which
        // we can write, and we just checked that it's not null.
        unsafe {
            *context.cast::<usize>() = size;
        }
    }
    Box::into_raw(boxed_slice).cast()
}

impl_deserialize_for_unstructured_parcelable!(PersistableBundle);
impl_serialize_for_unstructured_parcelable!(PersistableBundle);

/// The types which may be stored as values in a [`PersistableBundle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    /// A `bool`.
    Boolean,
    /// An `i32`.
    Integer,
    /// An `i64`.
    Long,
    /// An `f64`.
    Double,
    /// A string.
    String,
    /// A vector of `bool`s.
    BooleanVector,
    /// A vector of `i32`s.
    IntegerVector,
    /// A vector of `i64`s.
    LongVector,
    /// A vector of `f64`s.
    DoubleVector,
    /// A vector of strings.
    StringVector,
    /// A nested `PersistableBundle`.
    PersistableBundle,
}
