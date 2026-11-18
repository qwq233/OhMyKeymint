/*
 * Copyright (C) 2021 The Android Open Source Project
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

use crate::binder::Stability;
use crate::binder::StabilityType;
use crate::binder_impl::panic_if_poisoned;
use crate::binder_impl::Mutex;
use crate::error::StatusCode;
use crate::parcel::{
    BorrowedParcel, Deserialize, Parcel, Parcelable, Serialize, NON_NULL_PARCELABLE_FLAG,
    NULL_PARCELABLE_FLAG,
};

use downcast_rs::{impl_downcast, DowncastSync};
use std::any::Any;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

/// Metadata that `ParcelableHolder` needs for all parcelables.
///
/// The compiler auto-generates implementations of this trait
/// for AIDL parcelables.
pub trait ParcelableMetadata {
    /// The Binder parcelable descriptor string.
    ///
    /// This string is a unique identifier for a Binder parcelable.
    fn get_descriptor() -> &'static str;

    /// The Binder parcelable stability.
    fn get_stability(&self) -> Stability {
        Stability::Local
    }
}

trait AnyParcelable: DowncastSync + Parcelable + Debug {}
impl_downcast!(sync AnyParcelable);
impl<T> AnyParcelable for T where T: DowncastSync + Parcelable + Debug {}

#[derive(Debug, Clone)]
enum ParcelableHolderData {
    Empty,
    Parcelable { parcelable: Arc<dyn AnyParcelable>, name: String },
    Parcel(Parcel),
}

/// A container that can hold any arbitrary `Parcelable`.
///
/// This type is currently used for AIDL parcelable fields.
///
/// `ParcelableHolder` is currently not thread-safe (neither
/// `Send` nor `Sync`), mainly because it internally contains
/// a `Parcel` which in turn is not thread-safe.
#[derive(Debug)]
pub struct ParcelableHolder<STABILITY: StabilityType> {
    // This is a `Mutex` because of `get_parcelable`
    // which takes `&self` for consistency with C++.
    // We could make `get_parcelable` take a `&mut self`
    // and get rid of the `Mutex` here for a performance
    // improvement, but then callers would require a mutable
    // `ParcelableHolder` even for that getter method.
    data: Mutex<ParcelableHolderData>,

    _stability_phantom: PhantomData<STABILITY>,
}

impl<STABILITY: StabilityType> ParcelableHolder<STABILITY> {
    /// Construct a new `ParcelableHolder` with the given stability.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(ParcelableHolderData::Empty),
            _stability_phantom: Default::default(),
        }
    }

    /// Reset the contents of this `ParcelableHolder`.
    ///
    /// Note that this method does not reset the stability,
    /// only the contents.
    pub fn reset(&mut self) {
        *panic_if_poisoned!(self.data.get_mut()) = ParcelableHolderData::Empty;
        // We could also clear stability here, but C++ doesn't
    }

    /// Set the parcelable contained in this `ParcelableHolder`.
    pub fn set_parcelable<T>(&mut self, p: Arc<T>) -> Result<(), StatusCode>
    where
        T: Any + Parcelable + ParcelableMetadata + Debug + Send + Sync,
    {
        if STABILITY::VALUE > p.get_stability() {
            return Err(StatusCode::BAD_VALUE);
        }

        *panic_if_poisoned!(self.data.get_mut()) =
            ParcelableHolderData::Parcelable { parcelable: p, name: T::get_descriptor().into() };

        Ok(())
    }

    /// Retrieve the parcelable stored in this `ParcelableHolder`.
    ///
    /// This method attempts to retrieve the parcelable inside
    /// the current object as a parcelable of type `T`.
    /// The object is validated against `T` by checking that
    /// its parcelable descriptor matches the one returned
    /// by `T::get_descriptor()`.
    ///
    /// Returns one of the following:
    /// * `Err(_)` in case of error
    /// * `Ok(None)` if the holder is empty or the descriptor does not match
    /// * `Ok(Some(_))` if the object holds a parcelable of type `T`
    ///   with the correct descriptor
    pub fn get_parcelable<T>(&self) -> Result<Option<Arc<T>>, StatusCode>
    where
        T: Any + Parcelable + ParcelableMetadata + Default + Debug + Send + Sync,
    {
        let parcelable_desc = T::get_descriptor();
        let mut data = panic_if_poisoned!(self.data.lock());
        match *data {
            ParcelableHolderData::Empty => Ok(None),
            ParcelableHolderData::Parcelable { ref parcelable, ref name } => {
                if name != parcelable_desc {
                    return Err(StatusCode::BAD_VALUE);
                }

                match Arc::clone(parcelable).downcast_arc::<T>() {
                    Err(_) => Err(StatusCode::BAD_VALUE),
                    Ok(x) => Ok(Some(x)),
                }
            }
            ParcelableHolderData::Parcel(ref mut parcel) => {
                // Safety: 0 should always be a valid position.
                unsafe {
                    parcel.set_data_position(0)?;
                }

                let name: String = parcel.read()?;
                if name != parcelable_desc {
                    return Ok(None);
                }

                let mut parcelable = T::default();
                parcelable.read_from_parcel(parcel.borrowed_ref())?;

                let parcelable = Arc::new(parcelable);
                let result = Arc::clone(&parcelable);
                *data = ParcelableHolderData::Parcelable { parcelable, name };

                Ok(Some(result))
            }
        }
    }

    /// Return the stability value of this object.
    pub fn get_stability(&self) -> Stability {
        STABILITY::VALUE
    }
}

impl<STABILITY: StabilityType> Default for ParcelableHolder<STABILITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<STABILITY: StabilityType> Clone for ParcelableHolder<STABILITY> {
    fn clone(&self) -> Self {
        ParcelableHolder {
            data: Mutex::new(panic_if_poisoned!(self.data.lock()).clone()),
            _stability_phantom: Default::default(),
        }
    }
}

impl<STABILITY: StabilityType> Serialize for ParcelableHolder<STABILITY> {
    fn serialize(&self, parcel: &mut BorrowedParcel<'_>) -> Result<(), StatusCode> {
        parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
        self.write_to_parcel(parcel)
    }
}

impl<STABILITY: StabilityType> Deserialize for ParcelableHolder<STABILITY> {
    type UninitType = Self;
    fn uninit() -> Self::UninitType {
        Self::new()
    }
    fn from_init(value: Self) -> Self::UninitType {
        value
    }

    fn deserialize(parcel: &BorrowedParcel<'_>) -> Result<Self, StatusCode> {
        let status: i32 = parcel.read()?;
        if status == NULL_PARCELABLE_FLAG {
            Err(StatusCode::UNEXPECTED_NULL)
        } else {
            let mut parcelable = Self::new();
            parcelable.read_from_parcel(parcel)?;
            Ok(parcelable)
        }
    }
}

impl<STABILITY: StabilityType> Parcelable for ParcelableHolder<STABILITY> {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<(), StatusCode> {
        parcel.write(&STABILITY::VALUE)?;

        let mut data = panic_if_poisoned!(self.data.lock());
        match *data {
            ParcelableHolderData::Empty => parcel.write(&0i32),
            ParcelableHolderData::Parcelable { ref parcelable, ref name } => {
                let length_start = parcel.get_data_position();
                parcel.write(&0i32)?;

                let data_start = parcel.get_data_position();
                parcel.write(name)?;
                parcelable.write_to_parcel(parcel)?;

                let end = parcel.get_data_position();
                // Safety: we got the position from `get_data_position`.
                unsafe {
                    parcel.set_data_position(length_start)?;
                }

                assert!(end >= data_start);
                parcel.write(&(end - data_start))?;
                // Safety: we got the position from `get_data_position`.
                unsafe {
                    parcel.set_data_position(end)?;
                }

                Ok(())
            }
            ParcelableHolderData::Parcel(ref mut p) => {
                parcel.write(&p.get_data_size())?;
                parcel.append_all_from(&*p)
            }
        }
    }

    fn read_from_parcel(&mut self, parcel: &BorrowedParcel<'_>) -> Result<(), StatusCode> {
        if self.get_stability() != parcel.read()? {
            return Err(StatusCode::BAD_VALUE);
        }

        let data_size: i32 = parcel.read()?;
        if data_size < 0 {
            // C++ returns BAD_VALUE here,
            // while Java returns ILLEGAL_ARGUMENT
            return Err(StatusCode::BAD_VALUE);
        }
        if data_size == 0 {
            *panic_if_poisoned!(self.data.get_mut()) = ParcelableHolderData::Empty;
            return Ok(());
        }

        // TODO: C++ ParcelableHolder accepts sizes up to SIZE_MAX here, but we
        // only go up to i32::MAX because that's what our API uses everywhere
        let data_start = parcel.get_data_position();
        let data_end = data_start.checked_add(data_size).ok_or(StatusCode::BAD_VALUE)?;

        let mut new_parcel = Parcel::new();
        new_parcel.append_from(parcel, data_start, data_size)?;
        *panic_if_poisoned!(self.data.get_mut()) = ParcelableHolderData::Parcel(new_parcel);

        // Safety: `append_from` checks if `data_size` overflows
        // `parcel` and returns `BAD_VALUE` if that happens. We also
        // explicitly check for negative and zero `data_size` above,
        // so `data_end` is guaranteed to be greater than `data_start`.
        unsafe {
            parcel.set_data_position(data_end)?;
        }

        Ok(())
    }
}
