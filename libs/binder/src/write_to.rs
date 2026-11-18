//! Trait implemented by all AIDL `@FixedSize` types.

use zerocopy::Immutable;

/// Trait for writing a struct to a byte buffer.
///
/// This will write all of the fields, skipping padding. The byte buffer written to should be
/// treated as a byte buffer rather than an instance of `Self` to avoid e.g. running destructors
/// twice.
pub trait WriteTo: Immutable + Sized {
    /// Write `self` to `target`, skipping padding.
    ///
    /// It is guaranteed that no uninitialized bytes are written to `target`.
    ///
    /// # Safety
    ///
    /// * The pointer must be valid for writing `size_of::<Self>()` bytes.
    /// * The pointer must be aligned to `align_of::<Self>()`.
    unsafe fn write_to(&self, target: *mut Self);

    /// Write `self` to `target` using one or more volatile writes, skipping padding.
    ///
    /// It is guaranteed that no uninitialized bytes are written to `target`.
    ///
    /// # Safety
    ///
    /// * The pointer must be valid for writing `size_of::<Self>()` bytes with volatile.
    /// * The pointer must be aligned to `align_of::<Self>()`.
    unsafe fn write_to_volatile(&self, target: *mut Self);
}

macro_rules! impl_primitive {
    {$ty:ty} => {
        static_assertions::assert_impl_all!($ty: Copy);

        impl $crate::WriteTo for $ty {
            #[inline]
            unsafe fn write_to(&self, target: *mut Self) {
                // SAFETY:
                // * Caller ensures that `target` is valid for writing and sufficiently aligned.
                // * We know that `Self: Copy` and `self` is a shared reference, so the bytes in
                //   `self` are not valid for writing during this call. Since `target` references only
                //   bytes that are valid for writing, this means that `self` and `target` do not overlap.
                unsafe { *target = *self };
            }

            #[inline]
            unsafe fn write_to_volatile(&self, target: *mut Self) {
                // SAFETY: Caller ensures that `target` is valid for writing and sufficiently aligned.
                unsafe { target.write_volatile(*self) };
            }
        }
    }
}
impl_primitive!(bool);
impl_primitive!(i8);
impl_primitive!(u8);
impl_primitive!(i16);
impl_primitive!(u16);
impl_primitive!(i32);
impl_primitive!(u32);
impl_primitive!(i64);
impl_primitive!(u64);
impl_primitive!(f32);
impl_primitive!(f64);

impl<T, const N: usize> WriteTo for [T; N]
where
    T: WriteTo,
{
    #[inline]
    unsafe fn write_to(&self, target: *mut Self) {
        for (i, elem) in self.iter().enumerate() {
            // SAFETY: The source and target arrays are both arrays
            // of identical sizes and types.
            unsafe { elem.write_to(target.cast::<T>().add(i)) };
        }
    }

    #[inline]
    unsafe fn write_to_volatile(&self, target: *mut Self) {
        for (i, elem) in self.iter().enumerate() {
            // SAFETY: The source and target arrays are both arrays
            // of identical sizes and types.
            unsafe { elem.write_to_volatile(target.cast::<T>().add(i)) };
        }
    }
}
