/// This returns the current time (in milliseconds) as an instance of a monotonic clock,
/// by invoking the system call since Rust does not support getting monotonic time instance
/// as an integer.
pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid because it comes from a reference, and clock_gettime doesn't
    // retain it beyond the call.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    current_time.tv_sec as i64 * 1000 + (current_time.tv_nsec as i64 / 1_000_000)
}

pub trait ParcelExt {
    fn data(&self) -> &[u8];
}

impl ParcelExt for rsbinder::Parcel {
    fn data(&self) -> &[u8] {
        unsafe {
            let data = self.as_ptr();
            let parcel_size = self.data_size();
            std::slice::from_raw_parts(data, parcel_size)
        }
    }
}
