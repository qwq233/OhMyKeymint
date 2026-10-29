use super::*;
use std::sync::atomic::AtomicUsize;

static EFAULT_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn efault_ioctl(_fd: c_int, _request: c_int, _arg: *mut c_void) -> c_int {
    EFAULT_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst);
    *libc::__errno() = libc::EFAULT;
    -1
}

#[test]
fn invalid_binder_write_read_input_returns_efault_without_crashing() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    EFAULT_IOCTL_CALLS.store(0, Ordering::SeqCst);
    let previous = OLD_IOCTL.swap(efault_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe { new_ioctl(91, BINDER_WRITE_READ as c_int, std::ptr::dangling_mut::<c_void>(),) },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));

    let mut bwr = binder_write_read {
        write_size: size_of::<u32>(),
        write_consumed: 0,
        write_buffer: 1,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    assert_eq!(
        unsafe {
            new_ioctl(91, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
    assert_eq!(EFAULT_IOCTL_CALLS.load(Ordering::SeqCst), 1);

    bwr.write_size = 0;
    bwr.write_buffer = 0;
    bwr.read_size = size_of::<u32>();
    bwr.read_buffer = 1;
    assert_eq!(
        unsafe {
            new_ioctl(91, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(EFAULT_IOCTL_CALLS.load(Ordering::SeqCst), 2);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(91);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn unsafe_reply_parcels_and_partial_commands_are_not_claimed() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 93;
    let connection = binder_state_key(fd);
    let previous = OLD_IOCTL.swap(efault_ioctl as *mut c_void, Ordering::SeqCst);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = 1;
    tr.data.ptr.buffer = 1;
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };

    reset_pending_reply_frames_for_test(connection, 1);
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);

    tr.data_size = 0;
    tr.data.ptr.buffer = 0;
    write.clear();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    bwr.write_size = write.len();
    bwr.write_consumed = size_of::<u32>() + 1;
    bwr.write_buffer = write.as_mut_ptr() as libc::c_ulong;
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_pending_reply_frames_for_test(connection, 0);
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}
