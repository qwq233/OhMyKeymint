use std::sync::atomic::AtomicUsize;

use super::*;

static COPYBACK_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
static BOUNDARY_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
static BOUNDARY_IOCTL_MODE: AtomicUsize = AtomicUsize::new(0);
static POST_IOCTL_PROTECT_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static POST_IOCTL_PROTECT_LENGTH: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn protect_copyback_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    COPYBACK_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst);
    let bwr = &mut *(arg as *mut binder_write_read);
    bwr.write_consumed = bwr.write_size;
    if bwr.read_consumed < bwr.read_size {
        std::ptr::write_unaligned(
            (bwr.read_buffer as *mut u8).add(bwr.read_consumed) as *mut u32,
            BR_TRANSACTION_COMPLETE_CMD,
        );
        bwr.read_consumed += size_of::<u32>();
    }
    assert_eq!(
        libc::mprotect(
            POST_IOCTL_PROTECT_ADDRESS.load(Ordering::SeqCst) as *mut c_void,
            POST_IOCTL_PROTECT_LENGTH.load(Ordering::SeqCst),
            libc::PROT_NONE,
        ),
        0
    );
    0
}

unsafe extern "C" fn invalid_consumption_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    BOUNDARY_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst);
    let bwr = &mut *(arg as *mut binder_write_read);
    match BOUNDARY_IOCTL_MODE.load(Ordering::SeqCst) {
        0 => bwr.write_consumed = bwr.write_size + 1,
        1 => bwr.read_consumed = bwr.read_size + 1,
        _ => bwr.read_consumed -= 1,
    }
    0
}

unsafe extern "C" fn write_error_resets_accumulated_read_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    assert!(bwr.write_size > 0);
    assert!(bwr.read_consumed > 0);
    bwr.write_consumed = 0;
    bwr.read_consumed = 0;
    *libc::__errno() = libc::EINTR;
    -1
}

#[test]
fn read_buffer_copyback_efault_does_not_replay_ioctl() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 97;
    reset_binder_fd_for_test(fd);
    let connection = binder_state_key(fd);
    let pending_completions = || {
        PENDING_TRANSACTION_COMPLETIONS
            .with(|pending| pending.borrow().get(&connection).map_or(0, VecDeque::len))
    };
    record_transaction_completion(fd, false, false, None);
    assert_eq!(pending_completions(), 1);
    COPYBACK_IOCTL_CALLS.store(0, Ordering::SeqCst);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let read_page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(read_page, libc::MAP_FAILED);
    unsafe { std::ptr::write_bytes(read_page.cast::<u8>(), 0x5a, page_size) };
    let mut bwr = binder_write_read {
        write_size: 0,
        write_consumed: 0,
        write_buffer: 0,
        read_size: size_of::<u32>(),
        read_consumed: 0,
        read_buffer: read_page as libc::c_ulong,
    };
    POST_IOCTL_PROTECT_ADDRESS.store(read_page as usize, Ordering::SeqCst);
    POST_IOCTL_PROTECT_LENGTH.store(page_size, Ordering::SeqCst);
    let previous = OLD_IOCTL.swap(protect_copyback_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
    assert_eq!(bwr.read_consumed, 0);
    assert_eq!(pending_completions(), 1);
    assert_eq!(
        unsafe { libc::mprotect(read_page, page_size, libc::PROT_READ | libc::PROT_WRITE) },
        0
    );
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );
    assert_eq!(COPYBACK_IOCTL_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(bwr.read_consumed, size_of::<u32>());
    assert_eq!(pending_completions(), 0);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(read_page.cast::<u8>(), size_of::<u32>()) },
        &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes()
    );

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    unsafe { libc::munmap(read_page, page_size) };
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn binder_write_read_copyback_efault_does_not_replay_ioctl() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 97;
    reset_binder_fd_for_test(fd);
    COPYBACK_IOCTL_CALLS.store(0, Ordering::SeqCst);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let bwr_page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(bwr_page, libc::MAP_FAILED);
    let bwr_ptr = bwr_page.cast::<binder_write_read>();
    unsafe {
        std::ptr::write(
            bwr_ptr,
            binder_write_read {
                write_size: 0,
                write_consumed: 0,
                write_buffer: 0,
                read_size: 0,
                read_consumed: 0,
                read_buffer: 0,
            },
        )
    };
    POST_IOCTL_PROTECT_ADDRESS.store(bwr_page as usize, Ordering::SeqCst);
    POST_IOCTL_PROTECT_LENGTH.store(page_size, Ordering::SeqCst);
    let previous = OLD_IOCTL.swap(protect_copyback_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(unsafe { new_ioctl(fd, BINDER_WRITE_READ as c_int, bwr_ptr.cast()) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
    assert_eq!(COPYBACK_IOCTL_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        unsafe { libc::mprotect(bwr_page, page_size, libc::PROT_READ | libc::PROT_WRITE) },
        0
    );
    assert_eq!(unsafe { new_ioctl(fd, BINDER_WRITE_READ as c_int, bwr_ptr.cast()) }, 0);
    assert_eq!(COPYBACK_IOCTL_CALLS.load(Ordering::SeqCst), 1);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    unsafe { libc::munmap(bwr_page, page_size) };
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn invalid_driver_consumption_poison_connection_without_replaying_ioctl() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = OLD_IOCTL.swap(invalid_consumption_ioctl as *mut c_void, Ordering::SeqCst);
    let mut write = BR_NOOP_CMD.to_ne_bytes();
    let mut read = [0u8; 2 * size_of::<u32>()];

    let assert_poisoned = |fd, bwr: &mut binder_write_read, mode| {
        reset_binder_fd_for_test(fd);
        BOUNDARY_IOCTL_CALLS.store(0, Ordering::SeqCst);
        BOUNDARY_IOCTL_MODE.store(mode, Ordering::SeqCst);
        for _ in 0..2 {
            assert_eq!(
                unsafe {
                    new_ioctl(
                        fd,
                        BINDER_WRITE_READ as c_int,
                        (bwr as *mut binder_write_read).cast(),
                    )
                },
                -1
            );
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPROTO));
        }
        assert_eq!(BOUNDARY_IOCTL_CALLS.load(Ordering::SeqCst), 1);
        assert!(PENDING_IOCTL_COPYBACKS
            .with(|pending| !pending.borrow().contains_key(&binder_state_key(fd))));
        reset_binder_fd_for_test(fd);
    };

    assert_poisoned(
        99,
        &mut binder_write_read {
            write_size: write.len(),
            write_consumed: 0,
            write_buffer: write.as_mut_ptr() as libc::c_ulong,
            read_size: 0,
            read_consumed: 0,
            read_buffer: 0,
        },
        0,
    );
    assert_poisoned(
        100,
        &mut binder_write_read {
            write_size: 0,
            write_consumed: 0,
            write_buffer: 0,
            read_size: read.len(),
            read_consumed: 0,
            read_buffer: read.as_mut_ptr() as libc::c_ulong,
        },
        1,
    );
    assert_poisoned(
        101,
        &mut binder_write_read {
            write_size: 0,
            write_consumed: 0,
            write_buffer: 0,
            read_size: read.len(),
            read_consumed: size_of::<u32>(),
            read_buffer: read.as_mut_ptr() as libc::c_ulong,
        },
        2,
    );

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn write_error_preserves_kernel_read_consumed_reset() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 26;
    let mut write = [0u8; size_of::<u32>()];
    let mut read = [0x5au8; 2 * size_of::<u32>()];
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: read.len(),
        read_consumed: size_of::<u32>(),
        read_buffer: read.as_mut_ptr() as libc::c_ulong,
    };
    let previous =
        OLD_IOCTL.swap(write_error_resets_accumulated_read_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
    assert_eq!(bwr.read_consumed, 0);
    assert_eq!(read, [0x5a; 2 * size_of::<u32>()]);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}
