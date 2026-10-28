use super::*;
use std::sync::atomic::AtomicUsize;

static HOST_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
static INTERLEAVED_REPLY_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn fail_reply_ioctl(_fd: c_int, _request: c_int, arg: *mut c_void) -> c_int {
    let bwr = &mut *(arg as *mut binder_write_read);
    bwr.write_consumed = 0;
    *libc::__errno() = libc::EIO;
    -1
}

unsafe extern "C" fn retry_host_reply_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    match HOST_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) {
        0 => {
            bwr.write_consumed = 0;
            0
        }
        1 => {
            bwr.write_consumed = size_of::<u32>() + size_of::<binder_transaction_data>();
            *libc::__errno() = libc::EIO;
            -1
        }
        _ => {
            bwr.write_consumed = bwr.write_size;
            0
        }
    }
}

unsafe extern "C" fn partial_eintr_host_write_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    let command_size = size_of::<u32>() + size_of::<binder_transaction_data>();
    if HOST_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
        assert_eq!(bwr.write_consumed, 0);
        bwr.write_consumed = command_size;
        *libc::__errno() = libc::EINTR;
        -1
    } else {
        assert_eq!(bwr.write_consumed, 0);
        assert_eq!(bwr.write_size, command_size);
        bwr.write_consumed = bwr.write_size;
        0
    }
}

unsafe extern "C" fn interleaved_host_reply_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    match INTERLEAVED_REPLY_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) {
        0 => {
            assert!(bwr.write_size > 0);
            assert!(bwr.read_size >= size_of::<u32>() + size_of::<binder_transaction_data>());
            bwr.write_consumed = 0;
            std::ptr::write_unaligned(bwr.read_buffer as *mut u32, BR_TRANSACTION_CMD);
            std::ptr::write_unaligned(
                (bwr.read_buffer as *mut u8).add(size_of::<u32>()) as *mut binder_transaction_data,
                std::mem::zeroed(),
            );
            bwr.read_consumed = size_of::<u32>() + size_of::<binder_transaction_data>();
        }
        1 => {
            bwr.write_consumed = bwr.write_size;
            assert_eq!(
                bwr.read_consumed,
                size_of::<u32>() + size_of::<binder_transaction_data>()
            );
        }
        call => panic!("unexpected interleaved reply ioctl call {call}"),
    }
    0
}

#[test]
fn fatal_zero_progress_host_reply_aborts_its_prepared_frame() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 24;
    let connection = binder_state_key(fd);
    drain_transaction_completions(fd);
    reset_pending_reply_frames_for_test(connection, 2);
    *CAPTURED_REPLY_DATA
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data.ptr.buffer = 0x1111;
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
    let previous = OLD_IOCTL.swap(fail_reply_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);
    PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&connection)));

    tr.data.ptr.buffer = 0x2222;
    write.clear();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    bwr.write_size = write.len();
    bwr.write_consumed = 0;
    bwr.write_buffer = write.as_mut_ptr() as libc::c_ulong;
    OLD_IOCTL.store(capture_reply_ioctl as *mut c_void, Ordering::SeqCst);
    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        0
    );
    assert_eq!(pending_reply_frame_count_for_test(connection), 0);
    PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&connection)));

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_pending_reply_frames_for_test(connection, 0);
    drain_transaction_completions(fd);
    CAPTURED_REPLY_DATA
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn fatal_partial_host_reply_commits_prefix_and_aborts_suffix() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 6;
    let connection = binder_state_key(fd);
    drain_transaction_completions(fd);
    reset_pending_reply_frames_for_test(connection, 3);
    HOST_IOCTL_CALLS.store(0, Ordering::SeqCst);

    let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
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
    let previous = OLD_IOCTL.swap(retry_host_reply_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        0
    );
    assert_eq!(pending_reply_frame_count_for_test(connection), 3);

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        -1
    );
    assert_eq!(pending_reply_frame_count_for_test(connection), 1);
    PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&connection)));

    write.clear();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    bwr.write_buffer = write.as_mut_ptr() as libc::c_ulong;
    bwr.write_size = write.len();
    bwr.write_consumed = 0;

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        0
    );
    assert_eq!(pending_reply_frame_count_for_test(connection), 0);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_pending_reply_frames_for_test(connection, 0);
    drain_transaction_completions(fd);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn zero_progress_host_reply_keeps_its_frame_across_nested_transaction() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 21;
    let connection = binder_state_key(fd);
    drain_transaction_completions(fd);
    reset_pending_reply_frames_for_test(connection, 1);
    INTERLEAVED_REPLY_IOCTL_CALLS.store(0, Ordering::SeqCst);

    let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    let mut read = vec![0u8; size_of::<u32>() + size_of::<binder_transaction_data>()];
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: read.len(),
        read_consumed: 0,
        read_buffer: read.as_mut_ptr() as libc::c_ulong,
    };
    let previous = OLD_IOCTL.swap(
        interleaved_host_reply_ioctl as *mut c_void,
        Ordering::SeqCst,
    );

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        0
    );
    assert_eq!(bwr.write_consumed, 0);
    assert_eq!(
        pending_reply_frame_claims_for_test(connection),
        vec![true, false]
    );

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                &mut bwr as *mut binder_write_read as *mut c_void,
            )
        },
        0
    );
    assert_eq!(bwr.write_consumed, bwr.write_size);
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_pending_reply_frames_for_test(connection, 0);
    drain_transaction_completions(fd);
}

#[test]
fn undelivered_operation_acquire_is_canceled_but_delivered_acquire_is_retained() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = crate::tracker::tests::state_test_guard();
    let fd = 98;
    let connection = binder_state_key(fd);
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let retirement = register_operation_publication_for_test(target);
    bind_operation_publication_connection(retirement, connection);

    let mut effects = PendingReadEffects::new(connection);
    effects
        .operation_acquires
        .push(observe_operation_acquire(fd, target).unwrap());
    drop(effects);
    assert_eq!(
        mark_operation_publication_acquire_pending(target, connection),
        Some(retirement)
    );
    cancel_operation_publication_acquire_pending(retirement);

    let mut effects = PendingReadEffects::new(connection);
    effects
        .operation_acquires
        .push(observe_operation_acquire(fd, target).unwrap());
    effects.commit();
    assert_eq!(
        mark_operation_publication_acquire_pending(target, connection),
        None
    );

    cancel_operation_publication_acquire_pending(retirement);
    finish_local_operation_publication(retirement);
    reset_binder_fd_for_test(fd);
}

#[test]
fn fatal_partial_write_retains_unconsumed_operation_acquire() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = crate::tracker::tests::state_test_guard();
    let fd = 32;
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let retirement = register_operation_publication_for_test(target);
    let connection = binder_state_key(fd);
    bind_operation_publication_connection(retirement, connection);
    assert_eq!(
        mark_operation_publication_acquire_pending(target, connection),
        Some(retirement)
    );

    let mut transaction: binder_transaction_data = unsafe { std::mem::zeroed() };
    transaction.flags = TF_ONE_WAY;
    let transaction_command = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
    let mut write = Vec::new();
    push_unaligned(&mut write, &transaction_command);
    push_unaligned(&mut write, &transaction);
    push_unaligned(&mut write, &BC_ACQUIRE_DONE_CMD);
    push_unaligned(
        &mut write,
        &binder_ptr_cookie {
            ptr: target.ptr,
            cookie: target.cookie,
        },
    );
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    HOST_IOCTL_CALLS.store(1, Ordering::SeqCst);
    let previous = OLD_IOCTL.swap(retry_host_reply_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(
        bwr.write_consumed,
        size_of::<u32>() + size_of::<binder_transaction_data>()
    );
    assert_eq!(
        mark_operation_publication_acquire_pending(target, connection),
        None
    );

    cancel_operation_publication_acquire_pending(retirement);
    finish_local_operation_publication(retirement);
    drain_transaction_completions(fd);
    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn partial_eintr_retry_registers_each_host_transaction_once() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 25;
    drain_transaction_completions(fd);
    HOST_IOCTL_CALLS.store(0, Ordering::SeqCst);

    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.flags = TF_ONE_WAY;
    let command = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
    let mut write = Vec::new();
    push_unaligned(&mut write, &command);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &command);
    push_unaligned(&mut write, &tr);
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    let previous = OLD_IOCTL.swap(
        partial_eintr_host_write_ioctl as *mut c_void,
        Ordering::SeqCst,
    );

    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINTR)
    );
    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        0
    );
    assert_eq!(complete_transaction_submission(fd), Some(()));
    assert_eq!(complete_transaction_submission(fd), Some(()));
    assert_eq!(complete_transaction_submission(fd), None);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    drain_transaction_completions(fd);
    unsafe { *libc::__errno() = 0 };
}
