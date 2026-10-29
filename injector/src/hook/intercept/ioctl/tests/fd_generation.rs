use super::*;
use std::sync::atomic::AtomicI32;

static POST_IOCTL_INVALIDATE_FD: AtomicI32 = AtomicI32::new(-1);

unsafe extern "C" fn invalidate_after_consuming_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    bwr.write_consumed = bwr.write_size;
    assert!(bwr.read_size >= size_of::<u32>());
    std::ptr::write_unaligned(bwr.read_buffer as *mut u32, BR_NOOP_CMD);
    bwr.read_consumed = size_of::<u32>();
    invalidate_binder_fd(POST_IOCTL_INVALIDATE_FD.load(Ordering::SeqCst));
    0
}

#[test]
fn binder_fd_generation_reset_discards_stale_thread_state() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 90;
    reset_binder_fd_for_test(fd);
    drain_transaction_completions(fd);

    let original = synchronize_binder_fd_generation(fd).unwrap();
    let connection = original.connection;
    record_transaction_completion(fd, false, true, None);
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared.borrow_mut().entry(connection).or_default().push_back(PreparedBcReply {
            frame_id: None,
            data_ptr: 0,
            transaction: unsafe { std::mem::zeroed() },
        });
    });
    reset_pending_reply_frames_for_test(connection, 1);

    invalidate_binder_fd(fd);
    assert_eq!(synchronize_binder_fd_generation(fd), Err(original));
    let replacement = synchronize_binder_fd_generation(fd).unwrap();
    assert_ne!(replacement.connection, original.connection);
    assert!(!binder_fd_token_is_current(original));
    assert!(binder_fd_token_is_current(replacement));
    assert!(
        PENDING_TRANSACTION_COMPLETIONS.with(|pending| !pending.borrow().contains_key(&connection))
    );
    assert!(SYNC_TRANSACTIONS.with(|transactions| !transactions.borrow().contains_key(&connection)));
    assert!(PREPARED_BC_REPLIES.with(|prepared| !prepared.borrow().contains_key(&connection)));
    assert_eq!(pending_reply_frame_count_for_test(connection), 0);
    reset_binder_fd_for_test(fd);
}

#[test]
fn duplicated_binder_fds_share_connection_state_until_the_last_close() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let original_fd = 94;
    let alias_fd = 95;
    reset_binder_fd_for_test(original_fd);
    reset_binder_fd_for_test(alias_fd);

    let original = binder_fd_token(original_fd);
    assert_eq!(
        unsafe { duplicate_binder_fd_with_lifecycle(original_fd, None, || alias_fd) },
        alias_fd
    );
    let alias = binder_fd_token(alias_fd);
    assert_eq!(alias.connection, original.connection);
    assert_eq!(alias.generation, original.generation);

    record_transaction_completion(original_fd, false, false, None);
    assert_eq!(complete_transaction_submission(alias_fd), Some(()));
    assert_eq!(unsafe { close_with_binder_fd_lifecycle(original_fd, || 0) }, 0);
    assert!(binder_fd_token_is_current(alias));
    assert_eq!(unsafe { close_with_binder_fd_lifecycle(alias_fd, || 0) }, 0);
    assert!(!binder_fd_token_is_current(alias));
    reset_binder_fd_for_test(original_fd);
    reset_binder_fd_for_test(alias_fd);
}

#[test]
fn reused_fd_never_submits_an_ambiguous_write() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 88;
    reset_binder_fd_for_test(fd);

    synchronize_binder_fd_generation(fd).unwrap();
    invalidate_binder_fd(fd);
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &0usize);
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    let previous = OLD_IOCTL.swap(capture_reply_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    assert_eq!(bwr.write_consumed, 0);

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
}

#[test]
fn completed_ioctl_keeps_its_result_after_fd_reuse() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 92;
    reset_binder_fd_for_test(fd);
    POST_IOCTL_INVALIDATE_FD.store(fd, Ordering::SeqCst);

    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &0usize);
    let mut read = [0u8; size_of::<u32>()];
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: read.len(),
        read_consumed: 0,
        read_buffer: read.as_mut_ptr() as libc::c_ulong,
    };
    let previous =
        OLD_IOCTL.swap(invalidate_after_consuming_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );
    assert_eq!(bwr.write_consumed, bwr.write_size);
    assert_eq!(bwr.read_consumed, size_of::<u32>());
    assert_eq!(read, BR_NOOP_CMD.to_ne_bytes());

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
}
