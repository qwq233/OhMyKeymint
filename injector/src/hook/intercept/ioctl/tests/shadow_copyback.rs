use super::*;

unsafe extern "C" fn partial_read_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    assert_eq!(bwr.read_consumed, size_of::<u32>());
    assert!(bwr.read_size >= 3 * size_of::<u32>());
    std::ptr::write_unaligned(
        (bwr.read_buffer as *mut u8).add(bwr.read_consumed) as *mut u32,
        BR_NOOP_CMD,
    );
    bwr.read_consumed += size_of::<u32>();
    0
}

unsafe extern "C" fn prefix_only_read_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    assert!(bwr.read_consumed > 0);
    0
}

#[test]
fn reset_discards_pending_staged_shadow_but_preserves_live_shadow() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let connection = binder_state_key(20);
    clear_inbound_transaction_shadows(connection);
    let original = [1u8, 2, 3, 4];
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = original.len();
    tr.data.ptr.buffer = original.as_ptr() as libc::c_ulong;
    let shadow = unsafe { TransactionPayloadShadow::read(&tr) }
        .expect("readable transaction should create a shadow");
    let live_buffer = retain_inbound_transaction_shadow(connection, shadow);

    assert_eq!(inbound_transaction_original_buffer(connection, live_buffer), None);
    publish_inbound_transaction_shadows(connection, &[live_buffer]);
    assert_eq!(
        inbound_transaction_original_buffer(connection, live_buffer),
        Some(original.as_ptr() as libc::c_ulong)
    );

    let staged = unsafe { TransactionPayloadShadow::read(&tr) }
        .expect("readable transaction should create a shadow");
    let staged_buffer = retain_inbound_transaction_shadow(connection, staged);
    let mut read_effects = PendingReadEffects::new(connection);
    read_effects.staged_inbound_shadows.push(staged_buffer);
    PENDING_IOCTL_COPYBACKS.with(|pending| {
        pending.borrow_mut().insert(
            connection,
            PendingIoctlCopyback {
                arg: 0,
                write_buffer: 0,
                read_buffer: 0,
                write_size: 0,
                read_size: 0,
                read: PendingReadCopyback::None,
                output: unsafe { std::mem::zeroed() },
                read_effects,
                freed_inbound_shadows: Vec::new(),
                ret: 0,
                errno: 0,
            },
        );
    });

    reset_current_thread_binder_state(connection);
    assert_eq!(
        inbound_transaction_original_buffer(connection, live_buffer),
        Some(original.as_ptr() as libc::c_ulong)
    );
    assert!(!INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned")
        .contains_key(&(connection, staged_buffer)));
    clear_inbound_transaction_shadows(connection);
}

#[test]
fn read_shadow_only_copies_newly_consumed_bytes() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 96;
    reset_binder_fd_for_test(fd);
    let mut read = [0x5au8; 3 * size_of::<u32>()];
    let mut bwr = binder_write_read {
        write_size: 0,
        write_consumed: 0,
        write_buffer: 0,
        read_size: read.len(),
        read_consumed: size_of::<u32>(),
        read_buffer: read.as_mut_ptr() as libc::c_ulong,
    };
    let previous = OLD_IOCTL.swap(capture_reply_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );
    assert_eq!(read, [0x5a; 3 * size_of::<u32>()]);

    OLD_IOCTL.store(partial_read_ioctl as *mut c_void, Ordering::SeqCst);
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );
    assert_eq!(bwr.read_consumed, 2 * size_of::<u32>());
    assert_eq!(&read[..size_of::<u32>()], &[0x5a; size_of::<u32>()]);
    assert_eq!(&read[size_of::<u32>()..2 * size_of::<u32>()], &BR_NOOP_CMD.to_ne_bytes());
    assert_eq!(&read[2 * size_of::<u32>()..], &[0x5a; size_of::<u32>()]);

    read[..size_of::<u32>()].fill(0x33);
    OLD_IOCTL.store(prefix_only_read_ioctl as *mut c_void, Ordering::SeqCst);
    assert_eq!(
        unsafe {
            new_ioctl(fd, BINDER_WRITE_READ as c_int, (&mut bwr as *mut binder_write_read).cast())
        },
        0
    );
    assert_eq!(bwr.read_consumed, 2 * size_of::<u32>());
    assert_eq!(&read[..size_of::<u32>()], &[0x33; size_of::<u32>()]);
    assert_eq!(&read[2 * size_of::<u32>()..], &[0x5a; size_of::<u32>()]);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
}
