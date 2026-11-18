use super::*;

use crate::hook::rewrite::pending;
#[cfg(test)]
use crate::hook::rewrite::tests as rpc;
#[cfg(not(test))]
use kmr_common::rpc;

/// # Safety
///
/// Called by the installed ioctl hook with the same ABI and pointer validity
/// requirements as libc ioctl. `arg` must be valid for the request being made.
pub(in crate::hook) unsafe extern "C" fn new_ioctl(
    fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    let mut old_ioctl_ptr = OLD_IOCTL.load(Ordering::Relaxed);
    if old_ioctl_ptr.is_null() {
        extern "C" {
            fn ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int;
        }
        old_ioctl_ptr = ioctl as *mut c_void;
    }

    let old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int =
        std::mem::transmute(old_ioctl_ptr);

    if request as u32 != BINDER_WRITE_READ {
        return old_ioctl_fn(fd, request, arg);
    }
    if OBSERVED_BINDER_FD_TOKENS.try_with(|_| ()).is_err()
        || !crate::hook::rewrite::pending::available()
    {
        return old_ioctl_fn(fd, request, arg);
    }

    let Some(binder_ioctl_guard) = BinderIoctlGuard::begin(fd) else {
        forget_current_thread_binder_fd(fd, None);
        return old_ioctl_fn(fd, request, arg);
    };
    let binder_token = binder_ioctl_guard.token;
    synchronize_binder_fd_generation(binder_token);
    cleanup_retired_current_thread_connections();
    let connection = binder_token.connection;
    let original = || old_ioctl_fn(binder_ioctl_guard.fd(), request, arg);
    let Some(mut bwr) = copy_process_value(arg.cast::<binder_write_read>()) else {
        return original();
    };
    let original_write_buffer = bwr.write_buffer;
    let original_read_buffer = bwr.read_buffer;
    let original_write_size = bwr.write_size as usize;
    let original_read_size = bwr.read_size as usize;
    let input_write_consumed = bwr.write_consumed as usize;
    let input_read_consumed = bwr.read_consumed as usize;
    let Some(write_remaining) = original_write_size.checked_sub(input_write_consumed) else {
        return original();
    };
    let Some(read_remaining) = original_read_size.checked_sub(input_read_consumed) else {
        return original();
    };
    if write_remaining > isize::MAX as usize || read_remaining > isize::MAX as usize {
        return original();
    }
    let mut host_write = Vec::new();
    if write_remaining > 0 {
        let Some(write_address) =
            (original_write_buffer as usize).checked_add(input_write_consumed)
        else {
            return original();
        };
        let Some(_) = (original_write_buffer as usize).checked_add(original_write_size) else {
            return original();
        };
        host_write = match copy_process_buffer(write_address, write_remaining) {
            Ok(write) => write,
            Err(_) => return original(),
        };
    }
    if read_remaining > 0 {
        let Some(_) = (original_read_buffer as usize).checked_add(input_read_consumed) else {
            return original();
        };
        let Some(_) = (original_read_buffer as usize).checked_add(original_read_size) else {
            return original();
        };
    }
    if write_process_value(arg.cast::<binder_write_read>(), &bwr).is_err() {
        return original();
    }

    let mut free_buffers = Vec::new();
    if write_remaining > 0 {
        let Some(commands) = parse_write_buffer(&host_write) else {
            return original();
        };
        free_buffers = commands;
        for (end, _) in &mut free_buffers {
            *end += input_write_consumed;
        }
        bwr.write_buffer = host_write.as_ptr() as libc::c_ulong;
    }
    bwr.write_size = write_remaining as u64;
    bwr.write_consumed = 0;

    let ret =
        old_ioctl_fn(binder_ioctl_guard.fd(), request, (&mut bwr as *mut binder_write_read).cast());
    let ioctl_errno = *libc::__errno();
    let ioctl_error = (ret < 0).then_some(ioctl_errno);
    let driver_write_consumed = bwr.write_consumed as usize;
    let driver_read_consumed = bwr.read_consumed as usize;
    let write_consumption_valid = driver_write_consumed <= write_remaining;
    // binder_ioctl_write_read() resets read_consumed when the write phase fails.
    let read_consumption_reset =
        ioctl_error.is_some() && write_remaining > 0 && driver_read_consumed == 0;
    let read_consumption_valid = read_consumption_reset
        || (input_read_consumed..=original_read_size).contains(&driver_read_consumed);
    assert!(
        write_consumption_valid && read_consumption_valid,
        "invalid Binder consumption: fd={fd} connection={connection} \
         write={driver_write_consumed}/{write_remaining} \
         read={input_read_consumed}->{driver_read_consumed}/{original_read_size} \
         ioctl_ret={ret} errno={ioctl_errno}"
    );
    bwr.write_size = original_write_size as u64;
    bwr.read_size = original_read_size as u64;
    bwr.write_consumed = (input_write_consumed + driver_write_consumed) as u64;
    bwr.read_consumed = driver_read_consumed as u64;
    bwr.write_buffer = original_write_buffer;
    bwr.read_buffer = original_read_buffer;

    for &(_, input) in
        free_buffers.iter().take_while(|(end, _)| *end <= bwr.write_consumed as usize)
    {
        pending::commit_free_buffer(connection, input);
    }

    let mut read_effects = PendingReadEffects::new();
    if driver_read_consumed > input_read_consumed {
        let read_len = driver_read_consumed - input_read_consumed;
        let read_address = (original_read_buffer as usize)
            .checked_add(input_read_consumed)
            .expect("read address was validated before ioctl");
        let mut read = copy_process_buffer(read_address, read_len).unwrap_or_else(|error| {
            panic!(
                "failed to read delivered Binder output: fd={fd} connection={connection} \
                 size={read_len} ioctl_ret={ret} errno={ioctl_errno}: {error:#}"
            )
        });
        read_effects = parse_read_buffer(connection, &mut read);
        copy_to_process(read_address, &read).unwrap_or_else(|error| {
            panic!(
                "failed to publish Binder output: fd={fd} connection={connection} \
                 size={read_len} ioctl_ret={ret} errno={ioctl_errno}: {error:#}"
            )
        });
    }
    if ioctl_error == Some(libc::EBADF) {
        let retired = invalidate_binder_fd_token(binder_token);
        forget_current_thread_binder_fd(fd, retired);
    }
    write_process_value(arg.cast::<binder_write_read>(), &bwr).unwrap_or_else(|error| {
        panic!(
            "failed to publish Binder counters: fd={fd} connection={connection} \
             write={} read={} ioctl_ret={ret} errno={ioctl_errno}: {error:#}",
            bwr.write_consumed, bwr.read_consumed
        )
    });
    read_effects.commit();
    *libc::__errno() = ioctl_errno;
    ret
}

pub(in crate::hook::intercept) unsafe fn parse_read_buffer(
    connection: BinderStateKey,
    read: &mut [u8],
) -> PendingReadEffects {
    let base = read.as_mut_ptr();
    let mut offset = 0usize;
    let mut effects = PendingReadEffects::new();
    loop {
        let (cmd, range) = match next_binder_command(read, &mut offset) {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(error) => {
                panic!("invalid delivered Binder command: connection={connection}: {error:#}")
            }
        };
        if _ioc_dir(cmd) != 2 || _ioc_nr(cmd) != BR_TRANSACTION_NR {
            continue;
        }
        if range.len() != size_of::<binder_transaction_data>()
            && range.len() != size_of::<binder_transaction_data_secctx>()
        {
            panic!(
                "unexpected BR_TRANSACTION payload: connection={connection} size={}",
                range.len()
            );
        }
        // SAFETY: Both validated ABI layouts begin with binder_transaction_data.
        let payload = unsafe { base.add(range.start).cast::<binder_transaction_data>() };
        let mut tr = unsafe { std::ptr::read_unaligned(payload) };
        let mut target = LocalBinderTarget { ptr: unsafe { tr.target.ptr }, cookie: tr.cookie };
        let mut pin = None;
        if rpc::may_intercept()
            && !crate::forward::is_bypassed()
            && (binder::binder_impl::FIRST_CALL_TRANSACTION
                ..=binder::binder_impl::LAST_CALL_TRANSACTION)
                .contains(&tr.code)
        {
            // SAFETY: The driver retains the incoming target until this transaction is consumed.
            if let Some((owner, proxy)) =
                unsafe { crate::hook::binder::receiver_proxy(connection, target) }
            {
                target = proxy;
                pin = Some(owner);
            }
        }
        let frame = pending::push_received_frame(
            Some(connection),
            target,
            unsafe { tr.data.ptr.buffer } as usize,
            tr.flags,
            pin,
        );
        if let Some(frame) = frame {
            effects.frames.push(frame);
            tr.target.ptr = target.ptr;
            tr.cookie = target.cookie;
            // SAFETY: Only target/cookie changed; payload size and secctx remain untouched.
            unsafe { std::ptr::write_unaligned(payload, tr) };
        }
    }
    effects
}

unsafe fn parse_write_buffer(write: &[u8]) -> Option<Vec<(usize, usize)>> {
    let mut commands = Vec::new();
    let mut offset = 0;
    loop {
        let (cmd, range) = match next_binder_command(write, &mut offset) {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(_) => return None,
        };
        if _ioc_dir(cmd) != 1 {
            continue;
        }
        let payload = unsafe { write.as_ptr().add(range.start) };
        let nr = _ioc_nr(cmd);
        if cmd == binder::ext::driver::BC_FREE_BUFFER && range.len() == size_of::<libc::c_ulong>() {
            // SAFETY: The checked command payload contains one Binder pointer.
            let input = unsafe { std::ptr::read_unaligned(payload.cast::<libc::c_ulong>()) };
            commands.push((range.end, input as usize));
        } else if matches!(
            nr,
            BC_TRANSACTION_NR | BC_REPLY_NR | BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR
        ) {
            let is_sg = matches!(nr, BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR);
            let expected = if is_sg {
                size_of::<binder_transaction_data_sg>()
            } else {
                size_of::<binder_transaction_data>()
            };
            if range.len() != expected {
                continue;
            }
            // SAFETY: Both validated layouts start with the transaction record.
            let tr = unsafe { std::ptr::read_unaligned(payload.cast::<binder_transaction_data>()) };
            if log::log_enabled!(log::Level::Info) {
                // SAFETY: The validated record is local; logging copies only its bounded preview.
                unsafe {
                    log_write_transaction(
                        if matches!(nr, BC_REPLY_NR | BC_REPLY_SG_NR) {
                            "BC_REPLY"
                        } else {
                            "BC_TRANSACTION"
                        },
                        &tr,
                    );
                }
            }
        }
    }
    Some(commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::intercept::fd::tests::{binder_fd_token_is_current, invalidate_binder_fd};
    use crate::hook::intercept::tests::{
        reset_binder_fd_for_test, BC_FREE_BUFFER_CMD, BC_REPLY_CMD, BR_NOOP_CMD,
        SYNTHETIC_REPLY_TEST_LOCK,
    };
    use crate::hook::rewrite::pending::tests::{
        received_frame_count_for_test, reset_received_frames_for_test,
    };
    use std::sync::atomic::{AtomicI32, AtomicUsize};

    static HOST_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn native_receive_pin_survives_delivery_and_connection_retirement() {
        use crate::hook::rewrite::pending::tests::pin;
        use crate::hook::rewrite::pending::{claim_callback, push_received_frame};
        let target = LocalBinderTarget { ptr: 11, cookie: 12 };
        let connection = 598;
        for flags in [0, TF_ONE_WAY] {
            for delivered in [false, true] {
                reset_received_frames_for_test(connection, 0);
                let drops = Arc::new(AtomicUsize::new(0));
                let frame = push_received_frame(
                    Some(connection),
                    target,
                    0x1234,
                    flags,
                    Some(pin(Arc::clone(&drops))),
                )
                .unwrap();
                let mut effects = PendingReadEffects { frames: vec![frame] };
                if delivered {
                    effects.commit();
                }
                drop(effects);
                reset_current_thread_binder_state(connection);
                assert_eq!(drops.load(Ordering::SeqCst), usize::from(!delivered));
                if delivered {
                    drop(claim_callback(target, 0x1234));
                }
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                reset_received_frames_for_test(connection, 0);
            }
        }
    }

    #[test]
    fn free_buffer_consumption_releases_unclaimed_pins_in_both_native_orders() {
        use crate::hook::rewrite::pending::{mark_delivered, push_received_frame, tests::pin};
        unsafe extern "C" fn original(_: c_int, _: c_int, arg: *mut c_void) -> c_int {
            let bwr = unsafe { &mut *arg.cast::<binder_write_read>() };
            match HOST_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) {
                0 => {}
                1 => {
                    let command = unsafe {
                        std::ptr::read_unaligned((bwr.write_buffer as *const u8).cast::<u32>())
                    };
                    bwr.write_consumed = (size_of::<u32>() + _ioc_size(command)) as u64;
                }
                _ => bwr.write_consumed = bwr.write_size,
            }
            0
        }
        let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap();
        let fd = 109;
        let previous = OLD_IOCTL.swap(original as *mut c_void, Ordering::SeqCst);
        for flags in [0, TF_ONE_WAY] {
            for free_first in [false, true] {
                reset_binder_fd_for_test(fd);
                let connection = binder_state_key(fd);
                let drops = Arc::new(AtomicUsize::new(0));
                let frame = push_received_frame(
                    Some(connection),
                    LocalBinderTarget { ptr: 11, cookie: 12 },
                    0x1234,
                    flags,
                    Some(pin(Arc::clone(&drops))),
                )
                .unwrap();
                mark_delivered(frame);
                let mut write = Vec::new();
                for free in [free_first, !free_first] {
                    if free {
                        push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
                        push_unaligned(&mut write, &0x1234_usize);
                    } else {
                        push_unaligned(&mut write, &BC_REPLY_CMD);
                        push_unaligned(&mut write, &binder_transaction_data::default());
                    }
                }
                let mut bwr = binder_write_read {
                    write_size: write.len() as u64,
                    write_buffer: write.as_ptr() as libc::c_ulong,
                    ..Default::default()
                };
                HOST_IOCTL_CALLS.store(0, Ordering::SeqCst);
                for expected in [0, usize::from(free_first), 1] {
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
                    assert_eq!(drops.load(Ordering::SeqCst), expected);
                    assert_eq!(received_frame_count_for_test(connection), 1 - expected);
                }
                assert_eq!(bwr.write_consumed, bwr.write_size);
                reset_binder_fd_for_test(fd);
            }
        }
        OLD_IOCTL.store(previous, Ordering::SeqCst);
    }

    static WRITE_ERROR: AtomicI32 = AtomicI32::new(libc::EINTR);

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
        *libc::__errno() = WRITE_ERROR.load(Ordering::Relaxed);
        -1
    }

    #[test]
    fn write_error_preserves_kernel_read_consumed_reset() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 26;
        let previous = OLD_IOCTL
            .swap(write_error_resets_accumulated_read_ioctl as *mut c_void, Ordering::SeqCst);
        for error in [libc::EINTR, libc::EFAULT] {
            WRITE_ERROR.store(error, Ordering::Relaxed);
            let mut write = [0u8; size_of::<u32>()];
            let mut read = [0x5au8; 2 * size_of::<u32>()];
            let mut bwr = binder_write_read {
                write_size: write.len() as u64,
                write_consumed: 0,
                write_buffer: write.as_mut_ptr() as libc::c_ulong,
                read_size: read.len() as u64,
                read_consumed: size_of::<u32>() as u64,
                read_buffer: read.as_mut_ptr() as libc::c_ulong,
            };
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
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(error));
            assert_eq!(bwr.read_consumed, 0);
            assert_eq!(read, [0x5a; 2 * size_of::<u32>()]);
            reset_binder_fd_for_test(fd);
        }
        OLD_IOCTL.store(previous, Ordering::SeqCst);
        unsafe { *libc::__errno() = 0 };
    }

    static POST_IOCTL_INVALIDATE_FD: AtomicI32 = AtomicI32::new(-1);

    unsafe extern "C" fn invalidate_after_consuming_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *(arg as *mut binder_write_read);
        bwr.write_consumed = bwr.write_size;
        assert!((bwr.read_size as usize) >= size_of::<u32>());
        std::ptr::write_unaligned(bwr.read_buffer as *mut u32, BR_NOOP_CMD);
        bwr.read_consumed = (size_of::<u32>()) as u64;
        invalidate_binder_fd(POST_IOCTL_INVALIDATE_FD.load(Ordering::SeqCst));
        0
    }

    #[test]
    fn binder_fd_generation_reset_discards_stale_thread_state() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 90;
        reset_binder_fd_for_test(fd);
        reset_current_thread_binder_state(binder_state_key(fd));

        let original = binder_fd_token(fd);
        synchronize_binder_fd_generation(original);
        let connection = original.connection;
        reset_received_frames_for_test(connection, 1);

        invalidate_binder_fd(fd);
        let guard = BinderIoctlGuard::begin(fd).unwrap();
        let replacement = guard.token;
        synchronize_binder_fd_generation(replacement);
        assert_ne!(replacement.connection, original.connection);
        assert!(!binder_fd_token_is_current(original));
        assert!(binder_fd_token_is_current(replacement));
        assert_eq!(received_frame_count_for_test(connection), 0);
        reset_binder_fd_for_test(fd);
    }

    #[test]
    fn duplicated_binder_fds_share_connection_state_until_the_last_close() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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

        reset_received_frames_for_test(original.connection, 1);
        pending::commit_free_buffer(alias.connection, 0);
        assert_eq!(received_frame_count_for_test(original.connection), 0);
        assert_eq!(unsafe { close_with_binder_fd_lifecycle(original_fd, || 0) }, 0);
        assert!(binder_fd_token_is_current(alias));
        assert_eq!(unsafe { close_with_binder_fd_lifecycle(alias_fd, || 0) }, 0);
        assert!(!binder_fd_token_is_current(alias));
        reset_binder_fd_for_test(original_fd);
        reset_binder_fd_for_test(alias_fd);
    }

    #[test]
    fn reused_fd_submits_the_new_connections_first_write() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 88;
        reset_binder_fd_for_test(fd);

        synchronize_binder_fd_generation(binder_fd_token(fd));
        invalidate_binder_fd(fd);
        let mut write = Vec::new();
        push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
        push_unaligned(&mut write, &0usize);
        let mut bwr = binder_write_read {
            write_size: (write.len()) as u64,
            write_consumed: 0,
            write_buffer: write.as_mut_ptr() as libc::c_ulong,
            read_size: 0,
            read_consumed: 0,
            read_buffer: 0,
        };
        let previous = OLD_IOCTL.swap(capture_reply_ioctl as *mut c_void, Ordering::SeqCst);

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
        assert_eq!(bwr.write_consumed, bwr.write_size);

        bwr.write_size = 0;
        bwr.write_consumed = 0;
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

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_binder_fd_for_test(fd);
    }

    #[test]
    fn completed_ioctl_keeps_its_result_after_fd_reuse() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 92;
        reset_binder_fd_for_test(fd);
        POST_IOCTL_INVALIDATE_FD.store(fd, Ordering::SeqCst);

        let mut write = Vec::new();
        push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
        push_unaligned(&mut write, &0usize);
        let mut read = [0u8; size_of::<u32>()];
        let mut bwr = binder_write_read {
            write_size: (write.len()) as u64,
            write_consumed: 0,
            write_buffer: write.as_mut_ptr() as libc::c_ulong,
            read_size: (read.len()) as u64,
            read_consumed: 0,
            read_buffer: read.as_mut_ptr() as libc::c_ulong,
        };
        let previous =
            OLD_IOCTL.swap(invalidate_after_consuming_ioctl as *mut c_void, Ordering::SeqCst);

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
        assert_eq!((bwr.write_consumed as usize), (bwr.write_size as usize));
        assert_eq!((bwr.read_consumed as usize), size_of::<u32>());
        assert_eq!(read, BR_NOOP_CMD.to_ne_bytes());

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_binder_fd_for_test(fd);
    }
    unsafe extern "C" fn partial_read_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *(arg as *mut binder_write_read);
        assert_eq!((bwr.read_consumed as usize), size_of::<u32>());
        assert!((bwr.read_size as usize) >= 3 * size_of::<u32>());
        std::ptr::write_unaligned(
            (bwr.read_buffer as *mut u8).add(bwr.read_consumed as usize) as *mut u32,
            BR_NOOP_CMD,
        );
        bwr.read_consumed += (size_of::<u32>()) as u64;
        0
    }

    unsafe extern "C" fn prefix_only_read_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *(arg as *mut binder_write_read);
        assert!((bwr.read_consumed as usize) > 0);
        0
    }

    #[test]
    fn read_shadow_only_copies_newly_consumed_bytes() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 96;
        reset_binder_fd_for_test(fd);
        let mut read = [0x5au8; 3 * size_of::<u32>()];
        let mut bwr = binder_write_read {
            write_size: 0,
            write_consumed: 0,
            write_buffer: 0,
            read_size: (read.len()) as u64,
            read_consumed: (size_of::<u32>()) as u64,
            read_buffer: read.as_mut_ptr() as libc::c_ulong,
        };
        let previous = OLD_IOCTL.swap(capture_reply_ioctl as *mut c_void, Ordering::SeqCst);

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
        assert_eq!(read, [0x5a; 3 * size_of::<u32>()]);

        OLD_IOCTL.store(partial_read_ioctl as *mut c_void, Ordering::SeqCst);
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
        assert_eq!((bwr.read_consumed as usize), 2 * size_of::<u32>());
        assert_eq!(&read[..size_of::<u32>()], &[0x5a; size_of::<u32>()]);
        assert_eq!(&read[size_of::<u32>()..2 * size_of::<u32>()], &BR_NOOP_CMD.to_ne_bytes());
        assert_eq!(&read[2 * size_of::<u32>()..], &[0x5a; size_of::<u32>()]);

        read[..size_of::<u32>()].fill(0x33);
        OLD_IOCTL.store(prefix_only_read_ioctl as *mut c_void, Ordering::SeqCst);
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
        assert_eq!((bwr.read_consumed as usize), 2 * size_of::<u32>());
        assert_eq!(&read[..size_of::<u32>()], &[0x33; size_of::<u32>()]);
        assert_eq!(&read[2 * size_of::<u32>()..], &[0x5a; size_of::<u32>()]);

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_binder_fd_for_test(fd);
    }

    static CAPTURED_WRITE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    unsafe extern "C" fn capture_write_then_fail(
        _fd: c_int,
        _request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        // SAFETY: The hook supplies its live command buffer; embedded payload pointers are not read.
        let bwr = unsafe { &*arg.cast::<binder_write_read>() };
        let commands = unsafe {
            std::slice::from_raw_parts(bwr.write_buffer as *const u8, bwr.write_size as usize)
        };
        *CAPTURED_WRITE.lock().unwrap() = commands.to_vec();
        unsafe { *libc::__errno() = libc::EFAULT };
        -1
    }

    #[test]
    fn unread_reply_payloads_and_their_native_owners_are_untouched() {
        use binder::binder_impl::Parcel;
        use binder::ext::driver::flat_binder_object;
        use std::os::fd::AsRawFd;

        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 93;
        let connection = binder_state_key(fd);
        let previous = OLD_IOCTL.swap(capture_write_then_fail as *mut c_void, Ordering::SeqCst);
        use crate::hook::rewrite::pending::{push_received_frame, tests::pin};
        let mut binder = pin(Arc::new(AtomicUsize::new(0)));
        let weak = binder.downgrade();
        let file = binder::ParcelFileDescriptor::new(std::fs::File::open("/dev/null").unwrap());
        let mut parcel = Parcel::new();
        parcel.write(&binder).unwrap();
        parcel.write(&file).unwrap();
        let offsets =
            [0_usize, parcel.get_data_position() as usize - size_of::<flat_binder_object>()];
        let view = binder::ext::owned_parcel_view(&parcel).unwrap();
        let status = binder::StatusCode::NOT_ENOUGH_DATA as i32;
        let cases = [
            (
                view.data_ptr() as usize,
                view.bytes.len(),
                offsets.as_ptr() as usize,
                size_of_val(&offsets),
                0,
            ),
            (
                &status as *const i32 as usize,
                size_of::<i32>(),
                0,
                0,
                binder::ext::driver::TF_STATUS_CODE,
            ),
        ];
        for (buffer, size, offset_buffer, offsets_size, flags) in cases {
            for sg in [false, true] {
                reset_received_frames_for_test(connection, 1);
                let drops = Arc::new(AtomicUsize::new(0));
                push_received_frame(
                    Some(connection),
                    LocalBinderTarget { ptr: 11, cookie: 12 },
                    13,
                    0,
                    Some(pin(Arc::clone(&drops))),
                )
                .unwrap();
                // SAFETY: Every field and union in the driver record permits zero.
                let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
                tr.data_size = size as u64;
                tr.data.ptr.buffer = buffer as u64;
                tr.data.ptr.offsets = offset_buffer as u64;
                tr.offsets_size = offsets_size as u64;
                tr.flags = flags;
                let mut write = Vec::new();
                if sg {
                    push_unaligned(&mut write, &binder::ext::driver::BC_REPLY_SG);
                    push_unaligned(
                        &mut write,
                        &binder_transaction_data_sg { transaction_data: tr, buffers_size: 64 },
                    );
                } else {
                    push_unaligned(&mut write, &BC_REPLY_CMD);
                    push_unaligned(&mut write, &tr);
                }
                let mut bwr = binder_write_read {
                    write_size: write.len() as u64,
                    write_buffer: write.as_mut_ptr() as u64,
                    ..Default::default()
                };
                // SAFETY: bwr and the command bytes are live; the mock never reads embedded payloads.
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
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
                assert_eq!(*CAPTURED_WRITE.lock().unwrap(), write);
                assert_eq!(received_frame_count_for_test(connection), 2);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } >= 0);
            }
        }

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_received_frames_for_test(connection, 0);
        reset_binder_fd_for_test(fd);
        drop(parcel);
        drop(binder);
        assert!(weak.promote().is_none());
        unsafe { *libc::__errno() = 0 };
    }

    unsafe extern "C" fn capture_reply_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *arg.cast::<binder_write_read>();
        bwr.write_consumed = bwr.write_size;
        0
    }

    pub(super) fn push_unaligned<T: Copy>(out: &mut Vec<u8>, value: &T) {
        let start = out.len();
        out.resize(start + size_of::<T>(), 0);
        // SAFETY: resize allocated space for T at start, and write_unaligned permits
        // any alignment.
        unsafe {
            std::ptr::write_unaligned(out.as_mut_ptr().add(start) as *mut T, *value);
        }
    }
}
