use super::*;

mod read;
mod write;

#[cfg(test)]
mod test_support;

use read::{
    complete_operation_acquire, complete_operation_publication, record_transaction_completion,
};
#[cfg(test)]
use read::{complete_transaction_submission, observe_operation_acquire};
pub(in crate::hook::intercept) use read::{flush_native_binder_lifecycle, parse_read_buffer};
use write::{
    abort_prepared_bc_replies, complete_prepared_bc_reply, mark_inbound_free_buffers_consumed,
    parse_write_buffer, rewrite_inbound_free_buffers, write_buffer_is_safe_to_intercept,
};
pub(in crate::hook::intercept) use write::{
    abort_prepared_bc_replies_for_connection, complete_inbound_free_buffers,
};

pub(in crate::hook) unsafe fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
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

    let binder_token = match synchronize_binder_fd_generation(fd) {
        Ok(token) => token,
        Err(_) => {
            cleanup_retired_current_thread_connections();
            *libc::__errno() = libc::EBADF;
            return -1;
        }
    };
    cleanup_retired_current_thread_connections();
    let binder_ioctl_guard = match BinderIoctlGuard::begin(binder_token) {
        Ok(guard) => guard,
        Err(error) => {
            forget_current_thread_binder_fd(fd, None);
            *libc::__errno() = error;
            return -1;
        }
    };
    let connection = binder_state_key(fd);
    if let Some(result) = retry_pending_ioctl_copyback(fd, connection, arg) {
        return result;
    }

    let Some(mut bwr) = copy_process_value(arg.cast::<binder_write_read>()) else {
        return old_ioctl_fn(binder_ioctl_guard.fd(), request, arg);
    };
    let fail_before_ioctl = |error| {
        *libc::__errno() = error;
        -1
    };
    let original_write_buffer = bwr.write_buffer;
    let original_read_buffer = bwr.read_buffer;
    let original_write_size = bwr.write_size;
    let original_read_size = bwr.read_size;
    let input_write_consumed = bwr.write_consumed;
    let input_read_consumed = bwr.read_consumed;
    let Some(write_remaining) = original_write_size.checked_sub(input_write_consumed) else {
        return fail_before_ioctl(libc::EINVAL);
    };
    let Some(read_remaining) = original_read_size.checked_sub(input_read_consumed) else {
        return fail_before_ioctl(libc::EINVAL);
    };
    let mut host_write = IoctlScratch::acquire();
    if write_remaining > 0 {
        let Some(write_address) =
            (original_write_buffer as usize).checked_add(input_write_consumed)
        else {
            return fail_before_ioctl(libc::EFAULT);
        };
        let Some(_) = (original_write_buffer as usize).checked_add(original_write_size) else {
            return fail_before_ioctl(libc::EFAULT);
        };
        if let Err(error) = fill_process_buffer(host_write.as_mut(), write_address, write_remaining)
        {
            return fail_before_ioctl(error);
        }
    }
    if read_remaining > 0 {
        let Some(_) = (original_read_buffer as usize).checked_add(input_read_consumed) else {
            return fail_before_ioctl(libc::EFAULT);
        };
        let Some(_) = (original_read_buffer as usize).checked_add(original_read_size) else {
            return fail_before_ioctl(libc::EFAULT);
        };
    }
    if !write_process_value(arg.cast::<binder_write_read>(), &bwr) {
        return fail_before_ioctl(libc::EFAULT);
    }

    flush_native_binder_lifecycle(old_ioctl_fn);

    let mut completion_commands = Vec::new();
    let mut freed_inbound_shadows = Vec::new();
    if write_remaining > 0 {
        freed_inbound_shadows = rewrite_inbound_free_buffers(connection, host_write.as_mut());
        for (end, _) in &mut freed_inbound_shadows {
            *end += input_write_consumed;
        }
        if write_buffer_is_safe_to_intercept(host_write.as_mut()) {
            completion_commands = parse_write_buffer(fd, host_write.as_mut());
            for (end, _, _, _) in &mut completion_commands {
                *end += input_write_consumed;
            }
        } else {
            warn!(
                "event=binder skipped unsafe write command stream fd={} remaining={} consumed={}",
                fd, write_remaining, input_write_consumed
            );
        }
        bwr.write_buffer = host_write.as_mut().as_mut_ptr() as libc::c_ulong;
    }
    bwr.write_size = write_remaining;
    bwr.write_consumed = 0;

    let ret = old_ioctl_fn(
        binder_ioctl_guard.fd(),
        request,
        (&mut bwr as *mut binder_write_read).cast(),
    );
    let ioctl_errno = *libc::__errno();
    let ioctl_error = (ret < 0).then_some(ioctl_errno);
    let driver_write_consumed = bwr.write_consumed;
    let driver_read_consumed = bwr.read_consumed;
    let write_consumption_valid = driver_write_consumed <= write_remaining;
    // binder_ioctl_write_read() resets read_consumed when the write phase fails,
    // even when userspace supplied an accumulated non-zero value.
    let read_consumption_reset =
        ioctl_error.is_some() && write_remaining > 0 && driver_read_consumed == 0;
    let read_consumption_valid = read_consumption_reset
        || (input_read_consumed..=original_read_size).contains(&driver_read_consumed);
    if !write_consumption_valid || !read_consumption_valid {
        if !write_consumption_valid {
            warn!(
                "event=binder driver reported invalid write consumption fd={} consumed={} remaining={}",
                fd, driver_write_consumed, write_remaining
            );
        }
        if !read_consumption_valid {
            warn!(
                "event=binder driver reported invalid read consumption fd={} previous={} consumed={} size={}",
                fd, input_read_consumed, driver_read_consumed, original_read_size
            );
        }
        binder_ioctl_guard
            .lifecycle
            .state
            .lock()
            .expect("binder fd lifecycle poisoned")
            .protocol_error = true;
        *libc::__errno() = libc::EPROTO;
        return -1;
    }
    bwr.write_size = original_write_size;
    bwr.read_size = original_read_size;
    bwr.write_consumed = input_write_consumed + driver_write_consumed;
    bwr.read_consumed = driver_read_consumed;
    bwr.write_buffer = original_write_buffer;
    bwr.read_buffer = original_read_buffer;

    for &(_, reply_data, expects_reply, acquire_target) in completion_commands
        .iter()
        .take_while(|(end, _, _, _)| *end <= bwr.write_consumed)
    {
        if let Some(target) = acquire_target {
            complete_operation_acquire(target);
            continue;
        }
        let is_reply = reply_data.is_some();
        let operation_target =
            reply_data.and_then(|data_ptr| complete_prepared_bc_reply(fd, data_ptr));
        if let Some(target) = operation_target {
            complete_operation_publication(target, fd);
        }
        record_transaction_completion(fd, is_reply, expects_reply, operation_target);
    }
    if bwr.write_size > 0 && bwr.write_consumed == bwr.write_size {
        abort_prepared_bc_replies(fd);
        clear_outbound_reply_buffers(binder_state_key(fd));
    }

    if let Some(error) = ioctl_error {
        if !matches!(error, libc::EINTR | libc::EAGAIN) {
            abort_prepared_bc_replies(fd);
            clear_outbound_reply_buffers(binder_state_key(fd));
        }
        if error == libc::EBADF {
            let retired = invalidate_binder_fd_token(binder_token);
            forget_current_thread_binder_fd(fd, retired);
        }
    }

    mark_inbound_free_buffers_consumed(connection, &freed_inbound_shadows, bwr.write_consumed);

    let mut pending_read = PendingReadCopyback::None;
    let mut read_effects = PendingReadEffects::new(connection);
    let mut read_copy_back_ok = true;
    if driver_read_consumed > input_read_consumed {
        let read_len = driver_read_consumed - input_read_consumed;
        let read_address = (original_read_buffer as usize)
            .checked_add(input_read_consumed)
            .expect("read address was validated before ioctl");
        let mut host_read = IoctlScratch::acquire();
        match fill_process_buffer(host_read.as_mut(), read_address, read_len) {
            Ok(()) => {
                read_effects = parse_read_buffer(fd, host_read.as_mut());
                if !copy_to_process(read_address, host_read.as_mut()) {
                    warn!(
                        "event=binder failed to copy processed read buffer after ioctl fd={} previous={} consumed={}",
                        fd, input_read_consumed, bwr.read_consumed
                    );
                    read_copy_back_ok = false;
                }
                pending_read = PendingReadCopyback::Processed {
                    address: read_address,
                    data: host_read.take(),
                };
            }
            Err(_) => {
                warn!(
                    "event=binder failed to read driver output after ioctl fd={} previous={} consumed={}",
                    fd, input_read_consumed, bwr.read_consumed
                );
                pending_read = PendingReadCopyback::Unread {
                    address: read_address,
                    len: read_len,
                };
                read_copy_back_ok = false;
            }
        }
    }
    if ret >= 0 && bwr.read_size > 0 {
        flush_native_binder_lifecycle(old_ioctl_fn);
    }
    let mut visible_bwr = bwr;
    if !read_copy_back_ok {
        visible_bwr.read_consumed = input_read_consumed;
    }
    let counters_copy_back_ok = write_process_value(arg.cast::<binder_write_read>(), &visible_bwr);
    if !counters_copy_back_ok {
        warn!(
            "event=binder failed to copy consumed counters after ioctl fd={}",
            fd
        );
    }
    if !read_copy_back_ok || !counters_copy_back_ok {
        PENDING_IOCTL_COPYBACKS.with(|slot| {
            slot.borrow_mut().insert(
                connection,
                PendingIoctlCopyback {
                    arg: arg as usize,
                    write_buffer: original_write_buffer,
                    read_buffer: original_read_buffer,
                    write_size: original_write_size,
                    read_size: original_read_size,
                    read: pending_read,
                    output: bwr,
                    read_effects,
                    freed_inbound_shadows,
                    ret,
                    errno: ioctl_errno,
                },
            );
        });
        *libc::__errno() = libc::EFAULT;
        return -1;
    }
    read_effects.commit();
    complete_inbound_free_buffers(connection, &freed_inbound_shadows, bwr.write_consumed);
    *libc::__errno() = ioctl_errno;
    ret
}

#[cfg(test)]
mod tests;
