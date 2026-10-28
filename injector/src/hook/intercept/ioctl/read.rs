use super::super::*;

#[cfg(test)]
mod tests;

pub(in crate::hook::intercept) unsafe fn parse_read_buffer(
    fd: c_int,
    read: &mut [u8],
) -> PendingReadEffects {
    let base = read.as_mut_ptr();
    let total_size = read.len();
    let mut offset = 0usize;
    let connection = binder_state_key(fd);
    let mut effects = PendingReadEffects::new(connection);
    while offset < total_size {
        let command_start = base.add(offset);
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder read command header: remaining={}",
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd = std::ptr::read_unaligned(command_start as *const u32);
        offset += size_of::<u32>();
        let payload = base.add(offset);

        let cmd_size = _ioc_size(cmd);
        if cmd_size > total_size.saturating_sub(offset) {
            warn!(
                "truncated binder read command payload: nr={} size={} remaining={}",
                _ioc_nr(cmd),
                cmd_size,
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd_nr = _ioc_nr(cmd);
        let is_read = _ioc_dir(cmd) == 2;
        let terminal_reply = matches!(
            cmd_nr,
            BR_DEAD_REPLY_NR | BR_FAILED_REPLY_NR | BR_FROZEN_REPLY_NR
        );

        if cmd == BR_TRANSACTION_COMPLETE_CMD {
            complete_transaction_submission(fd);
        } else if terminal_reply
            || matches!(
                cmd_nr,
                BR_ONEWAY_SPAM_SUSPECT_NR | BR_TRANSACTION_PENDING_FROZEN_NR
            )
        {
            complete_failed_transaction_submission(fd, cmd_nr);
        } else if is_read {
            match cmd_nr {
                BR_TRANSACTION_NR => {
                    let transaction = if cmd_size == size_of::<binder_transaction_data_secctx>() {
                        let tr = std::ptr::read_unaligned(
                            payload as *const binder_transaction_data_secctx,
                        );
                        Some((
                            tr.transaction_data,
                            tr.secctx as usize,
                            "BR_TRANSACTION_SEC_CTX",
                        ))
                    } else if cmd_size == size_of::<binder_transaction_data>() {
                        Some((
                            std::ptr::read_unaligned(payload as *const binder_transaction_data),
                            0,
                            "BR_TRANSACTION",
                        ))
                    } else {
                        warn!("unexpected BR_TRANSACTION-like payload size {}", cmd_size);
                        None
                    };
                    if let Some((mut tr, secctx, label)) = transaction {
                        let target = LocalBinderTarget {
                            ptr: tr.target.ptr,
                            cookie: tr.cookie,
                        };
                        if lookup_synthetic_target(target).is_some() {
                            if (tr.flags & TF_ONE_WAY) == 0 {
                                push_native_pending_frame(connection, target);
                            }
                        } else {
                            let caller_sid = if secctx == 0 {
                                Some(None)
                            } else {
                                copy_process_c_string(secctx).map(Some)
                            };
                            if let Some(caller_sid) = caller_sid {
                                if let Some(mut shadow) = TransactionPayloadShadow::read(&tr) {
                                    shadow.install(&mut tr);
                                    let handled = handle_br_transaction(
                                        connection, &mut tr, caller_sid, label,
                                    );
                                    if handled {
                                        if tr.data_size != 0
                                            && tr.data.ptr.buffer as usize == shadow.data_ptr()
                                        {
                                            effects.staged_inbound_shadows.push(
                                                retain_inbound_transaction_shadow(
                                                    connection, shadow,
                                                ),
                                            );
                                        } else {
                                            shadow.restore(&mut tr);
                                        }
                                        std::ptr::write_unaligned(
                                            payload as *mut binder_transaction_data,
                                            tr,
                                        );
                                    } else {
                                        shadow.restore(&mut tr);
                                    }
                                } else {
                                    warn!(
                                        "event=binder skipped unsafe incoming transaction parcel fd={} data_size={} offsets_size={}",
                                        fd, tr.data_size, tr.offsets_size
                                    );
                                }
                            }
                        }
                    }
                }
                BR_ACQUIRE_NR => {
                    if cmd_size == size_of::<binder_ptr_cookie>() {
                        let ptr_cookie =
                            std::ptr::read_unaligned(payload as *const binder_ptr_cookie);
                        let target = LocalBinderTarget {
                            ptr: ptr_cookie.ptr,
                            cookie: ptr_cookie.cookie,
                        };
                        if let Some(retirement) = observe_operation_acquire(fd, target) {
                            effects.operation_acquires.push(retirement);
                        }
                    } else {
                        warn!(
                            "unexpected binder ref command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                }
                BR_REPLY_NR => {
                    complete_sync_transaction(fd, SyncTransactionState::AwaitingReply);
                    if cmd_size == size_of::<binder_transaction_data>() {
                        let mut tr =
                            std::ptr::read_unaligned(payload as *const binder_transaction_data);
                        if log::log_enabled!(log::Level::Debug) {
                            if let Some(mut shadow) = TransactionPayloadShadow::read(&tr) {
                                shadow.install(&mut tr);
                                debug!(
                                ">>> BR_REPLY | target: {}, code: 0x{:x}, sender_euid: {}, sender_pid: {}, flags: 0x{:x}{}, parcel_size: {}, offsets_size: {}, parcel: {}",
                                format_target(&tr),
                                tr.code,
                                tr.sender_euid,
                                tr.sender_pid,
                                tr.flags,
                                if (tr.flags & TF_ONE_WAY) != 0 { ", oneway" } else { "" },
                                tr.data_size,
                                tr.offsets_size,
                                preview_transaction_parcel(&tr),
                            );
                            } else {
                                warn!(
                                "event=binder skipped unsafe BR_REPLY parcel fd={} data_size={} offsets_size={}",
                                fd, tr.data_size, tr.offsets_size
                            );
                            }
                        }
                    } else {
                        warn!("unexpected BR_REPLY payload size {}", cmd_size);
                    }
                }
                _ => {}
            }
        }
        offset += cmd_size;
    }
    effects
}

pub(super) fn record_transaction_completion(
    fd: c_int,
    is_reply: bool,
    expects_reply: bool,
    operation_target: Option<NativeBinderRetirement>,
) {
    let connection = binder_state_key(fd);
    let pending_count = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        let mut pending = pending.borrow_mut();
        let queue = pending.entry(connection).or_default();
        queue.push_back(PendingTransactionCompletion {
            is_reply,
            expects_reply,
            operation_target,
        });
        queue.len()
    });
    if expects_reply {
        SYNC_TRANSACTIONS.with(|transactions| {
            transactions
                .borrow_mut()
                .entry(connection)
                .or_default()
                .push(SyncTransactionState::PendingCompletion);
        });
    }
    debug!(
        "event=synthetic registered BR_TRANSACTION_COMPLETE for fd={} thread={:?} reply={} expects_reply={} pending={}",
        fd,
        std::thread::current().id(),
        is_reply,
        expects_reply,
        pending_count
    );
}

pub(super) fn observe_operation_acquire(
    fd: c_int,
    target: LocalBinderTarget,
) -> Option<NativeBinderRetirement> {
    let retirement = mark_operation_publication_acquire_pending(target, binder_state_key(fd));
    if retirement.is_some() {
        debug!(
            "event=synthetic observed BR_ACQUIRE for operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
    }
    retirement
}

pub(super) fn complete_operation_acquire(retirement: NativeBinderRetirement) {
    mark_operation_publication_acquire_committed(retirement);
}

pub(super) fn complete_operation_publication(retirement: NativeBinderRetirement, binder_fd: c_int) {
    mark_operation_publication_completed(retirement, observed_binder_fd_token(binder_fd));
}

pub(in crate::hook::intercept) unsafe fn flush_native_binder_lifecycle(
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
) {
    while let Some(probe) = take_operation_publication_probe(Instant::now()) {
        let node_exists = operation_binder_node_exists(old_ioctl_fn, probe);
        if let Some(retirement) =
            finish_operation_publication_probe(probe, node_exists, Instant::now())
        {
            debug!(
                "event=synthetic operation publication has no driver references; dropping ptr=0x{:x} cookie=0x{:x}",
                retirement.target.ptr, retirement.target.cookie
            );
            crate::hook::rewrite::drop_synthetic_operation_retirement(retirement);
        }
    }
}

unsafe fn operation_binder_node_exists(
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    probe: OperationPublicationProbe,
) -> Result<bool, c_int> {
    let target = probe.target;
    let mut info = binder_node_debug_info {
        // Binder returns the first node whose ptr is strictly greater than the cursor.
        ptr: target.ptr.checked_sub(1).ok_or(libc::EINVAL)?,
        ..Default::default()
    };
    let ret = match call_binder_connection_ioctl(
        probe.binder,
        old_ioctl_fn,
        BINDER_GET_NODE_DEBUG_INFO as c_int,
        &mut info as *mut binder_node_debug_info as *mut c_void,
    ) {
        BinderIoctlCall::Called(ret) => ret,
        BinderIoctlCall::Stale => {
            debug!(
                "event=synthetic operation publication belongs to a retired Binder fd generation; retaining until acquire ownership is resolved ptr=0x{:x} cookie=0x{:x} fd={} generation={}",
                target.ptr, target.cookie, probe.binder.fd, probe.binder.generation
            );
            return Err(libc::ESTALE);
        }
        BinderIoctlCall::Retired => {
            if operation_publication_acquire_is_pending(probe) {
                return Err(libc::ESTALE);
            }
            return Ok(false);
        }
    };
    if ret < 0 {
        let error = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if error == libc::EBADF {
            debug!(
                "event=synthetic operation node query fd no longer references its Binder connection; retaining because process-wide acquire work may still be in flight fd={} ptr=0x{:x} cookie=0x{:x} errno={}",
                probe.binder.fd, target.ptr, target.cookie, error
            );
            return Err(error);
        }
        debug!(
            "event=synthetic operation node query failed fd={} ptr=0x{:x} cookie=0x{:x} errno={}",
            probe.binder.fd, target.ptr, target.cookie, error
        );
        return Err(error);
    }
    if info.ptr == 0 || info.ptr > target.ptr {
        return Ok(false);
    }
    if info.ptr == target.ptr {
        if info.cookie == target.cookie {
            return Ok(true);
        }
        warn!(
            "event=synthetic operation node identity changed fd={} expected_ptr=0x{:x} expected_cookie=0x{:x} actual_cookie=0x{:x}; treating target as gone",
            probe.binder.fd, target.ptr, target.cookie, info.cookie
        );
        return Ok(false);
    }
    warn!(
        "event=synthetic operation node query returned unexpected identity fd={} expected_ptr=0x{:x} expected_cookie=0x{:x} actual_ptr=0x{:x} actual_cookie=0x{:x}",
        probe.binder.fd, target.ptr, target.cookie, info.ptr, info.cookie
    );
    Err(libc::EPROTO)
}

pub(super) fn complete_transaction_submission(fd: c_int) -> Option<()> {
    let connection = binder_state_key(fd);
    let (completion, remaining) = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        let mut pending = pending.borrow_mut();
        let queue = pending.get_mut(&connection)?;
        let completion = queue.pop_front()?;
        let remaining = queue.len();
        if queue.is_empty() {
            pending.remove(&connection);
        }
        Some((completion, remaining))
    })?;

    if completion.expects_reply && !mark_sync_transaction_completed(fd) {
        warn!(
            "event=synthetic synchronous transaction completion had no pending transaction fd={} thread={:?}",
            fd,
            std::thread::current().id()
        );
    }

    debug!(
        "event=synthetic consumed BR_TRANSACTION_COMPLETE for fd={} thread={:?} remaining={}",
        fd,
        std::thread::current().id(),
        remaining
    );
    Some(())
}

fn mark_sync_transaction_completed(fd: c_int) -> bool {
    let connection = binder_state_key(fd);
    SYNC_TRANSACTIONS.with(|transactions| {
        let mut transactions = transactions.borrow_mut();
        let Some(stack) = transactions.get_mut(&connection) else {
            return false;
        };
        let Some(state) = stack.last_mut() else {
            return false;
        };
        if *state != SyncTransactionState::PendingCompletion {
            return false;
        }
        *state = SyncTransactionState::AwaitingReply;
        true
    })
}

fn complete_sync_transaction(fd: c_int, expected: SyncTransactionState) -> bool {
    let connection = binder_state_key(fd);
    SYNC_TRANSACTIONS.with(|transactions| {
        let mut transactions = transactions.borrow_mut();
        let Some(stack) = transactions.get_mut(&connection) else {
            return false;
        };
        if stack.last() != Some(&expected) {
            return false;
        }
        stack.pop();
        if stack.is_empty() {
            transactions.remove(&connection);
        }
        true
    })
}

fn complete_failed_transaction_submission(fd: c_int, cmd_nr: u32) {
    let connection = binder_state_key(fd);
    let terminal_reply = matches!(
        cmd_nr,
        BR_DEAD_REPLY_NR | BR_FAILED_REPLY_NR | BR_FROZEN_REPLY_NR
    );
    if terminal_reply {
        let failed_reply = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
            let mut pending = pending.borrow_mut();
            let queue = pending.get_mut(&connection)?;
            if queue.front().is_none_or(|completion| !completion.is_reply) {
                return None;
            }
            let completion = queue.pop_front()?;
            if queue.is_empty() {
                pending.remove(&connection);
            }
            Some(completion)
        });
        if let Some(completion) = failed_reply {
            if let Some(target) = completion.operation_target {
                retire_synthetic_operation_retirement(target);
                debug!(
                    "event=synthetic failed reply retired operation backend and retained publication tombstone fd={} ptr=0x{:x} cookie=0x{:x}",
                    fd, target.target.ptr, target.target.cookie
                );
            }
            debug!(
                "event=synthetic consumed terminal result for failed synthetic reply fd={} thread={:?}",
                fd,
                std::thread::current().id()
            );
            return;
        }
    }

    let front = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        pending
            .borrow()
            .get(&connection)
            .and_then(|queue| queue.front())
            .map(|completion| (completion.is_reply, completion.expects_reply))
    });
    let immediate_failure = match front {
        Some((false, false)) => true,
        Some((false, true)) => {
            complete_sync_transaction(fd, SyncTransactionState::PendingCompletion)
        }
        Some((true, _)) | None => false,
    };

    if terminal_reply
        && !immediate_failure
        && complete_sync_transaction(fd, SyncTransactionState::AwaitingReply)
    {
        debug!(
            "event=synthetic consumed terminal result after completed synchronous transaction fd={} thread={:?}",
            fd,
            std::thread::current().id()
        );
        return;
    }

    if !immediate_failure && matches!(front, Some((false, true))) {
        warn!(
            "event=synthetic terminal result found a synchronous completion marker without matching transaction state fd={} thread={:?}",
            fd,
            std::thread::current().id()
        );
    }

    let removed = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        let mut pending = pending.borrow_mut();
        let queue = pending.get_mut(&connection)?;
        if queue.front().is_none_or(|completion| completion.is_reply) {
            return None;
        }
        queue.pop_front();
        if queue.is_empty() {
            pending.remove(&connection);
        }
        Some(())
    });
    if removed.is_some() {
        debug!(
            "event=synthetic consumed terminal result for failed outgoing transaction fd={} thread={:?}",
            fd,
            std::thread::current().id()
        );
    }
}
