use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::raw::c_int;
use std::sync::atomic::Ordering;
use std::time::Instant;

#[cfg(test)]
use std::sync::Mutex;

use log::{debug, warn};

#[cfg(test)]
use super::binder::BR_TRANSACTION_CMD;
use super::binder::{
    _ioc_dir, _ioc_nr, _ioc_size, binder_node_debug_info, binder_pri_ptr_cookie, binder_ptr_cookie,
    binder_transaction_data, binder_transaction_data_secctx, binder_transaction_data_sg,
    binder_write_read, format_target, log_write_transaction, parse_secctx_sid,
    preview_transaction_parcel, take_native_binder_retirement, BC_ACQUIRE_DONE_CMD,
    BC_ACQUIRE_RESULT_CMD, BC_INCREFS_DONE_CMD, BC_REPLY_CMD, BC_REPLY_NR, BC_REPLY_SG_NR,
    BC_TRANSACTION_NR, BC_TRANSACTION_SG_NR, BINDER_GET_NODE_DEBUG_INFO, BINDER_WRITE_READ,
    BR_ACQUIRE_NR, BR_ATTEMPT_ACQUIRE_NR, BR_DEAD_REPLY_NR, BR_DECREFS_NR, BR_FAILED_REPLY_NR,
    BR_FROZEN_REPLY_NR, BR_INCREFS_NR, BR_NOOP_CMD, BR_ONEWAY_SPAM_SUSPECT_NR, BR_RELEASE_NR,
    BR_REPLY_NR, BR_TRANSACTION_COMPLETE_CMD, BR_TRANSACTION_NR, BR_TRANSACTION_PENDING_FROZEN_NR,
    TF_ONE_WAY, TF_STATUS_CODE,
};
use super::rewrite::{
    abort_bc_reply, cancel_operation_publication_acquire_pending, clear_outbound_reply_buffers,
    commit_bc_reply, drop_synthetic_operation_target, finish_operation_publication_probe,
    handle_bc_reply, handle_br_transaction, handle_synthetic_br_transaction,
    is_raw_synthetic_target, lookup_raw_synthetic_target,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, retire_native_operation_target,
    take_operation_publication_probe, OperationPublicationProbe, SyntheticReply,
    SyntheticTargetKind,
};
use super::OLD_IOCTL;
use crate::hook::binder::{LocalBinderTarget, BC_FREE_BUFFER_CMD};

struct PendingTransactionCompletion {
    is_reply: bool,
    expects_reply: bool,
    hide_from_host: bool,
    operation_target: Option<LocalBinderTarget>,
}

#[derive(Clone, Copy)]
struct PreparedBcReply {
    frame_id: Option<u64>,
    data_ptr: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncTransactionState {
    PendingCompletion,
    AwaitingReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyntheticWriteStatus {
    Complete,
    Retry,
    NeedsRead,
    Failed(c_int),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSyntheticFlush {
    Drained,
    Retry,
    NeedsRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyntheticWriteRecovery {
    None,
    ReplyRetried,
    StatusFallback,
}

struct PendingSyntheticWrite {
    write: Vec<u8>,
    consumed: usize,
    reply: Option<Box<SyntheticReply>>,
    acquire_target: Option<LocalBinderTarget>,
    needs_read: bool,
    recovery: SyntheticWriteRecovery,
    label: &'static str,
}

impl PendingSyntheticWrite {
    fn prepare_original_reply_retry(&mut self, error: c_int) -> bool {
        let free_size = size_of::<u32>() + size_of::<libc::c_ulong>();
        if self.recovery != SyntheticWriteRecovery::None
            || matches!(error, libc::EBADF | libc::EPROTO)
            || self.consumed != 0 && self.consumed != free_size
            || !match self.reply.as_deref() {
                Some(SyntheticReply::Parcel(reply)) => {
                    reply.offsets.is_empty() && reply.native_operation_target.is_none()
                }
                Some(SyntheticReply::Status(_) | SyntheticReply::NoReply) => true,
                None => false,
            }
        {
            return false;
        }

        self.needs_read = false;
        self.recovery = SyntheticWriteRecovery::ReplyRetried;
        true
    }

    unsafe fn install_status_fallback(&mut self, error: c_int) -> Option<Vec<u8>> {
        let free_size = size_of::<u32>() + size_of::<libc::c_ulong>();
        let reply_offset = free_size + size_of::<u32>();
        if self.recovery == SyntheticWriteRecovery::StatusFallback
            || matches!(error, libc::EBADF | libc::EPROTO)
            || self.consumed != 0 && self.consumed != free_size
            || self.write.len() < reply_offset + size_of::<binder_transaction_data>()
            || self
                .reply
                .as_deref()
                .is_none_or(|reply| matches!(reply, SyntheticReply::NoReply))
        {
            return None;
        }

        let free_pending = self.consumed == 0;
        let free_buffer = std::ptr::read_unaligned(
            self.write.as_ptr().add(size_of::<u32>()) as *const libc::c_ulong
        );
        let mut reply_tr = std::ptr::read_unaligned(
            self.write.as_ptr().add(reply_offset) as *const binder_transaction_data
        );
        self.reply = Some(Box::new(SyntheticReply::Status(i32::from(
            rsbinder::StatusCode::FailedTransaction,
        ))));
        let Some(SyntheticReply::Status(status)) = self.reply.as_deref() else {
            unreachable!("synthetic fallback reply should be a status")
        };
        reply_tr.flags = TF_STATUS_CODE;
        reply_tr.data_size = size_of::<i32>();
        reply_tr.offsets_size = 0;
        reply_tr.data.ptr.buffer = status as *const i32 as libc::c_ulong;
        reply_tr.data.ptr.offsets = 0;

        let mut reply_write = Vec::new();
        push_unaligned(&mut reply_write, &BC_REPLY_CMD);
        push_unaligned(&mut reply_write, &reply_tr);
        self.write = reply_write;
        self.consumed = 0;
        self.needs_read = false;
        self.recovery = SyntheticWriteRecovery::StatusFallback;
        self.label = "synthetic fallback BC_REPLY";

        let mut cleanup = Vec::new();
        if free_pending {
            push_unaligned(&mut cleanup, &BC_FREE_BUFFER_CMD);
            push_unaligned(&mut cleanup, &free_buffer);
        }
        Some(cleanup)
    }
}

impl Drop for PendingSyntheticWrite {
    fn drop(&mut self) {
        if let Some(target) = self.acquire_target.take() {
            cancel_operation_publication_acquire_pending(target);
        }
    }
}

thread_local! {
    static PENDING_TRANSACTION_COMPLETIONS: RefCell<HashMap<c_int, VecDeque<PendingTransactionCompletion>>> = RefCell::default();
    static SYNC_TRANSACTIONS: RefCell<HashMap<c_int, Vec<SyncTransactionState>>> = RefCell::default();
    static PENDING_SYNTHETIC_WRITES: RefCell<HashMap<c_int, VecDeque<PendingSyntheticWrite>>> = RefCell::default();
    static PREPARED_BC_REPLIES: RefCell<HashMap<c_int, VecDeque<PreparedBcReply>>> = RefCell::default();
}

pub(super) unsafe fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    let mut old_ioctl_ptr = OLD_IOCTL.load(Ordering::Relaxed);
    if old_ioctl_ptr.is_null() {
        extern "C" {
            fn ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int;
        }
        old_ioctl_ptr = ioctl as *mut c_void;
    }

    let old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int =
        std::mem::transmute(old_ioctl_ptr);

    let is_binder_write_read = request as u32 == BINDER_WRITE_READ;

    let mut suppressed_host_write = None;
    if is_binder_write_read {
        flush_native_binder_lifecycle(old_ioctl_fn);
        match flush_pending_synthetic_writes(fd, old_ioctl_fn) {
            PendingSyntheticFlush::Drained => {}
            PendingSyntheticFlush::Retry => {
                *libc::__errno() = libc::EINTR;
                return -1;
            }
            PendingSyntheticFlush::NeedsRead => {
                if !arg.is_null() {
                    let bwr = &mut *(arg as *mut binder_write_read);
                    if bwr.read_size == 0 {
                        return 0;
                    }
                    suppressed_host_write = Some((bwr.write_size, bwr.write_consumed));
                    bwr.write_size = 0;
                    bwr.write_consumed = 0;
                }
            }
        }
    }

    let mut completion_commands = Vec::new();
    if is_binder_write_read && !arg.is_null() && suppressed_host_write.is_none() {
        let bwr = &*(arg as *const binder_write_read);
        if bwr.write_size > 0 {
            completion_commands =
                parse_write_buffer(fd, bwr.write_buffer as *mut c_void, bwr.write_size as u64);
        }
    }

    let ret = old_ioctl_fn(fd, request, arg);
    let ioctl_error = (ret < 0).then(|| {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    });

    if let Some((write_size, write_consumed)) = suppressed_host_write {
        let bwr = &mut *(arg as *mut binder_write_read);
        bwr.write_size = write_size;
        bwr.write_consumed = write_consumed;
        if ret >= 0 {
            complete_pending_synthetic_read(fd);
            if write_consumed > 0 {
                completion_commands =
                    parse_write_buffer(fd, bwr.write_buffer as *mut c_void, write_consumed as u64);
            }
        } else if let Some(error) = ioctl_error {
            if !matches!(error, libc::EINTR | libc::EAGAIN) {
                drop_pending_synthetic_writes(fd);
            }
        }
    }

    if is_binder_write_read && !arg.is_null() {
        let bwr = &*(arg as *const binder_write_read);
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
            record_transaction_completion(fd, is_reply, expects_reply, false, operation_target);
        }
        if bwr.write_size > 0 && bwr.write_consumed == bwr.write_size {
            abort_prepared_bc_replies(fd);
            clear_outbound_reply_buffers(fd);
        }
    }

    if let Some(error) = ioctl_error {
        if !matches!(error, libc::EINTR | libc::EAGAIN) && is_binder_write_read && !arg.is_null() {
            abort_prepared_bc_replies(fd);
            clear_outbound_reply_buffers(fd);
        }
        *libc::__errno() = error;
        return ret;
    }

    if is_binder_write_read && !arg.is_null() {
        let bwr = &mut *(arg as *mut binder_write_read);
        if bwr.read_consumed > 0 {
            parse_read_buffer(
                fd,
                old_ioctl_fn,
                bwr.read_buffer as *mut c_void,
                bwr.read_consumed as u64,
            );
        }
        if bwr.read_size > 0 {
            flush_native_binder_lifecycle(old_ioctl_fn);
        }
    }

    ret
}

fn prepared_bc_reply(fd: c_int, reply_index: usize) -> Option<PreparedBcReply> {
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow()
            .get(&fd)
            .and_then(|replies| replies.get(reply_index))
            .copied()
    })
}

fn remember_prepared_bc_reply(fd: c_int, prepared_reply: PreparedBcReply) {
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow_mut()
            .entry(fd)
            .or_default()
            .push_back(prepared_reply);
    });
}

fn take_prepared_bc_reply(fd: c_int) -> Option<PreparedBcReply> {
    PREPARED_BC_REPLIES.with(|prepared| {
        let mut prepared = prepared.borrow_mut();
        let replies = prepared.get_mut(&fd)?;
        let reply = replies.pop_front();
        if replies.is_empty() {
            prepared.remove(&fd);
        }
        reply
    })
}

fn complete_prepared_bc_reply(fd: c_int, observed_data_ptr: usize) -> Option<LocalBinderTarget> {
    let Some(prepared) = take_prepared_bc_reply(fd) else {
        return commit_bc_reply(fd, None, observed_data_ptr);
    };
    let data_ptr = prepared.data_ptr;
    if data_ptr != observed_data_ptr {
        warn!(
            "event=reply consumed prepared BC_REPLY with changed data pointer fd={} prepared=0x{:x} observed=0x{:x}",
            fd, data_ptr, observed_data_ptr
        );
    }
    commit_bc_reply(fd, prepared.frame_id, data_ptr)
}

fn abort_prepared_bc_replies(fd: c_int) {
    let prepared = PREPARED_BC_REPLIES.with(|prepared| prepared.borrow_mut().remove(&fd));
    if let Some(prepared) = prepared {
        for reply in prepared {
            abort_bc_reply(fd, reply.frame_id, reply.data_ptr);
        }
    }
}

unsafe fn parse_write_buffer(
    fd: c_int,
    ptr: *mut c_void,
    size: u64,
) -> Vec<(usize, Option<usize>, bool, Option<LocalBinderTarget>)> {
    let base = ptr as *mut u8;
    let total_size = size as usize;
    let mut offset = 0usize;
    let mut completion_commands = Vec::new();
    let mut reply_count = 0;
    while offset < total_size {
        let command_start = base.add(offset);
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder write command header: remaining={}",
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
                "truncated binder write command payload: nr={} size={} remaining={}",
                _ioc_nr(cmd),
                cmd_size,
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd_nr = _ioc_nr(cmd);
        let is_write = _ioc_dir(cmd) == 1;

        if is_write {
            match cmd_nr {
                BC_TRANSACTION_NR | BC_REPLY_NR | BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR => {
                    let is_sg = matches!(cmd_nr, BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR);
                    let is_reply = matches!(cmd_nr, BC_REPLY_NR | BC_REPLY_SG_NR);
                    let expected_size = if is_sg {
                        size_of::<binder_transaction_data_sg>()
                    } else {
                        size_of::<binder_transaction_data>()
                    };
                    if cmd_size == expected_size {
                        let tr_ptr = payload as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        if is_reply && prepared_bc_reply(fd, reply_count).is_none() {
                            let frame_id = handle_bc_reply(fd, &mut tr);
                            remember_prepared_bc_reply(
                                fd,
                                PreparedBcReply {
                                    frame_id,
                                    data_ptr: tr.data.ptr.buffer as usize,
                                },
                            );
                            std::ptr::write_unaligned(tr_ptr, tr);
                        }
                        let label = match cmd_nr {
                            BC_TRANSACTION_NR => "BC_TRANSACTION",
                            BC_REPLY_NR => "BC_REPLY",
                            BC_TRANSACTION_SG_NR => "BC_TRANSACTION_SG",
                            BC_REPLY_SG_NR => "BC_REPLY_SG",
                            _ => unreachable!(),
                        };
                        log_write_transaction(label, &tr);
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(tr.data.ptr.buffer as usize),
                            !is_reply && (tr.flags & TF_ONE_WAY) == 0,
                            None,
                        ));
                    } else if !is_sg {
                        warn!(
                            "unexpected binder write command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    } else {
                        warn!(
                            "unexpected binder write SG payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                    if cmd_size != expected_size {
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(0),
                            false,
                            None,
                        ));
                    }
                    if is_reply {
                        reply_count += 1;
                    }
                }
                _ => {}
            }
            if cmd == BC_ACQUIRE_DONE_CMD && cmd_size == size_of::<binder_ptr_cookie>() {
                let ptr_cookie = std::ptr::read_unaligned(payload as *const binder_ptr_cookie);
                completion_commands.push((
                    offset + cmd_size,
                    None,
                    false,
                    Some(LocalBinderTarget {
                        ptr: ptr_cookie.ptr,
                        cookie: ptr_cookie.cookie,
                    }),
                ));
            }
        }

        offset += cmd_size;
    }

    completion_commands
}

unsafe fn parse_read_buffer(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    ptr: *mut c_void,
    size: u64,
) {
    let base = ptr as *mut u8;
    let total_size = size as usize;
    let mut offset = 0usize;
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
            if complete_transaction_submission(fd).is_some_and(|hide| hide) {
                debug!(
                    "event=synthetic consumed hidden BR_TRANSACTION_COMPLETE for synthetic reply"
                );
                fill_noop_command(command_start as *mut c_void, size_of::<u32>());
            }
        } else if terminal_reply
            || matches!(
                cmd_nr,
                BR_ONEWAY_SPAM_SUSPECT_NR | BR_TRANSACTION_PENDING_FROZEN_NR
            )
        {
            if complete_failed_transaction_submission(fd, cmd_nr) {
                fill_noop_command(command_start as *mut c_void, cmd_size + size_of::<u32>());
            }
        } else if is_read {
            match cmd_nr {
                BR_TRANSACTION_NR => {
                    let transaction = if cmd_size == size_of::<binder_transaction_data_secctx>() {
                        let tr = std::ptr::read_unaligned(
                            payload as *const binder_transaction_data_secctx,
                        );
                        Some((
                            tr.transaction_data,
                            parse_secctx_sid(tr.secctx),
                            "BR_TRANSACTION_SEC_CTX",
                        ))
                    } else if cmd_size == size_of::<binder_transaction_data>() {
                        Some((
                            std::ptr::read_unaligned(payload as *const binder_transaction_data),
                            None,
                            "BR_TRANSACTION",
                        ))
                    } else {
                        warn!("unexpected BR_TRANSACTION-like payload size {}", cmd_size);
                        None
                    };
                    if let Some((mut tr, caller_sid, label)) = transaction {
                        match handle_incoming_transaction(
                            fd,
                            old_ioctl_fn,
                            &mut tr,
                            caller_sid,
                            label,
                        ) {
                            Some(true) => std::ptr::write_unaligned(
                                payload as *mut binder_transaction_data,
                                tr,
                            ),
                            Some(false) => fill_noop_command(
                                command_start as *mut c_void,
                                cmd_size + size_of::<u32>(),
                            ),
                            None => {}
                        }
                    }
                }
                BR_INCREFS_NR | BR_ACQUIRE_NR | BR_RELEASE_NR | BR_DECREFS_NR => {
                    if cmd_size == size_of::<binder_ptr_cookie>() {
                        let ptr_cookie =
                            std::ptr::read_unaligned(payload as *const binder_ptr_cookie);
                        let target = LocalBinderTarget {
                            ptr: ptr_cookie.ptr,
                            cookie: ptr_cookie.cookie,
                        };
                        if is_raw_synthetic_target(target) {
                            let kind = lookup_raw_synthetic_target(target);
                            match cmd_nr {
                                BR_INCREFS_NR => {
                                    submit_synthetic_command(
                                        fd,
                                        old_ioctl_fn,
                                        BC_INCREFS_DONE_CMD,
                                        ptr_cookie,
                                        None,
                                        "BC_INCREFS_DONE",
                                    );
                                }
                                BR_ACQUIRE_NR => {
                                    let acquire_target = (kind
                                        == Some(SyntheticTargetKind::Operation)
                                        && observe_raw_binder_acquire(target))
                                    .then_some(target);
                                    submit_synthetic_command(
                                        fd,
                                        old_ioctl_fn,
                                        BC_ACQUIRE_DONE_CMD,
                                        ptr_cookie,
                                        acquire_target,
                                        "BC_ACQUIRE_DONE",
                                    );
                                }
                                BR_RELEASE_NR => {
                                    if kind == Some(SyntheticTargetKind::Operation) {
                                        drop_synthetic_operation_target(target);
                                    }
                                }
                                BR_DECREFS_NR => {}
                                _ => unreachable!(),
                            }
                            debug!(
                                "event=synthetic consumed raw Binder ref command nr={} ptr=0x{:x} cookie=0x{:x} live={}",
                                cmd_nr,
                                target.ptr,
                                target.cookie,
                                kind.is_some()
                            );
                            fill_noop_command(
                                command_start as *mut c_void,
                                cmd_size + size_of::<u32>(),
                            );
                        }
                    } else {
                        warn!(
                            "unexpected binder ref command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                }
                BR_ATTEMPT_ACQUIRE_NR => {
                    if cmd_size == size_of::<binder_pri_ptr_cookie>() {
                        let pri_ptr_cookie =
                            std::ptr::read_unaligned(payload as *const binder_pri_ptr_cookie);
                        let target = LocalBinderTarget {
                            ptr: pri_ptr_cookie.ptr,
                            cookie: pri_ptr_cookie.cookie,
                        };
                        if is_raw_synthetic_target(target) {
                            let kind = lookup_raw_synthetic_target(target);
                            let live = kind.is_some();
                            let acquire_target = (live
                                && kind == Some(SyntheticTargetKind::Operation)
                                && observe_raw_binder_acquire(target))
                            .then_some(target);
                            submit_synthetic_command(
                                fd,
                                old_ioctl_fn,
                                BC_ACQUIRE_RESULT_CMD,
                                i32::from(live),
                                acquire_target,
                                "BC_ACQUIRE_RESULT",
                            );
                            debug!(
                                "event=synthetic consumed raw Binder attempt-acquire ptr=0x{:x} cookie=0x{:x} live={}",
                                target.ptr, target.cookie, live
                            );
                            fill_noop_command(
                                command_start as *mut c_void,
                                cmd_size + size_of::<u32>(),
                            );
                        }
                    } else {
                        warn!(
                            "unexpected binder attempt-acquire payload size {}",
                            cmd_size
                        );
                    }
                }
                BR_REPLY_NR => {
                    complete_sync_transaction(fd, SyncTransactionState::AwaitingReply);
                    if cmd_size == size_of::<binder_transaction_data>() {
                        let tr =
                            std::ptr::read_unaligned(payload as *const binder_transaction_data);
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
                        warn!("unexpected BR_REPLY payload size {}", cmd_size);
                    }
                }
                _ => {}
            }
        }
        offset += cmd_size;
    }
}

unsafe fn handle_incoming_transaction(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    tr: &mut binder_transaction_data,
    caller_sid: Option<String>,
    label: &str,
) -> Option<bool> {
    if let Some(reply) = handle_synthetic_br_transaction(tr, caller_sid.clone(), label) {
        if !submit_synthetic_transaction_reply(fd, old_ioctl_fn, tr, reply) {
            warn!(
                "event=synthetic {} reply submission did not complete synchronously; hiding the already-executed transaction",
                label
            );
        }
        return Some(false);
    }

    handle_br_transaction(tr, caller_sid, label).then_some(true)
}

unsafe fn fill_noop_command(command_start: *mut c_void, total_len: usize) {
    let mut written = 0usize;
    while total_len.saturating_sub(written) >= size_of::<u32>() {
        std::ptr::write_unaligned(command_start.add(written) as *mut u32, BR_NOOP_CMD);
        written += size_of::<u32>();
    }
}

unsafe fn submit_synthetic_command<T: Copy>(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    command: u32,
    payload: T,
    acquire_target: Option<LocalBinderTarget>,
    label: &'static str,
) {
    let mut write = Vec::with_capacity(size_of::<u32>() + size_of::<T>());
    push_unaligned(&mut write, &command);
    push_unaligned(&mut write, &payload);
    submit_or_defer_synthetic_write(fd, old_ioctl_fn, write, None, acquire_target, label);
}

unsafe fn submit_synthetic_transaction_reply(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    tr: &binder_transaction_data,
    reply: SyntheticReply,
) -> bool {
    let reply = Box::new(reply);
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    let free_buffer = tr.data.ptr.buffer;
    push_unaligned(&mut write, &free_buffer);

    let has_reply = !matches!(reply.as_ref(), SyntheticReply::NoReply);
    if has_reply {
        let mut reply_tr = *tr;
        reply_tr.target.handle = 0;
        reply_tr.cookie = 0;
        reply_tr.code = 0;
        reply_tr.sender_pid = 0;
        reply_tr.sender_euid = 0;
        match reply.as_ref() {
            SyntheticReply::Parcel(reply) => {
                reply_tr.flags = 0;
                reply_tr.data_size = reply.data_size();
                reply_tr.offsets_size = reply.offsets_size();
                reply_tr.data.ptr.buffer = reply.data_ptr() as libc::c_ulong;
                reply_tr.data.ptr.offsets = if reply.offsets.is_empty() {
                    0
                } else {
                    reply.offsets.as_ptr() as libc::c_ulong
                };
            }
            SyntheticReply::Status(status) => {
                reply_tr.flags = TF_STATUS_CODE;
                reply_tr.data_size = size_of::<i32>();
                reply_tr.offsets_size = 0;
                reply_tr.data.ptr.buffer = status as *const i32 as libc::c_ulong;
                reply_tr.data.ptr.offsets = 0;
            }
            SyntheticReply::NoReply => unreachable!(),
        }
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &reply_tr);
    }
    submit_or_defer_synthetic_write(
        fd,
        old_ioctl_fn,
        write,
        Some(reply),
        None,
        "synthetic BC_REPLY",
    )
}

unsafe fn submit_or_defer_synthetic_write(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    mut write: Vec<u8>,
    reply: Option<Box<SyntheticReply>>,
    acquire_target: Option<LocalBinderTarget>,
    label: &'static str,
) -> bool {
    let queue_was_empty =
        PENDING_SYNTHETIC_WRITES.with(|pending| !pending.borrow().contains_key(&fd));
    let (consumed, status) = if queue_was_empty {
        submit_write_buffer(fd, old_ioctl_fn, &mut write, label)
    } else {
        (0, SyntheticWriteStatus::Retry)
    };
    let mut pending_write = PendingSyntheticWrite {
        write,
        consumed,
        reply,
        acquire_target,
        needs_read: status == SyntheticWriteStatus::NeedsRead,
        recovery: SyntheticWriteRecovery::None,
        label,
    };
    match status {
        SyntheticWriteStatus::Complete => {
            complete_synthetic_write(fd, pending_write);
            true
        }
        SyntheticWriteStatus::Failed(error) => {
            if pending_write.prepare_original_reply_retry(error) {
                PENDING_SYNTHETIC_WRITES.with(|pending| {
                    pending
                        .borrow_mut()
                        .entry(fd)
                        .or_default()
                        .push_back(pending_write);
                });
            } else if let Some(cleanup) = pending_write.install_status_fallback(error) {
                PENDING_SYNTHETIC_WRITES.with(|pending| {
                    let mut pending = pending.borrow_mut();
                    let queue = pending.entry(fd).or_default();
                    queue.push_back(pending_write);
                    if !cleanup.is_empty() {
                        queue.push_back(PendingSyntheticWrite {
                            write: cleanup,
                            consumed: 0,
                            reply: None,
                            acquire_target: None,
                            needs_read: false,
                            recovery: SyntheticWriteRecovery::StatusFallback,
                            label: "synthetic BC_FREE_BUFFER cleanup",
                        });
                    }
                });
            } else {
                drop(pending_write);
            }
            false
        }
        SyntheticWriteStatus::Retry | SyntheticWriteStatus::NeedsRead => {
            PENDING_SYNTHETIC_WRITES.with(|pending| {
                pending
                    .borrow_mut()
                    .entry(fd)
                    .or_default()
                    .push_back(pending_write);
            });
            false
        }
    }
}

fn complete_synthetic_write(fd: c_int, mut write: PendingSyntheticWrite) {
    if let Some(target) = write.acquire_target.take() {
        complete_operation_acquire(target);
    }
    let operation_target = match write.reply.as_deref_mut() {
        Some(SyntheticReply::Parcel(reply)) => reply.native_operation_target.take(),
        Some(SyntheticReply::Status(_)) => None,
        Some(SyntheticReply::NoReply) | None => return,
    };
    if let Some(target) = operation_target {
        complete_operation_publication(target, fd);
    }
    record_transaction_completion(fd, true, false, true, operation_target);
}

unsafe fn flush_pending_synthetic_writes(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
) -> PendingSyntheticFlush {
    loop {
        let Some(mut write) = PENDING_SYNTHETIC_WRITES.with(|pending| {
            let mut pending = pending.borrow_mut();
            let queue = pending.get_mut(&fd)?;
            let write = queue.pop_front();
            if queue.is_empty() {
                pending.remove(&fd);
            }
            write
        }) else {
            return PendingSyntheticFlush::Drained;
        };

        if write.needs_read {
            PENDING_SYNTHETIC_WRITES.with(|pending| {
                pending
                    .borrow_mut()
                    .entry(fd)
                    .or_default()
                    .push_front(write);
            });
            return PendingSyntheticFlush::NeedsRead;
        }

        let consumed = write.consumed;
        let (written, status) =
            submit_write_buffer(fd, old_ioctl_fn, &mut write.write[consumed..], write.label);
        write.consumed += written;
        match status {
            SyntheticWriteStatus::Complete => {
                complete_synthetic_write(fd, write);
            }
            SyntheticWriteStatus::Retry | SyntheticWriteStatus::NeedsRead => {
                write.needs_read = status == SyntheticWriteStatus::NeedsRead;
                PENDING_SYNTHETIC_WRITES.with(|pending| {
                    pending
                        .borrow_mut()
                        .entry(fd)
                        .or_default()
                        .push_front(write);
                });
                return if status == SyntheticWriteStatus::Retry {
                    PendingSyntheticFlush::Retry
                } else {
                    PendingSyntheticFlush::NeedsRead
                };
            }
            SyntheticWriteStatus::Failed(error) => {
                let failed_label = write.label;
                if write.prepare_original_reply_retry(error) {
                    warn!(
                        "event=synthetic retrying terminally failed {} write once fd={} errno={}",
                        failed_label, fd, error
                    );
                    PENDING_SYNTHETIC_WRITES.with(|pending| {
                        pending
                            .borrow_mut()
                            .entry(fd)
                            .or_default()
                            .push_front(write);
                    });
                    continue;
                }
                if let Some(cleanup) = write.install_status_fallback(error) {
                    warn!(
                        "event=synthetic replacing terminally failed {} write with status fallback fd={} errno={}",
                        failed_label, fd, error
                    );
                    PENDING_SYNTHETIC_WRITES.with(|pending| {
                        let mut pending = pending.borrow_mut();
                        let queue = pending.entry(fd).or_default();
                        if !cleanup.is_empty() {
                            queue.push_front(PendingSyntheticWrite {
                                write: cleanup,
                                consumed: 0,
                                reply: None,
                                acquire_target: None,
                                needs_read: false,
                                recovery: SyntheticWriteRecovery::StatusFallback,
                                label: "synthetic BC_FREE_BUFFER cleanup",
                            });
                        }
                        queue.push_front(write);
                    });
                    continue;
                }
                warn!(
                    "event=synthetic dropping terminally failed {} write fd={} consumed={} expected={} errno={}",
                    write.label,
                    fd,
                    write.consumed,
                    write.write.len(),
                    error
                );
                drop(write);
                continue;
            }
        }
    }
}

fn complete_pending_synthetic_read(fd: c_int) {
    PENDING_SYNTHETIC_WRITES.with(|pending| {
        if let Some(write) = pending
            .borrow_mut()
            .get_mut(&fd)
            .and_then(|queue| queue.front_mut())
        {
            write.needs_read = false;
        }
    });
}

fn drop_pending_synthetic_writes(fd: c_int) {
    let writes = PENDING_SYNTHETIC_WRITES.with(|pending| pending.borrow_mut().remove(&fd));
    drop(writes);
}

unsafe fn submit_write_buffer(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    write: &mut [u8],
    label: &str,
) -> (usize, SyntheticWriteStatus) {
    let mut consumed = 0usize;
    if write.is_empty() {
        return (0, SyntheticWriteStatus::Complete);
    }
    loop {
        let remaining = write.len() - consumed;
        let mut bwr = binder_write_read {
            write_size: remaining,
            write_consumed: 0,
            write_buffer: write.as_mut_ptr().add(consumed) as libc::c_ulong,
            read_size: 0,
            read_consumed: 0,
            read_buffer: 0,
        };
        let ret = old_ioctl_fn(
            fd,
            BINDER_WRITE_READ as c_int,
            &mut bwr as *mut binder_write_read as *mut c_void,
        );
        if bwr.write_consumed > remaining {
            warn!(
                "event=synthetic invalid {} write consumption from binder driver: consumed={} remaining={}",
                label, bwr.write_consumed, remaining
            );
            return (consumed, SyntheticWriteStatus::Failed(libc::EPROTO));
        }
        consumed += bwr.write_consumed;
        if consumed == write.len() {
            return (consumed, SyntheticWriteStatus::Complete);
        }

        if ret < 0 {
            let error = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if matches!(error, libc::EINTR | libc::EAGAIN) {
                return (consumed, SyntheticWriteStatus::Retry);
            }
            warn!(
                "event=synthetic failed to submit {} to binder driver: ret={} consumed={} expected={} errno={}",
                label,
                ret,
                consumed,
                write.len(),
                error
            );
            return (consumed, SyntheticWriteStatus::Failed(error));
        }

        if bwr.write_consumed == 0 {
            return (consumed, SyntheticWriteStatus::NeedsRead);
        }
    }
}

fn push_unaligned<T: Copy>(out: &mut Vec<u8>, value: &T) {
    let start = out.len();
    out.resize(start + size_of::<T>(), 0);
    unsafe {
        std::ptr::write_unaligned(out.as_mut_ptr().add(start) as *mut T, *value);
    }
}

fn record_transaction_completion(
    fd: c_int,
    is_reply: bool,
    expects_reply: bool,
    hide_from_host: bool,
    operation_target: Option<LocalBinderTarget>,
) {
    let pending_count = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        let mut pending = pending.borrow_mut();
        let queue = pending.entry(fd).or_default();
        queue.push_back(PendingTransactionCompletion {
            is_reply,
            expects_reply,
            hide_from_host,
            operation_target,
        });
        queue.len()
    });
    if expects_reply {
        SYNC_TRANSACTIONS.with(|transactions| {
            transactions
                .borrow_mut()
                .entry(fd)
                .or_default()
                .push(SyncTransactionState::PendingCompletion);
        });
    }
    debug!(
        "event=synthetic registered BR_TRANSACTION_COMPLETE for fd={} thread={:?} reply={} expects_reply={} hidden={} pending={}",
        fd,
        std::thread::current().id(),
        is_reply,
        expects_reply,
        hide_from_host,
        pending_count
    );
}

fn observe_raw_binder_acquire(target: LocalBinderTarget) -> bool {
    if mark_operation_publication_acquire_pending(target) {
        debug!(
            "event=synthetic observed BR_ACQUIRE for raw operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        true
    } else {
        false
    }
}

fn complete_operation_acquire(target: LocalBinderTarget) {
    mark_operation_publication_acquire_committed(target);
}

fn complete_operation_publication(target: LocalBinderTarget, binder_fd: c_int) {
    mark_operation_publication_completed(target, binder_fd);
}

unsafe fn flush_native_binder_lifecycle(
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
) {
    while let Some(retirement) = take_native_binder_retirement() {
        debug!(
            "event=synthetic native operation binder destroyed; retiring ptr=0x{:x} cookie=0x{:x} generation={}",
            retirement.target.ptr, retirement.target.cookie, retirement.generation
        );
        retire_native_operation_target(retirement);
    }

    let now = Instant::now();
    if let Some(probe) = take_operation_publication_probe(now) {
        let node_exists = operation_binder_node_exists(old_ioctl_fn, probe);
        if let Some(target) = finish_operation_publication_probe(probe, node_exists, Instant::now())
        {
            debug!(
                "event=synthetic operation publication node disappeared; dropping ptr=0x{:x} cookie=0x{:x}",
                target.ptr, target.cookie
            );
            drop_synthetic_operation_target(target);
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
    if old_ioctl_fn(
        probe.binder_fd,
        BINDER_GET_NODE_DEBUG_INFO as c_int,
        &mut info as *mut binder_node_debug_info as *mut c_void,
    ) < 0
    {
        let error = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if matches!(error, libc::EBADF | libc::ENOTTY) {
            debug!(
                "event=synthetic operation node query fd no longer references its Binder connection fd={} ptr=0x{:x} cookie=0x{:x} errno={}",
                probe.binder_fd, target.ptr, target.cookie, error
            );
            return Ok(false);
        }
        debug!(
            "event=synthetic operation node query failed fd={} ptr=0x{:x} cookie=0x{:x} errno={}",
            probe.binder_fd, target.ptr, target.cookie, error
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
            probe.binder_fd, target.ptr, target.cookie, info.cookie
        );
        return Ok(false);
    }
    warn!(
        "event=synthetic operation node query returned unexpected identity fd={} expected_ptr=0x{:x} expected_cookie=0x{:x} actual_ptr=0x{:x} actual_cookie=0x{:x}",
        probe.binder_fd, target.ptr, target.cookie, info.ptr, info.cookie
    );
    Err(libc::EPROTO)
}

fn complete_transaction_submission(fd: c_int) -> Option<bool> {
    let (completion, remaining) = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        let mut pending = pending.borrow_mut();
        let queue = pending.get_mut(&fd)?;
        let completion = queue.pop_front()?;
        let remaining = queue.len();
        if queue.is_empty() {
            pending.remove(&fd);
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
        "event=synthetic consumed BR_TRANSACTION_COMPLETE for fd={} thread={:?} hidden={} remaining={}",
        fd,
        std::thread::current().id(),
        completion.hide_from_host,
        remaining
    );
    Some(completion.hide_from_host)
}

fn mark_sync_transaction_completed(fd: c_int) -> bool {
    SYNC_TRANSACTIONS.with(|transactions| {
        let mut transactions = transactions.borrow_mut();
        let Some(stack) = transactions.get_mut(&fd) else {
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
    SYNC_TRANSACTIONS.with(|transactions| {
        let mut transactions = transactions.borrow_mut();
        let Some(stack) = transactions.get_mut(&fd) else {
            return false;
        };
        if stack.last() != Some(&expected) {
            return false;
        }
        stack.pop();
        if stack.is_empty() {
            transactions.remove(&fd);
        }
        true
    })
}

fn complete_failed_transaction_submission(fd: c_int, cmd_nr: u32) -> bool {
    let terminal_reply = matches!(
        cmd_nr,
        BR_DEAD_REPLY_NR | BR_FAILED_REPLY_NR | BR_FROZEN_REPLY_NR
    );
    if terminal_reply {
        let failed_reply = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
            let mut pending = pending.borrow_mut();
            let queue = pending.get_mut(&fd)?;
            if queue.front().is_none_or(|completion| !completion.is_reply) {
                return None;
            }
            let completion = queue.pop_front()?;
            if queue.is_empty() {
                pending.remove(&fd);
            }
            Some(completion)
        });
        if let Some(completion) = failed_reply {
            if let Some(target) = completion.operation_target {
                drop_synthetic_operation_target(target);
            }
            debug!(
                "event=synthetic consumed terminal result for failed synthetic reply fd={} thread={:?}",
                fd,
                std::thread::current().id()
            );
            return completion.hide_from_host;
        }
    }

    let front = PENDING_TRANSACTION_COMPLETIONS.with(|pending| {
        pending
            .borrow()
            .get(&fd)
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
        return false;
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
        let queue = pending.get_mut(&fd)?;
        if queue.front().is_none_or(|completion| completion.is_reply) {
            return None;
        }
        queue.pop_front();
        if queue.is_empty() {
            pending.remove(&fd);
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
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::rewrite::{
        pending_reply_frame_claims_for_test, pending_reply_frame_count_for_test,
        reset_pending_reply_frames_for_test,
    };
    use crate::parcel;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    static CAPTURED_REPLY_DATA: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static HOST_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PARTIAL_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PARTIAL_IOCTL_FAIL: AtomicBool = AtomicBool::new(false);
    static PARTIAL_IOCTL_INTERRUPT: AtomicBool = AtomicBool::new(false);
    static RECOVERY_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NEEDS_READ_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static INTERLEAVED_REPLY_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NODE_QUERY_RESULTS: Mutex<VecDeque<Result<binder_node_debug_info, c_int>>> =
        Mutex::new(VecDeque::new());
    static SYNTHETIC_REPLY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn drain_transaction_completions(fd: c_int) {
        while complete_transaction_submission(fd).is_some() {}
        abort_prepared_bc_replies(fd);
        clear_outbound_reply_buffers(fd);
        SYNC_TRANSACTIONS.with(|transactions| {
            transactions.borrow_mut().remove(&fd);
        });
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            pending.borrow_mut().clear();
        });
    }

    unsafe extern "C" fn capture_reply_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        if request != BINDER_WRITE_READ as c_int || arg.is_null() {
            return -1;
        }

        let bwr = &mut *(arg as *mut binder_write_read);
        let write = if bwr.write_size == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(bwr.write_buffer as *const u8, bwr.write_size)
        };
        let mut offset = 0usize;
        let mut captured = None;
        while offset + size_of::<u32>() <= write.len() {
            let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
            offset += size_of::<u32>();
            match cmd {
                BC_FREE_BUFFER_CMD => {
                    offset = offset.saturating_add(size_of::<libc::c_ulong>());
                }
                BC_REPLY_CMD => {
                    if offset + size_of::<binder_transaction_data>() > write.len() {
                        return -1;
                    }
                    let tr = std::ptr::read_unaligned(
                        write.as_ptr().add(offset) as *const binder_transaction_data
                    );
                    offset += size_of::<binder_transaction_data>();
                    captured = Some(
                        std::slice::from_raw_parts(tr.data.ptr.buffer as *const u8, tr.data_size)
                            .to_vec(),
                    );
                }
                _ => return -1,
            }
        }

        if captured.is_some() {
            *CAPTURED_REPLY_DATA
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = captured;
        }
        bwr.write_consumed = bwr.write_size;
        0
    }

    unsafe extern "C" fn partial_reply_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
        if request != BINDER_WRITE_READ as c_int || arg.is_null() {
            return -1;
        }
        let bwr = &mut *(arg as *mut binder_write_read);
        if PARTIAL_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            bwr.write_consumed = size_of::<u32>() + size_of::<libc::c_ulong>();
            return 0;
        }
        if PARTIAL_IOCTL_FAIL.load(Ordering::SeqCst) {
            *libc::__errno() = libc::EIO;
            return -1;
        }
        if PARTIAL_IOCTL_INTERRUPT.load(Ordering::SeqCst) {
            *libc::__errno() = libc::EINTR;
            return -1;
        }
        capture_reply_ioctl(fd, request, arg)
    }

    unsafe extern "C" fn fail_reply_ioctl(_fd: c_int, _request: c_int, arg: *mut c_void) -> c_int {
        let bwr = &mut *(arg as *mut binder_write_read);
        bwr.write_consumed = 0;
        *libc::__errno() = libc::EIO;
        -1
    }

    unsafe extern "C" fn fail_twice_then_capture_ioctl(
        fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        if RECOVERY_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) < 2 {
            return fail_reply_ioctl(fd, request, arg);
        }
        capture_reply_ioctl(fd, request, arg)
    }

    unsafe extern "C" fn interrupt_reply_ioctl(
        _fd: c_int,
        _request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        let bwr = &mut *(arg as *mut binder_write_read);
        bwr.write_consumed = 0;
        *libc::__errno() = libc::EINTR;
        -1
    }

    unsafe extern "C" fn needs_read_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *(arg as *mut binder_write_read);
        match NEEDS_READ_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst) {
            0 => {
                assert!(bwr.write_size > 0);
                bwr.write_consumed = 0;
            }
            1 => {
                assert_eq!(bwr.write_size, 0);
                assert!(bwr.read_size >= size_of::<u32>());
                std::ptr::write_unaligned(bwr.read_buffer as *mut u32, BR_NOOP_CMD);
                bwr.read_consumed = size_of::<u32>();
            }
            2 | 3 => {
                assert!(bwr.write_size > 0);
                bwr.write_consumed = bwr.write_size;
            }
            call => panic!("unexpected NeedsRead ioctl call {call}"),
        }
        0
    }

    unsafe extern "C" fn node_query_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
        assert_eq!(request, BINDER_GET_NODE_DEBUG_INFO as c_int);
        assert_eq!((*(arg as *const binder_node_debug_info)).ptr, 0x2f);
        let result = NODE_QUERY_RESULTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .expect("node query result should be queued");
        match result {
            Ok(info) => {
                std::ptr::write(arg as *mut binder_node_debug_info, info);
                0
            }
            Err(error) => {
                *libc::__errno() = error;
                -1
            }
        }
    }

    unsafe extern "C" fn retry_host_reply_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
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
                    (bwr.read_buffer as *mut u8).add(size_of::<u32>())
                        as *mut binder_transaction_data,
                    std::mem::zeroed(),
                );
                bwr.read_consumed = size_of::<u32>() + size_of::<binder_transaction_data>();
            }
            1 => {
                bwr.write_consumed = bwr.write_size;
                bwr.read_consumed = 0;
            }
            call => panic!("unexpected interleaved reply ioctl call {call}"),
        }
        0
    }

    unsafe extern "C" fn suppressed_host_read_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        assert_eq!(request, BINDER_WRITE_READ as c_int);
        let bwr = &mut *(arg as *mut binder_write_read);
        assert_eq!(bwr.write_size, 0);
        assert_eq!(bwr.write_consumed, 0);
        assert!(bwr.read_size >= size_of::<u32>());
        std::ptr::write_unaligned(bwr.read_buffer as *mut u32, BR_NOOP_CMD);
        bwr.read_consumed = size_of::<u32>();
        0
    }

    #[test]
    fn write_parser_tracks_transaction_and_reply_completions() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_pending_reply_frames_for_test(0);
        let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        let mut write = Vec::new();
        let bc_transaction_cmd = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
        push_unaligned(&mut write, &bc_transaction_cmd);
        push_unaligned(&mut write, &tr);
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &tr);
        push_unaligned(&mut write, &BC_ACQUIRE_DONE_CMD);
        push_unaligned(
            &mut write,
            &binder_ptr_cookie {
                ptr: 0x1234,
                cookie: 0x5678,
            },
        );

        let completions = unsafe {
            parse_write_buffer(20, write.as_mut_ptr() as *mut c_void, write.len() as u64)
        };
        assert_eq!(completions.len(), 3);
        assert_eq!(completions[0].1, None);
        assert!(completions[0].2);
        assert_eq!(completions[0].3, None);
        assert_eq!(completions[1].1, Some(0));
        assert!(!completions[1].2);
        assert_eq!(completions[1].3, None);
        assert_eq!(
            completions[2].3,
            Some(LocalBinderTarget {
                ptr: 0x1234,
                cookie: 0x5678,
            })
        );
        abort_prepared_bc_replies(20);
    }

    #[test]
    fn pending_synthetic_writes_are_isolated_by_binder_fd() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let blocked_fd = 16;
        let ready_fd = 17;
        drain_transaction_completions(blocked_fd);
        drain_transaction_completions(ready_fd);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;

        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = 0x4000;
        let status = || SyntheticReply::Status(i32::from(rsbinder::StatusCode::UnknownTransaction));
        assert!(!unsafe {
            submit_synthetic_transaction_reply(blocked_fd, interrupt_reply_ioctl, &tr, status())
        });
        assert!(unsafe {
            submit_synthetic_transaction_reply(ready_fd, capture_reply_ioctl, &tr, status())
        });
        assert!(PENDING_SYNTHETIC_WRITES.with(|pending| {
            let pending = pending.borrow();
            pending.contains_key(&blocked_fd) && !pending.contains_key(&ready_fd)
        }));
        assert_eq!(complete_transaction_submission(ready_fd), Some(true));
        assert_eq!(complete_transaction_submission(blocked_fd), None);
        drop_pending_synthetic_writes(blocked_fd);
    }

    #[test]
    fn zero_progress_synthetic_write_allows_read_before_retrying() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 18;
        drain_transaction_completions(fd);
        NEEDS_READ_IOCTL_CALLS.store(0, Ordering::SeqCst);

        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = 0x5000;
        assert!(!unsafe {
            submit_synthetic_transaction_reply(
                fd,
                needs_read_ioctl,
                &tr,
                SyntheticReply::Status(i32::from(rsbinder::StatusCode::UnknownTransaction)),
            )
        });

        let mut host_write = Vec::new();
        push_unaligned(&mut host_write, &BC_FREE_BUFFER_CMD);
        push_unaligned(&mut host_write, &0usize);
        let mut host_read = [0u8; size_of::<u32>()];
        let mut bwr = binder_write_read {
            write_size: host_write.len(),
            write_consumed: 0,
            write_buffer: host_write.as_mut_ptr() as libc::c_ulong,
            read_size: 0,
            read_consumed: 0,
            read_buffer: 0,
        };
        let previous = OLD_IOCTL.swap(needs_read_ioctl as *mut c_void, Ordering::SeqCst);

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
        assert_eq!(NEEDS_READ_IOCTL_CALLS.load(Ordering::SeqCst), 1);
        assert!(PENDING_SYNTHETIC_WRITES.with(|pending| {
            pending
                .borrow()
                .get(&fd)
                .and_then(|queue| queue.front())
                .is_some_and(|write| write.needs_read)
        }));

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
        assert_eq!(NEEDS_READ_IOCTL_CALLS.load(Ordering::SeqCst), 1);
        assert!(PENDING_SYNTHETIC_WRITES.with(|pending| {
            pending
                .borrow()
                .get(&fd)
                .and_then(|queue| queue.front())
                .is_some_and(|write| write.needs_read)
        }));

        bwr.read_size = host_read.len();
        bwr.read_buffer = host_read.as_mut_ptr() as libc::c_ulong;
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
        assert_eq!(bwr.write_size, host_write.len());
        assert_eq!(bwr.write_consumed, 0);
        assert_eq!(NEEDS_READ_IOCTL_CALLS.load(Ordering::SeqCst), 2);
        assert!(PENDING_SYNTHETIC_WRITES.with(|pending| {
            pending
                .borrow()
                .get(&fd)
                .and_then(|queue| queue.front())
                .is_some_and(|write| !write.needs_read)
        }));

        bwr.read_consumed = 0;
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
        assert_eq!(NEEDS_READ_IOCTL_CALLS.load(Ordering::SeqCst), 4);
        assert!(PENDING_SYNTHETIC_WRITES.with(|pending| pending.borrow().is_empty()));
        assert_eq!(complete_transaction_submission(fd), Some(true));

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        drain_transaction_completions(fd);
    }

    #[test]
    fn operation_node_query_requires_an_exact_ptr_and_cookie_match() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let target = LocalBinderTarget {
            ptr: 0x30,
            cookie: 0x40,
        };
        let probe = OperationPublicationProbe {
            target,
            binder_fd: 19,
            generation: 1,
            not_before: Instant::now(),
        };
        let info = |ptr, cookie, has_strong_ref, has_weak_ref| binder_node_debug_info {
            ptr,
            cookie,
            has_strong_ref,
            has_weak_ref,
        };
        let queue = |results| {
            *NODE_QUERY_RESULTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = results;
        };

        queue(VecDeque::from([Ok(info(0x30, 0x40, 1, 0))]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Ok(true)
        );

        queue(VecDeque::from([Ok(info(0x30, 0x40, 0, 0))]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Ok(true)
        );

        queue(VecDeque::from([Ok(info(0x30, 0x40, 0, 1))]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Ok(true)
        );

        queue(VecDeque::from([Ok(info(0x50, 2, 0, 0))]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Ok(false)
        );

        queue(VecDeque::from([Ok(info(0x30, 0x41, 1, 0))]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Ok(false)
        );

        queue(VecDeque::from([Err(libc::EIO)]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Err(libc::EIO)
        );

        for error in [libc::EBADF, libc::ENOTTY] {
            queue(VecDeque::from([Err(error)]));
            assert_eq!(
                unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
                Ok(false)
            );
        }
    }

    #[test]
    fn synthetic_reply_distinguishes_partial_completion_and_failure() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = 0x3000;
        let status = || SyntheticReply::Status(i32::from(rsbinder::StatusCode::UnknownTransaction));

        drain_transaction_completions(3);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        PARTIAL_IOCTL_CALLS.store(0, Ordering::SeqCst);
        PARTIAL_IOCTL_FAIL.store(false, Ordering::SeqCst);
        let submitted =
            unsafe { submit_synthetic_transaction_reply(3, partial_reply_ioctl, &tr, status()) };
        assert!(submitted);
        assert_eq!(PARTIAL_IOCTL_CALLS.load(Ordering::SeqCst), 2);
        assert!(CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .is_some());
        assert_eq!(complete_transaction_submission(3), Some(true));

        drain_transaction_completions(4);
        PARTIAL_IOCTL_CALLS.store(0, Ordering::SeqCst);
        PARTIAL_IOCTL_INTERRUPT.store(true, Ordering::SeqCst);
        let submitted =
            unsafe { submit_synthetic_transaction_reply(4, partial_reply_ioctl, &tr, status()) };
        assert!(!submitted);
        assert!(CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
        assert_eq!(complete_transaction_submission(4), None);
        let previous = OLD_IOCTL.swap(partial_reply_ioctl as *mut c_void, Ordering::SeqCst);
        let mut bwr: binder_write_read = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                new_ioctl(
                    4,
                    BINDER_WRITE_READ as c_int,
                    &mut bwr as *mut binder_write_read as *mut c_void,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR)
        );
        OLD_IOCTL.store(previous, Ordering::SeqCst);
        PARTIAL_IOCTL_INTERRUPT.store(false, Ordering::SeqCst);
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(4, partial_reply_ioctl) },
            PendingSyntheticFlush::Drained
        );
        assert!(CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .is_some());
        assert_eq!(complete_transaction_submission(4), Some(true));

        drain_transaction_completions(8);
        PARTIAL_IOCTL_CALLS.store(0, Ordering::SeqCst);
        PARTIAL_IOCTL_FAIL.store(true, Ordering::SeqCst);
        let submitted =
            unsafe { submit_synthetic_transaction_reply(8, partial_reply_ioctl, &tr, status()) };
        assert!(!submitted);
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            let pending = pending.borrow();
            let writes = pending
                .get(&8)
                .expect("original reply retry should be queued");
            assert_eq!(writes.len(), 1);
            assert!(!writes[0].needs_read);
            assert_eq!(writes[0].recovery, SyntheticWriteRecovery::ReplyRetried);
        });
        PARTIAL_IOCTL_FAIL.store(false, Ordering::SeqCst);
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(8, partial_reply_ioctl) },
            PendingSyntheticFlush::Drained
        );
        let captured = CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("original status reply should be submitted");
        assert_eq!(
            i32::from_ne_bytes(captured.try_into().expect("status reply size")),
            i32::from(rsbinder::StatusCode::UnknownTransaction)
        );
        assert_eq!(complete_transaction_submission(8), Some(true));

        drain_transaction_completions(5);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        let submitted =
            unsafe { submit_synthetic_transaction_reply(5, fail_reply_ioctl, &tr, status()) };
        assert!(!submitted);
        assert_eq!(complete_transaction_submission(5), None);
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            let pending = pending.borrow();
            let writes = pending
                .get(&5)
                .expect("original reply retry should be queued");
            assert_eq!(writes.len(), 1);
            assert!(!writes[0].needs_read);
            assert_eq!(writes[0].recovery, SyntheticWriteRecovery::ReplyRetried);
        });
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(5, capture_reply_ioctl) },
            PendingSyntheticFlush::Drained
        );
        PENDING_SYNTHETIC_WRITES.with(|pending| assert!(pending.borrow().is_empty()));
        let captured = CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("zero-progress retry should submit the original status reply");
        assert_eq!(
            i32::from_ne_bytes(captured.try_into().expect("status reply size")),
            i32::from(rsbinder::StatusCode::UnknownTransaction)
        );
        assert_eq!(complete_transaction_submission(5), Some(true));

        drain_transaction_completions(9);
        RECOVERY_IOCTL_CALLS.store(0, Ordering::SeqCst);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        let submitted = unsafe {
            submit_synthetic_transaction_reply(9, fail_twice_then_capture_ioctl, &tr, status())
        };
        assert!(!submitted);
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(9, fail_twice_then_capture_ioctl) },
            PendingSyntheticFlush::Drained
        );
        PENDING_SYNTHETIC_WRITES.with(|pending| assert!(pending.borrow().is_empty()));
        let captured = CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("second terminal failure should submit status fallback");
        assert_eq!(
            i32::from_ne_bytes(captured.try_into().expect("status reply size")),
            i32::from(rsbinder::StatusCode::FailedTransaction)
        );
        assert_eq!(complete_transaction_submission(9), Some(true));

        drain_transaction_completions(11);
        let submitted =
            unsafe { submit_synthetic_transaction_reply(11, fail_reply_ioctl, &tr, status()) };
        assert!(!submitted);
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(11, fail_reply_ioctl) },
            PendingSyntheticFlush::Drained
        );
        PENDING_SYNTHETIC_WRITES.with(|pending| assert!(pending.borrow().is_empty()));
        assert_eq!(complete_transaction_submission(11), None);

        drain_transaction_completions(10);
        let submitted = unsafe {
            submit_synthetic_transaction_reply(10, fail_reply_ioctl, &tr, SyntheticReply::NoReply)
        };
        assert!(!submitted);
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            let pending = pending.borrow();
            let writes = pending
                .get(&10)
                .expect("free-buffer retry should be queued");
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].recovery, SyntheticWriteRecovery::ReplyRetried);
        });
        assert_eq!(
            unsafe { flush_pending_synthetic_writes(10, capture_reply_ioctl) },
            PendingSyntheticFlush::Drained
        );
        PENDING_SYNTHETIC_WRITES.with(|pending| assert!(pending.borrow().is_empty()));
        assert_eq!(complete_transaction_submission(10), None);
        PARTIAL_IOCTL_FAIL.store(false, Ordering::SeqCst);
        unsafe { *libc::__errno() = 0 };
    }

    #[test]
    fn fatal_zero_progress_host_reply_aborts_its_prepared_frame() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 24;
        drain_transaction_completions(fd);
        reset_pending_reply_frames_for_test(2);
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
        assert_eq!(pending_reply_frame_claims_for_test(), vec![false]);
        PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&fd)));

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
        assert_eq!(pending_reply_frame_count_for_test(), 0);
        PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&fd)));

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_pending_reply_frames_for_test(0);
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
        drain_transaction_completions(6);
        reset_pending_reply_frames_for_test(3);
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
                    6,
                    BINDER_WRITE_READ as c_int,
                    &mut bwr as *mut binder_write_read as *mut c_void,
                )
            },
            0
        );
        assert_eq!(pending_reply_frame_count_for_test(), 3);

        assert_eq!(
            unsafe {
                new_ioctl(
                    6,
                    BINDER_WRITE_READ as c_int,
                    &mut bwr as *mut binder_write_read as *mut c_void,
                )
            },
            -1
        );
        assert_eq!(pending_reply_frame_count_for_test(), 1);
        PREPARED_BC_REPLIES.with(|prepared| assert!(!prepared.borrow().contains_key(&6)));

        write.clear();
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &tr);
        bwr.write_buffer = write.as_mut_ptr() as libc::c_ulong;
        bwr.write_size = write.len();
        bwr.write_consumed = 0;

        assert_eq!(
            unsafe {
                new_ioctl(
                    6,
                    BINDER_WRITE_READ as c_int,
                    &mut bwr as *mut binder_write_read as *mut c_void,
                )
            },
            0
        );
        assert_eq!(pending_reply_frame_count_for_test(), 0);

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_pending_reply_frames_for_test(0);
        drain_transaction_completions(6);
        unsafe { *libc::__errno() = 0 };
    }

    #[test]
    fn suppressed_host_write_commits_only_accumulated_reply_prefix() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 23;
        drain_transaction_completions(fd);
        reset_pending_reply_frames_for_test(3);

        let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        let mut write = Vec::new();
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &tr);
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &tr);
        let reply_size = size_of::<u32>() + size_of::<binder_transaction_data>();
        unsafe { parse_write_buffer(fd, write.as_mut_ptr() as *mut c_void, write.len() as u64) };
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            pending
                .borrow_mut()
                .entry(fd)
                .or_default()
                .push_back(PendingSyntheticWrite {
                    write: vec![0],
                    consumed: 0,
                    reply: None,
                    acquire_target: None,
                    needs_read: true,
                    recovery: SyntheticWriteRecovery::None,
                    label: "test pending write",
                });
        });

        let mut read = vec![0u8; size_of::<u32>()];
        let mut bwr = binder_write_read {
            write_size: write.len(),
            write_consumed: reply_size,
            write_buffer: write.as_mut_ptr() as libc::c_ulong,
            read_size: read.len(),
            read_consumed: 0,
            read_buffer: read.as_mut_ptr() as libc::c_ulong,
        };
        let previous = OLD_IOCTL.swap(suppressed_host_read_ioctl as *mut c_void, Ordering::SeqCst);

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
        assert_eq!(bwr.write_consumed, reply_size);
        assert_eq!(pending_reply_frame_count_for_test(), 2);
        PREPARED_BC_REPLIES.with(|prepared| {
            assert_eq!(prepared.borrow().get(&fd).map(VecDeque::len), Some(1));
        });
        PENDING_SYNTHETIC_WRITES.with(|pending| {
            assert!(pending
                .borrow()
                .get(&fd)
                .and_then(|writes| writes.front())
                .is_some_and(|write| !write.needs_read));
        });

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_pending_reply_frames_for_test(0);
        drain_transaction_completions(fd);
    }

    #[test]
    fn zero_progress_host_reply_keeps_its_frame_across_nested_transaction() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 21;
        drain_transaction_completions(fd);
        reset_pending_reply_frames_for_test(1);
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
        assert_eq!(pending_reply_frame_claims_for_test(), vec![true, false]);

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
        assert_eq!(pending_reply_frame_claims_for_test(), vec![false]);

        OLD_IOCTL.store(previous, Ordering::SeqCst);
        reset_pending_reply_frames_for_test(0);
        drain_transaction_completions(fd);
    }

    #[test]
    fn terminal_results_preserve_nested_sync_completion_order() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 9;
        drain_transaction_completions(fd);

        record_transaction_completion(fd, false, true, false, None);
        assert_eq!(complete_transaction_submission(fd), Some(false));
        record_transaction_completion(fd, false, true, false, None);
        complete_failed_transaction_submission(fd, BR_DEAD_REPLY_NR);
        assert_eq!(complete_transaction_submission(fd), None);
        complete_failed_transaction_submission(fd, BR_FROZEN_REPLY_NR);
        assert!(!complete_sync_transaction(
            fd,
            SyncTransactionState::AwaitingReply
        ));

        record_transaction_completion(fd, false, true, false, None);
        assert_eq!(complete_transaction_submission(fd), Some(false));
        assert!(complete_sync_transaction(
            fd,
            SyncTransactionState::AwaitingReply
        ));
        record_transaction_completion(fd, false, true, false, None);
        complete_failed_transaction_submission(fd, BR_FAILED_REPLY_NR);
        assert_eq!(complete_transaction_submission(fd), None);

        record_transaction_completion(fd, false, true, false, None);
        assert_eq!(complete_transaction_submission(fd), Some(false));
        record_transaction_completion(fd, false, false, false, None);
        complete_failed_transaction_submission(fd, BR_DEAD_REPLY_NR);
        assert_eq!(complete_transaction_submission(fd), None);
        assert!(complete_sync_transaction(
            fd,
            SyncTransactionState::AwaitingReply
        ));
        drain_transaction_completions(fd);
    }

    #[test]
    fn terminal_failure_removes_synthetic_reply_completion() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (fd, terminal) in [(10, BR_DEAD_REPLY_NR), (11, BR_FROZEN_REPLY_NR)] {
            drain_transaction_completions(fd);
            record_transaction_completion(
                fd,
                true,
                false,
                true,
                Some(LocalBinderTarget {
                    ptr: 0x3456,
                    cookie: 0x789a,
                }),
            );
            assert!(complete_failed_transaction_submission(fd, terminal));
            assert_eq!(complete_transaction_submission(fd), None);
        }
    }

    #[test]
    fn synthetic_reply_storage_and_completion_lifecycle() {
        let _guard = SYNTHETIC_REPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drain_transaction_completions(1);
        drain_transaction_completions(2);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = 0x1000;
        let reply = parcel::build_raw_i32_reply(0x1234_5678)
            .expect("raw i32 synthetic reply should serialize");

        let submitted = unsafe {
            submit_synthetic_transaction_reply(
                1,
                capture_reply_ioctl,
                &tr,
                SyntheticReply::Parcel(Box::new(reply)),
            )
        };

        assert!(submitted);
        let captured = CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("fake ioctl should capture BC_REPLY payload");
        assert_eq!(captured.len(), size_of::<i32>());
        let value = unsafe { std::ptr::read_unaligned(captured.as_ptr() as *const i32) };
        assert_eq!(value, 0x1234_5678);
        assert_eq!(complete_transaction_submission(1), Some(true));
        assert_eq!(complete_transaction_submission(1), None);

        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = 0x2000;

        let submitted = unsafe {
            submit_synthetic_transaction_reply(
                2,
                capture_reply_ioctl,
                &tr,
                SyntheticReply::Status(i32::from(rsbinder::StatusCode::UnknownTransaction)),
            )
        };

        assert!(submitted);
        let captured = CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("fake ioctl should capture synthetic status payload");
        assert_eq!(captured.len(), size_of::<i32>());
        let status = unsafe { std::ptr::read_unaligned(captured.as_ptr() as *const i32) };
        assert_eq!(status, i32::from(rsbinder::StatusCode::UnknownTransaction));
        assert_eq!(complete_transaction_submission(2), Some(true));
        assert_eq!(complete_transaction_submission(2), None);

        let submitted = unsafe {
            submit_synthetic_transaction_reply(2, capture_reply_ioctl, &tr, SyntheticReply::NoReply)
        };

        assert!(submitted);
        assert!(CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
        assert_eq!(complete_transaction_submission(2), None);

        drain_transaction_completions(1);
        drain_transaction_completions(2);
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}
