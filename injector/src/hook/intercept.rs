use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::raw::c_int;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

use log::{debug, info, warn};

use super::binder::{
    _ioc_dir, _ioc_nr, _ioc_size, binder_ptr_cookie, binder_transaction_data,
    binder_transaction_data_secctx, binder_transaction_data_sg, binder_write_read, format_target,
    log_write_transaction, parse_secctx_sid, preview_transaction_parcel, BC_ACQUIRE_DONE_CMD,
    BC_REPLY_CMD, BC_REPLY_NR, BC_REPLY_SG_NR, BC_TRANSACTION_NR, BC_TRANSACTION_SG_NR,
    BINDER_WRITE_READ, BR_ACQUIRE_NR, BR_DECREFS_NR, BR_INCREFS_NR, BR_NOOP_CMD, BR_RELEASE_NR,
    BR_REPLY_NR, BR_TRANSACTION_COMPLETE_CMD, BR_TRANSACTION_NR, TF_ONE_WAY, TF_STATUS_CODE,
};
use super::rewrite::{
    clear_outbound_reply_buffers, handle_bc_reply, handle_br_transaction,
    handle_synthetic_br_transaction, handle_synthetic_ref_command, SyntheticReply,
};
use super::OLD_IOCTL;
use crate::hook::binder::{LocalBinderTarget, BC_FREE_BUFFER_CMD, BC_INCREFS_DONE_CMD};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingCompletionKey {
    fd: c_int,
    thread_id: ThreadId,
}

static PENDING_SYNTHETIC_TRANSACTION_COMPLETIONS: OnceLock<
    Mutex<HashMap<PendingCompletionKey, usize>>,
> = OnceLock::new();

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

    if request as u32 == BINDER_WRITE_READ && !arg.is_null() {
        clear_outbound_reply_buffers();
        let bwr = &*(arg as *const binder_write_read);
        if bwr.write_size > 0 {
            parse_write_buffer(bwr.write_buffer as *mut c_void, bwr.write_size as u64);
        }
    }

    let ret = old_ioctl_fn(fd, request, arg);
    clear_outbound_reply_buffers();

    if ret < 0 {
        return ret;
    }

    if request as u32 == BINDER_WRITE_READ && !arg.is_null() {
        let bwr = &mut *(arg as *mut binder_write_read);
        if bwr.read_consumed > 0 {
            parse_read_buffer(
                fd,
                old_ioctl_fn,
                bwr.read_buffer as *mut c_void,
                bwr.read_consumed as u64,
            );
        }
    }

    ret
}

unsafe fn parse_write_buffer(mut ptr: *mut c_void, size: u64) {
    let total_size = size as usize;
    let mut offset = 0usize;
    while offset < total_size {
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder write command header: remaining={}",
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd = std::ptr::read_unaligned(ptr as *const u32);
        ptr = ptr.add(4);
        offset += 4;

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
                BC_TRANSACTION_NR | BC_REPLY_NR => {
                    if cmd_size == size_of::<binder_transaction_data>() {
                        let tr_ptr = ptr as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);

                        if cmd_nr == BC_REPLY_NR {
                            handle_bc_reply(&mut tr);
                            std::ptr::write_unaligned(tr_ptr, tr);
                        }

                        log_write_transaction(
                            if cmd_nr == BC_TRANSACTION_NR {
                                "BC_TRANSACTION"
                            } else {
                                "BC_REPLY"
                            },
                            &tr,
                        );
                    } else {
                        warn!(
                            "unexpected binder write command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                }
                BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR => {
                    if cmd_size == size_of::<binder_transaction_data_sg>() {
                        let tr_ptr = ptr as *mut binder_transaction_data_sg;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);

                        if cmd_nr == BC_REPLY_SG_NR {
                            handle_bc_reply(&mut tr.transaction_data);
                            std::ptr::write_unaligned(tr_ptr, tr);
                        }

                        log_write_transaction(
                            if cmd_nr == BC_TRANSACTION_SG_NR {
                                "BC_TRANSACTION_SG"
                            } else {
                                "BC_REPLY_SG"
                            },
                            &tr.transaction_data,
                        );
                    } else {
                        warn!(
                            "unexpected binder write SG payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                }
                _ => {}
            }
        }

        ptr = ptr.add(cmd_size);
        offset += cmd_size;
    }
}

unsafe fn parse_read_buffer(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    mut ptr: *mut c_void,
    size: u64,
) {
    let total_size = size as usize;
    let mut offset = 0usize;
    while offset < total_size {
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder read command header: remaining={}",
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd = std::ptr::read_unaligned(ptr as *const u32);
        ptr = ptr.add(4);
        offset += 4;

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

        if cmd == BR_TRANSACTION_COMPLETE_CMD && consume_synthetic_transaction_complete(fd) {
            debug!("event=synthetic consumed hidden BR_TRANSACTION_COMPLETE for synthetic reply");
            fill_noop_command(ptr.sub(4), size_of::<u32>());
        } else if is_read {
            match cmd_nr {
                BR_TRANSACTION_NR => {
                    if cmd_size == size_of::<binder_transaction_data_secctx>() {
                        let tr_ptr = ptr as *mut binder_transaction_data_secctx;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        let caller_sid = parse_secctx_sid(tr.secctx);
                        match handle_incoming_transaction(
                            fd,
                            old_ioctl_fn,
                            &mut tr.transaction_data,
                            caller_sid,
                            "BR_TRANSACTION_SEC_CTX",
                        ) {
                            Some(true) => std::ptr::write_unaligned(tr_ptr, tr),
                            Some(false) => {
                                fill_noop_command(ptr.sub(4), cmd_size + size_of::<u32>())
                            }
                            None => {}
                        }
                    } else if cmd_size == size_of::<binder_transaction_data>() {
                        let tr_ptr = ptr as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        match handle_incoming_transaction(
                            fd,
                            old_ioctl_fn,
                            &mut tr,
                            None,
                            "BR_TRANSACTION",
                        ) {
                            Some(true) => std::ptr::write_unaligned(tr_ptr, tr),
                            Some(false) => {
                                fill_noop_command(ptr.sub(4), cmd_size + size_of::<u32>())
                            }
                            None => {}
                        }
                    } else {
                        warn!("unexpected BR_TRANSACTION-like payload size {}", cmd_size);
                    }
                }
                BR_INCREFS_NR | BR_ACQUIRE_NR | BR_RELEASE_NR | BR_DECREFS_NR => {
                    if cmd_size == size_of::<binder_ptr_cookie>() {
                        let ptr_cookie = std::ptr::read_unaligned(ptr as *const binder_ptr_cookie);
                        let target = LocalBinderTarget {
                            ptr: ptr_cookie.ptr,
                            cookie: ptr_cookie.cookie,
                        };
                        if handle_synthetic_ref_command(target, cmd_nr) {
                            let submitted = match cmd_nr {
                                BR_INCREFS_NR => submit_synthetic_ref_done(
                                    fd,
                                    old_ioctl_fn,
                                    BC_INCREFS_DONE_CMD,
                                    ptr_cookie,
                                    "BC_INCREFS_DONE",
                                ),
                                BR_ACQUIRE_NR => submit_synthetic_ref_done(
                                    fd,
                                    old_ioctl_fn,
                                    BC_ACQUIRE_DONE_CMD,
                                    ptr_cookie,
                                    "BC_ACQUIRE_DONE",
                                ),
                                _ => true,
                            };
                            if submitted {
                                info!(
                                    "event=synthetic consumed binder ref command nr={} for ptr=0x{:x} cookie=0x{:x}",
                                    cmd_nr, target.ptr, target.cookie
                                );
                                fill_noop_command(ptr.sub(4), cmd_size + size_of::<u32>());
                            } else {
                                warn!(
                                    "event=synthetic dropping binder ref command nr={} for ptr=0x{:x} cookie=0x{:x} after done submission failed",
                                    cmd_nr, target.ptr, target.cookie
                                );
                                fill_noop_command(ptr.sub(4), cmd_size + size_of::<u32>());
                            }
                        }
                    } else {
                        warn!(
                            "unexpected binder ref command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                }
                BR_REPLY_NR => {
                    if cmd_size == size_of::<binder_transaction_data>() {
                        let tr = std::ptr::read_unaligned(ptr as *const binder_transaction_data);
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

        ptr = ptr.add(cmd_size);
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
                "event=synthetic dropping {} after synthetic reply submission failed",
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

unsafe fn submit_synthetic_ref_done(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    command: u32,
    ptr_cookie: binder_ptr_cookie,
    label: &str,
) -> bool {
    let mut write = Vec::with_capacity(size_of::<u32>() + size_of::<binder_ptr_cookie>());
    push_unaligned(&mut write, &command);
    push_unaligned(&mut write, &ptr_cookie);
    submit_write_buffer(fd, old_ioctl_fn, &mut write, label)
}

unsafe fn submit_synthetic_transaction_reply(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    tr: &binder_transaction_data,
    reply: SyntheticReply,
) -> bool {
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    let free_buffer = tr.data.ptr.buffer;
    push_unaligned(&mut write, &free_buffer);

    let has_reply = !matches!(reply, SyntheticReply::NoReply);
    let submitted = match reply {
        SyntheticReply::Parcel(reply) => {
            let mut reply_tr = *tr;
            reply_tr.target.handle = 0;
            reply_tr.cookie = 0;
            reply_tr.code = 0;
            reply_tr.flags = 0;
            reply_tr.sender_pid = 0;
            reply_tr.sender_euid = 0;
            reply_tr.data_size = reply.data_size();
            reply_tr.offsets_size = reply.offsets_size();
            reply_tr.data.ptr.buffer = reply.data_ptr() as libc::c_ulong;
            reply_tr.data.ptr.offsets = if reply.offsets.is_empty() {
                0
            } else {
                reply.offsets.as_ptr() as libc::c_ulong
            };
            push_unaligned(&mut write, &BC_REPLY_CMD);
            push_unaligned(&mut write, &reply_tr);
            submit_write_buffer(fd, old_ioctl_fn, &mut write, "synthetic BC_REPLY")
        }
        SyntheticReply::Status(status) => {
            let status_storage = status;
            let mut reply_tr = *tr;
            reply_tr.target.handle = 0;
            reply_tr.cookie = 0;
            reply_tr.code = 0;
            reply_tr.flags = TF_STATUS_CODE;
            reply_tr.sender_pid = 0;
            reply_tr.sender_euid = 0;
            reply_tr.data_size = size_of::<i32>();
            reply_tr.offsets_size = 0;
            reply_tr.data.ptr.buffer = &status_storage as *const i32 as libc::c_ulong;
            reply_tr.data.ptr.offsets = 0;
            push_unaligned(&mut write, &BC_REPLY_CMD);
            push_unaligned(&mut write, &reply_tr);
            submit_write_buffer(fd, old_ioctl_fn, &mut write, "synthetic BC_REPLY")
        }
        SyntheticReply::NoReply => {
            submit_write_buffer(fd, old_ioctl_fn, &mut write, "synthetic BC_REPLY")
        }
    };

    if submitted && has_reply {
        record_synthetic_transaction_complete(fd);
    }
    submitted
}

unsafe fn submit_write_buffer(
    fd: c_int,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    write: &mut [u8],
    label: &str,
) -> bool {
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    let ret = old_ioctl_fn(
        fd,
        BINDER_WRITE_READ as c_int,
        &mut bwr as *mut binder_write_read as *mut c_void,
    );
    if ret < 0 {
        warn!(
            "event=synthetic failed to submit {} to binder driver: ret={} errno={}",
            label,
            ret,
            std::io::Error::last_os_error()
        );
        return false;
    }
    if bwr.write_consumed != write.len() {
        warn!(
            "event=synthetic incomplete {} write to binder driver: consumed={} expected={}",
            label,
            bwr.write_consumed,
            write.len()
        );
        return false;
    }
    true
}

fn push_unaligned<T: Copy>(out: &mut Vec<u8>, value: &T) {
    let start = out.len();
    out.resize(start + size_of::<T>(), 0);
    unsafe {
        std::ptr::write_unaligned(out.as_mut_ptr().add(start) as *mut T, *value);
    }
}

fn pending_completion_key(fd: c_int) -> PendingCompletionKey {
    PendingCompletionKey {
        fd,
        thread_id: std::thread::current().id(),
    }
}

fn pending_synthetic_transaction_completions(
) -> &'static Mutex<HashMap<PendingCompletionKey, usize>> {
    PENDING_SYNTHETIC_TRANSACTION_COMPLETIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn record_synthetic_transaction_complete(fd: c_int) {
    let key = pending_completion_key(fd);
    let mut pending = pending_synthetic_transaction_completions()
        .lock()
        .unwrap_or_else(|poisoned| {
            warn!("event=synthetic pending transaction-completion state was poisoned; recovering");
            poisoned.into_inner()
        });
    let count = pending.entry(key).or_insert(0);
    *count = count.saturating_add(1);
    debug!(
        "event=synthetic registered hidden BR_TRANSACTION_COMPLETE for fd={} thread={:?} pending={}",
        key.fd, key.thread_id, *count
    );
}

fn consume_synthetic_transaction_complete(fd: c_int) -> bool {
    let key = pending_completion_key(fd);
    let mut pending = pending_synthetic_transaction_completions()
        .lock()
        .unwrap_or_else(|poisoned| {
            warn!("event=synthetic pending transaction-completion state was poisoned; recovering");
            poisoned.into_inner()
        });
    let Some(count) = pending.get_mut(&key) else {
        return false;
    };
    *count = count.saturating_sub(1);
    let remaining = *count;
    if remaining == 0 {
        pending.remove(&key);
    }
    debug!(
        "event=synthetic consumed hidden BR_TRANSACTION_COMPLETE for fd={} thread={:?} remaining={}",
        key.fd, key.thread_id, remaining
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parcel;

    static CAPTURED_REPLY_DATA: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    unsafe extern "C" fn capture_reply_ioctl(
        _fd: c_int,
        request: c_int,
        arg: *mut c_void,
    ) -> c_int {
        if request != BINDER_WRITE_READ as c_int || arg.is_null() {
            return -1;
        }

        let bwr = &mut *(arg as *mut binder_write_read);
        let write = std::slice::from_raw_parts(bwr.write_buffer as *const u8, bwr.write_size);
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

        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = captured;
        bwr.write_consumed = bwr.write_size;
        0
    }

    #[test]
    fn synthetic_parcel_reply_storage_lives_until_ioctl() {
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
    }
}
