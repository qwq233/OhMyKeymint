use std::ffi::c_void;
use std::mem::size_of;
use std::os::raw::c_int;
use std::sync::atomic::Ordering;

use log::{debug, warn};

use super::binder::{
    _ioc_dir, _ioc_nr, _ioc_size, binder_transaction_data, binder_transaction_data_secctx,
    binder_transaction_data_sg, binder_write_read, format_target, log_write_transaction,
    parse_secctx_sid, preview_transaction_parcel, BC_REPLY_NR, BC_REPLY_SG_NR, BC_TRANSACTION_NR,
    BC_TRANSACTION_SG_NR, BINDER_WRITE_READ, BR_REPLY_NR, BR_TRANSACTION_NR, TF_ONE_WAY,
};
use super::rewrite::{clear_outbound_reply_buffers, handle_bc_reply, handle_br_transaction};
use super::OLD_IOCTL;

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
            parse_read_buffer(bwr.read_buffer as *mut c_void, bwr.read_consumed as u64);
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
                "[BinderInterceptor][pre] truncated binder command header: remaining={}",
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
                "[BinderInterceptor][pre] truncated binder command payload: nr={} size={} remaining={}",
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
                            "[BinderInterceptor][pre] unexpected payload size {} for binder command nr={}",
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
                            "[BinderInterceptor][pre] unexpected SG payload size {} for binder command nr={}",
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

unsafe fn parse_read_buffer(mut ptr: *mut c_void, size: u64) {
    let total_size = size as usize;
    let mut offset = 0usize;
    while offset < total_size {
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "[BinderInterceptor][post] truncated binder command header: remaining={}",
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
                "[BinderInterceptor][post] truncated binder command payload: nr={} size={} remaining={}",
                _ioc_nr(cmd),
                cmd_size,
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd_nr = _ioc_nr(cmd);
        let is_read = _ioc_dir(cmd) == 2;

        if is_read {
            match cmd_nr {
                BR_TRANSACTION_NR => {
                    if cmd_size == size_of::<binder_transaction_data_secctx>() {
                        let tr_ptr = ptr as *mut binder_transaction_data_secctx;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        if handle_br_transaction(
                            &mut tr.transaction_data,
                            parse_secctx_sid(tr.secctx),
                            "BR_TRANSACTION_SEC_CTX",
                        ) {
                            std::ptr::write_unaligned(tr_ptr, tr);
                        }
                    } else if cmd_size == size_of::<binder_transaction_data>() {
                        let tr_ptr = ptr as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        if handle_br_transaction(&mut tr, None, "BR_TRANSACTION") {
                            std::ptr::write_unaligned(tr_ptr, tr);
                        }
                    } else {
                        warn!(
                            "[BinderInterceptor][post] unexpected payload size {} for BR_TRANSACTION-like command",
                            cmd_size
                        );
                    }
                }
                BR_REPLY_NR => {
                    if cmd_size == size_of::<binder_transaction_data>() {
                        let tr = std::ptr::read_unaligned(ptr as *const binder_transaction_data);
                        debug!(
                            ">>> [BinderInterceptor][post] BR_REPLY | target: {}, code: 0x{:x}, sender_euid: {}, sender_pid: {}, flags: 0x{:x}{}, parcel_size: {}, offsets_size: {}, parcel: {}",
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
                            "[BinderInterceptor][post] unexpected payload size {} for BR_REPLY",
                            cmd_size
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
