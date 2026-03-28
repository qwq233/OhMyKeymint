use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicPtr, Ordering};

use log::{error, info, warn};

const BINDER_WRITE_READ: u32 = 0xc0306201;
const BC_TRANSACTION_NR: u32 = 0;
const BC_REPLY_NR: u32 = 1;
const BR_TRANSACTION_NR: u32 = 2;
const BR_REPLY_NR: u32 = 3;
const TF_ONE_WAY: u32 = 0x01;
const PARCEL_PREVIEW_CHARS: usize = 50;

#[repr(C)]
pub struct binder_write_read {
    pub write_size: libc::size_t,
    pub write_consumed: libc::size_t,
    pub write_buffer: libc::c_ulong,
    pub read_size: libc::size_t,
    pub read_consumed: libc::size_t,
    pub read_buffer: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union binder_transaction_data_target {
    pub handle: u32,
    pub ptr: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union binder_transaction_data_data {
    pub ptr: binder_transaction_data_data_ptr,
    pub buf: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct binder_transaction_data_data_ptr {
    pub buffer: libc::c_ulong,
    pub offsets: libc::c_ulong,
}

#[repr(C)]
pub struct binder_transaction_data {
    pub target: binder_transaction_data_target,
    pub cookie: libc::c_ulong,
    pub code: u32,
    pub flags: u32,
    pub sender_pid: i32,
    pub sender_euid: i32,
    pub data_size: libc::size_t,
    pub offsets_size: libc::size_t,
    pub data: binder_transaction_data_data,
}

static OLD_IOCTL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

pub unsafe extern "C" fn new_ioctl(fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
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
        let bwr = &*(arg as *const binder_write_read);
        if bwr.write_size > 0 {
            parse_write_buffer(bwr.write_buffer as *mut c_void, bwr.write_size as u64);
        }
    }

    let ret = old_ioctl_fn(fd, request, arg);

    // If the system call failed, do NOT do anything that could clobber `errno`.
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
    let mut offset = 0;
    while offset < size {
        let cmd = std::ptr::read_unaligned(ptr as *const u32);
        ptr = ptr.add(4);
        offset += 4;

        let cmd_size = _ioc_size(cmd);
        let cmd_type = cmd & 0xFF;
        let dir = (cmd >> 30) & 3;
        let is_write = dir == 1;

        if is_write && (cmd_type == BC_TRANSACTION_NR || cmd_type == BC_REPLY_NR) {
            let tr = std::ptr::read_unaligned(ptr as *const binder_transaction_data);
            info!(
                "<<< [BinderInterceptor][pre] {} | target: {}, code: 0x{:x}, flags: 0x{:x}{}{}, data_size: {}, offsets_size: {}, parcel: {}",
                if cmd_type == BC_TRANSACTION_NR { "BC_TRANSACTION" } else { "BC_REPLY" },
                format_target(&tr),
                tr.code,
                tr.flags,
                if (tr.flags & TF_ONE_WAY) != 0 { ", oneway" } else { "" },
                if cmd_type == BC_REPLY_NR { ", reply" } else { "" },
                tr.data_size,
                tr.offsets_size,
                preview_transaction_parcel(&tr),
            );
        }

        ptr = ptr.add(cmd_size);
        offset += cmd_size as u64;
    }
}

unsafe fn parse_read_buffer(mut ptr: *mut c_void, size: u64) {
    let mut offset = 0;
    while offset < size {
        let cmd = std::ptr::read_unaligned(ptr as *const u32);
        ptr = ptr.add(4);
        offset += 4;

        let cmd_size = _ioc_size(cmd);
        let cmd_type = cmd & 0xFF;
        let dir = (cmd >> 30) & 3;
        let is_read = dir == 2;

        if is_read && (cmd_type == BR_TRANSACTION_NR || cmd_type == BR_REPLY_NR) {
            let tr = std::ptr::read_unaligned(ptr as *const binder_transaction_data);
            info!(
                ">>> [BinderInterceptor][post] {} | target: {}, code: 0x{:x}, sender_euid: {}, sender_pid: {}, flags: 0x{:x}{}{}, parcel_size: {}, offsets_size: {}, parcel: {}",
                if cmd_type == BR_TRANSACTION_NR { "BR_TRANSACTION" } else { "BR_REPLY" },
                format_target(&tr),
                tr.code,
                tr.sender_euid,
                tr.sender_pid,
                tr.flags,
                if (tr.flags & TF_ONE_WAY) != 0 { ", oneway" } else { "" },
                if cmd_type == BR_REPLY_NR { ", reply" } else { "" },
                tr.data_size,
                tr.offsets_size,
                preview_transaction_parcel(&tr),
            );
        }

        ptr = ptr.add(cmd_size);
        offset += cmd_size as u64;
    }
}

unsafe fn preview_transaction_parcel(tr: &binder_transaction_data) -> String {
    let data_size = tr.data_size as usize;
    if data_size == 0 {
        return "<empty>".to_string();
    }

    let buffer = tr.data.ptr.buffer as *const u8;
    if buffer.is_null() {
        return "<null>".to_string();
    }

    let preview_len = data_size.min(128);
    let bytes = std::slice::from_raw_parts(buffer, preview_len);
    let mut preview = String::new();

    for byte in bytes {
        for ch in byte.escape_ascii() {
            if preview.chars().count() >= PARCEL_PREVIEW_CHARS {
                preview.push('…');
                return preview;
            }
            preview.push(ch as char);
        }
    }

    if data_size > preview_len {
        preview.push('…');
    }

    if preview.is_empty() {
        "<binary>".to_string()
    } else {
        preview
    }
}

unsafe fn format_target(tr: &binder_transaction_data) -> String {
    let handle = tr.target.handle;
    if handle != 0 {
        format!("handle:{}", handle)
    } else {
        format!("ptr:0x{:x}", tr.target.ptr)
    }
}

fn _ioc_size(cmd: u32) -> usize {
    ((cmd >> 16) & 0x3FFF) as usize
}

pub fn init_hook() {
    info!("[BinderInterceptor] Initializing binder ioctl hook...");

    let maps = lsplt_rs::MapInfo::scan("self");
    let mut targets = Vec::new();

    for map in maps {
        if let Some(path) = &map.pathname {
            if path.ends_with("/libbinder.so")
                || path.ends_with("libbinder.so")
                || path.ends_with("/libhwbinder.so")
                || path.ends_with("libhwbinder.so")
            {
                info!(
                    "Found binder-related library for hook: {} (dev={}, inode={})",
                    path, map.dev, map.inode
                );
                targets.push((path.clone(), map.dev, map.inode));
            }
        }
    }

    if targets.is_empty() {
        error!("Could not find libbinder.so/libhwbinder.so in process maps");
        return;
    }

    let mut registered = 0usize;

    for (path, dev, inode) in targets {
        for symbol in ["ioctl", "__ioctl"] {
            let mut old_ptr: *mut c_void = std::ptr::null_mut();
            match lsplt_rs::register_hook(
                dev,
                inode,
                symbol,
                new_ioctl as *mut c_void,
                Some(&mut old_ptr),
            ) {
                Ok(_) => {
                    if !old_ptr.is_null() && OLD_IOCTL.load(Ordering::Relaxed).is_null() {
                        OLD_IOCTL.store(old_ptr, Ordering::SeqCst);
                    }
                    registered += 1;
                    info!("Registered hook for {} symbol {}", path, symbol);
                }
                Err(e) => {
                    warn!(
                        "Failed to register hook for {} symbol {}: {:?}",
                        path, symbol, e
                    );
                }
            }
        }
    }

    if registered == 0 {
        error!("Failed to register any binder ioctl hooks");
        return;
    }

    if let Err(e) = lsplt_rs::commit_hook() {
        error!("Failed to commit lsplt hook: {:?}", e);
    } else {
        info!("Successfully committed {} binder ioctl hook(s)", registered);
    }
}
