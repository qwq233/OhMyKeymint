use std::ffi::{c_char, CStr};
use std::mem::size_of;

use log::info;

const PARCEL_PREVIEW_CHARS: usize = 50;
const B_TYPE_LARGE: u32 = 0x85;

pub(crate) const BINDER_WRITE_READ: u32 = 0xc0306201;
pub(crate) const BC_TRANSACTION_NR: u32 = 0;
pub(crate) const BC_REPLY_NR: u32 = 1;
pub(crate) const BC_TRANSACTION_SG_NR: u32 = 17;
pub(crate) const BC_REPLY_SG_NR: u32 = 18;
pub(crate) const BR_TRANSACTION_NR: u32 = 2;
pub(crate) const BR_REPLY_NR: u32 = 3;
pub(crate) const TF_ONE_WAY: u32 = 0x01;
pub(crate) const BINDER_TYPE_BINDER: u32 = b_pack_chars(b's', b'b', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_WEAK_BINDER: u32 = b_pack_chars(b'w', b'b', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_HANDLE: u32 = b_pack_chars(b's', b'h', b'*', B_TYPE_LARGE as u8);
pub(crate) const BINDER_TYPE_WEAK_HANDLE: u32 = b_pack_chars(b'w', b'h', b'*', B_TYPE_LARGE as u8);

const fn b_pack_chars(c1: u8, c2: u8, c3: u8, c4: u8) -> u32 {
    ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_object_header {
    pub type_: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union flat_binder_object_handle_or_ptr {
    pub binder: libc::c_ulong,
    pub handle: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct flat_binder_object {
    pub hdr: binder_object_header,
    pub flags: u32,
    pub handle_or_ptr: flat_binder_object_handle_or_ptr,
    pub cookie: libc::c_ulong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LocalBinderTarget {
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
}

#[repr(C)]
pub(crate) struct binder_write_read {
    pub write_size: libc::size_t,
    pub write_consumed: libc::size_t,
    pub write_buffer: libc::c_ulong,
    pub read_size: libc::size_t,
    pub read_consumed: libc::size_t,
    pub read_buffer: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union binder_transaction_data_target {
    pub handle: u32,
    pub ptr: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union binder_transaction_data_data {
    pub ptr: binder_transaction_data_data_ptr,
    pub buf: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_data_ptr {
    pub buffer: libc::c_ulong,
    pub offsets: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data {
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

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_secctx {
    pub transaction_data: binder_transaction_data,
    pub secctx: libc::c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct binder_transaction_data_sg {
    pub transaction_data: binder_transaction_data,
    pub buffers_size: libc::size_t,
}

pub(crate) fn _ioc_dir(cmd: u32) -> u32 {
    (cmd >> 30) & 0x3
}

pub(crate) fn _ioc_nr(cmd: u32) -> u32 {
    cmd & 0xFF
}

pub(crate) fn _ioc_size(cmd: u32) -> usize {
    ((cmd >> 16) & 0x3FFF) as usize
}

pub(crate) unsafe fn parse_secctx_sid(secctx: libc::c_ulong) -> Option<String> {
    if secctx == 0 {
        return None;
    }

    let ptr = secctx as *const c_char;
    if ptr.is_null() {
        return None;
    }

    Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
}

pub(crate) unsafe fn log_write_transaction(command_name: &str, tr: &binder_transaction_data) {
    info!(
        "<<< [BinderInterceptor][pre] {} | target: {}, code: 0x{:x}, flags: 0x{:x}{}{}, data_size: {}, offsets_size: {}, parcel: {}",
        command_name,
        format_target(tr),
        tr.code,
        tr.flags,
        if (tr.flags & TF_ONE_WAY) != 0 { ", oneway" } else { "" },
        if command_name.contains("REPLY") { ", reply" } else { "" },
        tr.data_size,
        tr.offsets_size,
        preview_transaction_parcel(tr),
    );
}

pub(crate) unsafe fn preview_transaction_parcel(tr: &binder_transaction_data) -> String {
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

pub(crate) unsafe fn describe_transaction_objects(tr: &binder_transaction_data) -> String {
    let offsets_size = tr.offsets_size as usize;
    if offsets_size == 0 {
        return "[]".to_string();
    }

    let offsets_ptr = tr.data.ptr.offsets as *const usize;
    if offsets_ptr.is_null() {
        return "[<null offsets>]".to_string();
    }

    let count = offsets_size / size_of::<usize>();
    if count == 0 {
        return "[]".to_string();
    }

    let data_size = tr.data_size as usize;
    let offsets = std::slice::from_raw_parts(offsets_ptr, count);
    let bytes = match transaction_data_bytes(tr) {
        Some(bytes) => bytes,
        None => return "[<null data>]".to_string(),
    };

    let mut out = Vec::with_capacity(count);
    for &offset in offsets {
        let object_size = size_of::<flat_binder_object>();
        if offset > data_size || data_size.saturating_sub(offset) < object_size {
            out.push(format!("{{offset={}, invalid=true}}", offset));
            continue;
        }

        let object =
            std::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const flat_binder_object);
        let type_name = match object.hdr.type_ {
            BINDER_TYPE_BINDER => "BINDER",
            BINDER_TYPE_WEAK_BINDER => "WEAK_BINDER",
            BINDER_TYPE_HANDLE => "HANDLE",
            BINDER_TYPE_WEAK_HANDLE => "WEAK_HANDLE",
            other => {
                out.push(format!(
                    "{{offset={}, type=0x{:x}, flags=0x{:x}, handle_or_ptr=0x{:x}, cookie=0x{:x}}}",
                    offset, other, object.flags, object.handle_or_ptr.binder, object.cookie
                ));
                continue;
            }
        };

        let stability_offset = offset + object_size;
        let stability = if data_size.saturating_sub(stability_offset) >= size_of::<i32>() {
            Some(std::ptr::read_unaligned(
                bytes.as_ptr().add(stability_offset) as *const i32,
            ))
        } else {
            None
        };

        out.push(format!(
            "{{offset={}, type={}, flags=0x{:x}, handle=0x{:x}, ptr=0x{:x}, cookie=0x{:x}, stability={}}}",
            offset,
            type_name,
            object.flags,
            object.handle_or_ptr.handle,
            object.handle_or_ptr.binder,
            object.cookie,
            stability
                .map(|value| format!("0x{:x}", value))
                .unwrap_or_else(|| "<missing>".to_string())
        ));
    }

    format!("[{}]", out.join(", "))
}

pub(crate) unsafe fn format_target(tr: &binder_transaction_data) -> String {
    let handle = tr.target.handle;
    if handle != 0 {
        format!("handle:{}", handle)
    } else {
        format!("ptr:0x{:x}", tr.target.ptr)
    }
}

pub(crate) unsafe fn transaction_data_bytes<'a>(tr: &binder_transaction_data) -> Option<&'a [u8]> {
    let data_size = tr.data_size as usize;
    if data_size == 0 {
        return Some(&[]);
    }

    let buffer = tr.data.ptr.buffer as *const u8;
    if buffer.is_null() {
        return None;
    }

    Some(std::slice::from_raw_parts(buffer, data_size))
}

pub(crate) unsafe fn parse_local_binder_target_from_parcel_bytes(
    bytes: &[u8],
) -> Option<LocalBinderTarget> {
    if bytes.len() < size_of::<flat_binder_object>() {
        return None;
    }

    let object = std::ptr::read_unaligned(bytes.as_ptr() as *const flat_binder_object);
    if !matches!(
        object.hdr.type_,
        BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER
    ) {
        return None;
    }

    let ptr = object.handle_or_ptr.binder;
    if ptr == 0 || object.cookie == 0 {
        return None;
    }

    Some(LocalBinderTarget {
        ptr,
        cookie: object.cookie,
    })
}
