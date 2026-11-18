use log::info;
use std::mem::size_of;

use binder::ext::driver;
pub(crate) use driver::{
    binder_transaction_data, binder_transaction_data_secctx, binder_transaction_data_sg,
    binder_version, binder_write_read, flat_binder_object, BINDER_TYPE_BINDER,
    BINDER_TYPE_WEAK_BINDER, BINDER_VERSION, BINDER_WRITE_READ, FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
    TF_ONE_WAY,
};

#[cfg(test)]
pub(in crate::hook) use native::create_native_security_level_binder;
pub(super) use native::local_binder_receiver;
pub(in crate::hook) use native::{
    create_receiver_binder, init_request_binders, receiver_proxy,
    register_synthetic_security_level_binder, remember_security_level_target,
    remember_system_dump_peer, retire_receivers, SyntheticTargetKind,
};

#[cfg(test)]
pub(in crate::hook) use native::tests::state_test_guard;

mod native;

pub(in crate::hook) const KEYSTORE_AUTHORIZATION_INTERFACE: &str =
    "android.security.authorization.IKeystoreAuthorization";
pub(in crate::hook) const KEYSTORE_MAINTENANCE_INTERFACE: &str =
    "android.security.maintenance.IKeystoreMaintenance";
pub(in crate::hook) const KEYSTORE_SERVICE_INTERFACE: &str =
    "android.system.keystore2.IKeystoreService";
pub(in crate::hook) const KEYSTORE_SECURITY_LEVEL_INTERFACE: &str =
    "android.system.keystore2.IKeystoreSecurityLevel";
pub(in crate::hook) const KEYSTORE_OPERATION_INTERFACE: &str =
    "android.system.keystore2.IKeystoreOperation";

const PARCEL_PREVIEW_CHARS: usize = 50;

#[cfg(test)]
use driver::{_IOC_NONE as IOC_NONE, _IOC_WRITE as IOC_WRITE};

#[cfg(test)]
const fn ioc(direction: u32, kind: u32, number: u32, size: usize) -> u32 {
    (direction << driver::_IOC_DIRSHIFT)
        | (kind << driver::_IOC_TYPESHIFT)
        | (number << driver::_IOC_NRSHIFT)
        | ((size as u32) << driver::_IOC_SIZESHIFT)
}

pub(crate) const BC_TRANSACTION_NR: u32 = _ioc_nr(driver::BC_TRANSACTION);
pub(crate) const BC_REPLY_NR: u32 = _ioc_nr(driver::BC_REPLY);
pub(crate) const BC_TRANSACTION_SG_NR: u32 = _ioc_nr(driver::BC_TRANSACTION_SG);
pub(crate) const BC_REPLY_SG_NR: u32 = _ioc_nr(driver::BC_REPLY_SG);
pub(crate) const BR_TRANSACTION_NR: u32 = _ioc_nr(driver::BR_TRANSACTION);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LocalBinderTarget {
    pub ptr: libc::c_ulong,
    pub cookie: libc::c_ulong,
}

pub(crate) fn _ioc_dir(cmd: u32) -> u32 {
    (cmd >> driver::_IOC_DIRSHIFT) & driver::_IOC_DIRMASK
}

pub(crate) const fn _ioc_nr(cmd: u32) -> u32 {
    (cmd >> driver::_IOC_NRSHIFT) & driver::_IOC_NRMASK
}

pub(crate) fn _ioc_size(cmd: u32) -> usize {
    ((cmd >> driver::_IOC_SIZESHIFT) & driver::_IOC_SIZEMASK) as usize
}

pub(crate) unsafe fn log_write_transaction(command_name: &str, tr: &binder_transaction_data) {
    info!(
        "<<< {} | target: {}, code: 0x{:x}, flags: 0x{:x}{}{}, data_size: {}, offsets_size: {}, parcel: {}",
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

    let mut preview_bytes = [0_u8; 128];
    let preview_len = data_size.min(preview_bytes.len());
    let bytes = &mut preview_bytes[..preview_len];
    if crate::sys::read_process_exact(nix::unistd::Pid::this(), buffer as usize, bytes).is_err() {
        return "<unreadable>".to_string();
    }
    let mut escaped = bytes.iter().flat_map(|byte| byte.escape_ascii());
    let mut preview: String = escaped.by_ref().take(PARCEL_PREVIEW_CHARS).map(char::from).collect();
    if escaped.next().is_some() || data_size > preview_len {
        preview.push('…');
    }
    preview
}

pub(crate) unsafe fn format_target(tr: &binder_transaction_data) -> String {
    let handle = tr.target.handle;
    if handle != 0 {
        format!("handle:{}", handle)
    } else {
        format!("ptr:0x{:x}", tr.target.ptr)
    }
}

pub(crate) unsafe fn parse_local_binder_target_from_parcel_bytes(
    bytes: &[u8],
) -> Option<LocalBinderTarget> {
    if bytes.len() < size_of::<flat_binder_object>() {
        return None;
    }

    let object = std::ptr::read_unaligned(bytes.as_ptr() as *const flat_binder_object);
    if !matches!(object.hdr.type_, BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER) {
        return None;
    }

    let ptr = object.__bindgen_anon_1.binder;
    if ptr == 0 || object.cookie == 0 {
        return None;
    }

    Some(LocalBinderTarget { ptr, cookie: object.cookie })
}

#[cfg(test)]
pub(super) mod tests {
    use super::{binder_transaction_data, BC_REPLY_NR, IOC_NONE, IOC_WRITE};
    use std::mem;

    const BR_NOOP_NR: u32 = 12;

    pub(in crate::hook) const BR_NOOP_CMD: u32 = super::ioc(IOC_NONE, b'r' as u32, BR_NOOP_NR, 0);

    pub(in crate::hook) const BC_FREE_BUFFER_CMD: u32 = super::driver::BC_FREE_BUFFER;

    pub(in crate::hook) const BC_REPLY_CMD: u32 =
        super::ioc(IOC_WRITE, b'c' as u32, BC_REPLY_NR, mem::size_of::<binder_transaction_data>());
}
