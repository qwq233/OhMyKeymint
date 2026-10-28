use crate::hook::binder::{flat_binder_object, BINDER_TYPE_FD};
use crate::identify::{
    KEYSTORE_AUTHORIZATION_INTERFACE, KEYSTORE_MAINTENANCE_INTERFACE, KEYSTORE_OPERATION_INTERFACE,
    KEYSTORE_SECURITY_LEVEL_INTERFACE, KEYSTORE_SERVICE_INTERFACE,
};
use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{Parcel, StatusCode};
use std::mem::size_of;

pub use reply::*;
pub use request::*;

mod reply;
mod request;
#[cfg(test)]
mod tests;

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn peek_request_interface(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<String> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_request_interface(&mut parcel)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_no_arg_request_interface(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<String> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    ensure_no_request_trailing_data(&parcel, "AIDL metadata")?;
    Ok(interface)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn parse_metadata_request_interface_allow_trailing(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<Option<String>> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_request_interface_for_check(&mut parcel)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn peek_request_interface_for_check(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<Option<String>> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_request_interface_for_check(&mut parcel)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder transaction parcel for the duration of this call.
pub unsafe fn validate_dump_request(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<()> {
    let object_size = size_of::<flat_binder_object>();
    if data_size < object_size {
        bail!("dump request is missing fd object");
    }
    if data.is_null() {
        bail!("dump request data pointer is null");
    }
    if offsets_size < size_of::<usize>() || offsets.is_null() {
        bail!("dump request is missing fd object offset");
    }
    if !offsets_size.is_multiple_of(size_of::<usize>()) {
        bail!("dump request offsets size is not aligned");
    }

    let first_offset = std::ptr::read_unaligned(offsets);
    if first_offset != 0 {
        bail!("dump request fd object is not first");
    }

    let object = std::ptr::read_unaligned(data as *const flat_binder_object);
    if object.hdr.type_ != BINDER_TYPE_FD {
        bail!("dump request first object is not a file descriptor");
    }

    // AOSP BBinder::onTransact lets readInt32() collapse a missing argc to 0
    // and best-effort reads dump args while data remains.
    Ok(())
}

pub fn contains_keystore_authorization_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_AUTHORIZATION_INTERFACE)
}

pub fn contains_keystore_maintenance_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_MAINTENANCE_INTERFACE)
}

pub fn contains_keystore_service_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_SERVICE_INTERFACE)
}

pub fn contains_keystore_security_level_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_SECURITY_LEVEL_INTERFACE)
}

pub fn contains_keystore_operation_interface(parcel: &[u8]) -> bool {
    contains_utf16_token(parcel, KEYSTORE_OPERATION_INTERFACE)
}

pub fn contains_known_keystore_interface(parcel: &[u8]) -> bool {
    crate::identify::KNOWN_KEYSTORE_INTERFACES
        .iter()
        .any(|interface| contains_utf16_token(parcel, interface))
}

fn read_request_interface(parcel: &mut Parcel) -> Result<String> {
    read_request_interface_for_check(parcel)?.ok_or_else(|| StatusCode::BadType.into())
}

fn read_request_interface_for_check(parcel: &mut Parcel) -> Result<Option<String>> {
    let _: i32 = parcel.read().context("missing strict mode header")?;
    let _: i32 = parcel.read().context("missing work source header")?;
    let marker: u32 = parcel.read().context("missing interface marker")?;
    if marker != rsbinder::INTERFACE_HEADER {
        return Ok(None);
    }
    parcel.read().context("missing interface token").map(Some)
}

fn ensure_no_request_trailing_data(parcel: &Parcel, interface_name: &str) -> Result<()> {
    let remaining = parcel.data_avail();
    if remaining != 0 {
        bail!("{interface_name} request has {remaining} trailing bytes");
    }
    Ok(())
}

struct RequestEnvelope {
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
    code: u32,
}

unsafe fn parse_typed_request<M>(
    envelope: RequestEnvelope,
    expected_interface: &str,
    interface_name: &str,
    method_from_code: impl FnOnce(u32) -> Option<M>,
) -> Result<(Parcel, M)> {
    let RequestEnvelope {
        data,
        data_size,
        offsets,
        offsets_size,
        code,
    } = envelope;
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    let interface = read_request_interface(&mut parcel)?;
    if interface != expected_interface {
        bail!("unexpected interface token: {}", interface);
    }

    let method = method_from_code(code)
        .ok_or_else(|| anyhow!("unknown {interface_name} transaction code {code}"))?;
    Ok((parcel, method))
}

unsafe fn parcel_from_ipc_parts(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Parcel {
    let data = if data_size == 0 {
        std::ptr::NonNull::<u8>::dangling().as_ptr()
    } else {
        data
    };
    let offsets = if offsets_size == 0 {
        std::ptr::NonNull::<usize>::dangling().as_ptr()
    } else {
        offsets
    };

    Parcel::from_ipc_parts(
        data,
        data_size,
        offsets as *mut u64,
        offsets_size / size_of::<usize>(),
        noop_free_buffer,
    )
}

fn noop_free_buffer(
    _parcel: Option<&Parcel>,
    _data: u64,
    _data_size: usize,
    _offsets: u64,
    _offsets_size: usize,
) -> rsbinder::Result<()> {
    Ok(())
}

fn contains_utf16_token(parcel: &[u8], token: &str) -> bool {
    let encoded: Vec<u8> = token
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    parcel
        .windows(encoded.len())
        .any(|window| window == encoded)
}
