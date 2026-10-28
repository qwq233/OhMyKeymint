use super::parcel_from_ipc_parts;
use crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse;
use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation;
use crate::android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::KeyParameters::KeyParameters;
use crate::android::system::keystore2::OperationChallenge::OperationChallenge;
use crate::hook::binder::{
    binder_object_header, flat_binder_object, flat_binder_object_handle_or_ptr,
    NativeBinderRetirement, BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE, BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_WEAK_HANDLE,
};
use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{
    Deserialize, FromIBinder, Parcel, Serialize, SerializeOption, Status, StatusCode, Strong,
    NON_NULL_PARCELABLE_FLAG,
};
use std::mem::size_of;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct OwnedReply {
    data: Vec<u8>,
    _parcel: Parcel,
    pub offsets: Box<[usize]>,
    pub(crate) native_operation: Option<NativeBinderRetirement>,
}

impl OwnedReply {
    pub fn data_size(&self) -> usize {
        self.data.len()
    }

    pub fn offsets_size(&self) -> usize {
        self.offsets.len() * size_of::<usize>()
    }

    pub fn data_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl Drop for OwnedReply {
    fn drop(&mut self) {
        if let Some(retirement) = self.native_operation.take() {
            crate::hook::rewrite::drop_synthetic_operation_retirement(retirement);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplyBinderCarrier {
    pub bytes: Vec<u8>,
    pub is_object: bool,
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_success_reply<T: Deserialize>(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<T> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    parcel.read().context("failed to decode reply payload")
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_reply_status(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<Status> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    parcel.read().context("failed to decode binder status")
}

pub fn parse_owned_success_reply<T: Deserialize>(reply: &mut OwnedReply) -> Result<T> {
    unsafe {
        parse_success_reply(
            reply.data_mut_ptr(),
            reply.data_size(),
            if reply.offsets.is_empty() {
                std::ptr::null_mut()
            } else {
                reply.offsets.as_mut_ptr()
            },
            reply.offsets_size(),
        )
    }
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_direct_binder_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_reply_binder_carrier(&mut parcel, data)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_key_entry_reply(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<(
    ReplyBinderCarrier,
    crate::android::system::keystore2::KeyMetadata::KeyMetadata,
)> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;
    read_sized_reply_payload(&mut parcel, "key-entry payload", |sub_parcel| {
        let carrier = read_reply_binder_carrier(sub_parcel, data)?;
        let metadata = sub_parcel
            .read()
            .context("failed to decode key-entry metadata payload")?;
        Ok((carrier, metadata))
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_create_operation_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "create-operation")?;
    read_sized_reply_payload(
        &mut parcel,
        "create-operation binder carrier",
        |sub_parcel| read_reply_binder_carrier(sub_parcel, data),
    )
}

pub fn build_get_security_level_reply_with_carrier_bytes(
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    let start = parcel.data_position();
    let (placeholder_start, end) =
        write_none_binder_placeholder::<dyn IKeystoreSecurityLevel>(&mut parcel)?;
    debug_assert_eq!(start, placeholder_start);
    let binder_len = end - start;
    if carrier_bytes.len() != binder_len {
        bail!(
            "get-security-level carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }

    let mut data = parcel_bytes(&mut parcel)?;
    data[start..end].copy_from_slice(carrier_bytes);
    Ok(owned_reply_from_bytes(
        parcel,
        data,
        carrier_is_object.then_some(start),
    ))
}

pub fn build_interface_descriptor_reply(descriptor: &str) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&descriptor.to_string())?;
    let data = parcel_bytes(&mut parcel)?;
    Ok(owned_reply_from_bytes(
        parcel,
        data,
        std::iter::empty::<usize>(),
    ))
}

pub fn build_empty_reply() -> OwnedReply {
    owned_reply_from_bytes(Parcel::new(), Vec::new(), std::iter::empty::<usize>())
}

pub fn build_raw_i32_reply(value: i32) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&value)?;
    let data = parcel_bytes(&mut parcel)?;
    Ok(owned_reply_from_bytes(
        parcel,
        data,
        std::iter::empty::<usize>(),
    ))
}

pub fn build_null_binder_reply() -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    let binder: Option<rsbinder::SIBinder> = None;
    parcel.write(&binder)?;
    let data = parcel_bytes(&mut parcel)?;
    Ok(owned_reply_from_bytes(
        parcel,
        data,
        std::iter::empty::<usize>(),
    ))
}

pub fn build_local_binder_carrier_bytes(
    ptr: libc::c_ulong,
    cookie: libc::c_ulong,
    flags: u32,
    stability: i32,
) -> Vec<u8> {
    let object = flat_binder_object {
        hdr: binder_object_header {
            type_: BINDER_TYPE_BINDER,
        },
        flags,
        handle_or_ptr: flat_binder_object_handle_or_ptr { binder: ptr },
        cookie,
    };
    let mut bytes = vec![0u8; size_of::<flat_binder_object>() + size_of::<i32>()];
    unsafe {
        std::ptr::write_unaligned(bytes.as_mut_ptr() as *mut flat_binder_object, object);
        std::ptr::write_unaligned(
            bytes.as_mut_ptr().add(size_of::<flat_binder_object>()) as *mut i32,
            stability,
        );
    }
    bytes
}

fn build_sized_parcelable_reply(
    write_payload: impl FnOnce(&mut Parcel, &mut Option<usize>) -> rsbinder::Result<()>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    parcel.sized_write(|sub_parcel| write_payload(sub_parcel, &mut binder_offset))?;
    let data = parcel_bytes(&mut parcel)?;
    Ok(owned_reply_from_bytes(parcel, data, binder_offset))
}

pub fn build_key_entry_reply(reply: KeyEntryResponse) -> Result<OwnedReply> {
    let KeyEntryResponse {
        r#iSecurityLevel,
        r#metadata,
    } = reply;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        match r#iSecurityLevel.as_ref() {
            Some(binder) => {
                *binder_offset = Some(sub_parcel.data_position());
                sub_parcel.write(&Some(binder.clone()))?;
            }
            None => {
                let none: Option<Strong<dyn IKeystoreSecurityLevel>> = None;
                sub_parcel.write(&none)?;
            }
        }
        sub_parcel.write(&r#metadata)?;
        Ok(())
    })
}

pub fn build_key_entry_reply_with_carrier_bytes(
    metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "key-entry",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreSecurityLevel>(sub_parcel)?;
            sub_parcel.write(&metadata)?;
            Ok(span)
        },
    )
}

pub fn build_create_operation_reply(reply: CreateOperationResponse) -> Result<OwnedReply> {
    let CreateOperationResponse {
        r#iOperation,
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
    } = reply;
    let operation = r#iOperation.as_ref().ok_or(StatusCode::UnexpectedNull)?;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        *binder_offset = Some(sub_parcel.data_position());
        sub_parcel.write(operation)?;
        sub_parcel.write(&r#operationChallenge)?;
        sub_parcel.write(&r#parameters)?;
        sub_parcel.write(&r#upgradedBlob)?;
        Ok(())
    })
}

pub fn build_create_operation_reply_with_carrier_bytes(
    operation_challenge: Option<OperationChallenge>,
    parameters: Option<KeyParameters>,
    upgraded_blob: Option<Vec<u8>>,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "create-operation",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreOperation>(sub_parcel)?;
            sub_parcel.write(&operation_challenge)?;
            sub_parcel.write(&parameters)?;
            sub_parcel.write(&upgraded_blob)?;
            Ok(span)
        },
    )
}

pub fn build_plain_reply<T: Serialize>(value: &T) -> Result<OwnedReply> {
    struct PlainReply<'a, T>(&'a T);
    impl<T: Serialize> Serialize for PlainReply<'_, T> {
        fn serialize(&self, parcel: &mut Parcel) -> rsbinder::Result<()> {
            parcel.write(&Status::from(StatusCode::Ok))?;
            parcel.write(self.0)
        }
    }
    let data = rsbinder::to_bytes(&PlainReply(value))?;
    Ok(owned_reply_from_bytes(
        Parcel::with_capacity(0),
        data,
        std::iter::empty::<usize>(),
    ))
}

pub fn build_void_reply() -> Result<OwnedReply> {
    build_status_reply(&Status::from(StatusCode::Ok))
}

pub fn build_status_reply(status: &Status) -> Result<OwnedReply> {
    let data = rsbinder::to_bytes(status)?;
    Ok(owned_reply_from_bytes(
        Parcel::with_capacity(0),
        data,
        std::iter::empty::<usize>(),
    ))
}

fn owned_reply_from_bytes(
    parcel: Parcel,
    data: Vec<u8>,
    offsets: impl IntoIterator<Item = usize>,
) -> OwnedReply {
    OwnedReply {
        _parcel: parcel,
        data,
        offsets: offsets.into_iter().collect(),
        native_operation: None,
    }
}

fn parcel_bytes(parcel: &mut Parcel) -> Result<Vec<u8>> {
    let original_position = parcel.data_position();
    let len = {
        parcel.set_data_position(0);
        parcel.data_size()
    };
    if !len.is_multiple_of(size_of::<u32>()) {
        parcel.set_data_position(original_position);
        bail!("binder parcel length {len} is not word-aligned");
    }

    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let chunk: [u8; 4] = parcel
            .try_into()
            .map_err(|error| anyhow!("failed to copy binder parcel bytes: {error}"))?;
        bytes.extend_from_slice(&chunk);
    }
    parcel.set_data_position(original_position);
    Ok(bytes)
}

fn read_ok_status(parcel: &mut Parcel) -> Result<()> {
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    Ok(())
}

fn read_non_null_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<()> {
    let flag: i32 = parcel
        .read()
        .with_context(|| format!("failed to decode {label} parcelable flag"))?;
    if flag != NON_NULL_PARCELABLE_FLAG {
        bail!("unexpected {label} parcelable flag: {flag}");
    }
    Ok(())
}

fn read_sized_reply_payload<T>(
    parcel: &mut Parcel,
    label: &str,
    mut read_payload: impl FnMut(&mut Parcel) -> Result<T>,
) -> Result<T> {
    let mut value = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_payload(sub_parcel) {
            Ok(payload) => value = Some(payload),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    value.ok_or_else(|| anyhow!("missing {label}"))
}

fn read_reply_binder_carrier(parcel: &mut Parcel, base: *mut u8) -> Result<ReplyBinderCarrier> {
    let start = parcel.data_position();
    let binder_len = size_of::<flat_binder_object>() + size_of::<i32>();
    let end = start
        .checked_add(binder_len)
        .ok_or_else(|| anyhow!("binder carrier length overflow"))?;
    if end > parcel.data_size() {
        bail!(
            "binder carrier truncated: end {} exceeds parcel size {}",
            end,
            parcel.data_size()
        );
    }

    let flat = unsafe { std::ptr::read_unaligned(base.add(start) as *const flat_binder_object) };
    parcel.set_data_position(end);

    let bytes = unsafe { std::slice::from_raw_parts(base.add(start), end - start) }.to_vec();
    Ok(ReplyBinderCarrier {
        bytes,
        is_object: binder_carrier_is_object(&flat),
    })
}

fn binder_carrier_is_object(flat: &flat_binder_object) -> bool {
    match flat.hdr.type_ {
        BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER => unsafe {
            flat.handle_or_ptr.binder != 0 && flat.cookie != 0
        },
        BINDER_TYPE_HANDLE | BINDER_TYPE_WEAK_HANDLE => unsafe { flat.handle_or_ptr.handle != 0 },
        _ => false,
    }
}

fn build_parcelable_reply_with_carrier_bytes(
    label: &str,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
    write_body: impl FnOnce(&mut Parcel) -> rsbinder::Result<(usize, usize)>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut span = None;
    parcel.sized_write(|sub_parcel| {
        span = Some(write_body(sub_parcel)?);
        Ok(())
    })?;
    let Some((start, end)) = span else {
        bail!("{label} carrier binder span was not recorded");
    };
    let binder_len = end - start;
    if carrier_bytes.len() != binder_len {
        bail!(
            "{label} carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }

    let mut data = parcel_bytes(&mut parcel)?;
    data[start..end].copy_from_slice(carrier_bytes);
    Ok(owned_reply_from_bytes(
        parcel,
        data,
        carrier_is_object.then_some(start),
    ))
}

fn write_none_binder_placeholder<T>(parcel: &mut Parcel) -> rsbinder::Result<(usize, usize)>
where
    T: FromIBinder + SerializeOption + ?Sized,
{
    let none: Option<Strong<T>> = None;
    let start = parcel.data_position();
    parcel.write(&none)?;
    let end = parcel.data_position();
    Ok((start, end))
}
