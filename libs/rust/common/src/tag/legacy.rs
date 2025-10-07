// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helper functionality for working with legacy tag serialization.

use crate::{km_err, try_to_vec, vec_try, vec_try_with_capacity, Error, FallibleAllocExt};
use core::cmp::Ordering;
use core::convert::{TryFrom, TryInto};
use kmr_wire::{
    keymint::{
        Algorithm, BlockMode, DateTime, Digest, EcCurve, KeyOrigin, KeyParam, KeyPurpose,
        PaddingMode, Tag,
    },
    KeySizeInBits, RsaExponent,
};

/// Retrieve a `u8` from the start of the given slice, if possible.
pub fn consume_u8(data: &mut &[u8]) -> Result<u8, Error> {
    match data.first() {
        Some(b) => {
            *data = &(*data)[1..];
            Ok(*b)
        }
        None => Err(km_err!(InvalidKeyBlob, "failed to find 1 byte")),
    }
}

/// Move past a bool value from the start of the given slice, if possible.
/// Bool values should only be included if `true`, so fail if the value
/// is anything other than 1.
pub fn consume_bool(data: &mut &[u8]) -> Result<(), Error> {
    let b = consume_u8(data)?;
    if b == 0x01 {
        Ok(())
    } else {
        Err(km_err!(
            InvalidKeyBlob,
            "bool value other than 1 encountered"
        ))
    }
}

/// Retrieve a (host-ordered) `u32` from the start of the given slice, if possible.
pub fn consume_u32(data: &mut &[u8]) -> Result<u32, Error> {
    if data.len() < 4 {
        return Err(km_err!(InvalidKeyBlob, "failed to find 4 bytes"));
    }
    let chunk: [u8; 4] = data[..4].try_into().unwrap(); // safe: just checked
    *data = &(*data)[4..];
    Ok(u32::from_ne_bytes(chunk))
}

/// Retrieve a (host-ordered) `i32` from the start of the given slice, if possible.
pub fn consume_i32(data: &mut &[u8]) -> Result<i32, Error> {
    if data.len() < 4 {
        return Err(km_err!(InvalidKeyBlob, "failed to find 4 bytes"));
    }
    let chunk: [u8; 4] = data[..4].try_into().unwrap(); // safe: just checked
    *data = &(*data)[4..];
    Ok(i32::from_ne_bytes(chunk))
}

/// Retrieve a (host-ordered) `u64` from the start of the given slice, if possible.
pub fn consume_u64(data: &mut &[u8]) -> Result<u64, Error> {
    if data.len() < 8 {
        return Err(km_err!(InvalidKeyBlob, "failed to find 8 bytes"));
    }
    let chunk: [u8; 8] = data[..8].try_into().unwrap(); // safe: just checked
    *data = &(*data)[8..];
    Ok(u64::from_ne_bytes(chunk))
}

/// Retrieve a (host-ordered) `i64` from the start of the given slice, if possible.
pub fn consume_i64(data: &mut &[u8]) -> Result<i64, Error> {
    if data.len() < 8 {
        return Err(km_err!(InvalidKeyBlob, "failed to find 8 bytes"));
    }
    let chunk: [u8; 8] = data[..8].try_into().unwrap(); // safe: just checked
    *data = &(*data)[8..];
    Ok(i64::from_ne_bytes(chunk))
}

/// Retrieve a vector of bytes from the start of the given slice, if possible,
/// with the length of the data is expected to appear as a host-ordered `u32` prefix.
pub fn consume_vec(data: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let len = consume_u32(data)? as usize;
    if len > data.len() {
        return Err(km_err!(InvalidKeyBlob, "failed to find {} bytes", len));
    }
    let result = try_to_vec(&data[..len])?;
    *data = &(*data)[len..];
    Ok(result)
}

/// Serialize a collection of [`KeyParam`]s into a format that is compatible with previous
/// implementations:
///
/// ```text
/// [0..4]              Size B of `TagType::Bytes` data, in host order.
/// [4..4+B]      (*)   Concatenated contents of each `TagType::Bytes` tag.
/// [4+B..4+B+4]        Count N of the number of parameters, in host order.
/// [8+B..8+B+4]        Size Z of encoded parameters.
/// [12+B..12+B+Z]      Serialized parameters one after another.
/// ```
///
/// Individual parameters are serialized in the last chunk as:
///
/// ```text
/// [0..4]              Tag number, in host order.
/// Followed by one of the following depending on the tag's `TagType`; all integers in host order:
///   [4..5]            Bool value (`TagType::Bool`)
///   [4..8]            i32 values (`TagType::Uint[Rep]`, `TagType::Enum[Rep]`)
///   [4..12]           i64 values, in host order (`TagType::UlongRep`, `TagType::Date`)
///   [4..8] + [8..12]  Size + offset of data in (*) above (`TagType::Bytes`, `TagType::Bignum`)
/// ```
pub fn serialize(params: &[KeyParam]) -> Result<Vec<u8>, Error> {
    // First 4 bytes are the length of the combined [`TagType::Bytes`] data; come back to set that
    // in a moment.
    let mut result = vec_try![0; 4]?;

    // Next append the contents of all of the [`TagType::Bytes`] data.
    let mut blob_size = 0u32;
    for param in params {
        match param {
            // Variants that hold `Vec<u8>`.
            KeyParam::ApplicationId(v)
            | KeyParam::ApplicationData(v)
            | KeyParam::AttestationChallenge(v)
            | KeyParam::AttestationApplicationId(v)
            | KeyParam::AttestationIdBrand(v)
            | KeyParam::AttestationIdDevice(v)
            | KeyParam::AttestationIdProduct(v)
            | KeyParam::AttestationIdSerial(v)
            | KeyParam::AttestationIdImei(v)
            | KeyParam::AttestationIdSecondImei(v)
            | KeyParam::AttestationIdMeid(v)
            | KeyParam::AttestationIdManufacturer(v)
            | KeyParam::AttestationIdModel(v)
            | KeyParam::Nonce(v)
            | KeyParam::RootOfTrust(v)
            | KeyParam::CertificateSerial(v)
            | KeyParam::CertificateSubject(v)
            | KeyParam::ModuleHash(v) => {
                result.try_extend_from_slice(v)?;
                blob_size += v.len() as u32;
            }
            _ => {}
        }
    }
    // Go back and fill in the combined blob length in native order at the start.
    result[..4].clone_from_slice(&blob_size.to_ne_bytes());

    result.try_extend_from_slice(&(params.len() as u32).to_ne_bytes())?;

    let params_size_offset = result.len();
    result.try_extend_from_slice(&[0u8; 4])?; // placeholder for size of elements
    let first_param_offset = result.len();
    let mut blob_offset = 0u32;
    for param in params {
        result.try_extend_from_slice(&(param.tag() as u32).to_ne_bytes())?;
        match &param {
            // Enum-holding variants.
            KeyParam::Purpose(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::Algorithm(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::BlockMode(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::Digest(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::Padding(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::EcCurve(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,
            KeyParam::RsaOaepMgfDigest(v) => {
                result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?
            }
            KeyParam::Origin(v) => result.try_extend_from_slice(&(*v as u32).to_ne_bytes())?,

            // `u32`-holding variants.
            KeyParam::KeySize(v) => result.try_extend_from_slice(&(v.0).to_ne_bytes())?,
            KeyParam::MinMacLength(v)
            | KeyParam::MaxUsesPerBoot(v)
            | KeyParam::UsageCountLimit(v)
            | KeyParam::UserId(v)
            | KeyParam::UserAuthType(v)
            | KeyParam::AuthTimeout(v)
            | KeyParam::OsVersion(v)
            | KeyParam::OsPatchlevel(v)
            | KeyParam::VendorPatchlevel(v)
            | KeyParam::BootPatchlevel(v)
            | KeyParam::MacLength(v)
            | KeyParam::MaxBootLevel(v) => result.try_extend_from_slice(&v.to_ne_bytes())?,

            // `u64`-holding variants.
            KeyParam::RsaPublicExponent(v) => result.try_extend_from_slice(&(v.0).to_ne_bytes())?,
            KeyParam::UserSecureId(v) => result.try_extend_from_slice(&(*v).to_ne_bytes())?,

            // `true`-holding variants.
            KeyParam::CallerNonce
            | KeyParam::IncludeUniqueId
            | KeyParam::BootloaderOnly
            | KeyParam::RollbackResistance
            | KeyParam::EarlyBootOnly
            | KeyParam::AllowWhileOnBody
            | KeyParam::NoAuthRequired
            | KeyParam::TrustedUserPresenceRequired
            | KeyParam::TrustedConfirmationRequired
            | KeyParam::UnlockedDeviceRequired
            | KeyParam::DeviceUniqueAttestation
            | KeyParam::StorageKey
            | KeyParam::ResetSinceIdRotation => result.try_push(0x01u8)?,

            // `DateTime`-holding variants.
            KeyParam::ActiveDatetime(v)
            | KeyParam::OriginationExpireDatetime(v)
            | KeyParam::UsageExpireDatetime(v)
            | KeyParam::CreationDatetime(v)
            | KeyParam::CertificateNotBefore(v)
            | KeyParam::CertificateNotAfter(v) => {
                result.try_extend_from_slice(&(v.ms_since_epoch as u64).to_ne_bytes())?
            }

            // `Vec<u8>`-holding variants.
            KeyParam::ApplicationId(v)
            | KeyParam::ApplicationData(v)
            | KeyParam::AttestationChallenge(v)
            | KeyParam::AttestationApplicationId(v)
            | KeyParam::AttestationIdBrand(v)
            | KeyParam::AttestationIdDevice(v)
            | KeyParam::AttestationIdProduct(v)
            | KeyParam::AttestationIdSerial(v)
            | KeyParam::AttestationIdImei(v)
            | KeyParam::AttestationIdSecondImei(v)
            | KeyParam::AttestationIdMeid(v)
            | KeyParam::AttestationIdManufacturer(v)
            | KeyParam::AttestationIdModel(v)
            | KeyParam::Nonce(v)
            | KeyParam::RootOfTrust(v)
            | KeyParam::CertificateSerial(v)
            | KeyParam::CertificateSubject(v)
            | KeyParam::ModuleHash(v) => {
                let blob_len = v.len() as u32;
                result.try_extend_from_slice(&blob_len.to_ne_bytes())?;
                result.try_extend_from_slice(&blob_offset.to_ne_bytes())?;
                blob_offset += blob_len;
            }
        }
    }
    let serialized_size = (result.len() - first_param_offset) as u32;

    // Go back and fill in the total serialized size.
    result[params_size_offset..params_size_offset + 4]
        .clone_from_slice(&serialized_size.to_ne_bytes());
    Ok(result)
}

/// Retrieve the contents of a tag of `TagType::Bytes`.  The `data` parameter holds
/// the as-yet unparsed data, and a length and offset are read from this (and consumed).
/// This length and offset refer to a location in the combined `blob_data`; however,
/// the offset is expected to be the next unconsumed chunk of `blob_data`, as indicated
/// by `next_blob_offset` (which itself is updated as a result of consuming the data).
fn consume_blob(
    data: &mut &[u8],
    next_blob_offset: &mut usize,
    blob_data: &[u8],
) -> Result<Vec<u8>, Error> {
    let data_len = consume_u32(data)? as usize;
    let data_offset = consume_u32(data)? as usize;
    // Expect the blob data to come from the next offset in the initial blob chunk.
    if data_offset != *next_blob_offset {
        return Err(km_err!(
            InvalidKeyBlob,
            "got blob offset {} instead of {}",
            data_offset,
            next_blob_offset
        ));
    }
    if (data_offset + data_len) > blob_data.len() {
        return Err(km_err!(
            InvalidKeyBlob,
            "blob at offset [{}..{}+{}] goes beyond blob data size {}",
            data_offset,
            data_offset,
            data_len,
            blob_data.len(),
        ));
    }

    let slice = &blob_data[data_offset..data_offset + data_len];
    *next_blob_offset += data_len;
    try_to_vec(slice)
}

/// Deserialize a collection of [`KeyParam`]s in legacy serialized format. The provided slice is
/// modified to contain the unconsumed part of the data.
pub fn deserialize(data: &mut &[u8]) -> Result<Vec<KeyParam>, Error> {
    let blob_data_size = consume_u32(data)? as usize;

    let blob_data = &data[..blob_data_size];
    let mut next_blob_offset = 0;

    // Move past the blob data.
    *data = &data[blob_data_size..];

    let param_count = consume_u32(data)? as usize;
    let param_size = consume_u32(data)? as usize;
    if param_size > data.len() {
        return Err(km_err!(
            InvalidKeyBlob,
            "size mismatch 4+{}+4+4+{} > {}",
            blob_data_size,
            param_size,
            data.len()
        ));
    }

    let mut results = vec_try_with_capacity!(param_count)?;
    for _i in 0..param_count {
        let tag_num = consume_u32(data)? as i32;
        let tag = <Tag>::try_from(tag_num)
            .map_err(|_e| km_err!(InvalidKeyBlob, "unknown tag {} encountered", tag_num))?;
        let enum_err = |_e| km_err!(InvalidKeyBlob, "unknown enum value for {:?}", tag);
        results.try_push(match tag {
            // Enum-holding variants.
            Tag::Purpose => {
                KeyParam::Purpose(<KeyPurpose>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::Algorithm => {
                KeyParam::Algorithm(<Algorithm>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::BlockMode => {
                KeyParam::BlockMode(<BlockMode>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::Digest => {
                KeyParam::Digest(<Digest>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::Padding => {
                KeyParam::Padding(<PaddingMode>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::EcCurve => {
                KeyParam::EcCurve(<EcCurve>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }
            Tag::RsaOaepMgfDigest => KeyParam::RsaOaepMgfDigest(
                <Digest>::try_from(consume_i32(data)?).map_err(enum_err)?,
            ),
            Tag::Origin => {
                KeyParam::Origin(<KeyOrigin>::try_from(consume_i32(data)?).map_err(enum_err)?)
            }

            // `u32`-holding variants.
            Tag::KeySize => KeyParam::KeySize(KeySizeInBits(consume_u32(data)?)),
            Tag::MinMacLength => KeyParam::MinMacLength(consume_u32(data)?),
            Tag::MaxUsesPerBoot => KeyParam::MaxUsesPerBoot(consume_u32(data)?),
            Tag::UsageCountLimit => KeyParam::UsageCountLimit(consume_u32(data)?),
            Tag::UserId => KeyParam::UserId(consume_u32(data)?),
            Tag::UserAuthType => KeyParam::UserAuthType(consume_u32(data)?),
            Tag::AuthTimeout => KeyParam::AuthTimeout(consume_u32(data)?),
            Tag::OsVersion => KeyParam::OsVersion(consume_u32(data)?),
            Tag::OsPatchlevel => KeyParam::OsPatchlevel(consume_u32(data)?),
            Tag::VendorPatchlevel => KeyParam::VendorPatchlevel(consume_u32(data)?),
            Tag::BootPatchlevel => KeyParam::BootPatchlevel(consume_u32(data)?),
            Tag::MacLength => KeyParam::MacLength(consume_u32(data)?),
            Tag::MaxBootLevel => KeyParam::MaxBootLevel(consume_u32(data)?),

            // `u64`-holding variants.
            Tag::RsaPublicExponent => KeyParam::RsaPublicExponent(RsaExponent(consume_u64(data)?)),
            Tag::UserSecureId => KeyParam::UserSecureId(consume_u64(data)?),

            // `true`-holding variants.
            Tag::CallerNonce => {
                consume_bool(data)?;
                KeyParam::CallerNonce
            }
            Tag::IncludeUniqueId => {
                consume_bool(data)?;
                KeyParam::IncludeUniqueId
            }
            Tag::BootloaderOnly => {
                consume_bool(data)?;
                KeyParam::BootloaderOnly
            }
            Tag::RollbackResistance => {
                consume_bool(data)?;
                KeyParam::RollbackResistance
            }
            Tag::EarlyBootOnly => {
                consume_bool(data)?;
                KeyParam::EarlyBootOnly
            }
            Tag::AllowWhileOnBody => {
                consume_bool(data)?;
                KeyParam::AllowWhileOnBody
            }
            Tag::NoAuthRequired => {
                consume_bool(data)?;
                KeyParam::NoAuthRequired
            }
            Tag::TrustedUserPresenceRequired => {
                consume_bool(data)?;
                KeyParam::TrustedUserPresenceRequired
            }
            Tag::TrustedConfirmationRequired => {
                consume_bool(data)?;
                KeyParam::TrustedConfirmationRequired
            }
            Tag::UnlockedDeviceRequired => {
                consume_bool(data)?;
                KeyParam::UnlockedDeviceRequired
            }
            Tag::DeviceUniqueAttestation => {
                consume_bool(data)?;
                KeyParam::DeviceUniqueAttestation
            }
            Tag::StorageKey => {
                consume_bool(data)?;
                KeyParam::StorageKey
            }
            Tag::ResetSinceIdRotation => {
                consume_bool(data)?;
                KeyParam::ResetSinceIdRotation
            }

            // `DateTime`-holding variants.
            Tag::ActiveDatetime => KeyParam::ActiveDatetime(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),
            Tag::OriginationExpireDatetime => KeyParam::OriginationExpireDatetime(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),
            Tag::UsageExpireDatetime => KeyParam::UsageExpireDatetime(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),
            Tag::CreationDatetime => KeyParam::CreationDatetime(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),
            Tag::CertificateNotBefore => KeyParam::CertificateNotBefore(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),
            Tag::CertificateNotAfter => KeyParam::CertificateNotAfter(DateTime {
                ms_since_epoch: consume_i64(data)?,
            }),

            // `Vec<u8>`-holding variants.
            Tag::ApplicationId => {
                KeyParam::ApplicationId(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::ApplicationData => {
                KeyParam::ApplicationData(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationChallenge => KeyParam::AttestationChallenge(consume_blob(
                data,
                &mut next_blob_offset,
                blob_data,
            )?),
            Tag::AttestationApplicationId => KeyParam::AttestationApplicationId(consume_blob(
                data,
                &mut next_blob_offset,
                blob_data,
            )?),
            Tag::AttestationIdBrand => {
                KeyParam::AttestationIdBrand(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationIdDevice => {
                KeyParam::AttestationIdDevice(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationIdProduct => KeyParam::AttestationIdProduct(consume_blob(
                data,
                &mut next_blob_offset,
                blob_data,
            )?),
            Tag::AttestationIdSerial => {
                KeyParam::AttestationIdSerial(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationIdImei => {
                KeyParam::AttestationIdImei(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationIdSecondImei => KeyParam::AttestationIdSecondImei(consume_blob(
                data,
                &mut next_blob_offset,
                blob_data,
            )?),
            Tag::AttestationIdMeid => {
                KeyParam::AttestationIdMeid(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::AttestationIdManufacturer => KeyParam::AttestationIdManufacturer(consume_blob(
                data,
                &mut next_blob_offset,
                blob_data,
            )?),
            Tag::AttestationIdModel => {
                KeyParam::AttestationIdModel(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::Nonce => KeyParam::Nonce(consume_blob(data, &mut next_blob_offset, blob_data)?),
            Tag::RootOfTrust => {
                KeyParam::RootOfTrust(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::CertificateSerial => {
                KeyParam::CertificateSerial(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::CertificateSubject => {
                KeyParam::CertificateSubject(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            Tag::ModuleHash => {
                KeyParam::ModuleHash(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            // Invalid variants.
            Tag::Invalid
            | Tag::HardwareType
            | Tag::MinSecondsBetweenOps
            | Tag::UniqueId
            | Tag::IdentityCredentialKey
            | Tag::AssociatedData
            | Tag::ConfirmationToken => {
                return Err(km_err!(InvalidKeyBlob, "invalid tag {:?} encountered", tag));
            }
        })?;
    }

    Ok(results)
}

/// Determine ordering of two [`KeyParam`] values for legacy key blob ordering.
/// Invalid parameters are likely to compare equal.
pub fn param_compare(left: &KeyParam, right: &KeyParam) -> Ordering {
    match (left, right) {
        (KeyParam::Purpose(l), KeyParam::Purpose(r)) => l.cmp(r),
        (KeyParam::Algorithm(l), KeyParam::Algorithm(r)) => l.cmp(r),
        (KeyParam::KeySize(l), KeyParam::KeySize(r)) => l.cmp(r),
        (KeyParam::BlockMode(l), KeyParam::BlockMode(r)) => l.cmp(r),
        (KeyParam::Digest(l), KeyParam::Digest(r)) => l.cmp(r),
        (KeyParam::Padding(l), KeyParam::Padding(r)) => l.cmp(r),
        (KeyParam::CallerNonce, KeyParam::CallerNonce) => Ordering::Equal,
        (KeyParam::MinMacLength(l), KeyParam::MinMacLength(r)) => l.cmp(r),
        (KeyParam::EcCurve(l), KeyParam::EcCurve(r)) => l.cmp(r),
        (KeyParam::RsaPublicExponent(l), KeyParam::RsaPublicExponent(r)) => l.cmp(r),
        (KeyParam::IncludeUniqueId, KeyParam::IncludeUniqueId) => Ordering::Equal,
        (KeyParam::RsaOaepMgfDigest(l), KeyParam::RsaOaepMgfDigest(r)) => l.cmp(r),
        (KeyParam::BootloaderOnly, KeyParam::BootloaderOnly) => Ordering::Equal,
        (KeyParam::RollbackResistance, KeyParam::RollbackResistance) => Ordering::Equal,
        (KeyParam::EarlyBootOnly, KeyParam::EarlyBootOnly) => Ordering::Equal,
        (KeyParam::ActiveDatetime(l), KeyParam::ActiveDatetime(r)) => l.cmp(r),
        (KeyParam::OriginationExpireDatetime(l), KeyParam::OriginationExpireDatetime(r)) => {
            l.cmp(r)
        }
        (KeyParam::UsageExpireDatetime(l), KeyParam::UsageExpireDatetime(r)) => l.cmp(r),
        (KeyParam::MaxUsesPerBoot(l), KeyParam::MaxUsesPerBoot(r)) => l.cmp(r),
        (KeyParam::UsageCountLimit(l), KeyParam::UsageCountLimit(r)) => l.cmp(r),
        (KeyParam::UserId(l), KeyParam::UserId(r)) => l.cmp(r),
        (KeyParam::UserSecureId(l), KeyParam::UserSecureId(r)) => l.cmp(r),
        (KeyParam::NoAuthRequired, KeyParam::NoAuthRequired) => Ordering::Equal,
        (KeyParam::UserAuthType(l), KeyParam::UserAuthType(r)) => l.cmp(r),
        (KeyParam::AuthTimeout(l), KeyParam::AuthTimeout(r)) => l.cmp(r),
        (KeyParam::AllowWhileOnBody, KeyParam::AllowWhileOnBody) => Ordering::Equal,
        (KeyParam::TrustedUserPresenceRequired, KeyParam::TrustedUserPresenceRequired) => {
            Ordering::Equal
        }
        (KeyParam::TrustedConfirmationRequired, KeyParam::TrustedConfirmationRequired) => {
            Ordering::Equal
        }
        (KeyParam::UnlockedDeviceRequired, KeyParam::UnlockedDeviceRequired) => Ordering::Equal,
        (KeyParam::ApplicationId(l), KeyParam::ApplicationId(r)) => l.cmp(r),
        (KeyParam::ApplicationData(l), KeyParam::ApplicationData(r)) => l.cmp(r),
        (KeyParam::CreationDatetime(l), KeyParam::CreationDatetime(r)) => l.cmp(r),
        (KeyParam::Origin(l), KeyParam::Origin(r)) => l.cmp(r),
        (KeyParam::RootOfTrust(l), KeyParam::RootOfTrust(r)) => l.cmp(r),
        (KeyParam::OsVersion(l), KeyParam::OsVersion(r)) => l.cmp(r),
        (KeyParam::OsPatchlevel(l), KeyParam::OsPatchlevel(r)) => l.cmp(r),
        (KeyParam::AttestationChallenge(l), KeyParam::AttestationChallenge(r)) => l.cmp(r),
        (KeyParam::AttestationApplicationId(l), KeyParam::AttestationApplicationId(r)) => l.cmp(r),
        (KeyParam::AttestationIdBrand(l), KeyParam::AttestationIdBrand(r)) => l.cmp(r),
        (KeyParam::AttestationIdDevice(l), KeyParam::AttestationIdDevice(r)) => l.cmp(r),
        (KeyParam::AttestationIdProduct(l), KeyParam::AttestationIdProduct(r)) => l.cmp(r),
        (KeyParam::AttestationIdSerial(l), KeyParam::AttestationIdSerial(r)) => l.cmp(r),
        (KeyParam::AttestationIdImei(l), KeyParam::AttestationIdImei(r)) => l.cmp(r),
        (KeyParam::AttestationIdSecondImei(l), KeyParam::AttestationIdSecondImei(r)) => l.cmp(r),
        (KeyParam::AttestationIdMeid(l), KeyParam::AttestationIdMeid(r)) => l.cmp(r),
        (KeyParam::AttestationIdManufacturer(l), KeyParam::AttestationIdManufacturer(r)) => {
            l.cmp(r)
        }
        (KeyParam::AttestationIdModel(l), KeyParam::AttestationIdModel(r)) => l.cmp(r),
        (KeyParam::VendorPatchlevel(l), KeyParam::VendorPatchlevel(r)) => l.cmp(r),
        (KeyParam::BootPatchlevel(l), KeyParam::BootPatchlevel(r)) => l.cmp(r),
        (KeyParam::DeviceUniqueAttestation, KeyParam::DeviceUniqueAttestation) => Ordering::Equal,
        (KeyParam::StorageKey, KeyParam::StorageKey) => Ordering::Equal,
        (KeyParam::Nonce(l), KeyParam::Nonce(r)) => l.cmp(r),
        (KeyParam::MacLength(l), KeyParam::MacLength(r)) => l.cmp(r),
        (KeyParam::ResetSinceIdRotation, KeyParam::ResetSinceIdRotation) => Ordering::Equal,
        (KeyParam::CertificateSerial(l), KeyParam::CertificateSerial(r)) => l.cmp(r),
        (KeyParam::CertificateSubject(l), KeyParam::CertificateSubject(r)) => l.cmp(r),
        (KeyParam::CertificateNotBefore(l), KeyParam::CertificateNotBefore(r)) => l.cmp(r),
        (KeyParam::CertificateNotAfter(l), KeyParam::CertificateNotAfter(r)) => l.cmp(r),
        (KeyParam::MaxBootLevel(l), KeyParam::MaxBootLevel(r)) => l.cmp(r),
        (KeyParam::ModuleHash(l), KeyParam::ModuleHash(r)) => l.cmp(r),

        (left, right) => left.tag().cmp(&right.tag()),
    }
}
