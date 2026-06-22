// Copyright 2023, The Android Open Source Project
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

//! Code for parsing software-backed keyblobs, as emitted by the C++ reference implementation of
//! KeyMint.

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyFormat::KeyFormat, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    Tag::Tag, TagType::TagType,
};
use crate::err as ks_err;
use crate::keymaster::crypto::hmac_sha256;
use crate::keymaster::error::Error;
use anyhow::Result;
use std::mem::size_of;

#[cfg(test)]
mod tests;

/// Root of trust value.
const SOFTWARE_ROOT_OF_TRUST: &[u8] = b"SW";

/// Error macro.
macro_rules! bloberr {
    { $($arg:tt)+ } => {
        anyhow::Error::new(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(ks_err!($($arg)+))
    };
}

/// Get the `KeyParameterValue` associated with a tag from a collection of `KeyParameter`s.
fn get_tag_value(params: &[KeyParameter], tag: Tag) -> Option<&KeyParameterValue> {
    params
        .iter()
        .find_map(|kp| if kp.tag == tag { Some(&kp.value) } else { None })
}

/// Get the [`TagType`] for a [`Tag`].
fn tag_type(tag: &Tag) -> TagType {
    TagType((tag.0 as u32 & 0xf0000000) as i32)
}

/// Extract key material and combined key characteristics from a legacy authenticated keyblob.
pub fn export_key(
    data: &[u8],
    params: &[KeyParameter],
) -> Result<(KeyFormat, Vec<u8>, Vec<KeyParameter>)> {
    let hidden = hidden_params(params, &[SOFTWARE_ROOT_OF_TRUST]);
    let KeyBlob {
        key_material,
        hw_enforced,
        sw_enforced,
    } = KeyBlob::new_from_serialized(data, &hidden)?;

    let mut combined = hw_enforced;
    combined.extend_from_slice(&sw_enforced);

    let algo_val =
        get_tag_value(&combined, Tag::ALGORITHM).ok_or_else(|| bloberr!("No algorithm found!"))?;

    let format = match algo_val {
        KeyParameterValue::Algorithm(Algorithm::AES)
        | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES)
        | KeyParameterValue::Algorithm(Algorithm::HMAC) => KeyFormat::RAW,
        KeyParameterValue::Algorithm(Algorithm::RSA)
        | KeyParameterValue::Algorithm(Algorithm::EC) => KeyFormat::PKCS8,
        _ => return Err(bloberr!("Unexpected algorithm {:?}", algo_val)),
    };

    let key_material = match (format, algo_val) {
        (KeyFormat::PKCS8, KeyParameterValue::Algorithm(Algorithm::EC)) => {
            // Key material format depends on the curve.
            let curve = get_tag_value(&combined, Tag::EC_CURVE)
                .ok_or_else(|| bloberr!("Failed to determine curve for EC key!"))?;
            match curve {
                KeyParameterValue::EcCurve(EcCurve::CURVE_25519) => key_material,
                KeyParameterValue::EcCurve(EcCurve::P_224) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_224)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_256) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_256)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_384) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_384)?
                }
                KeyParameterValue::EcCurve(EcCurve::P_521) => {
                    pkcs8_wrap_nist_key(&key_material, EcCurve::P_521)?
                }
                _ => {
                    return Err(bloberr!("Unexpected EC curve {curve:?}"));
                }
            }
        }
        (KeyFormat::RAW, _) => key_material,
        (format, algo) => {
            return Err(bloberr!(
                "Unsupported combination of {format:?} format for {algo:?} algorithm"
            ));
        }
    };
    Ok((format, key_material, combined))
}

/// DER-encoded `AlgorithmIdentifier` for a P-224 key.
const DER_ALGORITHM_ID_P224: &[u8] = &[
    0x30, 0x10, // SEQUENCE (AlgorithmIdentifier) {
    0x06, 0x07, // OBJECT IDENTIFIER (algorithm)
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x05, // OBJECT IDENTIFIER (param)
    0x2b, 0x81, 0x04, 0x00, 0x21, //  1.3.132.0.33 (secp224r1) }
];

/// DER-encoded `AlgorithmIdentifier` for a P-256 key.
const DER_ALGORITHM_ID_P256: &[u8] = &[
    0x30, 0x13, // SEQUENCE (AlgorithmIdentifier) {
    0x06, 0x07, // OBJECT IDENTIFIER (algorithm)
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x08, // OBJECT IDENTIFIER (param)
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, //  1.2.840.10045.3.1.7 (secp256r1) }
];

/// DER-encoded `AlgorithmIdentifier` for a P-384 key.
const DER_ALGORITHM_ID_P384: &[u8] = &[
    0x30, 0x10, // SEQUENCE (AlgorithmIdentifier) {
    0x06, 0x07, // OBJECT IDENTIFIER (algorithm)
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x05, // OBJECT IDENTIFIER (param)
    0x2b, 0x81, 0x04, 0x00, 0x22, //  1.3.132.0.34 (secp384r1) }
];

/// DER-encoded `AlgorithmIdentifier` for a P-384 key.
const DER_ALGORITHM_ID_P521: &[u8] = &[
    0x30, 0x10, // SEQUENCE (AlgorithmIdentifier) {
    0x06, 0x07, // OBJECT IDENTIFIER (algorithm)
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x05, // OBJECT IDENTIFIER (param)
    0x2b, 0x81, 0x04, 0x00, 0x23, //  1.3.132.0.35 (secp521r1) }
];

/// DER-encoded integer value zero.
const DER_VERSION_0: &[u8] = &[
    0x02, // INTEGER
    0x01, // len
    0x00, // value 0
];

/// Given a NIST curve EC key in the form of a DER-encoded `ECPrivateKey`
/// (RFC 5915 s3), wrap it in a DER-encoded PKCS#8 format (RFC 5208 s5).
fn pkcs8_wrap_nist_key(nist_key: &[u8], curve: EcCurve) -> Result<Vec<u8>> {
    let der_alg_id = match curve {
        EcCurve::P_224 => DER_ALGORITHM_ID_P224,
        EcCurve::P_256 => DER_ALGORITHM_ID_P256,
        EcCurve::P_384 => DER_ALGORITHM_ID_P384,
        EcCurve::P_521 => DER_ALGORITHM_ID_P521,
        _ => return Err(bloberr!("unknown curve {curve:?}")),
    };

    // Output format is:
    //
    //    PrivateKeyInfo ::= SEQUENCE {
    //        version                   INTEGER,
    //        privateKeyAlgorithm       AlgorithmIdentifier,
    //        privateKey                OCTET STRING,
    //    }
    //
    // Start by building the OCTET STRING so we know its length.
    let mut nist_key_octet_string = Vec::new();
    nist_key_octet_string.push(0x04); // OCTET STRING
    add_der_len(&mut nist_key_octet_string, nist_key.len())?;
    nist_key_octet_string.extend_from_slice(nist_key);

    let mut buf = Vec::new();
    buf.push(0x30); // SEQUENCE
    add_der_len(
        &mut buf,
        DER_VERSION_0.len() + der_alg_id.len() + nist_key_octet_string.len(),
    )?;
    buf.extend_from_slice(DER_VERSION_0);
    buf.extend_from_slice(der_alg_id);
    buf.extend_from_slice(&nist_key_octet_string);
    Ok(buf)
}

/// Append a DER-encoded length value to the given buffer.
fn add_der_len(buf: &mut Vec<u8>, len: usize) -> Result<()> {
    if len <= 0x7f {
        buf.push(len as u8)
    } else if len <= 0xff {
        buf.push(0x81); // One length octet to come
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x82); // Two length octets to come
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    } else {
        return Err(bloberr!("Unsupported DER length {len}"));
    }
    Ok(())
}

/// Plaintext key blob, with key characteristics.
#[derive(PartialEq, Eq)]
struct KeyBlob {
    /// Raw key material.
    key_material: Vec<u8>,
    /// Hardware-enforced key characteristics.
    hw_enforced: Vec<KeyParameter>,
    /// Software-enforced key characteristics.
    sw_enforced: Vec<KeyParameter>,
}

impl KeyBlob {
    /// Key blob version.
    const KEY_BLOB_VERSION: u8 = 0;

    /// Hard-coded HMAC key used for keyblob authentication.
    const LEGACY_HMAC_KEY: &'static [u8] = b"IntegrityAssuredBlob0\0";

    /// Size (in bytes) of appended MAC.
    const MAC_LEN: usize = 8;

    /// Parse a serialized [`KeyBlob`].
    fn new_from_serialized(mut data: &[u8], hidden: &[KeyParameter]) -> Result<Self> {
        // Keyblob needs to be at least long enough for:
        // - version byte,
        // - 4-byte len for key material
        // - 4-byte len for hw_enforced params
        // - 4-byte len for sw_enforced params
        // - MAC tag.
        if data.len() < (1 + 3 * size_of::<u32>() + Self::MAC_LEN) {
            return Err(bloberr!("blob not long enough (len = {})", data.len()));
        }

        // Check the HMAC in the last 8 bytes before doing anything else.
        let mac = &data[data.len() - Self::MAC_LEN..];
        let computed_mac = Self::compute_hmac(&data[..data.len() - Self::MAC_LEN], hidden)?;
        if mac != computed_mac {
            return Err(bloberr!("invalid key blob"));
        }

        let version = consume_u8(&mut data)?;
        if version != Self::KEY_BLOB_VERSION {
            return Err(bloberr!("unexpected blob version {}", version));
        }
        let key_material = consume_vec(&mut data)?;
        let hw_enforced = deserialize_params(&mut data)?;
        let sw_enforced = deserialize_params(&mut data)?;

        // Should just be the (already-checked) MAC left.
        let rest = &data[Self::MAC_LEN..];
        if !rest.is_empty() {
            return Err(bloberr!("extra data (len {})", rest.len()));
        }
        Ok(KeyBlob {
            key_material,
            hw_enforced,
            sw_enforced,
        })
    }

    /// Compute the authentication HMAC for a KeyBlob. This is built as:
    ///   HMAC-SHA256(HK, data || serialize(hidden))
    /// with HK = b"IntegrityAssuredBlob0\0".
    fn compute_hmac(data: &[u8], hidden: &[KeyParameter]) -> Result<Vec<u8>> {
        let hidden_data = serialize_params(hidden)?;
        let mut combined = data.to_vec();
        combined.extend_from_slice(&hidden_data);
        let mut tag = hmac_sha256(Self::LEGACY_HMAC_KEY, &combined)?;
        tag.truncate(Self::MAC_LEN);
        Ok(tag)
    }
}

/// Build the parameters that are used as the hidden input to HMAC calculations:
/// - `ApplicationId(data)` if present
/// - `ApplicationData(data)` if present
/// - (repeated) `RootOfTrust(rot)` where `rot` is a hardcoded piece of root of trust information.
fn hidden_params(params: &[KeyParameter], rots: &[&[u8]]) -> Vec<KeyParameter> {
    let mut results = Vec::new();
    if let Some(app_id) = get_tag_value(params, Tag::APPLICATION_ID) {
        results.push(KeyParameter {
            tag: Tag::APPLICATION_ID,
            value: app_id.clone(),
        });
    }
    if let Some(app_data) = get_tag_value(params, Tag::APPLICATION_DATA) {
        results.push(KeyParameter {
            tag: Tag::APPLICATION_DATA,
            value: app_data.clone(),
        });
    }
    for rot in rots {
        results.push(KeyParameter {
            tag: Tag::ROOT_OF_TRUST,
            value: KeyParameterValue::Blob(rot.to_vec()),
        });
    }
    results
}

/// Retrieve a `u8` from the start of the given slice, if possible.
fn consume_u8(data: &mut &[u8]) -> Result<u8> {
    match data.first() {
        Some(b) => {
            *data = &(*data)[1..];
            Ok(*b)
        }
        None => Err(bloberr!("failed to find 1 byte")),
    }
}

/// Move past a bool value from the start of the given slice, if possible.
/// Bool values should only be included if `true`, so fail if the value
/// is anything other than 1.
fn consume_bool(data: &mut &[u8]) -> Result<bool> {
    let b = consume_u8(data)?;
    if b == 0x01 {
        Ok(true)
    } else {
        Err(bloberr!("bool value other than 1 encountered"))
    }
}

/// Retrieve a (host-ordered) `u32` from the start of the given slice, if possible.
fn consume_u32(data: &mut &[u8]) -> Result<u32> {
    const LEN: usize = size_of::<u32>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap(); // safe: just checked
    *data = &(*data)[LEN..];
    Ok(u32::from_ne_bytes(chunk))
}

/// Retrieve a (host-ordered) `i32` from the start of the given slice, if possible.
fn consume_i32(data: &mut &[u8]) -> Result<i32> {
    const LEN: usize = size_of::<i32>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap(); // safe: just checked
    *data = &(*data)[4..];
    Ok(i32::from_ne_bytes(chunk))
}

/// Retrieve a (host-ordered) `i64` from the start of the given slice, if possible.
fn consume_i64(data: &mut &[u8]) -> Result<i64> {
    const LEN: usize = size_of::<i64>();
    if data.len() < LEN {
        return Err(bloberr!("failed to find {LEN} bytes"));
    }
    let chunk: [u8; LEN] = data[..LEN].try_into().unwrap(); // safe: just checked
    *data = &(*data)[LEN..];
    Ok(i64::from_ne_bytes(chunk))
}

/// Retrieve a vector of bytes from the start of the given slice, if possible,
/// with the length of the data expected to appear as a host-ordered `u32` prefix.
fn consume_vec(data: &mut &[u8]) -> Result<Vec<u8>> {
    let len = consume_u32(data)? as usize;
    if len > data.len() {
        return Err(bloberr!("failed to find {} bytes", len));
    }
    let result = data[..len].to_vec();
    *data = &(*data)[len..];
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
) -> Result<Vec<u8>> {
    let data_len = consume_u32(data)? as usize;
    let data_offset = consume_u32(data)? as usize;
    // Expect the blob data to come from the next offset in the initial blob chunk.
    if data_offset != *next_blob_offset {
        return Err(bloberr!(
            "got blob offset {} instead of {}",
            data_offset,
            next_blob_offset
        ));
    }
    if (data_offset + data_len) > blob_data.len() {
        return Err(bloberr!(
            "blob at offset [{}..{}+{}] goes beyond blob data size {}",
            data_offset,
            data_offset,
            data_len,
            blob_data.len(),
        ));
    }

    let slice = &blob_data[data_offset..data_offset + data_len];
    *next_blob_offset += data_len;
    Ok(slice.to_vec())
}

/// Deserialize a collection of [`KeyParam`]s in legacy serialized format. The provided slice is
/// modified to contain the unconsumed part of the data.
fn deserialize_params(data: &mut &[u8]) -> Result<Vec<KeyParameter>> {
    let blob_data_size = consume_u32(data)? as usize;
    if blob_data_size > data.len() {
        return Err(bloberr!(
            "blob data size {} bigger than data (len={})",
            blob_data_size,
            data.len()
        ));
    }

    let blob_data = &data[..blob_data_size];
    let mut next_blob_offset = 0;

    // Move past the blob data.
    *data = &data[blob_data_size..];

    let param_count = consume_u32(data)? as usize;
    let param_size = consume_u32(data)? as usize;
    if param_size > data.len() {
        return Err(bloberr!(
            "size mismatch 4+{}+4+4+{} > {}",
            blob_data_size,
            param_size,
            data.len()
        ));
    }

    let mut results = Vec::new();
    for _i in 0..param_count {
        let tag_num = consume_u32(data)? as i32;
        let tag = Tag(tag_num);
        let value = match tag_type(&tag) {
            TagType::INVALID => return Err(bloberr!("invalid tag {:?} encountered", tag)),
            TagType::ENUM | TagType::ENUM_REP => {
                let val = consume_i32(data)?;
                match tag {
                    Tag::ALGORITHM => KeyParameterValue::Algorithm(Algorithm(val)),
                    Tag::BLOCK_MODE => KeyParameterValue::BlockMode(BlockMode(val)),
                    Tag::PADDING => KeyParameterValue::PaddingMode(PaddingMode(val)),
                    Tag::DIGEST | Tag::RSA_OAEP_MGF_DIGEST => {
                        KeyParameterValue::Digest(Digest(val))
                    }
                    Tag::EC_CURVE => KeyParameterValue::EcCurve(EcCurve(val)),
                    Tag::ORIGIN => KeyParameterValue::Origin(KeyOrigin(val)),
                    Tag::PURPOSE => KeyParameterValue::KeyPurpose(KeyPurpose(val)),
                    Tag::USER_AUTH_TYPE => {
                        KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(val))
                    }
                    _ => KeyParameterValue::Integer(val),
                }
            }
            TagType::UINT | TagType::UINT_REP => KeyParameterValue::Integer(consume_i32(data)?),
            TagType::ULONG | TagType::ULONG_REP => {
                KeyParameterValue::LongInteger(consume_i64(data)?)
            }
            TagType::DATE => KeyParameterValue::DateTime(consume_i64(data)?),
            TagType::BOOL => KeyParameterValue::BoolValue(consume_bool(data)?),
            TagType::BIGNUM | TagType::BYTES => {
                KeyParameterValue::Blob(consume_blob(data, &mut next_blob_offset, blob_data)?)
            }
            _ => return Err(bloberr!("unexpected tag type for {:?}", tag)),
        };
        results.push(KeyParameter { tag, value });
    }

    Ok(results)
}

/// Serialize a collection of [`KeyParameter`]s into a format that is compatible with previous
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
fn serialize_params(params: &[KeyParameter]) -> Result<Vec<u8>> {
    // First 4 bytes are the length of the combined [`TagType::Bytes`] data; come back to set that
    // in a moment.
    let mut result = vec![0; 4];

    // Next append the contents of all of the [`TagType::Bytes`] data.
    let mut blob_size = 0u32;
    for param in params {
        let tag_type = tag_type(&param.tag);
        if let KeyParameterValue::Blob(v) = &param.value {
            if tag_type != TagType::BIGNUM && tag_type != TagType::BYTES {
                return Err(bloberr!(
                    "unexpected tag type for tag {:?} with blob",
                    param.tag
                ));
            }
            result.extend_from_slice(v);
            blob_size += v.len() as u32;
        }
    }
    // Go back and fill in the combined blob length in native order at the start.
    result[..4].clone_from_slice(&blob_size.to_ne_bytes());

    result.extend_from_slice(&(params.len() as u32).to_ne_bytes());

    let params_size_offset = result.len();
    result.extend_from_slice(&[0u8; 4]); // placeholder for size of elements
    let first_param_offset = result.len();
    let mut blob_offset = 0u32;
    for param in params {
        result.extend_from_slice(&(param.tag.0 as u32).to_ne_bytes());
        match &param.value {
            KeyParameterValue::Invalid(_v) => {
                return Err(bloberr!("invalid tag found in {:?}", param))
            }

            // Enum-holding variants.
            KeyParameterValue::Algorithm(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::BlockMode(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::PaddingMode(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::Digest(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::EcCurve(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::Origin(v) => result.extend_from_slice(&(v.0 as u32).to_ne_bytes()),
            KeyParameterValue::KeyPurpose(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }
            KeyParameterValue::HardwareAuthenticatorType(v) => {
                result.extend_from_slice(&(v.0 as u32).to_ne_bytes())
            }

            // Value-holding variants.
            KeyParameterValue::Integer(v) => result.extend_from_slice(&(*v as u32).to_ne_bytes()),
            KeyParameterValue::BoolValue(_v) => result.push(0x01u8),
            KeyParameterValue::LongInteger(v) | KeyParameterValue::DateTime(v) => {
                result.extend_from_slice(&(*v as u64).to_ne_bytes())
            }
            KeyParameterValue::Blob(v) => {
                let blob_len = v.len() as u32;
                result.extend_from_slice(&blob_len.to_ne_bytes());
                result.extend_from_slice(&blob_offset.to_ne_bytes());
                blob_offset += blob_len;
            }

            _ => return Err(bloberr!("unknown value found in {:?}", param)),
        }
    }
    let serialized_size = (result.len() - first_param_offset) as u32;

    // Go back and fill in the total serialized size.
    result[params_size_offset..params_size_offset + 4]
        .clone_from_slice(&serialized_size.to_ne_bytes());
    Ok(result)
}
