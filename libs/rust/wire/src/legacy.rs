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

//! Functionality for dealing with (a subset of) legacy C++ KeyMint internal messages.
//!
//! The inner messages are defined by the classes deriving from `KeymasterMessage` in
//! `system/keymaster/include/keymaster/android_keymaster_messages.h`. Each of these classes derives
//! from `Serializable` (in `system/keymaster/include/keymaster/serializable.h`) and implements
//! `Serialize` and `Deserialize` methods that convert instances of the message into opaque
//! sequences of bytes.
//!
//! However, these opaque sequences of bytes do not self-identify which particular message is
//! involved.  Instead, there is device specific code to wrap the inner serialized data into some
//! sort of envelope that identifies the message type.
//!
//! 1) For Trusty, this envelope is the `keymaster_message` struct from
//!    `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`; this struct holds
//!    (and is serialized as):
//!
//!    - A u32 indicating which command is involved, together with two low bits to encode whether the
//!      message is a response, and a stop bit.  The command code values are taken from
//!      `keymaster_command` in
//!      `system/core/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h`.
//!    - The payload.
//!
//! 2) For Cuttlefish, this envelope is the `keymaster_message` struct from
//!    `device/google/cuttlefish/common/libs/security/keymaster_channel.h`; this struct holds (and is
//!    serialized as):
//!
//!    - A u32 indicating which command is involved, together with a bit indicating if the message is a
//!      response.  The command code values are taken from `AndroidKeymasterCommand` in
//!      `system/keymaster/include/keymaster/android_keymaster_messages.h`.
//!    - A u32 indicating the size of the payload
//!    - The payload.
//!
//! In addition to the common messages defined in `android_keymaster_messages.h`, Trusty includes
//! additional messages defined in `app/keymaster/trusty_keymaster_messages.h`.
//!
//!
//! Only a subset of legacy messages are of interest; specifically, messages that involve
//! interactions with things *other* than the HAL service, such as:
//! - The bootloader.
//! - Other TAs (e.g. Gatekeeper, ConfirmationUI) running in the secure environment.
//! - Provisioning tools.

use crate::{
    keymint::{Algorithm, ErrorCode, VerifiedBootState},
    try_from_n,
};
use enumn::N;
use kmr_derive::LegacySerialize;
use zeroize::ZeroizeOnDrop;
use Vec;

/// This bit is set in the `u32` command value for response messages.
const TRUSTY_RESPONSE_BITMASK: u32 = 0x01;
/// This bit is set in the `u32` command value for the final fragment of response messages; i.e. if
/// this bit is clear on a response message, more data is expected.
pub const TRUSTY_STOP_BITMASK: u32 = 0x02;
/// The raw `u32` command value should be shifted right by this number of bits to get the command
/// enum value.
pub const TRUSTY_CMD_SHIFT: usize = 2;

/// Legacy serialized trusty messages have as a first element the desired command encoded on a `u32`
pub const CMD_SIZE: usize = 4;
/// After the command, non-secure port responses have an error code encoded on a `u32`
pub const ERROR_CODE_SIZE: usize = 4;
/// Non-secure channel response headers are comprised of a CMD and an Error code
pub const LEGACY_NON_SEC_RSP_HEADER_SIZE: usize = CMD_SIZE + ERROR_CODE_SIZE;

/// Key{Mint,master} version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, N)]
#[repr(i32)]
pub enum KmVersion {
    Keymaster1 = 10,
    Keymaster11 = 11,
    Keymaster2 = 20,
    Keymaster3 = 30,
    Keymaster4 = 40,
    Keymaster41 = 41,
    KeyMint1 = 100,
    KeyMint2 = 200,
    KeyMint3 = 300,
}
try_from_n!(KmVersion);

impl KmVersion {
    /// Indicate the message format version associated with a C++ KeyMint version.
    pub fn message_version(&self) -> u32 {
        match self {
            KmVersion::Keymaster1 => 1,
            KmVersion::Keymaster11 => 2,
            KmVersion::Keymaster2
            | KmVersion::Keymaster3
            | KmVersion::Keymaster4
            | KmVersion::Keymaster41 => 3,
            KmVersion::KeyMint1 | KmVersion::KeyMint2 | KmVersion::KeyMint3 => 4,
        }
    }
}

/// Date marker used by the last version of the previous C++ code.
pub const KM_DATE: u32 = 20201219;

/// Errors encountered when [de-]serializing legacy messages.
#[derive(Debug, Clone, Copy)]
pub enum Error {
    DataTruncated,
    ExcessData(usize),
    AllocationFailed,
    UnexpectedResponse,
    UnknownCommand(u32),
    InvalidEnumValue(u32),
}

/// Identification of Trusty messages.
pub trait TrustyMessageId {
    type Code;
    fn code(&self) -> Self::Code;
}

/// Trait for deserialization of Trusty messages.
trait TrustyDeserialize: TrustyMessageId + Sized {
    fn from_code_and_data(cmd: u32, data: &[u8]) -> Result<Self, Error>;
}

fn deserialize_trusty_request_message<T: TrustyDeserialize>(data: &[u8]) -> Result<T, Error> {
    let (raw_cmd, data) = <u32>::deserialize(data)?;
    let cmd = raw_cmd >> TRUSTY_CMD_SHIFT;
    if (raw_cmd & TRUSTY_RESPONSE_BITMASK) == TRUSTY_RESPONSE_BITMASK {
        return Err(Error::UnexpectedResponse);
    }
    let req = T::from_code_and_data(cmd, data)?;
    Ok(req)
}

/// Deserialize a legacy Trusty request message arriving on the non-secure port.
pub fn deserialize_trusty_req(data: &[u8]) -> Result<TrustyPerformOpReq, Error> {
    deserialize_trusty_request_message(data)
}

/// Deserialize a legacy Trusty request message arriving on the secure port.
pub fn deserialize_trusty_secure_req(data: &[u8]) -> Result<TrustyPerformSecureOpReq, Error> {
    deserialize_trusty_request_message(data)
}

/// Trait to allow serialization of Trusty messages.
pub trait TrustySerialize: TrustyMessageId {
    fn raw_code(&self) -> u32;
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error>;
}

/// The result of a legacy operation is either a response message or an error code associated with
/// the original command.
pub enum LegacyResult<T> {
    Ok(T),
    Err { cmd: u32, code: ErrorCode },
}

impl<T: TrustySerialize> LegacyResult<T> {
    /// Return the command code associated with the result.
    fn cmd(&self) -> u32 {
        match self {
            LegacyResult::Ok(rsp) => rsp.raw_code(),
            LegacyResult::Err { cmd, code: _code } => *cmd,
        }
    }
}

/// Serialize a Trusty response message in the form:
/// - command code: 32-bit integer (native endian)
/// - return code: 32-bit integer (native endian)
/// - encoded response data (if return code is 0/Ok).
///
/// Note that some legacy response messages (e.g. [`GetDeviceInfoResponse`],
/// [`GetAuthTokenKeyResponse`]) do not use this encoding format.
fn serialize_trusty_response_message<T: TrustySerialize>(
    result: LegacyResult<T>,
) -> Result<Vec<u8>, Error> {
    let cmd = result.cmd();
    // None of the supported response messages are large enough to require fragmentation, so always
    // mark this as the final response.
    let raw_cmd = cmd << TRUSTY_CMD_SHIFT | TRUSTY_RESPONSE_BITMASK | TRUSTY_STOP_BITMASK;
    let mut buf = Vec::new();
    buf.try_reserve(LEGACY_NON_SEC_RSP_HEADER_SIZE)
        .map_err(|_e| Error::AllocationFailed)?;
    buf.extend_from_slice(&raw_cmd.to_ne_bytes());

    match result {
        LegacyResult::Ok(rsp) => {
            buf.extend_from_slice(&(ErrorCode::Ok as u32).to_ne_bytes());
            rsp.serialize_into(&mut buf)?;
        }
        LegacyResult::Err { cmd: _cmd, code } => {
            buf.extend_from_slice(&(code as u32).to_ne_bytes());
        }
    }

    Ok(buf)
}

/// Serialize a legacy Trusty response message for the non-secure port.
pub fn serialize_trusty_rsp(rsp: TrustyPerformOpRsp) -> Result<Vec<u8>, Error> {
    serialize_trusty_response_message(LegacyResult::Ok(rsp))
}

/// Serialize raw data as a Trusty response message without length prefix.
fn serialize_trusty_raw_rsp(cmd: u32, raw_data: &[u8]) -> Result<Vec<u8>, Error> {
    let raw_cmd = cmd << TRUSTY_CMD_SHIFT | TRUSTY_RESPONSE_BITMASK | TRUSTY_STOP_BITMASK;
    let mut buf = Vec::new();
    buf.try_reserve(CMD_SIZE + raw_data.len())
        .map_err(|_e| Error::AllocationFailed)?;
    buf.extend_from_slice(&raw_cmd.to_ne_bytes());
    buf.extend_from_slice(raw_data);
    Ok(buf)
}

/// Serialize a legacy Trusty response message for the secure port.
pub fn serialize_trusty_secure_rsp(rsp: TrustyPerformSecureOpRsp) -> Result<Vec<u8>, Error> {
    match &rsp {
        TrustyPerformSecureOpRsp::GetAuthTokenKey(GetAuthTokenKeyResponse { key_material }) => {
            // The `KM_GET_AUTH_TOKEN_KEY` response does not include the error code value.  (The
            // recipient has to distinguish between OK and error responses by the size of the
            // response message: 4+32 for OK, 4+4 for error).
            serialize_trusty_raw_rsp(rsp.raw_code(), key_material)
        }
        TrustyPerformSecureOpRsp::GetDeviceInfo(GetDeviceInfoResponse { device_ids }) => {
            // The `KM_GET_DEVICE_INFO` response does not include the error code value. (The
            // recipient has to distinguish between OK and error response by attempting to parse
            // the response data as a CBOR map, and if this fails assume that the response hold
            // an error code instead).
            // TODO: update this to include explicit error code information if/when the C++ code
            // and library are updated.
            serialize_trusty_raw_rsp(rsp.raw_code(), device_ids)
        }
        TrustyPerformSecureOpRsp::GetUdsCerts(GetUdsCertsResponse { uds_certs: _ }) => {
            serialize_trusty_response_message(LegacyResult::Ok(rsp))
        }
        TrustyPerformSecureOpRsp::SetAttestationIds(_) => {
            serialize_trusty_response_message(LegacyResult::Ok(rsp))
        }
    }
}

/// Deserialize the header of a non-secure channel Trusty response message to know if the operation
/// succeeded. The Result is the error code of the operation, which is roughly equivalent to the
/// legacy keymaster error. Notice that if the keymint operation was successful the return error
/// code will be `ErrorCode::Ok`.
pub fn deserialize_trusty_rsp_error_code(rsp: &[u8]) -> Result<ErrorCode, Error> {
    if rsp.len() < LEGACY_NON_SEC_RSP_HEADER_SIZE {
        return Err(Error::DataTruncated);
    }

    let (error_code, _) = u32::deserialize(&rsp[CMD_SIZE..LEGACY_NON_SEC_RSP_HEADER_SIZE])?;
    ErrorCode::try_from(error_code as i32).map_err(|_e| Error::InvalidEnumValue(error_code))
}

/// Serialize a legacy Trusty error response for the non-secure port.
pub fn serialize_trusty_error_rsp(
    op: TrustyKeymasterOperation,
    rc: ErrorCode,
) -> Result<Vec<u8>, Error> {
    serialize_trusty_response_message(LegacyResult::<TrustyPerformOpRsp>::Err {
        cmd: op as u32,
        code: rc,
    })
}

/// Serialize a legacy Trusty error response for the secure port.
pub fn serialize_trusty_secure_error_rsp(
    op: TrustyKeymasterSecureOperation,
    rc: ErrorCode,
) -> Result<Vec<u8>, Error> {
    serialize_trusty_response_message(LegacyResult::<TrustyPerformSecureOpRsp>::Err {
        cmd: op as u32,
        code: rc,
    })
}

/// Trait that serializes an inner message to/from the format used by the legacy C++ Keymaster code.
pub trait InnerSerialize: Sized {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error>;
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error>;
}

impl InnerSerialize for u64 {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        if data.len() < 8 {
            return Err(Error::DataTruncated);
        }
        let int_data: [u8; 8] = data[..8].try_into().map_err(|_e| Error::DataTruncated)?;
        Ok((<u64>::from_ne_bytes(int_data), &data[8..]))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(8).map_err(|_e| Error::AllocationFailed)?;
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(())
    }
}

impl InnerSerialize for u32 {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        if data.len() < 4 {
            return Err(Error::DataTruncated);
        }
        let int_data: [u8; 4] = data[..4].try_into().map_err(|_e| Error::DataTruncated)?;
        Ok((<u32>::from_ne_bytes(int_data), &data[4..]))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(4).map_err(|_e| Error::AllocationFailed)?;
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(())
    }
}

impl InnerSerialize for u8 {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        if data.is_empty() {
            return Err(Error::DataTruncated);
        }
        Ok((data[0], &data[1..]))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(1).map_err(|_e| Error::AllocationFailed)?;
        buf.push(*self);
        Ok(())
    }
}

impl InnerSerialize for bool {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (v, rest) = <u32>::deserialize(data)?;
        Ok((v != 0, rest))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        (*self as u32).serialize_into(buf)
    }
}

impl InnerSerialize for Vec<u8> {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (len, rest) = <u32>::deserialize(data)?;
        let len = len as usize;
        if rest.len() < len {
            return Err(Error::DataTruncated);
        }
        let mut buf = Vec::new();
        buf.try_reserve(len).map_err(|_e| Error::AllocationFailed)?;
        buf.extend_from_slice(&rest[..len]);
        Ok((buf, &rest[len..]))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(4 + self.len())
            .map_err(|_e| Error::AllocationFailed)?;
        let len = self.len() as u32;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(self);
        Ok(())
    }
}

impl InnerSerialize for KmVersion {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (v, rest) = <u32>::deserialize(data)?;
        Ok((
            Self::try_from(v as i32).map_err(|_e| Error::InvalidEnumValue(v))?,
            rest,
        ))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        (*self as u32).serialize_into(buf)
    }
}

impl InnerSerialize for Algorithm {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (v, rest) = <u32>::deserialize(data)?;
        Ok((
            Self::try_from(v as i32).map_err(|_e| Error::InvalidEnumValue(v))?,
            rest,
        ))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        (*self as u32).serialize_into(buf)
    }
}

impl InnerSerialize for VerifiedBootState {
    fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (v, rest) = <u32>::deserialize(data)?;
        Ok((
            Self::try_from(v as i32).map_err(|_e| Error::InvalidEnumValue(v))?,
            rest,
        ))
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        (*self as u32).serialize_into(buf)
    }
}

// Legacy messages of interest from `android_keymaster_messages.h`.

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetVersionRequest {}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetVersionResponse {
    pub major_ver: u8,
    pub minor_ver: u8,
    pub subminor_ver: u8,
}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetVersion2Request {
    pub max_message_version: u32,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetVersion2Response {
    pub max_message_version: u32,
    pub km_version: KmVersion,
    pub km_date: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ConfigureBootPatchlevelRequest {
    pub boot_patchlevel: u32, // YYYMMDD
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ConfigureBootPatchlevelResponse {}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ConfigureVerifiedBootInfoRequest {
    pub boot_state: Vec<u8>,
    pub bootloader_state: Vec<u8>,
    pub vbmeta_digest: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ConfigureVerifiedBootInfoResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct SetAttestationIdsRequest {
    pub brand: Vec<u8>,
    pub device: Vec<u8>,
    pub product: Vec<u8>,
    pub serial: Vec<u8>,
    pub imei: Vec<u8>,
    pub meid: Vec<u8>,
    pub manufacturer: Vec<u8>,
    pub model: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetAttestationIdsResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct SetAttestationIdsKM3Request {
    pub base: SetAttestationIdsRequest,
    pub second_imei: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetAttestationIdsKM3Response {}

// Legacy messages of interest from `trusty_keymaster_messages.h`.

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetAuthTokenKeyRequest {}
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct GetAuthTokenKeyResponse {
    pub key_material: Vec<u8>,
}

/// The serialization of a `GET_AUTH_TOKEN_KEY` response does not include a length field before the
/// contents of the key, so the auto-derive implementation can't be used. (This also means that
/// `deserialize()` can't be implemented, because there is no length information available.)
impl InnerSerialize for GetAuthTokenKeyResponse {
    fn deserialize(_data: &[u8]) -> Result<(Self, &[u8]), Error> {
        Err(Error::UnexpectedResponse)
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(self.key_material.len())
            .map_err(|_e| Error::AllocationFailed)?;
        buf.extend_from_slice(&self.key_material);
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetDeviceInfoRequest {}
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct GetDeviceInfoResponse {
    // Device ID information encoded as a CBOR map.
    pub device_ids: Vec<u8>,
}

/// The serialization of a `GET_DEVICE_INFO` response does not include a length field before the
/// contents, so the auto-derive implementation can't be used. (This also means that `deserialize()`
/// can't be implemented, because there is no length information available.)
impl InnerSerialize for GetDeviceInfoResponse {
    fn deserialize(_data: &[u8]) -> Result<(Self, &[u8]), Error> {
        Err(Error::UnexpectedResponse)
    }
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.try_reserve(self.device_ids.len())
            .map_err(|_e| Error::AllocationFailed)?;
        buf.extend_from_slice(&self.device_ids);
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetUdsCertsRequest {}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct GetUdsCertsResponse {
    pub uds_certs: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetBootParamsRequest {
    pub os_version: u32,
    pub os_patchlevel: u32, // YYYYMM
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_key: Vec<u8>,
    pub verified_boot_hash: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetBootParamsResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct SetAttestationKeyRequest {
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    pub key_data: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetAttestationKeyResponse {}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct AppendAttestationCertChainRequest {
    pub algorithm: Algorithm,
    pub cert_data: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct AppendAttestationCertChainResponse {}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ClearAttestationCertChainRequest {
    pub algorithm: Algorithm,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ClearAttestationCertChainResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct SetWrappedAttestationKeyRequest {
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    pub key_data: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct SetWrappedAttestationKeyResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct AppendUdsCertificateRequest {
    pub cert_data: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct AppendUdsCertificateResponse {}

#[derive(Clone, PartialEq, Eq, LegacySerialize, ZeroizeOnDrop)]
pub struct ClearUdsCertificateRequest {}

#[derive(Clone, PartialEq, Eq, Debug, LegacySerialize)]
pub struct ClearUdsCertificateResponse {}

macro_rules! declare_req_rsp_enums {
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident)
        {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {
        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, N)]
        pub enum $cenum {
            $( $cname = $cvalue, )*
        }
        pub enum $reqenum {
            $( $cname($reqtyp), )*
        }
        pub enum $rspenum {
            $( $cname($rsptyp), )*
        }
        impl TrustyMessageId for $reqenum {
            type Code = $cenum;
            fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }
        impl TrustyDeserialize  for $reqenum {
            fn from_code_and_data(cmd: u32, data: &[u8]) -> Result<Self, Error> {
                let (req, rest) = match cmd {
                    $(
                        $cvalue => {
                            let (req, rest) = <$reqtyp>::deserialize(data)?;
                            ($reqenum::$cname(req), rest)
                        }
                    )*
                    _ => return Err(Error::UnknownCommand(cmd)),
                };
                if !rest.is_empty() {
                    return Err(Error::ExcessData(rest.len()));
                }
                Ok(req)
            }
        }
        impl TrustyMessageId for $rspenum {
            type Code = $cenum;
            fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }
        impl TrustySerialize for $rspenum {
            fn raw_code(&self) -> u32 {
                self.code() as u32
            }
            fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
                match self {
                    $( Self::$cname(rsp) => rsp.serialize_into(buf), )*
                }
            }
        }
    };
}

// Possible legacy Cuttlefish Keymaster operation requests, as:
// - an enum value with an explicit numeric value
// - a request enum which has an operation code associated to each variant
// - a response enum which has the same operation code associated to each variant.
//
// Numerical values for discriminants match the values in
// system/keymaster/include/keymaster/android_keymaster_messages.h
declare_req_rsp_enums! { CuttlefishKeymasterOperation => (CuttlefishPerformOpReq, CuttlefishPerformOpRsp) {
    ConfigureBootPatchlevel = 33 =>                      (ConfigureBootPatchlevelRequest, ConfigureBootPatchlevelResponse),
    ConfigureVerifiedBootInfo = 34 =>                    (ConfigureVerifiedBootInfoRequest, ConfigureVerifiedBootInfoResponse),
    SetAttestationIds = 38 =>                            (SetAttestationIdsRequest, SetAttestationIdsResponse),
} }

// Possible legacy Trusty Keymaster operation requests for the non-secure port.
//
// Numerical values for discriminants match the values in
// trusty/user/app/keymaster/ipc/keymaster_ipc.h.
declare_req_rsp_enums! { TrustyKeymasterOperation => (TrustyPerformOpReq, TrustyPerformOpRsp) {
    GetVersion = 7 =>                                (GetVersionRequest, GetVersionResponse),
    GetVersion2 = 28 =>                              (GetVersion2Request, GetVersion2Response),
    SetBootParams = 0x1000 =>                        (SetBootParamsRequest, SetBootParamsResponse),

    // Provisioning-related requests. Changes here should be reflected in `is_trusty_provisioning_{code,req}`.
    SetAttestationKey = 0x2000 =>                    (SetAttestationKeyRequest, SetAttestationKeyResponse),
    AppendAttestationCertChain = 0x3000 =>           (AppendAttestationCertChainRequest, AppendAttestationCertChainResponse),
    ClearAttestationCertChain = 0xa000 =>            (ClearAttestationCertChainRequest, ClearAttestationCertChainResponse),
    SetWrappedAttestationKey = 0xb000 =>             (SetWrappedAttestationKeyRequest, SetWrappedAttestationKeyResponse),
    SetAttestationIds = 0xc000 =>                    (SetAttestationIdsRequest, SetAttestationIdsResponse),
    SetAttestationIdsKM3 = 0xc001 =>                 (SetAttestationIdsKM3Request, SetAttestationIdsKM3Response),
    ConfigureBootPatchlevel = 0xd0000 =>             (ConfigureBootPatchlevelRequest, ConfigureBootPatchlevelResponse),
    AppendUdsCertificate = 0xe0000 =>                (AppendUdsCertificateRequest, AppendUdsCertificateResponse),
    ClearUdsCertificate = 0xe0001 =>                 (ClearUdsCertificateRequest, ClearUdsCertificateResponse),
} }

// Possible legacy Trusty Keymaster operation requests for the secure port.
//
// Numerical values for discriminants match the values in
// trusty/user/base/interface/keymaster/include/interface/keymaster/keymaster.h
declare_req_rsp_enums! { TrustyKeymasterSecureOperation  => (TrustyPerformSecureOpReq, TrustyPerformSecureOpRsp) {
    GetAuthTokenKey = 0 =>                                  (GetAuthTokenKeyRequest, GetAuthTokenKeyResponse),
    GetDeviceInfo = 1 =>                                    (GetDeviceInfoRequest, GetDeviceInfoResponse),
    GetUdsCerts = 2 =>                                      (GetUdsCertsRequest, GetUdsCertsResponse),
    SetAttestationIds = 0xc000 =>                           (SetAttestationIdsRequest, SetAttestationIdsResponse),
} }

/// Indicate whether a request message is a bootloader message.
pub fn is_trusty_bootloader_code(code: u32) -> bool {
    matches!(
        TrustyKeymasterOperation::n(code),
        Some(TrustyKeymasterOperation::SetBootParams)
            | Some(TrustyKeymasterOperation::ConfigureBootPatchlevel)
    )
}

/// Indicate whether a request message is a bootloader message.
pub fn is_trusty_bootloader_req(req: &TrustyPerformOpReq) -> bool {
    matches!(
        req,
        TrustyPerformOpReq::SetBootParams(_) | TrustyPerformOpReq::ConfigureBootPatchlevel(_)
    )
}

/// Indicate whether a request message is a provisioning message.
pub fn is_trusty_provisioning_code(code: u32) -> bool {
    matches!(
        TrustyKeymasterOperation::n(code),
        Some(TrustyKeymasterOperation::SetAttestationKey)
            | Some(TrustyKeymasterOperation::AppendAttestationCertChain)
            | Some(TrustyKeymasterOperation::ClearAttestationCertChain)
            | Some(TrustyKeymasterOperation::SetWrappedAttestationKey)
            | Some(TrustyKeymasterOperation::SetAttestationIds)
            | Some(TrustyKeymasterOperation::SetAttestationIdsKM3)
            | Some(TrustyKeymasterOperation::AppendUdsCertificate)
            | Some(TrustyKeymasterOperation::ClearUdsCertificate)
    )
}

/// Indicate whether a request message is a provisioning message.
pub fn is_trusty_provisioning_req(req: &TrustyPerformOpReq) -> bool {
    matches!(
        req,
        TrustyPerformOpReq::SetAttestationKey(_)
            | TrustyPerformOpReq::AppendAttestationCertChain(_)
            | TrustyPerformOpReq::ClearAttestationCertChain(_)
            | TrustyPerformOpReq::SetWrappedAttestationKey(_)
            | TrustyPerformOpReq::SetAttestationIds(_)
            | TrustyPerformOpReq::SetAttestationIdsKM3(_)
            | TrustyPerformOpReq::AppendUdsCertificate(_)
            | TrustyPerformOpReq::ClearUdsCertificate(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_inner_serialize() {
        let msg = SetBootParamsRequest {
            // `u32` encoding uses native byte order so use symmetric values
            os_version: 0x01010101,
            os_patchlevel: 0x02020202,
            device_locked: false,
            verified_boot_state: VerifiedBootState::Unverified,
            verified_boot_key: vec![1, 2, 3],
            verified_boot_hash: vec![5, 4, 3],
        };
        #[cfg(target_endian = "little")]
        let hex_data = concat!(
            "01010101", // os_version
            "02020202", // os_patchlevel
            "00000000", // device_locked
            "02000000", // verified_boot_state
            "03000000", "010203", // verified_boot_key
            "03000000", "050403", // verified_boot_key
        );
        #[cfg(target_endian = "big")]
        let hex_data = concat!(
            "01010101", // os_version
            "02020202", // os_patchlevel
            "00000000", // device_locked
            "02000002", // verified_boot_state
            "00000003", "010203", // verified_boot_key
            "00000003", "050403", // verified_boot_key
        );
        let data = hex::decode(hex_data).unwrap();

        let mut got_data = Vec::new();
        msg.serialize_into(&mut got_data).unwrap();
        assert_eq!(hex::encode(got_data), hex_data);

        let (got, rest) = SetBootParamsRequest::deserialize(&data).unwrap();
        assert!(rest.is_empty());
        assert!(got == msg);
    }
    #[test]
    fn test_get_version_serialize() {
        let msg = GetVersionResponse {
            major_ver: 1,
            minor_ver: 2,
            subminor_ver: 3,
        };
        let data = vec![1, 2, 3];

        let mut got_data = Vec::new();
        msg.serialize_into(&mut got_data).unwrap();
        assert_eq!(got_data, data);

        let (got, rest) = GetVersionResponse::deserialize(&data).unwrap();
        assert!(rest.is_empty());
        assert!(got == msg);
    }
    #[test]
    fn test_inner_deserialize_fail() {
        let data = "010101"; // too short
        let data = hex::decode(data).unwrap();
        let result = ConfigureBootPatchlevelRequest::deserialize(&data);
        assert!(result.is_err());
    }
    #[test]
    fn test_trusty_serialize_rsp() {
        let msg = TrustyPerformSecureOpRsp::GetAuthTokenKey(GetAuthTokenKeyResponse {
            key_material: vec![1, 2, 3],
        });
        #[cfg(target_endian = "little")]
        let data = concat!("03000000", "010203");
        #[cfg(target_endian = "big")]
        let data = concat!("00000003", "010203");

        let got_data = serialize_trusty_secure_rsp(msg).unwrap();
        assert_eq!(hex::encode(got_data), data);
    }
    #[test]
    fn test_get_uds_certs_rsp_serialize() {
        let msg = TrustyPerformSecureOpRsp::GetUdsCerts(GetUdsCertsResponse {
            uds_certs: vec![1, 2, 3],
        });
        #[cfg(target_endian = "little")]
        let data = concat!(
            /* cmd */ "0b000000", /* rc */ "00000000", /* len */ "03000000",
            /* data */ "010203"
        );
        #[cfg(target_endian = "big")]
        let data = concat!(
            /* cmd */ "0000000b", /* rc */ "00000000", /* len */ "00000003",
            /* data */ "010203"
        );
        let got_data = serialize_trusty_secure_rsp(msg).unwrap();
        assert_eq!(hex::encode(got_data), data);
    }
}
