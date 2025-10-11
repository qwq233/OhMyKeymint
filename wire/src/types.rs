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

use crate::keymint::{
    AttestationKey, HardwareAuthToken, KeyCharacteristics, KeyCreationResult, KeyFormat,
    KeyMintHardwareInfo, KeyParam, KeyPurpose,
};
use crate::rpc;
use crate::secureclock::TimeStampToken;
use crate::sharedsecret::SharedSecretParameters;
use crate::{cbor, cbor_type_error, vec_try, AsCborValue, CborError};
use enumn::N;
use kmr_derive::AsCborValue;

/// Key size in bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct KeySizeInBits(pub u32);

/// RSA exponent.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct RsaExponent(pub u64);

/// Default maximum supported size for CBOR-serialized messages.
pub const DEFAULT_MAX_SIZE: usize = 4096;

/// Marker type indicating failure to convert into a wire type.  For `enum` wire types, the variant
/// names match the `enum` whose value failed to convert.
#[derive(Debug)]
pub enum ValueNotRecognized {
    // Enum type names.
    KeyPurpose,
    Algorithm,
    BlockMode,
    Digest,
    PaddingMode,
    EcCurve,
    ErrorCode,
    HardwareAuthenticatorType,
    KeyFormat,
    KeyOrigin,
    SecurityLevel,
    Tag,
    TagType,
    KmVersion,
    EekCurve,
    Origin,
    // Non-enum types.
    Bool,
    Blob,
    DateTime,
    Integer,
    LongInteger,
}

/// Trait that associates an enum value of the specified type with a type.
/// Values of the `enum` type `T` are used to identify particular message types.
/// A message type implements `Code<T>` to indicate which `enum` value it is
/// associated with.
///
/// For example, an `enum WhichMsg { Hello, Goodbye }` could be used to distinguish
/// between `struct HelloMsg` and `struct GoodbyeMsg` instances, in which case the
/// latter types would both implement `Code<WhichMsg>` with `CODE` values of
/// `WhichMsg::Hello` and `WhichMsg::Goodbye` respectively.
pub trait Code<T> {
    /// The enum value identifying this request/response.
    const CODE: T;
    /// Return the enum value associated with the underlying type of this item.
    fn code(&self) -> T {
        Self::CODE
    }
}

/// Internal equivalent of the `keymint::BeginResult` type; instead of the Binder object reference
/// there is an opaque `op_handle` value that the bottom half implementation uses to identify the
/// in-progress operation.  This field is included as an extra parameter in all of the per-operation
/// ...Request types.
#[derive(Debug, Default, AsCborValue)]
pub struct InternalBeginResult {
    pub challenge: i64,
    pub params: Vec<KeyParam>,
    // Extra for internal use: returned by bottom half of KeyMint implementation, used on
    // all subsequent operation methods to identify the operation.
    pub op_handle: i64,
}

// The following types encapsulate the arguments to each method into a corresponding ..Request
// struct, and the return value and out parameters into a corresponding ..Response struct.
// These are currently hand-generated, but they could be auto-generated from the AIDL spec.

// IKeyMintDevice methods.
#[derive(Debug, AsCborValue)]
pub struct GetHardwareInfoRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetHardwareInfoResponse {
    pub ret: KeyMintHardwareInfo,
}
#[derive(Debug, AsCborValue)]
pub struct AddRngEntropyRequest {
    pub data: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct AddRngEntropyResponse {}
#[derive(Debug, AsCborValue)]
pub struct GenerateKeyRequest {
    pub key_params: Vec<KeyParam>,
    pub attestation_key: Option<AttestationKey>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct ImportKeyRequest {
    pub key_params: Vec<KeyParam>,
    pub key_format: KeyFormat,
    pub key_data: Vec<u8>,
    pub attestation_key: Option<AttestationKey>,
}
#[derive(Debug, AsCborValue)]
pub struct ImportKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct ImportWrappedKeyRequest {
    pub wrapped_key_data: Vec<u8>,
    pub wrapping_key_blob: Vec<u8>,
    pub masking_key: Vec<u8>,
    pub unwrapping_params: Vec<KeyParam>,
    pub password_sid: i64,
    pub biometric_sid: i64,
}
#[derive(Debug, AsCborValue)]
pub struct ImportWrappedKeyResponse {
    pub ret: KeyCreationResult,
}
#[derive(Debug, AsCborValue)]
pub struct UpgradeKeyRequest {
    pub key_blob_to_upgrade: Vec<u8>,
    pub upgrade_params: Vec<KeyParam>,
}
#[derive(Debug, AsCborValue)]
pub struct UpgradeKeyResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct DeleteKeyRequest {
    pub key_blob: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct DeleteKeyResponse {}
#[derive(Debug, AsCborValue)]
pub struct DeleteAllKeysRequest {}
#[derive(Debug, AsCborValue)]
pub struct DeleteAllKeysResponse {}
#[derive(Debug, AsCborValue)]
pub struct DestroyAttestationIdsRequest {}
#[derive(Debug, AsCborValue)]
pub struct DestroyAttestationIdsResponse {}
#[derive(Debug, AsCborValue)]
pub struct BeginRequest {
    pub purpose: KeyPurpose,
    pub key_blob: Vec<u8>,
    pub params: Vec<KeyParam>,
    pub auth_token: Option<HardwareAuthToken>,
}
#[derive(Debug, AsCborValue)]
pub struct BeginResponse {
    pub ret: InternalBeginResult, // special case: no Binder ref here
}
#[derive(Debug, AsCborValue)]
pub struct EarlyBootEndedRequest {}
#[derive(Debug, AsCborValue)]
pub struct EarlyBootEndedResponse {}
#[derive(Debug, AsCborValue)]
pub struct ConvertStorageKeyToEphemeralRequest {
    pub storage_key_blob: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct ConvertStorageKeyToEphemeralResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GetKeyCharacteristicsRequest {
    pub key_blob: Vec<u8>,
    pub app_id: Vec<u8>,
    pub app_data: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GetKeyCharacteristicsResponse {
    pub ret: Vec<KeyCharacteristics>,
}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustChallengeRequest {}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustChallengeResponse {
    pub ret: [u8; 16],
}

#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustRequest {
    pub challenge: [u8; 16],
}
#[derive(Debug, AsCborValue)]
pub struct GetRootOfTrustResponse {
    pub ret: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct SendRootOfTrustRequest {
    pub root_of_trust: Vec<u8>,
}

#[derive(Debug, AsCborValue)]
pub struct SendRootOfTrustResponse {}

#[derive(Debug, AsCborValue)]
pub struct SetAdditionalAttestationInfoRequest {
    pub info: Vec<KeyParam>,
}

#[derive(Debug, AsCborValue)]
pub struct SetAdditionalAttestationInfoResponse {}

// IKeyMintOperation methods.  These ...Request structures include an extra `op_handle` field whose
// value was returned in the `InternalBeginResult` type and which identifies the operation in
// progress.
//
// `Debug` deliberately not derived to reduce the chances of inadvertent leakage of private info.
#[derive(Debug, Clone, AsCborValue)]
pub struct UpdateAadRequest {
    pub op_handle: i64, // Extra for internal use, from `InternalBeginResult`.
    pub input: Vec<u8>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
}
#[derive(Debug, AsCborValue)]
pub struct UpdateAadResponse {}
#[derive(Debug, Clone, AsCborValue)]
pub struct UpdateRequest {
    pub op_handle: i64, // Extra for internal use, from `InternalBeginResult`.
    pub input: Vec<u8>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
}
#[derive(Debug, AsCborValue)]
pub struct UpdateResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct FinishRequest {
    pub op_handle: i64, // Extra for internal use, from `InternalBeginResult`.
    pub input: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub auth_token: Option<HardwareAuthToken>,
    pub timestamp_token: Option<TimeStampToken>,
    pub confirmation_token: Option<Vec<u8>>,
}
#[derive(Debug, AsCborValue)]
pub struct FinishResponse {
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct AbortRequest {
    pub op_handle: i64, // Extra for internal use, from `InternalBeginResult`.
}
#[derive(Debug, AsCborValue)]
pub struct AbortResponse {}

// IRemotelyProvisionedComponent methods.

#[derive(Debug, AsCborValue)]
pub struct GetRpcHardwareInfoRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetRpcHardwareInfoResponse {
    pub ret: rpc::HardwareInfo,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateEcdsaP256KeyPairRequest {
    pub test_mode: bool,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateEcdsaP256KeyPairResponse {
    pub maced_public_key: rpc::MacedPublicKey,
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestRequest {
    pub test_mode: bool,
    pub keys_to_sign: Vec<rpc::MacedPublicKey>,
    pub endpoint_encryption_cert_chain: Vec<u8>,
    pub challenge: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestResponse {
    pub device_info: rpc::DeviceInfo,
    pub protected_data: rpc::ProtectedData,
    pub ret: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestV2Request {
    pub keys_to_sign: Vec<rpc::MacedPublicKey>,
    pub challenge: Vec<u8>,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateCertificateRequestV2Response {
    pub ret: Vec<u8>,
}

// ISharedSecret methods.
#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParametersRequest {}
#[derive(Debug, AsCborValue)]
pub struct GetSharedSecretParametersResponse {
    pub ret: SharedSecretParameters,
}
#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretRequest {
    pub params: Vec<SharedSecretParameters>,
}
#[derive(Debug, AsCborValue)]
pub struct ComputeSharedSecretResponse {
    pub ret: Vec<u8>,
}

// ISecureClock methods.
#[derive(Debug, AsCborValue)]
pub struct GenerateTimeStampRequest {
    pub challenge: i64,
}
#[derive(Debug, AsCborValue)]
pub struct GenerateTimeStampResponse {
    pub ret: TimeStampToken,
}

// The following messages have no equivalent on a HAL interface, but are used internally
// between components.

// HAL->TA at start of day.
#[derive(Debug, PartialEq, Eq, AsCborValue)]
pub struct SetHalInfoRequest {
    pub os_version: u32,
    pub os_patchlevel: u32,     // YYYYMM format
    pub vendor_patchlevel: u32, // YYYYMMDD format
}
#[derive(Debug, AsCborValue)]
pub struct SetHalInfoResponse {}

// HAL->TA at start of day.
#[derive(Debug, PartialEq, Eq, AsCborValue)]
pub struct SetHalVersionRequest {
    pub aidl_version: u32,
}
#[derive(Debug, AsCborValue)]
pub struct SetHalVersionResponse {}

// Boot loader->TA at start of day.
#[derive(Debug, AsCborValue)]
pub struct SetBootInfoRequest {
    pub verified_boot_key: Vec<u8>,
    pub device_boot_locked: bool,
    pub verified_boot_state: i32,
    pub verified_boot_hash: Vec<u8>,
    pub boot_patchlevel: u32, // YYYYMMDD format
}
#[derive(Debug, AsCborValue)]
pub struct SetBootInfoResponse {}

/// Attestation ID information.
#[derive(Clone, Debug, AsCborValue, PartialEq, Eq, Default)]
pub struct AttestationIdInfo {
    // The following fields are byte vectors that typically hold UTF-8 string data.
    pub brand: Vec<u8>,
    pub device: Vec<u8>,
    pub product: Vec<u8>,
    pub serial: Vec<u8>,
    pub imei: Vec<u8>,
    pub imei2: Vec<u8>,
    pub meid: Vec<u8>,
    pub manufacturer: Vec<u8>,
    pub model: Vec<u8>,
}

unsafe impl Sync for AttestationIdInfo {}

// Provisioner->TA at device provisioning time.
#[derive(Debug, AsCborValue)]
pub struct SetAttestationIdsRequest {
    pub ids: AttestationIdInfo,
}
#[derive(Debug, AsCborValue)]
pub struct SetAttestationIdsResponse {}

// Result of an operation, as an error code and a response message (only present when
// `error_code` is zero).
#[derive(AsCborValue, Debug)]
pub struct PerformOpResponse {
    pub error_code: i32,
    pub rsp: Option<PerformOpRsp>,
}

/// Declare a collection of related enums for a code and a pair of types.
///
/// An invocation like:
/// ```ignore
/// declare_req_rsp_enums! { KeyMintOperation  => (PerformOpReq, PerformOpRsp) {
///     DeviceGetHardwareInfo = 0x11 => (GetHardwareInfoRequest, GetHardwareInfoResponse),
///     DeviceAddRngEntropy = 0x12 =>   (AddRngEntropyRequest, AddRngEntropyResponse),
/// } }
/// ```
/// will emit three `enum` types all of whose variant names are the same (taken from the leftmost
/// column), but whose contents are:
///
/// - the numeric values (second column)
///   ```ignore
///   #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
///   enum KeyMintOperation {
///       DeviceGetHardwareInfo = 0x11,
///       DeviceAddRngEntropy = 0x12,
///   }
///   ```
///
/// - the types from the third column:
///   ```ignore
///   #[derive(Debug)]
///   enum PerformOpReq {
///       DeviceGetHardwareInfo(GetHardwareInfoRequest),
///       DeviceAddRngEntropy(AddRngEntropyRequest),
///   }
///   ```
///
/// - the types from the fourth column:
///   ```ignore
///   #[derive(Debug)]
///   enum PerformOpRsp {
///       DeviceGetHardwareInfo(GetHardwareInfoResponse),
///       DeviceAddRngEntropy(AddRngEntropyResponse),
///   }
//   ```
///
/// Each of these enum types will also get an implementation of [`AsCborValue`]
macro_rules! declare_req_rsp_enums {
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident)
        {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {
        declare_req_rsp_enums! { $cenum => ($reqenum, $rspenum)
                                 ( concat!("&(\n",
                                           $( "    [", stringify!($cname), ", {}],\n", )*
                                           ")") )
          {
            $( $cname = $cvalue => ($reqtyp, $rsptyp), )*
        } }
    };
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident) ( $cddlfmt:expr )
        {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {

        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, N)]
        pub enum $cenum {
            $( $cname = $cvalue, )*
        }

        impl AsCborValue for $cenum {
            /// Create an instance of the enum from a [`cbor::value::Value`], checking that the
            /// value is valid.
            fn from_cbor_value(value: $crate::cbor::value::Value) ->
                Result<Self, crate::CborError> {
                use core::convert::TryInto;
                // First get the int value as an `i32`.
                let v: i32 = match value {
                    $crate::cbor::value::Value::Integer(i) => i.try_into().map_err(|_| {
                        crate::CborError::OutOfRangeIntegerValue
                    })?,
                    v => return crate::cbor_type_error(&v, &"int"),
                };
                // Now check it is one of the defined enum values.
                Self::n(v).ok_or(crate::CborError::NonEnumValue)
            }
            /// Convert the enum value to a [`cbor::value::Value`] (without checking that the
            /// contained enum value is valid).
            fn to_cbor_value(self) -> Result<$crate::cbor::value::Value, crate::CborError> {
                Ok($crate::cbor::value::Value::Integer((self as i64).into()))
            }
            fn cddl_typename() -> Option<String> {
                Some(stringify!($cenum).to_string())
            }
            fn cddl_schema() -> Option<String> {
                Some( concat!("&(\n",
                              $( "    ", stringify!($cname), ": ", stringify!($cvalue), ",\n", )*
                              ")").to_string() )
            }
        }

        #[derive(Debug)]
        pub enum $reqenum {
            $( $cname($reqtyp), )*
        }

        impl $reqenum {
            pub fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }

        #[derive(Debug)]
        pub enum $rspenum {
            $( $cname($rsptyp), )*
        }

        impl AsCborValue for $reqenum {
            fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
                let mut a = match value {
                    cbor::value::Value::Array(a) => a,
                    _ => return crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$reqtyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
                Ok(cbor::value::Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec_try![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]?
                    }, )*
                }))
            }

            fn cddl_typename() -> Option<String> {
                Some(stringify!($reqenum).to_string())
            }

            fn cddl_schema() -> Option<String> {
                Some(format!($cddlfmt,
                             $( <$reqtyp>::cddl_ref(), )*
                ))
            }
        }

        impl AsCborValue for $rspenum {
            fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
                let mut a = match value {
                    cbor::value::Value::Array(a) => a,
                    _ => return crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err(CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$rsptyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
                Ok(cbor::value::Value::Array(match self {
                    $( Self::$cname(val) => {
                        vec_try![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]?
                    }, )*
                }))
            }

            fn cddl_typename() -> Option<String> {
                Some(stringify!($rspenum).to_string())
            }

            fn cddl_schema() -> Option<String> {
                Some(format!($cddlfmt,
                             $( <$rsptyp>::cddl_ref(), )*
                ))
            }
        }

        $(
            impl Code<$cenum> for $reqtyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*

        $(
            impl Code<$cenum> for $rsptyp {
                const CODE: $cenum = $cenum::$cname;
            }
        )*
    };
}

// Possible KeyMint operation requests, as:
// - an enum value with an explicit numeric value
// - a request enum which has an operation code associated to each variant
// - a response enum which has the same operation code associated to each variant.
declare_req_rsp_enums! { KeyMintOperation  =>    (PerformOpReq, PerformOpRsp) {
    DeviceGetHardwareInfo = 0x11 =>                    (GetHardwareInfoRequest, GetHardwareInfoResponse),
    DeviceAddRngEntropy = 0x12 =>                      (AddRngEntropyRequest, AddRngEntropyResponse),
    DeviceGenerateKey = 0x13 =>                        (GenerateKeyRequest, GenerateKeyResponse),
    DeviceImportKey = 0x14 =>                          (ImportKeyRequest, ImportKeyResponse),
    DeviceImportWrappedKey = 0x15 =>                   (ImportWrappedKeyRequest, ImportWrappedKeyResponse),
    DeviceUpgradeKey = 0x16 =>                         (UpgradeKeyRequest, UpgradeKeyResponse),
    DeviceDeleteKey = 0x17 =>                          (DeleteKeyRequest, DeleteKeyResponse),
    DeviceDeleteAllKeys = 0x18 =>                      (DeleteAllKeysRequest, DeleteAllKeysResponse),
    DeviceDestroyAttestationIds = 0x19 =>              (DestroyAttestationIdsRequest, DestroyAttestationIdsResponse),
    DeviceBegin = 0x1a =>                              (BeginRequest, BeginResponse),
    // 0x1b used to be DeviceDeviceLocked, but it was never used and consequently was removed.
    DeviceEarlyBootEnded = 0x1c =>                     (EarlyBootEndedRequest, EarlyBootEndedResponse),
    DeviceConvertStorageKeyToEphemeral = 0x1d =>       (ConvertStorageKeyToEphemeralRequest, ConvertStorageKeyToEphemeralResponse),
    DeviceGetKeyCharacteristics = 0x1e =>              (GetKeyCharacteristicsRequest, GetKeyCharacteristicsResponse),
    OperationUpdateAad = 0x31 =>                       (UpdateAadRequest, UpdateAadResponse),
    OperationUpdate = 0x32 =>                          (UpdateRequest, UpdateResponse),
    OperationFinish = 0x33 =>                          (FinishRequest, FinishResponse),
    OperationAbort = 0x34 =>                           (AbortRequest, AbortResponse),
    RpcGetHardwareInfo = 0x41 =>                       (GetRpcHardwareInfoRequest, GetRpcHardwareInfoResponse),
    RpcGenerateEcdsaP256KeyPair = 0x42 =>              (GenerateEcdsaP256KeyPairRequest, GenerateEcdsaP256KeyPairResponse),
    RpcGenerateCertificateRequest = 0x43 =>            (GenerateCertificateRequestRequest, GenerateCertificateRequestResponse),
    RpcGenerateCertificateV2Request = 0x44 =>          (GenerateCertificateRequestV2Request, GenerateCertificateRequestV2Response),
    SharedSecretGetSharedSecretParameters = 0x51 =>    (GetSharedSecretParametersRequest, GetSharedSecretParametersResponse),
    SharedSecretComputeSharedSecret = 0x52 =>          (ComputeSharedSecretRequest, ComputeSharedSecretResponse),
    SecureClockGenerateTimeStamp = 0x61 =>             (GenerateTimeStampRequest, GenerateTimeStampResponse),
    GetRootOfTrustChallenge = 0x71 =>                  (GetRootOfTrustChallengeRequest, GetRootOfTrustChallengeResponse),
    GetRootOfTrust = 0x72 =>                           (GetRootOfTrustRequest, GetRootOfTrustResponse),
    SendRootOfTrust = 0x73 =>                          (SendRootOfTrustRequest, SendRootOfTrustResponse),
    SetHalInfo = 0x81 =>                               (SetHalInfoRequest, SetHalInfoResponse),
    SetBootInfo = 0x82 =>                              (SetBootInfoRequest, SetBootInfoResponse),
    SetAttestationIds = 0x83 =>                        (SetAttestationIdsRequest, SetAttestationIdsResponse),
    SetHalVersion = 0x84 =>                            (SetHalVersionRequest, SetHalVersionResponse),
    SetAdditionalAttestationInfo = 0x91 =>             (SetAdditionalAttestationInfoRequest, SetAdditionalAttestationInfoResponse),
} }

/// Indicate whether an operation is part of the `IRemotelyProvisionedComponent` HAL.
pub fn is_rpc_operation(code: KeyMintOperation) -> bool {
    matches!(
        code,
        KeyMintOperation::RpcGetHardwareInfo
            | KeyMintOperation::RpcGenerateEcdsaP256KeyPair
            | KeyMintOperation::RpcGenerateCertificateRequest
            | KeyMintOperation::RpcGenerateCertificateV2Request
    )
}
