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

//! Local types that are equivalent to those generated for KeyMint HAL interfaces
//!
//! - Enums are encoded as exhaustive Rust enums backed by `i32`, using Rust naming
//!   conventions (CamelCase values).
//! - Structs have all fields `pub`, using Rust naming conventions (snake_case fields).
//! - Both enums and structs get a `[derive(AsCborValue)]`
//!
//! Special cases:
//! - The `BeginResult` type of the HAL interface is omitted here, as it includes a
//!   Binder reference.
//! - `Tag` is private to this module, because....
//! - `KeyParam` is a Rust `enum` that is used in place of the `KeyParameter` struct, meaning...
//! - `KeyParameterValue` is not included here.

use crate::{
    cbor, cbor_type_error, try_from_n, vec_try, AsCborValue, CborError, KeySizeInBits, RsaExponent,
};
use enumn::N;
use kmr_derive::{AsCborValue, FromRawTag};

/// Default certificate serial number of 1.
pub const DEFAULT_CERT_SERIAL: &[u8] = &[0x01];

/// ASN.1 DER encoding of the default certificate subject of 'CN=Android Keystore Key'.
pub const DEFAULT_CERT_SUBJECT: &[u8] = &[
    0x30, 0x1f, // SEQUENCE len 31
    0x31, 0x1d, // SET len 29
    0x30, 0x1b, // SEQUENCE len 27
    0x06, 0x03, // OBJECT IDENTIFIER len 3
    0x55, 0x04, 0x03, // 2.5.4.3 (commonName)
    0x0c, 0x14, // UTF8String len 20
    0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65,
    0x20, 0x4b, 0x65, 0x79, // "Android Keystore Key"
];

/// Constants to indicate whether or not to include/expect more messages when splitting and then
/// assembling the large responses sent from the TA to the HAL.
pub const NEXT_MESSAGE_SIGNAL_TRUE: u8 = 0b00000001u8;
pub const NEXT_MESSAGE_SIGNAL_FALSE: u8 = 0b00000000u8;

/// We use Unix epoch as the start date of an undefined certificate validity period.
pub const UNDEFINED_NOT_BEFORE: DateTime = DateTime { ms_since_epoch: 0 };
/// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to
/// 9999-12-31T23:59:59Z.
pub const UNDEFINED_NOT_AFTER: DateTime = DateTime {
    ms_since_epoch: 253402300799000,
};

/// Possible verified boot state values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, N, AsCborValue)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl TryFrom<i32> for VerifiedBootState {
    type Error = CborError;
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        Self::n(v).ok_or(CborError::OutOfRangeIntegerValue)
    }
}

/// Information provided once at start-of-day, normally by the bootloader.
///
/// Field order is fixed, to match the CBOR type definition of `RootOfTrust` in `IKeyMintDevice`.
#[derive(Clone, Debug, AsCborValue, PartialEq, Eq)]
pub struct BootInfo {
    pub verified_boot_key: Vec<u8>,
    pub device_boot_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Vec<u8>,
    pub boot_patchlevel: u32, // YYYYMMDD format
}

// Implement the `coset` CBOR serialization traits in terms of the local `AsCborValue` trait,
// in order to get access to tagged versions of serialize/deserialize.
impl coset::AsCborValue for BootInfo {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        <Self as AsCborValue>::from_cbor_value(value).map_err(|e| e.into())
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        <Self as AsCborValue>::to_cbor_value(self).map_err(|e| e.into())
    }
}

impl coset::TaggedCborSerializable for BootInfo {
    const TAG: u64 = 40001;
}

/// Representation of a date/time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime {
    pub ms_since_epoch: i64,
}

impl AsCborValue for DateTime {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let val = <i64>::from_cbor_value(value)?;
        Ok(Self {
            ms_since_epoch: val,
        })
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        self.ms_since_epoch.to_cbor_value()
    }
    fn cddl_typename() -> Option<String> {
        Some("DateTime".to_string())
    }
    fn cddl_schema() -> Option<String> {
        Some("int".to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum Algorithm {
    Rsa = 1,
    Ec = 3,
    Aes = 32,
    TripleDes = 33,
    Hmac = 128,
}
try_from_n!(Algorithm);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct AttestationKey {
    pub key_blob: Vec<u8>,
    pub attest_key_params: Vec<KeyParam>,
    pub issuer_subject_name: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum BlockMode {
    Ecb = 1,
    Cbc = 2,
    Ctr = 3,
    Gcm = 32,
}
try_from_n!(BlockMode);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct Certificate {
    pub encoded_certificate: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum Digest {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
}
try_from_n!(Digest);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum EcCurve {
    P224 = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
    #[cfg(feature = "hal_v2")]
    Curve25519 = 4,
}
try_from_n!(EcCurve);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0,
    RootOfTrustAlreadySet = -1,
    UnsupportedPurpose = -2,
    IncompatiblePurpose = -3,
    UnsupportedAlgorithm = -4,
    IncompatibleAlgorithm = -5,
    UnsupportedKeySize = -6,
    UnsupportedBlockMode = -7,
    IncompatibleBlockMode = -8,
    UnsupportedMacLength = -9,
    UnsupportedPaddingMode = -10,
    IncompatiblePaddingMode = -11,
    UnsupportedDigest = -12,
    IncompatibleDigest = -13,
    InvalidExpirationTime = -14,
    InvalidUserId = -15,
    InvalidAuthorizationTimeout = -16,
    UnsupportedKeyFormat = -17,
    IncompatibleKeyFormat = -18,
    UnsupportedKeyEncryptionAlgorithm = -19,
    UnsupportedKeyVerificationAlgorithm = -20,
    InvalidInputLength = -21,
    KeyExportOptionsInvalid = -22,
    DelegationNotAllowed = -23,
    KeyNotYetValid = -24,
    KeyExpired = -25,
    KeyUserNotAuthenticated = -26,
    OutputParameterNull = -27,
    InvalidOperationHandle = -28,
    InsufficientBufferSpace = -29,
    VerificationFailed = -30,
    TooManyOperations = -31,
    UnexpectedNullPointer = -32,
    InvalidKeyBlob = -33,
    ImportedKeyNotEncrypted = -34,
    ImportedKeyDecryptionFailed = -35,
    ImportedKeyNotSigned = -36,
    ImportedKeyVerificationFailed = -37,
    InvalidArgument = -38,
    UnsupportedTag = -39,
    InvalidTag = -40,
    MemoryAllocationFailed = -41,
    ImportParameterMismatch = -44,
    SecureHwAccessDenied = -45,
    OperationCancelled = -46,
    ConcurrentAccessConflict = -47,
    SecureHwBusy = -48,
    SecureHwCommunicationFailed = -49,
    UnsupportedEcField = -50,
    MissingNonce = -51,
    InvalidNonce = -52,
    MissingMacLength = -53,
    KeyRateLimitExceeded = -54,
    CallerNonceProhibited = -55,
    KeyMaxOpsExceeded = -56,
    InvalidMacLength = -57,
    MissingMinMacLength = -58,
    UnsupportedMinMacLength = -59,
    UnsupportedKdf = -60,
    UnsupportedEcCurve = -61,
    KeyRequiresUpgrade = -62,
    AttestationChallengeMissing = -63,
    KeymintNotConfigured = -64,
    AttestationApplicationIdMissing = -65,
    CannotAttestIds = -66,
    RollbackResistanceUnavailable = -67,
    HardwareTypeUnavailable = -68,
    ProofOfPresenceRequired = -69,
    ConcurrentProofOfPresenceRequested = -70,
    NoUserConfirmation = -71,
    DeviceLocked = -72,
    EarlyBootEnded = -73,
    AttestationKeysNotProvisioned = -74,
    AttestationIdsNotProvisioned = -75,
    InvalidOperation = -76,
    StorageKeyUnsupported = -77,
    IncompatibleMgfDigest = -78,
    UnsupportedMgfDigest = -79,
    MissingNotBefore = -80,
    MissingNotAfter = -81,
    MissingIssuerSubject = -82,
    InvalidIssuerSubject = -83,
    BootLevelExceeded = -84,
    HardwareNotYetAvailable = -85,
    ModuleHashAlreadySet = -86,
    Unimplemented = -100,
    VersionMismatch = -101,
    UnknownError = -1000,
    // Implementer's namespace for error codes starts at -10000.
    EncodingError = -20000,
    BoringSslError = -30000,
}
try_from_n!(ErrorCode);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct HardwareAuthToken {
    pub challenge: i64,
    pub user_id: i64,
    pub authenticator_id: i64,
    pub authenticator_type: HardwareAuthenticatorType,
    pub timestamp: super::secureclock::Timestamp,
    pub mac: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum HardwareAuthenticatorType {
    None = 0,
    Password = 1,
    Fingerprint = 2,
    Any = -1,
}
try_from_n!(HardwareAuthenticatorType);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct KeyCharacteristics {
    pub security_level: SecurityLevel,
    pub authorizations: Vec<KeyParam>,
}

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct KeyCreationResult {
    pub key_blob: Vec<u8>,
    pub key_characteristics: Vec<KeyCharacteristics>,
    pub certificate_chain: Vec<Certificate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum KeyFormat {
    X509 = 0,
    Pkcs8 = 1,
    Raw = 3,
}
try_from_n!(KeyFormat);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct KeyMintHardwareInfo {
    pub version_number: i32,
    pub security_level: SecurityLevel,
    pub key_mint_name: String,
    pub key_mint_author_name: String,
    pub timestamp_token_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum KeyOrigin {
    Generated = 0,
    Derived = 1,
    Imported = 2,
    Reserved = 3,
    SecurelyImported = 4,
}
try_from_n!(KeyOrigin);

/// Rust exhaustive enum for all key parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyParam {
    Purpose(KeyPurpose),
    Algorithm(Algorithm),
    KeySize(KeySizeInBits),
    BlockMode(BlockMode),
    Digest(Digest),
    Padding(PaddingMode),
    CallerNonce,
    MinMacLength(u32),
    EcCurve(EcCurve),
    RsaPublicExponent(RsaExponent),
    IncludeUniqueId,
    RsaOaepMgfDigest(Digest),
    BootloaderOnly,
    RollbackResistance,
    EarlyBootOnly,
    ActiveDatetime(DateTime),
    OriginationExpireDatetime(DateTime),
    UsageExpireDatetime(DateTime),
    MaxUsesPerBoot(u32),
    UsageCountLimit(u32),
    UserId(u32),
    UserSecureId(u64),
    NoAuthRequired,
    UserAuthType(u32),
    AuthTimeout(u32),
    AllowWhileOnBody,
    TrustedUserPresenceRequired,
    TrustedConfirmationRequired,
    UnlockedDeviceRequired,
    ApplicationId(Vec<u8>),
    ApplicationData(Vec<u8>),
    CreationDatetime(DateTime),
    Origin(KeyOrigin),
    RootOfTrust(Vec<u8>),
    OsVersion(u32),
    OsPatchlevel(u32),
    AttestationChallenge(Vec<u8>),
    AttestationApplicationId(Vec<u8>),
    AttestationIdBrand(Vec<u8>),
    AttestationIdDevice(Vec<u8>),
    AttestationIdProduct(Vec<u8>),
    AttestationIdSerial(Vec<u8>),
    AttestationIdImei(Vec<u8>),
    #[cfg(feature = "hal_v3")]
    AttestationIdSecondImei(Vec<u8>),
    AttestationIdMeid(Vec<u8>),
    AttestationIdManufacturer(Vec<u8>),
    AttestationIdModel(Vec<u8>),
    VendorPatchlevel(u32),
    BootPatchlevel(u32),
    DeviceUniqueAttestation,
    StorageKey,
    Nonce(Vec<u8>),
    MacLength(u32),
    ResetSinceIdRotation,
    CertificateSerial(Vec<u8>),
    CertificateSubject(Vec<u8>),
    CertificateNotBefore(DateTime),
    CertificateNotAfter(DateTime),
    MaxBootLevel(u32),
    #[cfg(feature = "hal_v4")]
    ModuleHash(Vec<u8>),
}

impl KeyParam {
    pub fn tag(&self) -> Tag {
        match self {
            KeyParam::Algorithm(_) => Tag::Algorithm,
            KeyParam::BlockMode(_) => Tag::BlockMode,
            KeyParam::Padding(_) => Tag::Padding,
            KeyParam::Digest(_) => Tag::Digest,
            KeyParam::EcCurve(_) => Tag::EcCurve,
            KeyParam::Origin(_) => Tag::Origin,
            KeyParam::Purpose(_) => Tag::Purpose,
            KeyParam::KeySize(_) => Tag::KeySize,
            KeyParam::CallerNonce => Tag::CallerNonce,
            KeyParam::MinMacLength(_) => Tag::MinMacLength,
            KeyParam::RsaPublicExponent(_) => Tag::RsaPublicExponent,
            KeyParam::IncludeUniqueId => Tag::IncludeUniqueId,
            KeyParam::RsaOaepMgfDigest(_) => Tag::RsaOaepMgfDigest,
            KeyParam::BootloaderOnly => Tag::BootloaderOnly,
            KeyParam::RollbackResistance => Tag::RollbackResistance,
            KeyParam::EarlyBootOnly => Tag::EarlyBootOnly,
            KeyParam::ActiveDatetime(_) => Tag::ActiveDatetime,
            KeyParam::OriginationExpireDatetime(_) => Tag::OriginationExpireDatetime,
            KeyParam::UsageExpireDatetime(_) => Tag::UsageExpireDatetime,
            KeyParam::MaxUsesPerBoot(_) => Tag::MaxUsesPerBoot,
            KeyParam::UsageCountLimit(_) => Tag::UsageCountLimit,
            KeyParam::UserId(_) => Tag::UserId,
            KeyParam::UserSecureId(_) => Tag::UserSecureId,
            KeyParam::NoAuthRequired => Tag::NoAuthRequired,
            KeyParam::UserAuthType(_) => Tag::UserAuthType,
            KeyParam::AuthTimeout(_) => Tag::AuthTimeout,
            KeyParam::AllowWhileOnBody => Tag::AllowWhileOnBody,
            KeyParam::TrustedUserPresenceRequired => Tag::TrustedUserPresenceRequired,
            KeyParam::TrustedConfirmationRequired => Tag::TrustedConfirmationRequired,
            KeyParam::UnlockedDeviceRequired => Tag::UnlockedDeviceRequired,
            KeyParam::ApplicationId(_) => Tag::ApplicationId,
            KeyParam::ApplicationData(_) => Tag::ApplicationData,
            KeyParam::CreationDatetime(_) => Tag::CreationDatetime,
            KeyParam::RootOfTrust(_) => Tag::RootOfTrust,
            KeyParam::OsVersion(_) => Tag::OsVersion,
            KeyParam::OsPatchlevel(_) => Tag::OsPatchlevel,
            KeyParam::AttestationChallenge(_) => Tag::AttestationChallenge,
            KeyParam::AttestationApplicationId(_) => Tag::AttestationApplicationId,
            KeyParam::AttestationIdBrand(_) => Tag::AttestationIdBrand,
            KeyParam::AttestationIdDevice(_) => Tag::AttestationIdDevice,
            KeyParam::AttestationIdProduct(_) => Tag::AttestationIdProduct,
            KeyParam::AttestationIdSerial(_) => Tag::AttestationIdSerial,
            KeyParam::AttestationIdImei(_) => Tag::AttestationIdImei,
            #[cfg(feature = "hal_v3")]
            KeyParam::AttestationIdSecondImei(_) => Tag::AttestationIdSecondImei,
            KeyParam::AttestationIdMeid(_) => Tag::AttestationIdMeid,
            KeyParam::AttestationIdManufacturer(_) => Tag::AttestationIdManufacturer,
            KeyParam::AttestationIdModel(_) => Tag::AttestationIdModel,
            KeyParam::VendorPatchlevel(_) => Tag::VendorPatchlevel,
            KeyParam::BootPatchlevel(_) => Tag::BootPatchlevel,
            KeyParam::DeviceUniqueAttestation => Tag::DeviceUniqueAttestation,
            KeyParam::StorageKey => Tag::StorageKey,
            KeyParam::Nonce(_) => Tag::Nonce,
            KeyParam::MacLength(_) => Tag::MacLength,
            KeyParam::ResetSinceIdRotation => Tag::ResetSinceIdRotation,
            KeyParam::CertificateSerial(_) => Tag::CertificateSerial,
            KeyParam::CertificateSubject(_) => Tag::CertificateSubject,
            KeyParam::CertificateNotBefore(_) => Tag::CertificateNotBefore,
            KeyParam::CertificateNotAfter(_) => Tag::CertificateNotAfter,
            KeyParam::MaxBootLevel(_) => Tag::MaxBootLevel,
            #[cfg(feature = "hal_v4")]
            KeyParam::ModuleHash(_) => Tag::ModuleHash,
        }
    }
}

/// Check that a `bool` value is true (false values are represented by the absence of a tag).
fn check_bool(value: cbor::value::Value) -> Result<(), crate::CborError> {
    match value {
        cbor::value::Value::Bool(true) => Ok(()),
        cbor::value::Value::Bool(false) => Err(crate::CborError::UnexpectedItem("false", "true")),
        _ => crate::cbor_type_error(&value, "true"),
    }
}

/// Manual implementation of [`crate::AsCborValue`] for the [`KeyParam`] enum that
/// matches the serialization of the HAL `Tag` / `KeyParameterValue` types.
impl crate::AsCborValue for KeyParam {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, crate::CborError> {
        let mut a = match value {
            cbor::value::Value::Array(a) => a,
            _ => return crate::cbor_type_error(&value, "arr"),
        };
        if a.len() != 2 {
            return Err(crate::CborError::UnexpectedItem("arr", "arr len 2"));
        }

        // Need to know the tag value to completely parse the value.
        let raw = a.remove(1);
        let tag = <Tag>::from_cbor_value(a.remove(0))?;

        Ok(match tag {
            Tag::Algorithm => KeyParam::Algorithm(<Algorithm>::from_cbor_value(raw)?),
            Tag::BlockMode => KeyParam::BlockMode(<BlockMode>::from_cbor_value(raw)?),
            Tag::Padding => KeyParam::Padding(<PaddingMode>::from_cbor_value(raw)?),
            Tag::Digest => KeyParam::Digest(<Digest>::from_cbor_value(raw)?),
            Tag::EcCurve => KeyParam::EcCurve(<EcCurve>::from_cbor_value(raw)?),
            Tag::Origin => KeyParam::Origin(<KeyOrigin>::from_cbor_value(raw)?),
            Tag::Purpose => KeyParam::Purpose(<KeyPurpose>::from_cbor_value(raw)?),
            Tag::KeySize => KeyParam::KeySize(<KeySizeInBits>::from_cbor_value(raw)?),
            Tag::CallerNonce => KeyParam::CallerNonce,
            Tag::MinMacLength => KeyParam::MinMacLength(<u32>::from_cbor_value(raw)?),
            Tag::RsaPublicExponent => {
                KeyParam::RsaPublicExponent(<RsaExponent>::from_cbor_value(raw)?)
            }
            Tag::IncludeUniqueId => {
                check_bool(raw)?;
                KeyParam::IncludeUniqueId
            }
            Tag::RsaOaepMgfDigest => KeyParam::RsaOaepMgfDigest(<Digest>::from_cbor_value(raw)?),
            Tag::BootloaderOnly => {
                check_bool(raw)?;
                KeyParam::BootloaderOnly
            }
            Tag::RollbackResistance => {
                check_bool(raw)?;
                KeyParam::RollbackResistance
            }
            Tag::EarlyBootOnly => {
                check_bool(raw)?;
                KeyParam::EarlyBootOnly
            }
            Tag::ActiveDatetime => KeyParam::ActiveDatetime(<DateTime>::from_cbor_value(raw)?),
            Tag::OriginationExpireDatetime => {
                KeyParam::OriginationExpireDatetime(<DateTime>::from_cbor_value(raw)?)
            }
            Tag::UsageExpireDatetime => {
                KeyParam::UsageExpireDatetime(<DateTime>::from_cbor_value(raw)?)
            }
            Tag::MaxUsesPerBoot => KeyParam::MaxUsesPerBoot(<u32>::from_cbor_value(raw)?),
            Tag::UsageCountLimit => KeyParam::UsageCountLimit(<u32>::from_cbor_value(raw)?),
            Tag::UserId => KeyParam::UserId(<u32>::from_cbor_value(raw)?),
            Tag::UserSecureId => KeyParam::UserSecureId(<u64>::from_cbor_value(raw)?),
            Tag::NoAuthRequired => {
                check_bool(raw)?;
                KeyParam::NoAuthRequired
            }
            Tag::UserAuthType => KeyParam::UserAuthType(<u32>::from_cbor_value(raw)?),
            Tag::AuthTimeout => KeyParam::AuthTimeout(<u32>::from_cbor_value(raw)?),
            Tag::AllowWhileOnBody => KeyParam::AllowWhileOnBody,
            Tag::TrustedUserPresenceRequired => {
                check_bool(raw)?;
                KeyParam::TrustedUserPresenceRequired
            }
            Tag::TrustedConfirmationRequired => {
                check_bool(raw)?;
                KeyParam::TrustedConfirmationRequired
            }
            Tag::UnlockedDeviceRequired => {
                check_bool(raw)?;
                KeyParam::UnlockedDeviceRequired
            }
            Tag::ApplicationId => KeyParam::ApplicationId(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::ApplicationData => KeyParam::ApplicationData(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::CreationDatetime => KeyParam::CreationDatetime(<DateTime>::from_cbor_value(raw)?),
            Tag::RootOfTrust => KeyParam::RootOfTrust(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::OsVersion => KeyParam::OsVersion(<u32>::from_cbor_value(raw)?),
            Tag::OsPatchlevel => KeyParam::OsPatchlevel(<u32>::from_cbor_value(raw)?),
            Tag::AttestationChallenge => {
                KeyParam::AttestationChallenge(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationApplicationId => {
                KeyParam::AttestationApplicationId(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdBrand => {
                KeyParam::AttestationIdBrand(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdDevice => {
                KeyParam::AttestationIdDevice(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdProduct => {
                KeyParam::AttestationIdProduct(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdSerial => {
                KeyParam::AttestationIdSerial(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdImei => KeyParam::AttestationIdImei(<Vec<u8>>::from_cbor_value(raw)?),
            #[cfg(feature = "hal_v3")]
            Tag::AttestationIdSecondImei => {
                KeyParam::AttestationIdSecondImei(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdMeid => KeyParam::AttestationIdMeid(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::AttestationIdManufacturer => {
                KeyParam::AttestationIdManufacturer(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::AttestationIdModel => {
                KeyParam::AttestationIdModel(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::VendorPatchlevel => KeyParam::VendorPatchlevel(<u32>::from_cbor_value(raw)?),
            Tag::BootPatchlevel => KeyParam::BootPatchlevel(<u32>::from_cbor_value(raw)?),
            Tag::DeviceUniqueAttestation => {
                check_bool(raw)?;
                KeyParam::DeviceUniqueAttestation
            }
            Tag::StorageKey => KeyParam::StorageKey,
            Tag::Nonce => KeyParam::Nonce(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::MacLength => KeyParam::MacLength(<u32>::from_cbor_value(raw)?),
            Tag::ResetSinceIdRotation => {
                check_bool(raw)?;
                KeyParam::ResetSinceIdRotation
            }
            Tag::CertificateSerial => KeyParam::CertificateSerial(<Vec<u8>>::from_cbor_value(raw)?),
            Tag::CertificateSubject => {
                KeyParam::CertificateSubject(<Vec<u8>>::from_cbor_value(raw)?)
            }
            Tag::CertificateNotBefore => {
                KeyParam::CertificateNotBefore(<DateTime>::from_cbor_value(raw)?)
            }
            Tag::CertificateNotAfter => {
                KeyParam::CertificateNotAfter(<DateTime>::from_cbor_value(raw)?)
            }
            Tag::MaxBootLevel => KeyParam::MaxBootLevel(<u32>::from_cbor_value(raw)?),
            #[cfg(feature = "hal_v4")]
            Tag::ModuleHash => KeyParam::ModuleHash(<Vec<u8>>::from_cbor_value(raw)?),

            _ => return Err(crate::CborError::UnexpectedItem("tag", "known tag")),
        })
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, crate::CborError> {
        let (tag, val) = match self {
            KeyParam::Algorithm(v) => (Tag::Algorithm, v.to_cbor_value()?),
            KeyParam::BlockMode(v) => (Tag::BlockMode, v.to_cbor_value()?),
            KeyParam::Padding(v) => (Tag::Padding, v.to_cbor_value()?),
            KeyParam::Digest(v) => (Tag::Digest, v.to_cbor_value()?),
            KeyParam::EcCurve(v) => (Tag::EcCurve, v.to_cbor_value()?),
            KeyParam::Origin(v) => (Tag::Origin, v.to_cbor_value()?),
            KeyParam::Purpose(v) => (Tag::Purpose, v.to_cbor_value()?),
            KeyParam::KeySize(v) => (Tag::KeySize, v.to_cbor_value()?),
            KeyParam::CallerNonce => (Tag::CallerNonce, true.to_cbor_value()?),
            KeyParam::MinMacLength(v) => (Tag::MinMacLength, v.to_cbor_value()?),
            KeyParam::RsaPublicExponent(v) => (Tag::RsaPublicExponent, v.to_cbor_value()?),
            KeyParam::IncludeUniqueId => (Tag::IncludeUniqueId, true.to_cbor_value()?),
            KeyParam::RsaOaepMgfDigest(v) => (Tag::RsaOaepMgfDigest, v.to_cbor_value()?),
            KeyParam::BootloaderOnly => (Tag::BootloaderOnly, true.to_cbor_value()?),
            KeyParam::RollbackResistance => (Tag::RollbackResistance, true.to_cbor_value()?),
            KeyParam::EarlyBootOnly => (Tag::EarlyBootOnly, true.to_cbor_value()?),
            KeyParam::ActiveDatetime(v) => (Tag::ActiveDatetime, v.to_cbor_value()?),
            KeyParam::OriginationExpireDatetime(v) => {
                (Tag::OriginationExpireDatetime, v.to_cbor_value()?)
            }
            KeyParam::UsageExpireDatetime(v) => (Tag::UsageExpireDatetime, v.to_cbor_value()?),
            KeyParam::MaxUsesPerBoot(v) => (Tag::MaxUsesPerBoot, v.to_cbor_value()?),
            KeyParam::UsageCountLimit(v) => (Tag::UsageCountLimit, v.to_cbor_value()?),
            KeyParam::UserId(v) => (Tag::UserId, v.to_cbor_value()?),
            KeyParam::UserSecureId(v) => (Tag::UserSecureId, v.to_cbor_value()?),
            KeyParam::NoAuthRequired => (Tag::NoAuthRequired, true.to_cbor_value()?),
            KeyParam::UserAuthType(v) => (Tag::UserAuthType, v.to_cbor_value()?),
            KeyParam::AuthTimeout(v) => (Tag::AuthTimeout, v.to_cbor_value()?),
            KeyParam::AllowWhileOnBody => (Tag::AllowWhileOnBody, true.to_cbor_value()?),
            KeyParam::TrustedUserPresenceRequired => {
                (Tag::TrustedUserPresenceRequired, true.to_cbor_value()?)
            }
            KeyParam::TrustedConfirmationRequired => {
                (Tag::TrustedConfirmationRequired, true.to_cbor_value()?)
            }
            KeyParam::UnlockedDeviceRequired => {
                (Tag::UnlockedDeviceRequired, true.to_cbor_value()?)
            }
            KeyParam::ApplicationId(v) => (Tag::ApplicationId, v.to_cbor_value()?),
            KeyParam::ApplicationData(v) => (Tag::ApplicationData, v.to_cbor_value()?),
            KeyParam::CreationDatetime(v) => (Tag::CreationDatetime, v.to_cbor_value()?),
            KeyParam::RootOfTrust(v) => (Tag::RootOfTrust, v.to_cbor_value()?),
            KeyParam::OsVersion(v) => (Tag::OsVersion, v.to_cbor_value()?),
            KeyParam::OsPatchlevel(v) => (Tag::OsPatchlevel, v.to_cbor_value()?),
            KeyParam::AttestationChallenge(v) => (Tag::AttestationChallenge, v.to_cbor_value()?),
            KeyParam::AttestationApplicationId(v) => {
                (Tag::AttestationApplicationId, v.to_cbor_value()?)
            }
            KeyParam::AttestationIdBrand(v) => (Tag::AttestationIdBrand, v.to_cbor_value()?),
            KeyParam::AttestationIdDevice(v) => (Tag::AttestationIdDevice, v.to_cbor_value()?),
            KeyParam::AttestationIdProduct(v) => (Tag::AttestationIdProduct, v.to_cbor_value()?),
            KeyParam::AttestationIdSerial(v) => (Tag::AttestationIdSerial, v.to_cbor_value()?),
            KeyParam::AttestationIdImei(v) => (Tag::AttestationIdImei, v.to_cbor_value()?),
            #[cfg(feature = "hal_v3")]
            KeyParam::AttestationIdSecondImei(v) => {
                (Tag::AttestationIdSecondImei, v.to_cbor_value()?)
            }
            KeyParam::AttestationIdMeid(v) => (Tag::AttestationIdMeid, v.to_cbor_value()?),
            KeyParam::AttestationIdManufacturer(v) => {
                (Tag::AttestationIdManufacturer, v.to_cbor_value()?)
            }
            KeyParam::AttestationIdModel(v) => (Tag::AttestationIdModel, v.to_cbor_value()?),
            KeyParam::VendorPatchlevel(v) => (Tag::VendorPatchlevel, v.to_cbor_value()?),
            KeyParam::BootPatchlevel(v) => (Tag::BootPatchlevel, v.to_cbor_value()?),
            KeyParam::DeviceUniqueAttestation => {
                (Tag::DeviceUniqueAttestation, true.to_cbor_value()?)
            }
            KeyParam::StorageKey => (Tag::StorageKey, true.to_cbor_value()?),
            KeyParam::Nonce(v) => (Tag::Nonce, v.to_cbor_value()?),
            KeyParam::MacLength(v) => (Tag::MacLength, v.to_cbor_value()?),
            KeyParam::ResetSinceIdRotation => (Tag::ResetSinceIdRotation, true.to_cbor_value()?),
            KeyParam::CertificateSerial(v) => (Tag::CertificateSerial, v.to_cbor_value()?),
            KeyParam::CertificateSubject(v) => (Tag::CertificateSubject, v.to_cbor_value()?),
            KeyParam::CertificateNotBefore(v) => (Tag::CertificateNotBefore, v.to_cbor_value()?),
            KeyParam::CertificateNotAfter(v) => (Tag::CertificateNotAfter, v.to_cbor_value()?),
            KeyParam::MaxBootLevel(v) => (Tag::MaxBootLevel, v.to_cbor_value()?),
            #[cfg(feature = "hal_v4")]
            KeyParam::ModuleHash(v) => (Tag::ModuleHash, v.to_cbor_value()?),
        };
        Ok(cbor::value::Value::Array(vec_try![
            tag.to_cbor_value()?,
            val
        ]?))
    }
    fn cddl_typename() -> Option<String> {
        Some("KeyParam".to_string())
    }
    fn cddl_schema() -> Option<String> {
        let mut result = "&(\n".to_string();

        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Algorithm as i32,
            Algorithm::cddl_ref(),
            "Tag_Algorithm"
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::BlockMode as i32,
            BlockMode::cddl_ref(),
            "Tag_BlockMode",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Padding as i32,
            PaddingMode::cddl_ref(),
            "Tag_Padding",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Digest as i32,
            Digest::cddl_ref(),
            "Tag_Digest",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::EcCurve as i32,
            EcCurve::cddl_ref(),
            "Tag_EcCurve",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Origin as i32,
            KeyOrigin::cddl_ref(),
            "Tag_Origin",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Purpose as i32,
            KeyPurpose::cddl_ref(),
            "Tag_Purpose",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::KeySize as i32,
            KeySizeInBits::cddl_ref(),
            "Tag_KeySize",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CallerNonce as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_CallerNonce",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::MinMacLength as i32,
            u32::cddl_ref(),
            "Tag_MinMacLength",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::RsaPublicExponent as i32,
            RsaExponent::cddl_ref(),
            "Tag_RsaPublicExponent",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::IncludeUniqueId as i32,
            "true",
            "Tag_IncludeUniqueId",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::RsaOaepMgfDigest as i32,
            Digest::cddl_ref(),
            "Tag_RsaOaepMgfDigest",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::BootloaderOnly as i32,
            "true",
            "Tag_BootloaderOnly",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::RollbackResistance as i32,
            "true",
            "Tag_RollbackResistance",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::EarlyBootOnly as i32,
            "true",
            "Tag_EarlyBootOnly",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::ActiveDatetime as i32,
            DateTime::cddl_ref(),
            "Tag_ActiveDatetime",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::OriginationExpireDatetime as i32,
            DateTime::cddl_ref(),
            "Tag_OriginationExpireDatetime",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UsageExpireDatetime as i32,
            DateTime::cddl_ref(),
            "Tag_UsageExpireDatetime",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::MaxUsesPerBoot as i32,
            u32::cddl_ref(),
            "Tag_MaxUsesPerBoot",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UsageCountLimit as i32,
            u32::cddl_ref(),
            "Tag_UsageCountLimit",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UserId as i32,
            u32::cddl_ref(),
            "Tag_UserId",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UserSecureId as i32,
            u64::cddl_ref(),
            "Tag_UserSecureId",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::NoAuthRequired as i32,
            "true",
            "Tag_NoAuthRequired",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UserAuthType as i32,
            u32::cddl_ref(),
            "Tag_UserAuthType",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AuthTimeout as i32,
            u32::cddl_ref(),
            "Tag_AuthTimeout",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AllowWhileOnBody as i32,
            "true",
            "Tag_AllowWhileOnBody",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::TrustedUserPresenceRequired as i32,
            "true",
            "Tag_TrustedUserPresenceRequired",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::TrustedConfirmationRequired as i32,
            "true",
            "Tag_TrustedConfirmationRequired",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::UnlockedDeviceRequired as i32,
            "true",
            "Tag_UnlockedDeviceRequired",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::ApplicationId as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_ApplicationId",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::ApplicationData as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_ApplicationData",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CreationDatetime as i32,
            DateTime::cddl_ref(),
            "Tag_CreationDatetime",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::RootOfTrust as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_RootOfTrust",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::OsVersion as i32,
            u32::cddl_ref(),
            "Tag_OsVersion",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::OsPatchlevel as i32,
            u32::cddl_ref(),
            "Tag_OsPatchlevel",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationChallenge as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationChallenge",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationApplicationId as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationApplicationId",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdBrand as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdBrand",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdDevice as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdDevice",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdProduct as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdProduct",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdSerial as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdSerial",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdImei as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdImei",
        );
        #[cfg(feature = "hal_v3")]
        {
            result += &format!(
                "    [{}, {}], ; {}\n",
                Tag::AttestationIdSecondImei as i32,
                Vec::<u8>::cddl_ref(),
                "Tag_AttestationIdSecondImei",
            );
        }
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdMeid as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdMeid",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdManufacturer as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdManufacturer",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::AttestationIdModel as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_AttestationIdModel",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::VendorPatchlevel as i32,
            u32::cddl_ref(),
            "Tag_VendorPatchlevel",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::BootPatchlevel as i32,
            u32::cddl_ref(),
            "Tag_BootPatchlevel",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::DeviceUniqueAttestation as i32,
            "true",
            "Tag_DeviceUniqueAttestation",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::StorageKey as i32,
            "true",
            "Tag_StorageKey",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::Nonce as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_Nonce",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::MacLength as i32,
            u32::cddl_ref(),
            "Tag_MacLength",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::ResetSinceIdRotation as i32,
            "true",
            "Tag_ResetSinceIdRotation",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CertificateSerial as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_CertificateSerial",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CertificateSubject as i32,
            Vec::<u8>::cddl_ref(),
            "Tag_CertificateSubject",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CertificateNotBefore as i32,
            DateTime::cddl_ref(),
            "Tag_CertificateNotBefore",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::CertificateNotAfter as i32,
            DateTime::cddl_ref(),
            "Tag_CertificateNotAfter",
        );
        result += &format!(
            "    [{}, {}], ; {}\n",
            Tag::MaxBootLevel as i32,
            u32::cddl_ref(),
            "Tag_MaxBootLevel",
        );
        #[cfg(feature = "hal_v4")]
        {
            result += &format!(
                "    [{}, {}], ; {}\n",
                Tag::ModuleHash as i32,
                Vec::<u8>::cddl_ref(),
                "Tag_ModuleHash",
            );
        }
        result += ")";
        Some(result)
    }
}

/// Determine the tag type for a tag, based on the top 4 bits of the tag number.
pub fn tag_type(tag: Tag) -> TagType {
    match ((tag as u32) & 0xf0000000u32) as i32 {
        x if x == TagType::Enum as i32 => TagType::Enum,
        x if x == TagType::EnumRep as i32 => TagType::EnumRep,
        x if x == TagType::Uint as i32 => TagType::Uint,
        x if x == TagType::UintRep as i32 => TagType::UintRep,
        x if x == TagType::Ulong as i32 => TagType::Ulong,
        x if x == TagType::Date as i32 => TagType::Date,
        x if x == TagType::Bool as i32 => TagType::Bool,
        x if x == TagType::Bignum as i32 => TagType::Bignum,
        x if x == TagType::Bytes as i32 => TagType::Bytes,
        x if x == TagType::UlongRep as i32 => TagType::UlongRep,
        _ => TagType::Invalid,
    }
}

/// Determine the raw tag value with tag type information stripped out.
pub fn raw_tag_value(tag: Tag) -> u32 {
    (tag as u32) & 0x0fffffffu32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum KeyPurpose {
    Encrypt = 0,
    Decrypt = 1,
    Sign = 2,
    Verify = 3,
    WrapKey = 5,
    AgreeKey = 6,
    AttestKey = 7,
}
try_from_n!(KeyPurpose);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum PaddingMode {
    None = 1,
    RsaOaep = 2,
    RsaPss = 3,
    RsaPkcs115Encrypt = 4,
    RsaPkcs115Sign = 5,
    Pkcs7 = 64,
}
try_from_n!(PaddingMode);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    Strongbox = 2,
    Keystore = 100,
}
try_from_n!(SecurityLevel);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, FromRawTag, N)]
#[repr(i32)]
pub enum Tag {
    Invalid = 0,
    Purpose = 536870913,
    Algorithm = 268435458,
    KeySize = 805306371,
    BlockMode = 536870916,
    Digest = 536870917,
    Padding = 536870918,
    CallerNonce = 1879048199,
    MinMacLength = 805306376,
    EcCurve = 268435466,
    RsaPublicExponent = 1342177480,
    IncludeUniqueId = 1879048394,
    RsaOaepMgfDigest = 536871115,
    BootloaderOnly = 1879048494,
    RollbackResistance = 1879048495,
    HardwareType = 268435760,
    EarlyBootOnly = 1879048497,
    ActiveDatetime = 1610613136,
    OriginationExpireDatetime = 1610613137,
    UsageExpireDatetime = 1610613138,
    MinSecondsBetweenOps = 805306771,
    MaxUsesPerBoot = 805306772,
    UsageCountLimit = 805306773,
    UserId = 805306869,
    UserSecureId = -1610612234,
    NoAuthRequired = 1879048695,
    UserAuthType = 268435960,
    AuthTimeout = 805306873,
    AllowWhileOnBody = 1879048698,
    TrustedUserPresenceRequired = 1879048699,
    TrustedConfirmationRequired = 1879048700,
    UnlockedDeviceRequired = 1879048701,
    ApplicationId = -1879047591,
    ApplicationData = -1879047492,
    CreationDatetime = 1610613437,
    Origin = 268436158,
    RootOfTrust = -1879047488,
    OsVersion = 805307073,
    OsPatchlevel = 805307074,
    UniqueId = -1879047485,
    AttestationChallenge = -1879047484,
    AttestationApplicationId = -1879047483,
    AttestationIdBrand = -1879047482,
    AttestationIdDevice = -1879047481,
    AttestationIdProduct = -1879047480,
    AttestationIdSerial = -1879047479,
    AttestationIdImei = -1879047478,
    AttestationIdMeid = -1879047477,
    AttestationIdManufacturer = -1879047476,
    AttestationIdModel = -1879047475,
    VendorPatchlevel = 805307086,
    BootPatchlevel = 805307087,
    DeviceUniqueAttestation = 1879048912,
    IdentityCredentialKey = 1879048913,
    StorageKey = 1879048914,
    #[cfg(feature = "hal_v3")]
    AttestationIdSecondImei = -1879047469,
    AssociatedData = -1879047192,
    Nonce = -1879047191,
    MacLength = 805307371,
    ResetSinceIdRotation = 1879049196,
    ConfirmationToken = -1879047187,
    CertificateSerial = -2147482642,
    CertificateSubject = -1879047185,
    CertificateNotBefore = 1610613744,
    CertificateNotAfter = 1610613745,
    MaxBootLevel = 805307378,
    #[cfg(feature = "hal_v4")]
    ModuleHash = -1879047468,
}
try_from_n!(Tag);

#[derive(Clone, Copy, Debug, PartialEq, Eq, AsCborValue, N)]
#[repr(i32)]
pub enum TagType {
    Invalid = 0,
    Enum = 268435456,
    EnumRep = 536870912,
    Uint = 805306368,
    UintRep = 1073741824,
    Ulong = 1342177280,
    Date = 1610612736,
    Bool = 1879048192,
    Bignum = -2147483648,
    Bytes = -1879048192,
    UlongRep = -1610612736,
}
try_from_n!(TagType);
