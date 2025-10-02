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

//! Static information about tag behaviour.

use crate::{km_err, Error};
use kmr_wire::keymint::{Tag, TagType};

#[cfg(test)]
mod tests;

/// Indicate the allowed use of the tag as a key characteristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Characteristic {
    /// Tag is a key characteristic that is enforced by KeyMint (at whatever security
    /// level the KeyMint implementation is running at), and is visible to KeyMint
    /// users (e.g. via GetKeyCharacteristics).
    KeyMintEnforced,

    /// Tag is a key characteristic that is enforced by KeyMint (at whatever security
    /// level the KeyMint implementation is running at), but is not exposed to KeyMint
    /// users.  If a key has this tag associated with it, all operations on the key
    /// must have this tag provided as an operation parameter.
    KeyMintHidden,

    /// Tag is a key characteristic that is enforced by Keystore.
    KeystoreEnforced,

    /// Tag is enforced by both KeyMint and Keystore, in different ways.
    BothEnforced,

    /// Tag is not a key characteristic, either because it only acts as an operation
    /// parameter or because it never appears on the API.
    NotKeyCharacteristic,
}

/// The set of characteristics that are necessarily enforced by Keystore.
pub const KEYSTORE_ENFORCED_CHARACTERISTICS: &[Tag] = &[
    Tag::ActiveDatetime,
    Tag::OriginationExpireDatetime,
    Tag::UsageExpireDatetime,
    Tag::UserId,
    Tag::AllowWhileOnBody,
    Tag::CreationDatetime,
    Tag::MaxBootLevel,
    Tag::UnlockedDeviceRequired,
];

/// The set of characteristics that are enforced by KeyMint.
pub const KEYMINT_ENFORCED_CHARACTERISTICS: &[Tag] = &[
    Tag::UserSecureId,
    Tag::Algorithm,
    Tag::EcCurve,
    Tag::UserAuthType,
    Tag::Origin,
    Tag::Purpose,
    Tag::BlockMode,
    Tag::Digest,
    Tag::Padding,
    Tag::RsaOaepMgfDigest,
    Tag::KeySize,
    Tag::MinMacLength,
    Tag::MaxUsesPerBoot,
    Tag::AuthTimeout,
    Tag::OsVersion,
    Tag::OsPatchlevel,
    Tag::VendorPatchlevel,
    Tag::BootPatchlevel,
    Tag::RsaPublicExponent,
    Tag::CallerNonce,
    Tag::BootloaderOnly,
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::NoAuthRequired,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::StorageKey,
];

/// The set of characteristics that are automatically added by KeyMint on key generation.
pub const AUTO_ADDED_CHARACTERISTICS: &[Tag] =
    &[Tag::Origin, Tag::OsVersion, Tag::OsPatchlevel, Tag::VendorPatchlevel, Tag::BootPatchlevel];

/// Indicate the allowed use of the tag as a parameter for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationParam {
    /// Tag acts as an operation parameter for key generation/import operations.
    KeyGenImport,

    /// Tag is provided as an explicit argument for a cipher operation, and must
    /// match one of the values for this tag in the key characteristics.
    CipherExplicitArgOneOf,

    /// Tag is provided as a parameter for a cipher operation, and must
    /// match one of the values for this tag in the key characteristics.
    CipherParamOneOf,

    /// Tag is provided as a parameter for a cipher operation, and must
    /// exactly match the (single) value for this tag in the key characteristics.
    CipherParamExactMatch,

    /// Tag is provided as a parameter for a cipher operation, and is not a key
    /// characteristic.
    CipherParam,

    /// Tag is not an operation parameter; this *normally* means that it only acts
    /// as a key characteristic (exception: ROOT_OF_TRUST is neither an operation
    /// parameter nor a key characteristic).
    NotOperationParam,
}

/// Indicate whether the KeyMint user is allowed to specify this tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserSpecifiable(pub bool);

/// Indicate whether the KeyMint implementation auto-adds this tag as a characteristic to generated
/// or imported keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoAddedCharacteristic(pub bool);

/// Indicate the lifetime of the value associated with the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueLifetime {
    /// Indicates that the value of the tag is communicated to KeyMint from the bootloader, and
    /// fixed thereafter.
    FixedAtBoot,
    /// Indicates that the value of the tag is communicated to KeyMint from the HAL service, and
    /// fixed thereafter.
    FixedAtStartup,
    /// Indicates that the value of the tag varies from key to key, or operation to operation.
    Variable,
}

/// Indicate whether a tag provided as an asymmetric key generation/import parameter is
/// required for the production of a certificate or attestation extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertGenParam {
    /// Tag not required as a parameter for certificate or extension generation (although its value
    /// may appear in the extension as a key characteristic).
    ///
    /// Example: `Tag::KeySize` doesn't affect cert generation (but does appear in any attestation
    /// extension).
    NotRequired,
    /// Tag must be specified as a parameter on key generation in order to get certificate
    /// generation.
    ///
    /// Example: `Tag::CertificateNotBefore` must be specified to get a cert.
    Required,
    /// Tag must be specified as a parameter on key generation in order to get an attestation
    /// extension in a generated certificate.
    ///
    /// Example: `Tag::AttestationChallenge` must be specified to get a cert with an attestation
    /// extension.
    RequiredForAttestation,
    /// Tag need not be specified as a parameter on key generation, but if specified it does affect
    /// the contents of the generated certificate (not extension).
    ///
    /// Example: `Tag::CertificateSerial` can be omitted, but if supplied it alters the cert.
    Optional,
    /// Tag need not be specified as a parameter on key generation, but if specified it does affect
    /// the contents of the attestation extension.
    ///
    /// Example: `Tag::ResetSinceIdRotation` can be omitted, but if supplied (along with
    /// `Tag::IncludeUniqueId`) then the attestation extension contents are altered.
    OptionalForAttestation,
    /// Special cases; see individual tags for information.
    Special,
}

/// Information about a tag's behaviour.
#[derive(Debug, Clone)]
pub struct Info {
    /// Tag name as a string for debug purposes.
    pub name: &'static str,
    /// Indication of the type of the corresponding value.
    pub tt: TagType,
    /// Indicates whether the tag value appears in an attestation extension, and as what ASN.1
    /// type.
    pub ext_asn1_type: Option<&'static str>,
    /// Indicates whether the KeyMint user can specify this tag.
    pub user_can_specify: UserSpecifiable,
    /// Indicates how this tag acts as a key characteristic.
    pub characteristic: Characteristic,
    /// Indicates how this tag acts as an operation parameter.
    pub op_param: OperationParam,
    /// Indicates whether KeyMint automatically adds this tag to keys as a key characteristic.
    pub keymint_auto_adds: AutoAddedCharacteristic,
    /// Indicates the lifetime of the value associated with this tag.
    pub lifetime: ValueLifetime,
    /// Indicates the role this tag plays in certificate generation for asymmetric keys.
    pub cert_gen: CertGenParam,
    /// Unique bit index for tracking this tag.
    bit_index: usize,
}

/// Global "map" of tags to information about their behaviour.
/// Encoded as an array to avoid allocation; lookup should only be slightly slower
/// for this few entries.
const INFO: [(Tag, Info); 61] = [
    (
        Tag::Purpose,
        Info {
            name: "PURPOSE",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherExplicitArgOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 0,
        },
    ),
    (
        Tag::Algorithm,
        Info {
            name: "ALGORITHM",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 1,
        },
    ),
    (
        Tag::KeySize,
        Info {
            name: "KEY_SIZE",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 2,
        },
    ),
    (
        Tag::BlockMode,
        Info {
            name: "BLOCK_MODE",
            tt: TagType::EnumRep,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 3,
        },
    ),
    (
        Tag::Digest,
        Info {
            name: "DIGEST",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 4,
        },
    ),
    (
        Tag::Padding,
        Info {
            name: "PADDING",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 5,
        },
    ),
    (
        Tag::CallerNonce,
        Info {
            name: "CALLER_NONCE",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 6,
        },
    ),
    (
        Tag::MinMacLength,
        Info {
            name: "MIN_MAC_LENGTH",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 7,
        },
    ),
    (
        Tag::EcCurve,
        Info {
            name: "EC_CURVE",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 8,
        },
    ),
    (
        Tag::RsaPublicExponent,
        Info {
            name: "RSA_PUBLIC_EXPONENT",
            tt: TagType::Ulong,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 9,
        },
    ),
    (
        Tag::IncludeUniqueId,
        Info {
            name: "INCLUDE_UNIQUE_ID",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 10,
        },
    ),
    (
        Tag::RsaOaepMgfDigest,
        Info {
            name: "RSA_OAEP_MGF_DIGEST",
            tt: TagType::EnumRep,
            ext_asn1_type: Some("SET OF INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 11,
        },
    ),
    (
        Tag::BootloaderOnly,
        Info {
            name: "BOOTLOADER_ONLY",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 12,
        },
    ),
    (
        Tag::RollbackResistance,
        Info {
            name: "ROLLBACK_RESISTANCE",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 13,
        },
    ),
    (
        Tag::EarlyBootOnly,
        Info {
            name: "EARLY_BOOT_ONLY",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 14,
        },
    ),
    (
        Tag::ActiveDatetime,
        Info {
            name: "ACTIVE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 15,
        },
    ),
    (
        Tag::OriginationExpireDatetime,
        Info {
            name: "ORIGINATION_EXPIRE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 16,
        },
    ),
    (
        Tag::UsageExpireDatetime,
        Info {
            name: "USAGE_EXPIRE_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 17,
        },
    ),
    (
        Tag::MaxUsesPerBoot,
        Info {
            name: "MAX_USES_PER_BOOT",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 18,
        },
    ),
    (
        Tag::UsageCountLimit,
        Info {
            name: "USAGE_COUNT_LIMIT",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::BothEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 19,
        },
    ),
    (
        Tag::UserId,
        Info {
            name: "USER_ID",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 20,
        },
    ),
    // Value must match userID or secureId in authToken param
    (
        Tag::UserSecureId,
        Info {
            name: "USER_SECURE_ID",
            tt: TagType::UlongRep,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherExplicitArgOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 21,
        },
    ),
    (
        Tag::NoAuthRequired,
        Info {
            name: "NO_AUTH_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 22,
        },
    ),
    (
        Tag::UserAuthType,
        Info {
            name: "USER_AUTH_TYPE",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::CipherParamOneOf,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 23,
        },
    ),
    (
        Tag::AuthTimeout,
        Info {
            name: "AUTH_TIMEOUT",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 24,
        },
    ),
    (
        Tag::AllowWhileOnBody,
        Info {
            name: "ALLOW_WHILE_ON_BODY",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 25,
        },
    ),
    (
        Tag::TrustedUserPresenceRequired,
        Info {
            name: "TRUSTED_USER_PRESENCE_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 26,
        },
    ),
    (
        Tag::TrustedConfirmationRequired,
        Info {
            name: "TRUSTED_CONFIRMATION_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 27,
        },
    ),
    (
        Tag::UnlockedDeviceRequired,
        Info {
            name: "UNLOCKED_DEVICE_REQUIRED",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 28,
        },
    ),
    (
        Tag::ApplicationId,
        Info {
            name: "APPLICATION_ID",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintHidden,
            op_param: OperationParam::CipherParamExactMatch,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 29,
        },
    ),
    (
        Tag::ApplicationData,
        Info {
            name: "APPLICATION_DATA",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintHidden,
            op_param: OperationParam::CipherParamExactMatch,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 30,
        },
    ),
    (
        Tag::CreationDatetime,
        Info {
            name: "CREATION_DATETIME",
            tt: TagType::Date,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            // If `Tag::IncludeUniqueId` is specified for attestation extension
            // generation, then a value for `Tag::CreationDatetime` is needed for
            // the calculation of the unique ID value.
            cert_gen: CertGenParam::Special,
            bit_index: 31,
        },
    ),
    (
        Tag::Origin,
        Info {
            name: "ORIGIN",
            tt: TagType::Enum,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 32,
        },
    ),
    (
        Tag::RootOfTrust,
        Info {
            name: "ROOT_OF_TRUST",
            tt: TagType::Bytes,
            ext_asn1_type: Some("RootOfTrust SEQUENCE"),
            user_can_specify: UserSpecifiable(false),
            // The root of trust is neither a key characteristic nor an operation parameter.
            // The tag exists only to reserve a numeric value that can be used in the
            // attestation extension record.
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 33,
        },
    ),
    (
        Tag::OsVersion,
        Info {
            name: "OS_VERSION",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 34,
        },
    ),
    (
        Tag::OsPatchlevel,
        Info {
            name: "OS_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 35,
        },
    ),
    (
        Tag::UniqueId,
        Info {
            name: "UNIQUE_ID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(false),
            // The unique ID is neither a key characteristic nor an operation parameter.
            //
            // The docs claim that tag exists only to reserve a numeric value that can be used in
            // the attestation extension record created on key generation.
            //
            // However, the unique ID gets a field of its own in the top-level KeyDescription
            // SEQUENCE; it does not appear in the AuthorizationList SEQUENCE, so this tag value
            // should never be seen anywhere.
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Special,
            bit_index: 36,
        },
    ),
    (
        Tag::AttestationChallenge,
        Info {
            name: "ATTESTATION_CHALLENGE",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::RequiredForAttestation,
            bit_index: 37,
        },
    ),
    (
        Tag::AttestationApplicationId,
        Info {
            name: "ATTESTATION_APPLICATION_ID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::RequiredForAttestation,
            bit_index: 38,
        },
    ),
    (
        Tag::AttestationIdBrand,
        Info {
            name: "ATTESTATION_ID_BRAND",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 39,
        },
    ),
    (
        Tag::AttestationIdDevice,
        Info {
            name: "ATTESTATION_ID_DEVICE",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 40,
        },
    ),
    (
        Tag::AttestationIdProduct,
        Info {
            name: "ATTESTATION_ID_PRODUCT",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 41,
        },
    ),
    (
        Tag::AttestationIdSerial,
        Info {
            name: "ATTESTATION_ID_SERIAL",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 42,
        },
    ),
    (
        Tag::AttestationIdImei,
        Info {
            name: "ATTESTATION_ID_IMEI",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 43,
        },
    ),
    (
        Tag::AttestationIdSecondImei,
        Info {
            name: "ATTESTATION_ID_SECOND_IMEI",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 44,
        },
    ),
    (
        Tag::AttestationIdMeid,
        Info {
            name: "ATTESTATION_ID_MEID",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 45,
        },
    ),
    (
        Tag::AttestationIdManufacturer,
        Info {
            name: "ATTESTATION_ID_MANUFACTURER",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 46,
        },
    ),
    (
        Tag::AttestationIdModel,
        Info {
            name: "ATTESTATION_ID_MODEL",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 47,
        },
    ),
    (
        Tag::VendorPatchlevel,
        Info {
            name: "VENDOR_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtStartup,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 48,
        },
    ),
    (
        Tag::BootPatchlevel,
        Info {
            name: "BOOT_PATCHLEVEL",
            tt: TagType::Uint,
            ext_asn1_type: Some("INTEGER"),
            user_can_specify: UserSpecifiable(false),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(true),
            lifetime: ValueLifetime::FixedAtBoot,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 49,
        },
    ),
    (
        Tag::DeviceUniqueAttestation,
        Info {
            name: "DEVICE_UNIQUE_ATTESTATION",
            tt: TagType::Bool,
            ext_asn1_type: Some("NULL"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            // Device unique attestation does not affect the contents of the `tbsCertificate`,
            // but it does change the chain used to sign the resulting certificate.
            cert_gen: CertGenParam::Special,
            bit_index: 50,
        },
    ),
    // A key marked as a storage key cannot be used via most of the KeyMint API. Instead, it
    // can be passed to `convertStorageKeyToEphemeral` to convert it to an ephemeral key.
    (
        Tag::StorageKey,
        Info {
            name: "STORAGE_KEY",
            tt: TagType::Bool,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeyMintEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 51,
        },
    ),
    // Can only be user-specified if CALLER_NONCE set in key characteristics.
    (
        Tag::Nonce,
        Info {
            name: "NONCE",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::CipherParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 52,
        },
    ),
    (
        Tag::MacLength,
        Info {
            name: "MAC_LENGTH",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::CipherParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 53,
        },
    ),
    (
        Tag::ResetSinceIdRotation,
        Info {
            name: "RESET_SINCE_ID_ROTATION",
            tt: TagType::Bool,
            ext_asn1_type: Some("part of UniqueID"),
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::OptionalForAttestation,
            bit_index: 54,
        },
    ),
    // Default to 1 if not present
    (
        Tag::CertificateSerial,
        Info {
            name: "CERTIFICATE_SERIAL",
            tt: TagType::Bignum,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Optional,
            bit_index: 55,
        },
    ),
    // Default to "CN=Android Keystore Key" if not present
    (
        Tag::CertificateSubject,
        Info {
            name: "CERTIFICATE_SUBJECT",
            tt: TagType::Bytes,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Optional,
            bit_index: 56,
        },
    ),
    (
        Tag::CertificateNotBefore,
        Info {
            name: "CERTIFICATE_NOT_BEFORE",
            tt: TagType::Date,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Required,
            bit_index: 57,
        },
    ),
    (
        Tag::CertificateNotAfter,
        Info {
            name: "CERTIFICATE_NOT_AFTER",
            tt: TagType::Date,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::KeyGenImport,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::Required,
            bit_index: 58,
        },
    ),
    (
        Tag::MaxBootLevel,
        Info {
            name: "MAX_BOOT_LEVEL",
            tt: TagType::Uint,
            ext_asn1_type: None,
            user_can_specify: UserSpecifiable(true),
            characteristic: Characteristic::KeystoreEnforced,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::Variable,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 59,
        },
    ),
    (
        Tag::ModuleHash,
        Info {
            name: "MODULE_HASH",
            tt: TagType::Bytes,
            ext_asn1_type: Some("OCTET STRING"),
            user_can_specify: UserSpecifiable(false),
            // The module hash is neither a key characteristic nor an operation parameter.
            // The tag exists only to reserve a numeric value that can be used in the
            // attestation extension record.
            characteristic: Characteristic::NotKeyCharacteristic,
            op_param: OperationParam::NotOperationParam,
            keymint_auto_adds: AutoAddedCharacteristic(false),
            lifetime: ValueLifetime::FixedAtStartup,
            cert_gen: CertGenParam::NotRequired,
            bit_index: 60,
        },
    ),
];

/// Return behaviour information about the specified tag.
pub fn info(tag: Tag) -> Result<&'static Info, Error> {
    for (t, info) in &INFO {
        if tag == *t {
            return Ok(info);
        }
    }
    Err(km_err!(InvalidTag, "unknown tag {:?}", tag))
}

/// Indicate whether a tag is allowed to have multiple values.
#[inline]
pub fn multivalued(tag: Tag) -> bool {
    matches!(
        kmr_wire::keymint::tag_type(tag),
        TagType::EnumRep | TagType::UintRep | TagType::UlongRep
    )
}

/// Tracker for observed tag values.
#[derive(Default)]
pub struct DuplicateTagChecker(u64);

impl DuplicateTagChecker {
    /// Add the given tag to the set of seen tags, failing if the tag
    /// has already been observed (and is not multivalued).
    pub fn add(&mut self, tag: Tag) -> Result<(), Error> {
        let bit_idx = info(tag)?.bit_index;
        let bit_mask = 0x01u64 << bit_idx;
        if !multivalued(tag) && (self.0 & bit_mask) != 0 {
            return Err(km_err!(InvalidKeyBlob, "duplicate value for {:?}", tag));
        }
        self.0 |= bit_mask;
        Ok(())
    }
}
