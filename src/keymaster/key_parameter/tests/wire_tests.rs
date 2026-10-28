// Copyright 2020, The Android Open Source Project
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

//! The wire_tests module tests the 'convert_to_wire' and 'convert_from_wire' methods for
//! KeyParameter, for the four different types used in KmKeyParameter, in addition to Invalid
//! key parameter.
//! i) bool
//! ii) integer
//! iii) longInteger
//! iv) blob

use super::*;
/// unit tests for to conversions
#[test]
fn test_convert_to_wire_invalid() {
    let kp = KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::STRONGBOX);
    assert_eq!(
        KmKeyParameter {
            tag: Tag::INVALID,
            value: KmKeyParameterValue::Invalid(0)
        },
        kp.value.into()
    );
}
#[test]
fn test_convert_to_wire_bool() {
    let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
    assert_eq!(
        KmKeyParameter {
            tag: Tag::CALLER_NONCE,
            value: KmKeyParameterValue::BoolValue(true)
        },
        kp.value.into()
    );
}
#[test]
fn test_convert_to_wire_integer() {
    let kp = KeyParameter::new(
        KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        SecurityLevel::STRONGBOX,
    );
    assert_eq!(
        KmKeyParameter {
            tag: Tag::PURPOSE,
            value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT)
        },
        kp.value.into()
    );
}
#[test]
fn test_convert_to_wire_long_integer() {
    let kp = KeyParameter::new(
        KeyParameterValue::UserSecureID(i64::MAX),
        SecurityLevel::STRONGBOX,
    );
    assert_eq!(
        KmKeyParameter {
            tag: Tag::USER_SECURE_ID,
            value: KmKeyParameterValue::LongInteger(i64::MAX)
        },
        kp.value.into()
    );
}
#[test]
fn test_convert_to_wire_blob() {
    let kp = KeyParameter::new(
        KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
        SecurityLevel::STRONGBOX,
    );
    assert_eq!(
        KmKeyParameter {
            tag: Tag::CONFIRMATION_TOKEN,
            value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes())
        },
        kp.value.into()
    );
}

/// unit tests for from conversion
#[test]
fn test_convert_from_wire_invalid() {
    let aidl_kp = KmKeyParameter {
        tag: Tag::INVALID,
        ..Default::default()
    };
    assert_eq!(KeyParameterValue::Invalid, aidl_kp.into());
}
#[test]
fn test_convert_from_wire_bool() {
    let aidl_kp = KmKeyParameter {
        tag: Tag::CALLER_NONCE,
        value: KmKeyParameterValue::BoolValue(true),
    };
    assert_eq!(KeyParameterValue::CallerNonce, aidl_kp.into());
}
#[test]
fn test_convert_from_wire_integer() {
    let aidl_kp = KmKeyParameter {
        tag: Tag::PURPOSE,
        value: KmKeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
    };
    assert_eq!(
        KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        aidl_kp.into()
    );
}
#[test]
fn test_convert_from_wire_long_integer() {
    let aidl_kp = KmKeyParameter {
        tag: Tag::USER_SECURE_ID,
        value: KmKeyParameterValue::LongInteger(i64::MAX),
    };
    assert_eq!(KeyParameterValue::UserSecureID(i64::MAX), aidl_kp.into());
}
#[test]
fn test_convert_from_wire_blob() {
    let aidl_kp = KmKeyParameter {
        tag: Tag::CONFIRMATION_TOKEN,
        value: KmKeyParameterValue::Blob(String::from("ConfirmationToken").into_bytes()),
    };
    assert_eq!(
        KeyParameterValue::ConfirmationToken(String::from("ConfirmationToken").into_bytes()),
        aidl_kp.into()
    );
}
