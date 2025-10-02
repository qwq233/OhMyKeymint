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

use super::*;
use crate::expect_err;
use kmr_wire::{keymint::KeyParam, KeySizeInBits};

#[test]
fn test_characteristics_invalid() {
    let tests = vec![
        (vec![KeyParam::UsageCountLimit(42), KeyParam::UsageCountLimit(43)], "duplicate value"),
        (vec![KeyParam::Nonce(vec![1, 2])], "not a valid key characteristic"),
    ];
    for (characteristics, msg) in tests {
        let result = crate::tag::characteristics_valid(&characteristics);
        expect_err!(result, msg);
    }
}

#[test]
fn test_legacy_serialization() {
    let tests = vec![(
        concat!(
            "00000000", // blob data size
            "03000000", // param count
            "15000000", // param size
            "02000010", // Tag::ALGORITHM = 268435458 = 0x10000002,
            "20000000", // Algorithm::AES
            "03000030", // Tag::KEY_SIZE = 805306371 = 0x30000003
            "00010000", // size = 0x00000100
            "fb010070", // Tag::TRUSTED_USER_PRESENCE_REQUIRED = 0x700001fb
            "01",       // True
        ),
        vec![
            KeyParam::Algorithm(Algorithm::Aes),
            KeyParam::KeySize(KeySizeInBits(256)),
            KeyParam::TrustedUserPresenceRequired,
        ],
    )];

    for (hex_data, want_params) in tests {
        let want_data = hex::decode(hex_data).unwrap();

        let got_data = legacy::serialize(&want_params).unwrap();
        assert_eq!(hex::encode(got_data), hex_data);

        let mut data = &want_data[..];
        let got_params = legacy::deserialize(&mut data).unwrap();
        assert!(data.is_empty(), "data left: {}", hex::encode(data));
        assert_eq!(got_params, want_params);
    }
}

#[test]
fn test_check_begin_params_fail() {
    let chars = vec![
        KeyParam::NoAuthRequired,
        KeyParam::Algorithm(Algorithm::Hmac),
        KeyParam::KeySize(KeySizeInBits(128)),
        KeyParam::Digest(Digest::Sha256),
        KeyParam::Purpose(KeyPurpose::Sign),
        KeyParam::Purpose(KeyPurpose::Verify),
        KeyParam::MinMacLength(160),
    ];

    let tests = vec![
        (
            KeyPurpose::Encrypt,
            vec![KeyParam::Digest(Digest::Sha256), KeyParam::MacLength(160)],
            "invalid purpose Encrypt",
        ),
        (KeyPurpose::Sign, vec![KeyParam::Digest(Digest::Sha256)], "MissingMacLength"),
        (
            KeyPurpose::Sign,
            vec![KeyParam::Digest(Digest::Sha512), KeyParam::MacLength(160)],
            "not in key characteristics",
        ),
    ];
    for (purpose, params, msg) in tests {
        expect_err!(check_begin_params(&chars, purpose, &params), msg);
    }
}

#[test]
fn test_copyable_tags() {
    for tag in UNPOLICED_COPYABLE_TAGS {
        let info = info(*tag).unwrap();
        assert!(info.user_can_specify.0, "tag {:?} not listed as user-specifiable", tag);
        assert!(
            info.characteristic == info::Characteristic::KeyMintEnforced
                || info.characteristic == info::Characteristic::KeystoreEnforced
                || info.characteristic == info::Characteristic::BothEnforced,
            "tag {:?} with unexpected characteristic {:?}",
            tag,
            info.characteristic
        );
    }
}

#[test]
fn test_luhn_checksum() {
    let tests = vec![(0, 0), (7992739871, 3), (735423462345, 6), (721367498765427, 4)];
    for (input, want) in tests {
        let got = luhn_checksum(input);
        assert_eq!(got, want, "mismatch for input {}", input);
    }
}

#[test]
fn test_increment_imei() {
    let tests = vec![
        // Anything that's not ASCII digits gives empty vec.
        ("", ""),
        ("01", ""),
        ("01", ""),
        ("7576", ""),
        ("c328", ""), // Invalid UTF-8
        // 721367498765404 => 721367498765412
        ("373231333637343938373635343034", "373231333637343938373635343132"),
        ("39393930", "3130303039"), // String gets longer
    ];
    for (input, want) in tests {
        let input_data = hex::decode(input).unwrap();
        let got = increment_imei(&input_data);
        assert_eq!(hex::encode(got), want, "mismatch for input IMEI {}", input);
    }
}
