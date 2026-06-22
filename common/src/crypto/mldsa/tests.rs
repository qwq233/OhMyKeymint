// Copyright 2025, The Android Open Source Project
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

//! ML-DSA unit tests.
use super::*;

/// Private key seed.
const PKCS8_SEED_65_DATA: &str = concat!(
    "3034",               // SEQUENCE len x34 {
    "020100",             // INTEGER 0 (Version)
    "300b",               // SEQUENCE len 11 (privateKeyAlgorithm) {
    "0609",               // OBJECT_IDENTIFIER len 9
    "608648016503040312", //  2.16.840.1.101.3.4.3.18
    // }
    "0422",                                                             // OCTET STRING len 34
    "8020",                                                             // tag 0 primitive len 32
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"  // seed value
);

/// Private key encoded with both seed and an (invalid) expanded key.
const PKCS8_BOTH_65_DATA: &str = concat!(
    "303c",               // SEQUENCE len x3c {
    "020100",             // INTEGER 0 (Version)
    "300b",               // SEQUENCE len 11 (privateKeyAlgorithm) {
    "0609",               // OBJECT_IDENTIFIER len 9
    "608648016503040312", //  2.16.840.1.101.3.4.3.18
    // }
    "042a", // OCTET STRING len 42 {
    "3028", // SEQUENCE len 40
    "0420", // OCTET STRING len 32
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "0404", // OCTET STRING len 4 (invalid)
    "deadbeef"
);

const SEED: [u8; SEED_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn parse_pkcs8_seed() {
    let key_data = hex::decode(PKCS8_SEED_65_DATA).unwrap();
    let key = import_pkcs8_key(&key_data).expect("PKCS8 parse failed");
    assert_eq!(
        key,
        KeyMaterial::MlDsa(
            MlDsaVariant::MlDsa65,
            OpaqueOr::Explicit(Key::MlDsa65(SEED))
        )
    );
}

#[test]
fn parse_pkcs8_both_fail() {
    let key_data = hex::decode(PKCS8_BOTH_65_DATA).unwrap();
    let result = import_pkcs8_key(&key_data);
    assert!(result.is_err());
}

#[test]
fn parse_pkcs8_failures() {
    let tests = [
        // Invalid seed format
        concat!(
            "801f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        ), // too short
        concat!(
            "8020",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        ), // len mismatch
        concat!(
            "8021",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ), // len mismatch
        concat!(
            "8021",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        ), // too long
        "8000", // empty
        // Invalid both format
        concat!(
            "3027",
            "041f", // too short
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            "0401aa"
        ),
        concat!(
            "3029",
            "0421", // too long
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0401aa"
        ),
        // Unexpected OCTET STRING (e.g. an expanded key)
        concat!(
            "0420",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
    ];
    for hex_data in tests {
        let data = hex::decode(hex_data).unwrap();
        let result = import_pkcs8_key(&data);
        assert!(result.is_err(), "unexpected success parsing {hex_data}");
    }
}
