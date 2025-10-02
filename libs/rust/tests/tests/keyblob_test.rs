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

// Integration test.
#![cfg(soong)]

// Explicitly include alloc because macros from `kmr_common` assume it.
extern crate alloc;

use kmr_common::{crypto, crypto::Rng, expect_err, keyblob, keyblob::legacy::KeyBlob};
use kmr_crypto_boring::aes::BoringAes;
use kmr_crypto_boring::eq::BoringEq;
use kmr_crypto_boring::hmac::BoringHmac;
use kmr_crypto_boring::rng::BoringRng;
use kmr_wire::{keymint, keymint::KeyParam};

#[test]
fn test_encrypted_keyblob_roundtrip() {
    let aes = BoringAes;
    let hmac = BoringHmac;
    let mut rng = BoringRng;
    let mut root_key = crypto::hmac::Key(vec![0u8; 32]);
    rng.fill_bytes(&mut root_key.0);
    let root_key = crypto::OpaqueOr::Explicit(root_key);
    let plaintext_keyblob = keyblob::PlaintextKeyBlob {
        characteristics: vec![keymint::KeyCharacteristics {
            security_level: keymint::SecurityLevel::TrustedEnvironment,
            authorizations: vec![
                KeyParam::Algorithm(keymint::Algorithm::Aes),
                KeyParam::BlockMode(keymint::BlockMode::Ecb),
                KeyParam::Padding(keymint::PaddingMode::None),
            ],
        }],
        key_material: crypto::KeyMaterial::Aes(crypto::aes::Key::Aes128([0u8; 16]).into()),
    };
    let hidden = vec![
        KeyParam::ApplicationId(b"app_id".to_vec()),
        KeyParam::ApplicationData(b"app_data".to_vec()),
    ];

    let encrypted_keyblob = keyblob::encrypt(
        keymint::SecurityLevel::TrustedEnvironment,
        None,
        &aes,
        &hmac,
        &mut rng,
        &root_key,
        &[],
        plaintext_keyblob.clone(),
        hidden.clone(),
        keyblob::SlotPurpose::KeyGeneration,
    )
    .unwrap();

    let recovered_keyblob =
        keyblob::decrypt(None, &aes, &hmac, &root_key, encrypted_keyblob, hidden).unwrap();
    assert_eq!(plaintext_keyblob, recovered_keyblob);
}

#[test]
fn test_serialize_authenticated_legacy_keyblob() {
    let hidden = kmr_common::keyblob::legacy::hidden(&[], &[b"SW"]).unwrap();
    let tests = vec![(
        concat!(
            "00", // version
            "02000000",
            "bbbb", // key material
            concat!(
                "00000000", // no blob data
                "00000000", // no params
                "00000000", // zero size of params
            ),
            concat!(
                "00000000", // no blob data
                "00000000", // no params
                "00000000", // zero size of params
            ),
            "0000000000000000", // hmac
        ),
        KeyBlob { key_material: vec![0xbb, 0xbb], hw_enforced: vec![], sw_enforced: vec![] },
    )];
    for (hex_data, want) in tests {
        let mut data = hex::decode(hex_data).unwrap();

        // Key blob cannot be deserialized without a correct MAC.
        let hmac = BoringHmac {};
        let result = KeyBlob::deserialize(&hmac, &data, &hidden, BoringEq);
        expect_err!(result, "invalid key blob");

        fix_hmac(&mut data, &hidden);
        let got = KeyBlob::deserialize(&hmac, &data, &hidden, BoringEq).unwrap();
        assert_eq!(got, want);
        let new_data = got.serialize(&hmac, &hidden).unwrap();
        assert_eq!(new_data, data);
    }
}

#[test]
fn test_deserialize_authenticated_legacy_keyblob_fail() {
    let hidden = kmr_common::keyblob::legacy::hidden(&[], &[b"SW"]).unwrap();
    let tests = vec![
        (
            concat!(
                "02", // version
                "02000000",
                "bbbb", // key material
                concat!(
                    "00000000", // no blob data
                    "00000000", // no params
                    "00000000", // zero size of params
                ),
                concat!(
                    "00000000", // no blob data
                    "00000000", // no params
                    "00000000", // zero size of params
                ),
                "0000000000000000", // hmac
            ),
            "unexpected blob version 2",
        ),
        (
            concat!(
                "00", // version
                "02000000",
                "bbbb", // key material
                concat!(
                    "00000000", // no blob data
                    "00000000", // no params
                    "00000000", // zero size of params
                ),
                concat!(
                    "00000000", // no blob data
                    "00000000", // no params
                    "00000000", // zero size of params
                ),
                "00",               // bonus byte
                "0000000000000000", // hmac
            ),
            "extra data (len 1)",
        ),
    ];
    let hmac = BoringHmac {};
    for (hex_data, msg) in tests {
        let mut data = hex::decode(hex_data).unwrap();
        fix_hmac(&mut data, &hidden);
        let result = KeyBlob::deserialize(&hmac, &data, &hidden, BoringEq);
        expect_err!(result, msg);
    }
}

#[test]
fn test_deserialize_authenticated_legacy_keyblob_truncated() {
    let hidden = kmr_common::keyblob::legacy::hidden(&[], &[b"SW"]).unwrap();
    let mut data = hex::decode(concat!(
        "00", // version
        "02000000",
        "bbbb", // key material
        concat!(
            "00000000", // no blob data
            "00000000", // no params
            "00000000", // zero size of params
        ),
        concat!(
            "00000000", // no blob data
            "00000000", // no params
            "00000000", // zero size of params
        ),
        "0000000000000000", // hmac
    ))
    .unwrap();
    fix_hmac(&mut data, &hidden);
    let hmac = BoringHmac {};
    assert!(KeyBlob::deserialize(&hmac, &data, &hidden, BoringEq).is_ok());

    for len in 0..data.len() - 1 {
        // Any truncation of this data is invalid.
        assert!(
            KeyBlob::deserialize(&hmac, &data[..len], &hidden, BoringEq).is_err(),
            "deserialize of data[..{}] subset (len={}) unexpectedly succeeded",
            len,
            data.len()
        );
    }
}

fn fix_hmac(data: &mut [u8], hidden: &[KeyParam]) {
    let hmac = BoringHmac {};
    let mac_offset = data.len() - KeyBlob::MAC_LEN;
    let mac = KeyBlob::compute_hmac(&hmac, &data[..mac_offset], hidden).unwrap();
    data[mac_offset..].copy_from_slice(&mac);
}
