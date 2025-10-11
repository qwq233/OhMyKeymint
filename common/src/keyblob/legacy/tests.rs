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
use crate::tag::legacy::{consume_u32, consume_u64, consume_u8, consume_vec};

#[test]
fn test_consume_u8() {
    let buffer = [1, 2];
    let mut data = &buffer[..];
    assert_eq!(1u8, consume_u8(&mut data).unwrap());
    assert_eq!(2u8, consume_u8(&mut data).unwrap());
    let result = consume_u8(&mut data);
    expect_err!(result, "failed to find 1 byte");
}

#[test]
fn test_consume_u32() {
    let buffer = [
        0x01, 0x02, 0x03, 0x04, //
        0x04, 0x03, 0x02, 0x01, //
        0x11, 0x12, 0x13,
    ];
    let mut data = &buffer[..];
    assert_eq!(0x04030201u32, consume_u32(&mut data).unwrap());
    assert_eq!(0x01020304u32, consume_u32(&mut data).unwrap());
    let result = consume_u32(&mut data);
    expect_err!(result, "failed to find 4 bytes");
}

#[test]
fn test_consume_u64() {
    let buffer = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, //
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let mut data = &buffer[..];
    assert_eq!(0x0807060504030201u64, consume_u64(&mut data).unwrap());
    assert_eq!(0x0102030405060708u64, consume_u64(&mut data).unwrap());
    let result = consume_u64(&mut data);
    expect_err!(result, "failed to find 8 bytes");
}

#[test]
fn test_consume_vec() {
    let buffer = [
        0x01, 0x00, 0x00, 0x00, 0xaa, //
        0x00, 0x00, 0x00, 0x00, //
        0x01, 0x00, 0x00, 0x00, 0xbb, //
        0x07, 0x00, 0x00, 0x00, 0xbb, // not enough data
    ];
    let mut data = &buffer[..];
    assert_eq!(vec![0xaa], consume_vec(&mut data).unwrap());
    assert_eq!(Vec::<u8>::new(), consume_vec(&mut data).unwrap());
    assert_eq!(vec![0xbb], consume_vec(&mut data).unwrap());
    let result = consume_vec(&mut data);
    expect_err!(result, "failed to find 7 bytes");

    let buffer = [
        0x01, 0x00, 0x00, //
    ];
    let mut data = &buffer[..];
    let result = consume_vec(&mut data);
    expect_err!(result, "failed to find 4 bytes");
}

#[test]
fn test_serialize_encrypted_keyblob() {
    let tests = vec![
        (
            concat!(
                "00", // format
                "01000000",
                "aa", // nonce
                "02000000",
                "bbbb", // ciphertext
                "01000000",
                "cc", // tag
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
            ),
            EncryptedKeyBlob {
                format: AuthEncryptedBlobFormat::AesOcb,
                nonce: vec![0xaa],
                ciphertext: vec![0xbb, 0xbb],
                tag: vec![0xcc],
                kdf_version: None,
                addl_info: None,
                hw_enforced: vec![],
                sw_enforced: vec![],
                key_slot: None,
            },
        ),
        (
            concat!(
                "01", // format
                "01000000",
                "aa", // nonce
                "02000000",
                "bbbb", // ciphertext
                "01000000",
                "cc", // tag
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
                "06000000",
            ),
            EncryptedKeyBlob {
                format: AuthEncryptedBlobFormat::AesGcmWithSwEnforced,
                nonce: vec![0xaa],
                ciphertext: vec![0xbb, 0xbb],
                tag: vec![0xcc],
                kdf_version: None,
                addl_info: None,
                hw_enforced: vec![],
                sw_enforced: vec![],
                key_slot: Some(6),
            },
        ),
        (
            concat!(
                "03", // format
                "01000000",
                "aa", // nonce
                "02000000",
                "bbbb", // ciphertext
                "01000000",
                "cc",       // tag
                "01010101", // kdf_version
                "04040404", // addl_info
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
                "06000000",
            ),
            EncryptedKeyBlob {
                format: AuthEncryptedBlobFormat::AesGcmWithSwEnforcedVersioned,
                nonce: vec![0xaa],
                ciphertext: vec![0xbb, 0xbb],
                tag: vec![0xcc],
                kdf_version: Some(0x01010101),
                addl_info: Some(0x04040404),
                hw_enforced: vec![],
                sw_enforced: vec![],
                key_slot: Some(6),
            },
        ),
    ];
    for (hex_data, want) in tests {
        let data = hex::decode(hex_data).unwrap();
        let got = EncryptedKeyBlob::deserialize(&data).unwrap();
        assert_eq!(got, want);
        let new_data = got.serialize().unwrap();
        assert_eq!(new_data, data);
    }
}

#[test]
fn test_deserialize_encrypted_keyblob_fail() {
    let tests = vec![
        (
            concat!(
                "09", // format (invalid)
                "01000000",
                "aa", // nonce
                "02000000",
                "bbbb", // ciphertext
                "01000000",
                "cc", // tag
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
            ),
            "unexpected blob format 9",
        ),
        (
            concat!(
                "02", // format
                "01000000",
                "aa", // nonce
                "02000000",
                "bbbb", // ciphertext
                "01000000",
                "cc", // tag
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
                "060000",
            ),
            "unexpected remaining length 3",
        ),
    ];
    for (hex_data, msg) in tests {
        let data = hex::decode(hex_data).unwrap();
        let result = EncryptedKeyBlob::deserialize(&data);
        expect_err!(result, msg);
    }
}

#[test]
fn test_deserialize_encrypted_keyblob_truncated() {
    let data = hex::decode(concat!(
        "00", // format
        "01000000",
        "aa", // nonce
        "02000000",
        "bbbb", // ciphertext
        "01000000",
        "cc", // tag
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
    ))
    .unwrap();
    assert!(EncryptedKeyBlob::deserialize(&data).is_ok());
    for len in 0..data.len() - 1 {
        // Any truncation of this data is invalid.
        assert!(
            EncryptedKeyBlob::deserialize(&data[..len]).is_err(),
            "deserialize of data[..{}] subset (len={}) unexpectedly succeeded",
            len,
            data.len()
        );
    }
}
