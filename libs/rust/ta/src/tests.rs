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

//! Tests

use crate::{error_rsp, invalid_cbor_rsp_data, keys::SecureKeyWrapper, split_rsp};
use der::{Decode, Encode};
use kmr_common::Error;
use kmr_wire::{
    keymint::{
        ErrorCode, KeyFormat, KeyParam, KeyPurpose, NEXT_MESSAGE_SIGNAL_FALSE,
        NEXT_MESSAGE_SIGNAL_TRUE,
    },
    AsCborValue,
};

#[test]
fn test_invalid_data() {
    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
    let rsp = error_rsp(ErrorCode::UnknownError as i32);
    let rsp_data = rsp.into_vec().unwrap();
    assert_eq!(rsp_data, invalid_cbor_rsp_data());
}

#[test]
fn test_secure_key_wrapper() {
    let encoded_str = concat!(
        "30820179", // SEQUENCE length 0x179 (SecureKeyWrapper) {
        "020100",   // INTEGER length 1 value 0x00 (version)
        "04820100", // OCTET STRING length 0x100 (encryptedTransportKey)
        "aad93ed5924f283b4bb5526fbe7a1412",
        "f9d9749ec30db9062b29e574a8546f33",
        "c88732452f5b8e6a391ee76c39ed1712",
        "c61d8df6213dec1cffbc17a8c6d04c7b",
        "30893d8daa9b2015213e219468215532",
        "07f8f9931c4caba23ed3bee28b36947e",
        "47f10e0a5c3dc51c988a628daad3e5e1",
        "f4005e79c2d5a96c284b4b8d7e4948f3",
        "31e5b85dd5a236f85579f3ea1d1b8484",
        "87470bdb0ab4f81a12bee42c99fe0df4",
        "bee3759453e69ad1d68a809ce06b949f",
        "7694a990429b2fe81e066ff43e56a216",
        "02db70757922a4bcc23ab89f1e35da77",
        "586775f423e519c2ea394caf48a28d0c",
        "8020f1dcf6b3a68ec246f615ae96dae9",
        "a079b1f6eb959033c1af5c125fd94168",
        "040c", // OCTET STRING length 0x0c (initializationVector)
        "6d9721d08589581ab49204a3",
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
        // } end [503]
        // } end SEQUENCE (AuthorizationList)
        // } end SEQUENCE (KeyDescription)
        "0420", // OCTET STRING length 0x20 (encryptedKey)
        "a61c6e247e25b3e6e69aa78eb03c2d4a",
        "c20d1f99a9a024a76f35c8e2cab9b68d",
        "0410", // OCTET STRING length 0x10 (tag)
        "2560c70109ae67c030f00b98b512a670",
        // } SEQUENCE (SecureKeyWrapper)
    );
    let encoded_bytes = hex::decode(encoded_str).unwrap();
    let secure_key_wrapper = SecureKeyWrapper::from_der(&encoded_bytes).unwrap();
    assert_eq!(secure_key_wrapper.version, 0);
    let key_format: KeyFormat = secure_key_wrapper
        .key_description
        .key_format
        .try_into()
        .unwrap();
    assert_eq!(KeyFormat::Raw, key_format);
    let authz = secure_key_wrapper.key_description.key_params.auths;
    let purpose_values: Vec<KeyPurpose> = authz
        .iter()
        .filter_map(|param| {
            if let KeyParam::Purpose(v) = param {
                Some(*v)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(purpose_values.len(), 2);
    assert!(purpose_values.contains(&KeyPurpose::Encrypt));
    assert!(purpose_values.contains(&KeyPurpose::Decrypt));
}

#[test]
fn test_key_description_encode_decode() {
    let encoded_secure_key_wrapper = concat!(
        "30820179", // SEQUENCE length 0x179 (SecureKeyWrapper) {
        "020100",   // INTEGER length 1 value 0x00 (version)
        "04820100", // OCTET STRING length 0x100 (encryptedTransportKey)
        "aad93ed5924f283b4bb5526fbe7a1412",
        "f9d9749ec30db9062b29e574a8546f33",
        "c88732452f5b8e6a391ee76c39ed1712",
        "c61d8df6213dec1cffbc17a8c6d04c7b",
        "30893d8daa9b2015213e219468215532",
        "07f8f9931c4caba23ed3bee28b36947e",
        "47f10e0a5c3dc51c988a628daad3e5e1",
        "f4005e79c2d5a96c284b4b8d7e4948f3",
        "31e5b85dd5a236f85579f3ea1d1b8484",
        "87470bdb0ab4f81a12bee42c99fe0df4",
        "bee3759453e69ad1d68a809ce06b949f",
        "7694a990429b2fe81e066ff43e56a216",
        "02db70757922a4bcc23ab89f1e35da77",
        "586775f423e519c2ea394caf48a28d0c",
        "8020f1dcf6b3a68ec246f615ae96dae9",
        "a079b1f6eb959033c1af5c125fd94168",
        "040c", // OCTET STRING length 0x0c (initializationVector)
        "6d9721d08589581ab49204a3",
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
        // } end [503]
        // } end SEQUENCE (AuthorizationList)
        // } end SEQUENCE (KeyDescription)
        "0420", // OCTET STRING length 0x20 (encryptedKey)
        "a61c6e247e25b3e6e69aa78eb03c2d4a",
        "c20d1f99a9a024a76f35c8e2cab9b68d",
        "0410", // OCTET STRING length 0x10 (tag)
        "2560c70109ae67c030f00b98b512a670",
        // } SEQUENCE (SecureKeyWrapper)
    );
    let encoded_key_description_want = concat!(
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
                // } end [503]
                // } end SEQUENCE (AuthorizationList)
                // } end SEQUENCE (KeyDescription)
    );
    let encoded_bytes = hex::decode(encoded_secure_key_wrapper).unwrap();
    let secure_key_wrapper = SecureKeyWrapper::from_der(&encoded_bytes).unwrap();
    let key_description = secure_key_wrapper.key_description;
    let encoded_key_description_got = key_description.to_der().unwrap();
    assert_eq!(
        hex::encode(encoded_key_description_got),
        encoded_key_description_want
    );
}

#[test]
fn test_split_rsp_invalid_input() {
    // Check for invalid inputs
    let rsp = vec![];
    let result = split_rsp(&rsp, 5);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(Error::Hal(ErrorCode::InvalidArgument, _))
    ));

    let rsp = vec![0x82, 0x21, 0x80];
    let result = split_rsp(&rsp, 1);
    assert!(matches!(
        result,
        Err(Error::Hal(ErrorCode::InvalidArgument, _))
    ));
}

#[test]
fn test_split_rsp_smaller_input() {
    // Test for rsp_data size < max_size
    let rsp = vec![0x82, 0x13, 0x82, 0x80, 0x80];
    let result = split_rsp(&rsp, 20).expect("result should not be error");
    assert_eq!(result.len(), 1);
    let inner_msg = result
        .first()
        .expect("single message is expected")
        .as_slice();
    assert_eq!(inner_msg.len(), 6);
    let marker = inner_msg[0];
    assert_eq!(marker, NEXT_MESSAGE_SIGNAL_FALSE);
    let msg = &inner_msg[1..];
    assert_eq!(msg, rsp);
}

#[test]
fn test_split_rsp_allowed_size_input() {
    // Test for rsp_data size = allowed message length
    let rsp = vec![0x82, 0x13, 0x82, 0x80, 0x80];
    let result = split_rsp(&rsp, 6).expect("result should not be error");
    assert_eq!(result.len(), 1);
    let inner_msg = result
        .first()
        .expect("single message is expected")
        .as_slice();
    assert_eq!(inner_msg.len(), 6);
    let marker = inner_msg[0];
    assert_eq!(marker, NEXT_MESSAGE_SIGNAL_FALSE);
    let msg = &inner_msg[1..];
    assert_eq!(msg, rsp);
}

#[test]
fn test_split_rsp_max_size_input() {
    // Test for rsp_data size = max_size
    let rsp = vec![0x82, 0x13, 0x82, 0x80, 0x80, 0x82];
    let result = split_rsp(&rsp, 6).expect("result should not be error");
    assert_eq!(result.len(), 2);

    let inner_msg1 = result
        .first()
        .expect("a message is expected at index 0")
        .as_slice();
    assert_eq!(inner_msg1.len(), 6);
    let marker1 = inner_msg1[0];
    assert_eq!(marker1, NEXT_MESSAGE_SIGNAL_TRUE);
    assert_eq!(&inner_msg1[1..], &rsp[..5]);

    let inner_msg2 = result
        .get(1)
        .expect("a message is expected at index 1")
        .as_slice();
    assert_eq!(inner_msg2.len(), 2);
    let marker2 = inner_msg2[0];
    assert_eq!(marker2, NEXT_MESSAGE_SIGNAL_FALSE);
    assert_eq!(&inner_msg2[1..], &rsp[5..]);
}

#[test]
fn test_split_rsp_larger_input_perfect_split() {
    // Test for rsp_data size > max_size and it is a perfect split
    let rsp1 = vec![0x82, 0x13, 0x82, 0x80, 0x80];
    let rsp2 = vec![0x82, 0x14, 0x82, 0x80, 0x80];
    let rsp3 = vec![0x82, 0x15, 0x82, 0x80, 0x80];
    let mut rsp = vec![];
    rsp.extend_from_slice(&rsp1);
    rsp.extend_from_slice(&rsp2);
    rsp.extend_from_slice(&rsp3);
    let result = split_rsp(&rsp, 6).expect("result should not be error");
    assert_eq!(result.len(), 3);

    let inner_msg1 = result
        .first()
        .expect("a message is expected at index 0")
        .as_slice();
    assert_eq!(inner_msg1.len(), 6);
    let marker1 = inner_msg1[0];
    assert_eq!(marker1, NEXT_MESSAGE_SIGNAL_TRUE);
    let msg1 = &inner_msg1[1..];
    assert_eq!(msg1, rsp1);

    let inner_msg2 = result
        .get(1)
        .expect("a message is expected at index 1")
        .as_slice();
    assert_eq!(inner_msg2.len(), 6);
    let marker2 = inner_msg2[0];
    assert_eq!(marker2, NEXT_MESSAGE_SIGNAL_TRUE);
    let msg2 = &inner_msg2[1..];
    assert_eq!(msg2, rsp2);

    let inner_msg3 = result
        .get(2)
        .expect("a message is expected at index 2")
        .as_slice();
    assert_eq!(inner_msg3.len(), 6);
    let marker3 = inner_msg3[0];
    assert_eq!(marker3, NEXT_MESSAGE_SIGNAL_FALSE);
    let msg3 = &inner_msg3[1..];
    assert_eq!(msg3, rsp3);
}

#[test]
fn test_split_rsp_larger_input_imperfect_split() {
    // Test for rsp_data size > max_size and it is not a perfect split
    let rsp1 = vec![0x82, 0x00, 0x81, 0x82, 0x13];
    let rsp2 = vec![0x81, 0x83, 0x41, 0x01, 0x80];
    let rsp3 = vec![0x80];
    let mut rsp = vec![];
    rsp.extend_from_slice(&rsp1);
    rsp.extend_from_slice(&rsp2);
    rsp.extend_from_slice(&rsp3);
    let result = split_rsp(&rsp, 6).expect("result should not be error");
    assert_eq!(result.len(), 3);

    let inner_msg1 = result
        .first()
        .expect("a message is expected at index 0")
        .as_slice();
    assert_eq!(inner_msg1.len(), 6);
    let marker1 = inner_msg1[0];
    assert_eq!(marker1, NEXT_MESSAGE_SIGNAL_TRUE);
    let msg1 = &inner_msg1[1..];
    assert_eq!(msg1, rsp1);

    let inner_msg2 = result
        .get(1)
        .expect("a message is expected at index 1")
        .as_slice();
    assert_eq!(inner_msg2.len(), 6);
    let marker2 = inner_msg2[0];
    assert_eq!(marker2, NEXT_MESSAGE_SIGNAL_TRUE);
    let msg2 = &inner_msg2[1..];
    assert_eq!(msg2, rsp2);

    let inner_msg3 = result
        .get(2)
        .expect("a message is expected at index 2")
        .as_slice();
    assert_eq!(inner_msg3.len(), 2);
    let marker3 = inner_msg3[0];
    assert_eq!(marker3, NEXT_MESSAGE_SIGNAL_FALSE);
    let msg3 = &inner_msg3[1..];
    assert_eq!(msg3, rsp3);
}
