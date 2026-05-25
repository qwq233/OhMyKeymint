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

// Inject the BoringSSL-based implementations of crypto traits into the smoke tests from
// `kmr_tests`.

#[test]
fn test_rng() {
    let mut rng = rng::BoringRng;
    kmr_tests::test_rng(&mut rng);
}

#[test]
fn test_eq() {
    let comparator = eq::BoringEq;
    kmr_tests::test_eq(comparator);
}

#[test]
fn test_hkdf() {
    kmr_tests::test_hkdf(hmac::BoringHmac {});
}

#[test]
fn test_hmac() {
    kmr_tests::test_hmac(hmac::BoringHmac {});
}

#[test]
fn test_km_hmac_sha256() {
    let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    let mac = km::hmac_sha256(key, b"Hello").unwrap();
    assert_eq!(mac.len(), km::HMAC_SHA256_LEN);
    assert_eq!(
        mac.as_slice(),
        &[
            0xe0, 0xff, 0x02, 0x55, 0x3d, 0x9a, 0x61, 0x96, 0x61, 0x02, 0x6c, 0x7a, 0xa1, 0xdd,
            0xf5, 0x9b, 0x7b, 0x44, 0xea, 0xc0, 0x6a, 0x99, 0x08, 0xff, 0x9e, 0x19, 0x96, 0x1d,
            0x48, 0x19, 0x35, 0xd4,
        ]
    );

    let empty_mac = km::hmac_sha256(key, &[]).unwrap();
    assert_eq!(empty_mac.len(), km::HMAC_SHA256_LEN);
    assert_eq!(
        empty_mac.as_slice(),
        &[
            0x07, 0xef, 0xf8, 0xb3, 0x26, 0xb7, 0x79, 0x8c, 0x9c, 0xcf, 0xcb, 0xdb, 0xe5, 0x79,
            0x48, 0x9a, 0xc7, 0x85, 0xa7, 0x99, 0x5a, 0x04, 0x61, 0x8b, 0x1a, 0x28, 0x13, 0xc2,
            0x67, 0x44, 0x77, 0x7d,
        ]
    );
}

#[test]
fn test_km_ec_private_key_round_trip() {
    let key = km::ec_key_generate_key().unwrap();
    let private_key = km::ec_key_marshal_private_key(&key).unwrap();
    assert_eq!(private_key.len(), 73);

    let parsed = km::ec_key_parse_private_key(&private_key).unwrap();
    let original_public = km::ec_point_point_to_oct(km::ec_key_get0_public_key(&key)).unwrap();
    let parsed_public = km::ec_point_point_to_oct(km::ec_key_get0_public_key(&parsed)).unwrap();
    assert_eq!(original_public, parsed_public);
}

#[cfg(soong)]
#[test]
fn test_aes_cmac() {
    kmr_tests::test_aes_cmac(aes_cmac::BoringAesCmac {});
}

#[cfg(soong)]
#[test]
fn test_ckdf() {
    kmr_tests::test_ckdf(aes_cmac::BoringAesCmac {});
}

#[test]
fn test_aes_gcm() {
    kmr_tests::test_aes_gcm(aes::BoringAes {});
}

#[test]
fn test_des() {
    kmr_tests::test_des(des::BoringDes {});
}

#[test]
fn test_sha256() {
    kmr_tests::test_sha256(sha256::BoringSha256 {});
}
