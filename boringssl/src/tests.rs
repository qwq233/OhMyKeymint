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
