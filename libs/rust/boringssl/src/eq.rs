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

//! BoringSSL-based implementation of constant-time comparisons.
use kmr_common::crypto;

/// Constant time comparator based on BoringSSL.
#[derive(Clone)]
pub struct BoringEq;

impl crypto::ConstTimeEq for BoringEq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        openssl::memcmp::eq(left, right)
    }
}
