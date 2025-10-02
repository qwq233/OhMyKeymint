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

//! Local types that are equivalent to those generated for the SharedSecret HAL interface

use crate::{cbor_type_error, AsCborValue, CborError};
use kmr_derive::AsCborValue;

pub const KEY_AGREEMENT_LABEL: &str = "KeymasterSharedMac";
pub const KEY_CHECK_LABEL: &str = "Keymaster HMAC Verification";

#[derive(Debug, Clone, Eq, Hash, PartialEq, Default, AsCborValue)]
pub struct SharedSecretParameters {
    pub seed: Vec<u8>,
    pub nonce: Vec<u8>,
}
