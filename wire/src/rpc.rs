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

//! Local types that are equivalent to those generated for the IRemotelyProvisionedComponent HAL
//! interface

use crate::{cbor_type_error, try_from_n, AsCborValue, CborError};
use enumn::N;
use kmr_derive::AsCborValue;

/// IRPC HAL Versions
pub const IRPC_V2: i32 = 2;
pub const IRPC_V3: i32 = 3;
/// `AuthenticatedRequest` CDDL schema version
pub const AUTH_REQ_SCHEMA_V1: i32 = 1;
/// `CertificateType` for keymint
pub const CERT_TYPE_KEYMINT: &str = "keymint";

/// Indication of whether RKP is operating in test mode. (Only relevant for RKP v1 and v2.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TestMode(pub bool);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0, // not in HAL, assumed
    Failed = 1,
    InvalidMac = 2,
    ProductionKeyInTestRequest = 3,
    TestKeyInProductionRequest = 4,
    InvalidEek = 5,
    Removed = 6,
}

/// The default value for the minimum number of keys supported in a CSR.
pub const MINIMUM_SUPPORTED_KEYS_IN_CSR: i32 = 20;

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct HardwareInfo {
    pub version_number: i32,
    pub rpc_author_name: String,
    pub supported_eek_curve: EekCurve,
    pub unique_id: Option<String>,
    pub supported_num_keys_in_csr: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue, N)]
#[repr(i32)]
pub enum EekCurve {
    None = 0,
    P256 = 1,
    Curve25519 = 2,
}
try_from_n!(EekCurve);

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct MacedPublicKey {
    pub maced_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct ProtectedData {
    pub protected_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, AsCborValue)]
pub struct DeviceInfo {
    pub device_info: Vec<u8>,
}
