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

//! Rust types definitions for BoringSSL objects.
#[cfg(soong)]
use bssl_sys as ffi;

/// New type for `*mut ffi::CMAC_CTX` to implement `Send` for it. This allow us to still check if a
/// `!Send` item is added to `BoringAesCmacOperation`
#[allow(dead_code)]
pub(crate) struct CmacCtx(pub(crate) *mut ffi::CMAC_CTX);

// Safety: Checked CMAC_CTX allocation, initialization and destruction code to insure that it is
//         safe to share it between threads.
unsafe impl Send for CmacCtx {}

/// New type for `*mut ffi::EVP_MD_CTX` to implement `Send` for it. This allow us to still check if
/// a `!Send` item is added to `BoringEcDigestSignOperation`
pub(crate) struct EvpMdCtx(pub(crate) *mut ffi::EVP_MD_CTX);

// Safety: Checked EVP_MD_CTX allocation, initialization and destruction code to insure that it is
//         safe to share it between threads.
unsafe impl Send for EvpMdCtx {}

/// New type for `*mut ffi::EVP_PKEY_CTX` to implement `Send` for it. This allow us to still check
/// if a `!Send` item is added to `BoringEcDigestSignOperation`
pub(crate) struct EvpPkeyCtx(pub(crate) *mut ffi::EVP_PKEY_CTX);

// Safety: Checked EVP_MD_CTX allocation, initialization and destruction code to insure that it is
//         safe to share it between threads.
unsafe impl Send for EvpPkeyCtx {}

/// New type for `*mut ffi::HMAC_CTX` to implement `Send` for it. This allow us to still check if
/// a `!Send` item is added to `BoringHmacOperation`
pub(crate) struct HmacCtx(pub(crate) *mut ffi::HMAC_CTX);

// Safety: Checked EVP_MD_CTX allocation, initialization and destruction code to insure that it is
//         safe to share it between threads.
unsafe impl Send for HmacCtx {}
