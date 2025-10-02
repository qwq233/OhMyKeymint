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

//! BoringSSL-based implementation of random number generation.
#[cfg(soong)]
use bssl_sys as ffi;
use kmr_common::crypto;

/// [`crypto::Rng`] implementation based on BoringSSL.
#[derive(Default)]
pub struct BoringRng;

impl crypto::Rng for BoringRng {
    fn add_entropy(&mut self, data: &[u8]) {
        #[cfg(soong)]
        // Safety: `data` is a valid slice.
        unsafe {
            ffi::RAND_seed(data.as_ptr() as *const libc::c_void, data.len() as libc::c_int);
        }
        #[cfg(not(soong))]
        // Safety: `data` is a valid slice.
        unsafe {
            ffi::RAND_add(
                data.as_ptr() as *const libc::c_void,
                data.len() as libc::c_int,
                data.len() as f64,
            );
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        openssl::rand::rand_bytes(dest).unwrap(); // safe: BoringSSL's RAND_bytes() never fails
    }
}
