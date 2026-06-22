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

//! Functionality related to triple DES encryption

use crate::{km_err, try_to_vec, Error};
use core::convert::TryInto;
use kmr_wire::KeySizeInBits;
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

/// Size of an DES block in bytes.
pub const BLOCK_SIZE: usize = 8;

/// The size of a 3-DES key in bits.
pub const KEY_SIZE_BITS: KeySizeInBits = KeySizeInBits(168);

/// The size of a 3-DES key in bytes.  Note that this is `KEY_SIZE_BITS` / 7, not
/// `KEY_SIZE_BITS` / 8 because each byte has a check bit (even though this check
/// bit is never actually checked).
pub const KEY_SIZE_BYTES: usize = 24;

/// A 3-DES key. The key data is 24 bytes / 192 bits in length, but only 7/8 of the
/// bits are used giving an effective key size of 168 bits.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Key(pub [u8; KEY_SIZE_BYTES]);

impl Key {
    /// Create a new 3-DES key from 24 bytes of data.
    pub fn new(data: Vec<u8>) -> Result<Key, Error> {
        Ok(Key(data.try_into().map_err(|_e| {
            km_err!(UnsupportedKeySize, "3-DES key size wrong")
        })?))
    }
    /// Create a new 3-DES key from 24 bytes of data.
    pub fn new_from(data: &[u8]) -> Result<Key, Error> {
        let data = try_to_vec(data)?;
        Ok(Key(data.try_into().map_err(|_e| {
            km_err!(UnsupportedKeySize, "3-DES key size wrong")
        })?))
    }
}

/// Mode of DES operation.  Associated value is the nonce.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// ECB mode with no padding.
    EcbNoPadding,
    /// ECB mode with PKCS#7 padding.
    EcbPkcs7Padding,
    /// CBC mode with no padding.
    CbcNoPadding {
        /// Nonce to use.
        nonce: [u8; BLOCK_SIZE],
    },
    /// CBC mode with PKCS#7 padding.
    CbcPkcs7Padding {
        /// Nonce to use.
        nonce: [u8; BLOCK_SIZE],
    },
}
