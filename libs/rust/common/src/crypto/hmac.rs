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

//! Functionality related to HMAC signing/verification.

use crate::{km_err, try_to_vec, Error};
use kmr_wire::KeySizeInBits;
use zeroize::ZeroizeOnDrop;

/// Minimum size of an HMAC key in bits.
pub const MIN_KEY_SIZE_BITS: usize = 64;

/// Maximum size of a StrongBox HMAC key in bits.
pub const MAX_STRONGBOX_KEY_SIZE_BITS: usize = 512;

/// Maximum size of a HMAC key in bits.
pub const MAX_KEY_SIZE_BITS: usize = 1024;

/// An HMAC key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Key(pub Vec<u8>);

fn valid_size(key_size: KeySizeInBits, max_size_bits: usize) -> Result<(), Error> {
    if key_size.0 % 8 != 0 {
        Err(km_err!(UnsupportedKeySize, "key size {} bits not a multiple of 8", key_size.0))
    } else if !(MIN_KEY_SIZE_BITS..=max_size_bits).contains(&(key_size.0 as usize)) {
        Err(km_err!(UnsupportedKeySize, "unsupported KEY_SIZE {} bits for HMAC", key_size.0))
    } else {
        Ok(())
    }
}

/// Check that the size of an HMAC key is within the allowed size for the KeyMint HAL.
pub fn valid_hal_size(key_size: KeySizeInBits) -> Result<(), Error> {
    valid_size(key_size, MAX_KEY_SIZE_BITS)
}

/// Check that the size of an HMAC key is within the allowed size for a StrongBox implementation.
pub fn valid_strongbox_hal_size(key_size: KeySizeInBits) -> Result<(), Error> {
    valid_size(key_size, MAX_STRONGBOX_KEY_SIZE_BITS)
}

impl Key {
    /// Create a new HMAC key from data.
    pub fn new(data: Vec<u8>) -> Key {
        Key(data)
    }

    /// Create a new HMAC key from data.
    pub fn new_from(data: &[u8]) -> Result<Key, Error> {
        Ok(Key::new(try_to_vec(data)?))
    }

    /// Indicate the size of the key in bits.
    pub fn size(&self) -> KeySizeInBits {
        KeySizeInBits((self.0.len() * 8) as u32)
    }
}
