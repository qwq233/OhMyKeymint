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

//! Functionality related to AES encryption

use super::{nonce, Rng};
use crate::{get_tag_value, km_err, tag, try_to_vec, Error};
use core::convert::TryInto;
use kmr_wire::keymint::{BlockMode, ErrorCode, KeyParam, PaddingMode};
use kmr_wire::KeySizeInBits;
use zeroize::ZeroizeOnDrop;

/// Size of an AES block in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Size of AES-GCM nonce in bytes.
pub const GCM_NONCE_SIZE: usize = 12; // 96 bits

/// AES variant.
#[derive(Clone)]
pub enum Variant {
    /// AES-128
    Aes128,
    /// AES-192
    Aes192,
    /// AES-256
    Aes256,
}

impl Variant {
    /// Size in bytes of the corresponding AES key.
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

/// An AES-128, AES-192 or AES-256 key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum Key {
    /// AES-128
    Aes128([u8; 16]),
    /// AES-192
    Aes192([u8; 24]),
    /// AES-256
    Aes256([u8; 32]),
}

impl Key {
    /// Create a new [`Key`] from raw data, which must be 16, 24 or 32 bytes long.
    pub fn new(data: Vec<u8>) -> Result<Self, Error> {
        match data.len() {
            16 => Ok(Key::Aes128(data.try_into().unwrap())), // safe: len checked
            24 => Ok(Key::Aes192(data.try_into().unwrap())), // safe: len checked
            32 => Ok(Key::Aes256(data.try_into().unwrap())), // safe: len checked
            l => Err(km_err!(UnsupportedKeySize, "AES keys must be 16, 24 or 32 bytes not {}", l)),
        }
    }
    /// Create a new [`Key`] from raw data, which must be 16, 24 or 32 bytes long.
    pub fn new_from(data: &[u8]) -> Result<Self, Error> {
        Key::new(try_to_vec(data)?)
    }

    /// Indicate the size of the key in bits.
    pub fn size(&self) -> KeySizeInBits {
        KeySizeInBits(match self {
            Key::Aes128(_) => 128,
            Key::Aes192(_) => 192,
            Key::Aes256(_) => 256,
        })
    }
}

/// Mode of AES plain cipher operation.  Associated value is the nonce.
#[derive(Clone, Copy, Debug)]
pub enum CipherMode {
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
    /// CTR mode with the given nonce.
    Ctr {
        /// Nonce to use.
        nonce: [u8; BLOCK_SIZE],
    },
}

/// Mode of AES-GCM operation.  Associated value is the nonce, size of
/// tag is indicated by the variant name.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum GcmMode {
    GcmTag12 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag13 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag14 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag15 { nonce: [u8; GCM_NONCE_SIZE] },
    GcmTag16 { nonce: [u8; GCM_NONCE_SIZE] },
}

/// Mode of AES operation.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Perform unauthenticated cipher operation.
    Cipher(CipherMode),
    /// Perform authenticated cipher with additional data operation.
    Aead(GcmMode),
}

impl Mode {
    /// Determine the [`Mode`], rejecting invalid parameters. Use `caller_nonce` if provided,
    /// otherwise generate a new nonce using the provided [`Rng`] instance.
    pub fn new(
        params: &[KeyParam],
        caller_nonce: Option<&Vec<u8>>,
        rng: &mut dyn Rng,
    ) -> Result<Self, Error> {
        let mode = tag::get_block_mode(params)?;
        let padding = tag::get_padding_mode(params)?;
        match mode {
            BlockMode::Ecb => {
                if caller_nonce.is_some() {
                    return Err(km_err!(InvalidNonce, "nonce unexpectedly provided for AES-ECB"));
                }
                match padding {
                    PaddingMode::None => Ok(Mode::Cipher(CipherMode::EcbNoPadding)),
                    PaddingMode::Pkcs7 => Ok(Mode::Cipher(CipherMode::EcbPkcs7Padding)),
                    _ => Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE/PKCS7 padding for AES-ECB"
                    )),
                }
            }
            BlockMode::Cbc => {
                let nonce: [u8; BLOCK_SIZE] =
                    nonce(BLOCK_SIZE, caller_nonce, rng)?.try_into().map_err(|_e| {
                        km_err!(InvalidNonce, "want {} byte nonce for AES-CBC", BLOCK_SIZE)
                    })?;
                match padding {
                    PaddingMode::None => Ok(Mode::Cipher(CipherMode::CbcNoPadding { nonce })),
                    PaddingMode::Pkcs7 => Ok(Mode::Cipher(CipherMode::CbcPkcs7Padding { nonce })),
                    _ => Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE/PKCS7 padding for AES-CBC"
                    )),
                }
            }
            BlockMode::Ctr => {
                if padding != PaddingMode::None {
                    return Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE padding for AES-CTR"
                    ));
                }
                let nonce: [u8; BLOCK_SIZE] =
                    nonce(BLOCK_SIZE, caller_nonce, rng)?.try_into().map_err(|_e| {
                        km_err!(InvalidNonce, "want {} byte nonce for AES-CTR", BLOCK_SIZE)
                    })?;
                Ok(Mode::Cipher(CipherMode::Ctr { nonce }))
            }
            BlockMode::Gcm => {
                if padding != PaddingMode::None {
                    return Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE padding for AES-GCM"
                    ));
                }
                let nonce: [u8; GCM_NONCE_SIZE] = nonce(GCM_NONCE_SIZE, caller_nonce, rng)?
                    .try_into()
                    .map_err(|_e| km_err!(InvalidNonce, "want 12 byte nonce for AES-GCM"))?;
                let tag_len = get_tag_value!(params, MacLength, ErrorCode::InvalidMacLength)?;
                if tag_len % 8 != 0 {
                    return Err(km_err!(
                        InvalidMacLength,
                        "tag length {} not a multiple of 8",
                        tag_len
                    ));
                }
                match tag_len / 8 {
                    12 => Ok(Mode::Aead(GcmMode::GcmTag12 { nonce })),
                    13 => Ok(Mode::Aead(GcmMode::GcmTag13 { nonce })),
                    14 => Ok(Mode::Aead(GcmMode::GcmTag14 { nonce })),
                    15 => Ok(Mode::Aead(GcmMode::GcmTag15 { nonce })),
                    16 => Ok(Mode::Aead(GcmMode::GcmTag16 { nonce })),
                    v => Err(km_err!(
                        InvalidMacLength,
                        "want 12-16 byte tag for AES-GCM not {} bytes",
                        v
                    )),
                }
            }
        }
    }

    /// Indicate whether the AES mode is an AEAD.
    pub fn is_aead(&self) -> bool {
        match self {
            Mode::Aead(_) => true,
            Mode::Cipher(_) => false,
        }
    }
}

impl GcmMode {
    /// Return the tag length (in bytes) for an AES-GCM mode.
    pub fn tag_len(&self) -> usize {
        match self {
            GcmMode::GcmTag12 { nonce: _ } => 12,
            GcmMode::GcmTag13 { nonce: _ } => 13,
            GcmMode::GcmTag14 { nonce: _ } => 14,
            GcmMode::GcmTag15 { nonce: _ } => 15,
            GcmMode::GcmTag16 { nonce: _ } => 16,
        }
    }
}
