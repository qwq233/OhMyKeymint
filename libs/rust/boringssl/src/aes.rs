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

//! BoringSSL-based implementation of AES.
use crate::{openssl_err, openssl_err_or, ossl};
use Box;
use Vec;
use core::cmp::min;
use kmr_common::{
    crypto, crypto::OpaqueOr, explicit, km_err, vec_try, vec_try_with_capacity, Error,
    FallibleAllocExt,
};
use openssl::symm::{Cipher, Crypter};

/// [`crypto::Aes`] implementation based on BoringSSL.
pub struct BoringAes;

impl crypto::Aes for BoringAes {
    fn begin(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::CipherMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, Error> {
        let key = explicit!(key)?;
        let dir_mode = match dir {
            crypto::SymmetricOperation::Encrypt => openssl::symm::Mode::Encrypt,
            crypto::SymmetricOperation::Decrypt => openssl::symm::Mode::Decrypt,
        };
        let crypter = match mode {
            crypto::aes::CipherMode::EcbNoPadding | crypto::aes::CipherMode::EcbPkcs7Padding => {
                let (cipher, key) = match &key {
                    crypto::aes::Key::Aes128(k) => (Cipher::aes_128_ecb(), &k[..]),
                    crypto::aes::Key::Aes192(k) => (Cipher::aes_192_ecb(), &k[..]),
                    crypto::aes::Key::Aes256(k) => (Cipher::aes_256_ecb(), &k[..]),
                };
                let mut crypter = Crypter::new(cipher, dir_mode, key, None)
                    .map_err(openssl_err!("failed to create ECB Crypter"))?;
                if let crypto::aes::CipherMode::EcbPkcs7Padding = mode {
                    crypter.pad(true);
                } else {
                    crypter.pad(false);
                }
                crypter
            }

            crypto::aes::CipherMode::CbcNoPadding { nonce: n }
            | crypto::aes::CipherMode::CbcPkcs7Padding { nonce: n } => {
                let (cipher, key) = match &key {
                    crypto::aes::Key::Aes128(k) => (Cipher::aes_128_cbc(), &k[..]),
                    crypto::aes::Key::Aes192(k) => (Cipher::aes_192_cbc(), &k[..]),
                    crypto::aes::Key::Aes256(k) => (Cipher::aes_256_cbc(), &k[..]),
                };
                let mut crypter = Crypter::new(cipher, dir_mode, key, Some(&n[..]))
                    .map_err(openssl_err!("failed to create CBC Crypter"))?;
                if let crypto::aes::CipherMode::CbcPkcs7Padding { nonce: _ } = mode {
                    crypter.pad(true);
                } else {
                    crypter.pad(false);
                }
                crypter
            }

            crypto::aes::CipherMode::Ctr { nonce: n } => {
                let (cipher, key) = match &key {
                    crypto::aes::Key::Aes128(k) => (Cipher::aes_128_ctr(), &k[..]),
                    crypto::aes::Key::Aes192(k) => (Cipher::aes_192_ctr(), &k[..]),
                    crypto::aes::Key::Aes256(k) => (Cipher::aes_256_ctr(), &k[..]),
                };
                Crypter::new(cipher, dir_mode, key, Some(&n[..]))
                    .map_err(openssl_err!("failed to create CTR Crypter"))?
            }
        };

        Ok(Box::new(BoringAesOperation { crypter }))
    }

    fn begin_aead(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::GcmMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::AadOperation>, Error> {
        let key = explicit!(key)?;
        let dir_mode = match dir {
            crypto::SymmetricOperation::Encrypt => openssl::symm::Mode::Encrypt,
            crypto::SymmetricOperation::Decrypt => openssl::symm::Mode::Decrypt,
        };
        let crypter = match mode {
            crypto::aes::GcmMode::GcmTag12 { nonce: n }
            | crypto::aes::GcmMode::GcmTag13 { nonce: n }
            | crypto::aes::GcmMode::GcmTag14 { nonce: n }
            | crypto::aes::GcmMode::GcmTag15 { nonce: n }
            | crypto::aes::GcmMode::GcmTag16 { nonce: n } => {
                let (cipher, key) = match &key {
                    crypto::aes::Key::Aes128(k) => (Cipher::aes_128_gcm(), &k[..]),
                    crypto::aes::Key::Aes192(k) => (Cipher::aes_192_gcm(), &k[..]),
                    crypto::aes::Key::Aes256(k) => (Cipher::aes_256_gcm(), &k[..]),
                };
                Crypter::new(cipher, dir_mode, key, Some(&n[..])).map_err(openssl_err!(
                    "failed to create GCM Crypter for {:?} {:?}",
                    mode,
                    dir
                ))?
            }
        };

        Ok(match dir {
            crypto::SymmetricOperation::Encrypt => Box::new({
                BoringAesGcmEncryptOperation { mode, inner: BoringAesOperation { crypter } }
            }),
            crypto::SymmetricOperation::Decrypt => Box::new(BoringAesGcmDecryptOperation {
                crypter,
                decrypt_tag_len: mode.tag_len(),
                pending_input_tail: vec_try_with_capacity!(mode.tag_len())?,
            }),
        })
    }
}

/// AES operation based on BoringSSL.
pub struct BoringAesOperation {
    crypter: openssl::symm::Crypter,
}

impl crypto::EmittingOperation for BoringAesOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = vec_try![0; data.len() + crypto::aes::BLOCK_SIZE]?;
        let out_len = self
            .crypter
            .update(data, &mut output)
            .map_err(openssl_err!("update {} bytes from input failed", data.len()))?;
        output.truncate(out_len);
        Ok(output)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut output = vec_try![0; crypto::aes::BLOCK_SIZE]?;
        let out_len = ossl!(self.crypter.finalize(&mut output))?;
        output.truncate(out_len);
        Ok(output)
    }
}

/// AES-GCM encrypt operation based on BoringSSL.
pub struct BoringAesGcmEncryptOperation {
    mode: crypto::aes::GcmMode,
    inner: BoringAesOperation,
}

impl crypto::AadOperation for BoringAesGcmEncryptOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        ossl!(self.inner.crypter.aad_update(aad))
    }
}

impl crypto::EmittingOperation for BoringAesGcmEncryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.update(data)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut output = vec_try![0; crypto::aes::BLOCK_SIZE + self.mode.tag_len()]?;
        let offset = self
            .inner
            .crypter
            .finalize(&mut output)
            .map_err(openssl_err_or!(VerificationFailed, "failed to finalize"))?;

        self.inner
            .crypter
            .get_tag(&mut output[offset..offset + self.mode.tag_len()])
            .map_err(openssl_err!("failed to get tag of len {}", self.mode.tag_len()))?;
        output.truncate(offset + self.mode.tag_len());
        Ok(output)
    }
}

/// AES-GCM decrypt operation based on BoringSSL.
pub struct BoringAesGcmDecryptOperation {
    crypter: openssl::symm::Crypter,

    // Size of a final tag when decrypting.
    decrypt_tag_len: usize,

    // For decryption, the last `decrypt_tag_len` bytes of input must be fed in separately.
    // However, the overall size of the input data is not known in advance, so we need to hold up to
    // `decrypt_tag_len` bytes on input in reserve until `finish()`.
    pending_input_tail: Vec<u8>, // Capacity = decrypt_tag_len
}

impl crypto::AadOperation for BoringAesGcmDecryptOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        ossl!(self.crypter.aad_update(aad))
    }
}

impl crypto::EmittingOperation for BoringAesGcmDecryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // The current input is the (self.pending_input_tail || data) combination.
        let combined_len = self.pending_input_tail.len() + data.len();
        if combined_len <= self.decrypt_tag_len {
            // Adding on this data is still not enough for more than just a tag,
            // so save off the input data for next time and return.
            self.pending_input_tail.try_extend_from_slice(data)?;
            return Ok(Vec::new());
        }

        // At this point the combination (self.pending_input_tail || data) includes enough data to both:
        // - feed some into the cipher
        // - still keep a full self.decrypt_tag_len worth of data still pending.
        let cipherable_len = combined_len - self.decrypt_tag_len;
        let cipherable_from_pending = min(cipherable_len, self.pending_input_tail.len());
        let cipherable_from_data = cipherable_len - cipherable_from_pending;

        let mut output = vec_try![0; data.len()]?;
        let mut offset = 0;
        if cipherable_from_pending > 0 {
            offset = self
                .crypter
                .update(&self.pending_input_tail[..cipherable_from_pending], &mut output)
                .map_err(openssl_err!(
                    "update {} bytes from pending failed",
                    cipherable_from_pending
                ))?;
        }
        if cipherable_from_data > 0 {
            let out_len = self
                .crypter
                .update(&data[..cipherable_from_data], &mut output[offset..])
                .map_err(openssl_err!("update {} bytes from input failed", cipherable_from_data))?;
            offset += out_len;
        }
        output.truncate(offset);

        // Reset `self.pending_input_tail` to the unused data.
        let leftover_pending = self.pending_input_tail.len() - cipherable_from_pending;
        self.pending_input_tail.resize(self.decrypt_tag_len, 0);
        self.pending_input_tail.copy_within(cipherable_from_pending.., 0);
        self.pending_input_tail[leftover_pending..].copy_from_slice(&data[cipherable_from_data..]);

        Ok(output)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        // Need to feed in the entire tag before completion.
        if self.pending_input_tail.len() != self.decrypt_tag_len {
            return Err(km_err!(
                InvalidTag,
                "only {} bytes of pending data, need {}",
                self.pending_input_tail.len(),
                self.decrypt_tag_len
            ));
        }
        self.crypter.set_tag(&self.pending_input_tail).map_err(openssl_err!(
            "failed to set {} bytes of tag",
            self.pending_input_tail.len()
        ))?;

        // Feeding in just the tag should not result in any output data.
        let mut output = Vec::new();
        let out_len = self
            .crypter
            .finalize(&mut output)
            .map_err(openssl_err_or!(VerificationFailed, "failed to finalize"))?;
        if out_len != 0 {
            return Err(km_err!(
                BoringSslError,
                "finalizing AES-GCM tag produced {} bytes of data!",
                out_len
            ));
        }
        Ok(output)
    }
}
