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

//! BoringSSL-based implementation of 3-DES.
use crate::{openssl_err, ossl};
use Box;
use Vec;
use kmr_common::{crypto, crypto::OpaqueOr, explicit, vec_try, Error};
use openssl::symm::{Cipher, Crypter};

/// [`crypto::Des`] implementation based on BoringSSL.
pub struct BoringDes;

impl crypto::Des for BoringDes {
    fn begin(
        &self,
        key: OpaqueOr<crypto::des::Key>,
        mode: crypto::des::Mode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, Error> {
        let key = explicit!(key)?;
        let dir_mode = match dir {
            crypto::SymmetricOperation::Encrypt => openssl::symm::Mode::Encrypt,
            crypto::SymmetricOperation::Decrypt => openssl::symm::Mode::Decrypt,
        };
        let crypter = match mode {
            crypto::des::Mode::EcbNoPadding | crypto::des::Mode::EcbPkcs7Padding => {
                let cipher = Cipher::des_ede3();
                let mut crypter = Crypter::new(cipher, dir_mode, &key.0, None)
                    .map_err(openssl_err!("failed to create ECB Crypter"))?;
                if let crypto::des::Mode::EcbPkcs7Padding = mode {
                    crypter.pad(true);
                } else {
                    crypter.pad(false);
                }
                crypter
            }

            crypto::des::Mode::CbcNoPadding { nonce: n }
            | crypto::des::Mode::CbcPkcs7Padding { nonce: n } => {
                let cipher = Cipher::des_ede3_cbc();
                let mut crypter = Crypter::new(cipher, dir_mode, &key.0, Some(&n[..]))
                    .map_err(openssl_err!("failed to create CBC Crypter"))?;
                if let crypto::des::Mode::CbcPkcs7Padding { nonce: _ } = mode {
                    crypter.pad(true);
                } else {
                    crypter.pad(false);
                }
                crypter
            }
        };

        Ok(Box::new(BoringDesOperation { crypter }))
    }
}

/// DES operation based on BoringSSL.
pub struct BoringDesOperation {
    crypter: openssl::symm::Crypter,
}

impl crypto::EmittingOperation for BoringDesOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = vec_try![0; data.len() + crypto::des::BLOCK_SIZE]?;
        let out_len = self
            .crypter
            .update(data, &mut output[..])
            .map_err(openssl_err!("update with {} bytes of data failed", data.len()))?;
        output.truncate(out_len);
        Ok(output)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut output = vec_try![0; crypto::des::BLOCK_SIZE]?;
        let out_len = ossl!(self.crypter.finalize(&mut output))?;
        output.truncate(out_len);
        Ok(output)
    }
}
