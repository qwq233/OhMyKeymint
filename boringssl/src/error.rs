// Copyright 2020, The Android Open Source Project
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

//! This module implements Error for the keystore2_crypto library.
use crate::zvec;

/// Crypto specific error codes.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    /// This is returned if the C/C++ implementation of AES_gcm_decrypt returned false.
    #[error("Failed to decrypt.")]
    DecryptionFailed,

    /// This is returned if the C/C++ implementation of AES_gcm_encrypt returned false.
    #[error("Failed to encrypt.")]
    EncryptionFailed,

    /// The initialization vector has the wrong length.
    #[error("Invalid IV length.")]
    InvalidIvLength,

    /// The aead tag has the wrong length.
    #[error("Invalid AEAD tag length.")]
    InvalidAeadTagLength,

    /// The key has the wrong length.
    #[error("Invalid key length.")]
    InvalidKeyLength,

    /// Invalid data length.
    #[error("Invalid data length.")]
    InvalidDataLength,

    /// Invalid salt length.
    #[error("Invalid salt length.")]
    InvalidSaltLength,

    /// Random number generation failed.
    #[error("Random number generation failed.")]
    RandomNumberGenerationFailed,

    /// Nix error.
    #[error(transparent)]
    NixError(#[from] nix::Error),

    /// This is returned if the C implementation of HKDFExtract returned false
    /// or otherwise failed.
    #[error("Failed to extract.")]
    HKDFExtractFailed,

    /// This is returned if the C implementation of HKDFExpand returned false.
    #[error("Failed to expand.")]
    HKDFExpandFailed,

    /// This is returned if the C implementation of ECDHComputeKey returned -1.
    #[error("Failed to compute ecdh key.")]
    ECDHComputeKeyFailed,

    /// This is returned if the C implementation of ECKEYGenerateKey returned null.
    #[error("Failed to generate key.")]
    ECKEYGenerateKeyFailed,

    /// This is returned if the C implementation of ECKEYMarshalPrivateKey returned 0.
    #[error("Failed to marshal private key.")]
    ECKEYMarshalPrivateKeyFailed,

    /// This is returned if the C implementation of ECKEYParsePrivateKey returned null.
    #[error("Failed to parse private key.")]
    ECKEYParsePrivateKeyFailed,

    /// This is returned if the C implementation of ECPOINTPoint2Oct returned 0.
    #[error("Failed to convert point to oct.")]
    ECPoint2OctFailed,

    /// This is returned if the C implementation of ECPOINTOct2Point returned null.
    #[error("Failed to convert oct to point.")]
    ECOct2PointFailed,

    /// This is returned if the C implementation of extractSubjectFromCertificate failed.
    #[error("Failed to extract certificate subject.")]
    ExtractSubjectFailed,

    /// This is returned if the C implementation of hmacSha256 failed.
    #[error("Failed to calculate HMAC-SHA256.")]
    HmacSha256Failed,

    /// Zvec error.
    #[error(transparent)]
    ZVec(#[from] zvec::Error),
}
