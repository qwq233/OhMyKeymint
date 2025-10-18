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

//! Traits representing abstractions of cryptographic functionality.
use super::*;
use crate::{crypto::ec::Key, der_err, explicit, keyblob, vec_try, Error};
use der::Decode;
use kmr_wire::{keymint, keymint::Digest, KeySizeInBits, RsaExponent};
use log::{error, warn};

/// Combined collection of trait implementations that must be provided.
pub struct Implementation {
    /// Random number generator.
    pub rng: Box<dyn Rng>,

    /// A local clock, if available. If not available, KeyMint will require timestamp tokens to
    /// be provided by an external `ISecureClock` (with which it shares a common key).
    pub clock: Option<Box<dyn MonotonicClock>>,

    /// A constant-time equality implementation.
    pub compare: Box<dyn ConstTimeEq>,

    /// AES implementation.
    pub aes: Box<dyn Aes>,

    /// DES implementation.
    pub des: Box<dyn Des>,

    /// HMAC implementation.
    pub hmac: Box<dyn Hmac>,

    /// RSA implementation.
    pub rsa: Box<dyn Rsa>,

    /// EC implementation.
    pub ec: Box<dyn Ec>,

    /// CKDF implementation.
    pub ckdf: Box<dyn Ckdf>,

    /// HKDF implementation.
    pub hkdf: Box<dyn Hkdf>,

    /// SHA-256 implementation.
    pub sha256: Box<dyn Sha256>,
}

/// Abstraction of a random number generator that is cryptographically secure
/// and which accepts additional entropy to be mixed in.
pub trait Rng: Send {
    /// Add entropy to the generator's pool.
    fn add_entropy(&mut self, data: &[u8]);
    /// Generate random data.
    fn fill_bytes(&mut self, dest: &mut [u8]);
    /// Return a random `u64` value.
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Abstraction of constant-time comparisons, for use in cryptographic contexts where timing attacks
/// need to be avoided.
pub trait ConstTimeEq: Send {
    /// Indicate whether arguments are the same.
    fn eq(&self, left: &[u8], right: &[u8]) -> bool;
    /// Indicate whether arguments are the different.
    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
        !self.eq(left, right)
    }
}

/// Abstraction of a monotonic clock.
pub trait MonotonicClock: Send {
    /// Return the current time in milliseconds since some arbitrary point in time.  Time must be
    /// monotonically increasing, and "current time" must not repeat until the Android device
    /// reboots, or until at least 50 million years have elapsed.  Time must also continue to
    /// advance while the device is suspended (which may not be the case with e.g. Linux's
    /// `clock_gettime(CLOCK_MONOTONIC)`).
    fn now(&self) -> MillisecondsSinceEpoch;
}

/// Abstraction of AES functionality.
pub trait Aes: Send {
    /// Generate an AES key.  The default implementation fills with random data.  Key generation
    /// parameters are passed in for reference, to allow for implementations that might have
    /// parameter-specific behaviour.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        variant: aes::Variant,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        Ok(match variant {
            aes::Variant::Aes128 => {
                let mut key = [0; 16];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes128(key).into())
            }
            aes::Variant::Aes192 => {
                let mut key = [0; 24];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes192(key).into())
            }
            aes::Variant::Aes256 => {
                let mut key = [0; 32];
                rng.fill_bytes(&mut key[..]);
                KeyMaterial::Aes(aes::Key::Aes256(key).into())
            }
        })
    }

    /// Import an AES key, also returning the key size in bits.  Key import parameters are passed in
    /// for reference, to allow for implementations that might have parameter-specific behaviour.
    fn import_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits), Error> {
        let aes_key = aes::Key::new_from(data)?;
        let key_size = aes_key.size();
        Ok((KeyMaterial::Aes(aes_key.into()), key_size))
    }

    /// Create an AES operation.  For block mode operations with no padding
    /// ([`aes::CipherMode::EcbNoPadding`] and [`aes::CipherMode::CbcNoPadding`]) the operation
    /// implementation should reject (with `ErrorCode::InvalidInputLength`) input data that does
    /// not end up being a multiple of the block size.
    fn begin(
        &self,
        key: OpaqueOr<aes::Key>,
        mode: aes::CipherMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;

    /// Create an AES-GCM operation.
    fn begin_aead(
        &self,
        key: OpaqueOr<aes::Key>,
        mode: aes::GcmMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error>;
}

/// Abstraction of 3-DES functionality.
pub trait Des: Send {
    /// Generate a triple DES key. Key generation parameters are passed in for reference, to allow
    /// for implementations that might have parameter-specific behaviour.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        let mut key = vec_try![0; 24]?;
        // Note: parity bits must be ignored.
        rng.fill_bytes(&mut key[..]);
        Ok(KeyMaterial::TripleDes(des::Key::new(key)?.into()))
    }

    /// Import a triple DES key. Key import parameters are passed in for reference, to allow for
    /// implementations that might have parameter-specific behaviour.
    fn import_key(&self, data: &[u8], _params: &[keymint::KeyParam]) -> Result<KeyMaterial, Error> {
        let des_key = des::Key::new_from(data)?;
        Ok(KeyMaterial::TripleDes(des_key.into()))
    }

    /// Create a DES operation.  For block mode operations with no padding
    /// ([`des::Mode::EcbNoPadding`] and [`des::Mode::CbcNoPadding`]) the operation implementation
    /// should reject (with `ErrorCode::InvalidInputLength`) input data that does not end up being
    /// a multiple of the block size.
    fn begin(
        &self,
        key: OpaqueOr<des::Key>,
        mode: des::Mode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;
}

/// Abstraction of HMAC functionality.
pub trait Hmac: Send {
    /// Generate an HMAC key. Key generation parameters are passed in for reference, to allow for
    /// implementations that might have parameter-specific behaviour.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        hmac::valid_hal_size(key_size)?;

        let key_len = (key_size.0 / 8) as usize;
        let mut key = vec_try![0; key_len]?;
        rng.fill_bytes(&mut key);
        Ok(KeyMaterial::Hmac(hmac::Key::new(key).into()))
    }

    /// Import an HMAC key, also returning the key size in bits. Key import parameters are passed in
    /// for reference, to allow for implementations that might have parameter-specific behaviour.
    fn import_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits), Error> {
        let hmac_key = hmac::Key::new_from(data)?;
        let key_size = hmac_key.size();
        hmac::valid_hal_size(key_size)?;
        Ok((KeyMaterial::Hmac(hmac_key.into()), key_size))
    }

    /// Create an HMAC operation. Implementations can assume that:
    /// - `key` will have length in range `8..=64` bytes.
    /// - `digest` will not be [`Digest::None`]
    fn begin(
        &self,
        key: OpaqueOr<hmac::Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of AES-CMAC functionality. (Note that this is not exposed in the KeyMint HAL API
/// directly, but is required for the CKDF operations involved in `ISharedSecret` negotiation.)
pub trait AesCmac: Send {
    /// Create an AES-CMAC operation. Implementations can assume that `key` will have length
    /// of either 16 (AES-128) or 32 (AES-256).
    fn begin(&self, key: OpaqueOr<aes::Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of RSA functionality.
pub trait Rsa: Send {
    /// Generate an RSA key. Key generation parameters are passed in for reference, to allow for
    /// implementations that might have parameter-specific behaviour.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
        pub_exponent: RsaExponent,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    /// Import an RSA key in PKCS#8 format, also returning the key size in bits and public exponent.
    /// Key import parameters are passed in for reference, to allow for implementations that might
    /// have parameter-specific behaviour.
    fn import_pkcs8_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<(KeyMaterial, KeySizeInBits, RsaExponent), Error> {
        rsa::import_pkcs8_key(data)
    }

    /// Return the public key data corresponds to the provided private `key`,
    /// as an ASN.1 DER-encoded `SEQUENCE` as per RFC 3279 section 2.3.1:
    ///     ```asn1
    ///     RSAPublicKey ::= SEQUENCE {
    ///        modulus            INTEGER,    -- n
    ///        publicExponent     INTEGER  }  -- e
    ///     ```
    /// which is the `subjectPublicKey` to be included in `SubjectPublicKeyInfo`.
    fn subject_public_key(&self, key: &OpaqueOr<rsa::Key>) -> Result<Vec<u8>, Error> {
        // The default implementation only handles the `Explicit<rsa::Key>` variant.
        let rsa_key = explicit!(key)?;
        rsa_key.subject_public_key()
    }

    /// Create an RSA decryption operation.
    fn begin_decrypt(
        &self,
        key: OpaqueOr<rsa::Key>,
        mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;

    /// Create an RSA signing operation.  For [`rsa::SignMode::Pkcs1_1_5Padding(Digest::None)`] the
    /// implementation should reject (with `ErrorCode::InvalidInputLength`) accumulated input that
    /// is larger than the size of the RSA key less overhead
    /// ([`rsa::PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD`]).
    fn begin_sign(
        &self,
        key: OpaqueOr<rsa::Key>,
        mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of EC functionality.
pub trait Ec: Send {
    /// Generate an EC key for a NIST curve.  Key generation parameters are passed in for reference,
    /// to allow for implementations that might have parameter-specific behaviour.
    fn generate_nist_key(
        &self,
        rng: &mut dyn Rng,
        curve: ec::NistCurve,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    /// Generate an Ed25519 key.  Key generation parameters are passed in for reference, to allow
    /// for implementations that might have parameter-specific behaviour.
    fn generate_ed25519_key(
        &self,
        rng: &mut dyn Rng,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    /// Generate an X25519 key.  Key generation parameters are passed in for reference, to allow for
    /// implementations that might have parameter-specific behaviour.
    fn generate_x25519_key(
        &self,
        rng: &mut dyn Rng,
        params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error>;

    /// Import an EC key in PKCS#8 format.  Key import parameters are passed in for reference, to
    /// allow for implementations that might have parameter-specific behaviour.
    fn import_pkcs8_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_pkcs8_key(data)
    }

    /// Import a 32-byte raw Ed25519 key.  Key import parameters are passed in for reference, to
    /// allow for implementations that might have parameter-specific behaviour.
    fn import_raw_ed25519_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_raw_ed25519_key(data)
    }

    /// Import a 32-byte raw X25519 key.  Key import parameters are passed in for reference, to
    /// allow for implementations that might have parameter-specific behaviour.
    fn import_raw_x25519_key(
        &self,
        data: &[u8],
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        ec::import_raw_x25519_key(data)
    }

    /// Return the public key data that corresponds to the provided private `key`.
    /// If `CurveType` of the key is `CurveType::Nist`, return the public key data
    /// as a SEC-1 encoded uncompressed point as described in RFC 5480 section 2.1.
    /// I.e. 0x04: uncompressed, followed by x || y coordinates.
    ///
    /// For other two curve types, return the raw public key data.
    fn subject_public_key(&self, key: &OpaqueOr<ec::Key>) -> Result<Vec<u8>, Error> {
        // The default implementation only handles the `Explicit<ec::Key>` variant.
        let ec_key = explicit!(key)?;
        match ec_key {
            Key::P224(nist_key)
            | Key::P256(nist_key)
            | Key::P384(nist_key)
            | Key::P521(nist_key) => {
                let ec_pvt_key = sec1::EcPrivateKey::from_der(nist_key.0.as_slice())
                    .map_err(|e| der_err!(e, "failed to parse DER NIST EC PrivateKey"))?;
                match ec_pvt_key.public_key {
                    Some(pub_key) => Ok(pub_key.to_vec()),
                    None => {
                        // Key structure doesn't include optional public key, so regenerate it.
                        let nist_curve: ec::NistCurve = ec_key.curve().try_into()?;
                        Ok(self.nist_public_key(nist_key, nist_curve)?)
                    }
                }
            }
            Key::Ed25519(ed25519_key) => self.ed25519_public_key(ed25519_key),
            Key::X25519(x25519_key) => self.x25519_public_key(x25519_key),
        }
    }

    /// Return the public key data that corresponds to the provided private `key`, as a SEC-1
    /// encoded uncompressed point.
    fn nist_public_key(&self, key: &ec::NistKey, curve: ec::NistCurve) -> Result<Vec<u8>, Error>;

    /// Return the raw public key data that corresponds to the provided private `key`.
    fn ed25519_public_key(&self, key: &ec::Ed25519Key) -> Result<Vec<u8>, Error>;

    /// Return the raw public key data that corresponds to the provided private `key`.
    fn x25519_public_key(&self, key: &ec::X25519Key) -> Result<Vec<u8>, Error>;

    /// Create an EC key agreement operation.
    /// The accumulated input for the operation is expected to be the peer's
    /// public key, provided as an ASN.1 DER-encoded `SubjectPublicKeyInfo`.
    fn begin_agree(&self, key: OpaqueOr<ec::Key>) -> Result<Box<dyn AccumulatingOperation>, Error>;

    /// Create an EC signing operation.  For Ed25519 signing operations, the implementation should
    /// reject (with `ErrorCode::InvalidInputLength`) accumulated data that is larger than
    /// [`ec::MAX_ED25519_MSG_SIZE`].
    fn begin_sign(
        &self,
        key: OpaqueOr<ec::Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of an in-progress operation that emits data as it progresses.
pub trait EmittingOperation: Send {
    /// Update operation with data.
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of an in-progress operation that has authenticated associated data.
pub trait AadOperation: EmittingOperation {
    /// Update additional data.  Implementations can assume that all calls to `update_aad()`
    /// will occur before any calls to `update()` or `finish()`.
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error>;
}

/// Abstraction of an in-progress operation that only emits data when it completes.
pub trait AccumulatingOperation: Send {
    /// Maximum size of accumulated input.
    fn max_input_size(&self) -> Option<usize> {
        None
    }

    /// Update operation with data.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of HKDF key derivation with HMAC-SHA256.
///
/// A default implementation of this trait is available (in `crypto.rs`) for any type that
/// implements [`Hmac`].
pub trait Hkdf: Send {
    /// Perform combined HKDF using the input key material in `ikm`.
    fn hkdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
        let prk = self.extract(salt, ikm)?;
        self.expand(&prk, info, out_len)
    }

    /// Perform the HKDF-Extract step on the input key material in `ikm`, using optional `salt`.
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error>;

    /// Perform the HKDF-Expand step using the pseudo-random key in `prk`.
    fn expand(
        &self,
        prk: &OpaqueOr<hmac::Key>,
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error>;

    /// Perform combined HKDF using the input key material in `ikm`, emitting output in the form of
    /// an AES key.
    fn hkdf_aes(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        variant: aes::Variant,
    ) -> Result<OpaqueOr<aes::Key>, Error> {
        // Default implementation generates explicit key material and converts to an [`aes::Key`].
        let data = self.hkdf(salt, ikm, info, variant.key_size())?;
        let explicit_key = aes::Key::new(data)?;
        Ok(explicit_key.into())
    }

    /// Perform the HKDF-Expand step using the pseudo-random key in `prk`, emitting output in the
    /// form of an AES key.
    fn expand_aes(
        &self,
        prk: &OpaqueOr<hmac::Key>,
        info: &[u8],
        variant: aes::Variant,
    ) -> Result<OpaqueOr<aes::Key>, Error> {
        // Default implementation generates explicit key material and converts to an [`aes::Key`].
        let data = self.expand(prk, info, variant.key_size())?;
        let explicit_key = aes::Key::new(data)?;
        Ok(explicit_key.into())
    }
}

/// Abstraction of CKDF key derivation with AES-CMAC KDF from NIST SP 800-108 in counter mode (see
/// section 5.1).
///
/// Aa default implementation of this trait is available (in `crypto.rs`) for any type that
/// implements [`AesCmac`].
pub trait Ckdf: Send {
    /// Perform CKDF using the key material in `key`.
    fn ckdf(
        &self,
        key: &OpaqueOr<aes::Key>,
        label: &[u8],
        chunks: &[&[u8]],
        out_len: usize,
    ) -> Result<Vec<u8>, Error>;
}

/// Abstraction for SHA-256 hashing.
pub trait Sha256: Send {
    /// Generate the SHA-256 input of `data`.
    fn hash(&self, data: &[u8]) -> Result<[u8; 32], Error>;
}

////////////////////////////////////////////////////////////
// No-op implementations of traits. These implementations are
// only intended for convenience during the process of porting
// the KeyMint code to a new environment.

/// Macro to emit an error log indicating that an unimplemented function
/// has been invoked (and where it is).
#[macro_export]
macro_rules! log_unimpl {
    () => {
        error!(
            "{}:{}: Unimplemented placeholder KeyMint trait method invoked!",
            file!(),
            line!(),
        );
    };
}

/// Mark a method as unimplemented (log error, return `ErrorCode::Unimplemented`)
#[macro_export]
macro_rules! unimpl {
    () => {
        log_unimpl!();
        return Err(Error::Hal(
            kmr_wire::keymint::ErrorCode::Unimplemented,
            format!("{}:{}: method unimplemented", file!(), line!()),
        ));
    };
}

/// Stub implementation of [`Rng`].
pub struct NoOpRng;
impl Rng for NoOpRng {
    fn add_entropy(&mut self, _data: &[u8]) {
        log_unimpl!();
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        log_unimpl!();
    }
}

/// Stub implementation of [`ConstTimeEq`].
#[derive(Clone)]
pub struct InsecureEq;
impl ConstTimeEq for InsecureEq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        warn!("Insecure comparison operation performed");
        left == right
    }
}

/// Stub implementation of [`MonotonicClock`].
pub struct NoOpClock;
impl MonotonicClock for NoOpClock {
    fn now(&self) -> MillisecondsSinceEpoch {
        log_unimpl!();
        MillisecondsSinceEpoch(0)
    }
}

/// Stub implementation of [`Aes`].
pub struct NoOpAes;
impl Aes for NoOpAes {
    fn begin(
        &self,
        _key: OpaqueOr<aes::Key>,
        _mode: aes::CipherMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
    fn begin_aead(
        &self,
        _key: OpaqueOr<aes::Key>,
        _mode: aes::GcmMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`Des`].
pub struct NoOpDes;
impl Des for NoOpDes {
    fn begin(
        &self,
        _key: OpaqueOr<des::Key>,
        _mode: des::Mode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`Hmac`].
pub struct NoOpHmac;
impl Hmac for NoOpHmac {
    fn begin(
        &self,
        _key: OpaqueOr<hmac::Key>,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`AesCmac`].
pub struct NoOpAesCmac;
impl AesCmac for NoOpAesCmac {
    fn begin(&self, _key: OpaqueOr<aes::Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`Rsa`].
pub struct NoOpRsa;
impl Rsa for NoOpRsa {
    fn generate_key(
        &self,
        _rng: &mut dyn Rng,
        _key_size: KeySizeInBits,
        _pub_exponent: RsaExponent,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn begin_decrypt(
        &self,
        _key: OpaqueOr<rsa::Key>,
        _mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: OpaqueOr<rsa::Key>,
        _mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`Ec`].
pub struct NoOpEc;
impl Ec for NoOpEc {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn Rng,
        _curve: ec::NistCurve,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn generate_ed25519_key(
        &self,
        _rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn generate_x25519_key(
        &self,
        _rng: &mut dyn Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn nist_public_key(&self, _key: &ec::NistKey, _curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn ed25519_public_key(&self, _key: &ec::Ed25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn x25519_public_key(&self, _key: &ec::X25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn begin_agree(
        &self,
        _key: OpaqueOr<ec::Key>,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: OpaqueOr<ec::Key>,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`keyblob::SecureDeletionSecretManager`].
pub struct NoOpSdsManager;
impl keyblob::SecureDeletionSecretManager for NoOpSdsManager {
    fn get_or_create_factory_reset_secret(
        &mut self,
        _rng: &mut dyn Rng,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }

    fn get_factory_reset_secret(&self) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }

    fn new_secret(
        &mut self,
        _rng: &mut dyn Rng,
        _purpose: keyblob::SlotPurpose,
    ) -> Result<(keyblob::SecureDeletionSlot, keyblob::SecureDeletionData), Error> {
        unimpl!();
    }

    fn get_secret(
        &self,
        _slot: keyblob::SecureDeletionSlot,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }
    fn delete_secret(&mut self, _slot: keyblob::SecureDeletionSlot) -> Result<(), Error> {
        unimpl!();
    }

    fn delete_all(&mut self) {
        log_unimpl!();
    }
}
