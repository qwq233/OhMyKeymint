// Copyright 2026, The Android Open Source Project
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

//! TA functionality for beginning a crypto operation.

use super::{AuthInfo, CryptoOperation, Operation, CONFIRMATION_DATA_PREFIX};
use kmr_common::{
    contains_tag_value,
    crypto::{aes, des, rsa, KeyMaterial, Rng, SymmetricOperation},
    get_bool_tag_value, get_opt_tag_value, get_tag_value, keyblob, km_err,
    tag::{
        characteristics_at, digest_len, get_algorithm, get_block_mode, get_digest, get_ec_curve,
        get_mgf_digest, get_padding_mode,
    },
    try_to_vec, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{
        Algorithm, BlockMode, Digest, EcCurve, ErrorCode, HardwareAuthToken, KeyParam, KeyPurpose,
        PaddingMode, Tag,
    },
    secureclock::Timestamp,
    InternalBeginResult, KeySizeInBits,
};
use log::{info, warn};
use std::vec::Vec;

impl crate::KeyMintTa {
    pub(crate) fn begin_operation(
        &mut self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: Vec<KeyParam>,
        auth_token: Option<HardwareAuthToken>,
    ) -> Result<InternalBeginResult, Error> {
        let op_idx = self.new_operation_index()?;

        // Parse and decrypt the keyblob, which requires extra hidden params.
        let (keyblob, sdd_slot) = self.keyblob_parse_decrypt(key_blob, &params)?;
        let keyblob::PlaintextKeyBlob {
            characteristics,
            key_material,
        } = keyblob;

        // Validate parameters.
        let key_chars = characteristics_at(&characteristics, self.hw_info.security_level)?;
        check_begin_params(key_chars, purpose, &params)?;
        self.check_begin_auths(key_chars, key_blob)?;

        let trusted_conf_data = if purpose == KeyPurpose::Sign
            && get_bool_tag_value!(key_chars, TrustedConfirmationRequired)?
        {
            // Trusted confirmation is required; accumulate the signed data in an extra buffer,
            // starting with a prefix.
            Some(try_to_vec(CONFIRMATION_DATA_PREFIX)?)
        } else {
            None
        };

        let slot_to_delete = if let Some(&1) = get_opt_tag_value!(key_chars, UsageCountLimit)? {
            warn!("single-use key will be deleted on operation completion");
            sdd_slot
        } else {
            None
        };

        // At most one operation involving proof of user presence can be in-flight at a time.
        let presence_required = get_bool_tag_value!(key_chars, TrustedUserPresenceRequired)?;
        if presence_required && self.presence_required_op.is_some() {
            return Err(km_err!(
                ConcurrentProofOfPresenceRequested,
                "additional op with proof-of-presence requested"
            ));
        }

        let mut op_auth_info = AuthInfo::new(key_chars)?;
        if let Some(auth_info) = &op_auth_info {
            // Authentication checks are required on begin() if there's a timeout that
            // we can check.
            if let Some(timeout_secs) = auth_info.timeout_secs {
                if let Some(clock) = &self.imp.clock {
                    let now: Timestamp = clock.now().into();
                    let auth_token = auth_token.ok_or_else(|| {
                        km_err!(KeyUserNotAuthenticated, "no auth token on begin()")
                    })?;
                    self.check_auth_token(
                        auth_token,
                        auth_info,
                        Some(now),
                        Some(timeout_secs),
                        None,
                    )?;

                    // Auth already checked, nothing needed on subsequent calls
                    op_auth_info = None;
                } else if let Some(auth_token) = auth_token {
                    self.check_auth_token(auth_token, auth_info, None, None, None)?;
                }
            }
        }

        // Re-use the same random value for both:
        // - op_handle: the way to identify which operation is involved
        // - challenge: the value used as part of the input for authentication tokens
        let op_handle = self.new_op_handle();
        let challenge = op_handle.0;
        let mut ret_params = Vec::new();
        let op = match key_material {
            KeyMaterial::Aes(key) => {
                let caller_nonce = get_opt_tag_value!(&params, Nonce)?.map(Vec::as_ref);
                let mode = aes_mode(&params, caller_nonce, &mut *self.imp.rng)?;
                let dir = match purpose {
                    KeyPurpose::Encrypt => SymmetricOperation::Encrypt,
                    KeyPurpose::Decrypt => SymmetricOperation::Decrypt,
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for AES key",
                        ))
                    }
                };
                if caller_nonce.is_none() {
                    // Need to return any randomly-generated nonce to the caller.
                    match &mode {
                        aes::Mode::Cipher(aes::CipherMode::EcbNoPadding)
                        | aes::Mode::Cipher(aes::CipherMode::EcbPkcs7Padding) => {}
                        aes::Mode::Cipher(aes::CipherMode::CbcNoPadding { nonce: n })
                        | aes::Mode::Cipher(aes::CipherMode::CbcPkcs7Padding { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                        aes::Mode::Cipher(aes::CipherMode::Ctr { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                        aes::Mode::Aead(aes::GcmMode::GcmTag12 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag13 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag14 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag15 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag16 { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                    }
                }
                match &mode {
                    aes::Mode::Cipher(mode) => Operation {
                        handle: op_handle,
                        aad_allowed: false,
                        input_size: 0,
                        slot_to_delete,
                        trusted_conf_data,
                        auth_info: op_auth_info,
                        crypto_op: CryptoOperation::Aes(self.imp.aes.begin(key, *mode, dir)?),
                    },
                    aes::Mode::Aead(mode) => Operation {
                        handle: op_handle,
                        aad_allowed: true,
                        input_size: 0,
                        slot_to_delete,
                        trusted_conf_data,
                        auth_info: op_auth_info,
                        crypto_op: CryptoOperation::AesGcm(
                            self.imp.aes.begin_aead(key, *mode, dir)?,
                        ),
                    },
                }
            }
            KeyMaterial::TripleDes(key) => {
                let caller_nonce = get_opt_tag_value!(&params, Nonce)?.map(Vec::as_ref);
                let mode = des_mode(&params, caller_nonce, &mut *self.imp.rng)?;
                let dir = match purpose {
                    KeyPurpose::Encrypt => SymmetricOperation::Encrypt,
                    KeyPurpose::Decrypt => SymmetricOperation::Decrypt,
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for DES key",
                        ))
                    }
                };
                if caller_nonce.is_none() {
                    // Need to return any randomly-generated nonce to the caller.
                    match &mode {
                        des::Mode::EcbNoPadding | des::Mode::EcbPkcs7Padding => {}
                        des::Mode::CbcNoPadding { nonce: n }
                        | des::Mode::CbcPkcs7Padding { nonce: n } => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                    }
                }
                Operation {
                    handle: op_handle,
                    aad_allowed: false,
                    input_size: 0,
                    slot_to_delete,
                    trusted_conf_data,
                    auth_info: op_auth_info,
                    crypto_op: CryptoOperation::Des(self.imp.des.begin(key, mode, dir)?),
                }
            }
            KeyMaterial::Hmac(key) => {
                let digest = get_digest(&params)?;

                Operation {
                    handle: op_handle,
                    aad_allowed: false,
                    input_size: 0,
                    slot_to_delete,
                    trusted_conf_data,
                    auth_info: op_auth_info,
                    crypto_op: match purpose {
                        KeyPurpose::Sign => {
                            let tag_len =
                                get_tag_value!(&params, MacLength, ErrorCode::MissingMacLength)?
                                    as usize
                                    / 8;
                            CryptoOperation::HmacSign(self.imp.hmac.begin(key, digest)?, tag_len)
                        }
                        KeyPurpose::Verify => {
                            // Remember the acceptable tag lengths.
                            let min_tag_len = get_tag_value!(
                                key_chars,
                                MinMacLength,
                                ErrorCode::MissingMinMacLength
                            )? as usize
                                / 8;
                            let max_tag_len = digest_len(digest)? as usize;
                            CryptoOperation::HmacVerify(
                                self.imp.hmac.begin(key, digest)?,
                                min_tag_len..max_tag_len,
                            )
                        }
                        _ => {
                            return Err(km_err!(
                                IncompatiblePurpose,
                                "invalid purpose {purpose:?} for HMAC key",
                            ))
                        }
                    },
                }
            }
            KeyMaterial::Rsa(key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::Decrypt => {
                        let mode = rsa_decryption_mode(&params)?;
                        CryptoOperation::RsaDecrypt(self.imp.rsa.begin_decrypt(key, mode)?)
                    }
                    KeyPurpose::Sign => {
                        let mode = rsa_sign_mode(&params)?;
                        CryptoOperation::RsaSign(self.imp.rsa.begin_sign(key, mode)?)
                    }
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for RSA key",
                        ))
                    }
                },
            },
            KeyMaterial::Ec(_, _, key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::AgreeKey => CryptoOperation::EcAgree(self.imp.ec.begin_agree(key)?),
                    KeyPurpose::Sign => {
                        let digest = get_digest(&params)?;
                        CryptoOperation::EcSign(self.imp.ec.begin_sign(key, digest)?)
                    }
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for EC key",
                        ))
                    }
                },
            },
            KeyMaterial::MlDsa(_variant, key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::Sign => CryptoOperation::MlDsaSign(self.imp.mldsa.begin_sign(key)?),
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for ML-DSA key",
                        ))
                    }
                },
            },
        };
        self.operations[op_idx] = Some(op);
        if presence_required {
            info!("this operation requires proof-of-presence");
            self.presence_required_op = Some(op_handle);
        }
        Ok(InternalBeginResult {
            challenge,
            params: ret_params,
            op_handle: op_handle.0,
        })
    }

    /// Check TA-specific key authorizations on `begin()`.
    fn check_begin_auths(&mut self, key_chars: &[KeyParam], key_blob: &[u8]) -> Result<(), Error> {
        if self.dev.bootloader.done() && get_bool_tag_value!(key_chars, BootloaderOnly)? {
            return Err(km_err!(
                InvalidKeyBlob,
                "attempt to use bootloader-only key after bootloader done"
            ));
        }
        if !self.in_early_boot && get_bool_tag_value!(key_chars, EarlyBootOnly)? {
            return Err(km_err!(
                EarlyBootEnded,
                "attempt to use EARLY_BOOT key after early boot"
            ));
        }

        if let Some(max_uses) = get_opt_tag_value!(key_chars, MaxUsesPerBoot)? {
            // Track the use count for this key.
            let key_id = self.key_id(key_blob)?;
            self.update_use_count(key_id, *max_uses)?;
        }
        Ok(())
    }
}

/// Return an error if any of the `exclude` tags are found in `params`.
fn reject_tags(params: &[KeyParam], exclude: &[Tag]) -> Result<(), Error> {
    for param in params {
        if exclude.contains(&param.tag()) {
            return Err(km_err!(InvalidTag, "tag {:?} not allowed", param.tag()));
        }
    }
    Ok(())
}

/// Return an error if non-None padding found.
fn reject_some_padding(params: &[KeyParam]) -> Result<(), Error> {
    if let Some(padding) = get_opt_tag_value!(params, Padding)? {
        if *padding != PaddingMode::None {
            return Err(km_err!(InvalidTag, "padding {:?} not allowed", padding));
        }
    }
    Ok(())
}

/// Return an error if non-None digest found.
fn reject_some_digest(params: &[KeyParam]) -> Result<(), Error> {
    if let Some(digest) = get_opt_tag_value!(params, Digest)? {
        if *digest != Digest::None {
            return Err(km_err!(InvalidTag, "digest {:?} not allowed", digest));
        }
    }
    Ok(())
}

/// Indication of which parameters on a `begin` need to be checked against key authorizations.
struct BeginParamsToCheck {
    block_mode: bool,
    padding: bool,
    digest: bool,
    mgf_digest: bool,
}

/// Check that an operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    // General checks for all algorithms.
    let algo = get_algorithm(chars)?;
    let valid_purpose = matches!(
        (algo, purpose),
        (Algorithm::Aes, KeyPurpose::Encrypt)
            | (Algorithm::Aes, KeyPurpose::Decrypt)
            | (Algorithm::TripleDes, KeyPurpose::Encrypt)
            | (Algorithm::TripleDes, KeyPurpose::Decrypt)
            | (Algorithm::Hmac, KeyPurpose::Sign)
            | (Algorithm::Hmac, KeyPurpose::Verify)
            | (Algorithm::Ec, KeyPurpose::Sign)
            | (Algorithm::Ec, KeyPurpose::AttestKey)
            | (Algorithm::Ec, KeyPurpose::AgreeKey)
            | (Algorithm::Rsa, KeyPurpose::Sign)
            | (Algorithm::Rsa, KeyPurpose::Decrypt)
            | (Algorithm::Rsa, KeyPurpose::AttestKey)
            | (Algorithm::MlDsa, KeyPurpose::Sign)
            | (Algorithm::MlDsa, KeyPurpose::AttestKey)
    );
    if !valid_purpose {
        return Err(km_err!(
            UnsupportedPurpose,
            "invalid purpose {:?} for {:?} key",
            purpose,
            algo
        ));
    }
    if !contains_tag_value!(chars, Purpose, purpose) {
        return Err(km_err!(
            IncompatiblePurpose,
            "purpose {:?} not in key characteristics",
            purpose
        ));
    }
    if get_bool_tag_value!(chars, StorageKey)? {
        return Err(km_err!(StorageKeyUnsupported, "attempt to use storage key",));
    }
    let nonce = get_opt_tag_value!(params, Nonce)?;
    if get_bool_tag_value!(chars, CallerNonce)? {
        // Caller-provided nonces are allowed.
    } else if nonce.is_some() && purpose == KeyPurpose::Encrypt {
        return Err(km_err!(
            CallerNonceProhibited,
            "caller nonce not allowed for encryption"
        ));
    }

    // Further algorithm-specific checks.
    let check = match algo {
        Algorithm::Rsa => check_begin_rsa_params(chars, purpose, params),
        Algorithm::Ec => check_begin_ec_params(chars, purpose, params),
        Algorithm::MlDsa => check_begin_mldsa_params(purpose, params),
        Algorithm::Aes => check_begin_aes_params(chars, params, nonce.map(|v| v.as_ref())),
        Algorithm::TripleDes => check_begin_3des_params(params, nonce.map(|v| v.as_ref())),
        Algorithm::Hmac => check_begin_hmac_params(chars, purpose, params),
    }?;

    // For various parameters, if they are specified in the begin parameters and they
    // are relevant for the algorithm, then the same value must also exist in the key
    // characteristics. Also, there can be only one distinct value in the parameters.
    if check.block_mode {
        if let Some(bmode) = get_opt_tag_value!(params, BlockMode, UnsupportedBlockMode)? {
            if !contains_tag_value!(chars, BlockMode, *bmode) {
                return Err(km_err!(
                    IncompatibleBlockMode,
                    "block mode {:?} not in key characteristics {:?}",
                    bmode,
                    chars,
                ));
            }
        }
    }
    if check.padding {
        if let Some(pmode) = get_opt_tag_value!(params, Padding, UnsupportedPaddingMode)? {
            if !contains_tag_value!(chars, Padding, *pmode) {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding mode {:?} not in key characteristics {:?}",
                    pmode,
                    chars,
                ));
            }
        }
    }
    if check.digest {
        if let Some(digest) = get_opt_tag_value!(params, Digest, UnsupportedDigest)? {
            if !contains_tag_value!(chars, Digest, *digest) {
                return Err(km_err!(
                    IncompatibleDigest,
                    "digest {:?} not in key characteristics",
                    digest,
                ));
            }
        }
    }
    if check.mgf_digest {
        let mut mgf_digest_to_find =
            get_opt_tag_value!(params, RsaOaepMgfDigest, UnsupportedMgfDigest)?;

        let chars_have_mgf_digest = chars
            .iter()
            .any(|param| matches!(param, KeyParam::RsaOaepMgfDigest(_)));
        if chars_have_mgf_digest && mgf_digest_to_find.is_none() {
            // The key characteristics include an explicit set of MGF digests, but the begin()
            // operation is using the default SHA1.  Check that this default is in the
            // characteristics.
            mgf_digest_to_find = Some(&Digest::Sha1);
        }

        if let Some(mgf_digest) = mgf_digest_to_find {
            if !contains_tag_value!(chars, RsaOaepMgfDigest, *mgf_digest) {
                return Err(km_err!(
                    IncompatibleMgfDigest,
                    "MGF digest {:?} not in key characteristics",
                    mgf_digest,
                ));
            }
        }
    }
    Ok(())
}

/// Indicate whether a [`KeyPurpose`] is for encryption/decryption.
fn for_encryption(purpose: KeyPurpose) -> bool {
    purpose == KeyPurpose::Encrypt
        || purpose == KeyPurpose::Decrypt
        || purpose == KeyPurpose::WrapKey
}

/// Indicate whether a [`KeyPurpose`] is for signing.
fn for_signing(purpose: KeyPurpose) -> bool {
    purpose == KeyPurpose::Sign
}

/// Check that an RSA operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_rsa_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    let padding = get_padding_mode(params)?;
    let mut digest = None;
    if for_signing(purpose) || (for_encryption(purpose) && padding == PaddingMode::RsaOaep) {
        digest = Some(get_digest(params)?);
    }
    if for_signing(purpose) && padding == PaddingMode::None && digest != Some(Digest::None) {
        return Err(km_err!(
            IncompatibleDigest,
            "unpadded RSA sign requires Digest::None not {:?}",
            digest
        ));
    }
    match padding {
        PaddingMode::None => {}
        PaddingMode::RsaOaep if for_encryption(purpose) => {
            if digest.is_none() || digest == Some(Digest::None) {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-OAEP"));
            }
            let mgf_digest = get_mgf_digest(params)?;
            if mgf_digest == Digest::None {
                return Err(km_err!(
                    UnsupportedMgfDigest,
                    "MGF digest cannot be NONE for RSA-OAEP"
                ));
            }
        }
        PaddingMode::RsaPss if for_signing(purpose) => {
            if let Some(digest) = digest {
                let key_size_bits = get_tag_value!(chars, KeySize, ErrorCode::InvalidArgument)?;
                let d = digest_len(digest)?;
                if key_size_bits < KeySizeInBits(2 * d + 9) {
                    return Err(km_err!(
                        IncompatibleDigest,
                        "key size {:?} < 2*8*D={} + 9",
                        key_size_bits,
                        d
                    ));
                }
            } else {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-PSS"));
            }
        }
        PaddingMode::RsaPkcs115Encrypt if for_encryption(purpose) => {
            if digest.is_some() && digest != Some(Digest::None) {
                warn!("ignoring digest {digest:?} provided for PKCS#1 v1.5 encryption/decryption");
            }
        }
        PaddingMode::RsaPkcs115Sign if for_signing(purpose) => {
            if digest.is_none() {
                return Err(km_err!(
                    IncompatibleDigest,
                    "digest required for RSA-PKCS_1_5_SIGN"
                ));
            }
        }
        _ => {
            return Err(km_err!(
                UnsupportedPaddingMode,
                "purpose {:?} incompatible with padding {:?}",
                purpose,
                padding
            ))
        }
    }

    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: true,
        digest: true,
        mgf_digest: true,
    })
}

/// Determine the [`rsa::DecryptionMode`] from parameters.
fn rsa_decryption_mode(params: &[KeyParam]) -> Result<rsa::DecryptionMode, Error> {
    let padding = get_padding_mode(params)?;
    match padding {
        PaddingMode::None => Ok(rsa::DecryptionMode::NoPadding),
        PaddingMode::RsaOaep => {
            let msg_digest = get_digest(params)?;
            let mgf_digest = get_mgf_digest(params)?;
            Ok(rsa::DecryptionMode::OaepPadding {
                msg_digest,
                mgf_digest,
            })
        }
        PaddingMode::RsaPkcs115Encrypt => Ok(rsa::DecryptionMode::Pkcs1_1_5Padding),
        _ => Err(km_err!(
            UnsupportedPaddingMode,
            "padding mode {:?} not supported for RSA decryption",
            padding
        )),
    }
}

/// Determine the [`rsa::SignMode`] from parameters.
fn rsa_sign_mode(params: &[KeyParam]) -> Result<rsa::SignMode, Error> {
    let padding = get_padding_mode(params)?;
    match padding {
        PaddingMode::None => Ok(rsa::SignMode::NoPadding),
        PaddingMode::RsaPss => {
            let digest = get_digest(params)?;
            Ok(rsa::SignMode::PssPadding(digest))
        }
        PaddingMode::RsaPkcs115Sign => {
            let digest = get_digest(params)?;
            Ok(rsa::SignMode::Pkcs1_1_5Padding(digest))
        }
        _ => Err(km_err!(
            UnsupportedPaddingMode,
            "padding mode {:?} not supported for RSA signing",
            padding
        )),
    }
}

/// Check that an EC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_ec_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    let curve = get_ec_curve(chars)?;
    if purpose == KeyPurpose::Sign {
        let digest = get_digest(params)?;
        if digest == Digest::Md5 {
            return Err(km_err!(
                UnsupportedDigest,
                "Digest::MD5 unsupported for EC signing"
            ));
        }
        if curve == EcCurve::Curve25519 && digest != Digest::None {
            return Err(km_err!(
                UnsupportedDigest,
                "Ed25519 only supports Digest::None not {:?}",
                digest
            ));
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: false,
        digest: true,
        mgf_digest: false,
    })
}

/// Check that an ML-DSA operation with the given `purpose` and `params` can validly be started.
fn check_begin_mldsa_params(
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    if purpose == KeyPurpose::Sign {
        let digest = get_digest(params)?;
        if digest != Digest::None {
            return Err(km_err!(
                UnsupportedDigest,
                "{digest:?} unsupported for ML-DSA signing"
            ));
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: false,
        digest: true,
        mgf_digest: false,
    })
}

/// Check that an AES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_aes_params(
    chars: &[KeyParam],
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::RsaOaepMgfDigest])?;
    reject_some_digest(params)?;
    let bmode = get_block_mode(params)?;
    let padding = get_padding_mode(params)?;

    if bmode == BlockMode::Gcm {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > 128 {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }
    match bmode {
        BlockMode::Gcm | BlockMode::Ctr => match padding {
            PaddingMode::None => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
        BlockMode::Ecb | BlockMode::Cbc => match padding {
            PaddingMode::None | PaddingMode::Pkcs7 => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
    }

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 16 => {}
            BlockMode::Ctr if nonce.len() == 16 => {}
            BlockMode::Gcm if nonce.len() == 12 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: true,
        padding: true,
        digest: false,
        mgf_digest: false,
    })
}

/// Determine the [`aes::Mode`], rejecting invalid parameters. Use `caller_nonce` if provided,
/// otherwise generate a new nonce using the provided [`Rng`] instance.
fn aes_mode(
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
    rng: &mut dyn Rng,
) -> Result<aes::Mode, Error> {
    let mode = get_block_mode(params)?;
    let padding = get_padding_mode(params)?;
    match mode {
        BlockMode::Ecb => {
            if caller_nonce.is_some() {
                return Err(km_err!(
                    InvalidNonce,
                    "nonce unexpectedly provided for AES-ECB"
                ));
            }
            match padding {
                PaddingMode::None => Ok(aes::Mode::Cipher(aes::CipherMode::EcbNoPadding)),
                PaddingMode::Pkcs7 => Ok(aes::Mode::Cipher(aes::CipherMode::EcbPkcs7Padding)),
                _ => Err(km_err!(
                    IncompatiblePaddingMode,
                    "expected NONE/PKCS7 padding for AES-ECB"
                )),
            }
        }
        BlockMode::Cbc => {
            let nonce: [u8; aes::BLOCK_SIZE] = nonce(caller_nonce, rng)?;
            match padding {
                PaddingMode::None => Ok(aes::Mode::Cipher(aes::CipherMode::CbcNoPadding { nonce })),
                PaddingMode::Pkcs7 => Ok(aes::Mode::Cipher(aes::CipherMode::CbcPkcs7Padding {
                    nonce,
                })),
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
            let nonce: [u8; aes::BLOCK_SIZE] = nonce(caller_nonce, rng)?;
            Ok(aes::Mode::Cipher(aes::CipherMode::Ctr { nonce }))
        }
        BlockMode::Gcm => {
            if padding != PaddingMode::None {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "expected NONE padding for AES-GCM"
                ));
            }
            let nonce: [u8; aes::GCM_NONCE_SIZE] = nonce(caller_nonce, rng)?;
            let tag_len = get_tag_value!(params, MacLength, ErrorCode::InvalidMacLength)?;
            if tag_len % 8 != 0 {
                return Err(km_err!(
                    InvalidMacLength,
                    "tag length {} not a multiple of 8",
                    tag_len
                ));
            }
            match tag_len / 8 {
                12 => Ok(aes::Mode::Aead(aes::GcmMode::GcmTag12 { nonce })),
                13 => Ok(aes::Mode::Aead(aes::GcmMode::GcmTag13 { nonce })),
                14 => Ok(aes::Mode::Aead(aes::GcmMode::GcmTag14 { nonce })),
                15 => Ok(aes::Mode::Aead(aes::GcmMode::GcmTag15 { nonce })),
                16 => Ok(aes::Mode::Aead(aes::GcmMode::GcmTag16 { nonce })),
                v => Err(km_err!(
                    InvalidMacLength,
                    "want 12-16 byte tag for AES-GCM not {} bytes",
                    v
                )),
            }
        }
    }
}

/// Check that a 3-DES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_3des_params(
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::RsaOaepMgfDigest])?;
    reject_some_digest(params)?;
    let bmode = get_block_mode(params)?;
    let _padding = get_padding_mode(params)?;

    match bmode {
        BlockMode::Cbc | BlockMode::Ecb => {}
        _ => {
            return Err(km_err!(
                UnsupportedBlockMode,
                "block mode {:?} not valid for 3-DES",
                bmode
            ))
        }
    }

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 8 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(BeginParamsToCheck {
        block_mode: true,
        padding: true,
        digest: false,
        mgf_digest: false,
    })
}

/// Determine the [`des::Mode`], rejecting invalid parameters. Use `caller_nonce` if provided,
/// otherwise generate a new nonce using the provided [`Rng`] instance.
fn des_mode(
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
    rng: &mut dyn Rng,
) -> Result<des::Mode, Error> {
    let mode = get_block_mode(params)?;
    let padding = get_padding_mode(params)?;
    match mode {
        BlockMode::Ecb => {
            if caller_nonce.is_some() {
                return Err(km_err!(InvalidNonce, "nonce unexpectedly provided"));
            }
            match padding {
                PaddingMode::None => Ok(des::Mode::EcbNoPadding),
                PaddingMode::Pkcs7 => Ok(des::Mode::EcbPkcs7Padding),
                _ => Err(km_err!(
                    IncompatiblePaddingMode,
                    "expected NONE/PKCS7 padding for DES-ECB"
                )),
            }
        }
        BlockMode::Cbc => {
            let nonce: [u8; des::BLOCK_SIZE] = nonce(caller_nonce, rng)?;
            match padding {
                PaddingMode::None => Ok(des::Mode::CbcNoPadding { nonce }),
                PaddingMode::Pkcs7 => Ok(des::Mode::CbcPkcs7Padding { nonce }),
                _ => Err(km_err!(
                    IncompatiblePaddingMode,
                    "expected NONE/PKCS7 padding for DES-CBC"
                )),
            }
        }
        _ => Err(km_err!(UnsupportedBlockMode, "want ECB/CBC")),
    }
}

/// Check that an HMAC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_hmac_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<BeginParamsToCheck, Error> {
    reject_tags(params, &[Tag::BlockMode, Tag::RsaOaepMgfDigest])?;
    reject_some_padding(params)?;
    let digest = get_digest(params)?;
    if purpose == KeyPurpose::Sign {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > digest_len(digest)? {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }

    Ok(BeginParamsToCheck {
        block_mode: false,
        padding: false,
        digest: true,
        mgf_digest: false,
    })
}

/// Extract or generate a nonce of the given size.
fn nonce<const N: usize>(caller_nonce: Option<&[u8]>, rng: &mut dyn Rng) -> Result<[u8; N], Error> {
    Ok(match caller_nonce {
        Some(n) => n
            .try_into()
            .map_err(|_| km_err!(InvalidNonce, "want {N} byte nonce"))?,
        None => {
            let mut arr = [0u8; N];
            rng.fill_bytes(&mut arr);
            arr
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_common::expect_err;
    use kmr_wire::{keymint::KeyParam, KeySizeInBits};
    use std::vec;

    #[test]
    fn test_check_begin_params_fail() {
        let chars = vec![
            KeyParam::NoAuthRequired,
            KeyParam::Algorithm(Algorithm::Hmac),
            KeyParam::KeySize(KeySizeInBits(128)),
            KeyParam::Digest(Digest::Sha256),
            KeyParam::Purpose(KeyPurpose::Sign),
            KeyParam::Purpose(KeyPurpose::Verify),
            KeyParam::MinMacLength(160),
        ];

        let tests = vec![
            (
                KeyPurpose::Encrypt,
                vec![KeyParam::Digest(Digest::Sha256), KeyParam::MacLength(160)],
                "invalid purpose Encrypt",
            ),
            (
                KeyPurpose::Sign,
                vec![KeyParam::Digest(Digest::Sha256)],
                "MissingMacLength",
            ),
            (
                KeyPurpose::Sign,
                vec![KeyParam::Digest(Digest::Sha512), KeyParam::MacLength(160)],
                "not in key characteristics",
            ),
        ];
        for (purpose, params, msg) in tests {
            expect_err!(check_begin_params(&chars, purpose, &params), msg);
        }
    }
}
