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

//! TA functionality related to key generation/import/upgrade.

use crate::{cert, device, AttestationChainInfo};
use core::{borrow::Borrow, cmp::Ordering, convert::TryFrom};
use der::{referenced::RefToOwned, Decode, Sequence};
use kmr_common::{
    crypto::{self, aes, rsa, KeyMaterial, OpaqueOr},
    der_err, get_bool_tag_value, get_opt_tag_value, get_tag_value, keyblob, km_err, tag,
    try_to_vec, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{
        AttestationKey, Digest, EcCurve, ErrorCode, HardwareAuthenticatorType, KeyCharacteristics,
        KeyCreationResult, KeyFormat, KeyOrigin, KeyParam, KeyPurpose, SecurityLevel,
        UNDEFINED_NOT_AFTER, UNDEFINED_NOT_BEFORE,
    },
    *,
};
use log::{error, warn};
use spki::SubjectPublicKeyInfoOwned;
use std::collections::btree_map::Entry;
use x509_cert::ext::pkix::KeyUsages;
use Vec;

/// Maximum size of an attestation challenge value.
const MAX_ATTESTATION_CHALLENGE_LEN: usize = 128;

/// Contents of wrapping key data
///
/// ```asn1
/// SecureKeyWrapper ::= SEQUENCE {
///     version                   INTEGER, # Value 0
///     encryptedTransportKey     OCTET_STRING,
///     initializationVector      OCTET_STRING,
///     keyDescription            KeyDescription, # See below
///     encryptedKey              OCTET_STRING,
///     tag                       OCTET_STRING,
/// }
/// ```
#[derive(Debug, Clone, Sequence)]
pub struct SecureKeyWrapper<'a> {
    /// Version of this structure.
    pub version: i32,
    /// Encrypted transport key.
    #[asn1(type = "OCTET STRING")]
    pub encrypted_transport_key: &'a [u8],
    /// IV to use for decryption.
    #[asn1(type = "OCTET STRING")]
    pub initialization_vector: &'a [u8],
    /// Key parameters and description.
    pub key_description: KeyDescription<'a>,
    /// Ciphertext of the imported key.
    #[asn1(type = "OCTET STRING")]
    pub encrypted_key: &'a [u8],
    /// Tag value.
    #[asn1(type = "OCTET STRING")]
    pub tag: &'a [u8],
}

const SECURE_KEY_WRAPPER_VERSION: i32 = 0;

/// Contents of key description.
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     keyFormat    INTEGER, # Values from KeyFormat enum
///     keyParams    AuthorizationList, # See cert.rs
/// }
/// ```
#[derive(Debug, Clone, Sequence)]
pub struct KeyDescription<'a> {
    /// Format of imported key.
    pub key_format: i32,
    /// Key parameters.
    pub key_params: cert::AuthorizationList<'a>,
}

/// Indication of whether key import has a secure wrapper.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyImport {
    Wrapped,
    NonWrapped,
}

/// Combined information needed for signing a fresh public key.
#[derive(Clone)]
pub(crate) struct SigningInfo<'a> {
    pub attestation_info: Option<(&'a [u8], &'a [u8])>, // (challenge, app_id)
    pub signing_key: KeyMaterial,
    /// ASN.1 DER encoding of subject field from first cert.
    pub issuer_subject: Vec<u8>,
    /// Cert chain starting with public key for `signing_key`.
    pub chain: Vec<keymint::Certificate>,
}

impl crate::KeyMintTa {
    /// Retrieve the signing information.
    pub(crate) fn get_signing_info(
        &self,
        key_type: device::SigningKeyType,
    ) -> Result<SigningInfo<'_>, Error> {
        let sign_info = self.dev.sign_info.as_ref().ok_or_else(|| {
            km_err!(
                AttestationKeysNotProvisioned,
                "batch attestation keys not available"
            )
        })?;
        // Retrieve the chain and issuer information, which is cached after first retrieval.
        let mut attestation_chain_info = self.attestation_chain_info.borrow_mut();
        let chain_info = match attestation_chain_info.entry(key_type) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                // Retrieve and store the cert chain information (as this is public).
                let chain = sign_info.cert_chain(key_type)?;
                let issuer =
                    cert::extract_subject(chain.first().ok_or_else(|| {
                        km_err!(KeymintNotConfigured, "empty attestation chain")
                    })?)?;
                e.insert(AttestationChainInfo { chain, issuer })
            }
        };

        // Retrieve the signing key information (which will be dropped when signing is done).
        let signing_key = sign_info.signing_key(key_type)?;

        log::info!(
            "using attestation key with subject {:?}",
            String::from_utf8_lossy(&chain_info.issuer)
        );

        Ok(SigningInfo {
            attestation_info: None,
            signing_key,
            issuer_subject: chain_info.issuer.clone(),
            chain: chain_info.chain.clone(),
        })
    }

    /// Generate an X.509 leaf certificate.
    pub(crate) fn generate_cert(
        &self,
        info: Option<SigningInfo>,
        spki: SubjectPublicKeyInfoOwned,
        params: &[KeyParam],
        chars: &[KeyCharacteristics],
    ) -> Result<keymint::Certificate, Error> {
        // Build and encode key usage extension value
        let key_usage_ext_bits = cert::key_usage_extension_bits(params);
        let key_usage_ext_val = cert::asn1_der_encode(&key_usage_ext_bits)
            .map_err(|e| der_err!(e, "failed to encode KeyUsage {:?}", key_usage_ext_bits))?;

        // Build and encode basic constraints extension value, based on the key usage extension
        // value
        let basic_constraints_ext_val = if (key_usage_ext_bits.0 & KeyUsages::KeyCertSign)
            .bits()
            .count_ones()
            != 0
        {
            let basic_constraints = cert::basic_constraints_ext_value(true);
            Some(cert::asn1_der_encode(&basic_constraints).map_err(|e| {
                der_err!(
                    e,
                    "failed to encode basic constraints {:?}",
                    basic_constraints
                )
            })?)
        } else {
            None
        };

        // Build and encode attestation extension if present
        let id_info = self.get_attestation_ids();
        let attest_ext_val = if let Some(SigningInfo {
            attestation_info: Some((challenge, app_id)),
            ..
        }) = &info
        {
            let unique_id = self.calculate_unique_id(app_id, params)?;
            let boot_info = self.boot_info_hashed_key()?;
            let attest_ext = cert::attestation_extension(
                self.aidl_version as i32,
                challenge,
                app_id,
                self.hw_info.security_level,
                id_info.as_ref().map(|v| v.borrow()),
                params,
                chars,
                &unique_id,
                &boot_info,
                &self.additional_attestation_info,
            )?;
            Some(
                cert::asn1_der_encode(&attest_ext)
                    .map_err(|e| der_err!(e, "failed to encode attestation extension"))?,
            )
        } else {
            None
        };

        let tbs_cert = cert::tbs_certificate(
            &info,
            spki,
            &key_usage_ext_val,
            basic_constraints_ext_val.as_deref(),
            attest_ext_val.as_deref(),
            tag::characteristics_at(chars, self.hw_info.security_level)?,
            params,
        )?;
        let tbs_data = cert::asn1_der_encode(&tbs_cert)
            .map_err(|e| der_err!(e, "failed to encode tbsCert"))?;
        // If key does not have ATTEST_KEY or SIGN purpose, the certificate has empty signature
        let sig_data = match info.as_ref() {
            Some(info) => self.sign_cert_data(info.signing_key.clone(), tbs_data.as_slice())?,
            None => Vec::new(),
        };

        let cert = cert::certificate(tbs_cert, &sig_data)?;
        let cert_data = cert::asn1_der_encode(&cert)
            .map_err(|e| der_err!(e, "failed to encode certificate"))?;
        Ok(keymint::Certificate {
            encoded_certificate: cert_data,
        })
    }

    /// Perform a complete signing operation using default modes.
    fn sign_cert_data(&self, signing_key: KeyMaterial, tbs_data: &[u8]) -> Result<Vec<u8>, Error> {
        match signing_key {
            KeyMaterial::Rsa(key) => {
                let mut op = self
                    .imp
                    .rsa
                    .begin_sign(key, rsa::SignMode::Pkcs1_1_5Padding(Digest::Sha256))?;
                op.update(tbs_data)?;
                op.finish()
            }
            KeyMaterial::Ec(curve, _, key) => {
                let digest = if curve == EcCurve::Curve25519 {
                    // Ed25519 includes an internal digest and so does not use an external digest.
                    Digest::None
                } else {
                    Digest::Sha256
                };
                let mut op = self.imp.ec.begin_sign(key, digest)?;
                op.update(tbs_data)?;
                op.finish()
            }
            _ => Err(km_err!(
                IncompatibleAlgorithm,
                "unexpected cert signing key type"
            )),
        }
    }

    /// Calculate the `UNIQUE_ID` value for the parameters, if needed.
    fn calculate_unique_id(&self, app_id: &[u8], params: &[KeyParam]) -> Result<Vec<u8>, Error> {
        if !get_bool_tag_value!(params, IncludeUniqueId)? {
            return Ok(Vec::new());
        }
        let creation_datetime =
            get_tag_value!(params, CreationDatetime, ErrorCode::InvalidArgument)?;
        let rounded_datetime = creation_datetime.ms_since_epoch / 2_592_000_000i64;
        let datetime_data = rounded_datetime.to_ne_bytes();

        let mut combined_input = vec_try_with_capacity!(datetime_data.len() + app_id.len() + 1)?;
        combined_input.extend_from_slice(&datetime_data[..]);
        combined_input.extend_from_slice(app_id);
        combined_input.push(u8::from(get_bool_tag_value!(params, ResetSinceIdRotation)?));

        let hbk = self.dev.keys.unique_id_hbk(&*self.imp.ckdf)?;

        let mut hmac_op = self.imp.hmac.begin(hbk.into(), Digest::Sha256)?;
        hmac_op.update(&combined_input)?;
        let tag = hmac_op.finish()?;
        try_to_vec(&tag[..16])
    }

    pub(crate) fn generate_key(
        &mut self,
        params: &[KeyParam],
        attestation_key: Option<AttestationKey>,
    ) -> Result<KeyCreationResult, Error> {
        let (key_material, chars) = self.generate_key_material(params)?;
        self.finish_keyblob_creation(
            params,
            attestation_key,
            chars,
            key_material,
            keyblob::SlotPurpose::KeyGeneration,
        )
    }

    pub(crate) fn generate_key_material(
        &mut self,
        params: &[KeyParam],
    ) -> Result<(KeyMaterial, Vec<KeyCharacteristics>), Error> {
        let (mut chars, keygen_info) = tag::extract_key_gen_characteristics(
            self.secure_storage_available(),
            params,
            self.hw_info.security_level,
        )?;
        self.add_keymint_tags(&mut chars, KeyOrigin::Generated)?;
        let key_material = match keygen_info {
            crypto::KeyGenInfo::Aes(variant) => {
                self.imp
                    .aes
                    .generate_key(&mut *self.imp.rng, variant, params)?
            }
            crypto::KeyGenInfo::TripleDes => {
                self.imp.des.generate_key(&mut *self.imp.rng, params)?
            }
            crypto::KeyGenInfo::Hmac(key_size) => {
                self.imp
                    .hmac
                    .generate_key(&mut *self.imp.rng, key_size, params)?
            }
            crypto::KeyGenInfo::Rsa(key_size, pub_exponent) => {
                self.imp
                    .rsa
                    .generate_key(&mut *self.imp.rng, key_size, pub_exponent, params)?
            }
            crypto::KeyGenInfo::NistEc(curve) => {
                self.imp
                    .ec
                    .generate_nist_key(&mut *self.imp.rng, curve, params)?
            }
            crypto::KeyGenInfo::Ed25519 => self
                .imp
                .ec
                .generate_ed25519_key(&mut *self.imp.rng, params)?,
            crypto::KeyGenInfo::X25519 => self
                .imp
                .ec
                .generate_x25519_key(&mut *self.imp.rng, params)?,
        };
        Ok((key_material, chars))
    }

    pub(crate) fn import_key(
        &mut self,
        params: &[KeyParam],
        key_format: KeyFormat,
        key_data: &[u8],
        attestation_key: Option<AttestationKey>,
        import_type: KeyImport,
    ) -> Result<KeyCreationResult, Error> {
        if !self.in_early_boot && get_bool_tag_value!(params, EarlyBootOnly)? {
            return Err(km_err!(
                EarlyBootEnded,
                "attempt to use EARLY_BOOT key after early boot"
            ));
        }

        let (mut chars, key_material) = tag::extract_key_import_characteristics(
            &self.imp,
            self.secure_storage_available(),
            params,
            self.hw_info.security_level,
            key_format,
            key_data,
        )?;
        match import_type {
            KeyImport::NonWrapped => {
                self.add_keymint_tags(&mut chars, KeyOrigin::Imported)?;
            }
            KeyImport::Wrapped => {
                self.add_keymint_tags(&mut chars, KeyOrigin::SecurelyImported)?;
            }
        }

        self.finish_keyblob_creation(
            params,
            attestation_key,
            chars,
            key_material,
            keyblob::SlotPurpose::KeyImport,
        )
    }

    /// Perform common processing for keyblob creation (for both generation and import).
    pub fn finish_keyblob_creation(
        &mut self,
        params: &[KeyParam],
        attestation_key: Option<AttestationKey>,
        chars: Vec<KeyCharacteristics>,
        key_material: KeyMaterial,
        purpose: keyblob::SlotPurpose,
    ) -> Result<KeyCreationResult, Error> {
        let keyblob = keyblob::PlaintextKeyBlob {
            // Don't include any `SecurityLevel::Keystore` characteristics in the set that is bound
            // to the key.
            characteristics: chars
                .iter()
                .filter(|c| c.security_level != SecurityLevel::Keystore)
                .cloned()
                .collect(),
            key_material: key_material.clone(),
        };
        let attest_keyblob;
        let mut certificate_chain = Vec::new();
        if let Some(spki) = keyblob.key_material.subject_public_key_info(
            &mut Vec::<u8>::new(),
            &*self.imp.ec,
            &*self.imp.rsa,
        )? {
            // Asymmetric keys return the public key inside an X.509 certificate.
            // Need to determine:
            // - a key to sign the cert with (may be absent), together with any associated
            //   cert chain to append
            // - whether to include an attestation extension
            let attest_challenge = get_opt_tag_value!(params, AttestationChallenge)?;

            let signing_info = if let Some(attest_challenge) = attest_challenge {
                // Attestation requested.
                if attest_challenge.len() > MAX_ATTESTATION_CHALLENGE_LEN {
                    return Err(km_err!(
                        InvalidInputLength,
                        "attestation challenge too large: {} bytes",
                        attest_challenge.len()
                    ));
                }
                let attest_app_id = get_opt_tag_value!(params, AttestationApplicationId)?
                    .ok_or_else(|| {
                        km_err!(AttestationApplicationIdMissing, "attestation requested")
                    })?;
                let attestation_info: Option<(&[u8], &[u8])> =
                    Some((attest_challenge, attest_app_id));

                if let Some(attest_keyinfo) = attestation_key.as_ref() {
                    // User-specified attestation key provided.
                    (attest_keyblob, _) = self.keyblob_parse_decrypt(
                        &attest_keyinfo.key_blob,
                        &attest_keyinfo.attest_key_params,
                    )?;
                    attest_keyblob
                        .suitable_for(KeyPurpose::AttestKey, self.hw_info.security_level)?;
                    if attest_keyinfo.issuer_subject_name.is_empty() {
                        return Err(km_err!(InvalidArgument, "empty subject name"));
                    }
                    Some(SigningInfo {
                        attestation_info,
                        signing_key: attest_keyblob.key_material,
                        issuer_subject: attest_keyinfo.issuer_subject_name.clone(),
                        chain: Vec::new(),
                    })
                } else {
                    // Need to use a device key for attestation. Look up the relevant device key and
                    // chain.
                    let which_key = match (
                        get_bool_tag_value!(params, DeviceUniqueAttestation)?,
                        self.is_strongbox(),
                    ) {
                        (false, _) => device::SigningKey::Batch,
                        (true, true) => device::SigningKey::DeviceUnique,
                        (true, false) => {
                            return Err(km_err!(
                                InvalidArgument,
                                "device unique attestation supported only by Strongbox TA"
                            ))
                        }
                    };
                    // Provide an indication of what's going to be signed, to allow the
                    // implementation to switch between EC and RSA signing keys if it so chooses.
                    let algo_hint = match &keyblob.key_material {
                        crypto::KeyMaterial::Rsa(_) => device::SigningAlgorithm::Rsa,
                        crypto::KeyMaterial::Ec(_, _, _) => device::SigningAlgorithm::Ec,
                        _ => return Err(km_err!(InvalidArgument, "unexpected key type!")),
                    };

                    let mut info = self.get_signing_info(device::SigningKeyType {
                        which: which_key,
                        algo_hint,
                    })?;
                    info.attestation_info = attestation_info;
                    Some(info)
                }
            } else {
                // No attestation challenge, so no attestation.
                if attestation_key.is_some() {
                    return Err(km_err!(
                        AttestationChallengeMissing,
                        "got attestation key but no challenge"
                    ));
                }

                // See if the generated key can self-sign.
                let is_signing_key = params.iter().any(|param| {
                    matches!(
                        param,
                        KeyParam::Purpose(KeyPurpose::Sign)
                            | KeyParam::Purpose(KeyPurpose::AttestKey)
                    )
                });
                if is_signing_key {
                    Some(SigningInfo {
                        attestation_info: None,
                        signing_key: key_material,
                        issuer_subject: try_to_vec(tag::get_cert_subject(params)?)?,
                        chain: Vec::new(),
                    })
                } else {
                    None
                }
            };

            // Build the X.509 leaf certificate.
            let leaf_cert =
                self.generate_cert(signing_info.clone(), spki.ref_to_owned(), params, &chars)?;
            certificate_chain.try_push(leaf_cert)?;

            // Append the rest of the chain.
            if let Some(info) = signing_info {
                for cert in info.chain {
                    certificate_chain.try_push(cert)?;
                }
            }
        }

        // Now build the keyblob.
        let kek_context = self.dev.keys.kek_context()?;
        let root_kek = self.root_kek(&kek_context)?;
        let hidden = tag::hidden(params, self.root_of_trust()?)?;
        let encrypted_keyblob = keyblob::encrypt(
            self.hw_info.security_level,
            match &mut self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&mut **mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &mut *self.imp.rng,
            &root_kek,
            &kek_context,
            keyblob,
            hidden,
            purpose,
        )?;
        let serialized_keyblob = encrypted_keyblob.into_vec()?;

        Ok(KeyCreationResult {
            key_blob: serialized_keyblob,
            key_characteristics: chars,
            certificate_chain,
        })
    }

    pub(crate) fn import_wrapped_key(
        &mut self,
        wrapped_key_data: &[u8],
        wrapping_key_blob: &[u8],
        masking_key: &[u8],
        unwrapping_params: &[KeyParam],
        password_sid: i64,
        biometric_sid: i64,
    ) -> Result<KeyCreationResult, Error> {
        // Decrypt the wrapping key blob
        let (wrapping_key, _) = self.keyblob_parse_decrypt(wrapping_key_blob, unwrapping_params)?;
        let keyblob::PlaintextKeyBlob {
            characteristics,
            key_material,
        } = wrapping_key;

        // Decode the ASN.1 DER encoded `SecureKeyWrapper`.
        let mut secure_key_wrapper = SecureKeyWrapper::from_der(wrapped_key_data)
            .map_err(|e| der_err!(e, "failed to parse SecureKeyWrapper"))?;

        if secure_key_wrapper.version != SECURE_KEY_WRAPPER_VERSION {
            return Err(km_err!(
                InvalidArgument,
                "invalid version in Secure Key Wrapper."
            ));
        }

        // Decrypt the masked transport key, using an RSA key. (Only RSA wrapping keys are supported
        // by the spec, as RSA is the only algorithm supporting asymmetric decryption.)
        let masked_transport_key = match key_material {
            KeyMaterial::Rsa(key) => {
                // Check the requirements on the wrapping key characterisitcs
                let decrypt_mode = tag::check_rsa_wrapping_key_params(
                    tag::characteristics_at(&characteristics, self.hw_info.security_level)?,
                    unwrapping_params,
                )?;

                // Decrypt the masked and encrypted transport key
                let mut crypto_op = self.imp.rsa.begin_decrypt(key, decrypt_mode)?;
                crypto_op
                    .as_mut()
                    .update(secure_key_wrapper.encrypted_transport_key)?;
                crypto_op.finish()?
            }
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "invalid key algorithm for transport key"
                ));
            }
        };

        if masked_transport_key.len() != masking_key.len() {
            return Err(km_err!(
                InvalidArgument,
                "masked transport key is {} bytes, but masking key is {} bytes",
                masked_transport_key.len(),
                masking_key.len()
            ));
        }

        let unmasked_transport_key: Vec<u8> = masked_transport_key
            .iter()
            .zip(masking_key)
            .map(|(x, y)| x ^ y)
            .collect();

        let aes_transport_key =
            aes::Key::Aes256(unmasked_transport_key.try_into().map_err(|_e| {
                km_err!(
                    InvalidArgument,
                    "transport key len {} not correct for AES-256 key",
                    masked_transport_key.len()
                )
            })?);

        // Validate the size of the IV and match the `aes::GcmMode` based on the tag size.
        let iv_len = secure_key_wrapper.initialization_vector.len();
        if iv_len != aes::GCM_NONCE_SIZE {
            return Err(km_err!(
                InvalidArgument,
                "IV length is of {} bytes, which should be of {} bytes",
                iv_len,
                aes::GCM_NONCE_SIZE
            ));
        }
        let tag_len = secure_key_wrapper.tag.len();
        let gcm_mode = match tag_len {
            12 => crypto::aes::GcmMode::GcmTag12 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            13 => crypto::aes::GcmMode::GcmTag13 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            14 => crypto::aes::GcmMode::GcmTag14 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            15 => crypto::aes::GcmMode::GcmTag15 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            16 => crypto::aes::GcmMode::GcmTag16 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            v => {
                return Err(km_err!(
                    InvalidMacLength,
                    "want 12-16 byte tag for AES-GCM not {} bytes",
                    v
                ))
            }
        };

        // Decrypt the encrypted key to be imported, using the ASN.1 DER (re-)encoding of the key
        // description as the AAD.
        let mut op = self.imp.aes.begin_aead(
            OpaqueOr::Explicit(aes_transport_key),
            gcm_mode,
            crypto::SymmetricOperation::Decrypt,
        )?;
        op.update_aad(
            &cert::asn1_der_encode(&secure_key_wrapper.key_description)
                .map_err(|e| der_err!(e, "failed to re-encode SecureKeyWrapper"))?,
        )?;

        let mut imported_key_data = op.update(secure_key_wrapper.encrypted_key)?;
        imported_key_data.try_extend_from_slice(&op.update(secure_key_wrapper.tag)?)?;
        imported_key_data.try_extend_from_slice(&op.finish()?)?;

        // The `Cow::to_mut()` call will not clone, because `from_der()` invokes
        // `AuthorizationList::decode_value()` which creates the owned variant.
        let imported_key_params: &mut Vec<KeyParam> =
            secure_key_wrapper.key_description.key_params.auths.to_mut();
        if let Some(secure_id) = get_opt_tag_value!(&*imported_key_params, UserSecureId)? {
            let secure_id = *secure_id;
            // If both the Password and Fingerprint bits are set in UserSecureId, the password SID
            // should be used, because biometric auth tokens contain both password and fingerprint
            // SIDs, but password auth tokens only contain the password SID.
            if (secure_id & (HardwareAuthenticatorType::Password as u64)
                == (HardwareAuthenticatorType::Password as u64))
                && (secure_id & (HardwareAuthenticatorType::Fingerprint as u64)
                    == (HardwareAuthenticatorType::Fingerprint as u64))
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(password_sid as u64))?;
            } else if secure_id & (HardwareAuthenticatorType::Password as u64)
                == (HardwareAuthenticatorType::Password as u64)
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(password_sid as u64))?;
            } else if secure_id & (HardwareAuthenticatorType::Fingerprint as u64)
                == (HardwareAuthenticatorType::Fingerprint as u64)
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(biometric_sid as u64))?;
            }
        };

        // There is no way for clients to pass CERTIFICATE_NOT_BEFORE and CERTIFICATE_NOT_AFTER.
        // importWrappedKey must use validity with no well-defined expiration date.
        imported_key_params.try_push(KeyParam::CertificateNotBefore(UNDEFINED_NOT_BEFORE))?;
        imported_key_params.try_push(KeyParam::CertificateNotAfter(UNDEFINED_NOT_AFTER))?;

        self.import_key(
            imported_key_params,
            KeyFormat::try_from(secure_key_wrapper.key_description.key_format).map_err(|_e| {
                km_err!(
                    UnsupportedKeyFormat,
                    "could not convert the provided keyformat {}",
                    secure_key_wrapper.key_description.key_format
                )
            })?,
            &imported_key_data,
            None,
            KeyImport::Wrapped,
        )
    }

    pub(crate) fn upgrade_key(
        &mut self,
        keyblob_to_upgrade: &[u8],
        upgrade_params: Vec<KeyParam>,
    ) -> Result<Vec<u8>, Error> {
        let (mut keyblob, mut modified) =
            match self.keyblob_parse_decrypt_backlevel(keyblob_to_upgrade, &upgrade_params) {
                Ok(v) => (v.0, false),
                Err(Error::Hal(ErrorCode::KeyRequiresUpgrade, _)) => {
                    // Because `keyblob_parse_decrypt_backlevel` explicitly allows back-level
                    // versioned keys, a `KeyRequiresUpgrade` error indicates that the keyblob looks
                    // to be in legacy format.  Try to convert it.
                    let legacy_handler =
                        self.dev.legacy_key.as_mut().ok_or_else(|| {
                            km_err!(KeymintNotConfigured, "no legacy key handler")
                        })?;
                    (
                        legacy_handler.convert_legacy_key(
                            keyblob_to_upgrade,
                            &upgrade_params,
                            self.boot_info
                                .as_ref()
                                .ok_or_else(|| km_err!(HardwareNotYetAvailable, "no boot info"))?,
                            self.hw_info.security_level,
                        )?,
                        // Force the emission of a new keyblob even if versions are the same.
                        true,
                    )
                }
                Err(e) => return Err(e),
            };

        fn upgrade(v: &mut u32, curr: u32, name: &str) -> Result<bool, Error> {
            match (*v).cmp(&curr) {
                Ordering::Less => {
                    *v = curr;
                    Ok(true)
                }
                Ordering::Equal => Ok(false),
                Ordering::Greater => {
                    error!("refusing to downgrade {} from {} to {}", name, v, curr);
                    Err(km_err!(
                        InvalidArgument,
                        "keyblob with future {} {} (current {})",
                        name,
                        v,
                        curr
                    ))
                }
            }
        }

        for chars in &mut keyblob.characteristics {
            if chars.security_level != self.hw_info.security_level {
                continue;
            }
            for param in &mut chars.authorizations {
                match param {
                    KeyParam::OsVersion(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            if hal_info.os_version == 0 {
                                // Special case: upgrades to OS version zero are always allowed.
                                warn!("forcing upgrade to OS version 0");
                                modified |= *v != 0;
                                *v = 0;
                            } else {
                                modified |= upgrade(v, hal_info.os_version, "OS version")?;
                            }
                        } else {
                            error!("OS version not available, can't upgrade from {}", v);
                        }
                    }
                    KeyParam::OsPatchlevel(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            modified |= upgrade(v, hal_info.os_patchlevel, "OS patchlevel")?;
                        } else {
                            error!("OS patchlevel not available, can't upgrade from {}", v);
                        }
                    }
                    KeyParam::VendorPatchlevel(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            modified |=
                                upgrade(v, hal_info.vendor_patchlevel, "vendor patchlevel")?;
                        } else {
                            error!("vendor patchlevel not available, can't upgrade from {}", v);
                        }
                    }
                    KeyParam::BootPatchlevel(v) => {
                        if let Some(boot_info) = &self.boot_info {
                            modified |= upgrade(v, boot_info.boot_patchlevel, "boot patchlevel")?;
                        } else {
                            error!("boot patchlevel not available, can't upgrade from {}", v);
                        }
                    }
                    _ => {}
                }
            }
        }

        if !modified {
            // No upgrade needed, return empty data to indicate existing keyblob can still be used.
            return Ok(Vec::new());
        }

        // Now re-build the keyblob. Use a potentially fresh key encryption key, and potentially a
        // new secure deletion secret slot. (The old slot will be released when Keystore performs
        // the corresponding `deleteKey` operation on the old keyblob.
        let kek_context = self.dev.keys.kek_context()?;
        let root_kek = self.root_kek(&kek_context)?;
        let hidden = tag::hidden(&upgrade_params, self.root_of_trust()?)?;
        let encrypted_keyblob = keyblob::encrypt(
            self.hw_info.security_level,
            match &mut self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&mut **mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &mut *self.imp.rng,
            &root_kek,
            &kek_context,
            keyblob,
            hidden,
            keyblob::SlotPurpose::KeyUpgrade,
        )?;
        Ok(encrypted_keyblob.into_vec()?)
    }
}
