use std::result;

use crate::{
    android::hardware::security::{
        self,
        keymint::{
            ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice,
            KeyCharacteristics::KeyCharacteristics, KeyParameter::KeyParameter as KmKeyParameter,
            KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
        },
    },
    consts, err,
    keymaster::{
        error::{KsError as Error, map_ks_error},
        key_parameter::KeyParameter,
        keymint_device::{KeyMintDevice, get_keymint_wrapper},
    },
    watchdog,
};

use anyhow::{anyhow, Context, Ok, Result};
use kmr_wire::{
    keymint::{self, KeyParam},
    KeySizeInBits,
};

pub fn log_params(params: &[KmKeyParameter]) -> Vec<KmKeyParameter> {
    params.iter().cloned().collect::<Vec<KmKeyParameter>>()
}

/// Converts a set of key characteristics as returned from KeyMint into the internal
/// representation of the keystore service.
pub fn key_characteristics_to_internal(
    key_characteristics: Vec<KeyCharacteristics>,
) -> Vec<KeyParameter> {
    key_characteristics
        .into_iter()
        .flat_map(|aidl_key_char| {
            let sec_level = aidl_key_char.securityLevel;
            aidl_key_char
                .authorizations
                .into_iter()
                .map(move |aidl_kp| KeyParameter::new(aidl_kp.into(), sec_level))
        })
        .collect()
}

/// Upgrade a keyblob then invoke both the `new_blob_handler` and the `km_op` closures.  On success
/// a tuple of the `km_op`s result and the optional upgraded blob is returned.
fn upgrade_keyblob_and_perform_op<T, KmOp, NewBlobHandler>(
    security_level: SecurityLevel,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    let km_dev = get_keymint_wrapper(security_level).unwrap();
    let upgraded_blob = {
        let _wp = watchdog::watch(
            "utils::upgrade_keyblob_and_perform_op: calling IKeyMintDevice::upgradeKey.",
        );
        km_dev.upgradeKey(key_blob, upgrade_params)
    }
    .context(err!("Upgrade failed."))?;

    new_blob_handler(&upgraded_blob).context(err!("calling new_blob_handler."))?;

    km_op(&upgraded_blob)
        .map(|v| (v, Some(upgraded_blob)))
        .context(err!("Calling km_op after upgrade."))
}

/// This function can be used to upgrade key blobs on demand. The return value of
/// `km_op` is inspected and if ErrorCode::KEY_REQUIRES_UPGRADE is encountered,
/// an attempt is made to upgrade the key blob. On success `new_blob_handler` is called
/// with the upgraded blob as argument. Then `km_op` is called a second time with the
/// upgraded blob as argument. On success a tuple of the `km_op`s result and the
/// optional upgraded blob is returned.
pub fn upgrade_keyblob_if_required_with<T, KmOp, NewBlobHandler>(
    security_level: SecurityLevel,
    km_dev_version: i32,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
    match km_op(key_blob) {
        Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => upgrade_keyblob_and_perform_op(
            security_level,
            key_blob,
            upgrade_params,
            km_op,
            new_blob_handler,
        ),
        Err(Error::Km(ErrorCode::INVALID_KEY_BLOB))
            if km_dev_version >= KeyMintDevice::KEY_MINT_V1 =>
        {
            // A KeyMint (not Keymaster via km_compat) device says that this is an invalid keyblob.
            //
            // This may be because the keyblob was created before an Android upgrade, and as part of
            // the device upgrade the underlying Keymaster/KeyMint implementation has been upgraded.
            //
            // If that's the case, there are three possible scenarios:
            if key_blob.starts_with(consts::KEYMASTER_BLOB_HW_PREFIX) {
                // 1) The keyblob was created in hardware by the km_compat C++ code, using a prior
                //    Keymaster implementation, and wrapped.
                //
                //    In this case, the keyblob will have the km_compat magic prefix, including the
                //    marker that indicates that this was a hardware-backed key.
                //
                //    The inner keyblob should still be recognized by the hardware implementation, so
                //    strip the prefix and attempt a key upgrade.
                log::info!(
                    "found apparent km_compat(Keymaster) HW blob, attempt strip-and-upgrade"
                );
                let inner_keyblob = &key_blob[consts::KEYMASTER_BLOB_HW_PREFIX.len()..];
                upgrade_keyblob_and_perform_op(
                    security_level,
                    inner_keyblob,
                    upgrade_params,
                    km_op,
                    new_blob_handler,
                )
            } else {
                Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)).context(err!("Calling km_op"))
            }
        }
        r => r.map(|v| (v, None)).context(err!("Calling km_op.")),
    }
}

/// Converts a set of key characteristics from the internal representation into a set of
/// Authorizations as they are used to convey key characteristics to the clients of keystore.
pub fn key_parameters_to_authorizations(
    parameters: Vec<crate::keymaster::key_parameter::KeyParameter>,
) -> Vec<crate::android::system::keystore2::Authorization::Authorization> {
    parameters
        .into_iter()
        .map(|p| p.into_authorization())
        .collect()
}

impl crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken {
    pub fn to_km(&self) -> Result<kmr_wire::keymint::HardwareAuthToken, Error> {
        core::result::Result::Ok(
            kmr_wire::keymint::HardwareAuthToken {
                challenge: self.challenge,
                user_id: self.userId,
                authenticator_id: self.authenticatorId,
                authenticator_type: kmr_wire::keymint::HardwareAuthenticatorType::try_from(self.authenticatorType.0)
                    .map_err(|_| Error::Km(crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_ARGUMENT))?,
                timestamp: kmr_wire::secureclock::Timestamp {
                    milliseconds: self.timestamp.milliSeconds,
                },
                mac: self.mac.clone(),
            }
        )
    }
}

impl crate::android::hardware::security::keymint::KeyParameter::KeyParameter {
    pub fn to_km(self) -> Result<kmr_wire::keymint::KeyParam> {
        let tag = kmr_wire::keymint::Tag::try_from(self.tag.0).unwrap_or(keymint::Tag::Invalid);
        let value = self.value;

        match tag {
            keymint::Tag::Invalid => Err(anyhow::anyhow!(err!("Invalid tag"))),
            keymint::Tag::Purpose => {
                let value = match value {
                    KeyParameterValue::KeyPurpose(v) => {
                        Ok(kmr_wire::keymint::KeyPurpose::try_from(v.0)
                            .map_err(|e| anyhow!("Failed to convert key purpose: {:?}", e))?)
                    }
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Purpose(value))
            }
            keymint::Tag::Algorithm => {
                let value = match value {
                    KeyParameterValue::Algorithm(v) => {
                        Ok(kmr_wire::keymint::Algorithm::try_from(v.0)
                            .map_err(|e| anyhow::anyhow!("Failed to convert algorithm: {:?}", e))?)
                    }
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Algorithm(value))
            }
            keymint::Tag::KeySize => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::KeySize(KeySizeInBits(value as u32)))
            }
            keymint::Tag::BlockMode => {
                let value = match value {
                    KeyParameterValue::BlockMode(v) => {
                        Ok(kmr_wire::keymint::BlockMode::try_from(v.0)
                            .map_err(|e| anyhow!("Failed to convert block mode: {:?}", e))?)
                    }
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::BlockMode(value))
            }
            keymint::Tag::Digest => {
                let value = match value {
                    KeyParameterValue::Digest(v) => Ok(kmr_wire::keymint::Digest::try_from(v.0)
                        .map_err(|e| anyhow!("Failed to convert digest: {:?}", e))?),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Digest(value))
            }
            keymint::Tag::Padding => {
                let value = match value {
                    KeyParameterValue::PaddingMode(v) => {
                        Ok(kmr_wire::keymint::PaddingMode::try_from(v.0)
                            .map_err(|e| anyhow!("Failed to convert padding mode: {:?}", e))?)
                    }
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Padding(value))
            }
            keymint::Tag::CallerNonce => Ok(KeyParam::CallerNonce),
            keymint::Tag::MinMacLength => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MinMacLength(value as u32))
            }
            keymint::Tag::EcCurve => {
                let value = match value {
                    KeyParameterValue::EcCurve(v) => Ok(kmr_wire::keymint::EcCurve::try_from(v.0)
                        .map_err(|e| anyhow!("Failed to convert EC curve: {:?}", e))?),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::EcCurve(value))
            }
            keymint::Tag::RsaPublicExponent => {
                let value = match value {
                    KeyParameterValue::LongInteger(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(
                    value as u64,
                )))
            }
            keymint::Tag::IncludeUniqueId => Ok(KeyParam::IncludeUniqueId),
            keymint::Tag::RsaOaepMgfDigest => {
                let value = match value {
                    KeyParameterValue::Digest(v) => Ok(kmr_wire::keymint::Digest::try_from(v.0)
                        .map_err(|e| anyhow!("Failed to convert digest: {:?}", e))?),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::RsaOaepMgfDigest(value))
            }
            keymint::Tag::BootloaderOnly => Ok(KeyParam::BootloaderOnly),
            keymint::Tag::RollbackResistance => Ok(KeyParam::RollbackResistance),
            keymint::Tag::HardwareType => Err(anyhow!(err!("unavailable"))),
            keymint::Tag::EarlyBootOnly => Ok(KeyParam::EarlyBootOnly),
            keymint::Tag::ActiveDatetime => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::ActiveDatetime(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            }
            keymint::Tag::OriginationExpireDatetime => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::OriginationExpireDatetime(
                    kmr_wire::keymint::DateTime {
                        ms_since_epoch: value,
                    },
                ))
            }
            keymint::Tag::UsageExpireDatetime => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::UsageExpireDatetime(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            }
            keymint::Tag::MinSecondsBetweenOps => Err(anyhow!(err!("Not implemented"))),
            keymint::Tag::MaxUsesPerBoot => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MaxUsesPerBoot(value as u32))
            }
            keymint::Tag::UsageCountLimit => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::UsageCountLimit(value as u32))
            }
            keymint::Tag::UserId => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::UserId(value as u32))
            }
            keymint::Tag::UserSecureId => {
                let value = match value {
                    KeyParameterValue::LongInteger(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::UserSecureId(value as u64))
            }
            keymint::Tag::NoAuthRequired => Ok(KeyParam::NoAuthRequired),
            keymint::Tag::UserAuthType => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::UserAuthType(value as u32))
            }
            keymint::Tag::AuthTimeout => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AuthTimeout(value as u32))
            }
            keymint::Tag::AllowWhileOnBody => Ok(KeyParam::AllowWhileOnBody),
            keymint::Tag::TrustedUserPresenceRequired => Ok(KeyParam::TrustedUserPresenceRequired),
            keymint::Tag::TrustedConfirmationRequired => Ok(KeyParam::TrustedConfirmationRequired),
            keymint::Tag::UnlockedDeviceRequired => Ok(KeyParam::UnlockedDeviceRequired),
            keymint::Tag::ApplicationId => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::ApplicationId(value))
            }
            keymint::Tag::ApplicationData => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::ApplicationData(value))
            }
            keymint::Tag::CreationDatetime => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CreationDatetime(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            }
            keymint::Tag::Origin => {
                let value = match value {
                    KeyParameterValue::Origin(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Origin(
                    kmr_wire::keymint::KeyOrigin::try_from(value.0)
                        .map_err(|e| anyhow!("Failed to convert origin: {:?}", e))?,
                ))
            }
            keymint::Tag::RootOfTrust => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;
                Ok(KeyParam::RootOfTrust(value))
            }
            keymint::Tag::OsVersion => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::OsVersion(value as u32))
            }
            keymint::Tag::OsPatchlevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::OsPatchlevel(value as u32))
            }
            keymint::Tag::UniqueId => Err(anyhow!("Not implemented")),
            keymint::Tag::AttestationChallenge => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationChallenge(value))
            }
            keymint::Tag::AttestationApplicationId => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationApplicationId(value))
            }
            keymint::Tag::AttestationIdBrand => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdBrand(value))
            }
            keymint::Tag::AttestationIdDevice => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdDevice(value))
            }
            keymint::Tag::AttestationIdProduct => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdProduct(value))
            }
            keymint::Tag::AttestationIdSerial => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdSerial(value))
            }
            keymint::Tag::AttestationIdImei => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdImei(value))
            }
            keymint::Tag::AttestationIdMeid => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdMeid(value))
            }
            keymint::Tag::AttestationIdManufacturer => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdManufacturer(value))
            }
            keymint::Tag::AttestationIdModel => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdModel(value))
            }
            keymint::Tag::VendorPatchlevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::VendorPatchlevel(value as u32))
            }
            keymint::Tag::BootPatchlevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::BootPatchlevel(value as u32))
            }
            keymint::Tag::DeviceUniqueAttestation => Ok(KeyParam::DeviceUniqueAttestation),
            keymint::Tag::IdentityCredentialKey => Err(anyhow!(err!("Not implemented"))),
            keymint::Tag::StorageKey => Ok(KeyParam::StorageKey),
            keymint::Tag::AttestationIdSecondImei => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::AttestationIdSecondImei(value))
            }
            keymint::Tag::AssociatedData => Err(anyhow!(err!("Not implemented"))),
            keymint::Tag::Nonce => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::Nonce(value))
            }
            keymint::Tag::MacLength => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MacLength(value as u32))
            }
            keymint::Tag::ResetSinceIdRotation => Ok(KeyParam::ResetSinceIdRotation),
            keymint::Tag::ConfirmationToken => Err(anyhow!(err!("Not implemented"))),
            keymint::Tag::CertificateSerial => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateSerial(value))
            }
            keymint::Tag::CertificateSubject => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateSubject(value))
            }
            keymint::Tag::CertificateNotBefore => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateNotBefore(
                    kmr_wire::keymint::DateTime {
                        ms_since_epoch: value,
                    },
                ))
            }
            keymint::Tag::CertificateNotAfter => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateNotAfter(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            }
            keymint::Tag::MaxBootLevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MaxBootLevel(value as u32))
            }
            keymint::Tag::ModuleHash => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::ModuleHash(value))
            }
        }
    }
}

pub fn key_creation_result_to_aidl(
    result: kmr_wire::keymint::KeyCreationResult,
) -> Result<crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult, rsbinder::Status> {

        let certificates: Vec<
            crate::android::hardware::security::keymint::Certificate::Certificate,
        > = result
            .certificate_chain
            .iter()
            .map(
                |c| crate::android::hardware::security::keymint::Certificate::Certificate {
                    encodedCertificate: c.encoded_certificate.clone(),
                },
            )
            .collect();

        let key_characteristics: Result<Vec<crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics>, rsbinder::Status> = result.key_characteristics.iter().map(|kc| {
            let params: Result<Vec<crate::android::hardware::security::keymint::KeyParameter::KeyParameter>, rsbinder::Status> = kc.authorizations.iter().map(|p| {
                    key_param_to_aidl(p.clone())
                        .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                        .map_err(|e| map_ks_error(e))
            }).collect();
            let params = params?;

            Result::Ok(crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics {
                authorizations: params,
                securityLevel: match kc.security_level {
                    kmr_wire::keymint::SecurityLevel::Software => SecurityLevel::SOFTWARE,
                    kmr_wire::keymint::SecurityLevel::TrustedEnvironment => {
                        SecurityLevel::TRUSTED_ENVIRONMENT
                    }
                    kmr_wire::keymint::SecurityLevel::Strongbox => SecurityLevel::STRONGBOX,
                    _ => {
                        return Err(rsbinder::Status::new_service_specific_error(
                            ErrorCode::UNKNOWN_ERROR.0,
                            None,
                        ))
                    }
                },
            })

        }).collect();
        let key_characteristics = key_characteristics?;

        let resp =
            crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult {
                keyBlob: result.key_blob,
                keyCharacteristics: key_characteristics,
                certificateChain: certificates,
            };

        Result::Ok(resp)
}

pub fn key_param_to_aidl(
    kp: KeyParam,
) -> Result<crate::android::hardware::security::keymint::KeyParameter::KeyParameter> {
    let tag = match kp.tag() {
        keymint::Tag::Invalid => crate::android::hardware::security::keymint::Tag::Tag::INVALID,
        keymint::Tag::Purpose => crate::android::hardware::security::keymint::Tag::Tag::PURPOSE,
        keymint::Tag::Algorithm => crate::android::hardware::security::keymint::Tag::Tag::ALGORITHM,
        keymint::Tag::KeySize => crate::android::hardware::security::keymint::Tag::Tag::KEY_SIZE,
        keymint::Tag::BlockMode => {
            crate::android::hardware::security::keymint::Tag::Tag::BLOCK_MODE
        }
        keymint::Tag::Digest => crate::android::hardware::security::keymint::Tag::Tag::DIGEST,
        keymint::Tag::Padding => crate::android::hardware::security::keymint::Tag::Tag::PADDING,
        keymint::Tag::CallerNonce => {
            crate::android::hardware::security::keymint::Tag::Tag::CALLER_NONCE
        }
        keymint::Tag::MinMacLength => {
            crate::android::hardware::security::keymint::Tag::Tag::MIN_MAC_LENGTH
        }
        keymint::Tag::EcCurve => crate::android::hardware::security::keymint::Tag::Tag::EC_CURVE,
        keymint::Tag::RsaPublicExponent => {
            crate::android::hardware::security::keymint::Tag::Tag::RSA_PUBLIC_EXPONENT
        }
        keymint::Tag::IncludeUniqueId => {
            crate::android::hardware::security::keymint::Tag::Tag::INCLUDE_UNIQUE_ID
        }
        keymint::Tag::RsaOaepMgfDigest => {
            crate::android::hardware::security::keymint::Tag::Tag::RSA_OAEP_MGF_DIGEST
        }
        keymint::Tag::BootloaderOnly => {
            crate::android::hardware::security::keymint::Tag::Tag::BOOTLOADER_ONLY
        }
        keymint::Tag::RollbackResistance => {
            crate::android::hardware::security::keymint::Tag::Tag::ROLLBACK_RESISTANCE
        }
        keymint::Tag::HardwareType => {
            crate::android::hardware::security::keymint::Tag::Tag::HARDWARE_TYPE
        }
        keymint::Tag::EarlyBootOnly => {
            crate::android::hardware::security::keymint::Tag::Tag::EARLY_BOOT_ONLY
        }
        keymint::Tag::ActiveDatetime => {
            crate::android::hardware::security::keymint::Tag::Tag::ACTIVE_DATETIME
        }
        keymint::Tag::OriginationExpireDatetime => {
            crate::android::hardware::security::keymint::Tag::Tag::ORIGINATION_EXPIRE_DATETIME
        }
        keymint::Tag::UsageExpireDatetime => {
            crate::android::hardware::security::keymint::Tag::Tag::USAGE_EXPIRE_DATETIME
        }
        keymint::Tag::MinSecondsBetweenOps => {
            crate::android::hardware::security::keymint::Tag::Tag::MIN_SECONDS_BETWEEN_OPS
        }
        keymint::Tag::MaxUsesPerBoot => {
            crate::android::hardware::security::keymint::Tag::Tag::MAX_USES_PER_BOOT
        }
        keymint::Tag::UsageCountLimit => {
            crate::android::hardware::security::keymint::Tag::Tag::USAGE_COUNT_LIMIT
        }
        keymint::Tag::UserId => crate::android::hardware::security::keymint::Tag::Tag::USER_ID,
        keymint::Tag::UserSecureId => {
            crate::android::hardware::security::keymint::Tag::Tag::USER_SECURE_ID
        }
        keymint::Tag::NoAuthRequired => {
            crate::android::hardware::security::keymint::Tag::Tag::NO_AUTH_REQUIRED
        }
        keymint::Tag::UserAuthType => {
            crate::android::hardware::security::keymint::Tag::Tag::USER_AUTH_TYPE
        }
        keymint::Tag::AuthTimeout => {
            crate::android::hardware::security::keymint::Tag::Tag::AUTH_TIMEOUT
        }
        keymint::Tag::AllowWhileOnBody => {
            crate::android::hardware::security::keymint::Tag::Tag::ALLOW_WHILE_ON_BODY
        }
        keymint::Tag::TrustedUserPresenceRequired => {
            crate::android::hardware::security::keymint::Tag::Tag::TRUSTED_USER_PRESENCE_REQUIRED
        }
        keymint::Tag::TrustedConfirmationRequired => {
            crate::android::hardware::security::keymint::Tag::Tag::TRUSTED_CONFIRMATION_REQUIRED
        }
        keymint::Tag::UnlockedDeviceRequired => {
            crate::android::hardware::security::keymint::Tag::Tag::UNLOCKED_DEVICE_REQUIRED
        }
        keymint::Tag::ApplicationId => {
            crate::android::hardware::security::keymint::Tag::Tag::APPLICATION_ID
        }
        keymint::Tag::ApplicationData => {
            crate::android::hardware::security::keymint::Tag::Tag::APPLICATION_DATA
        }
        keymint::Tag::CreationDatetime => {
            crate::android::hardware::security::keymint::Tag::Tag::CREATION_DATETIME
        }
        keymint::Tag::Origin => crate::android::hardware::security::keymint::Tag::Tag::ORIGIN,
        keymint::Tag::RootOfTrust => {
            crate::android::hardware::security::keymint::Tag::Tag::ROOT_OF_TRUST
        }
        keymint::Tag::OsVersion => {
            crate::android::hardware::security::keymint::Tag::Tag::OS_VERSION
        }
        keymint::Tag::OsPatchlevel => {
            crate::android::hardware::security::keymint::Tag::Tag::OS_PATCHLEVEL
        }
        keymint::Tag::UniqueId => crate::android::hardware::security::keymint::Tag::Tag::UNIQUE_ID,
        keymint::Tag::AttestationChallenge => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_CHALLENGE
        }
        keymint::Tag::AttestationApplicationId => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_APPLICATION_ID
        }
        keymint::Tag::AttestationIdBrand => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_BRAND
        }
        keymint::Tag::AttestationIdDevice => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_DEVICE
        }
        keymint::Tag::AttestationIdProduct => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_PRODUCT
        }
        keymint::Tag::AttestationIdSerial => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_SERIAL
        }
        keymint::Tag::AttestationIdImei => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_IMEI
        }
        keymint::Tag::AttestationIdMeid => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_MEID
        }
        keymint::Tag::AttestationIdManufacturer => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_MANUFACTURER
        }
        keymint::Tag::AttestationIdModel => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_MODEL
        }
        keymint::Tag::VendorPatchlevel => {
            crate::android::hardware::security::keymint::Tag::Tag::VENDOR_PATCHLEVEL
        }
        keymint::Tag::BootPatchlevel => {
            crate::android::hardware::security::keymint::Tag::Tag::BOOT_PATCHLEVEL
        }
        keymint::Tag::DeviceUniqueAttestation => {
            crate::android::hardware::security::keymint::Tag::Tag::DEVICE_UNIQUE_ATTESTATION
        }
        keymint::Tag::IdentityCredentialKey => {
            crate::android::hardware::security::keymint::Tag::Tag::IDENTITY_CREDENTIAL_KEY
        }
        keymint::Tag::StorageKey => {
            crate::android::hardware::security::keymint::Tag::Tag::STORAGE_KEY
        }
        keymint::Tag::AttestationIdSecondImei => {
            crate::android::hardware::security::keymint::Tag::Tag::ATTESTATION_ID_SECOND_IMEI
        }
        keymint::Tag::AssociatedData => {
            crate::android::hardware::security::keymint::Tag::Tag::ASSOCIATED_DATA
        }
        keymint::Tag::Nonce => crate::android::hardware::security::keymint::Tag::Tag::NONCE,
        keymint::Tag::MacLength => {
            crate::android::hardware::security::keymint::Tag::Tag::MAC_LENGTH
        }
        keymint::Tag::ResetSinceIdRotation => {
            crate::android::hardware::security::keymint::Tag::Tag::RESET_SINCE_ID_ROTATION
        }
        keymint::Tag::ConfirmationToken => {
            crate::android::hardware::security::keymint::Tag::Tag::CONFIRMATION_TOKEN
        }
        keymint::Tag::CertificateSerial => {
            crate::android::hardware::security::keymint::Tag::Tag::CERTIFICATE_SERIAL
        }
        keymint::Tag::CertificateSubject => {
            crate::android::hardware::security::keymint::Tag::Tag::CERTIFICATE_SUBJECT
        }
        keymint::Tag::CertificateNotBefore => {
            crate::android::hardware::security::keymint::Tag::Tag::CERTIFICATE_NOT_BEFORE
        }
        keymint::Tag::CertificateNotAfter => {
            crate::android::hardware::security::keymint::Tag::Tag::CERTIFICATE_NOT_AFTER
        }
        keymint::Tag::MaxBootLevel => {
            crate::android::hardware::security::keymint::Tag::Tag::MAX_BOOT_LEVEL
        }
        keymint::Tag::ModuleHash => {
            crate::android::hardware::security::keymint::Tag::Tag::MODULE_HASH
        }
    };

    let value = match kp {
        KeyParam::Purpose(v) => KeyParameterValue::KeyPurpose(
            crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose(v as i32),
        ),
        KeyParam::Algorithm(v) => KeyParameterValue::Algorithm(
            crate::android::hardware::security::keymint::Algorithm::Algorithm(v as i32),
        ),
        KeyParam::KeySize(KeySizeInBits(v)) => KeyParameterValue::Integer(v as i32),
        KeyParam::BlockMode(v) => KeyParameterValue::BlockMode(
            crate::android::hardware::security::keymint::BlockMode::BlockMode(v as i32),
        ),
        KeyParam::Digest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::Padding(v) => KeyParameterValue::PaddingMode(
            crate::android::hardware::security::keymint::PaddingMode::PaddingMode(v as i32),
        ),
        KeyParam::CallerNonce => KeyParameterValue::BoolValue(true),
        KeyParam::MinMacLength(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::EcCurve(v) => KeyParameterValue::EcCurve(
            crate::android::hardware::security::keymint::EcCurve::EcCurve(v as i32),
        ),
        KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(v)) => {
            KeyParameterValue::LongInteger(v as i64)
        }
        KeyParam::IncludeUniqueId => KeyParameterValue::BoolValue(true),
        KeyParam::RsaOaepMgfDigest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KeyParam::BootloaderOnly => KeyParameterValue::BoolValue(true),
        KeyParam::RollbackResistance => KeyParameterValue::BoolValue(true),
        KeyParam::EarlyBootOnly => KeyParameterValue::BoolValue(true),
        KeyParam::ActiveDatetime(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::OriginationExpireDatetime(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::UsageExpireDatetime(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::MaxUsesPerBoot(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::UsageCountLimit(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::UserId(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::UserSecureId(v) => KeyParameterValue::LongInteger(v as i64),
        KeyParam::NoAuthRequired => KeyParameterValue::BoolValue(true),
        KeyParam::UserAuthType(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::AuthTimeout(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::AllowWhileOnBody => KeyParameterValue::BoolValue(true),
        KeyParam::TrustedUserPresenceRequired => KeyParameterValue::BoolValue(true),
        KeyParam::TrustedConfirmationRequired => KeyParameterValue::BoolValue(true),
        KeyParam::UnlockedDeviceRequired => KeyParameterValue::BoolValue(true),
        KeyParam::ApplicationId(v) => KeyParameterValue::Blob(v),
        KeyParam::ApplicationData(v) => KeyParameterValue::Blob(v),
        KeyParam::CreationDatetime(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::Origin(v) => KeyParameterValue::Origin(
            crate::android::hardware::security::keymint::KeyOrigin::KeyOrigin(v as i32),
        ),
        KeyParam::RootOfTrust(v) => KeyParameterValue::Blob(v),
        KeyParam::OsVersion(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::OsPatchlevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::AttestationChallenge(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationApplicationId(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdBrand(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdDevice(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdProduct(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdSerial(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdImei(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdMeid(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdManufacturer(v) => KeyParameterValue::Blob(v),
        KeyParam::AttestationIdModel(v) => KeyParameterValue::Blob(v),
        KeyParam::VendorPatchlevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::BootPatchlevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::DeviceUniqueAttestation => KeyParameterValue::BoolValue(true),
        KeyParam::StorageKey => KeyParameterValue::BoolValue(true),
        KeyParam::AttestationIdSecondImei(v) => KeyParameterValue::Blob(v),
        KeyParam::Nonce(v) => KeyParameterValue::Blob(v),
        KeyParam::MacLength(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::ResetSinceIdRotation => KeyParameterValue::BoolValue(true),
        KeyParam::CertificateSerial(v) => KeyParameterValue::Blob(v),
        KeyParam::CertificateSubject(v) => KeyParameterValue::Blob(v),
        KeyParam::CertificateNotBefore(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::CertificateNotAfter(kmr_wire::keymint::DateTime { ms_since_epoch }) => {
            KeyParameterValue::DateTime(ms_since_epoch)
        }
        KeyParam::MaxBootLevel(v) => KeyParameterValue::Integer(v as i32),
        KeyParam::ModuleHash(v) => KeyParameterValue::Blob(v),
    };

    Ok(crate::android::hardware::security::keymint::KeyParameter::KeyParameter { tag, value })
}
