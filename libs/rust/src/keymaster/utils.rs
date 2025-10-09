use crate::{
    android::hardware::security::keymint::{
        ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice,
        KeyCharacteristics::KeyCharacteristics, KeyParameter::KeyParameter as KmKeyParameter, KeyParameterValue::KeyParameterValue,
    }, consts, err, keymaster::{
        error::KsError as Error, key_parameter::KeyParameter, keymint_device::KeyMintDevice,
    }, watchdog
};

use anyhow::{anyhow, Context, Result, Ok};
use kmr_wire::{keymint::{self, KeyParam}, KeySizeInBits};

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
    km_dev: &dyn IKeyMintDevice,
    key_blob: &[u8],
    upgrade_params: &[KmKeyParameter],
    km_op: KmOp,
    new_blob_handler: NewBlobHandler,
) -> Result<(T, Option<Vec<u8>>)>
where
    KmOp: Fn(&[u8]) -> Result<T, Error>,
    NewBlobHandler: FnOnce(&[u8]) -> Result<()>,
{
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
    km_dev: &dyn IKeyMintDevice,
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
            km_dev,
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
                    km_dev,
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

                Ok(KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(value as u64)))
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
            },
            keymint::Tag::BootPatchlevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::BootPatchlevel(value as u32))
            },
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
            },
            keymint::Tag::MacLength => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MacLength(value as u32))
            },
            keymint::Tag::ResetSinceIdRotation => Ok(KeyParam::ResetSinceIdRotation),
            keymint::Tag::ConfirmationToken => Err(anyhow!(err!("Not implemented"))),
            keymint::Tag::CertificateSerial => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateSerial(value))
            },
            keymint::Tag::CertificateSubject => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateSubject(value))
            },
            keymint::Tag::CertificateNotBefore => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateNotBefore(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            },
            keymint::Tag::CertificateNotAfter => {
                let value = match value {
                    KeyParameterValue::DateTime(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::CertificateNotAfter(kmr_wire::keymint::DateTime {
                    ms_since_epoch: value,
                }))
            },
            keymint::Tag::MaxBootLevel => {
                let value = match value {
                    KeyParameterValue::Integer(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::MaxBootLevel(value as u32))
            },
            keymint::Tag::ModuleHash => {
                let value = match value {
                    KeyParameterValue::Blob(v) => Ok(v),
                    _ => return Err(anyhow!("Mismatched key parameter value type")),
                }?;

                Ok(KeyParam::ModuleHash(value))
            },
        }
    }
}
