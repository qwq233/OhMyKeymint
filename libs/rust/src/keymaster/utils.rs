use crate::{
    android::hardware::security::keymint::{
        ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice,
        KeyCharacteristics::KeyCharacteristics, KeyParameter::KeyParameter as KmKeyParameter,
    },
    consts, err,
    keymaster::{
        error::KsError as Error, key_parameter::KeyParameter, keymint_device::KeyMintDevice,
    },
    watchdog,
};

use anyhow::{Context, Result};

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
    parameters: Vec<crate::key_parameter::KeyParameter>,
) -> Vec<Authorization> {
    parameters
        .into_iter()
        .map(|p| p.into_authorization())
        .collect()
}
