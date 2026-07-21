use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use rsbinder::{hub, Parcel, SIBinder, Status};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::transactions;

const PROVIDER_SERVICE: &str = "sec_key_att_app_id_provider";
const LEGACY_PROVIDER_DESCRIPTOR: &str =
    "android.security.keymaster.IKeyAttestationApplicationIdProvider";
const NULL_PARCELABLE: i32 = 0;
const NONNULL_PARCELABLE: i32 = 1;
const NULL_VECTOR_SIZE: i32 = -1;
const AAID_MAX_VECTOR_LEN: i32 = 1024;

static PROVIDER: Mutex<Option<SIBinder>> = Mutex::new(None);

pub fn should_use_aaid_provider() -> bool {
    should_use_legacy_aaid_provider(kmr_common::android_version::android_major_version())
}

fn should_use_legacy_aaid_provider(android_major_version: Option<i32>) -> bool {
    matches!(android_major_version, Some(version) if version <= 14)
}

pub fn clear_provider_cache() {
    *PROVIDER.lock().expect("legacy provider cache poisoned") = None;
}

pub fn resolve_package_names_for_uid(uid: u32) -> Result<Vec<String>> {
    let mut retried = false;
    loop {
        match resolve_package_names_for_uid_once(uid) {
            Ok(package_names) => return Ok(package_names),
            Err(error) if !retried && crate::ipc::is_dead_object_error(&error) => {
                log::warn!("legacy provider hit DeadObject; clearing cache and retrying once");
                clear_provider_cache();
                retried = true;
            }
            Err(error) => return Err(error),
        }
    }
}

fn resolve_package_names_for_uid_once(uid: u32) -> Result<Vec<String>> {
    let binder = get_provider_binder()?;
    let proxy = binder
        .as_proxy()
        .context("legacy key attestation provider binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare legacy getKeyAttestationApplicationId transaction")?;
    data.write(&(uid as i32))
        .context("failed to write legacy getKeyAttestationApplicationId uid")?;

    let mut reply = proxy
        .submit_transact(
            transactions::r#getKeyAttestationApplicationId,
            &data,
            rsbinder::FLAG_CLEAR_BUF,
        )
        .context("legacy getKeyAttestationApplicationId transact failed")?
        .context("legacy getKeyAttestationApplicationId returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode legacy getKeyAttestationApplicationId status")?;
    if !status.is_ok() {
        return Err(anyhow::Error::new(status));
    }

    read_package_names(&mut reply)
}

fn get_provider_binder() -> Result<SIBinder> {
    if let Some(provider) = PROVIDER
        .lock()
        .expect("legacy provider cache poisoned")
        .as_ref()
    {
        return Ok(provider.clone());
    }

    let provider = hub::check_service(PROVIDER_SERVICE)
        .ok_or_else(|| anyhow::anyhow!("service {PROVIDER_SERVICE} unavailable"))?;
    let descriptor = provider.descriptor();
    if descriptor != LEGACY_PROVIDER_DESCRIPTOR {
        bail!("legacy key attestation provider descriptor mismatch: {descriptor}");
    }

    *PROVIDER.lock().expect("legacy provider cache poisoned") = Some(provider.clone());
    Ok(provider)
}

fn read_package_names(parcel: &mut Parcel) -> Result<Vec<String>> {
    read_non_null_parcelable_flag(parcel, "application id")?;
    let package_names = read_typed_array(parcel, read_package_name)?
        .into_iter()
        .flatten()
        .collect();
    Ok(package_names)
}

fn read_package_name(parcel: &mut Parcel) -> Result<Option<String>> {
    let package_name = parcel
        .read::<Option<String>>()
        .context("failed to decode legacy package name")?
        .unwrap_or_default();
    let _version_code = parcel
        .read::<i64>()
        .context("failed to decode legacy package version")?;
    let _signatures = read_typed_array(parcel, read_signature)?;

    Ok((!package_name.is_empty()).then_some(package_name))
}

fn read_signature(parcel: &mut Parcel) -> Result<()> {
    let _data = parcel
        .read::<Vec<u8>>()
        .context("failed to decode legacy signature data")?;
    Ok(())
}

fn read_typed_array<T>(
    parcel: &mut Parcel,
    mut read_value: impl FnMut(&mut Parcel) -> Result<T>,
) -> Result<Vec<T>> {
    let size = parcel
        .read::<i32>()
        .context("failed to decode legacy typed array size")?;
    if size == NULL_VECTOR_SIZE {
        return Ok(Vec::new());
    }
    if !(0..=AAID_MAX_VECTOR_LEN).contains(&size) {
        bail!("invalid legacy typed array size: {size}");
    }

    let mut values = Vec::with_capacity(size as usize);
    for _ in 0..size {
        if read_nullable_parcelable_flag(parcel, "typed array element")? {
            values.push(read_value(parcel)?);
        }
    }
    Ok(values)
}

fn read_non_null_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<()> {
    if read_nullable_parcelable_flag(parcel, label)? {
        Ok(())
    } else {
        bail!("legacy {label} is null");
    }
}

fn read_nullable_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<bool> {
    let flag = parcel
        .read::<i32>()
        .with_context(|| format!("failed to decode legacy {label} parcelable flag"))?;
    match flag {
        NULL_PARCELABLE => Ok(false),
        NONNULL_PARCELABLE => Ok(true),
        _ => bail!("invalid legacy {label} parcelable flag: {flag}"),
    }
}

#[cfg(test)]
mod tests {
    use super::should_use_legacy_aaid_provider;

    #[test]
    fn legacy_aaid_provider_boundary_is_android_14() {
        for version in [Some(12), Some(13), Some(14)] {
            assert!(should_use_legacy_aaid_provider(version));
        }

        for version in [None, Some(15), Some(16), Some(17)] {
            assert!(!should_use_legacy_aaid_provider(version));
        }
    }
}
