use std::sync::Mutex;

use anyhow::{Context, Result};
use binder::binder_impl::Parcel;
use binder::SpIBinder;

pub use kmr_common::legacy_aaid::should_use_aaid_provider;
use kmr_common::legacy_aaid::{
    self, LegacyApplicationId, LEGACY_PROVIDER_DESCRIPTOR, PROVIDER_SERVICE,
};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::transactions;
use crate::android::security::keystore::KeyAttestationApplicationId::KeyAttestationApplicationId;
use crate::android::security::keystore::KeyAttestationPackageInfo::KeyAttestationPackageInfo;
use crate::android::security::keystore::Signature::Signature;

thread_local! {
    // clippy still flags this const initializer through thread_local!.
    #[allow(clippy::missing_const_for_thread_local)]
    static PROVIDER: Mutex<Option<SpIBinder>> = const { Mutex::new(None) };
}

pub fn clear_provider_cache() {
    PROVIDER.with(|slot| {
        *slot.lock().unwrap() = None;
    });
}

pub fn get_application_id(uid: u32) -> Result<KeyAttestationApplicationId> {
    let binder = get_provider_binder()?;
    let mut reply = legacy_aaid::request_application_id(
        &binder,
        transactions::r#getKeyAttestationApplicationId,
        uid,
    )?;
    read_application_id(&mut reply)
}

fn get_provider_binder() -> Result<SpIBinder> {
    PROVIDER.with(|slot| {
        let mut slot = slot.lock().unwrap();
        if let Some(provider) = slot.as_ref() {
            return Ok(provider.clone());
        }

        let provider = binder::ext::get_service_once(PROVIDER_SERVICE)
            .ok()
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("service {PROVIDER_SERVICE} unavailable"))?;
        binder::ext::associate_descriptor(&provider, LEGACY_PROVIDER_DESCRIPTOR)
            .context("legacy key attestation provider descriptor mismatch")?;
        *slot = Some(provider.clone());
        Ok(provider)
    })
}

fn read_application_id(parcel: &mut Parcel) -> Result<KeyAttestationApplicationId> {
    let app: LegacyApplicationId = parcel.read().context("failed to read legacy application id")?;
    Ok(KeyAttestationApplicationId {
        packageInfos: app
            .packages
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(|package| KeyAttestationPackageInfo {
                packageName: package.name.unwrap_or_default(),
                versionCode: package.version,
                signatures: package
                    .signatures
                    .unwrap_or_default()
                    .into_iter()
                    .flatten()
                    .map(|signature| Signature { data: signature.0 })
                    .collect(),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use binder::StatusCode;
    use kmr_common::legacy_aaid::AAID_MAX_VECTOR_LEN;

    #[test]
    fn legacy_java_arrays_preserve_package_fields_and_skip_null_elements() {
        let mut parcel = Parcel::new();
        for value in [1_i32, 3, 0, 1] {
            parcel.write(&value).unwrap();
        }
        parcel.write(&Some("com.example.app".to_string())).unwrap();
        parcel.write(&i64::MAX).unwrap();
        for value in [2_i32, 0, 1] {
            parcel.write(&value).unwrap();
        }
        parcel.write(&vec![1_u8, 2, 3]).unwrap();
        parcel.write(&1_i32).unwrap();
        parcel.write(&None::<String>).unwrap();
        parcel.write(&(-1_i64)).unwrap();
        parcel.write(&(-1_i32)).unwrap();
        // SAFETY: The initialized fixture's start is within its Parcel bounds.
        unsafe {
            parcel.set_data_position(0).unwrap();
        }

        let app = read_application_id(&mut parcel).unwrap();
        assert_eq!(app.packageInfos.len(), 2);
        assert_eq!(app.packageInfos[0].packageName, "com.example.app");
        assert_eq!(app.packageInfos[0].versionCode, i64::MAX);
        assert_eq!(app.packageInfos[0].signatures.len(), 1);
        assert_eq!(app.packageInfos[0].signatures[0].data, vec![1, 2, 3]);
        assert_eq!(app.packageInfos[1].packageName, "");
        assert_eq!(app.packageInfos[1].versionCode, -1);
        assert!(app.packageInfos[1].signatures.is_empty());
        assert_eq!(parcel.get_data_position(), parcel.get_data_size());
    }

    #[test]
    fn legacy_java_array_length_bounds_apply_to_packages_and_signatures() {
        for nested in [false, true] {
            for length in [-2_i32, -1, 0, AAID_MAX_VECTOR_LEN, AAID_MAX_VECTOR_LEN + 1] {
                let mut parcel = Parcel::new();
                parcel.write(&1_i32).unwrap();
                if nested {
                    parcel.write(&1_i32).unwrap();
                    parcel.write(&1_i32).unwrap();
                    parcel.write(&None::<String>).unwrap();
                    parcel.write(&7_i64).unwrap();
                }
                parcel.write(&length).unwrap();
                if length == AAID_MAX_VECTOR_LEN {
                    for _ in 0..length {
                        parcel.write(&0_i32).unwrap();
                    }
                }
                // SAFETY: The initialized fixture's start is within its Parcel bounds.
                unsafe {
                    parcel.set_data_position(0).unwrap();
                }

                let result = read_application_id(&mut parcel);
                if !(-1..=AAID_MAX_VECTOR_LEN).contains(&length) {
                    assert_eq!(result.unwrap_err().downcast_ref(), Some(&StatusCode::BAD_VALUE));
                } else {
                    let app = result.unwrap();
                    if nested {
                        assert_eq!(app.packageInfos.len(), 1);
                        assert!(app.packageInfos[0].signatures.is_empty());
                    } else {
                        assert!(app.packageInfos.is_empty());
                    }
                    assert_eq!(parcel.get_data_position(), parcel.get_data_size());
                }
            }
        }
    }

    #[test]
    fn legacy_java_parcelable_presence_flags_are_strict() {
        for values in [vec![0_i32], vec![-1], vec![2], vec![1, 1, 2], vec![1, 1, 1, -1, 0, 0, 1, 2]]
        {
            let mut parcel = Parcel::new();
            for value in &values {
                parcel.write(value).unwrap();
            }
            // SAFETY: The initialized fixture's start is within its Parcel bounds.
            unsafe {
                parcel.set_data_position(0).unwrap();
            }
            let expected =
                if values == [0] { StatusCode::UNEXPECTED_NULL } else { StatusCode::BAD_VALUE };
            assert_eq!(
                read_application_id(&mut parcel).unwrap_err().downcast_ref(),
                Some(&expected)
            );
        }
    }
}
