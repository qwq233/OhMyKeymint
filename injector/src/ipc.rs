use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::{
    transactions, IKeyAttestationApplicationIdProvider,
};
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use anyhow::{Context, Result};
use binder::binder_impl::Parcel;
use binder::{ExceptionCode, SpIBinder, Status, StatusCode, Strong};
use kmr_common::legacy_aaid::{self, LegacyApplicationId, LEGACY_PROVIDER_DESCRIPTOR};
use log::warn;
use std::sync::Mutex;

use kmr_common::legacy_aaid::PROVIDER_SERVICE as PM_SERVICE;

static PROVIDER: Mutex<Option<SpIBinder>> = Mutex::new(None);
type ModernProvider = Strong<dyn IKeyAttestationApplicationIdProvider>;
static MODERN_PROVIDER: Mutex<Option<ModernProvider>> = Mutex::new(None);

pub fn resolve_packages_for_caller_in_callback(caller: &CallerInfo) -> (u32, PackageResolution) {
    let _guard = crate::forward::BypassGuard::enter();
    resolve_packages_for_caller_with(caller, query_package_names_for_uid)
}

fn resolve_packages_for_caller_with(
    caller: &CallerInfo,
    query: impl FnOnce(u32) -> Result<Vec<String>>,
) -> (u32, PackageResolution) {
    let uid = caller.uid as u32;
    let package_uid =
        match non_isolated_package_uid(uid, kmr_common::android_version::android_major_version()) {
            Some(uid) => Some(uid),
            None => match kmr_common::rpc::with_admin(|omk| {
                Ok(u32::try_from(omk.getIsolatedOwnerUid(Some(caller))?).ok())
            }) {
                Ok(owner) => owner.flatten(),
                Err(error) => {
                    warn!(
                        "failed to resolve isolated caller uid={} pid={}: {error:#}",
                        uid, caller.pid
                    );
                    None
                }
            },
        };
    let Some(package_uid) = package_uid else {
        return (uid, PackageResolution::Unknown);
    };
    let resolution = match query(package_uid) {
        Ok(packages) if packages.is_empty() => PackageResolution::Unknown,
        Ok(packages) => PackageResolution::Known(packages),
        Err(error) => {
            warn!("failed to resolve packages for uid {}: {:#}", package_uid, error);
            PackageResolution::Unknown
        }
    };
    (package_uid, resolution)
}

fn non_isolated_package_uid(uid: u32, android_major: Option<i32>) -> Option<u32> {
    // AOSP Process.getAppUidForSdkSandboxUid/getAppUidForPrivateComputeCoreUid.
    match uid % kmr_common::consts::AID_USER_OFFSET {
        90_000..=99_999 => None,
        20_000..=29_999 if android_major.is_some_and(|version| version >= 13) => Some(uid - 10_000),
        30_000..=39_999 if android_major.is_some_and(|version| version >= 17) => Some(uid - 20_000),
        _ => Some(uid),
    }
}

fn query_package_names_for_uid(uid: u32) -> Result<Vec<String>> {
    if legacy_aaid::should_use_aaid_provider() {
        match resolve_legacy_package_names_once(uid) {
            Err(error) if is_dead_object_error(&error) => {
                warn!("legacy provider hit DeadObject; clearing cache and retrying once");
                *PROVIDER.lock().expect("legacy provider cache poisoned") = None;
                resolve_legacy_package_names_once(uid)
            }
            result => result,
        }
    } else {
        resolve_package_names_for_uid_once(uid)
    }
}

fn resolve_package_names_for_uid_once(uid: u32) -> Result<Vec<String>> {
    let app_id = with_pm_retry(
        &MODERN_PROVIDER,
        || {
            binder::check_interface(PM_SERVICE)
                .context("failed to connect to sec_key_att_app_id_provider")
        },
        |pm| {
            pm.getKeyAttestationApplicationId(uid as i32)
                .context("getKeyAttestationApplicationId failed")
        },
    )?;
    Ok(app_id
        .packageInfos
        .into_iter()
        .map(|pkg| pkg.packageName)
        .filter(|pkg| !pkg.is_empty())
        .collect())
}

fn with_pm_retry<T>(
    cache: &Mutex<Option<ModernProvider>>,
    mut lookup: impl FnMut() -> Result<ModernProvider>,
    mut call: impl FnMut(&ModernProvider) -> Result<T>,
) -> Result<T> {
    let cached = cache.lock().expect("provider cache poisoned").clone();
    let client = match cached {
        Some(client) => client,
        None => {
            let candidate = lookup()?;
            cache.lock().expect("provider cache poisoned").get_or_insert(candidate).clone()
        }
    };
    let mut invoke = |client: &ModernProvider| {
        let result = call(client);
        if result.as_ref().is_err_and(is_dead_object_error) {
            let mut cached = cache.lock().expect("provider cache poisoned");
            if cached.as_ref() == Some(client) {
                *cached = None;
            }
        }
        result
    };
    match invoke(&client) {
        Err(error) if is_dead_object_error(&error) => {
            warn!(
                "{} transaction hit DEAD_OBJECT; looking up service and retrying once",
                PM_SERVICE
            );
            let refreshed = lookup()?;
            {
                let mut cached = cache.lock().expect("provider cache poisoned");
                if cached.is_none() || cached.as_ref() == Some(&client) {
                    *cached = Some(refreshed.clone());
                }
            }
            invoke(&refreshed)
        }
        result => result,
    }
}

pub(crate) fn is_dead_object_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<Status>().is_some_and(is_dead_object_status)
            || cause
                .downcast_ref::<StatusCode>()
                .is_some_and(|status| *status == StatusCode::DEAD_OBJECT)
    })
}

fn is_dead_object_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TRANSACTION_FAILED
        && status.transaction_error() == StatusCode::DEAD_OBJECT
}

fn resolve_legacy_package_names_once(uid: u32) -> Result<Vec<String>> {
    let binder = get_provider_binder()?;
    let mut reply = legacy_aaid::request_application_id(
        &binder,
        transactions::r#getKeyAttestationApplicationId,
        uid,
    )?;
    read_package_names(&mut reply)
}

fn get_provider_binder() -> Result<SpIBinder> {
    if let Some(provider) = PROVIDER.lock().expect("legacy provider cache poisoned").as_ref() {
        return Ok(provider.clone());
    }

    let provider = binder::check_service(PM_SERVICE)
        .ok_or_else(|| anyhow::anyhow!("service {PM_SERVICE} unavailable"))?;
    binder::ext::associate_descriptor(&provider, LEGACY_PROVIDER_DESCRIPTOR)
        .context("legacy key attestation provider descriptor mismatch")?;

    *PROVIDER.lock().expect("legacy provider cache poisoned") = Some(provider.clone());
    Ok(provider)
}

fn read_package_names(parcel: &mut Parcel) -> Result<Vec<String>> {
    let app: LegacyApplicationId = parcel.read().context("failed to read legacy application id")?;
    Ok(app
        .packages
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .filter_map(|package| package.name.filter(|name| !name.is_empty()))
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kmr_common::legacy_aaid::AAID_MAX_VECTOR_LEN;
    use kmr_common::rpc::{
        is_rpc_cache_invalidating_status, is_rpc_cache_invalidating_status_code,
        is_stale_rpc_status_code,
    };

    #[test]
    fn package_uid_matches_android_process_uid_ranges() {
        for version in 13..=17 {
            for user in [0, 1, 10] {
                let base = user * kmr_common::consts::AID_USER_OFFSET;
                for app_id in [0, 1000, 9999, 10_000, 19_999, 40_000, 89_999] {
                    assert_eq!(
                        non_isolated_package_uid(base + app_id, Some(version)),
                        Some(base + app_id)
                    );
                }
                for app_id in [20_000, 20_123, 29_999] {
                    assert_eq!(
                        non_isolated_package_uid(base + app_id, Some(version)),
                        Some(base + app_id - 10_000)
                    );
                }
                for app_id in [30_000, 30_123, 39_999] {
                    assert_eq!(
                        non_isolated_package_uid(base + app_id, Some(version)),
                        Some(base + app_id - if version >= 17 { 20_000 } else { 0 })
                    );
                }
                for app_id in [90_000, 98_999, 99_000, 99_999] {
                    assert_eq!(non_isolated_package_uid(base + app_id, Some(version)), None);
                }
            }
        }
        assert_eq!(non_isolated_package_uid(20_123, Some(12)), Some(20_123));
        assert_eq!(non_isolated_package_uid(20_123, None), Some(20_123));
    }

    #[test]
    fn binder_status_classification() {
        let status = Status::from(StatusCode::DEAD_OBJECT as i32);
        assert!(is_dead_object_status(&status));

        let status = Status::from(StatusCode::OK as i32);
        assert!(!is_dead_object_status(&status));

        for status in [StatusCode::DEAD_OBJECT, StatusCode::NOT_ENOUGH_DATA] {
            assert!(is_stale_rpc_status_code(status));
            assert!(is_rpc_cache_invalidating_status(&Status::from(status as i32)));
            assert!(is_rpc_cache_invalidating_status_code(status));
        }

        assert!(is_rpc_cache_invalidating_status_code(StatusCode::NO_INIT));
        assert!(is_rpc_cache_invalidating_status(&Status::from(StatusCode::NO_INIT as i32)));
        assert!(!is_stale_rpc_status_code(StatusCode::NO_INIT));
        for (errno, expected, invalidates) in [
            (libc::ENOENT, StatusCode::NAME_NOT_FOUND, false),
            (libc::ECONNREFUSED, StatusCode::UNKNOWN_ERROR, true),
            (libc::ECONNRESET, StatusCode::UNKNOWN_ERROR, true),
            (libc::ENOTCONN, StatusCode::UNKNOWN_ERROR, true),
            (libc::EPIPE, StatusCode::DEAD_OBJECT, true),
        ] {
            let status = Status::from(-errno);
            assert_eq!(status.exception_code(), ExceptionCode::TRANSACTION_FAILED);
            assert_eq!(status.transaction_error(), expected, "errno={errno}");
            assert_eq!(is_rpc_cache_invalidating_status(&status), invalidates, "errno={errno}");
        }

        let status = Status::from(StatusCode::UNKNOWN_ERROR as i32);
        assert!(!is_stale_rpc_status_code(StatusCode::UNKNOWN_ERROR));
        assert!(is_rpc_cache_invalidating_status(&status));
        let stale = anyhow::Error::new(status);
        assert!(!is_dead_object_error(&stale));

        assert!(!is_rpc_cache_invalidating_status_code(StatusCode::UNKNOWN_ERROR));

        let business = Status::new_service_specific_error(1, None);
        assert!(!is_rpc_cache_invalidating_status(&business));
    }

    #[test]
    fn pm_lookup_and_calls_retry_only_the_first_dead_object() {
        use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::BnKeyAttestationApplicationIdProvider;
        use crate::android::security::keystore::KeyAttestationApplicationId::KeyAttestationApplicationId;
        use std::cell::Cell;

        struct Provider;
        impl binder::Interface for Provider {}
        impl IKeyAttestationApplicationIdProvider for Provider {
            fn getKeyAttestationApplicationId(
                &self,
                _: i32,
            ) -> binder::Result<KeyAttestationApplicationId> {
                Ok(Default::default())
            }
        }
        let provider = BnKeyAttestationApplicationIdProvider::new_binder(
            Provider,
            binder::BinderFeatures::default(),
        );
        for (
            failed_lookup,
            first_error,
            second_error,
            expected_lookups,
            expected_calls,
            expected_error,
        ) in [
            (Some(1), None, None, 1, 0, true),
            (None, None, None, 1, 1, false),
            (None, Some(StatusCode::PERMISSION_DENIED), None, 1, 1, true),
            (None, Some(StatusCode::DEAD_OBJECT), None, 2, 2, false),
            (Some(2), Some(StatusCode::DEAD_OBJECT), None, 2, 1, true),
            (None, Some(StatusCode::DEAD_OBJECT), Some(StatusCode::DEAD_OBJECT), 2, 2, true),
            (None, Some(StatusCode::DEAD_OBJECT), Some(StatusCode::PERMISSION_DENIED), 2, 2, true),
        ] {
            let lookups = Cell::new(0);
            let calls = Cell::new(0);
            let result = with_pm_retry(
                &Mutex::new(None),
                || {
                    lookups.set(lookups.get() + 1);
                    if failed_lookup == Some(lookups.get()) {
                        Err(anyhow::Error::new(StatusCode::NAME_NOT_FOUND))
                    } else {
                        Ok(provider.clone())
                    }
                },
                |_| {
                    calls.set(calls.get() + 1);
                    let status = if calls.get() == 1 { first_error } else { second_error };
                    match status {
                        Some(status) => Err(anyhow::Error::new(status)),
                        None => Ok(7),
                    }
                },
            );
            assert_eq!(lookups.get(), expected_lookups);
            assert_eq!(calls.get(), expected_calls);
            assert_eq!(result.is_err(), expected_error);
        }
        let cache = Mutex::new(None);
        let lookups = Cell::new(0);
        for package in ["first.package", "next.package"] {
            let names = with_pm_retry(
                &cache,
                || {
                    lookups.set(lookups.get() + 1);
                    Ok(provider.clone())
                },
                |_| Ok(vec![package]),
            )
            .unwrap();
            assert_eq!(names, [package]);
        }
        assert_eq!(lookups.get(), 1);

        let replacement =
            BnKeyAttestationApplicationIdProvider::new_binder(Provider, Default::default());
        let retry = with_pm_retry(
            &cache,
            || {
                // A concurrent cold lookup publishes the dead handle during the refresh.
                *cache.lock().unwrap() = Some(provider.clone());
                Ok(replacement.clone())
            },
            |client| {
                if client == &provider {
                    return Err(anyhow::Error::new(StatusCode::DEAD_OBJECT));
                }
                Ok(client == &replacement)
            },
        );
        assert!(retry.unwrap());
        assert!(cache.lock().unwrap().as_ref() == Some(&replacement));
    }

    #[test]
    fn legacy_java_typed_arrays_keep_nullable_elements_and_skip_empty_names() {
        let mut parcel = Parcel::new();
        for value in [1_i32, 3, 0, 1] {
            parcel.write(&value).unwrap();
        }
        parcel.write(&Some("com.example.app".to_string())).unwrap();
        parcel.write(&7_i64).unwrap();
        for value in [2_i32, 0, 1] {
            parcel.write(&value).unwrap();
        }
        parcel.write(&vec![1_u8, 2, 3]).unwrap();
        parcel.write(&1_i32).unwrap();
        parcel.write(&None::<String>).unwrap();
        parcel.write(&8_i64).unwrap();
        parcel.write(&(-1_i32)).unwrap();
        // SAFETY: The fixture is a valid Parcel, whose start is always in bounds.
        unsafe {
            parcel.set_data_position(0).unwrap();
        }
        assert_eq!(read_package_names(&mut parcel).unwrap(), vec!["com.example.app"]);
        assert_eq!(parcel.get_data_position(), parcel.get_data_size());
    }

    #[test]
    fn legacy_typed_array_length_is_validated_before_allocating() {
        for length in [-2_i32, AAID_MAX_VECTOR_LEN + 1] {
            let mut parcel = Parcel::new();
            parcel.write(&1_i32).unwrap();
            parcel.write(&length).unwrap();
            // SAFETY: The fixture is a valid Parcel, whose start is always in bounds.
            unsafe {
                parcel.set_data_position(0).unwrap();
            }
            assert!(read_package_names(&mut parcel).is_err());
        }
    }
}
