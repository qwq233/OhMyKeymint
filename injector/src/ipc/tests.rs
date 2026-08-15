use super::*;
use std::time::{Duration, Instant};

#[test]
fn binder_status_classification() {
    let status = Status::from(StatusCode::DeadObject);
    assert!(is_dead_object_status(&status));

    let status = Status::from(StatusCode::Ok);
    assert!(!is_dead_object_status(&status));

    for status in [
        StatusCode::DeadObject,
        StatusCode::RpcError,
        StatusCode::NotEnoughData,
    ] {
        assert!(is_stale_rpc_status_code(status));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(
            Status::from(status)
        )));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(status)));
    }

    let shared = Arc::new(
        anyhow::Error::new(StatusCode::DeadObject).context("failed to connect to omk service"),
    );
    assert!(is_rpc_cache_invalidating_error(&shared_rpc_connect_error(
        &shared
    )));

    for status in [
        StatusCode::NoInit,
        StatusCode::Errno(libc::ECONNRESET),
        StatusCode::Errno(libc::ENOTCONN),
        StatusCode::Errno(libc::EPIPE),
    ] {
        assert!(is_rpc_cache_invalidating_status_code(status));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(
            Status::from(status)
        )));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(status)));
    }

    let stale = anyhow::Error::new(Status::from(StatusCode::Unknown));
    assert!(!is_stale_rpc_status_code(StatusCode::Unknown));
    assert!(is_rpc_cache_invalidating_error(&stale));
    assert!(!is_dead_object_error(&stale));

    let direct_unknown = anyhow::Error::new(StatusCode::Unknown);
    assert!(!is_rpc_cache_invalidating_error(&direct_unknown));

    let business = anyhow::Error::new(Status::new_service_specific_error(1, None));
    assert!(!is_rpc_cache_invalidating_error(&business));
}

#[test]
fn package_cache_hits_until_cleared() {
    clear_package_cache();
    let uid = 10123;
    let known = PackageResolution::Known(vec!["com.example.app".to_string()]);
    store_package_cache(uid, known.clone());
    assert!(matches!(
        cached_packages(uid),
        Some(PackageResolution::Known(packages)) if packages == ["com.example.app"]
    ));
    clear_package_cache();
    assert!(cached_packages(uid).is_none());
}

#[test]
fn package_cache_expires_after_ttl() {
    clear_package_cache();
    let uid = 10124;
    package_cache_lock().insert(
        uid,
        PackageCacheEntry {
            resolution: PackageResolution::Unknown,
            expires_at: Instant::now() - Duration::from_secs(1),
        },
    );
    assert!(cached_packages(uid).is_none());
    assert!(package_cache_lock().get(&uid).is_none());
}

#[test]
fn pm_death_clears_package_cache() {
    clear_package_cache();
    store_package_cache(10125, PackageResolution::Unknown);
    clear_pm_cache();
    assert!(cached_packages(10125).is_none());
}
