use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
use crate::hook::binder::LocalBinderTarget;
use crate::identify::ServiceMethod;
use crate::route::RouteTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevelTargetInfo {
    pub security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    pub preferred_route: RouteTarget,
    pub source_method: ServiceMethod,
}

type TrackedDescriptorKey = (Domain, i64);
type GrantTargetKey = (Domain, i64, Option<String>, Option<Vec<u8>>, i32);

static SECURITY_LEVEL_TARGETS: LazyLock<
    Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));
static KEY_DESCRIPTOR_ROUTE_TARGETS: LazyLock<Mutex<HashMap<TrackedDescriptorKey, RouteTarget>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static GRANT_DESCRIPTORS_BY_TARGET: LazyLock<Mutex<HashMap<GrantTargetKey, KeyDescriptor>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
static STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn tracked_descriptor_key(descriptor: &KeyDescriptor) -> Option<TrackedDescriptorKey> {
    matches!(descriptor.domain, Domain::KEY_ID | Domain::GRANT)
        .then_some((descriptor.domain, descriptor.nspace))
}

fn grant_target_key(target: &KeyDescriptor, grantee_uid: i32) -> GrantTargetKey {
    (
        target.domain,
        target.nspace,
        target.alias.clone(),
        target.blob.clone(),
        grantee_uid,
    )
}

pub(crate) fn remember_security_level_target(
    target: LocalBinderTarget,
    info: SecurityLevelTargetInfo,
) {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .insert(target, info);
}

pub(crate) fn lookup_security_level_target(
    target: LocalBinderTarget,
) -> Option<SecurityLevelTargetInfo> {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .get(&target)
        .copied()
}

pub fn remember_key_descriptor_route(descriptor: &KeyDescriptor, route: RouteTarget) {
    let Some(key) = tracked_descriptor_key(descriptor) else {
        return;
    };
    KEY_DESCRIPTOR_ROUTE_TARGETS
        .lock()
        .expect("key-descriptor route map poisoned")
        .insert(key, route);
}

pub fn remember_key_metadata_route(metadata: &KeyMetadata, route: RouteTarget) {
    remember_key_descriptor_route(&metadata.key, route);
}

pub fn forget_key_descriptor_route(descriptor: &KeyDescriptor) {
    let Some(key) = tracked_descriptor_key(descriptor) else {
        return;
    };
    KEY_DESCRIPTOR_ROUTE_TARGETS
        .lock()
        .expect("key-descriptor route map poisoned")
        .remove(&key);
    GRANT_DESCRIPTORS_BY_TARGET
        .lock()
        .expect("grant target map poisoned")
        .retain(|_, grant| grant != descriptor);
}

pub fn lookup_key_descriptor_route(descriptor: &KeyDescriptor) -> Option<RouteTarget> {
    let key = tracked_descriptor_key(descriptor)?;
    KEY_DESCRIPTOR_ROUTE_TARGETS
        .lock()
        .expect("key-descriptor route map poisoned")
        .get(&key)
        .copied()
}

pub fn resolve_route_for_key_descriptor(
    descriptor: &KeyDescriptor,
    fallback: RouteTarget,
) -> RouteTarget {
    lookup_key_descriptor_route(descriptor).unwrap_or(fallback)
}

pub fn remember_grant_descriptor_for_ungrant(
    target: &KeyDescriptor,
    grantee_uid: i32,
    grant: &KeyDescriptor,
) {
    if tracked_descriptor_key(grant).is_none() {
        return;
    }
    GRANT_DESCRIPTORS_BY_TARGET
        .lock()
        .expect("grant target map poisoned")
        .insert(grant_target_key(target, grantee_uid), grant.clone());
}

pub fn retire_grant_descriptor_after_ungrant(target: &KeyDescriptor, grantee_uid: i32) {
    let grant = GRANT_DESCRIPTORS_BY_TARGET
        .lock()
        .expect("grant target map poisoned")
        .remove(&grant_target_key(target, grantee_uid));
    if let Some(grant) = grant {
        remember_key_descriptor_route(&grant, RouteTarget::System);
    }
    if target.domain == Domain::GRANT {
        remember_key_descriptor_route(target, RouteTarget::System);
    }
}

#[cfg(test)]
pub fn clear_state_for_tests() {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .clear();
    KEY_DESCRIPTOR_ROUTE_TARGETS
        .lock()
        .expect("key-descriptor route map poisoned")
        .clear();
    GRANT_DESCRIPTORS_BY_TARGET
        .lock()
        .expect("grant target map poisoned")
        .clear();
}

#[cfg(test)]
pub fn state_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_state_for_tests();
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(domain: Domain, nspace: i64) -> KeyDescriptor {
        KeyDescriptor {
            domain,
            nspace,
            alias: None,
            blob: None,
        }
    }

    #[test]
    fn key_route_tracking_lifecycle() {
        let _guard = state_test_guard();
        let key_id = descriptor(Domain::KEY_ID, 11);
        let grant = descriptor(Domain::GRANT, 22);
        let app = descriptor(Domain::APP, 33);

        remember_key_descriptor_route(&key_id, RouteTarget::Omk);
        remember_key_descriptor_route(&grant, RouteTarget::Omk);
        remember_key_descriptor_route(&app, RouteTarget::Omk);

        assert_eq!(lookup_key_descriptor_route(&key_id), Some(RouteTarget::Omk));
        assert_eq!(lookup_key_descriptor_route(&grant), Some(RouteTarget::Omk));
        assert_eq!(lookup_key_descriptor_route(&app), None);
        let mut equivalent_key_id = key_id.clone();
        equivalent_key_id.alias = Some("ignored".to_string());
        equivalent_key_id.blob = Some(vec![1, 2, 3]);
        assert_eq!(
            lookup_key_descriptor_route(&equivalent_key_id),
            Some(RouteTarget::Omk)
        );

        let surfaced = descriptor(Domain::GRANT, 1);

        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        forget_key_descriptor_route(&surfaced);

        assert_eq!(lookup_key_descriptor_route(&surfaced), None);

        let target = KeyDescriptor {
            domain: Domain::APP,
            nspace: 10001,
            alias: Some("alpha".to_string()),
            blob: None,
        };
        let mut alias_target = target.clone();
        alias_target.alias = Some("beta".to_string());
        let mut blob_target = target.clone();
        blob_target.blob = Some(vec![1, 2, 3]);
        let target_key = grant_target_key(&target, 10002);
        assert_ne!(target_key, grant_target_key(&alias_target, 10002));
        assert_ne!(target_key, grant_target_key(&blob_target, 10002));
        assert_ne!(target_key, grant_target_key(&target, 10003));

        let surfaced = descriptor(Domain::GRANT, 1);
        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        remember_grant_descriptor_for_ungrant(&target, 10002, &surfaced);
        retire_grant_descriptor_after_ungrant(&target, 10002);

        assert_eq!(
            lookup_key_descriptor_route(&surfaced),
            Some(RouteTarget::System)
        );
        clear_state_for_tests();
    }
}
