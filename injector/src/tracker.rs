use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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

static SECURITY_LEVEL_TARGETS: OnceLock<
    Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>>,
> = OnceLock::new();
static KEY_DESCRIPTOR_ROUTE_TARGETS: OnceLock<Mutex<HashMap<String, RouteTarget>>> =
    OnceLock::new();
static GRANT_DESCRIPTORS_BY_TARGET: OnceLock<Mutex<HashMap<String, KeyDescriptor>>> =
    OnceLock::new();
#[cfg(test)]
static STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn security_level_targets() -> &'static Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>> {
    SECURITY_LEVEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_descriptor_route_targets() -> &'static Mutex<HashMap<String, RouteTarget>> {
    KEY_DESCRIPTOR_ROUTE_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn grant_descriptors_by_target() -> &'static Mutex<HashMap<String, KeyDescriptor>> {
    GRANT_DESCRIPTORS_BY_TARGET.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tracked_descriptor_key(descriptor: &KeyDescriptor) -> Option<String> {
    match descriptor.domain {
        Domain::KEY_ID | Domain::GRANT => {
            Some(format!("{:?}:{}", descriptor.domain, descriptor.nspace))
        }
        _ => None,
    }
}

fn descriptor_identity_key(descriptor: &KeyDescriptor) -> String {
    format!(
        "{:?}:{}:{:?}:{:?}",
        descriptor.domain, descriptor.nspace, descriptor.alias, descriptor.blob
    )
}

fn grant_target_key(target: &KeyDescriptor, grantee_uid: i32) -> String {
    format!("{}:{}", descriptor_identity_key(target), grantee_uid)
}

pub(crate) fn remember_security_level_target(
    target: LocalBinderTarget,
    info: SecurityLevelTargetInfo,
) {
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .insert(target, info);
}

pub(crate) fn lookup_security_level_target(
    target: LocalBinderTarget,
) -> Option<SecurityLevelTargetInfo> {
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .get(&target)
        .copied()
}

pub fn remember_key_descriptor_route(descriptor: &KeyDescriptor, route: RouteTarget) {
    let Some(key) = tracked_descriptor_key(descriptor) else {
        return;
    };
    key_descriptor_route_targets()
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
    key_descriptor_route_targets()
        .lock()
        .expect("key-descriptor route map poisoned")
        .remove(&key);
    grant_descriptors_by_target()
        .lock()
        .expect("grant target map poisoned")
        .retain(|_, grant| grant != descriptor);
}

pub fn lookup_key_descriptor_route(descriptor: &KeyDescriptor) -> Option<RouteTarget> {
    let key = tracked_descriptor_key(descriptor)?;
    key_descriptor_route_targets()
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
    grant_descriptors_by_target()
        .lock()
        .expect("grant target map poisoned")
        .insert(grant_target_key(target, grantee_uid), grant.clone());
}

pub fn retire_grant_descriptor_after_ungrant(target: &KeyDescriptor, grantee_uid: i32) {
    let grant = grant_descriptors_by_target()
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
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .clear();
    key_descriptor_route_targets()
        .lock()
        .expect("key-descriptor route map poisoned")
        .clear();
    grant_descriptors_by_target()
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
    fn tracks_key_id_and_grant_descriptors() {
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
    }

    #[test]
    fn forget_removes_grant_descriptor_route() {
        let _guard = state_test_guard();
        let surfaced = descriptor(Domain::GRANT, 1);

        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        forget_key_descriptor_route(&surfaced);

        assert_eq!(lookup_key_descriptor_route(&surfaced), None);
    }

    #[test]
    fn ungrant_target_retires_remembered_grant_descriptor() {
        let _guard = state_test_guard();
        let target = KeyDescriptor {
            domain: Domain::APP,
            nspace: 10001,
            alias: Some("alpha".to_string()),
            blob: None,
        };
        let surfaced = descriptor(Domain::GRANT, 1);

        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        remember_grant_descriptor_for_ungrant(&target, 10002, &surfaced);
        retire_grant_descriptor_after_ungrant(&target, 10002);

        assert_eq!(
            lookup_key_descriptor_route(&surfaced),
            Some(RouteTarget::System)
        );
    }
}
