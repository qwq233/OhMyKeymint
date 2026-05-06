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

#[derive(Debug, Clone)]
pub struct SecurityLevelCarrierBytes {
    pub bytes: Vec<u8>,
    pub is_object: bool,
}

#[derive(Debug, Clone)]
pub struct KeyDescriptorBridge {
    pub system: KeyDescriptor,
    pub omk: KeyDescriptor,
}

static SECURITY_LEVEL_TARGETS: OnceLock<
    Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>>,
> = OnceLock::new();
static KEY_DESCRIPTOR_ROUTE_TARGETS: OnceLock<Mutex<HashMap<String, RouteTarget>>> =
    OnceLock::new();
static SECURITY_LEVEL_CARRIERS: OnceLock<Mutex<HashMap<String, SecurityLevelCarrierBytes>>> =
    OnceLock::new();
static KEY_DESCRIPTOR_BRIDGES: OnceLock<Mutex<HashMap<String, KeyDescriptorBridge>>> =
    OnceLock::new();
static GRANT_DESCRIPTORS_BY_TARGET: OnceLock<Mutex<HashMap<String, KeyDescriptor>>> =
    OnceLock::new();

fn security_level_targets() -> &'static Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>> {
    SECURITY_LEVEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_descriptor_route_targets() -> &'static Mutex<HashMap<String, RouteTarget>> {
    KEY_DESCRIPTOR_ROUTE_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn security_level_carriers() -> &'static Mutex<HashMap<String, SecurityLevelCarrierBytes>> {
    SECURITY_LEVEL_CARRIERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_descriptor_bridges() -> &'static Mutex<HashMap<String, KeyDescriptorBridge>> {
    KEY_DESCRIPTOR_BRIDGES.get_or_init(|| Mutex::new(HashMap::new()))
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

fn security_level_carrier_key(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    route: RouteTarget,
) -> String {
    format!("{security_level:?}:{route:?}")
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

pub(crate) fn remember_security_level_carrier(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    route: RouteTarget,
    carrier: SecurityLevelCarrierBytes,
) {
    security_level_carriers()
        .lock()
        .expect("security level carrier map poisoned")
        .insert(security_level_carrier_key(security_level, route), carrier);
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

pub(crate) fn lookup_security_level_carrier(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    route: RouteTarget,
) -> Option<SecurityLevelCarrierBytes> {
    security_level_carriers()
        .lock()
        .expect("security level carrier map poisoned")
        .get(&security_level_carrier_key(security_level, route))
        .cloned()
}

pub fn remember_key_descriptor_route(descriptor: &KeyDescriptor, route: RouteTarget) {
    let Some(key) = tracked_descriptor_key(descriptor) else {
        return;
    };
    key_descriptor_route_targets()
        .lock()
        .expect("key-descriptor route map poisoned")
        .insert(key.clone(), route);
    if route == RouteTarget::System {
        key_descriptor_bridges()
            .lock()
            .expect("key-descriptor bridge map poisoned")
            .remove(&key);
    }
}

pub fn remember_key_metadata_route(metadata: &KeyMetadata, route: RouteTarget) {
    remember_key_descriptor_route(&metadata.key, route);
}

pub fn remember_key_descriptor_bridge(
    surfaced: &KeyDescriptor,
    system: &KeyDescriptor,
    omk: &KeyDescriptor,
) {
    let Some(key) = tracked_descriptor_key(surfaced) else {
        return;
    };
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .insert(
            key,
            KeyDescriptorBridge {
                system: system.clone(),
                omk: omk.clone(),
            },
        );
}

pub fn remember_key_metadata_bridge(
    surfaced: &KeyMetadata,
    system: &KeyMetadata,
    omk: &KeyMetadata,
) {
    remember_key_descriptor_bridge(&surfaced.key, &system.key, &omk.key);
}

pub fn forget_key_descriptor_route(descriptor: &KeyDescriptor) {
    let Some(key) = tracked_descriptor_key(descriptor) else {
        return;
    };
    key_descriptor_route_targets()
        .lock()
        .expect("key-descriptor route map poisoned")
        .remove(&key);
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
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

pub fn lookup_key_descriptor_bridge(descriptor: &KeyDescriptor) -> Option<KeyDescriptorBridge> {
    let key = tracked_descriptor_key(descriptor)?;
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .get(&key)
        .cloned()
}

pub fn lookup_omk_descriptor_for_key(descriptor: &KeyDescriptor) -> Option<KeyDescriptor> {
    lookup_key_descriptor_bridge(descriptor).map(|bridge| bridge.omk)
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
    security_level_carriers()
        .lock()
        .expect("security level carrier map poisoned")
        .clear();
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .clear();
    grant_descriptors_by_target()
        .lock()
        .expect("grant target map poisoned")
        .clear();
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
        clear_state_for_tests();
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
    fn bridges_grant_descriptors() {
        clear_state_for_tests();
        let surfaced = descriptor(Domain::GRANT, 1);
        let system = descriptor(Domain::GRANT, 1);
        let omk = descriptor(Domain::GRANT, 2);

        remember_key_descriptor_bridge(&surfaced, &system, &omk);

        assert_eq!(lookup_omk_descriptor_for_key(&surfaced), Some(omk));
    }

    #[test]
    fn forget_removes_grant_descriptor_bridge_and_route() {
        clear_state_for_tests();
        let surfaced = descriptor(Domain::GRANT, 1);
        let system = descriptor(Domain::GRANT, 1);
        let omk = descriptor(Domain::GRANT, 2);

        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        remember_key_descriptor_bridge(&surfaced, &system, &omk);
        forget_key_descriptor_route(&surfaced);

        assert_eq!(lookup_key_descriptor_route(&surfaced), None);
        assert_eq!(lookup_omk_descriptor_for_key(&surfaced), None);
    }

    #[test]
    fn ungrant_target_retires_remembered_grant_descriptor() {
        clear_state_for_tests();
        let target = KeyDescriptor {
            domain: Domain::APP,
            nspace: 10001,
            alias: Some("alpha".to_string()),
            blob: None,
        };
        let surfaced = descriptor(Domain::GRANT, 1);
        let system = descriptor(Domain::GRANT, 1);
        let omk = descriptor(Domain::GRANT, 2);

        remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        remember_key_descriptor_bridge(&surfaced, &system, &omk);
        remember_grant_descriptor_for_ungrant(&target, 10002, &surfaced);
        retire_grant_descriptor_after_ungrant(&target, 10002);

        assert_eq!(
            lookup_key_descriptor_route(&surfaced),
            Some(RouteTarget::System)
        );
        assert_eq!(lookup_omk_descriptor_for_key(&surfaced), None);
    }
}
