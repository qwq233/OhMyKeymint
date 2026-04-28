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
static KEY_ID_ROUTE_TARGETS: OnceLock<Mutex<HashMap<i64, RouteTarget>>> = OnceLock::new();
static SECURITY_LEVEL_CARRIERS: OnceLock<Mutex<HashMap<String, SecurityLevelCarrierBytes>>> =
    OnceLock::new();
static KEY_DESCRIPTOR_BRIDGES: OnceLock<Mutex<HashMap<i64, KeyDescriptorBridge>>> = OnceLock::new();

fn security_level_targets() -> &'static Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>> {
    SECURITY_LEVEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_id_route_targets() -> &'static Mutex<HashMap<i64, RouteTarget>> {
    KEY_ID_ROUTE_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn security_level_carriers() -> &'static Mutex<HashMap<String, SecurityLevelCarrierBytes>> {
    SECURITY_LEVEL_CARRIERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_descriptor_bridges() -> &'static Mutex<HashMap<i64, KeyDescriptorBridge>> {
    KEY_DESCRIPTOR_BRIDGES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_id_nspace(descriptor: &KeyDescriptor) -> Option<i64> {
    (descriptor.domain == Domain::KEY_ID).then_some(descriptor.nspace)
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
    let Some(key_id) = key_id_nspace(descriptor) else {
        return;
    };
    key_id_route_targets()
        .lock()
        .expect("key-id route map poisoned")
        .insert(key_id, route);
}

pub fn remember_key_metadata_route(metadata: &KeyMetadata, route: RouteTarget) {
    remember_key_descriptor_route(&metadata.key, route);
}

pub fn remember_key_descriptor_bridge(
    surfaced: &KeyDescriptor,
    system: &KeyDescriptor,
    omk: &KeyDescriptor,
) {
    let Some(key_id) = key_id_nspace(surfaced) else {
        return;
    };
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .insert(
            key_id,
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
    let Some(key_id) = key_id_nspace(descriptor) else {
        return;
    };
    key_id_route_targets()
        .lock()
        .expect("key-id route map poisoned")
        .remove(&key_id);
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .remove(&key_id);
}

pub fn lookup_key_descriptor_route(descriptor: &KeyDescriptor) -> Option<RouteTarget> {
    let key_id = key_id_nspace(descriptor)?;
    key_id_route_targets()
        .lock()
        .expect("key-id route map poisoned")
        .get(&key_id)
        .copied()
}

pub fn resolve_route_for_key_descriptor(
    descriptor: &KeyDescriptor,
    fallback: RouteTarget,
) -> RouteTarget {
    lookup_key_descriptor_route(descriptor).unwrap_or(fallback)
}

pub fn lookup_key_descriptor_bridge(descriptor: &KeyDescriptor) -> Option<KeyDescriptorBridge> {
    let key_id = key_id_nspace(descriptor)?;
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .get(&key_id)
        .cloned()
}

pub fn lookup_omk_descriptor_for_key(descriptor: &KeyDescriptor) -> Option<KeyDescriptor> {
    lookup_key_descriptor_bridge(descriptor).map(|bridge| bridge.omk)
}

#[cfg(test)]
pub fn clear_state_for_tests() {
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .clear();
    key_id_route_targets()
        .lock()
        .expect("key-id route map poisoned")
        .clear();
    security_level_carriers()
        .lock()
        .expect("security level carrier map poisoned")
        .clear();
    key_descriptor_bridges()
        .lock()
        .expect("key-descriptor bridge map poisoned")
        .clear();
}
