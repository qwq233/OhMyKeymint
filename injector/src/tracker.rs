use crate::hook::binder::LocalBinderTarget;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevelTargetInfo {
    pub security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
}

static SECURITY_LEVEL_TARGETS: LazyLock<
    Mutex<HashMap<LocalBinderTarget, SecurityLevelTargetInfo>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

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
