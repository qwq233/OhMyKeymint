use super::SECURITY_LEVEL_TARGETS;
use std::sync::{Mutex, MutexGuard};

static STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn clear_state_for_tests() {
    SECURITY_LEVEL_TARGETS.lock().expect("security level target map poisoned").clear();
}

pub(crate) fn state_test_guard() -> MutexGuard<'static, ()> {
    let guard = STATE_TEST_LOCK.lock().expect("tracker test lock poisoned");
    clear_state_for_tests();
    guard
}
