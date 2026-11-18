use std::cell::Cell;

use log::debug;

thread_local! {
    static BYPASS_HOOK_DEPTH: Cell<u32> = Cell::default();
}

pub fn is_bypassed() -> bool {
    BYPASS_HOOK_DEPTH.try_with(|depth| depth.get() > 0).unwrap_or(true)
}

pub struct BypassGuard;

impl BypassGuard {
    pub fn enter() -> Self {
        let _ = BYPASS_HOOK_DEPTH.try_with(|depth| depth.set(depth.get() + 1));
        debug!("entered bypass scope");
        Self
    }
}

impl Drop for BypassGuard {
    fn drop(&mut self) {
        let _ = BYPASS_HOOK_DEPTH.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
        debug!("exited bypass scope");
    }
}
