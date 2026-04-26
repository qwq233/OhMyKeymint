use std::cell::Cell;

use log::debug;

thread_local! {
    static BYPASS_HOOK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

pub fn is_bypassed() -> bool {
    BYPASS_HOOK_DEPTH.with(|depth| depth.get() > 0)
}

pub struct BypassGuard;

impl BypassGuard {
    pub fn enter() -> Self {
        BYPASS_HOOK_DEPTH.with(|depth| depth.set(depth.get() + 1));
        debug!("[Injector][Bypass] entered bypass scope");
        Self
    }
}

impl Drop for BypassGuard {
    fn drop(&mut self) {
        BYPASS_HOOK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        debug!("[Injector][Bypass] exited bypass scope");
    }
}
