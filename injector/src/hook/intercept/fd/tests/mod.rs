use crate::hook::intercept::tests::{
    finish_local_operation_publication, register_operation_publication_for_test,
    reset_binder_fd_for_test, route_state_test_guard, SYNTHETIC_REPLY_TEST_LOCK,
};
use std::sync::{Barrier, LazyLock};
use std::time::Duration;

use super::*;

mod pinning;
mod registry;

static PINNED_IOCTL_ENTERED: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));
static PINNED_IOCTL_RELEASE: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));

unsafe extern "C" fn blocking_ioctl(_fd: c_int, _request: c_int, _arg: *mut c_void) -> c_int {
    PINNED_IOCTL_ENTERED.wait();
    PINNED_IOCTL_RELEASE.wait();
    0
}

#[test]
fn publication_deadline_wait_does_not_need_an_ioctl_wakeup() {
    let _ioctl_guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x6d00,
        cookie: 0x7d00,
    };
    let retirement = register_operation_publication_for_test(target);
    mark_operation_publication_completed(
        retirement,
        BinderFdToken {
            fd: 91,
            generation: 0,
            connection: 91,
        },
    );

    std::thread::spawn(wait_for_operation_publication_deadline)
        .join()
        .expect("deadline wait thread should not panic");
    let probe = take_operation_publication_probe(Instant::now())
        .expect("publication probe should be ready after its deadline");
    assert_eq!(probe.target, target);
    finish_local_operation_publication(retirement);
}

fn binder_fd_lifecycle(fd: c_int) -> Arc<BinderFdLifecycle> {
    let mut registry = binder_fd_registry();
    ensure_binder_fd_lifecycle(&mut registry, fd)
}

fn existing_binder_fd_lifecycle(fd: c_int) -> Option<Arc<BinderFdLifecycle>> {
    binder_fd_registry().by_fd.get(&fd).cloned()
}

pub(in crate::hook::intercept) fn binder_fd_token_is_current(token: BinderFdToken) -> bool {
    existing_binder_fd_lifecycle(token.fd).is_some_and(|lifecycle| {
        lifecycle.connection == token.connection
            && lifecycle
                .state
                .lock()
                .expect("binder fd lifecycle poisoned")
                .generation
                == token.generation
    })
}

pub(in crate::hook::intercept) fn invalidate_binder_fd(fd: c_int) {
    let _ = invalidate_binder_fd_token(binder_fd_token(fd));
}
