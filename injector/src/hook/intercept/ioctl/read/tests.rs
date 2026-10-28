use crate::hook::intercept::fd::tests::invalidate_binder_fd;
use crate::hook::intercept::tests::{reset_binder_fd_for_test, SYNTHETIC_REPLY_TEST_LOCK};
use std::collections::VecDeque;

use super::super::tests::drain_transaction_completions;
use super::*;

static NODE_QUERY_RESULTS: Mutex<VecDeque<Result<binder_node_debug_info, c_int>>> =
    Mutex::new(VecDeque::new());

unsafe extern "C" fn node_query_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    assert_eq!(request, BINDER_GET_NODE_DEBUG_INFO as c_int);
    assert_eq!((*(arg as *const binder_node_debug_info)).ptr, 0x2f);
    let result = NODE_QUERY_RESULTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop_front()
        .expect("node query result should be queued");
    match result {
        Ok(info) => {
            std::ptr::write(arg as *mut binder_node_debug_info, info);
            0
        }
        Err(error) => {
            *libc::__errno() = error;
            -1
        }
    }
}

#[test]
fn operation_node_query_requires_an_exact_node() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let target = LocalBinderTarget {
        ptr: 0x30,
        cookie: 0x40,
    };
    reset_binder_fd_for_test(19);
    let binder = synchronize_binder_fd_generation(19).unwrap();
    let probe = OperationPublicationProbe {
        target,
        binder,
        generation: 1,
        not_before: Instant::now(),
        query_failures: 0,
    };
    let info = |ptr, cookie, has_strong_ref, has_weak_ref| binder_node_debug_info {
        ptr,
        cookie,
        has_strong_ref,
        has_weak_ref,
    };
    let queue = |results| {
        *NODE_QUERY_RESULTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = results;
    };

    queue(VecDeque::from([Ok(info(0x30, 0x40, 1, 0))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(true)
    );
    queue(VecDeque::from([Ok(info(0x30, 0x40, 0, 0))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(true)
    );
    queue(VecDeque::from([Ok(info(0x30, 0x40, 0, 1))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(true)
    );
    queue(VecDeque::from([Ok(info(0x50, 2, 0, 0))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(false)
    );
    queue(VecDeque::from([Ok(info(0x30, 0x41, 1, 0))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(false)
    );
    for error in [libc::EIO, libc::EBADF, libc::ENOTTY] {
        queue(VecDeque::from([Err(error)]));
        assert_eq!(
            unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
            Err(error)
        );
    }

    invalidate_binder_fd(19);
    queue(VecDeque::from([Ok(info(0x30, 0x40, 1, 0))]));
    assert_eq!(
        unsafe { operation_binder_node_exists(node_query_ioctl, probe) },
        Ok(false)
    );
    assert_eq!(
        NODE_QUERY_RESULTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len(),
        1,
        "retired publication must not query a reused Binder fd"
    );
    NODE_QUERY_RESULTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
    reset_binder_fd_for_test(19);
}

#[test]
fn terminal_results_preserve_nested_sync_completion_order() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 9;
    drain_transaction_completions(fd);

    record_transaction_completion(fd, false, true, None);
    assert_eq!(complete_transaction_submission(fd), Some(()));
    record_transaction_completion(fd, false, true, None);
    complete_failed_transaction_submission(fd, BR_DEAD_REPLY_NR);
    assert_eq!(complete_transaction_submission(fd), None);
    complete_failed_transaction_submission(fd, BR_FROZEN_REPLY_NR);
    assert!(!complete_sync_transaction(
        fd,
        SyncTransactionState::AwaitingReply
    ));

    record_transaction_completion(fd, false, true, None);
    assert_eq!(complete_transaction_submission(fd), Some(()));
    assert!(complete_sync_transaction(
        fd,
        SyncTransactionState::AwaitingReply
    ));
    record_transaction_completion(fd, false, true, None);
    complete_failed_transaction_submission(fd, BR_FAILED_REPLY_NR);
    assert_eq!(complete_transaction_submission(fd), None);

    record_transaction_completion(fd, false, true, None);
    assert_eq!(complete_transaction_submission(fd), Some(()));
    record_transaction_completion(fd, false, false, None);
    complete_failed_transaction_submission(fd, BR_DEAD_REPLY_NR);
    assert_eq!(complete_transaction_submission(fd), None);
    assert!(complete_sync_transaction(
        fd,
        SyncTransactionState::AwaitingReply
    ));
    drain_transaction_completions(fd);
}
