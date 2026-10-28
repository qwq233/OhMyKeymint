use super::{BinderStateKey, INBOUND_TRANSACTION_SHADOWS};
use libc::c_int;
use std::sync::Mutex;

pub(super) use crate::hook::binder::tests::{
    BC_FREE_BUFFER_CMD, BC_REPLY_CMD, BR_NOOP_CMD, BR_TRANSACTION_CMD,
};
pub(super) use crate::hook::rewrite::tests::{
    register_operation_publication_for_test, route_state_test_guard,
};
pub(super) use crate::hook::rewrite::{
    bind_operation_publication_connection, finish_local_operation_publication,
};

pub(super) static SYNTHETIC_REPLY_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn clear_inbound_transaction_shadows(connection: BinderStateKey) {
    INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned")
        .retain(|(shadow_connection, _), _| *shadow_connection != connection);
}

pub(super) fn reset_binder_fd_for_test(fd: c_int) {
    let retired = super::invalidate_binder_fd_token(super::binder_fd_token(fd));
    super::forget_current_thread_binder_fd(fd, retired);
}
