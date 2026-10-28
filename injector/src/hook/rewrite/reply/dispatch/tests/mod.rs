use super::*;
use crate::android::system::keystore2::IKeystoreOperation::BnKeystoreOperation;
use crate::hook::rewrite::{reply::tests::*, tests::*};
use rsbinder::{ExceptionCode, StatusCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

mod base;
mod metadata;
mod one_way;
mod operation_dispatch;

#[test]
fn untracked_native_target_is_not_intercepted() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let empty = rsbinder::Parcel::new();
    let (tr, _data) = transaction_for_parcel(target, rsbinder::FIRST_CALL_TRANSACTION, empty);
    assert!(unsafe { handle_synthetic_br_transaction(&tr, None, "BR_TRANSACTION") }.is_none());
}

pub(in crate::hook::rewrite) unsafe fn handle_synthetic_br_transaction(
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
    command_name: &str,
) -> Option<SyntheticReply> {
    let target = target_from_transaction(tr)?;
    let info = lookup_synthetic_target_info(target)?;
    let state = info.operation.as_ref().and_then(Weak::upgrade);
    Some(handle_native_br_transaction(
        tr,
        info.kind,
        state.as_deref(),
        caller_sid,
        command_name,
    ))
}

unsafe fn build_synthetic_br_transaction_reply(
    tr: &binder_transaction_data,
    target: LocalBinderTarget,
    info: SyntheticTargetInfo,
    caller_sid: Option<String>,
    command_name: &str,
) -> anyhow::Result<SyntheticReply> {
    let state = info.operation.as_ref().and_then(Weak::upgrade);
    build_native_br_transaction_reply(
        tr,
        target,
        info.kind,
        state.as_deref(),
        info.caller.as_ref(),
        caller_sid,
        command_name,
    )
}
