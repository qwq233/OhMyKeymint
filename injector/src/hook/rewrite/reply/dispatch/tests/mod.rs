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
