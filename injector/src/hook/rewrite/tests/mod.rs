pub(super) use super::pending::tests::take_top_pending;
pub(in crate::hook) use super::pending::tests::{
    pending_reply_frame_claims_for_test, pending_reply_frame_count_for_test,
    reset_pending_reply_frames_for_test,
};
pub(super) use super::reply::tests::handle_synthetic_br_transaction;
pub(in crate::hook) use super::synthetic::tests::register_operation_publication_for_test;
pub(super) use super::synthetic::tests::{
    lookup_native_operation_state, lookup_synthetic_target_info,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use rsbinder::{Interface, Status};

use super::*;
use crate::{
    android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    android::hardware::security::keymint::Tag::Tag, android::system::keystore2::Domain::Domain,
    android::system::keystore2::IKeystoreOperation::IKeystoreOperation as AospKeystoreOperation,
    android::system::keystore2::KeyDescriptor::KeyDescriptor,
};

pub(super) fn ensure_binder_process_state() {
    let _ = rsbinder::ProcessState::init_default();
}

pub(super) fn sample_key_descriptor() -> KeyDescriptor {
    KeyDescriptor { domain: Domain::APP, nspace: 7, alias: Some("alias".to_string()), blob: None }
}

pub(super) fn sample_service_requests() -> Vec<ParsedServiceRequest> {
    vec![
        ParsedServiceRequest::GetSecurityLevel {
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        },
        ParsedServiceRequest::GetKeyEntry { key: sample_key_descriptor() },
        ParsedServiceRequest::UpdateSubcomponent {
            key: sample_key_descriptor(),
            public_cert: None,
            certificate_chain: None,
        },
        ParsedServiceRequest::ListEntries { domain: Domain::APP, nspace: 0 },
        ParsedServiceRequest::DeleteKey { key: sample_key_descriptor() },
        ParsedServiceRequest::Grant {
            key: sample_key_descriptor(),
            grantee_uid: 12345,
            access_vector: 7,
        },
        ParsedServiceRequest::Ungrant { key: sample_key_descriptor(), grantee_uid: 12345 },
        ParsedServiceRequest::GetNumberOfEntries { domain: Domain::APP, nspace: 0 },
        ParsedServiceRequest::ListEntriesBatched {
            domain: Domain::APP,
            nspace: 0,
            starting_past_alias: Some("alias".to_string()),
        },
        ParsedServiceRequest::GetSupplementaryAttestationInfo { tag: Tag::MODULE_HASH },
    ]
}

pub(super) fn disabled_intercept_config() -> config::InterceptConfig {
    config::InterceptConfig {
        get_security_level: false,
        get_key_entry: false,
        update_subcomponent: false,
        list_entries: false,
        delete_key: false,
        grant: false,
        ungrant: false,
        get_number_of_entries: false,
        list_entries_batched: false,
        get_supplementary_attestation_info: false,
    }
}

pub(super) struct TestOperationBackend {
    pub(super) update_output: Vec<u8>,
    pub(super) aborts: Arc<AtomicUsize>,
    pub(super) update_aad_status: Option<Status>,
}

impl Interface for TestOperationBackend {}

impl AospKeystoreOperation for TestOperationBackend {
    fn r#updateAad(&self, _aad_input: &[u8]) -> rsbinder::BinderResult<()> {
        match self.update_aad_status.as_ref() {
            Some(status) => Err(status.clone()),
            None => Ok(()),
        }
    }

    fn r#update(&self, _input: &[u8]) -> rsbinder::BinderResult<Option<Vec<u8>>> {
        Ok(Some(self.update_output.clone()))
    }

    fn r#finish(
        &self,
        _input: Option<&[u8]>,
        _signature: Option<&[u8]>,
    ) -> rsbinder::BinderResult<Option<Vec<u8>>> {
        Ok(Some(self.update_output.clone()))
    }

    fn r#abort(&self) -> rsbinder::BinderResult<()> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub(super) fn raw_parts(reply: &mut parcel::OwnedReply) -> (*mut u8, usize, *mut usize, usize) {
    (
        reply.data_mut_ptr(),
        reply.data_size(),
        if reply.offsets.is_empty() { std::ptr::null_mut() } else { reply.offsets.as_mut_ptr() },
        reply.offsets_size(),
    )
}

pub(super) fn carrier_target(carrier: &parcel::ReplyBinderCarrier) -> LocalBinderTarget {
    unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
        .expect("synthetic carrier should expose a native target")
}

pub(super) fn request_parcel(interface: &str) -> rsbinder::Parcel {
    request_parcel_with_marker(interface, rsbinder::INTERFACE_HEADER)
}

pub(super) fn request_parcel_with_marker(interface: &str, marker: u32) -> rsbinder::Parcel {
    let mut parcel = rsbinder::Parcel::new();
    parcel.write(&0i32).unwrap();
    parcel.write(&0i32).unwrap();
    parcel.write(&marker).unwrap();
    parcel.write(&interface.to_string()).unwrap();
    parcel
}

fn parcel_bytes(parcel: &mut rsbinder::Parcel) -> Vec<u8> {
    let original_position = parcel.data_position();
    let mut bytes = Vec::new();
    parcel.set_data_position(0);
    let mut cursor = parcel.data_position();
    let len = parcel.data_size();
    while cursor < len {
        let chunk: [u8; 4] = parcel.try_into().unwrap();
        bytes.extend_from_slice(&chunk);
        cursor += 4;
    }
    bytes.truncate(len);
    parcel.set_data_position(original_position);
    bytes
}

pub(super) fn transaction_for_parcel(
    target: LocalBinderTarget,
    code: rsbinder::TransactionCode,
    parcel: rsbinder::Parcel,
) -> (binder_transaction_data, Vec<u8>) {
    let mut parcel = parcel;
    let data = parcel_bytes(&mut parcel);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.target.ptr = target.ptr;
    tr.data.ptr.buffer = data.as_ptr() as libc::c_ulong;
    tr.data.ptr.offsets = 0;
    tr.cookie = target.cookie;
    tr.code = code;
    tr.sender_euid = 10002;
    tr.sender_pid = 2000;
    tr.data_size = data.len();
    tr.offsets_size = 0;
    (tr, data)
}

static ROUTE_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(in crate::hook) fn route_state_test_guard(
) -> (std::sync::MutexGuard<'static, ()>, std::sync::MutexGuard<'static, ()>) {
    let tracker_guard = tracker::tests::state_test_guard();
    let route_guard = ROUTE_STATE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_route_state_for_tests();
    (tracker_guard, route_guard)
}

pub(super) fn reset_route_state_for_tests() {
    tracker::tests::clear_state_for_tests();
    clear_operation_state_for_tests();
    super::pending::tests::reset_pending_state_for_tests();
}

pub(super) fn clear_operation_state_for_tests() {
    super::synthetic::tests::reset_state_for_tests();
}
