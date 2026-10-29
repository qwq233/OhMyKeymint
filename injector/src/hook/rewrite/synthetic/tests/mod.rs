use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use rsbinder::{Interface, StatusCode};

use super::*;
use crate::{
    android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
    android::system::keystore2::Domain::Domain,
    android::system::keystore2::EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
    android::system::keystore2::IKeystoreOperation::BnKeystoreOperation,
    android::system::keystore2::IKeystoreSecurityLevel::{
        BnKeystoreSecurityLevel, IKeystoreSecurityLevel as AospKeystoreSecurityLevel,
    },
    android::system::keystore2::KeyDescriptor::KeyDescriptor,
    android::system::keystore2::KeyEntryResponse::KeyEntryResponse,
    android::system::keystore2::KeyMetadata::KeyMetadata,
    hook::rewrite::tests::*,
};

mod carriers;
mod lifecycle;
mod probe;
mod race;

struct FakeAospSecurityLevel;

impl Interface for FakeAospSecurityLevel {}

impl AospKeystoreSecurityLevel for FakeAospSecurityLevel {
    fn r#createOperation(
        &self,
        _arg_key: &KeyDescriptor,
        _arg_operation_parameters:
            &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        _arg_forced: bool,
    ) -> rsbinder::BinderResult<CreateOperationResponse> {
        Err(StatusCode::UnknownTransaction.into())
    }

    fn r#generateKey(
        &self,
        _arg_key: &KeyDescriptor,
        _arg_attestation_key: Option<&KeyDescriptor>,
        _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        _arg_flags: i32,
        _arg_entropy: &[u8],
    ) -> rsbinder::BinderResult<KeyMetadata> {
        Err(StatusCode::UnknownTransaction.into())
    }

    fn r#importKey(
        &self,
        _arg_key: &KeyDescriptor,
        _arg_attestation_key: Option<&KeyDescriptor>,
        _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        _arg_flags: i32,
        _arg_key_data: &[u8],
    ) -> rsbinder::BinderResult<KeyMetadata> {
        Err(StatusCode::UnknownTransaction.into())
    }

    fn r#importWrappedKey(
        &self,
        _arg_key: &KeyDescriptor,
        _arg_wrapping_key: &KeyDescriptor,
        _arg_masking_key: Option<&[u8]>,
        _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        _arg_authenticators:
            &[crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec],
    ) -> rsbinder::BinderResult<KeyMetadata> {
        Err(StatusCode::UnknownTransaction.into())
    }

    fn r#convertStorageKeyToEphemeral(
        &self,
        _arg_storage_key: &KeyDescriptor,
    ) -> rsbinder::BinderResult<EphemeralStorageKeyResponse> {
        Err(StatusCode::UnknownTransaction.into())
    }

    fn r#deleteKey(&self, _arg_key: &KeyDescriptor) -> rsbinder::BinderResult<()> {
        Err(StatusCode::UnknownTransaction.into())
    }
}

fn fake_system_security_level_backend() -> rsbinder::Strong<dyn AospKeystoreSecurityLevel> {
    ensure_binder_process_state();
    BnKeystoreSecurityLevel::new_binder(FakeAospSecurityLevel)
}

static NEXT_TEST_TARGET_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_test_target() -> LocalBinderTarget {
    let id = NEXT_TEST_TARGET_ID.fetch_add(1, Ordering::Relaxed);
    LocalBinderTarget {
        ptr: (0x1000_0000_u64 | id) as libc::c_ulong,
        cookie: (0x2000_0000_u64 | id) as libc::c_ulong,
    }
}

fn take_ready_operation_publication_probe() -> Option<OperationPublicationProbe> {
    take_operation_publication_probe(
        Instant::now() + OPERATION_PUBLICATION_PROBE_GRACE + OPERATION_PUBLICATION_REPROBE_DELAY,
    )
}

fn binder_token(fd: i32) -> BinderFdToken {
    BinderFdToken { fd, generation: 0, connection: fd as BinderStateKey }
}

fn publication_retirement(target: LocalBinderTarget) -> NativeBinderRetirement {
    let generation = OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get(&target)
        .expect("operation publication should exist")
        .generation;
    NativeBinderRetirement { target, generation }
}

fn complete_test_publication(target: LocalBinderTarget, fd: i32) -> NativeBinderRetirement {
    let retirement = publication_retirement(target);
    bind_operation_publication_connection(retirement, fd as BinderStateKey);
    mark_operation_publication_completed(retirement, binder_token(fd));
    retirement
}

fn finish_operation_publication_probe_for_test(
    probe: OperationPublicationProbe,
    node_exists: Result<bool, i32>,
) -> Option<NativeBinderRetirement> {
    finish_operation_publication_probe(probe, node_exists, Instant::now())
}

pub(in crate::hook::rewrite) fn reset_state_for_tests() {
    OPERATION_TARGETS.lock().expect("operation target map poisoned").clear();
    OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned").clear();
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .clear();
    SYNTHETIC_SECURITY_LEVEL_TARGETS
        .lock()
        .expect("synthetic security-level target map poisoned")
        .clear();
    SYNTHETIC_TARGETS.lock().expect("synthetic target map poisoned").clear();
    let natives = NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .drain()
        .map(|(_, native)| native)
        .collect::<Vec<_>>();
    for native in &natives {
        native.disarm_retirement();
    }
}

pub(in crate::hook::rewrite) fn lookup_synthetic_target_info(
    target: LocalBinderTarget,
) -> Option<SyntheticTargetInfo> {
    SYNTHETIC_TARGETS.lock().expect("synthetic target map poisoned").get(&target).cloned()
}

pub(in crate::hook::rewrite) fn lookup_native_operation_state(
    target: LocalBinderTarget,
) -> Option<Arc<NativeOperationState>> {
    lookup_synthetic_target_info(target)?.operation?.upgrade()
}

fn current_operation_retirement(target: LocalBinderTarget) -> Option<NativeBinderRetirement> {
    let generation = SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .get(&target)
        .filter(|info| info.kind == SyntheticTargetKind::Operation)
        .and_then(|info| info.native_generation)?;
    Some(NativeBinderRetirement { target, generation })
}

fn drop_synthetic_operation_target(target: LocalBinderTarget) {
    if let Some(retirement) = current_operation_retirement(target) {
        drop_synthetic_operation_retirement(retirement);
        return;
    }
    OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned").remove(&target);
    let native = NATIVE_BINDERS.lock().expect("native binder map poisoned").remove(&target);
    if let Some(native) = native.as_ref() {
        native.disarm_retirement();
    }
    drop(native);

    retire_synthetic_operation_target(target);
}

fn retire_synthetic_operation_target(target: LocalBinderTarget) {
    let info = OPERATION_TARGETS.lock().expect("operation target map poisoned").remove(&target);
    let state = SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .remove(&target)
        .and_then(|info| info.operation)
        .and_then(|state| state.upgrade());
    if OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .contains_key(&target)
    {
        let now = Instant::now();
        {
            let mut probes = OPERATION_PUBLICATION_PROBES
                .lock()
                .expect("operation publication probe queue poisoned");
            let matching_probes = probes.iter_mut().filter(|probe| probe.target == target);
            for probe in matching_probes {
                probe.not_before = now;
            }
        }
        crate::hook::intercept::wake_operation_publication_worker();
    }

    if let Some(state) = state {
        state.retire();
    }
    abort_operation_target_info(target, info);
}

fn observe_synthetic_operation_release(target: LocalBinderTarget) {
    if lookup_synthetic_target(target) == Some(SyntheticTargetKind::Operation) {
        drop_synthetic_operation_target(target);
    }
}

pub(in crate::hook) fn register_operation_publication_for_test(
    target: LocalBinderTarget,
) -> NativeBinderRetirement {
    let generation =
        register_operation_publication(target).expect("test operation publication should register");
    NativeBinderRetirement { target, generation }
}
