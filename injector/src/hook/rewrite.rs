use super::binder::{
    binder_transaction_data, create_native_operation_binder, create_native_security_level_binder,
    describe_transaction_objects, format_target, parse_local_binder_target_from_parcel_bytes,
    LocalBinderTarget, NativeBinder, NativeBinderRetirement,
};
use super::{BinderFdToken, BinderStateKey};
use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation as AospKeystoreOperation;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::config;
use crate::filter::{self, FilterReason, PackageResolution};
use crate::forward::{self, BypassGuard};
use crate::identify::{
    self, AidlMetadataMethod, AuthorizationMethod, OperationMethod, SecurityLevelMethod,
    ServiceMethod,
};
use crate::ipc;
use crate::parcel::{
    self, ParsedAuthorizationRequest, ParsedMaintenanceRequest, ParsedOperationRequest,
    ParsedSecurityLevelRequest, ParsedServiceRequest,
};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::tracker::{self, SecurityLevelTargetInfo};
use log::{debug, info, warn};
use rsbinder::{ExceptionCode, Status, StatusCode, Strong};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, LazyLock, Mutex, Weak,
};
use std::time::{Duration, Instant};

use mirror::*;
use pending::*;
pub(super) use reply::handle_native_br_transaction;
use reply::*;
use request::*;
use synthetic::*;
pub(super) use synthetic::{
    bind_operation_publication_connection, cancel_operation_publication_acquire_pending,
    finish_local_operation_publication, finish_operation_publication_probe, lookup_native_binder,
    lookup_native_binder_for, lookup_synthetic_target,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, next_operation_publication_probe_deadline,
    operation_publication_acquire_is_pending, operation_publication_pending_acquire,
    retire_binder_connection_publications, retire_synthetic_operation_retirement,
    take_operation_publication_probe, NativeOperationState, OperationPublicationProbe,
    SyntheticReply, SyntheticTargetKind,
};
pub(crate) use synthetic::{drop_synthetic_operation_retirement, retire_native_operation_target};

pub(super) use pending::{
    abort_bc_reply, clear_binder_fd_thread_state, clear_outbound_reply_buffers, commit_bc_reply,
    handle_bc_reply, pending_reply_has_trusted_payload, pending_reply_requires_payload,
    push_native_pending_frame, push_pending_frame, remember_native_reply,
};
pub(super) use request::handle_br_transaction;

mod mirror;
mod pending;
mod reply;
mod request;
mod synthetic;
#[cfg(test)]
pub(super) mod tests;

type OutboundReply = parcel::OwnedReply;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteTarget {
    System,
    Omk,
}

type AospOperationBinder = Strong<dyn AospKeystoreOperation>;

fn evaluate_caller(
    caller: &CallerInfo,
    cfg: &config::InjectorConfig,
) -> crate::filter::FilterDecision {
    let uid = caller.uid as u32;
    let preflight = filter::evaluate(&cfg.scoop, &cfg.filter, uid, PackageResolution::Unknown);
    if matches!(
        preflight.reason,
        FilterReason::RejectedAndroidPackage | FilterReason::Disabled
    ) {
        return preflight;
    }

    let package_resolution = {
        let _guard = BypassGuard::enter();
        ipc::resolve_packages_for_uid(uid)
    };
    filter::evaluate(&cfg.scoop, &cfg.filter, uid, package_resolution)
}

fn precompute_omk_service_mutator_reply(
    request: &ParsedServiceRequest,
    caller: &CallerInfo,
) -> PrecomputedServiceReply {
    let _guard = BypassGuard::enter();
    match request {
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => match ipc::with_omk_once(|omk| {
            Ok(omk.r#updateSubcomponent(
                Some(caller),
                key,
                public_cert.as_deref(),
                certificate_chain.as_deref(),
            )?)
        }) {
            Ok(()) => PrecomputedServiceReply::UpdateSubcomponentSuccess,
            Err(error) => PrecomputedServiceReply::Error(precomputed_omk_error_reply(&error)),
        },
        ParsedServiceRequest::DeleteKey { key } => {
            match ipc::with_omk_once(|omk| Ok(omk.r#deleteKey(Some(caller), key)?)) {
                Ok(()) => PrecomputedServiceReply::DeleteKeySuccess,
                Err(error) => PrecomputedServiceReply::Error(precomputed_omk_error_reply(&error)),
            }
        }
        ParsedServiceRequest::Grant { .. } | ParsedServiceRequest::Ungrant { .. } => {
            precompute_omk_grant_service_reply_with(
                request,
                caller,
                |caller_info, key, grantee_uid, access_vector| {
                    ipc::with_omk_once(|omk| {
                        Ok(omk.r#grant(Some(caller_info), key, grantee_uid, access_vector)?)
                    })
                },
                |caller_info, key, grantee_uid| {
                    ipc::with_omk_once(|omk| {
                        Ok(omk.r#ungrant(Some(caller_info), key, grantee_uid)?)
                    })
                },
            )
        }
        _ => unreachable!("only service mutators are precomputed"),
    }
}

fn precompute_omk_grant_service_reply_with(
    request: &ParsedServiceRequest,
    caller: &CallerInfo,
    mut grant: impl FnMut(&CallerInfo, &KeyDescriptor, i32, i32) -> anyhow::Result<KeyDescriptor>,
    mut ungrant: impl FnMut(&CallerInfo, &KeyDescriptor, i32) -> anyhow::Result<()>,
) -> PrecomputedServiceReply {
    match request {
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => match grant(caller, key, *grantee_uid, *access_vector) {
            Ok(omk_grant) => PrecomputedServiceReply::GrantSuccess(omk_grant),
            Err(error) => PrecomputedServiceReply::Error(precomputed_omk_error_reply(&error)),
        },
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            match ungrant(caller, key, *grantee_uid) {
                Ok(()) => PrecomputedServiceReply::UngrantSuccess,
                Err(error) => PrecomputedServiceReply::Error(precomputed_omk_error_reply(&error)),
            }
        }
        _ => unreachable!("only grant/ungrant requests are precomputed"),
    }
}

unsafe fn transaction_parts(tr: &binder_transaction_data) -> (*mut u8, usize, *mut usize, usize) {
    (
        tr.data.ptr.buffer as *mut u8,
        tr.data_size,
        tr.data.ptr.offsets as *mut usize,
        tr.offsets_size,
    )
}

fn synthetic_fallback_reply() -> parcel::OwnedReply {
    build_service_specific_reply(ResponseCode::SYSTEM_ERROR.0)
        .expect("synthetic system-error status should serialize")
}

fn precompute_omk_migrate_reply(call: &PendingMaintenanceCall) -> PrecomputedMaintenanceReply {
    let ParsedMaintenanceRequest::MigrateKeyNamespace {
        source,
        destination,
    } = &call.request
    else {
        unreachable!(
            "OMK migrate precompute called for {:?}",
            call.request.method()
        );
    };
    debug_assert_eq!(call.route, RouteTarget::Omk);
    let _guard = BypassGuard::enter();
    match ipc::with_omk_maintenance_once(|maintenance| {
        Ok(maintenance.r#migrateKeyNamespace(Some(&call.caller), source, destination)?)
    }) {
        Ok(()) => PrecomputedMaintenanceReply::Success,
        Err(error) => PrecomputedMaintenanceReply::Error(precomputed_omk_error_reply(&error)),
    }
}
