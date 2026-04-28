use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use log::{debug, info, warn};
use rsbinder::Parcel;

use super::binder::{
    binder_transaction_data, binder_transaction_data_target, describe_transaction_objects,
    format_target, parse_local_binder_target_from_parcel_bytes, LocalBinderTarget,
};
use crate::config;
use crate::filter::{self, FilterReason};
use crate::forward::{self, BypassGuard};
use crate::identify::{self, OperationMethod, SecurityLevelMethod, ServiceMethod};
use crate::ipc;
use crate::parcel::{
    self, ParsedOperationRequest, ParsedSecurityLevelRequest, ParsedServiceRequest,
};
use crate::route::{self, CallerIdentity, RouteTarget};
use crate::tracker::{self, SecurityLevelTargetInfo};

struct PendingServiceCall {
    request: ParsedServiceRequest,
    method: ServiceMethod,
    caller: CallerIdentity,
    packages: Vec<String>,
    route: RouteTarget,
    execution_mode: ServiceExecutionMode,
    redirect_applied: bool,
    _redirect_keepalive: Option<route::AospServiceBinder>,
}

struct PendingSecurityLevelCall {
    request: ParsedSecurityLevelRequest,
    method: SecurityLevelMethod,
    caller: CallerIdentity,
    packages: Vec<String>,
    route: RouteTarget,
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
}

struct PendingOperationCall {
    request: ParsedOperationRequest,
    method: OperationMethod,
    caller: CallerIdentity,
    packages: Vec<String>,
    target: LocalBinderTarget,
}

enum PendingCall {
    Service(PendingServiceCall),
    SecurityLevel(PendingSecurityLevelCall),
    Operation(PendingOperationCall),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceExecutionMode {
    RequestSide,
    ReplyRewrite,
}

struct LocalServiceRedirect {
    keepalive: route::AospServiceBinder,
    target: LocalBinderTarget,
    preferred_route: RouteTarget,
}

thread_local! {
    static PENDING_REPLY_STACK: RefCell<Vec<Option<PendingCall>>> = const { RefCell::new(Vec::new()) };
    static OUTBOUND_REPLY_BUFFERS: RefCell<Vec<parcel::OwnedReply>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone)]
struct OperationTargetInfo {
    route: RouteTarget,
    aad_allowed: bool,
    backend: Option<route::AospOperationBinder>,
}

static OPERATION_TARGETS: OnceLock<Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>>> =
    OnceLock::new();

fn should_attempt_request_side_redirect(
    _request: &ParsedServiceRequest,
    _allow_omk_route: bool,
) -> bool {
    // Live keystore2 traffic cannot safely traverse local rsbinder-backed
    // wrapper binders. Keep the helper around for unit coverage, but disable
    // request-side redirect until a libbinder-native wrapper exists.
    false
}

fn maybe_build_request_side_redirect(
    request: &ParsedServiceRequest,
    caller: &CallerIdentity,
    intercept: &config::InterceptConfig,
    allow_omk_route: bool,
) -> Option<LocalServiceRedirect> {
    if !should_attempt_request_side_redirect(request, allow_omk_route) {
        return None;
    }

    // A system-only local redirect currently regresses live traffic in keystore2:
    // the process dispatches incoming BR_TRANSACTIONs through libbinder, while
    // our synthetic wrapper binders are created by rsbinder on a different binder
    // runtime. Until the local wrapper is backed by the same binder runtime as
    // keystore2 itself, preserve the original system target when OMK is not
    // actually available for this request.
    if !allow_omk_route {
        return None;
    }

    let system_backend = {
        let _guard = BypassGuard::enter();
        match ipc::get_system_keystore_service() {
            Ok(service) => service,
            Err(error) => {
                warn!(
                    "[Injector][Route] request-side redirect could not fetch system keystore service: {:#}",
                    error
                );
                return None;
            }
        }
    };

    let omk_backend = {
        if allow_omk_route {
            let _guard = BypassGuard::enter();
            match ipc::get_omk() {
                Ok(service) => Some(service),
                Err(error) => {
                    warn!(
                        "[Injector][Route] request-side redirect could not fetch omk service; wrapper will fall back to system only: {:#}",
                        error
                    );
                    return None;
                }
            }
        } else {
            None
        }
    };

    build_request_side_redirect_with_backends(
        request,
        caller.clone(),
        intercept.clone(),
        allow_omk_route,
        system_backend,
        omk_backend,
    )
}

fn build_request_side_redirect_with_backends(
    request: &ParsedServiceRequest,
    caller: CallerIdentity,
    intercept: config::InterceptConfig,
    allow_omk_route: bool,
    system_backend: route::AospServiceBinder,
    omk_backend: Option<route::OmkServiceBinder>,
) -> Option<LocalServiceRedirect> {
    if !should_attempt_request_side_redirect(request, allow_omk_route) {
        return None;
    }

    if !allow_omk_route || omk_backend.is_none() {
        return None;
    }

    let keepalive = route::new_service_binder(
        caller,
        intercept,
        allow_omk_route,
        system_backend,
        omk_backend.clone(),
    );
    let target = match extract_local_service_target(&keepalive) {
        Ok(target) => target,
        Err(error) => {
            warn!(
                "[Injector][Route] request-side redirect could not extract local service target: {:#}",
                error
            );
            return None;
        }
    };

    Some(LocalServiceRedirect {
        keepalive,
        target,
        preferred_route: if allow_omk_route && omk_backend.is_some() {
            RouteTarget::Omk
        } else {
            RouteTarget::System
        },
    })
}

fn extract_local_service_target(
    binder: &route::AospServiceBinder,
) -> anyhow::Result<LocalBinderTarget> {
    let mut parcel = Parcel::new();
    let binder_to_write: Option<route::AospServiceBinder> = Some(binder.clone());
    parcel.write(&binder_to_write)?;
    let bytes = unsafe { std::slice::from_raw_parts(parcel.as_ptr(), parcel.data_size()) };
    unsafe { parse_local_binder_target_from_parcel_bytes(bytes) }
        .ok_or_else(|| anyhow::anyhow!("failed to parse local service binder target from parcel"))
}

unsafe fn apply_request_side_redirect(tr: &mut binder_transaction_data, target: LocalBinderTarget) {
    tr.target = binder_transaction_data_target { ptr: target.ptr };
    tr.cookie = target.cookie;
}

fn evaluate_caller(
    caller: &CallerIdentity,
    cfg: &config::InjectorConfig,
) -> crate::filter::FilterDecision {
    let package_resolution = {
        let _guard = BypassGuard::enter();
        ipc::resolve_packages_for_uid(caller.uid)
    };
    let decision = filter::evaluate(&cfg.scoop, &cfg.filter, package_resolution);
    if decision.reason == FilterReason::Disabled {
        debug!(
            "[Injector][Decision] package filter disabled; routing still follows per-method intercept settings"
        );
    }
    decision
}

fn target_from_transaction(tr: &binder_transaction_data) -> Option<LocalBinderTarget> {
    let ptr = unsafe { tr.target.ptr };
    if ptr == 0 || tr.cookie == 0 {
        return None;
    }

    Some(LocalBinderTarget {
        ptr,
        cookie: tr.cookie,
    })
}

fn service_execution_mode(method: ServiceMethod) -> ServiceExecutionMode {
    let _ = method;
    ServiceExecutionMode::ReplyRewrite
}

fn route_for_service_request(
    request: &ParsedServiceRequest,
    intercept: &config::InterceptConfig,
) -> RouteTarget {
    let fallback = if identify::is_omk_service_route_enabled(request.method(), intercept) {
        RouteTarget::Omk
    } else {
        RouteTarget::System
    };
    match request {
        ParsedServiceRequest::GetKeyEntry { key }
        | ParsedServiceRequest::UpdateSubcomponent { key, .. }
        | ParsedServiceRequest::DeleteKey { key } => {
            tracker::resolve_route_for_key_descriptor(key, fallback)
        }
        ParsedServiceRequest::GetSecurityLevel { .. } => fallback,
        ParsedServiceRequest::ListEntries { .. }
        | ParsedServiceRequest::Grant { .. }
        | ParsedServiceRequest::Ungrant { .. }
        | ParsedServiceRequest::GetNumberOfEntries { .. }
        | ParsedServiceRequest::ListEntriesBatched { .. }
        | ParsedServiceRequest::GetSupplementaryAttestationInfo { .. } => RouteTarget::System,
    }
}

fn route_for_security_level_request(
    request: &ParsedSecurityLevelRequest,
    carrier_route: RouteTarget,
) -> RouteTarget {
    match request {
        ParsedSecurityLevelRequest::CreateOperation { key, .. }
        | ParsedSecurityLevelRequest::DeleteKey { key }
        | ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key: key } => {
            tracker::resolve_route_for_key_descriptor(key, carrier_route)
        }
        _ => carrier_route,
    }
}

fn operation_targets() -> &'static Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>> {
    OPERATION_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_operation_target(target: LocalBinderTarget, info: OperationTargetInfo) {
    operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .insert(target, info);
}

fn lookup_operation_target(target: LocalBinderTarget) -> Option<OperationTargetInfo> {
    operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .get(&target)
        .cloned()
}

fn forget_operation_target(target: LocalBinderTarget) {
    operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .remove(&target);
}

fn rewrite_create_operation_reply_with_native_carrier(
    omk_response: crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
    carrier: &parcel::ReplyBinderCarrier,
    aad_allowed: bool,
) -> anyhow::Result<parcel::OwnedReply> {
    if !carrier.is_object {
        anyhow::bail!("system createOperation carrier was null");
    }

    let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
        .ok_or_else(|| anyhow::anyhow!("failed to parse local operation carrier target"))?;
    let backend = omk_response
        .r#iOperation
        .clone()
        .ok_or_else(|| anyhow::anyhow!("OMK createOperation returned a null operation binder"))?;
    let reply = parcel::build_create_operation_reply_with_carrier_bytes(
        omk_response.r#operationChallenge,
        omk_response.r#parameters,
        omk_response.r#upgradedBlob,
        &carrier.bytes,
        carrier.is_object,
    )?;
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed,
            backend: Some(backend),
        },
    );
    info!(
        "[Injector][Route] registered operation carrier ptr=0x{:x} cookie=0x{:x} preferred_route={:?} aad_allowed={}",
        target.ptr,
        target.cookie,
        RouteTarget::Omk,
        aad_allowed,
    );
    Ok(reply)
}

fn operation_allows_aad(
    parameters: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
) -> bool {
    parameters.iter().any(|parameter| {
        parameter.tag
            == crate::android::hardware::security::keymint::Tag::Tag::BLOCK_MODE
            && matches!(
                parameter.value,
                crate::android::hardware::security::keymint::KeyParameterValue::KeyParameterValue::BlockMode(
                    crate::android::hardware::security::keymint::BlockMode::BlockMode::GCM
                )
            )
    })
}

unsafe fn register_operation_target_from_reply(
    tr: &binder_transaction_data,
    route: RouteTarget,
    backend: Option<route::AospOperationBinder>,
    aad_allowed: bool,
) -> anyhow::Result<()> {
    let carrier = match parcel::extract_create_operation_reply_carrier(
        tr.data.ptr.buffer as *mut u8,
        tr.data_size as usize,
        tr.data.ptr.offsets as *mut usize,
        tr.offsets_size as usize,
    ) {
        Ok(carrier) => carrier,
        Err(_) => return Ok(()),
    };
    if !carrier.is_object {
        return Ok(());
    }

    let target = parse_local_binder_target_from_parcel_bytes(&carrier.bytes)
        .ok_or_else(|| anyhow::anyhow!("failed to parse local operation carrier target"))?;
    remember_operation_target(
        target,
        OperationTargetInfo {
            route,
            aad_allowed,
            backend,
        },
    );
    info!(
        "[Injector][Route] observed operation carrier ptr=0x{:x} cookie=0x{:x} preferred_route={:?} aad_allowed={}",
        target.ptr,
        target.cookie,
        route,
        aad_allowed,
    );
    Ok(())
}

pub(super) unsafe fn handle_br_transaction(
    tr: &mut binder_transaction_data,
    caller_sid: Option<String>,
    command_name: &str,
) -> bool {
    let expects_reply = (tr.flags & super::binder::TF_ONE_WAY) == 0;
    if expects_reply {
        push_pending_frame();
    }

    if forward::is_bypassed() {
        debug!(
            "[Injector][Bypass] skipped {} code=0x{:x} uid={} pid={}",
            command_name, tr.code, tr.sender_euid, tr.sender_pid
        );
        return false;
    }

    let cfg = config::get();
    if !cfg.main.enabled {
        debug!("[Injector][Decision] injector disabled by config");
        return false;
    }

    let Some(parcel_bytes) = super::binder::transaction_data_bytes(tr) else {
        warn!(
            "[Injector][Decision] null parcel buffer for {} code=0x{:x} uid={} pid={}",
            command_name, tr.code, tr.sender_euid, tr.sender_pid
        );
        return false;
    };

    let caller = CallerIdentity::new(tr.sender_euid.max(0) as u32, tr.sender_pid)
        .with_sid(caller_sid.unwrap_or_default());
    let decision = evaluate_caller(&caller, &cfg);

    if parcel::contains_keystore_service_interface(parcel_bytes) {
        let request = match parcel::parse_service_request(
            tr.data.ptr.buffer as *mut u8,
            tr.data_size as usize,
            tr.data.ptr.offsets as *mut usize,
            tr.offsets_size as usize,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "[Injector][Decision] failed to parse IKeystoreService request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        if !decision.allowed {
            info!(
                "[Injector][Decision] command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=false reason={:?}; leaving original request untouched",
                command_name,
                method,
                tr.code,
                caller.uid,
                caller.pid,
                caller.sid,
                decision.packages,
                decision.reason,
            );
            return false;
        }

        let route = route_for_service_request(&request, &cfg.intercept);
        let execution_mode = service_execution_mode(method);
        let mut redirect_applied = false;
        let mut redirect_keepalive = None;
        if execution_mode == ServiceExecutionMode::RequestSide {
            if let Some(redirect) = maybe_build_request_side_redirect(
                &request,
                &caller,
                &cfg.intercept,
                route == RouteTarget::Omk,
            ) {
                debug_assert_eq!(redirect.preferred_route, route);
                apply_request_side_redirect(tr, redirect.target);
                redirect_applied = true;
                redirect_keepalive = Some(redirect.keepalive);
            }
        }

        info!(
            "[Injector][Decision] command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={} reason={:?}",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
            decision.packages,
            decision.allowed,
            decision.reason,
        );
        info!(
            "[Injector][Route] method={:?} uid={} pid={} route={:?} execution_mode={:?} redirect_applied={}",
            method,
            caller.uid,
            caller.pid,
            route,
            execution_mode,
            redirect_applied
        );

        if expects_reply {
            replace_top_pending(PendingCall::Service(PendingServiceCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route,
                execution_mode,
                redirect_applied,
                _redirect_keepalive: redirect_keepalive,
            }));
        }
        return redirect_applied;
    }

    let Some(target) = target_from_transaction(tr) else {
        if parcel::contains_known_keystore_interface(parcel_bytes) {
            debug!(
                "[Injector][Decision] skipping keystore request without local target code=0x{:x} target={}",
                tr.code,
                format_target(tr)
            );
        }
        return false;
    };

    if parcel::contains_keystore_security_level_interface(parcel_bytes) {
        let Some(target_info) = tracker::lookup_security_level_target(target) else {
            debug!(
                "[Injector][Decision] skipping IKeystoreSecurityLevel request for unmapped target ptr=0x{:x} cookie=0x{:x}",
                target.ptr, target.cookie
            );
            return false;
        };

        let request = match parcel::parse_security_level_request(
            tr.data.ptr.buffer as *mut u8,
            tr.data_size as usize,
            tr.data.ptr.offsets as *mut usize,
            tr.offsets_size as usize,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "[Injector][Decision] failed to parse IKeystoreSecurityLevel request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        if !decision.allowed {
            info!(
                "[Injector][Decision] command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=false reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?}; leaving original request untouched",
                command_name,
                method,
                tr.code,
                caller.uid,
                caller.pid,
                caller.sid,
                decision.packages,
                decision.reason,
                target.ptr,
                target.cookie,
                target_info.security_level,
            );
            return false;
        }

        let route = route_for_security_level_request(&request, target_info.preferred_route);

        info!(
            "[Injector][Decision] command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={} reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?} source_method={:?}",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
            decision.packages,
            decision.allowed,
            decision.reason,
            target.ptr,
            target.cookie,
            target_info.security_level,
            target_info.source_method,
        );
        info!(
            "[Injector][Route] security_level_method={:?} uid={} pid={} route={:?} security_level={:?}",
            method, caller.uid, caller.pid, route, target_info.security_level
        );

        if expects_reply {
            replace_top_pending(PendingCall::SecurityLevel(PendingSecurityLevelCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route,
                security_level: target_info.security_level,
            }));
        }
        return false;
    }

    if parcel::contains_keystore_operation_interface(parcel_bytes) {
        if lookup_operation_target(target).is_none() {
            debug!(
                "[Injector][Decision] skipping IKeystoreOperation request for unmapped target ptr=0x{:x} cookie=0x{:x}",
                target.ptr, target.cookie
            );
            return false;
        }

        let request = match parcel::parse_operation_request(
            tr.data.ptr.buffer as *mut u8,
            tr.data_size as usize,
            tr.data.ptr.offsets as *mut usize,
            tr.offsets_size as usize,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "[Injector][Decision] failed to parse IKeystoreOperation request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        if !decision.allowed {
            info!(
                "[Injector][Decision] command={} operation_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=false reason={:?} target=ptr:0x{:x}/cookie:0x{:x}; leaving original request untouched",
                command_name,
                method,
                tr.code,
                caller.uid,
                caller.pid,
                caller.sid,
                decision.packages,
                decision.reason,
                target.ptr,
                target.cookie,
            );
            return false;
        }

        info!(
            "[Injector][Decision] command={} operation_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} target=ptr:0x{:x}/cookie:0x{:x}",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
            decision.packages,
            target.ptr,
            target.cookie,
        );
        info!(
            "[Injector][Route] operation_method={:?} uid={} pid={} route={:?}",
            method,
            caller.uid,
            caller.pid,
            RouteTarget::Omk
        );

        if expects_reply {
            replace_top_pending(PendingCall::Operation(PendingOperationCall {
                request,
                method,
                caller,
                packages: decision.packages,
                target,
            }));
        }
        return false;
    }

    if parcel::contains_known_keystore_interface(parcel_bytes) {
        debug!(
            "[Injector][Decision] skipping unsupported keystore interface request code=0x{:x}",
            tr.code
        );
    }

    false
}

pub(super) unsafe fn handle_bc_reply(tr: &mut binder_transaction_data) {
    let Some(pending) = take_top_pending() else {
        return;
    };

    if let Some(pending) = pending {
        let original_data_size = tr.data_size;
        let original_offsets_size = tr.offsets_size;
        let original_flags = tr.flags;
        let original_objects = describe_transaction_objects(tr);

        let result = match &pending {
            PendingCall::Service(call) => {
                debug!(
                    "[Injector][Reply] handling service {:?} route={:?} uid={} pid={} packages={:?}",
                    call.method, call.route, call.caller.uid, call.caller.pid, call.packages
                );
                build_service_reply_rewrite(tr, call).map(|reply| {
                    reply.map(|reply| {
                        (
                            "service",
                            format!("{:?}", call.method),
                            call.caller.uid,
                            call.caller.pid,
                            reply,
                        )
                    })
                })
            }
            PendingCall::SecurityLevel(call) => {
                debug!(
                    "[Injector][Reply] handling security-level {:?} route={:?} uid={} pid={} packages={:?} security_level={:?}",
                    call.method, call.route, call.caller.uid, call.caller.pid, call.packages, call.security_level
                );
                build_security_level_reply_rewrite(tr, call).map(|reply| {
                    reply.map(|reply| {
                        (
                            "security-level",
                            format!("{:?}", call.method),
                            call.caller.uid,
                            call.caller.pid,
                            reply,
                        )
                    })
                })
            }
            PendingCall::Operation(call) => {
                debug!(
                    "[Injector][Reply] handling operation {:?} uid={} pid={} packages={:?} target=ptr:0x{:x}/cookie:0x{:x}",
                    call.method, call.caller.uid, call.caller.pid, call.packages, call.target.ptr, call.target.cookie
                );
                build_operation_reply_rewrite(call).map(|reply| {
                    reply.map(|reply| {
                        (
                            "operation",
                            format!("{:?}", call.method),
                            call.caller.uid,
                            call.caller.pid,
                            reply,
                        )
                    })
                })
            }
        };

        match result {
            Ok(Some((kind, method, uid, pid, reply))) => {
                install_outbound_reply(tr, reply);
                info!(
                    "[Injector][Reply] rewrote {} {} reply for uid={} pid={} original={{flags=0x{:x}, data_size={}, offsets_size={}, objects={}}} rewritten={{flags=0x{:x}, data_size={}, offsets_size={}, objects={}}}",
                    kind,
                    method,
                    uid,
                    pid,
                    original_flags,
                    original_data_size,
                    original_offsets_size,
                    original_objects,
                    tr.flags,
                    tr.data_size,
                    tr.offsets_size,
                    describe_transaction_objects(tr),
                );
            }
            Ok(None) => {}
            Err(error) => {
                warn!(
                    "[Injector][Reply] failed to rewrite pending reply: {:#}; keeping original system reply",
                    error
                );
            }
        }
    }

    pop_pending_frame();
}

fn register_security_level_carrier(
    carrier: &parcel::ReplyBinderCarrier,
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    preferred_route: RouteTarget,
    source_method: ServiceMethod,
) -> anyhow::Result<()> {
    if !carrier.is_object {
        warn!(
            "[Injector][Route] system security-level carrier for {:?} was null; skipping mapping",
            security_level
        );
        return Ok(());
    }

    let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
        .ok_or_else(|| anyhow::anyhow!("failed to parse local security-level carrier target"))?;
    tracker::remember_security_level_target(
        target,
        SecurityLevelTargetInfo {
            security_level,
            preferred_route,
            source_method,
        },
    );
    tracker::remember_security_level_carrier(
        security_level,
        preferred_route,
        tracker::SecurityLevelCarrierBytes {
            bytes: carrier.bytes.clone(),
            is_object: carrier.is_object,
        },
    );
    info!(
        "[Injector][Route] registered security-level carrier ptr=0x{:x} cookie=0x{:x} security_level={:?} preferred_route={:?} source_method={:?}",
        target.ptr, target.cookie, security_level, preferred_route, source_method
    );
    Ok(())
}

fn omk_descriptor_for_app_key(
    key: &crate::android::system::keystore2::KeyDescriptor::KeyDescriptor,
) -> crate::android::system::keystore2::KeyDescriptor::KeyDescriptor {
    tracker::lookup_omk_descriptor_for_key(key).unwrap_or_else(|| key.clone())
}

fn surface_omk_metadata_with_system_descriptor(
    system_metadata: &crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    mut omk_metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
) -> crate::android::system::keystore2::KeyMetadata::KeyMetadata {
    omk_metadata.r#key = system_metadata.r#key.clone();
    omk_metadata
}

unsafe fn observe_system_service_reply(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<()> {
    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } if !pending.redirect_applied => {
            let carrier = parcel::extract_direct_binder_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )?;
            register_security_level_carrier(
                &carrier,
                *security_level,
                RouteTarget::System,
                ServiceMethod::GetSecurityLevel,
            )?;
        }
        ParsedServiceRequest::GetKeyEntry { .. } if !pending.redirect_applied => {
            let metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                match parcel::parse_key_entry_reply_metadata(
                    tr.data.ptr.buffer as *mut u8,
                    tr.data_size as usize,
                    tr.data.ptr.offsets as *mut usize,
                    tr.offsets_size as usize,
                ) {
                    Ok(response) => response,
                    Err(_) => return Ok(()),
                };
            let carrier = parcel::extract_key_entry_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )?;
            register_security_level_carrier(
                &carrier,
                metadata.r#keySecurityLevel,
                RouteTarget::System,
                ServiceMethod::GetKeyEntry,
            )?;
            tracker::remember_key_metadata_route(&metadata, RouteTarget::System);
        }
        ParsedServiceRequest::DeleteKey { key } => {
            let status = match parcel::parse_reply_status(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            ) {
                Ok(status) => status,
                Err(_) => return Ok(()),
            };
            if status.is_ok() {
                tracker::forget_key_descriptor_route(key);
            }
        }
        _ => {}
    }
    Ok(())
}

unsafe fn build_service_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    if pending.execution_mode == ServiceExecutionMode::RequestSide {
        if !pending.redirect_applied {
            observe_system_service_reply(tr, pending)?;
        }
        return Ok(None);
    }

    if pending.route != RouteTarget::Omk {
        observe_system_service_reply(tr, pending)?;
        return Ok(None);
    }

    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();

    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } => {
            let carrier = match parcel::extract_direct_binder_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            ) {
                Ok(carrier) => carrier,
                Err(error) => {
                    warn!(
                        "[Injector][Reply] could not observe system getSecurityLevel carrier for uid={} pid={}: {:#}; preserving original reply without OMK carrier mapping",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    return Ok(None);
                }
            };
            if let Err(error) = register_security_level_carrier(
                &carrier,
                *security_level,
                RouteTarget::Omk,
                ServiceMethod::GetSecurityLevel,
            ) {
                warn!(
                    "[Injector][Reply] could not register OMK-preferred system getSecurityLevel carrier for uid={} pid={}: {:#}; preserving original reply without OMK carrier mapping",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
            }
            Ok(None)
        }
        ParsedServiceRequest::GetKeyEntry { key } => {
            let omk_key = omk_descriptor_for_app_key(key);
            let entry = match ipc::with_omk_retry(|omk| {
                Ok(omk.r#getKeyEntry(Some(&caller), &omk_key)?)
            }) {
                Ok(entry) => entry,
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK getKeyEntry failed for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    observe_system_service_reply(tr, pending)?;
                    return Ok(None);
                }
            };
            let system_metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                match parcel::parse_key_entry_reply_metadata(
                    tr.data.ptr.buffer as *mut u8,
                    tr.data_size as usize,
                    tr.data.ptr.offsets as *mut usize,
                    tr.offsets_size as usize,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        warn!(
                            "[Injector][Reply] OMK getKeyEntry could not parse the original system metadata for uid={} pid={}: {:#}; preserving original system reply",
                            pending.caller.uid,
                            pending.caller.pid,
                            error
                        );
                        observe_system_service_reply(tr, pending)?;
                        return Ok(None);
                    }
                };
            let omk_descriptor = entry.r#metadata.r#key.clone();
            let surfaced_metadata =
                surface_omk_metadata_with_system_descriptor(&system_metadata, entry.r#metadata);
            let carrier = match parcel::extract_key_entry_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            ) {
                Ok(carrier) => carrier,
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK getKeyEntry could not reuse the original system carrier for uid={} pid={}: {:#}; falling back to a fetched system security-level carrier",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    return build_omk_key_entry_reply_with_fetched_carrier(
                        surfaced_metadata,
                        pending,
                    );
                }
            };
            if let Err(error) = register_security_level_carrier(
                &carrier,
                surfaced_metadata.r#keySecurityLevel,
                RouteTarget::Omk,
                ServiceMethod::GetKeyEntry,
            ) {
                warn!(
                    "[Injector][Reply] OMK getKeyEntry could not register the rewritten carrier for uid={} pid={}: {:#}; preserving original system reply",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
                observe_system_service_reply(tr, pending)?;
                return Ok(None);
            }
            tracker::remember_key_descriptor_bridge(
                &surfaced_metadata.r#key,
                &system_metadata.r#key,
                &omk_descriptor,
            );
            tracker::remember_key_metadata_route(&surfaced_metadata, RouteTarget::Omk);
            Ok(Some(parcel::build_key_entry_reply_with_carrier_bytes(
                surfaced_metadata,
                &carrier.bytes,
                carrier.is_object,
            )?))
        }
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => {
            let system_status = parcel::parse_reply_status(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )
            .ok();
            if !matches!(system_status, Some(ref status) if status.is_ok()) {
                return Ok(None);
            }

            let omk_key = omk_descriptor_for_app_key(key);
            match ipc::with_omk_retry(|omk| {
                Ok(omk.r#updateSubcomponent(
                    Some(&caller),
                    &omk_key,
                    public_cert.as_deref(),
                    certificate_chain.as_deref(),
                )?)
            }) {
                Ok(()) => Ok(None),
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK updateSubcomponent failed for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    Ok(None)
                }
            }
        }
        ParsedServiceRequest::ListEntries { .. }
        | ParsedServiceRequest::Grant { .. }
        | ParsedServiceRequest::Ungrant { .. }
        | ParsedServiceRequest::GetNumberOfEntries { .. }
        | ParsedServiceRequest::ListEntriesBatched { .. }
        | ParsedServiceRequest::GetSupplementaryAttestationInfo { .. } => Ok(None),
        ParsedServiceRequest::DeleteKey { key } => {
            let system_status = parcel::parse_reply_status(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )
            .ok();
            let omk_key = omk_descriptor_for_app_key(key);

            match ipc::with_omk_retry(|omk| Ok(omk.r#deleteKey(Some(&caller), &omk_key)?)) {
                Ok(()) => {
                    tracker::forget_key_descriptor_route(key);
                    if matches!(system_status, Some(ref status) if status.is_ok()) {
                        return Ok(None);
                    }
                    Ok(Some(parcel::build_void_reply()?))
                }
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK deleteKey failed for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    observe_system_service_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
    }
}

fn build_omk_key_entry_reply_with_fetched_carrier(
    metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    _pending: &PendingServiceCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let security_level = metadata.r#keySecurityLevel;
    let Some(carrier) = tracker::lookup_security_level_carrier(security_level, RouteTarget::Omk)
    else {
        return Ok(None);
    };
    register_security_level_carrier(
        &parcel::ReplyBinderCarrier {
            bytes: carrier.bytes.clone(),
            is_object: carrier.is_object,
        },
        security_level,
        RouteTarget::Omk,
        ServiceMethod::GetKeyEntry,
    )?;
    tracker::remember_key_metadata_route(&metadata, RouteTarget::Omk);
    Ok(Some(parcel::build_key_entry_reply_with_carrier_bytes(
        metadata,
        &carrier.bytes,
        carrier.is_object,
    )?))
}

unsafe fn observe_system_security_level_reply(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<()> {
    match &pending.request {
        ParsedSecurityLevelRequest::GenerateKey { .. }
        | ParsedSecurityLevelRequest::ImportKey { .. }
        | ParsedSecurityLevelRequest::ImportWrappedKey { .. } => {
            let metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                match parcel::parse_success_reply(
                    tr.data.ptr.buffer as *mut u8,
                    tr.data_size as usize,
                    tr.data.ptr.offsets as *mut usize,
                    tr.offsets_size as usize,
                ) {
                    Ok(metadata) => metadata,
                    Err(_) => return Ok(()),
                };
            tracker::remember_key_metadata_route(&metadata, RouteTarget::System);
        }
        ParsedSecurityLevelRequest::DeleteKey { key } => {
            let status = match parcel::parse_reply_status(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            ) {
                Ok(status) => status,
                Err(_) => return Ok(()),
            };
            if status.is_ok() {
                tracker::forget_key_descriptor_route(key);
            }
        }
        ParsedSecurityLevelRequest::CreateOperation {
            operation_parameters,
            ..
        } => {
            register_operation_target_from_reply(
                tr,
                RouteTarget::System,
                None,
                operation_allows_aad(operation_parameters),
            )?;
        }
        ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { .. } => {}
    }
    Ok(())
}

unsafe fn build_security_level_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    if pending.route != RouteTarget::Omk {
        observe_system_security_level_reply(tr, pending)?;
        return Ok(None);
    }

    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();
    let omk_level = match ipc::with_omk_retry(|omk| {
        Ok(omk.r#getOhMySecurityLevel(pending.security_level)?)
    }) {
        Ok(level) => level,
        Err(error) => {
            warn!(
                "[Injector][Reply] OMK security-level lookup failed for {:?} uid={} pid={}: {:#}; preserving original system reply",
                pending.security_level,
                pending.caller.uid,
                pending.caller.pid,
                error
            );
            observe_system_security_level_reply(tr, pending)?;
            return Ok(None);
        }
    };

    match &pending.request {
        ParsedSecurityLevelRequest::CreateOperation {
            key,
            operation_parameters,
            forced,
        } => {
            let omk_key = omk_descriptor_for_app_key(key);
            let omk_response = match omk_level.r#createOperation(
                Some(&caller),
                &omk_key,
                operation_parameters,
                *forced,
            ) {
                Ok(response) => response,
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK createOperation failed for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    observe_system_security_level_reply(tr, pending)?;
                    return Ok(None);
                }
            };
            let carrier = match parcel::extract_create_operation_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            ) {
                Ok(carrier) => carrier,
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK createOperation could not reuse the original system carrier for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    observe_system_security_level_reply(tr, pending)?;
                    return Ok(None);
                }
            };
            Ok(Some(rewrite_create_operation_reply_with_native_carrier(
                omk_response,
                &carrier,
                operation_allows_aad(operation_parameters),
            )?))
        }
        ParsedSecurityLevelRequest::GenerateKey {
            key,
            attestation_key,
            params,
            flags,
            entropy,
        } => {
            let omk_attestation_key = attestation_key.as_ref().map(omk_descriptor_for_app_key);
            match omk_level.r#generateKey(
                Some(&caller),
                key,
                omk_attestation_key.as_ref(),
                params,
                *flags,
                entropy,
            ) {
                Ok(metadata) => {
                    let system_metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                    match parcel::parse_success_reply(
                        tr.data.ptr.buffer as *mut u8,
                        tr.data_size as usize,
                        tr.data.ptr.offsets as *mut usize,
                        tr.offsets_size as usize,
                    ) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            warn!(
                                "[Injector][Reply] OMK generateKey could not parse the original system metadata for uid={} pid={}: {:#}; preserving original system reply",
                                pending.caller.uid,
                                pending.caller.pid,
                                error
                            );
                            observe_system_security_level_reply(tr, pending)?;
                            return Ok(None);
                        }
                    };
                    let omk_descriptor = metadata.r#key.clone();
                    let surfaced_metadata =
                        surface_omk_metadata_with_system_descriptor(&system_metadata, metadata);
                    tracker::remember_key_descriptor_bridge(
                        &surfaced_metadata.r#key,
                        &system_metadata.r#key,
                        &omk_descriptor,
                    );
                    tracker::remember_key_metadata_route(&surfaced_metadata, RouteTarget::Omk);
                    Ok(Some(parcel::build_plain_reply(&surfaced_metadata)?))
                }
                Err(error) => {
                    warn!(
                    "[Injector][Reply] OMK generateKey failed for uid={} pid={}: {:#}; preserving original system reply",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
                    observe_system_security_level_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
        ParsedSecurityLevelRequest::ImportKey {
            key,
            attestation_key,
            params,
            flags,
            key_data,
        } => {
            let omk_attestation_key = attestation_key.as_ref().map(omk_descriptor_for_app_key);
            match omk_level.r#importKey(
                Some(&caller),
                key,
                omk_attestation_key.as_ref(),
                params,
                *flags,
                key_data,
            ) {
                Ok(metadata) => {
                    let system_metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                    match parcel::parse_success_reply(
                        tr.data.ptr.buffer as *mut u8,
                        tr.data_size as usize,
                        tr.data.ptr.offsets as *mut usize,
                        tr.offsets_size as usize,
                    ) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            warn!(
                                "[Injector][Reply] OMK importKey could not parse the original system metadata for uid={} pid={}: {:#}; preserving original system reply",
                                pending.caller.uid,
                                pending.caller.pid,
                                error
                            );
                            observe_system_security_level_reply(tr, pending)?;
                            return Ok(None);
                        }
                    };
                    let omk_descriptor = metadata.r#key.clone();
                    let surfaced_metadata =
                        surface_omk_metadata_with_system_descriptor(&system_metadata, metadata);
                    tracker::remember_key_descriptor_bridge(
                        &surfaced_metadata.r#key,
                        &system_metadata.r#key,
                        &omk_descriptor,
                    );
                    tracker::remember_key_metadata_route(&surfaced_metadata, RouteTarget::Omk);
                    Ok(Some(parcel::build_plain_reply(&surfaced_metadata)?))
                }
                Err(error) => {
                    warn!(
                    "[Injector][Reply] OMK importKey failed for uid={} pid={}: {:#}; preserving original system reply",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
                    observe_system_security_level_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
        ParsedSecurityLevelRequest::ImportWrappedKey {
            key,
            wrapping_key,
            masking_key,
            params,
            authenticators,
        } => {
            let omk_wrapping_key = omk_descriptor_for_app_key(wrapping_key);
            match omk_level.r#importWrappedKey(
                Some(&caller),
                key,
                &omk_wrapping_key,
                masking_key.as_deref(),
                params,
                authenticators,
            ) {
                Ok(metadata) => {
                    let system_metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                    match parcel::parse_success_reply(
                        tr.data.ptr.buffer as *mut u8,
                        tr.data_size as usize,
                        tr.data.ptr.offsets as *mut usize,
                        tr.offsets_size as usize,
                    ) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            warn!(
                                "[Injector][Reply] OMK importWrappedKey could not parse the original system metadata for uid={} pid={}: {:#}; preserving original system reply",
                                pending.caller.uid,
                                pending.caller.pid,
                                error
                            );
                            observe_system_security_level_reply(tr, pending)?;
                            return Ok(None);
                        }
                    };
                    let omk_descriptor = metadata.r#key.clone();
                    let surfaced_metadata =
                        surface_omk_metadata_with_system_descriptor(&system_metadata, metadata);
                    tracker::remember_key_descriptor_bridge(
                        &surfaced_metadata.r#key,
                        &system_metadata.r#key,
                        &omk_descriptor,
                    );
                    tracker::remember_key_metadata_route(&surfaced_metadata, RouteTarget::Omk);
                    Ok(Some(parcel::build_plain_reply(&surfaced_metadata)?))
                }
                Err(error) => {
                    warn!(
                    "[Injector][Reply] OMK importWrappedKey failed for uid={} pid={}: {:#}; preserving original system reply",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
                    observe_system_security_level_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
        ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key } => {
            let omk_storage_key = omk_descriptor_for_app_key(storage_key);
            match omk_level.r#convertStorageKeyToEphemeral(&omk_storage_key) {
                Ok(response) => Ok(Some(parcel::build_plain_reply(&response)?)),
                Err(error) => {
                    warn!(
                        "[Injector][Reply] OMK convertStorageKeyToEphemeral failed for uid={} pid={}: {:#}; preserving original system reply",
                        pending.caller.uid,
                        pending.caller.pid,
                        error
                    );
                    observe_system_security_level_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
        ParsedSecurityLevelRequest::DeleteKey { key } => {
            let omk_key = omk_descriptor_for_app_key(key);
            match omk_level.r#deleteKey(&omk_key) {
                Ok(()) => {
                    tracker::forget_key_descriptor_route(key);
                    Ok(Some(parcel::build_void_reply()?))
                }
                Err(error) => {
                    warn!(
                    "[Injector][Reply] OMK deleteKey failed for uid={} pid={}: {:#}; preserving original system reply",
                    pending.caller.uid,
                    pending.caller.pid,
                    error
                );
                    observe_system_security_level_reply(tr, pending)?;
                    Ok(None)
                }
            }
        }
    }
}

fn build_operation_reply_rewrite(
    pending: &PendingOperationCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let target = lookup_operation_target(pending.target)
        .ok_or_else(|| anyhow::anyhow!("missing operation target mapping"))?;

    if target.route == RouteTarget::System {
        if matches!(
            pending.request,
            ParsedOperationRequest::Finish { .. } | ParsedOperationRequest::Abort
        ) {
            forget_operation_target(pending.target);
        }
        return Ok(None);
    }

    let backend = target
        .backend
        .ok_or_else(|| anyhow::anyhow!("missing OMK operation backend mapping"))?;
    let _guard = BypassGuard::enter();

    let reply = match &pending.request {
        ParsedOperationRequest::UpdateAad { aad_input } => {
            if !target.aad_allowed {
                debug!(
                    "[Injector][Reply] OMK-owned updateAad rejected on a non-AAD-capable operation; returning OMK status reply"
                );
            }
            match backend.r#updateAad(aad_input) {
                Ok(()) => parcel::build_void_reply()?,
                Err(status) => parcel::build_status_reply(&status)?,
            }
        }
        ParsedOperationRequest::Update { input } => match backend.r#update(input) {
            Ok(output) => parcel::build_plain_reply(&output)?,
            Err(status) => parcel::build_status_reply(&status)?,
        },
        ParsedOperationRequest::Finish { input, signature } => {
            match backend.r#finish(input.as_deref(), signature.as_deref()) {
                Ok(output) => {
                    forget_operation_target(pending.target);
                    parcel::build_plain_reply(&output)?
                }
                Err(status) => parcel::build_status_reply(&status)?,
            }
        }
        ParsedOperationRequest::Abort => match backend.r#abort() {
            Ok(()) => {
                forget_operation_target(pending.target);
                parcel::build_void_reply()?
            }
            Err(status) => parcel::build_status_reply(&status)?,
        },
    };

    Ok(Some(reply))
}

unsafe fn install_outbound_reply(tr: &mut binder_transaction_data, reply: parcel::OwnedReply) {
    OUTBOUND_REPLY_BUFFERS.with(|slot| {
        let mut buffers = slot.borrow_mut();
        buffers.push(reply);
        let reply = buffers.last().expect("outbound reply buffer just pushed");
        tr.data_size = reply.data_size();
        tr.offsets_size = reply.offsets_size();
        tr.data.ptr.buffer = reply.data_ptr() as libc::c_ulong;
        tr.data.ptr.offsets = if reply.offsets.is_empty() {
            0
        } else {
            reply.offsets.as_ptr() as libc::c_ulong
        };
    });
}

fn push_pending_frame() {
    PENDING_REPLY_STACK.with(|slot| slot.borrow_mut().push(None));
}

fn replace_top_pending(pending: PendingCall) {
    PENDING_REPLY_STACK.with(|slot| {
        if let Some(top) = slot.borrow_mut().last_mut() {
            *top = Some(pending);
        }
    });
}

fn take_top_pending() -> Option<Option<PendingCall>> {
    PENDING_REPLY_STACK.with(|slot| slot.borrow_mut().last_mut().map(Option::take))
}

fn pop_pending_frame() {
    PENDING_REPLY_STACK.with(|slot| {
        let _ = slot.borrow_mut().pop();
    });
}

pub(super) fn clear_outbound_reply_buffers() {
    OUTBOUND_REPLY_BUFFERS.with(|slot| slot.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use rsbinder::{Interface, Status, StatusCode};

    use crate::{
        android::hardware::security::keymint::Certificate::Certificate,
        android::hardware::security::keymint::SecurityLevel::SecurityLevel,
        android::hardware::security::keymint::Tag::Tag,
        android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
        android::system::keystore2::Domain::Domain,
        android::system::keystore2::EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
        android::system::keystore2::IKeystoreOperation::{
            BnKeystoreOperation, IKeystoreOperation as AospKeystoreOperation,
        },
        android::system::keystore2::IKeystoreSecurityLevel::{
            BnKeystoreSecurityLevel, IKeystoreSecurityLevel as AospKeystoreSecurityLevel,
        },
        android::system::keystore2::IKeystoreService::{
            BnKeystoreService, IKeystoreService as AospKeystoreService,
        },
        android::system::keystore2::KeyDescriptor::KeyDescriptor,
        android::system::keystore2::KeyEntryResponse::KeyEntryResponse,
        android::system::keystore2::KeyMetadata::KeyMetadata,
        top::qwq2333::ohmykeymint::CallerInfo::CallerInfo,
        top::qwq2333::ohmykeymint::IOhMyKsService::{BnOhMyKsService, IOhMyKsService},
        top::qwq2333::ohmykeymint::IOhMySecurityLevel::IOhMySecurityLevel,
    };

    struct FakeOmkSecurityLevel;

    impl Interface for FakeOmkSecurityLevel {}

    impl IOhMySecurityLevel for FakeOmkSecurityLevel {
        fn r#createOperation(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_operation_parameters:
                &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_forced: bool,
        ) -> rsbinder::status::Result<CreateOperationResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#generateKey(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_attestation_key: Option<&KeyDescriptor>,
            _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_flags: i32,
            _arg_entropy: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importKey(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_attestation_key: Option<&KeyDescriptor>,
            _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_flags: i32,
            _arg_key_data: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importWrappedKey(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_wrapping_key: &KeyDescriptor,
            _arg_masking_key: Option<&[u8]>,
            _arg_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_authenticators: &[crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#convertStorageKeyToEphemeral(
            &self,
            _arg_storage_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<EphemeralStorageKeyResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _arg_key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }
    }

    struct FakeAospSecurityLevel;

    impl Interface for FakeAospSecurityLevel {}

    impl AospKeystoreSecurityLevel for FakeAospSecurityLevel {
        fn r#createOperation(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_operation_parameters:
                &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_forced: bool,
        ) -> rsbinder::status::Result<CreateOperationResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#generateKey(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_attestation_key: Option<&KeyDescriptor>,
            _arg_params:
                &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_flags: i32,
            _arg_entropy: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importKey(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_attestation_key: Option<&KeyDescriptor>,
            _arg_params:
                &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_flags: i32,
            _arg_key_data: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importWrappedKey(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_wrapping_key: &KeyDescriptor,
            _arg_masking_key: Option<&[u8]>,
            _arg_params:
                &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
            _arg_authenticators:
                &[crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#convertStorageKeyToEphemeral(
            &self,
            _arg_storage_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<EphemeralStorageKeyResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _arg_key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }
    }

    fn fake_system_security_level_backend() -> route::AospSecurityLevelBinder {
        BnKeystoreSecurityLevel::new_binder(FakeAospSecurityLevel)
    }

    fn fake_omk_security_level_backend() -> route::OmkSecurityLevelBinder {
        crate::top::qwq2333::ohmykeymint::IOhMySecurityLevel::BnOhMySecurityLevel::new_binder(
            FakeOmkSecurityLevel,
        )
    }

    struct FakeAospService;

    impl Interface for FakeAospService {}

    impl AospKeystoreService for FakeAospService {
        fn r#getSecurityLevel(
            &self,
            _arg_security_level: SecurityLevel,
        ) -> rsbinder::status::Result<route::AospSecurityLevelBinder> {
            Ok(fake_system_security_level_backend())
        }

        fn r#getKeyEntry(
            &self,
            _arg_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<KeyEntryResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#updateSubcomponent(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_public_cert: Option<&[u8]>,
            _arg_certificate_chain: Option<&[u8]>,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntries(
            &self,
            _arg_domain: Domain,
            _arg_nspace: i64,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _arg_key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#grant(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_grantee_uid: i32,
            _arg_access_vector: i32,
        ) -> rsbinder::status::Result<KeyDescriptor> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#ungrant(
            &self,
            _arg_key: &KeyDescriptor,
            _arg_grantee_uid: i32,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getNumberOfEntries(
            &self,
            _arg_domain: Domain,
            _arg_nspace: i64,
        ) -> rsbinder::status::Result<i32> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntriesBatched(
            &self,
            _arg_domain: Domain,
            _arg_nspace: i64,
            _arg_starting_past_alias: Option<&str>,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getSupplementaryAttestationInfo(
            &self,
            _arg_tag: Tag,
        ) -> rsbinder::status::Result<Vec<u8>> {
            Err(StatusCode::UnknownTransaction.into())
        }
    }

    fn fake_system_service_backend() -> route::AospServiceBinder {
        BnKeystoreService::new_binder(FakeAospService)
    }

    struct FakeOmkService;

    impl Interface for FakeOmkService {}

    impl IOhMyKsService for FakeOmkService {
        fn r#getSecurityLevel(
            &self,
            _arg_security_level: SecurityLevel,
        ) -> rsbinder::status::Result<route::AospSecurityLevelBinder> {
            Ok(fake_system_security_level_backend())
        }

        fn r#getOhMySecurityLevel(
            &self,
            _arg_security_level: SecurityLevel,
        ) -> rsbinder::status::Result<route::OmkSecurityLevelBinder> {
            Ok(fake_omk_security_level_backend())
        }

        fn r#getKeyEntry(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<KeyEntryResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#updateSubcomponent(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_public_cert: Option<&[u8]>,
            _arg_certificate_chain: Option<&[u8]>,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntries(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_domain: Domain,
            _arg_nspace: i64,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#grant(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_grantee_uid: i32,
            _arg_access_vector: i32,
        ) -> rsbinder::status::Result<KeyDescriptor> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#ungrant(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_key: &KeyDescriptor,
            _arg_grantee_uid: i32,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getNumberOfEntries(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_domain: Domain,
            _arg_nspace: i64,
        ) -> rsbinder::status::Result<i32> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntriesBatched(
            &self,
            _arg_ctx: Option<&CallerInfo>,
            _arg_domain: Domain,
            _arg_nspace: i64,
            _arg_starting_past_alias: Option<&str>,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getSupplementaryAttestationInfo(
            &self,
            _arg_tag: Tag,
        ) -> rsbinder::status::Result<Vec<u8>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#updateEcKeybox(
            &self,
            _arg_key: &[u8],
            _arg_chain: &[Certificate],
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#updateRsaKeybox(
            &self,
            _arg_key: &[u8],
            _arg_chain: &[Certificate],
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }
    }

    fn fake_omk_service_backend() -> route::OmkServiceBinder {
        BnOhMyKsService::new_binder(FakeOmkService)
    }

    fn sample_key_descriptor() -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: 7,
            alias: Some("alias".to_string()),
            blob: None,
        }
    }

    struct TestOperationBackend {
        update_output: Vec<u8>,
        aborts: Arc<AtomicUsize>,
        update_aad_status: Option<Status>,
    }

    impl Interface for TestOperationBackend {}

    impl AospKeystoreOperation for TestOperationBackend {
        fn r#updateAad(&self, _aad_input: &[u8]) -> rsbinder::status::Result<()> {
            match self.update_aad_status.as_ref() {
                Some(status) => Err(Status::new_service_specific_error(
                    status.service_specific_error(),
                    None,
                )),
                None => Ok(()),
            }
        }

        fn r#update(&self, _input: &[u8]) -> rsbinder::status::Result<Option<Vec<u8>>> {
            Ok(Some(self.update_output.clone()))
        }

        fn r#finish(
            &self,
            _input: Option<&[u8]>,
            _signature: Option<&[u8]>,
        ) -> rsbinder::status::Result<Option<Vec<u8>>> {
            Ok(Some(self.update_output.clone()))
        }

        fn r#abort(&self) -> rsbinder::status::Result<()> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn raw_parts(reply: &mut parcel::OwnedReply) -> (*mut u8, usize, *mut usize, usize) {
        (
            reply.data_mut_ptr(),
            reply.data_size(),
            if reply.offsets.is_empty() {
                std::ptr::null_mut()
            } else {
                reply.offsets.as_mut_ptr()
            },
            reply.offsets_size(),
        )
    }

    #[test]
    fn local_service_target_extraction_is_stable() {
        tracker::clear_state_for_tests();
        let binder = route::new_service_binder(
            CallerIdentity::new(1000, 2000),
            config::InterceptConfig::default(),
            true,
            fake_system_service_backend(),
            None,
        );

        let first = extract_local_service_target(&binder).expect("first extraction should succeed");
        let second =
            extract_local_service_target(&binder).expect("second extraction should succeed");

        assert_eq!(first, second);
        assert_ne!(first.ptr, 0);
        assert_ne!(first.cookie, 0);
    }

    #[test]
    fn request_side_redirect_is_disabled_for_live_keystore_traffic() {
        tracker::clear_state_for_tests();
        let caller = CallerIdentity::new(1000, 2000);
        let intercept = config::InterceptConfig::default();
        let system_backend = fake_system_service_backend();
        let omk_backend = fake_omk_service_backend();

        let requests = [
            ParsedServiceRequest::ListEntries {
                domain: Domain::APP,
                nspace: 0,
            },
            ParsedServiceRequest::Grant {
                key: sample_key_descriptor(),
                grantee_uid: 12345,
                access_vector: 7,
            },
            ParsedServiceRequest::Ungrant {
                key: sample_key_descriptor(),
                grantee_uid: 12345,
            },
            ParsedServiceRequest::GetNumberOfEntries {
                domain: Domain::APP,
                nspace: 0,
            },
            ParsedServiceRequest::ListEntriesBatched {
                domain: Domain::APP,
                nspace: 0,
                starting_past_alias: Some("alias".to_string()),
            },
            ParsedServiceRequest::GetSupplementaryAttestationInfo {
                tag: Tag::MODULE_HASH,
            },
            ParsedServiceRequest::UpdateSubcomponent {
                key: sample_key_descriptor(),
                public_cert: None,
                certificate_chain: None,
            },
            ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
        ];

        for req in &requests {
            assert!(
                build_request_side_redirect_with_backends(
                    req,
                    caller.clone(),
                    intercept.clone(),
                    true,
                    system_backend.clone(),
                    Some(omk_backend.clone()),
                )
                .is_none(),
                "live redirect should stay disabled for {:?}",
                req.method()
            );
            assert!(
                build_request_side_redirect_with_backends(
                    req,
                    caller.clone(),
                    intercept.clone(),
                    true,
                    system_backend.clone(),
                    None,
                )
                .is_none(),
                "redirect should remain disabled without OMK backend for {:?}",
                req.method()
            );
            assert!(
                build_request_side_redirect_with_backends(
                    req,
                    caller.clone(),
                    intercept.clone(),
                    false,
                    system_backend.clone(),
                    Some(omk_backend.clone()),
                )
                .is_none(),
                "redirect should remain disabled even when OMK route is disallowed for {:?}",
                req.method()
            );
        }
    }

    #[test]
    fn service_execution_mode_keeps_all_service_methods_on_reply_side() {
        for method in [
            ServiceMethod::UpdateSubcomponent,
            ServiceMethod::ListEntries,
            ServiceMethod::Grant,
            ServiceMethod::Ungrant,
            ServiceMethod::GetNumberOfEntries,
            ServiceMethod::ListEntriesBatched,
            ServiceMethod::GetSupplementaryAttestationInfo,
            ServiceMethod::GetSecurityLevel,
            ServiceMethod::GetKeyEntry,
            ServiceMethod::DeleteKey,
        ] {
            assert_eq!(
                service_execution_mode(method),
                ServiceExecutionMode::ReplyRewrite,
                "{method:?} should stay on reply-side rewriting",
            );
        }
    }

    #[test]
    fn service_route_stays_system_for_non_bridged_service_methods() {
        let intercept = config::InterceptConfig::default();

        for request in [
            ParsedServiceRequest::ListEntries {
                domain: Domain::APP,
                nspace: 0,
            },
            ParsedServiceRequest::Grant {
                key: sample_key_descriptor(),
                grantee_uid: 12345,
                access_vector: 7,
            },
            ParsedServiceRequest::Ungrant {
                key: sample_key_descriptor(),
                grantee_uid: 12345,
            },
            ParsedServiceRequest::GetNumberOfEntries {
                domain: Domain::APP,
                nspace: 0,
            },
            ParsedServiceRequest::ListEntriesBatched {
                domain: Domain::APP,
                nspace: 0,
                starting_past_alias: Some("alias".to_string()),
            },
            ParsedServiceRequest::GetSupplementaryAttestationInfo {
                tag: Tag::MODULE_HASH,
            },
        ] {
            assert_eq!(
                route_for_service_request(&request, &intercept),
                RouteTarget::System,
                "{:?} should stay on the system backend until it has a bridged reply-side implementation",
                request.method()
            );
        }
    }

    #[test]
    fn pending_reply_stack_keeps_outer_pending_across_inner_placeholder() {
        tracker::clear_state_for_tests();
        PENDING_REPLY_STACK.with(|slot| slot.borrow_mut().clear());
        push_pending_frame();
        replace_top_pending(PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
            method: ServiceMethod::GetSecurityLevel,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
            execution_mode: ServiceExecutionMode::ReplyRewrite,
            redirect_applied: false,
            _redirect_keepalive: None,
        }));

        push_pending_frame();
        assert!(matches!(take_top_pending(), Some(None)));
        pop_pending_frame();

        let outer = take_top_pending();
        assert!(matches!(outer, Some(Some(_))));
        pop_pending_frame();
    }

    #[test]
    fn create_operation_reply_reuses_native_carrier_and_routes_followups_to_omk() {
        tracker::clear_state_for_tests();
        operation_targets()
            .lock()
            .expect("operation target map poisoned")
            .clear();

        let system_aborts = Arc::new(AtomicUsize::new(0));
        let omk_aborts = Arc::new(AtomicUsize::new(0));
        let system_operation = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![1, 2, 3],
            aborts: system_aborts.clone(),
            update_aad_status: None,
        });
        let mut system_reply = parcel::build_create_operation_reply(CreateOperationResponse {
            r#iOperation: Some(system_operation),
            r#operationChallenge: None,
            r#parameters: None,
            r#upgradedBlob: Some(vec![1]),
        })
        .expect("system createOperation reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut system_reply);
        let original_carrier = unsafe {
            parcel::extract_create_operation_reply_carrier(data, data_size, offsets, offsets_size)
        }
        .expect("original carrier should be extractable");

        let omk_backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![9, 9, 9],
            aborts: omk_aborts.clone(),
            update_aad_status: None,
        });
        let mut rewritten = rewrite_create_operation_reply_with_native_carrier(
            CreateOperationResponse {
                r#iOperation: Some(omk_backend),
                r#operationChallenge: None,
                r#parameters: None,
                r#upgradedBlob: Some(vec![7, 7]),
            },
            &original_carrier,
            true,
        )
        .expect("rewritten createOperation reply should serialize");

        let (rewritten_data, rewritten_data_size, rewritten_offsets, rewritten_offsets_size) =
            raw_parts(&mut rewritten);
        let parsed: CreateOperationResponse = unsafe {
            parcel::parse_success_reply(
                rewritten_data,
                rewritten_data_size,
                rewritten_offsets,
                rewritten_offsets_size,
            )
        }
        .expect("rewritten reply should deserialize");
        assert!(parsed.r#iOperation.is_some());
        assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[7, 7][..]));

        let rewritten_carrier = unsafe {
            parcel::extract_create_operation_reply_carrier(
                rewritten_data,
                rewritten_data_size,
                rewritten_offsets,
                rewritten_offsets_size,
            )
        }
        .expect("rewritten carrier should be extractable");
        assert_eq!(rewritten_carrier.bytes, original_carrier.bytes);
        assert_eq!(rewritten_carrier.is_object, original_carrier.is_object);

        let target =
            unsafe { parse_local_binder_target_from_parcel_bytes(&rewritten_carrier.bytes) }
                .expect("rewritten carrier should expose a local binder target");
        let target_info = lookup_operation_target(target)
            .expect("rewritten native target should be mapped back to the OMK backend");
        assert_eq!(target_info.route, RouteTarget::Omk);
        assert!(target_info.aad_allowed);
        assert!(target_info.backend.is_some());

        let update_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Update {
                input: vec![4, 5, 6],
            },
            method: OperationMethod::Update,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("update rewrite should succeed")
        .expect("update rewrite should return a reply");
        let mut update_reply = update_reply;
        let (update_data, update_data_size, update_offsets, update_offsets_size) =
            raw_parts(&mut update_reply);
        let update_output: Option<Vec<u8>> = unsafe {
            parcel::parse_success_reply(
                update_data,
                update_data_size,
                update_offsets,
                update_offsets_size,
            )
        }
        .expect("update reply should deserialize");
        assert_eq!(update_output.as_deref(), Some(&[9, 9, 9][..]));
        assert_eq!(system_aborts.load(Ordering::SeqCst), 0);

        let abort_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Abort,
            method: OperationMethod::Abort,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("abort rewrite should succeed")
        .expect("abort rewrite should return a reply");
        let mut abort_reply = abort_reply;
        let (abort_data, abort_data_size, abort_offsets, abort_offsets_size) =
            raw_parts(&mut abort_reply);
        let abort_status = unsafe {
            parcel::parse_reply_status(
                abort_data,
                abort_data_size,
                abort_offsets,
                abort_offsets_size,
            )
        }
        .expect("abort reply should carry a binder status");
        assert!(abort_status.is_ok());
        assert_eq!(omk_aborts.load(Ordering::SeqCst), 1);
        assert!(
            lookup_operation_target(target).is_none(),
            "abort should clear the operation mapping"
        );
    }

    #[test]
    fn system_route_invalid_update_aad_preserves_native_reply() {
        tracker::clear_state_for_tests();
        operation_targets()
            .lock()
            .expect("operation target map poisoned")
            .clear();

        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::System,
                aad_allowed: false,
                backend: None,
            },
        );

        let reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::UpdateAad {
                aad_input: vec![1, 2, 3],
            },
            method: OperationMethod::UpdateAad,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("updateAad rewrite should succeed");
        assert!(
            reply.is_none(),
            "system invalid updateAad should preserve the original native reply parcel"
        );
        assert_eq!(
            lookup_operation_target(target).unwrap().route,
            RouteTarget::System
        );
    }

    #[test]
    fn omk_route_invalid_update_aad_returns_omk_service_specific_reply() {
        tracker::clear_state_for_tests();
        operation_targets()
            .lock()
            .expect("operation target map poisoned")
            .clear();

        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![1, 2, 3],
            aborts: Arc::new(AtomicUsize::new(0)),
            update_aad_status: Some(Status::new_service_specific_error(7, None)),
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: false,
                backend: Some(backend),
            },
        );

        let reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::UpdateAad {
                aad_input: vec![1, 2, 3],
            },
            method: OperationMethod::UpdateAad,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("updateAad rewrite should succeed")
        .expect("OMK invalid updateAad should return an OMK-owned reply");
        let mut reply = reply;
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("invalid updateAad reply should deserialize to a binder status");
        assert_eq!(
            status.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(status.service_specific_error(), 7);
        assert_eq!(
            lookup_operation_target(target).unwrap().route,
            RouteTarget::Omk
        );
    }
}
