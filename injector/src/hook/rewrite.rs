use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use log::{debug, info, warn};
use rsbinder::{ExceptionCode, Parcel, Status};

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

struct PendingServiceCall {
    request: ParsedServiceRequest,
    method: ServiceMethod,
    caller: CallerIdentity,
    packages: Vec<String>,
    route: RouteTarget,
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

struct LocalServiceRedirect {
    keepalive: route::AospServiceBinder,
    target: LocalBinderTarget,
    preferred_route: RouteTarget,
}

thread_local! {
    static PENDING_REPLY_STACK: RefCell<Vec<Option<PendingCall>>> = const { RefCell::new(Vec::new()) };
    static OUTBOUND_REPLY_BUFFERS: RefCell<Vec<parcel::OwnedReply>> = const { RefCell::new(Vec::new()) };
}

static SECURITY_LEVEL_TARGETS: OnceLock<
    Mutex<
        HashMap<
            LocalBinderTarget,
            crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
        >,
    >,
> = OnceLock::new();
static OMK_OPERATION_TARGETS: OnceLock<
    Mutex<HashMap<LocalBinderTarget, route::AospOperationBinder>>,
> = OnceLock::new();

fn should_attempt_request_side_redirect(
    _request: &ParsedServiceRequest,
    _allow_omk_route: bool,
) -> bool {
    true
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

fn extract_local_target_from_security_level_binder(
    binder: &route::AospSecurityLevelBinder,
) -> anyhow::Result<LocalBinderTarget> {
    let mut parcel = Parcel::new();
    let binder_to_write: Option<route::AospSecurityLevelBinder> = Some(binder.clone());
    parcel.write(&binder_to_write)?;
    let bytes = unsafe { std::slice::from_raw_parts(parcel.as_ptr(), parcel.data_size()) };
    unsafe { parse_local_binder_target_from_parcel_bytes(bytes) }
        .ok_or_else(|| anyhow::anyhow!("failed to parse local security-level binder target"))
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

fn security_level_targets() -> &'static Mutex<
    HashMap<
        LocalBinderTarget,
        crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    >,
> {
    SECURITY_LEVEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_security_level_target(
    target: LocalBinderTarget,
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
) {
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .insert(target, security_level);
}

fn lookup_security_level_target(
    target: LocalBinderTarget,
) -> Option<crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel> {
    security_level_targets()
        .lock()
        .expect("security level target map poisoned")
        .get(&target)
        .copied()
}

fn omk_operation_targets() -> &'static Mutex<HashMap<LocalBinderTarget, route::AospOperationBinder>>
{
    OMK_OPERATION_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_omk_operation_target(target: LocalBinderTarget, backend: route::AospOperationBinder) {
    omk_operation_targets()
        .lock()
        .expect("OMK operation target map poisoned")
        .insert(target, backend);
}

fn lookup_omk_operation_target(target: LocalBinderTarget) -> Option<route::AospOperationBinder> {
    omk_operation_targets()
        .lock()
        .expect("OMK operation target map poisoned")
        .get(&target)
        .cloned()
}

fn forget_omk_operation_target(target: LocalBinderTarget) {
    omk_operation_targets()
        .lock()
        .expect("OMK operation target map poisoned")
        .remove(&target);
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

        let route_enabled = identify::is_omk_service_route_enabled(method, &cfg.intercept);
        let route = if route_enabled {
            RouteTarget::Omk
        } else {
            RouteTarget::System
        };

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
            "[Injector][Route] method={:?} uid={} pid={} route={:?}",
            method, caller.uid, caller.pid, route
        );

        if expects_reply {
            replace_top_pending(PendingCall::Service(PendingServiceCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route,
            }));
        }
        return false;
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
        let Some(security_level) = lookup_security_level_target(target) else {
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
                security_level,
            );
            return false;
        }

        let route = RouteTarget::Omk;

        info!(
            "[Injector][Decision] command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={} reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?}",
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
            security_level,
        );
        info!(
            "[Injector][Route] security_level_method={:?} uid={} pid={} route={:?} security_level={:?}",
            method, caller.uid, caller.pid, route, security_level
        );

        if expects_reply {
            replace_top_pending(PendingCall::SecurityLevel(PendingSecurityLevelCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route,
                security_level,
            }));
        }
        return false;
    }

    if parcel::contains_keystore_operation_interface(parcel_bytes) {
        if lookup_omk_operation_target(target).is_none() {
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
                if call.route == RouteTarget::Omk {
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
                } else {
                    Ok(None)
                }
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
                if pending_prefers_omk_error_reply(&pending) {
                    if let Some(status) = extract_binder_status_for_reply(&error) {
                        match parcel::build_status_reply(&status) {
                            Ok(reply) => {
                                install_outbound_reply(tr, reply);
                                warn!(
                                    "[Injector][Reply] OMK route failed; returned OMK error reply for original={{flags=0x{:x}, data_size={}, offsets_size={}, objects={}}}: {:#}",
                                    original_flags,
                                    original_data_size,
                                    original_offsets_size,
                                    original_objects,
                                    error
                                );
                                pop_pending_frame();
                                return;
                            }
                            Err(build_error) => {
                                warn!(
                                    "[Injector][Reply] failed to serialize OMK error reply after rewrite failure: {:#}; original rewrite error: {:#}",
                                    build_error,
                                    error
                                );
                            }
                        }
                    }
                }
                warn!(
                    "[Injector][Reply] failed to rewrite pending reply: {:#}; keeping original system reply",
                    error
                );
            }
        }
    }

    pop_pending_frame();
}

fn pending_prefers_omk_error_reply(pending: &PendingCall) -> bool {
    match pending {
        PendingCall::Service(call) => call.route == RouteTarget::Omk,
        PendingCall::SecurityLevel(call) => call.route == RouteTarget::Omk,
        PendingCall::Operation(_) => true,
    }
}

fn extract_binder_status_for_reply(error: &anyhow::Error) -> Option<Status> {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<Status>())
        .find_map(status_for_reply)
}

fn status_for_reply(status: &Status) -> Option<Status> {
    match status.exception_code() {
        ExceptionCode::None => Some(Status::from(status.transaction_error())),
        ExceptionCode::TransactionFailed => Some(Status::from(status.transaction_error())),
        ExceptionCode::ServiceSpecific => Some(Status::new_service_specific_error(
            status.service_specific_error(),
            None,
        )),
        code => Some(Status::from(code)),
    }
}

fn register_security_level_carrier(
    carrier: &parcel::ReplyBinderCarrier,
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
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
    remember_security_level_target(target, security_level);
    info!(
        "[Injector][Route] registered security-level carrier ptr=0x{:x} cookie=0x{:x} security_level={:?}",
        target.ptr, target.cookie, security_level
    );
    Ok(())
}

unsafe fn build_service_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    if matches!(
        pending.request,
        ParsedServiceRequest::GetSecurityLevel { security_level: _ }
    ) {
        if let ParsedServiceRequest::GetSecurityLevel { security_level } = &pending.request {
            let carrier = parcel::extract_direct_binder_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )?;
            register_security_level_carrier(&carrier, *security_level)?;
        }
        return Ok(None);
    }

    if pending.route != RouteTarget::Omk {
        return Ok(None);
    }

    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();

    let reply = ipc::with_omk_retry(|omk| match &pending.request {
        ParsedServiceRequest::GetKeyEntry { key } => {
            let entry = omk.r#getKeyEntry(Some(&caller), key)?;
            let carrier = parcel::extract_key_entry_reply_carrier(
                tr.data.ptr.buffer as *mut u8,
                tr.data_size as usize,
                tr.data.ptr.offsets as *mut usize,
                tr.offsets_size as usize,
            )?;
            register_security_level_carrier(&carrier, entry.r#metadata.r#keySecurityLevel)?;
            parcel::build_key_entry_reply_with_carrier_bytes(
                entry.r#metadata,
                &carrier.bytes,
                carrier.is_object,
            )
        }
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => {
            omk.r#updateSubcomponent(
                Some(&caller),
                key,
                public_cert.as_deref(),
                certificate_chain.as_deref(),
            )?;
            parcel::build_void_reply()
        }
        ParsedServiceRequest::ListEntries { domain, nspace } => {
            let entries = omk.r#listEntries(Some(&caller), *domain, *nspace)?;
            parcel::build_plain_reply(&entries)
        }
        ParsedServiceRequest::DeleteKey { key } => {
            omk.r#deleteKey(Some(&caller), key)?;
            parcel::build_void_reply()
        }
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => {
            let granted = omk.r#grant(Some(&caller), key, *grantee_uid, *access_vector)?;
            parcel::build_plain_reply(&granted)
        }
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            omk.r#ungrant(Some(&caller), key, *grantee_uid)?;
            parcel::build_void_reply()
        }
        ParsedServiceRequest::GetNumberOfEntries { domain, nspace } => {
            let count = omk.r#getNumberOfEntries(Some(&caller), *domain, *nspace)?;
            parcel::build_plain_reply(&count)
        }
        ParsedServiceRequest::ListEntriesBatched {
            domain,
            nspace,
            starting_past_alias,
        } => {
            let entries = omk.r#listEntriesBatched(
                Some(&caller),
                *domain,
                *nspace,
                starting_past_alias.as_deref(),
            )?;
            parcel::build_plain_reply(&entries)
        }
        ParsedServiceRequest::GetSupplementaryAttestationInfo { tag } => {
            let info = omk.r#getSupplementaryAttestationInfo(*tag)?;
            parcel::build_plain_reply(&info)
        }
        ParsedServiceRequest::GetSecurityLevel { .. } => unreachable!(),
    })?;

    Ok(Some(reply))
}

unsafe fn build_security_level_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();
    let reply = ipc::with_omk_retry(|omk| {
        let omk_level = omk.r#getOhMySecurityLevel(pending.security_level)?;

        match &pending.request {
            ParsedSecurityLevelRequest::CreateOperation {
                key,
                operation_parameters,
                forced,
            } => {
                let carrier = parcel::extract_create_operation_reply_carrier(
                    tr.data.ptr.buffer as *mut u8,
                    tr.data_size as usize,
                    tr.data.ptr.offsets as *mut usize,
                    tr.offsets_size as usize,
                )?;
                let omk_response = omk_level.r#createOperation(
                    Some(&caller),
                    key,
                    operation_parameters,
                    *forced,
                )?;
                if let Some(omk_operation) = omk_response.r#iOperation.as_ref() {
                    if !carrier.is_object {
                        anyhow::bail!("system createOperation carrier was null; cannot preserve operation stickiness");
                    }
                    let target =
                        unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
                            .ok_or_else(|| {
                                anyhow::anyhow!("failed to parse local operation carrier target")
                            })?;
                    remember_omk_operation_target(target, omk_operation.clone());
                    info!(
                        "[Injector][Route] registered operation carrier ptr=0x{:x} cookie=0x{:x} security_level={:?}",
                        target.ptr, target.cookie, pending.security_level
                    );
                }
                parcel::build_create_operation_reply_with_carrier_bytes(
                    omk_response.r#operationChallenge,
                    omk_response.r#parameters,
                    omk_response.r#upgradedBlob,
                    &carrier.bytes,
                    carrier.is_object,
                )
            }
            ParsedSecurityLevelRequest::GenerateKey {
                key,
                attestation_key,
                params,
                flags,
                entropy,
            } => {
                let metadata = omk_level.r#generateKey(
                    Some(&caller),
                    key,
                    attestation_key.as_ref(),
                    params,
                    *flags,
                    entropy,
                )?;
                parcel::build_plain_reply(&metadata)
            }
            ParsedSecurityLevelRequest::ImportKey {
                key,
                attestation_key,
                params,
                flags,
                key_data,
            } => {
                let metadata = omk_level.r#importKey(
                    Some(&caller),
                    key,
                    attestation_key.as_ref(),
                    params,
                    *flags,
                    key_data,
                )?;
                parcel::build_plain_reply(&metadata)
            }
            ParsedSecurityLevelRequest::ImportWrappedKey {
                key,
                wrapping_key,
                masking_key,
                params,
                authenticators,
            } => {
                let metadata = omk_level.r#importWrappedKey(
                    Some(&caller),
                    key,
                    wrapping_key,
                    masking_key.as_deref(),
                    params,
                    authenticators,
                )?;
                parcel::build_plain_reply(&metadata)
            }
            ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key } => {
                let response = omk_level.r#convertStorageKeyToEphemeral(storage_key)?;
                parcel::build_plain_reply(&response)
            }
            ParsedSecurityLevelRequest::DeleteKey { key } => {
                omk_level.r#deleteKey(key)?;
                parcel::build_void_reply()
            }
        }
    })?;

    Ok(Some(reply))
}

fn build_operation_reply_rewrite(
    pending: &PendingOperationCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let backend = lookup_omk_operation_target(pending.target)
        .ok_or_else(|| anyhow::anyhow!("missing OMK operation backend mapping"))?;
    let _guard = BypassGuard::enter();

    let reply = match &pending.request {
        ParsedOperationRequest::UpdateAad { aad_input } => {
            backend.r#updateAad(aad_input)?;
            parcel::build_void_reply()?
        }
        ParsedOperationRequest::Update { input } => {
            let output = backend.r#update(input)?;
            parcel::build_plain_reply(&output)?
        }
        ParsedOperationRequest::Finish { input, signature } => {
            let output = backend.r#finish(input.as_deref(), signature.as_deref())?;
            forget_omk_operation_target(pending.target);
            parcel::build_plain_reply(&output)?
        }
        ParsedOperationRequest::Abort => {
            backend.r#abort()?;
            forget_omk_operation_target(pending.target);
            parcel::build_void_reply()?
        }
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
    use super::*;
    use rsbinder::{Interface, StatusCode};

    use crate::{
        android::hardware::security::keymint::Certificate::Certificate,
        android::hardware::security::keymint::SecurityLevel::SecurityLevel,
        android::hardware::security::keymint::Tag::Tag,
        android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
        android::system::keystore2::Domain::Domain,
        android::system::keystore2::EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
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

    #[test]
    fn local_service_target_extraction_is_stable() {
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
    fn request_side_redirect_builds_only_when_omk_route_is_available() {
        let caller = CallerIdentity::new(1000, 2000);
        let intercept = config::InterceptConfig::default();
        let system_backend = fake_system_service_backend();
        let omk_backend = fake_omk_service_backend();

        // All IKeystoreService methods should build a redirect only when the
        // OMK route is genuinely available.
        let requests = [
            ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
            ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            ParsedServiceRequest::ListEntries {
                domain: Domain::APP,
                nspace: 0,
            },
            ParsedServiceRequest::DeleteKey {
                key: sample_key_descriptor(),
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
        ];

        for req in &requests {
            let redirect = build_request_side_redirect_with_backends(
                req,
                caller.clone(),
                intercept.clone(),
                true,
                system_backend.clone(),
                Some(omk_backend.clone()),
            );
            assert!(
                redirect.is_some(),
                "expected redirect for {:?}",
                req.method()
            );
            assert_eq!(
                redirect.unwrap().preferred_route,
                RouteTarget::Omk,
                "expected OMK-preferred redirect for {:?}",
                req.method()
            );
        }

        let req = ParsedServiceRequest::GetSecurityLevel {
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        };
        let missing_omk = build_request_side_redirect_with_backends(
            &req,
            caller.clone(),
            intercept.clone(),
            true,
            system_backend.clone(),
            None,
        );
        assert!(
            missing_omk.is_none(),
            "redirect should not be built without an OMK backend"
        );

        let disallowed = build_request_side_redirect_with_backends(
            &req,
            caller.clone(),
            intercept.clone(),
            false,
            system_backend.clone(),
            Some(omk_backend),
        );
        assert!(
            disallowed.is_none(),
            "redirect should not be built for disallowed requests"
        );
    }

    #[test]
    fn pending_reply_stack_keeps_outer_pending_across_inner_placeholder() {
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
        }));

        push_pending_frame();
        assert!(matches!(take_top_pending(), Some(None)));
        pop_pending_frame();

        let outer = take_top_pending();
        assert!(matches!(outer, Some(Some(_))));
        pop_pending_frame();
    }
}
