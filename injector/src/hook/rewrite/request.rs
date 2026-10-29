use super::*;

#[cfg(test)]
mod tests;

pub(super) fn target_from_transaction(tr: &binder_transaction_data) -> Option<LocalBinderTarget> {
    let ptr = unsafe { tr.target.ptr };
    if ptr == 0 || tr.cookie == 0 {
        return None;
    }
    Some(LocalBinderTarget { ptr, cookie: tr.cookie })
}

fn route_for_service_request(
    request: &ParsedServiceRequest,
    allowed: bool,
    intercept: &config::InterceptConfig,
) -> RouteTarget {
    if allowed && identify::is_omk_service_route_enabled(request.method(), intercept) {
        RouteTarget::Omk
    } else {
        RouteTarget::System
    }
}

pub(super) fn security_level_scoop_enabled(intercept: &config::InterceptConfig) -> bool {
    intercept.get_security_level || intercept.get_key_entry
}

fn is_known_keystore_interface(interface: &str) -> bool {
    identify::KNOWN_KEYSTORE_INTERFACES.contains(&interface)
}

pub(in crate::hook) unsafe fn handle_br_transaction(
    connection: BinderStateKey,
    tr: &mut binder_transaction_data,
    caller_sid: Option<String>,
    command_name: &str,
) -> bool {
    let expects_reply = (tr.flags & super::super::binder::TF_ONE_WAY) == 0;
    if expects_reply {
        push_pending_frame(connection);
    }

    if forward::is_bypassed() {
        debug!(
            "skipped {} because bypass is active: code=0x{:x} uid={} pid={}",
            command_name, tr.code, tr.sender_euid, tr.sender_pid
        );
        return false;
    }

    let Some(parcel_bytes) = super::super::binder::transaction_data_bytes(tr) else {
        warn!(
            "event=decision null parcel buffer for {} code=0x{:x} uid={} pid={}",
            command_name, tr.code, tr.sender_euid, tr.sender_pid
        );
        return false;
    };

    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let request_interface =
        match parcel::peek_request_interface(data, data_size, offsets, offsets_size) {
            Ok(interface) => interface,
            Err(error) => {
                if parcel::contains_known_keystore_interface(parcel_bytes) {
                    debug!(
                        "event=decision failed to read keystore interface code=0x{:x}: {:#}",
                        tr.code, error
                    );
                }
                return false;
            }
        };
    if !is_known_keystore_interface(&request_interface) {
        return false;
    }

    let cfg = config::get();
    if !cfg.main.enabled {
        debug!("event=decision injector disabled by config");
        return false;
    }

    let caller = CallerInfo {
        uid: i64::from(tr.sender_euid.max(0)),
        sid: caller_sid.unwrap_or_default(),
        pid: i64::from(tr.sender_pid),
    };
    let caller_uid = caller.uid;
    // Authorization events are emitted by system auth components, not by the
    // app that later uses an auth-bound key. Mirror this global keystore state
    // after the system service accepts it; scoop still gates app key traffic.
    if request_interface == identify::KEYSTORE_AUTHORIZATION_INTERFACE {
        let request = match parcel::parse_authorization_request(
            data,
            data_size,
            offsets,
            offsets_size,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "event=decision failed to parse IKeystoreAuthorization request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        info!(
            "event=decision command={} authorization_method={:?} code=0x{:x} uid={} pid={} sid='{}'; mirroring auth state to OMK after system success",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
        );

        let requires_mirror = authorization_requires_mirror(&request);
        if requires_mirror && !expects_reply {
            if matches!(request, ParsedAuthorizationRequest::AddAuthToken { .. }) {
                warn!(
                    "event=mirror cannot confirm one-way authorization {:?} for uid={} pid={}; preserving System mutation without an OMK mirror",
                    method, caller_uid, caller.pid
                );
                return false;
            }
            warn!(
                "event=mirror cannot confirm one-way authorization {:?} for uid={} pid={}; blocking System mutation",
                method, caller_uid, caller.pid
            );
            block_system_request(tr);
            return true;
        }
        let pending = PendingAuthorizationCall { request, method, caller, config: cfg };
        if expects_reply {
            replace_top_pending(connection, PendingCall::Authorization(pending));
        }
        return false;
    }

    // Maintenance calls mostly carry global keystore state, so mirror them after
    // system success. migrateKeyNamespace moves app keys, so scoop-routed callers
    // use OMK as the authoritative business path.
    if request_interface == identify::KEYSTORE_MAINTENANCE_INTERFACE {
        let request = match parcel::parse_maintenance_request(
            data,
            data_size,
            offsets,
            offsets_size,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "event=decision failed to parse IKeystoreMaintenance request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        let (route, packages, reason) = match &request {
            ParsedMaintenanceRequest::MigrateKeyNamespace { .. } => {
                let decision = evaluate_caller(&caller, &cfg);
                (
                    if decision.allowed { RouteTarget::Omk } else { RouteTarget::System },
                    decision.packages,
                    Some(decision.reason),
                )
            }
            _ => (RouteTarget::System, Vec::new(), None),
        };
        let pending = PendingMaintenanceCall { request, caller, route, config: cfg };
        let precomputed = if pending.route == RouteTarget::Omk
            && matches!(&pending.request, ParsedMaintenanceRequest::MigrateKeyNamespace { .. })
        {
            block_system_request(tr);
            Some(precompute_omk_migrate_reply(&pending))
        } else {
            None
        };
        let request_rewritten = precomputed.is_some();
        let route_note =
            if matches!(&pending.request, ParsedMaintenanceRequest::MigrateKeyNamespace { .. }) {
                "using caller scoop decision as authoritative business path"
            } else {
                "mirroring maintenance state to OMK after system success"
            };
        info!(
            "event=decision command={} maintenance_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} route={:?} reason={:?}; {}",
            command_name,
            method,
            tr.code,
            caller_uid,
            pending.caller.pid,
            pending.caller.sid,
            packages,
            pending.route,
            reason,
            route_note,
        );

        let requires_mirror =
            pending.route == RouteTarget::System && maintenance_requires_mirror(&pending.request);
        if requires_mirror && !expects_reply {
            warn!(
                "event=mirror cannot confirm one-way maintenance {:?} for uid={} pid={}; blocking System mutation",
                method, caller_uid, pending.caller.pid
            );
            block_system_request(tr);
            return true;
        }
        if !expects_reply {
            return request_rewritten;
        }
        if let Some(reply) = precomputed {
            replace_top_pending(connection, PendingCall::PrecomputedMaintenance(pending, reply));
        } else {
            replace_top_pending(connection, PendingCall::Maintenance(pending));
        }
        return request_rewritten;
    }

    if request_interface == identify::KEYSTORE_SERVICE_INTERFACE {
        let request =
            match parcel::parse_service_request(data, data_size, offsets, offsets_size, tr.code) {
                Ok(request) => request,
                Err(error) => {
                    debug!(
                        "event=decision failed to parse IKeystoreService request code=0x{:x}: {:#}",
                        tr.code, error
                    );
                    return false;
                }
            };

        let method = request.method();
        let original_code = tr.code;
        let decision = identify::is_omk_service_route_enabled(method, &cfg.intercept)
            .then(|| evaluate_caller(&caller, &cfg));
        let route = route_for_service_request(
            &request,
            decision.as_ref().is_some_and(|decision| decision.allowed),
            &cfg.intercept,
        );

        let mut precomputed_service_reply = if route == RouteTarget::Omk
            && matches!(
                method,
                ServiceMethod::UpdateSubcomponent
                    | ServiceMethod::Grant
                    | ServiceMethod::Ungrant
                    | ServiceMethod::DeleteKey
            ) {
            block_system_request(tr);
            Some(precompute_omk_service_mutator_reply(&request, &caller))
        } else if route == RouteTarget::Omk
            && expects_reply
            && method != ServiceMethod::GetSecurityLevel
        {
            block_system_request(tr);
            let reply = match build_omk_service_reply(&request, &caller) {
                Ok(Some(reply)) => reply,
                Ok(None) => synthetic_fallback_reply(),
                Err(error) => {
                    warn!("event=reply failed to precompute OMK service reply: {error:#}");
                    synthetic_fallback_reply()
                }
            };
            Some(PrecomputedServiceReply::Serialized(Box::new(Some(reply))))
        } else {
            None
        };
        let request_rewritten = precomputed_service_reply.is_some();

        info!(
            "event=decision command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={:?} reason={:?}",
            command_name,
            method,
            original_code,
            caller.uid,
            caller.pid,
            caller.sid,
            decision.as_ref().map(|decision| &decision.packages),
            decision.as_ref().map(|decision| decision.allowed),
            decision.as_ref().map(|decision| &decision.reason),
        );
        info!(
            "event=route method={:?} uid={} pid={} route={:?}",
            method, caller.uid, caller.pid, route
        );

        let pending = PendingServiceCall {
            request,
            caller,
            packages: decision.map(|decision| decision.packages).unwrap_or_default(),
            route,
        };
        if !expects_reply {
            if let Some(reply) = precomputed_service_reply.as_mut() {
                if let Err(error) = build_precomputed_service_reply(reply) {
                    warn!(
                        "event=route failed to build one-way OMK service {:?} reply for uid={} pid={}: {:#}",
                        method, caller_uid, pending.caller.pid, error
                    );
                }
                return request_rewritten;
            }
        }
        if expects_reply {
            if let Some(reply) = precomputed_service_reply {
                replace_top_pending(connection, PendingCall::PrecomputedService(pending, reply));
            } else {
                replace_top_pending(connection, PendingCall::Service(pending));
            }
        }
        return request_rewritten;
    }

    let Some(target) = target_from_transaction(tr) else {
        debug!(
            "event=decision skipping keystore request without local target code=0x{:x} target={}",
            tr.code,
            format_target(tr)
        );
        return false;
    };

    if request_interface == identify::KEYSTORE_SECURITY_LEVEL_INTERFACE {
        let Some(target_info) = tracker::lookup_security_level_target(target) else {
            debug!(
                "event=decision skipping IKeystoreSecurityLevel request for unmapped target ptr=0x{:x} cookie=0x{:x}",
                target.ptr, target.cookie
            );
            return false;
        };

        let request = match parcel::parse_security_level_request(
            data,
            data_size,
            offsets,
            offsets_size,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "event=decision failed to parse IKeystoreSecurityLevel request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        // Keystore2 shares each security-level Binder between getSecurityLevel and getKeyEntry.
        let scoop_enabled = security_level_scoop_enabled(&cfg.intercept);
        let decision = scoop_enabled.then(|| evaluate_caller(&caller, &cfg));
        let route = if decision.as_ref().is_some_and(|decision| decision.allowed) {
            RouteTarget::Omk
        } else {
            RouteTarget::System
        };
        if let Some(decision) = decision.as_ref().filter(|decision| !decision.allowed) {
            info!(
                "event=decision command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=false reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?}; routing request to System",
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
        }

        info!(
            "event=decision command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={:?} reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?} scoop_enabled={}",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
            decision.as_ref().map(|decision| &decision.packages),
            decision.as_ref().map(|decision| decision.allowed),
            decision.as_ref().map(|decision| &decision.reason),
            target.ptr,
            target.cookie,
            target_info.security_level,
            scoop_enabled,
        );
        info!(
            "event=route security_level_method={:?} uid={} pid={} route={:?} security_level={:?}",
            method, caller.uid, caller.pid, route, target_info.security_level
        );

        let pending = PendingSecurityLevelCall {
            request,
            caller,
            packages: decision.map(|decision| decision.packages).unwrap_or_default(),
            route,
            security_level: target_info.security_level,
        };
        if expects_reply && pending.route == RouteTarget::Omk {
            let reply = match build_omk_security_level_reply(&pending, true) {
                Ok(Some(reply)) => reply,
                Ok(None) => synthetic_fallback_reply(),
                Err(error) => {
                    warn!(
                        "event=route failed to precompute authoritative OMK security-level {:?} reply for uid={} pid={}: {:#}; returning SYSTEM_ERROR without executing System",
                        method, caller_uid, pending.caller.pid, error
                    );
                    synthetic_fallback_reply()
                }
            };
            block_system_request(tr);
            replace_top_pending(
                connection,
                PendingCall::PrecomputedSecurityLevel(pending, Box::new(Some(reply))),
            );
            return true;
        }
        if !expects_reply
            && route == RouteTarget::Omk
            && can_execute_one_way(SyntheticTargetKind::SecurityLevel, tr.code)
        {
            return handle_omk_one_way_security_level_request(tr, &pending);
        }
        if expects_reply {
            replace_top_pending(connection, PendingCall::SecurityLevel(pending));
        }
        return false;
    }

    if request_interface == identify::KEYSTORE_OPERATION_INTERFACE {
        let Some(operation_target) = lookup_operation_target(target) else {
            debug!(
                "event=decision skipping IKeystoreOperation request for unmapped target ptr=0x{:x} cookie=0x{:x}",
                target.ptr, target.cookie
            );
            return false;
        };

        let request = match parcel::parse_operation_request(
            data,
            data_size,
            offsets,
            offsets_size,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                debug!(
                    "event=decision failed to parse IKeystoreOperation request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();

        info!(
            "event=decision command={} operation_method={:?} code=0x{:x} uid={} pid={} sid='{}' target=ptr:0x{:x}/cookie:0x{:x}",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
            target.ptr,
            target.cookie,
        );
        info!(
            "event=route operation_method={:?} uid={} pid={} route={:?}",
            method, caller.uid, caller.pid, operation_target.route
        );

        let pending =
            PendingOperationCall { request, caller, target, route: operation_target.route };
        if !expects_reply
            && operation_target.route == RouteTarget::Omk
            && can_execute_one_way(SyntheticTargetKind::Operation, tr.code)
        {
            return handle_omk_one_way_operation_request(tr, &pending);
        }
        if expects_reply {
            replace_top_pending(connection, PendingCall::Operation(pending));
        }
        return false;
    }

    debug!("event=decision skipping unsupported keystore interface request code=0x{:x}", tr.code);

    false
}

unsafe fn handle_omk_one_way_security_level_request(
    tr: &mut binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> bool {
    match build_security_level_reply_rewrite(tr, pending) {
        Ok(Some(_)) => {
            block_system_request(tr);
            true
        }
        Ok(None) => false,
        Err(error) => {
            warn!(
                "event=route failed to execute one-way OMK security-level {:?} for uid={} pid={}: {:#}; consuming original system request",
                pending.request.method(), pending.caller.uid, pending.caller.pid, error
            );
            block_system_request(tr);
            true
        }
    }
}

unsafe fn handle_omk_one_way_operation_request(
    tr: &mut binder_transaction_data,
    pending: &PendingOperationCall,
) -> bool {
    if let Err(error) = build_operation_reply_rewrite(pending) {
        warn!(
            "event=route failed to execute one-way OMK operation {:?} for uid={} pid={}: {:#}; consuming original system request",
            pending.request.method(), pending.caller.uid, pending.caller.pid, error
        );
    }
    block_system_request(tr);
    true
}

fn block_system_request(tr: &mut binder_transaction_data) {
    // Keep the parcel intact; the interceptor owns any receive-buffer shadow.
    tr.code = u32::MAX;
}
