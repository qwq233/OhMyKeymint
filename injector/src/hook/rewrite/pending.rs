use super::*;

pub(super) struct PendingAuthorizationCall {
    pub(super) request: ParsedAuthorizationRequest,
    pub(super) method: AuthorizationMethod,
    pub(super) caller: CallerInfo,
    pub(super) mirror_update: Option<MirrorUpdateReservation>,
}

pub(super) struct PendingMaintenanceCall {
    pub(super) request: ParsedMaintenanceRequest,
    pub(super) caller: CallerInfo,
    pub(super) route: RouteTarget,
    pub(super) mirror_update: Option<MirrorUpdateReservation>,
}

pub(super) struct PendingServiceCall {
    pub(super) request: ParsedServiceRequest,
    pub(super) caller: CallerInfo,
    pub(super) packages: Vec<String>,
    pub(super) route: RouteTarget,
}

pub(super) struct PendingSecurityLevelCall {
    pub(super) request: ParsedSecurityLevelRequest,
    pub(super) caller: CallerInfo,
    pub(super) packages: Vec<String>,
    pub(super) route: RouteTarget,
    pub(super) security_level:
        crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
}

pub(super) struct PendingOperationCall {
    pub(super) request: ParsedOperationRequest,
    pub(super) caller: CallerInfo,
    pub(super) target: LocalBinderTarget,
}

pub(super) enum PrecomputedServiceReply {
    UpdateSubcomponentSuccess,
    GrantSuccess(KeyDescriptor),
    UngrantSuccess,
    DeleteKeySuccess,
    Error(Status),
}

pub(super) enum PrecomputedMaintenanceReply {
    Success,
    Error(Status),
}

pub(super) enum OmkServicePrecompute {
    Reply(PrecomputedServiceReply),
    PreserveSystem,
}

pub(super) enum OmkMigratePrecompute {
    Reply(PrecomputedMaintenanceReply),
    PreserveSystem,
}

pub(super) enum PendingCall {
    Authorization(PendingAuthorizationCall),
    PrecomputedAuthorization(PendingAuthorizationCall, Status),
    Maintenance(PendingMaintenanceCall),
    PrecomputedMaintenance(PendingMaintenanceCall, PrecomputedMaintenanceReply),
    Service(PendingServiceCall),
    PrecomputedService(PendingServiceCall, PrecomputedServiceReply),
    SecurityLevel(PendingSecurityLevelCall),
    PrecomputedSecurityLevel(PendingSecurityLevelCall, Box<Option<OutboundReply>>),
    Operation(PendingOperationCall),
}

struct PendingReplyFrame {
    id: u64,
    connection: BinderStateKey,
    pending: Option<PendingCall>,
    claimed: bool,
}

impl PendingCall {
    fn reply_log_context(&self) -> (&'static str, String, i64, i64) {
        match self {
            Self::Authorization(call) | Self::PrecomputedAuthorization(call, _) => (
                "authorization",
                format!("{:?}", call.method),
                call.caller.uid,
                call.caller.pid,
            ),
            Self::Maintenance(call) | Self::PrecomputedMaintenance(call, _) => (
                "maintenance",
                format!("{:?}", call.request.method()),
                call.caller.uid,
                call.caller.pid,
            ),
            Self::Service(call) | Self::PrecomputedService(call, _) => (
                "service",
                format!("{:?}", call.request.method()),
                call.caller.uid,
                call.caller.pid,
            ),
            Self::SecurityLevel(call) | Self::PrecomputedSecurityLevel(call, _) => (
                "security-level",
                format!("{:?}", call.request.method()),
                call.caller.uid,
                call.caller.pid,
            ),
            Self::Operation(call) => (
                "operation",
                format!("{:?}", call.request.method()),
                call.caller.uid,
                call.caller.pid,
            ),
        }
    }
}

thread_local! {
    static PENDING_REPLY_QUEUE: RefCell<Vec<PendingReplyFrame>> = RefCell::default();
    static OUTBOUND_REPLY_BUFFERS: RefCell<Vec<(BinderStateKey, parcel::OwnedReply)>> = RefCell::default();
}

static NEXT_PENDING_REPLY_FRAME_ID: AtomicU64 = AtomicU64::new(1);

pub(in crate::hook) unsafe fn handle_bc_reply(
    connection: BinderStateKey,
    tr: &mut binder_transaction_data,
) -> Option<u64> {
    let (frame_id, pending) = PENDING_REPLY_QUEUE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let frame = slot
            .iter_mut()
            .rev()
            .find(|frame| frame.connection == connection && !frame.claimed)?;
        frame.claimed = true;
        Some((frame.id, frame.pending.take()))
    })?;
    let Some(mut pending) = pending else {
        return Some(frame_id);
    };

    let original_data_size = tr.data_size;
    let original_offsets_size = tr.offsets_size;
    let original_flags = tr.flags;
    let original_objects = describe_transaction_objects(tr);

    let result = match &mut pending {
        PendingCall::Authorization(call) => {
            debug!(
                "event=reply handling authorization {:?} uid={} pid={}",
                call.method, call.caller.uid, call.caller.pid
            );
            build_authorization_reply_mirror(tr, call)
        }
        PendingCall::PrecomputedAuthorization(call, status) => {
            debug!(
                "event=reply handling precomputed authorization {:?} uid={} pid={}",
                call.method, call.caller.uid, call.caller.pid
            );
            build_omk_status_reply(status).map(Some)
        }
        PendingCall::Maintenance(call) => {
            debug!(
                "event=reply handling maintenance {:?} uid={} pid={}",
                call.request.method(),
                call.caller.uid,
                call.caller.pid
            );
            build_maintenance_reply_mirror(tr, call)
        }
        PendingCall::PrecomputedMaintenance(call, precomputed) => {
            debug!(
                "event=reply handling precomputed maintenance {:?} route={:?} uid={} pid={}",
                call.request.method(),
                call.route,
                call.caller.uid,
                call.caller.pid
            );
            build_precomputed_maintenance_reply(precomputed).map(Some)
        }
        PendingCall::Service(call) => {
            debug!(
                "event=reply handling service {:?} route={:?} uid={} pid={} packages={:?}",
                call.request.method(),
                call.route,
                call.caller.uid,
                call.caller.pid,
                call.packages
            );
            build_service_reply_rewrite(tr, call)
        }
        PendingCall::PrecomputedService(call, precomputed) => {
            debug!(
                "event=reply handling precomputed service {:?} route={:?} uid={} pid={} packages={:?}",
                call.request.method(), call.route, call.caller.uid, call.caller.pid, call.packages
            );
            build_precomputed_service_reply(precomputed).map(Some)
        }
        PendingCall::SecurityLevel(call) => {
            debug!(
                "event=reply handling security-level {:?} route={:?} uid={} pid={} packages={:?} security_level={:?}",
                call.request.method(), call.route, call.caller.uid, call.caller.pid, call.packages, call.security_level
            );
            build_security_level_reply_rewrite(tr, call)
        }
        PendingCall::PrecomputedSecurityLevel(call, reply) => {
            debug!(
                "event=reply handling precomputed security-level {:?} route={:?} uid={} pid={} packages={:?} security_level={:?}",
                call.request.method(), call.route, call.caller.uid, call.caller.pid, call.packages, call.security_level
            );
            reply
                .take()
                .ok_or_else(|| anyhow::anyhow!("precomputed security-level reply already consumed"))
                .map(Some)
        }
        PendingCall::Operation(call) => {
            debug!(
                "event=reply handling operation {:?} uid={} pid={} target=ptr:0x{:x}/cookie:0x{:x}",
                call.request.method(),
                call.caller.uid,
                call.caller.pid,
                call.target.ptr,
                call.target.cookie
            );
            build_operation_reply_rewrite(call)
        }
    };

    match result {
        Ok(Some(reply)) => {
            let (kind, method, uid, pid) = pending.reply_log_context();
            install_outbound_reply(connection, tr, reply);
            debug!(
                "event=reply rewrote {} {} reply for uid={} pid={} original={{flags=0x{:x}, data_size={}, offsets_size={}, objects={}}} rewritten={{flags=0x{:x}, data_size={}, offsets_size={}, objects={}}}",
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
        Ok(None) => {
            let observed = match &pending {
                PendingCall::Service(call) if call.route == RouteTarget::Omk => {
                    observe_system_service_reply(tr, call)
                }
                PendingCall::SecurityLevel(call) if call.route == RouteTarget::Omk => {
                    observe_system_security_level_reply(tr, call)
                }
                _ => Ok(None),
            };
            match observed {
                Ok(Some(reply)) => install_outbound_reply(connection, tr, reply),
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        "event=route failed to observe preserved system fallback reply: {:#}",
                        error
                    );
                }
            }
        }
        Err(error) => {
            if pending_preserves_system_on_rewrite_failure(&pending) {
                warn!(
                    "event=reply failed to rewrite pending reply: {:#}; keeping original system reply",
                    error
                );
            } else {
                warn!(
                    "event=reply failed to rewrite authoritative OMK reply: {:#}; returning SYSTEM_ERROR",
                    error
                );
                install_outbound_reply(connection, tr, synthetic_fallback_reply());
            }
        }
    }
    Some(frame_id)
}

fn pending_preserves_system_on_rewrite_failure(pending: &PendingCall) -> bool {
    match pending {
        PendingCall::Authorization(_) => true,
        PendingCall::PrecomputedAuthorization(_, _) => false,
        PendingCall::Maintenance(call) => call.route != RouteTarget::Omk,
        PendingCall::PrecomputedMaintenance(_, _) => false,
        PendingCall::Service(call) => call.route != RouteTarget::Omk,
        PendingCall::PrecomputedService(_, _) => false,
        PendingCall::SecurityLevel(call) => call.route != RouteTarget::Omk,
        PendingCall::PrecomputedSecurityLevel(_, _) => false,
        PendingCall::Operation(call) => lookup_operation_target(call.target)
            .is_some_and(|target| target.route == RouteTarget::System),
    }
}

unsafe fn install_outbound_reply(
    connection: BinderStateKey,
    tr: &mut binder_transaction_data,
    reply: OutboundReply,
) {
    if let Some(retirement) = reply.native_operation {
        bind_operation_publication_connection(retirement, connection);
    }
    OUTBOUND_REPLY_BUFFERS.with(|slot| {
        let mut buffers = slot.borrow_mut();
        buffers.push((connection, reply));
        let reply = &buffers.last().expect("outbound reply buffer just pushed").1;
        tr.flags &= !super::super::binder::TF_STATUS_CODE;
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

pub(in crate::hook) fn push_pending_frame(connection: BinderStateKey) {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow_mut().push(PendingReplyFrame {
            id: NEXT_PENDING_REPLY_FRAME_ID.fetch_add(1, Ordering::Relaxed),
            connection,
            pending: None,
            claimed: false,
        });
    });
}

pub(super) fn replace_top_pending(connection: BinderStateKey, pending: PendingCall) {
    PENDING_REPLY_QUEUE.with(|slot| {
        if let Some(frame) = slot
            .borrow_mut()
            .iter_mut()
            .rev()
            .find(|frame| frame.connection == connection && !frame.claimed)
        {
            frame.pending = Some(pending);
        }
    });
}

#[cfg(test)]
pub(super) fn take_top_pending(connection: BinderStateKey) -> Option<Option<PendingCall>> {
    PENDING_REPLY_QUEUE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let position = slot
            .iter()
            .rposition(|frame| frame.connection == connection)?;
        Some(slot.remove(position).pending)
    })
}

fn remove_pending_reply_frame(frame_id: u64) {
    PENDING_REPLY_QUEUE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(position) = slot.iter().position(|frame| frame.id == frame_id) {
            slot.remove(position);
        }
    });
}

pub(in crate::hook) fn commit_bc_reply(
    connection: BinderStateKey,
    frame_id: Option<u64>,
    data_ptr: usize,
) -> Option<NativeBinderRetirement> {
    if let Some(frame_id) = frame_id {
        remove_pending_reply_frame(frame_id);
    }
    OUTBOUND_REPLY_BUFFERS.with(|slot| {
        let mut buffers = slot.borrow_mut();
        let position = buffers.iter_mut().position(|(reply_fd, reply)| {
            *reply_fd == connection && reply.data_ptr() as usize == data_ptr
        })?;
        buffers.remove(position).1.native_operation.take()
    })
}

pub(in crate::hook) fn abort_bc_reply(
    connection: BinderStateKey,
    frame_id: Option<u64>,
    data_ptr: usize,
) {
    if let Some(frame_id) = frame_id {
        remove_pending_reply_frame(frame_id);
    }
    OUTBOUND_REPLY_BUFFERS.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(position) = slot.iter().position(|(reply_fd, reply)| {
            *reply_fd == connection && reply.data_ptr() as usize == data_ptr
        }) {
            slot.remove(position);
        }
    });
}

pub(in crate::hook) fn clear_outbound_reply_buffers(connection: BinderStateKey) {
    OUTBOUND_REPLY_BUFFERS.with(|slot| {
        slot.borrow_mut()
            .retain(|(reply_fd, _)| *reply_fd != connection);
    });
}

pub(in crate::hook) fn clear_binder_fd_thread_state(connection: BinderStateKey) {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow_mut()
            .retain(|frame| frame.connection != connection);
    });
    clear_outbound_reply_buffers(connection);
}

#[cfg(test)]
pub(in crate::hook) fn reset_pending_reply_frames_for_test(
    connection: BinderStateKey,
    count: usize,
) {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    for _ in 0..count {
        push_pending_frame(connection);
    }
}

#[cfg(test)]
pub(in crate::hook) fn pending_reply_frame_count_for_test(connection: BinderStateKey) -> usize {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow()
            .iter()
            .filter(|frame| frame.connection == connection)
            .count()
    })
}

#[cfg(test)]
pub(in crate::hook) fn pending_reply_frame_claims_for_test(
    connection: BinderStateKey,
) -> Vec<bool> {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow()
            .iter()
            .filter(|frame| frame.connection == connection)
            .map(|frame| frame.claimed)
            .collect()
    })
}

#[cfg(test)]
pub(super) fn reset_pending_state_for_tests() {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    OUTBOUND_REPLY_BUFFERS.with(|slot| slot.borrow_mut().clear());
}

#[cfg(test)]
mod tests;
