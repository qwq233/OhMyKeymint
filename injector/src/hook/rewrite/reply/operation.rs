use super::*;

fn operation_error_finalizes(status: &Status) -> bool {
    status.exception_code() != ExceptionCode::ServiceSpecific
        || status.service_specific_error() != ResponseCode::OPERATION_BUSY.0
}

pub(super) fn operation_allows_aad(
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

pub(super) unsafe fn register_operation_target_from_reply(
    tr: &binder_transaction_data,
    route: RouteTarget,
    backend: Option<AospOperationBinder>,
    aad_allowed: bool,
) -> anyhow::Result<bool> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let carrier =
        parcel::extract_create_operation_reply_carrier(data, data_size, offsets, offsets_size)?;
    if !carrier.is_object {
        return Ok(false);
    }

    let target = parse_local_binder_target_from_parcel_bytes(&carrier.bytes)
        .ok_or_else(|| anyhow::anyhow!("failed to parse local operation carrier target"))?;
    remember_operation_target(
        target,
        OperationTargetInfo {
            route,
            aad_allowed,
            backend,
            finalized: false,
        },
    );
    debug!(
        "event=route observed operation carrier ptr=0x{:x} cookie=0x{:x} preferred_route={:?} aad_allowed={}",
        target.ptr,
        target.cookie,
        route,
        aad_allowed,
    );
    Ok(true)
}

fn invalid_operation_handle_reply() -> anyhow::Result<parcel::OwnedReply> {
    build_service_specific_reply(
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0,
    )
}

pub(in crate::hook::rewrite) fn build_no_carrier_create_operation_reply(
    mut response: crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
    aad_allowed: bool,
    caller: &CallerInfo,
    publish_operation_carrier: bool,
) -> anyhow::Result<parcel::OwnedReply> {
    if !publish_operation_carrier {
        let _guard = BypassGuard::enter();
        if let Some(operation) = response.r#iOperation.take() {
            if let Err(status) = operation.r#abort() {
                warn!(
                    "event=synthetic failed to abort OMK operation discarded after one-way createOperation: {}",
                    status
                );
            }
        }
        return parcel::build_void_reply();
    }

    let Some(operation) = response.r#iOperation.take() else {
        return parcel::build_create_operation_reply(response);
    };

    let abort_backend = operation.clone();
    let (carrier, retirement) = match register_synthetic_operation_carrier(
        operation,
        aad_allowed,
        caller,
    ) {
        Ok(registered) => registered,
        Err(error) => {
            let _guard = BypassGuard::enter();
            if let Err(status) = abort_backend.r#abort() {
                warn!(
                    "event=synthetic failed to abort OMK operation after carrier registration failed: {}",
                    status
                );
            }
            return Err(error);
        }
    };
    let reply = parcel::build_create_operation_reply_with_carrier_bytes(
        response.r#operationChallenge,
        response.r#parameters,
        response.r#upgradedBlob,
        &carrier.bytes,
        carrier.is_object,
    );
    match reply {
        Ok(mut reply) => {
            reply.native_operation = Some(retirement);
            Ok(reply)
        }
        Err(error) => {
            drop_synthetic_operation_retirement(retirement);
            Err(error)
        }
    }
}

pub(in crate::hook::rewrite) fn build_operation_reply_rewrite(
    pending: &PendingOperationCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let Some(target) = lookup_operation_target(pending.target) else {
        if lookup_synthetic_target(pending.target) == Some(SyntheticTargetKind::Operation) {
            debug!(
                "event=reply synthetic operation carrier ptr=0x{:x} cookie=0x{:x} has no live backend; returning INVALID_OPERATION_HANDLE",
                pending.target.ptr, pending.target.cookie
            );
            return Ok(Some(invalid_operation_handle_reply()?));
        }
        anyhow::bail!("missing operation target mapping");
    };

    if target.route == RouteTarget::System {
        if matches!(
            pending.request,
            ParsedOperationRequest::Finish { .. } | ParsedOperationRequest::Abort
        ) {
            forget_operation_target(pending.target);
        }
        return Ok(None);
    }

    if let Err(error) = ensure_mirror_state_recovered() {
        warn!(
            "event=route OMK operation {:?} blocked by unresolved mirror recovery for uid={} pid={}: {:#}",
            pending.request.method(), pending.caller.uid, pending.caller.pid, error
        );
        return Ok(Some(synthetic_fallback_reply()));
    }

    let Some(backend) = target.backend else {
        if target.finalized {
            if matches!(pending.request, ParsedOperationRequest::Abort) {
                debug!(
                    "event=reply cleanup abort for finalized OMK operation carrier ptr=0x{:x} cookie=0x{:x}; returning INVALID_OPERATION_HANDLE",
                    pending.target.ptr, pending.target.cookie
                );
                forget_operation_target(pending.target);
            }
            return Ok(Some(invalid_operation_handle_reply()?));
        }
        anyhow::bail!("missing OMK operation backend mapping");
    };
    let _guard = BypassGuard::enter();

    let reply = match &pending.request {
        ParsedOperationRequest::UpdateAad { aad_input } => {
            if !target.aad_allowed {
                debug!(
                    "event=reply OMK-owned updateAad rejected on a non-AAD-capable operation; returning OMK status reply"
                );
            }
            match backend.r#updateAad(aad_input) {
                Ok(()) => parcel::build_void_reply()?,
                Err(status) => {
                    if operation_error_finalizes(&status) {
                        mark_operation_target_finalized(pending.target);
                    }
                    build_omk_status_reply(&status)?
                }
            }
        }
        ParsedOperationRequest::Update { input } => match backend.r#update(input) {
            Ok(output) => parcel::build_plain_reply(&output)?,
            Err(status) => {
                if operation_error_finalizes(&status) {
                    mark_operation_target_finalized(pending.target);
                }
                build_omk_status_reply(&status)?
            }
        },
        ParsedOperationRequest::Finish { input, signature } => {
            match backend.r#finish(input.as_deref(), signature.as_deref()) {
                Ok(output) => {
                    mark_operation_target_finalized(pending.target);
                    parcel::build_plain_reply(&output)?
                }
                Err(status) => {
                    if operation_error_finalizes(&status) {
                        mark_operation_target_finalized(pending.target);
                    }
                    build_omk_status_reply(&status)?
                }
            }
        }
        ParsedOperationRequest::Abort => match backend.r#abort() {
            Ok(()) => {
                forget_operation_target(pending.target);
                parcel::build_void_reply()?
            }
            Err(status) => {
                if operation_error_finalizes(&status) {
                    mark_operation_target_finalized(pending.target);
                }
                build_omk_status_reply(&status)?
            }
        },
    };

    Ok(Some(reply))
}

#[cfg(test)]
mod tests;
