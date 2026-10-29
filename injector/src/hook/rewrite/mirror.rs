use super::*;

#[cfg(test)]
mod tests;

pub(super) fn authorization_requires_mirror(request: &ParsedAuthorizationRequest) -> bool {
    !matches!(
        request,
        ParsedAuthorizationRequest::GetAuthTokensForCredStore { .. }
            | ParsedAuthorizationRequest::GetLastAuthTime { .. }
    )
}

pub(super) fn maintenance_requires_mirror(request: &ParsedMaintenanceRequest) -> bool {
    !matches!(
        request,
        ParsedMaintenanceRequest::GetState { .. }
            | ParsedMaintenanceRequest::OnDeviceOffBody
            | ParsedMaintenanceRequest::MigrateKeyNamespace { .. }
            | ParsedMaintenanceRequest::GetAppUidsAffectedBySid { .. }
    )
}

pub(super) fn mirror_preserves_system_on_failure(
    caller: &CallerInfo,
    cfg: &config::InjectorConfig,
) -> bool {
    !evaluate_caller(caller, cfg).allowed
}

/// # Safety
///
/// The transaction's data and offsets must describe a readable Binder reply
/// parcel that remains alive and unchanged for the duration of this call.
unsafe fn build_mirror_reply(
    tr: &binder_transaction_data,
    caller: &CallerInfo,
    cfg: &config::InjectorConfig,
    requires_mirror: bool,
    execute: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<Option<OutboundReply>> {
    // SAFETY: The caller keeps Binder's raw parcel buffers readable for decoding.
    let status = unsafe {
        let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
        parcel::parse_reply_status(data, data_size, offsets, offsets_size)?
    };
    if !status.is_ok() || !requires_mirror {
        return Ok(None);
    }

    let _guard = BypassGuard::enter();
    match execute() {
        Ok(()) => Ok(None),
        Err(error) => {
            if mirror_preserves_system_on_failure(caller, cfg) {
                warn!(
                    "event=mirror OMK update failed for uid={} pid={}: {:#}; preserving System reply",
                    caller.uid, caller.pid, error
                );
                Ok(None)
            } else {
                warn!(
                    "event=mirror OMK update failed for uid={} pid={}: {:#}; returning OMK error",
                    caller.uid, caller.pid, error
                );
                build_omk_error_reply(&error).map(Some)
            }
        }
    }
}

/// # Safety
///
/// The transaction's data and offsets must describe a readable Binder reply
/// parcel that remains alive and unchanged for the duration of this call.
pub(super) unsafe fn build_authorization_reply_mirror(
    tr: &binder_transaction_data,
    call: &PendingAuthorizationCall,
) -> anyhow::Result<Option<OutboundReply>> {
    // SAFETY: The caller supplies the same live reply buffers required by the
    // helper.
    unsafe {
        build_mirror_reply(
            tr,
            &call.caller,
            &call.config,
            authorization_requires_mirror(&call.request),
            || execute_authorization_mirror(&call.request, &call.caller),
        )
    }
}

fn execute_authorization_mirror(
    request: &ParsedAuthorizationRequest,
    caller: &CallerInfo,
) -> anyhow::Result<()> {
    match request {
        ParsedAuthorizationRequest::AddAuthToken { auth_token } => {
            ipc::with_omk_auth_token_once(|auth| Ok(auth.r#addAuthToken(Some(caller), auth_token)?))
        }
        ParsedAuthorizationRequest::OnDeviceUnlocked { user_id, password } => {
            ipc::with_omk_authorization_once(|auth| {
                Ok(auth.r#onDeviceUnlocked(Some(caller), *user_id, password.as_deref())?)
            })
        }
        ParsedAuthorizationRequest::OnDeviceLocked {
            user_id,
            unlocking_sids,
            weak_unlock_enabled,
        } => ipc::with_omk_authorization_once(|auth| {
            Ok(auth.r#onDeviceLocked(
                Some(caller),
                *user_id,
                unlocking_sids,
                *weak_unlock_enabled,
            )?)
        }),
        ParsedAuthorizationRequest::OnUserStorageLocked { user_id } => {
            ipc::with_omk_authorization_once(|auth| {
                Ok(auth.r#onUserStorageLocked(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnWeakUnlockMethodsExpired { user_id } => {
            ipc::with_omk_authorization_once(|auth| {
                Ok(auth.r#onWeakUnlockMethodsExpired(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnNonLskfUnlockMethodsExpired { user_id } => {
            ipc::with_omk_authorization_once(|auth| {
                Ok(auth.r#onNonLskfUnlockMethodsExpired(Some(caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::GetAuthTokensForCredStore { .. }
        | ParsedAuthorizationRequest::GetLastAuthTime { .. } => Ok(()),
    }
}

/// # Safety
///
/// The transaction's data and offsets must describe a readable Binder reply
/// parcel that remains alive and unchanged for the duration of this call.
pub(super) unsafe fn build_maintenance_reply_mirror(
    tr: &binder_transaction_data,
    call: &PendingMaintenanceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    // SAFETY: The caller supplies the same live reply buffers required by the
    // helper.
    unsafe {
        build_mirror_reply(
            tr,
            &call.caller,
            &call.config,
            maintenance_requires_mirror(&call.request),
            || execute_maintenance_mirror(&call.request, &call.caller),
        )
    }
}

fn execute_maintenance_mirror(
    request: &ParsedMaintenanceRequest,
    caller: &CallerInfo,
) -> anyhow::Result<()> {
    match request {
        ParsedMaintenanceRequest::OnUserAdded { user_id } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserAdded(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::InitUserSuperKeys { user_id, password, allow_existing } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#initUserSuperKeys(
                    Some(caller),
                    *user_id,
                    password,
                    *allow_existing,
                )?)
            })
        }
        ParsedMaintenanceRequest::OnUserRemoved { user_id } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserRemoved(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::OnUserLskfRemoved { user_id } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserLskfRemoved(Some(caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::ClearNamespace { domain, nspace } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#clearNamespace(Some(caller), *domain, *nspace)?)
            })
        }
        ParsedMaintenanceRequest::EarlyBootEnded => ipc::with_omk_maintenance_once(|maintenance| {
            Ok(maintenance.r#earlyBootEnded(Some(caller))?)
        }),
        ParsedMaintenanceRequest::MigrateKeyNamespace { .. } => {
            unreachable!("migrateKeyNamespace is handled before maintenance mirroring")
        }
        ParsedMaintenanceRequest::DeleteAllKeys => ipc::with_omk_maintenance_once(|maintenance| {
            Ok(maintenance.r#deleteAllKeys(Some(caller))?)
        }),
        ParsedMaintenanceRequest::OnUserPasswordChanged { user_id, password } => {
            ipc::with_omk_maintenance_once(|maintenance| {
                Ok(maintenance.r#onUserPasswordChanged(
                    Some(caller),
                    *user_id,
                    password.as_deref(),
                )?)
            })
        }
        ParsedMaintenanceRequest::GetState { .. }
        | ParsedMaintenanceRequest::OnDeviceOffBody
        | ParsedMaintenanceRequest::GetAppUidsAffectedBySid { .. } => Ok(()),
    }
}
