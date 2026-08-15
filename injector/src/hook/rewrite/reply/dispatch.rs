use super::*;

static KEYSTORE2_AIDL_METADATA: OnceLock<Result<Keystore2AidlMetadata, String>> = OnceLock::new();

const KEYSTORE2_HAL_NAME: &str = "android.system.keystore2";
const KEYSTORE2_SERVICE_INTERFACE: &str = "IKeystoreService";
const KEYSTORE2_SERVICE_INSTANCE: &str = "default";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Keystore2AidlMetadata {
    version: i32,
    hash: &'static str,
}

fn synthetic_target_interface(kind: SyntheticTargetKind) -> &'static str {
    match kind {
        SyntheticTargetKind::SecurityLevel => identify::KEYSTORE_SECURITY_LEVEL_INTERFACE,
        SyntheticTargetKind::Operation => identify::KEYSTORE_OPERATION_INTERFACE,
    }
}

fn error_status_code(error: &anyhow::Error) -> Option<StatusCode> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StatusCode>().copied())
}

fn synthetic_parse_error_status_code(error: &anyhow::Error) -> StatusCode {
    error_status_code(error).unwrap_or(StatusCode::BadValue)
}

fn synthetic_parse_error_reply(status: StatusCode) -> anyhow::Result<SyntheticReply> {
    if status == StatusCode::UnexpectedNull {
        return Ok(synthetic_parcel_reply(parcel::build_status_reply(
            &Status::from(status),
        )?));
    }
    Ok(SyntheticReply::Status(status.into()))
}

fn synthetic_unknown_transaction_reply() -> SyntheticReply {
    SyntheticReply::Status(StatusCode::UnknownTransaction.into())
}

fn synthetic_parcel_reply(reply: parcel::OwnedReply) -> SyntheticReply {
    SyntheticReply::Parcel(Box::new(reply))
}

fn synthetic_reply_from_outbound(reply: Option<OutboundReply>) -> SyntheticReply {
    synthetic_parcel_reply(reply.unwrap_or_else(synthetic_fallback_reply))
}

fn synthetic_unknown_transaction_reply_for(
    kind: SyntheticTargetKind,
    code: u32,
) -> Option<SyntheticReply> {
    let known = match kind {
        SyntheticTargetKind::SecurityLevel => {
            identify::security_level_method_from_code(code).is_some()
        }
        SyntheticTargetKind::Operation => identify::operation_method_from_code(code).is_some(),
    };
    (!known).then(synthetic_unknown_transaction_reply)
}

fn build_synthetic_aidl_metadata_reply(
    method: AidlMetadataMethod,
) -> anyhow::Result<SyntheticReply> {
    let metadata = keystore2_aidl_metadata()?;
    match method {
        AidlMetadataMethod::GetInterfaceHash => {
            let hash = metadata.hash.to_string();
            Ok(synthetic_parcel_reply(parcel::build_plain_reply(&hash)?))
        }
        AidlMetadataMethod::GetInterfaceVersion => Ok(synthetic_parcel_reply(
            parcel::build_plain_reply(&metadata.version)?,
        )),
    }
}

fn keystore2_aidl_metadata() -> anyhow::Result<Keystore2AidlMetadata> {
    match KEYSTORE2_AIDL_METADATA
        .get_or_init(|| resolve_keystore2_aidl_metadata().map_err(|error| format!("{error:#}")))
    {
        Ok(metadata) => Ok(*metadata),
        Err(error) => Err(anyhow::anyhow!("{}", error)),
    }
}

fn resolve_keystore2_aidl_metadata() -> anyhow::Result<Keystore2AidlMetadata> {
    let version = probe_keystore2_aidl_version_from_vintf().unwrap_or_else(|| {
        let fallback = fallback_keystore2_aidl_version_from_android();
        warn!(
            "event=synthetic failed to resolve {} AIDL version from VINTF; using Android-version fallback v{}",
            KEYSTORE2_HAL_NAME, fallback
        );
        fallback
    });
    let hash =
        kmr_common::consts::android_system_keystore2_aidl_hash(version).ok_or_else(|| {
            anyhow::anyhow!(
                "no precomputed {} AIDL hash for version {}",
                KEYSTORE2_HAL_NAME,
                version
            )
        })?;
    Ok(Keystore2AidlMetadata { version, hash })
}

fn fallback_keystore2_aidl_version_from_android() -> i32 {
    kmr_common::android_version::android_major_version()
        .and_then(kmr_common::consts::android_system_keystore2_aidl_version_for_android_major)
        .unwrap_or(kmr_common::consts::ANDROID_SYSTEM_KEYSTORE2_LATEST_AIDL_VERSION)
}

fn probe_keystore2_aidl_version_from_vintf() -> Option<i32> {
    match kmr_common::vintf::resolve_aidl_hal_version(
        kmr_common::vintf::ManifestKind::Framework,
        KEYSTORE2_HAL_NAME,
        KEYSTORE2_SERVICE_INTERFACE,
        KEYSTORE2_SERVICE_INSTANCE,
    ) {
        Ok(Some(version)) => normalize_keystore2_aidl_version(version).or_else(|| {
            warn!(
                "event=synthetic unsupported {} AIDL version {} resolved from VINTF",
                KEYSTORE2_HAL_NAME, version
            );
            None
        }),
        Ok(None) => None,
        Err(error) => {
            warn!(
                "event=synthetic failed to resolve {} AIDL version from VINTF: {error:#}",
                KEYSTORE2_HAL_NAME
            );
            None
        }
    }
}

fn normalize_keystore2_aidl_version(version: i32) -> Option<i32> {
    (1..=kmr_common::consts::ANDROID_SYSTEM_KEYSTORE2_LATEST_AIDL_VERSION)
        .contains(&version)
        .then_some(version)
}

fn synthetic_debug_pid() -> i32 {
    unsafe { libc::getpid() }
}

unsafe fn synthetic_base_transaction_reply(
    kind: Option<SyntheticTargetKind>,
    target: LocalBinderTarget,
    tr: &binder_transaction_data,
) -> anyhow::Result<Option<SyntheticReply>> {
    let code = tr.code;
    let reply = match code {
        rsbinder::INTERFACE_TRANSACTION => match kind {
            Some(kind) => synthetic_parcel_reply(parcel::build_interface_descriptor_reply(
                synthetic_target_interface(kind),
            )?),
            None => synthetic_unknown_transaction_reply(),
        },
        rsbinder::PING_TRANSACTION
        | rsbinder::SHELL_COMMAND_TRANSACTION
        | rsbinder::SYSPROPS_TRANSACTION => synthetic_parcel_reply(parcel::build_empty_reply()),
        rsbinder::EXTENSION_TRANSACTION => {
            synthetic_parcel_reply(parcel::build_null_binder_reply()?)
        }
        rsbinder::DEBUG_PID_TRANSACTION => {
            synthetic_parcel_reply(parcel::build_raw_i32_reply(synthetic_debug_pid())?)
        }
        rsbinder::DUMP_TRANSACTION => {
            let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
            if let Err(error) =
                parcel::validate_dump_request(data, data_size, offsets, offsets_size)
            {
                warn!(
                    "event=synthetic malformed DUMP_TRANSACTION for target ptr=0x{:x} cookie=0x{:x} kind={:?}: {:#}; returning BAD_TYPE",
                    target.ptr, target.cookie, kind, error
                );
                SyntheticReply::Status(StatusCode::BadType.into())
            } else {
                synthetic_parcel_reply(parcel::build_empty_reply())
            }
        }
        rsbinder::SET_RPC_CLIENT_TRANSACTION
        | rsbinder::START_RECORDING_TRANSACTION
        | rsbinder::STOP_RECORDING_TRANSACTION => {
            SyntheticReply::Status(StatusCode::InvalidOperation.into())
        }
        rsbinder::TWEET_TRANSACTION | rsbinder::LIKE_TRANSACTION => {
            synthetic_unknown_transaction_reply()
        }
        _ if !(rsbinder::FIRST_CALL_TRANSACTION..=rsbinder::LAST_CALL_TRANSACTION)
            .contains(&code) =>
        {
            synthetic_unknown_transaction_reply()
        }
        _ => return Ok(None),
    };
    Ok(Some(reply))
}

fn synthetic_transaction_caller(
    fallback: Option<&CallerInfo>,
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
) -> CallerInfo {
    let uid = if tr.sender_euid >= 0 {
        i64::from(tr.sender_euid)
    } else {
        fallback.map_or(0, |caller| caller.uid)
    };
    let pid = if tr.sender_pid != 0 {
        i64::from(tr.sender_pid)
    } else {
        fallback.map_or(0, |caller| caller.pid)
    };
    let sid = caller_sid
        .filter(|sid| !sid.is_empty())
        .or_else(|| fallback.map(|caller| caller.sid.clone()))
        .unwrap_or_default();
    CallerInfo { uid, sid, pid }
}

pub(in crate::hook::rewrite) fn can_execute_one_way(kind: SyntheticTargetKind, code: u32) -> bool {
    match kind {
        SyntheticTargetKind::SecurityLevel => matches!(
            identify::security_level_method_from_code(code),
            Some(
                SecurityLevelMethod::GenerateKey
                    | SecurityLevelMethod::CreateOperation
                    | SecurityLevelMethod::ImportKey
                    | SecurityLevelMethod::ImportWrappedKey
                    | SecurityLevelMethod::DeleteKey
            )
        ),
        SyntheticTargetKind::Operation => matches!(
            identify::operation_method_from_code(code),
            Some(
                OperationMethod::UpdateAad
                    | OperationMethod::Update
                    | OperationMethod::Finish
                    | OperationMethod::Abort
            )
        ),
    }
}

pub(in crate::hook) unsafe fn handle_synthetic_br_transaction(
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
    command_name: &str,
) -> Option<SyntheticReply> {
    let target = target_from_transaction(tr)?;
    let info = lookup_synthetic_target_info(target)?;
    let kind = info.kind;

    let result = build_synthetic_br_transaction_reply(tr, target, info, caller_sid, command_name);
    let reply = match result {
        Ok(reply) => reply,
        Err(error) => {
            warn!(
                "event=synthetic failed to handle {} target=ptr:0x{:x}/cookie:0x{:x} kind={:?} code=0x{:x}: {:#}; returning SYSTEM_ERROR",
                command_name,
                target.ptr,
                target.cookie,
                kind,
                tr.code,
                error
            );
            if (tr.flags & crate::hook::binder::TF_ONE_WAY) != 0 {
                SyntheticReply::NoReply
            } else {
                synthetic_parcel_reply(synthetic_fallback_reply())
            }
        }
    };
    Some(reply)
}

unsafe fn build_synthetic_br_transaction_reply(
    tr: &binder_transaction_data,
    target: LocalBinderTarget,
    info: SyntheticTargetInfo,
    caller_sid: Option<String>,
    command_name: &str,
) -> anyhow::Result<SyntheticReply> {
    let expects_reply = (tr.flags & crate::hook::binder::TF_ONE_WAY) == 0;
    if !expects_reply && !can_execute_one_way(info.kind, tr.code) {
        return Ok(SyntheticReply::NoReply);
    }

    let reply =
        build_synthetic_br_transaction_reply_inner(tr, target, info, caller_sid, command_name)?;
    if expects_reply {
        Ok(reply)
    } else {
        Ok(SyntheticReply::NoReply)
    }
}

unsafe fn build_synthetic_br_transaction_reply_inner(
    tr: &binder_transaction_data,
    target: LocalBinderTarget,
    info: SyntheticTargetInfo,
    caller_sid: Option<String>,
    command_name: &str,
) -> anyhow::Result<SyntheticReply> {
    let kind = info.kind;
    if let Some(reply) = synthetic_base_transaction_reply(Some(kind), target, tr)? {
        return Ok(reply);
    }

    if let Some(method) = identify::aidl_metadata_method_from_code(tr.code) {
        let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
        let request_interface = match parcel::parse_metadata_request_interface_allow_trailing(
            data,
            data_size,
            offsets,
            offsets_size,
        ) {
            Ok(Some(interface)) => interface,
            Ok(None) => return Ok(SyntheticReply::Status(StatusCode::BadType.into())),
            Err(error) => {
                warn!(
                        "event=synthetic failed to read AIDL metadata interface token for target ptr=0x{:x} cookie=0x{:x} kind={:?} code=0x{:x}: {:#}; returning BAD_TYPE",
                        target.ptr, target.cookie, kind, tr.code, error
                    );
                return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
            }
        };
        let expected_interface = synthetic_target_interface(kind);
        if request_interface != expected_interface {
            warn!(
                "event=synthetic kind={:?} target ptr=0x{:x} cookie=0x{:x} received metadata request for unexpected interface {}; expected {}; returning BAD_TYPE",
                kind, target.ptr, target.cookie, request_interface, expected_interface
            );
            return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
        }
        return build_synthetic_aidl_metadata_reply(method);
    }

    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let request_interface = match parcel::peek_request_interface_for_check(
        data,
        data_size,
        offsets,
        offsets_size,
    ) {
        Ok(Some(interface)) => interface,
        Ok(None) => return Ok(SyntheticReply::Status(StatusCode::BadType.into())),
        Err(error) => {
            warn!(
                "event=synthetic failed to read interface token for target ptr=0x{:x} cookie=0x{:x} kind={:?} code=0x{:x}: {:#}; returning BAD_TYPE",
                target.ptr, target.cookie, kind, tr.code, error
            );
            return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
        }
    };
    let expected_interface = synthetic_target_interface(kind);
    if request_interface != expected_interface {
        warn!(
            "event=synthetic {:?} target ptr=0x{:x} cookie=0x{:x} received unexpected interface {}; expected {}; returning BAD_TYPE",
            kind, target.ptr, target.cookie, request_interface, expected_interface
        );
        return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
    }
    if let Some(reply) = synthetic_unknown_transaction_reply_for(kind, tr.code) {
        return Ok(reply);
    }

    let cfg = config::get();
    if !cfg.main.enabled {
        warn!(
            "event=synthetic injector disabled while synthetic target ptr=0x{:x} cookie=0x{:x} is still live; returning SYSTEM_ERROR",
            target.ptr, target.cookie
        );
        return Ok(synthetic_parcel_reply(build_service_specific_reply(
            ResponseCode::SYSTEM_ERROR.0,
        )?));
    }

    let fallback = match kind {
        SyntheticTargetKind::SecurityLevel => None,
        SyntheticTargetKind::Operation => Some(
            info.caller
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing synthetic operation caller fallback"))?,
        ),
    };
    let caller = synthetic_transaction_caller(fallback, tr, caller_sid);
    if kind == SyntheticTargetKind::SecurityLevel {
        let decision = evaluate_caller(&caller, &cfg);
        let request = match parcel::parse_security_level_request(
            data,
            data_size,
            offsets,
            offsets_size,
            tr.code,
        ) {
            Ok(request) => request,
            Err(error) => {
                let status = synthetic_parse_error_status_code(&error);
                warn!(
                    "event=synthetic failed to parse synthetic security-level request target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}: {:#}; returning {}",
                    target.ptr, target.cookie, tr.code, error, status
                );
                return synthetic_parse_error_reply(status);
            }
        };
        let method = request.method();
        if decision.allowed && !security_level_scoop_enabled(&cfg.intercept) {
            warn!(
                "event=synthetic security-level interception disabled while target ptr=0x{:x} cookie=0x{:x} is still live; returning SYSTEM_ERROR",
                target.ptr, target.cookie
            );
            return Ok(synthetic_parcel_reply(build_service_specific_reply(
                ResponseCode::SYSTEM_ERROR.0,
            )?));
        }
        let allow_omk_grant = should_allow_omk_grant_security_level_request_with_probe(
            &request,
            &decision,
            &caller,
            probe_omk_grant,
        )?;
        if !decision.allowed && !allow_omk_grant {
            debug!(
                "event=synthetic rejected {} security-level {:?} uid={} pid={} sid='{}' target=ptr:0x{:x}/cookie:0x{:x} packages={:?} reason={:?}",
                command_name,
                method,
                caller.uid,
                caller.pid,
                caller.sid,
                target.ptr,
                target.cookie,
                decision.packages,
                decision.reason,
            );
            return Ok(synthetic_parcel_reply(build_service_specific_reply(
                ResponseCode::PERMISSION_DENIED.0,
            )?));
        }
        let target_info = tracker::lookup_security_level_target(target).ok_or_else(|| {
            anyhow::anyhow!(
                "missing synthetic security-level mapping for ptr=0x{:x} cookie=0x{:x}",
                target.ptr,
                target.cookie
            )
        })?;

        debug!(
            "event=synthetic handling {} security-level {:?} uid={} pid={} target=ptr:0x{:x}/cookie=0x{:x} packages={:?} security_level={:?}",
            command_name,
            method,
            caller.uid,
            caller.pid,
            target.ptr,
            target.cookie,
            decision.packages,
            target_info.security_level,
        );

        let pending = PendingSecurityLevelCall {
            request,
            caller,
            packages: decision.packages,
            route: RouteTarget::Omk,
            security_level: target_info.security_level,
        };
        let reply = build_security_level_reply_rewrite(tr, &pending)?;
        return Ok(synthetic_reply_from_outbound(reply));
    }

    let request = match parcel::parse_operation_request(
        data,
        data_size,
        offsets,
        offsets_size,
        tr.code,
    ) {
        Ok(request) => request,
        Err(error) => {
            let status = synthetic_parse_error_status_code(&error);
            warn!(
                "event=synthetic failed to parse synthetic operation request target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}: {:#}; returning {}",
                target.ptr, target.cookie, tr.code, error, status
            );
            return synthetic_parse_error_reply(status);
        }
    };
    let method = request.method();

    debug!(
        "event=synthetic handling {} operation {:?} uid={} pid={} target=ptr:0x{:x}/cookie:0x{:x}",
        command_name, method, caller.uid, caller.pid, target.ptr, target.cookie,
    );

    let pending = PendingOperationCall {
        request,
        caller,
        target,
    };
    let reply = build_operation_reply_rewrite(&pending)?;
    Ok(synthetic_reply_from_outbound(reply))
}

#[cfg(test)]
mod tests;
