use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::mem::size_of;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex, OnceLock,
};

use log::{debug, info, warn};
use rsbinder::{ExceptionCode, Status, StatusCode};
use serde::Deserialize;

use super::binder::{
    binder_transaction_data, describe_transaction_objects, format_target,
    parse_local_binder_target_from_parcel_bytes, LocalBinderTarget,
};
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::IKeystoreService::transactions as service_tx;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::config;
use crate::filter::{self, FilterReason};
use crate::forward::{self, BypassGuard};
use crate::identify::{
    self, AidlMetadataMethod, AuthorizationMethod, MaintenanceMethod, OperationMethod,
    SecurityLevelMethod, ServiceMethod,
};
use crate::ipc;
use crate::parcel::{
    self, ParsedAuthorizationRequest, ParsedMaintenanceRequest, ParsedOperationRequest,
    ParsedSecurityLevelRequest, ParsedServiceRequest,
};
use crate::route::{AospOperationBinder, CallerIdentity, RouteTarget};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::tracker::{self, SecurityLevelTargetInfo};

struct PendingAuthorizationCall {
    request: ParsedAuthorizationRequest,
    method: AuthorizationMethod,
    caller: CallerIdentity,
}

struct PendingMaintenanceCall {
    request: ParsedMaintenanceRequest,
    method: MaintenanceMethod,
    caller: CallerIdentity,
}

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

enum PrecomputedServiceReply {
    GrantSuccess {
        target_key: KeyDescriptor,
        grantee_uid: i32,
        omk_grant: KeyDescriptor,
    },
    UngrantSuccess {
        target_key: KeyDescriptor,
        grantee_uid: i32,
    },
    Error(PrecomputedErrorReply),
}

enum PrecomputedErrorReply {
    Status(Status),
    StatusCode(i32),
}

enum OmkGrantPrecompute {
    Reply(PrecomputedServiceReply),
    PreserveSystem,
}

enum PendingCall {
    Authorization(PendingAuthorizationCall),
    Maintenance(PendingMaintenanceCall),
    Service(PendingServiceCall),
    PrecomputedService(PendingServiceCall, PrecomputedServiceReply),
    SecurityLevel(PendingSecurityLevelCall),
    Operation(PendingOperationCall),
}

thread_local! {
    static PENDING_REPLY_QUEUE: RefCell<VecDeque<Option<PendingCall>>> = RefCell::default();
    static OUTBOUND_REPLY_BUFFERS: RefCell<Vec<parcel::OwnedReply>> = RefCell::default();
    static OUTBOUND_STATUS_BUFFERS: RefCell<Vec<i32>> = RefCell::default();
    static INBOUND_REQUEST_BUFFERS: RefCell<Vec<parcel::OwnedReply>> = RefCell::default();
}

#[derive(Clone)]
struct OperationTargetInfo {
    route: RouteTarget,
    aad_allowed: bool,
    backend: Option<AospOperationBinder>,
    finalized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SyntheticTargetKind {
    SecurityLevel,
    Operation,
}

pub(super) enum SyntheticReply {
    Parcel(Box<parcel::OwnedReply>),
    Status(i32),
    NoReply,
}

enum OutboundReply {
    Parcel(Box<parcel::OwnedReply>),
    Status(i32),
}

impl From<parcel::OwnedReply> for OutboundReply {
    fn from(reply: parcel::OwnedReply) -> Self {
        OutboundReply::Parcel(Box::new(reply))
    }
}

#[derive(Clone, Debug)]
struct SyntheticTargetInfo {
    kind: SyntheticTargetKind,
    caller: Option<CallerIdentity>,
}

static OPERATION_TARGETS: OnceLock<Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>>> =
    OnceLock::new();
static SYNTHETIC_SECURITY_LEVEL_TARGETS: OnceLock<
    Mutex<
        HashMap<
            crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
            LocalBinderTarget,
        >,
    >,
> = OnceLock::new();
static SYNTHETIC_TARGETS: OnceLock<Mutex<HashMap<LocalBinderTarget, SyntheticTargetInfo>>> =
    OnceLock::new();
static KEYSTORE2_AIDL_METADATA: OnceLock<Result<Keystore2AidlMetadata, String>> = OnceLock::new();
static AUTHORIZATION_MIRROR_STATE_DIRTY: AtomicBool = AtomicBool::new(false);
static MAINTENANCE_MIRROR_STATE_DIRTY: AtomicBool = AtomicBool::new(false);
static NEXT_SYNTHETIC_BINDER_ID: AtomicU64 = AtomicU64::new(1);

const SYNTHETIC_BINDER_FLAGS: u32 = 0x1113;
const SYNTHETIC_BINDER_STABILITY: i32 = 0x0c;
const SYNTHETIC_BINDER_PTR_PREFIX_64: u64 = 0x4f4d_4b53_0000_0000;
const SYNTHETIC_BINDER_COOKIE_PREFIX_64: u64 = 0x4f4d_4b43_0000_0000;
const SYNTHETIC_BINDER_PTR_PREFIX_32: u64 = 0x4f4d_0000;
const SYNTHETIC_BINDER_COOKIE_PREFIX_32: u64 = 0x4d4b_0000;
const KEYSTORE2_HAL_NAME: &str = "android.system.keystore2";
const KEYSTORE2_SERVICE_INTERFACE: &str = "IKeystoreService";
const KEYSTORE2_SERVICE_INSTANCE: &str = "default";
const VINTF_MANIFEST_DIRS: &[&str] = &[
    "/system/etc/vintf/manifest",
    "/system_ext/etc/vintf/manifest",
    "/product/etc/vintf/manifest",
    "/vendor/etc/vintf/manifest",
    "/odm/etc/vintf/manifest",
];
const VINTF_MANIFEST_FILES: &[&str] = &[
    "/system/etc/vintf/manifest.xml",
    "/system_ext/etc/vintf/manifest.xml",
    "/product/etc/vintf/manifest.xml",
    "/vendor/etc/vintf/manifest.xml",
    "/odm/etc/vintf/manifest.xml",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Keystore2AidlMetadata {
    version: i32,
    hash: &'static str,
}

#[derive(Debug, Deserialize)]
struct VintfManifestXml {
    #[serde(rename = "hal", default)]
    hals: Vec<VintfHalXml>,
}

#[derive(Debug, Deserialize)]
struct VintfHalXml {
    #[serde(rename = "@format")]
    format: Option<String>,
    name: Option<String>,
    #[serde(rename = "version", default)]
    versions: Vec<String>,
    #[serde(rename = "fqname", default)]
    fqnames: Vec<String>,
    #[serde(rename = "interface", default)]
    interfaces: Vec<VintfInterfaceXml>,
}

#[derive(Debug, Deserialize)]
struct VintfInterfaceXml {
    name: Option<String>,
    #[serde(rename = "instance", default)]
    instances: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorStateKind {
    Authorization,
    Maintenance,
}

impl MirrorStateKind {
    fn dirty(self) -> &'static AtomicBool {
        match self {
            Self::Authorization => &AUTHORIZATION_MIRROR_STATE_DIRTY,
            Self::Maintenance => &MAINTENANCE_MIRROR_STATE_DIRTY,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Maintenance => "maintenance",
        }
    }
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

fn grant_descriptor_from_service_request(request: &ParsedServiceRequest) -> Option<&KeyDescriptor> {
    match request {
        ParsedServiceRequest::GetKeyEntry { key }
        | ParsedServiceRequest::UpdateSubcomponent { key, .. }
        | ParsedServiceRequest::DeleteKey { key }
        | ParsedServiceRequest::Grant { key, .. }
        | ParsedServiceRequest::Ungrant { key, .. }
            if key.domain == Domain::GRANT =>
        {
            Some(key)
        }
        _ => None,
    }
}

fn grant_descriptor_from_security_level_request(
    request: &ParsedSecurityLevelRequest,
) -> Option<&KeyDescriptor> {
    match request {
        ParsedSecurityLevelRequest::CreateOperation { key, .. }
        | ParsedSecurityLevelRequest::DeleteKey { key }
        | ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key: key }
            if key.domain == Domain::GRANT =>
        {
            Some(key)
        }
        _ => None,
    }
}

fn should_allow_omk_grant_descriptor_with_probe(
    grant: &KeyDescriptor,
    decision: &filter::FilterDecision,
    caller: &CallerIdentity,
    mut probe: impl FnMut(&CallerIdentity, &KeyDescriptor) -> bool,
) -> bool {
    if decision.allowed || decision.reason != FilterReason::RejectedUnknownPackage {
        return false;
    }

    if grant.domain != Domain::GRANT {
        return false;
    }

    if tracker::lookup_key_descriptor_route(grant) == Some(RouteTarget::Omk) {
        tracker::remember_key_descriptor_route(grant, RouteTarget::Omk);
        return true;
    }

    if probe(caller, grant) {
        tracker::remember_key_descriptor_route(grant, RouteTarget::Omk);
        return true;
    }

    false
}

fn probe_omk_grant(caller: &CallerIdentity, grant: &KeyDescriptor) -> bool {
    let caller_info = caller.to_caller_info();
    match ipc::with_omk_retry(|omk| Ok(omk.r#isOmkGrant(Some(&caller_info), grant)?)) {
        Ok(true) => true,
        Ok(false) => false,
        Err(error) => {
            debug!(
                "[Injector][Decision] OMK grant probe failed for uid={} pid={} grant_nspace={}: {:#}",
                caller.uid, caller.pid, grant.nspace, error
            );
            false
        }
    }
}

fn should_allow_omk_grant_service_request(
    request: &ParsedServiceRequest,
    decision: &filter::FilterDecision,
    caller: &CallerIdentity,
) -> bool {
    should_allow_omk_grant_service_request_with_probe(request, decision, caller, probe_omk_grant)
}

fn should_allow_omk_grant_service_request_with_probe(
    request: &ParsedServiceRequest,
    decision: &filter::FilterDecision,
    caller: &CallerIdentity,
    mut probe: impl FnMut(&CallerIdentity, &KeyDescriptor) -> bool,
) -> bool {
    let Some(grant) = grant_descriptor_from_service_request(request) else {
        return false;
    };

    should_allow_omk_grant_descriptor_with_probe(grant, decision, caller, &mut probe)
}

fn should_allow_omk_grant_security_level_request(
    request: &ParsedSecurityLevelRequest,
    decision: &filter::FilterDecision,
    caller: &CallerIdentity,
) -> bool {
    should_allow_omk_grant_security_level_request_with_probe(
        request,
        decision,
        caller,
        probe_omk_grant,
    )
}

fn should_allow_omk_grant_security_level_request_with_probe(
    request: &ParsedSecurityLevelRequest,
    decision: &filter::FilterDecision,
    caller: &CallerIdentity,
    mut probe: impl FnMut(&CallerIdentity, &KeyDescriptor) -> bool,
) -> bool {
    let Some(grant) = grant_descriptor_from_security_level_request(request) else {
        return false;
    };

    should_allow_omk_grant_descriptor_with_probe(grant, decision, caller, &mut probe)
}

fn precompute_omk_grant_service_reply(
    request: &ParsedServiceRequest,
    caller: &CallerIdentity,
) -> OmkGrantPrecompute {
    precompute_omk_grant_service_reply_with(
        request,
        caller,
        |caller_info, key, grantee_uid, access_vector| {
            ipc::with_omk_retry(|omk| {
                Ok(omk.r#grant(Some(caller_info), key, grantee_uid, access_vector)?)
            })
        },
        |caller_info, key, grantee_uid| {
            ipc::with_omk_retry(|omk| Ok(omk.r#ungrant(Some(caller_info), key, grantee_uid)?))
        },
    )
}

fn precompute_omk_grant_service_reply_with(
    request: &ParsedServiceRequest,
    caller: &CallerIdentity,
    mut grant: impl FnMut(&CallerInfo, &KeyDescriptor, i32, i32) -> anyhow::Result<KeyDescriptor>,
    mut ungrant: impl FnMut(&CallerInfo, &KeyDescriptor, i32) -> anyhow::Result<()>,
) -> OmkGrantPrecompute {
    let caller_info = caller.to_caller_info();
    match request {
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => match grant(&caller_info, key, *grantee_uid, *access_vector) {
            Ok(omk_grant) => OmkGrantPrecompute::Reply(PrecomputedServiceReply::GrantSuccess {
                target_key: key.clone(),
                grantee_uid: *grantee_uid,
                omk_grant,
            }),
            Err(error) if omk_unavailable_error(&error) => {
                warn!(
                    "[Injector][Route] OMK grant unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                    caller.uid, caller.pid, error
                );
                OmkGrantPrecompute::PreserveSystem
            }
            Err(error) => {
                warn!(
                    "[Injector][Route] OMK grant failed for uid={} pid={}: {:#}; returning OMK error",
                    caller.uid, caller.pid, error
                );
                OmkGrantPrecompute::Reply(PrecomputedServiceReply::Error(
                    precomputed_omk_error_reply(&error),
                ))
            }
        },
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            match ungrant(&caller_info, key, *grantee_uid) {
                Ok(()) => OmkGrantPrecompute::Reply(PrecomputedServiceReply::UngrantSuccess {
                    target_key: key.clone(),
                    grantee_uid: *grantee_uid,
                }),
                Err(error) if omk_unavailable_error(&error) => {
                    warn!(
                        "[Injector][Route] OMK ungrant unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                        caller.uid, caller.pid, error
                    );
                    OmkGrantPrecompute::PreserveSystem
                }
                Err(error) => {
                    warn!(
                        "[Injector][Route] OMK ungrant failed for uid={} pid={}: {:#}; returning OMK error",
                        caller.uid, caller.pid, error
                    );
                    OmkGrantPrecompute::Reply(PrecomputedServiceReply::Error(
                        precomputed_omk_error_reply(&error),
                    ))
                }
            }
        }
        _ => unreachable!("only grant/ungrant requests are precomputed"),
    }
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
        | ParsedServiceRequest::DeleteKey { key }
        | ParsedServiceRequest::Grant { key, .. }
        | ParsedServiceRequest::Ungrant { key, .. } => {
            tracker::resolve_route_for_key_descriptor(key, fallback)
        }
        ParsedServiceRequest::ListEntries { .. }
        | ParsedServiceRequest::GetSecurityLevel { .. }
        | ParsedServiceRequest::GetNumberOfEntries { .. }
        | ParsedServiceRequest::ListEntriesBatched { .. }
        | ParsedServiceRequest::GetSupplementaryAttestationInfo { .. } => fallback,
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

fn mirror_state_dirty(kind: MirrorStateKind) -> bool {
    kind.dirty().load(Ordering::SeqCst)
}

fn is_known_keystore_interface(interface: &str) -> bool {
    matches!(
        interface,
        identify::KEYSTORE_AUTHORIZATION_INTERFACE
            | identify::KEYSTORE_MAINTENANCE_INTERFACE
            | identify::KEYSTORE_SERVICE_INTERFACE
            | identify::KEYSTORE_SECURITY_LEVEL_INTERFACE
            | identify::KEYSTORE_OPERATION_INTERFACE
    )
}

fn mark_mirror_state_dirty(
    kind: MirrorStateKind,
    method: impl std::fmt::Debug,
    caller: &CallerIdentity,
) {
    let was_dirty = kind.dirty().swap(true, Ordering::SeqCst);
    warn!(
        "[Injector][Mirror] marked OMK mirror state dirty after failed {} {:?} mirror for uid={} pid={}{}",
        kind.label(),
        method,
        caller.uid,
        caller.pid,
        if was_dirty { " (already dirty)" } else { "" }
    );
}

fn clear_mirror_state_dirty(
    kind: MirrorStateKind,
    method: impl std::fmt::Debug,
    caller: &CallerIdentity,
) {
    if kind.dirty().swap(false, Ordering::SeqCst) {
        debug!(
            "[Injector][Mirror] cleared OMK {} mirror dirty state after successful {:?} mirror for uid={} pid={}",
            kind.label(),
            method,
            caller.uid,
            caller.pid
        );
    }
}

fn log_dirty_mirror_retry(
    kind: MirrorStateKind,
    method: impl std::fmt::Debug,
    caller: &CallerIdentity,
) {
    if !mirror_state_dirty(kind) {
        return;
    }

    warn!(
        "[Injector][Mirror] OMK {} mirror state is dirty; retrying {:?} mirror for uid={} pid={}",
        kind.label(),
        method,
        caller.uid,
        caller.pid
    );
}

fn authorization_mirror_mutates(method: AuthorizationMethod) -> bool {
    !matches!(
        method,
        AuthorizationMethod::GetAuthTokensForCredStore | AuthorizationMethod::GetLastAuthTime
    )
}

fn maintenance_mirror_mutates(method: MaintenanceMethod) -> bool {
    !matches!(method, MaintenanceMethod::GetAppUidsAffectedBySid)
}

fn operation_targets() -> &'static Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>> {
    OPERATION_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn synthetic_security_level_targets() -> &'static Mutex<
    HashMap<
        crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
        LocalBinderTarget,
    >,
> {
    SYNTHETIC_SECURITY_LEVEL_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn synthetic_targets() -> &'static Mutex<HashMap<LocalBinderTarget, SyntheticTargetInfo>> {
    SYNTHETIC_TARGETS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn lookup_synthetic_target(target: LocalBinderTarget) -> Option<SyntheticTargetKind> {
    lookup_synthetic_target_info(target).map(|info| info.kind)
}

fn lookup_synthetic_target_info(target: LocalBinderTarget) -> Option<SyntheticTargetInfo> {
    synthetic_targets()
        .lock()
        .expect("synthetic target map poisoned")
        .get(&target)
        .cloned()
}

fn is_synthetic_binder_target(target: LocalBinderTarget) -> bool {
    let (ptr_prefix, cookie_prefix, low_mask) = if size_of::<libc::c_ulong>() >= 8 {
        (
            SYNTHETIC_BINDER_PTR_PREFIX_64,
            SYNTHETIC_BINDER_COOKIE_PREFIX_64,
            0x0000_0000_ffff_ffffu64,
        )
    } else {
        (
            SYNTHETIC_BINDER_PTR_PREFIX_32,
            SYNTHETIC_BINDER_COOKIE_PREFIX_32,
            0x0000_ffffu64,
        )
    };
    let ptr = target.ptr;
    let cookie = target.cookie;
    (ptr & !low_mask) == ptr_prefix
        && (cookie & !low_mask) == cookie_prefix
        && (ptr & low_mask) != 0
        && (ptr & low_mask) == (cookie & low_mask)
}

fn remember_synthetic_target(
    target: LocalBinderTarget,
    kind: SyntheticTargetKind,
    caller: Option<&CallerIdentity>,
) {
    synthetic_targets()
        .lock()
        .expect("synthetic target map poisoned")
        .insert(
            target,
            SyntheticTargetInfo {
                kind,
                caller: caller.cloned(),
            },
        );
}

fn remember_operation_target(target: LocalBinderTarget, info: OperationTargetInfo) {
    let previous = operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .insert(target, info);
    if let Some(previous) = previous {
        if let Some(backend) = previous.backend {
            let _guard = BypassGuard::enter();
            if let Err(status) = backend.r#abort() {
                debug!(
                    "[Injector][Route] previous OMK operation for carrier ptr=0x{:x} cookie=0x{:x} could not be aborted while replacing mapping: {}",
                    target.ptr, target.cookie, status
                );
            }
        }
    }
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

fn take_operation_target(target: LocalBinderTarget) -> Option<OperationTargetInfo> {
    operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .remove(&target)
}

fn drop_synthetic_operation_target(target: LocalBinderTarget) {
    let Some(info) = take_operation_target(target) else {
        debug!(
            "[Injector][Synthetic] release for stale operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    };
    if info.finalized {
        debug!(
            "[Injector][Synthetic] release for finalized operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    }
    let Some(backend) = info.backend else {
        return;
    };
    let _guard = BypassGuard::enter();
    if let Err(status) = backend.r#abort() {
        debug!(
            "[Injector][Synthetic] drop abort for operation target ptr=0x{:x} cookie=0x{:x} failed: {}",
            target.ptr, target.cookie, status
        );
    }
}

pub(super) fn handle_synthetic_ref_command(target: LocalBinderTarget, command: u32) -> bool {
    match lookup_synthetic_target(target) {
        Some(SyntheticTargetKind::Operation) => {
            if command == super::binder::BR_RELEASE_NR {
                drop_synthetic_operation_target(target);
            }
            true
        }
        Some(SyntheticTargetKind::SecurityLevel) => true,
        None if is_synthetic_binder_target(target) => {
            warn!(
                "[Injector][Synthetic] consuming stale synthetic binder ref command nr={} for ptr=0x{:x} cookie=0x{:x}",
                command, target.ptr, target.cookie
            );
            true
        }
        None => false,
    }
}

fn mark_operation_target_finalized(target: LocalBinderTarget) {
    if let Some(info) = operation_targets()
        .lock()
        .expect("operation target map poisoned")
        .get_mut(&target)
    {
        info.backend = None;
        info.finalized = true;
    }
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

fn allocate_synthetic_target() -> LocalBinderTarget {
    let id = NEXT_SYNTHETIC_BINDER_ID.fetch_add(1, Ordering::Relaxed);
    let low_mask = if size_of::<libc::c_ulong>() >= 8 {
        0x0000_0000_ffff_ffffu64
    } else {
        0x0000_ffffu64
    };
    let ptr = if size_of::<libc::c_ulong>() >= 8 {
        SYNTHETIC_BINDER_PTR_PREFIX_64 | (id & low_mask)
    } else {
        SYNTHETIC_BINDER_PTR_PREFIX_32 | (id & low_mask)
    } as libc::c_ulong;
    let cookie = if size_of::<libc::c_ulong>() >= 8 {
        SYNTHETIC_BINDER_COOKIE_PREFIX_64 | (id & low_mask)
    } else {
        SYNTHETIC_BINDER_COOKIE_PREFIX_32 | (id & low_mask)
    } as libc::c_ulong;
    LocalBinderTarget { ptr, cookie }
}

fn synthetic_binder_carrier(target: LocalBinderTarget) -> parcel::ReplyBinderCarrier {
    parcel::ReplyBinderCarrier {
        bytes: parcel::build_local_binder_carrier_bytes(
            target.ptr,
            target.cookie,
            SYNTHETIC_BINDER_FLAGS,
            SYNTHETIC_BINDER_STABILITY,
        ),
        is_object: true,
    }
}

fn synthetic_security_level_target(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
) -> LocalBinderTarget {
    let mut targets = synthetic_security_level_targets()
        .lock()
        .expect("synthetic security-level target map poisoned");
    *targets
        .entry(security_level)
        .or_insert_with(allocate_synthetic_target)
}

fn register_synthetic_security_level_carrier(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    source_method: ServiceMethod,
    caller: &CallerIdentity,
) -> parcel::ReplyBinderCarrier {
    let target = synthetic_security_level_target(security_level);
    tracker::remember_security_level_target(
        target,
        SecurityLevelTargetInfo {
            security_level,
            preferred_route: RouteTarget::Omk,
            source_method,
        },
    );
    remember_synthetic_target(target, SyntheticTargetKind::SecurityLevel, None);
    info!(
        "[Injector][Synthetic] registered/reused security-level target ptr=0x{:x} cookie=0x{:x} security_level={:?} source_method={:?} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, security_level, source_method, caller.uid, caller.pid, caller.sid
    );
    synthetic_binder_carrier(target)
}

fn register_synthetic_operation_carrier(
    backend: AospOperationBinder,
    aad_allowed: bool,
    caller: &CallerIdentity,
) -> parcel::ReplyBinderCarrier {
    let target = allocate_synthetic_target();
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed,
            backend: Some(backend),
            finalized: false,
        },
    );
    remember_synthetic_target(target, SyntheticTargetKind::Operation, Some(caller));
    info!(
        "[Injector][Synthetic] registered operation target ptr=0x{:x} cookie=0x{:x} aad_allowed={} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, aad_allowed, caller.uid, caller.pid, caller.sid
    );
    synthetic_binder_carrier(target)
}

unsafe fn transaction_parts(tr: &binder_transaction_data) -> (*mut u8, usize, *mut usize, usize) {
    (
        tr.data.ptr.buffer as *mut u8,
        tr.data_size,
        tr.data.ptr.offsets as *mut usize,
        tr.offsets_size,
    )
}

unsafe fn register_operation_target_from_reply(
    tr: &binder_transaction_data,
    route: RouteTarget,
    backend: Option<AospOperationBinder>,
    aad_allowed: bool,
) -> anyhow::Result<()> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let carrier = match parcel::extract_create_operation_reply_carrier(
        data,
        data_size,
        offsets,
        offsets_size,
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
            finalized: false,
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

    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let caller = CallerIdentity::new(tr.sender_euid.max(0) as u32, tr.sender_pid)
        .with_sid(caller_sid.unwrap_or_default());
    let request_interface = match parcel::peek_request_interface(
        data,
        data_size,
        offsets,
        offsets_size,
    ) {
        Ok(interface) => interface,
        Err(error) => {
            if parcel::contains_known_keystore_interface(parcel_bytes) {
                debug!(
                    "[Injector][Decision] failed to read keystore request interface code=0x{:x}: {:#}",
                    tr.code, error
                );
            }
            return false;
        }
    };

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
                    "[Injector][Decision] failed to parse IKeystoreAuthorization request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        info!(
            "[Injector][Decision] command={} authorization_method={:?} code=0x{:x} uid={} pid={} sid='{}'; mirroring auth state to OMK after system success",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
        );

        if expects_reply {
            replace_top_pending(PendingCall::Authorization(PendingAuthorizationCall {
                request,
                method,
                caller,
            }));
        }
        return false;
    }

    // Maintenance calls carry keystore user lifecycle and super-key state. They
    // are global system state, so mirror them after system success rather than
    // gating them by scoop package routing.
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
                    "[Injector][Decision] failed to parse IKeystoreMaintenance request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        info!(
            "[Injector][Decision] command={} maintenance_method={:?} code=0x{:x} uid={} pid={} sid='{}'; mirroring maintenance state to OMK after system success",
            command_name,
            method,
            tr.code,
            caller.uid,
            caller.pid,
            caller.sid,
        );

        if expects_reply {
            replace_top_pending(PendingCall::Maintenance(PendingMaintenanceCall {
                request,
                method,
                caller,
            }));
        }
        return false;
    }

    let decision = evaluate_caller(&caller, &cfg);

    if request_interface == identify::KEYSTORE_SERVICE_INTERFACE {
        let request = match parcel::parse_service_request(
            data,
            data_size,
            offsets,
            offsets_size,
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
        let original_code = tr.code;
        let allow_omk_grant = should_allow_omk_grant_service_request(&request, &decision, &caller);
        if !decision.allowed && !allow_omk_grant {
            info!(
                "[Injector][Decision] command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=false reason={:?}; leaving original request untouched",
                command_name,
                method,
                original_code,
                caller.uid,
                caller.pid,
                caller.sid,
                decision.packages,
                decision.reason,
            );
            return false;
        }
        if allow_omk_grant {
            info!(
                "[Injector][Decision] command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed=true reason={:?} omk_grant=true",
                command_name,
                method,
                original_code,
                caller.uid,
                caller.pid,
                caller.sid,
                decision.packages,
                decision.reason,
            );
        }

        let route = if allow_omk_grant {
            RouteTarget::Omk
        } else {
            route_for_service_request(&request, &cfg.intercept)
        };
        let mut placeholder_applied = false;
        let mut precomputed_service_reply = None;
        if route == RouteTarget::Omk
            && matches!(method, ServiceMethod::Grant | ServiceMethod::Ungrant)
        {
            match precompute_omk_grant_service_reply(&request, &caller) {
                OmkGrantPrecompute::Reply(reply) => {
                    precomputed_service_reply = Some(reply);
                }
                OmkGrantPrecompute::PreserveSystem => {
                    info!(
                        "[Injector][Route] method={:?} uid={} pid={} route={:?} omk_unavailable=true; preserving original system request",
                        method, caller.uid, caller.pid, route
                    );
                    return false;
                }
            }

            match install_omk_grant_placeholder_request(tr) {
                Ok(()) => {
                    placeholder_applied = true;
                }
                Err(error) => {
                    warn!(
                        "[Injector][Route] failed to install generated OMK grant placeholder for {:?} uid={} pid={}: {:#}; using unknown transaction to fail closed",
                        method, caller.uid, caller.pid, error
                    );
                    tr.code = u32::MAX;
                    placeholder_applied = true;
                }
            }
        }

        info!(
            "[Injector][Decision] command={} service_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={} reason={:?}",
            command_name,
            method,
            original_code,
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
            let pending = PendingServiceCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route,
            };
            if let Some(reply) = precomputed_service_reply {
                replace_top_pending(PendingCall::PrecomputedService(pending, reply));
            } else {
                replace_top_pending(PendingCall::Service(pending));
            }
        }
        return placeholder_applied;
    }

    let Some(target) = target_from_transaction(tr) else {
        if is_known_keystore_interface(&request_interface) {
            debug!(
                "[Injector][Decision] skipping keystore request without local target code=0x{:x} target={}",
                tr.code,
                format_target(tr)
            );
        }
        return false;
    };

    if request_interface == identify::KEYSTORE_SECURITY_LEVEL_INTERFACE {
        let Some(target_info) = tracker::lookup_security_level_target(target) else {
            debug!(
                "[Injector][Decision] skipping IKeystoreSecurityLevel request for unmapped target ptr=0x{:x} cookie=0x{:x}",
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
                    "[Injector][Decision] failed to parse IKeystoreSecurityLevel request code=0x{:x}: {:#}",
                    tr.code, error
                );
                return false;
            }
        };

        let method = request.method();
        let allow_unknown_omk_route =
            should_allow_omk_grant_security_level_request(&request, &decision, &caller);
        let route = if allow_unknown_omk_route {
            RouteTarget::Omk
        } else {
            route_for_security_level_request(&request, target_info.preferred_route)
        };
        if !decision.allowed && !allow_unknown_omk_route {
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

        info!(
            "[Injector][Decision] command={} security_level_method={:?} code=0x{:x} uid={} pid={} sid='{}' packages={:?} allowed={} reason={:?} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?} source_method={:?} omk_derived_route={}",
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
            allow_unknown_omk_route,
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

    if request_interface == identify::KEYSTORE_OPERATION_INTERFACE {
        let Some(operation_target) = lookup_operation_target(target) else {
            debug!(
                "[Injector][Decision] skipping IKeystoreOperation request for unmapped target ptr=0x{:x} cookie=0x{:x}",
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
            method, caller.uid, caller.pid, operation_target.route
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

    if is_known_keystore_interface(&request_interface) {
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
            PendingCall::Authorization(call) => {
                debug!(
                    "[Injector][Reply] handling authorization {:?} uid={} pid={}",
                    call.method, call.caller.uid, call.caller.pid
                );
                build_authorization_reply_mirror(tr, call).map(|reply| {
                    reply.map(|reply| {
                        (
                            "authorization",
                            format!("{:?}", call.method),
                            call.caller.uid,
                            call.caller.pid,
                            reply.into(),
                        )
                    })
                })
            }
            PendingCall::Maintenance(call) => {
                debug!(
                    "[Injector][Reply] handling maintenance {:?} uid={} pid={}",
                    call.method, call.caller.uid, call.caller.pid
                );
                build_maintenance_reply_mirror(tr, call).map(|reply| {
                    reply.map(|reply| {
                        (
                            "maintenance",
                            format!("{:?}", call.method),
                            call.caller.uid,
                            call.caller.pid,
                            reply.into(),
                        )
                    })
                })
            }
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
            PendingCall::PrecomputedService(call, precomputed) => {
                debug!(
                    "[Injector][Reply] handling precomputed service {:?} route={:?} uid={} pid={} packages={:?}",
                    call.method, call.route, call.caller.uid, call.caller.pid, call.packages
                );
                build_precomputed_service_reply(precomputed).map(|reply| {
                    Some((
                        "service",
                        format!("{:?}", call.method),
                        call.caller.uid,
                        call.caller.pid,
                        reply,
                    ))
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
                if pending_preserves_system_on_rewrite_failure(&pending) {
                    warn!(
                        "[Injector][Reply] failed to rewrite pending reply: {:#}; keeping original system reply",
                        error
                    );
                } else {
                    warn!(
                        "[Injector][Reply] failed to rewrite authoritative OMK reply: {:#}; returning SYSTEM_ERROR",
                        error
                    );
                    install_outbound_reply(tr, synthetic_fallback_reply().into());
                }
            }
        }
    }

    pop_pending_frame();
}

fn pending_preserves_system_on_rewrite_failure(pending: &PendingCall) -> bool {
    match pending {
        PendingCall::Authorization(_) | PendingCall::Maintenance(_) => true,
        PendingCall::Service(call) => call.route != RouteTarget::Omk,
        PendingCall::PrecomputedService(_, _) => false,
        PendingCall::SecurityLevel(call) => call.route != RouteTarget::Omk,
        PendingCall::Operation(call) => lookup_operation_target(call.target)
            .is_some_and(|target| target.route == RouteTarget::System),
    }
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
    info!(
        "[Injector][Route] registered security-level carrier ptr=0x{:x} cookie=0x{:x} security_level={:?} preferred_route={:?} source_method={:?}",
        target.ptr, target.cookie, security_level, preferred_route, source_method
    );
    Ok(())
}

fn build_omk_status_reply(status: &Status) -> anyhow::Result<OutboundReply> {
    if status.is_ok() {
        return Ok(synthetic_fallback_reply().into());
    }

    if status.exception_code() == ExceptionCode::TransactionFailed {
        return Ok(OutboundReply::Status(status.transaction_error().into()));
    }

    Ok(parcel::build_status_reply(status)?.into())
}

fn build_omk_error_reply(error: &anyhow::Error) -> anyhow::Result<OutboundReply> {
    if let Some(status) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Status>())
    {
        return build_omk_status_reply(status);
    }

    if let Some(status) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StatusCode>())
    {
        return Ok(OutboundReply::Status((*status).into()));
    }

    Ok(synthetic_fallback_reply().into())
}

fn precomputed_omk_error_reply(error: &anyhow::Error) -> PrecomputedErrorReply {
    if let Some(status) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Status>())
    {
        return PrecomputedErrorReply::Status(status.clone());
    }

    if let Some(status) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StatusCode>())
    {
        return PrecomputedErrorReply::StatusCode((*status).into());
    }

    PrecomputedErrorReply::Status(Status::new_service_specific_error(
        ResponseCode::SYSTEM_ERROR.0,
        None,
    ))
}

fn omk_unavailable_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && omk_unavailable_status_code(status.transaction_error())
}

fn omk_unavailable_status_code(status: StatusCode) -> bool {
    match status {
        StatusCode::NameNotFound | StatusCode::NoInit | StatusCode::DeadObject => true,
        StatusCode::Errno(errno) => {
            let errno = errno.abs();
            matches!(
                errno,
                libc::ENOENT | libc::ECONNREFUSED | libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE
            )
        }
        _ => false,
    }
}

fn omk_unavailable_error(error: &anyhow::Error) -> bool {
    for status in error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<Status>())
    {
        if omk_unavailable_status(status) {
            return true;
        }
    }

    for status in error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<StatusCode>())
    {
        if omk_unavailable_status_code(*status) {
            return true;
        }
    }

    error
        .chain()
        .any(|cause| cause.to_string() == "failed to connect to omk service")
}

fn build_omk_error_reply_or_preserve_system(
    error: &anyhow::Error,
) -> anyhow::Result<Option<OutboundReply>> {
    if omk_unavailable_error(error) {
        Ok(None)
    } else {
        build_omk_error_reply(error).map(Some)
    }
}

fn build_omk_status_reply_or_preserve_system(
    status: &Status,
) -> anyhow::Result<Option<OutboundReply>> {
    if omk_unavailable_status(status) {
        Ok(None)
    } else {
        build_omk_status_reply(status).map(Some)
    }
}

fn omk_error_reply_for_method(
    method: &str,
    caller: &CallerIdentity,
    error: &anyhow::Error,
) -> anyhow::Result<Option<OutboundReply>> {
    match build_omk_error_reply_or_preserve_system(error)? {
        Some(reply) => {
            warn!(
                "[Injector][Reply] OMK {} failed for uid={} pid={}: {:#}; returning OMK error",
                method, caller.uid, caller.pid, error
            );
            Ok(Some(reply))
        }
        None => {
            warn!(
                "[Injector][Reply] OMK {} unavailable for uid={} pid={}: {:#}; preserving original system reply",
                method, caller.uid, caller.pid, error
            );
            Ok(None)
        }
    }
}

fn omk_status_reply_for_method(
    method: &str,
    caller: &CallerIdentity,
    status: &Status,
) -> anyhow::Result<Option<OutboundReply>> {
    match build_omk_status_reply_or_preserve_system(status)? {
        Some(reply) => {
            warn!(
                "[Injector][Reply] OMK {} failed for uid={} pid={}: {:#}; returning OMK error",
                method, caller.uid, caller.pid, status
            );
            Ok(Some(reply))
        }
        None => {
            warn!(
                "[Injector][Reply] OMK {} unavailable for uid={} pid={}: {:#}; preserving original system reply",
                method, caller.uid, caller.pid, status
            );
            Ok(None)
        }
    }
}

fn build_service_specific_reply(code: i32) -> anyhow::Result<parcel::OwnedReply> {
    parcel::build_status_reply(&Status::new_service_specific_error(code, None))
}

fn invalid_operation_handle_reply() -> anyhow::Result<parcel::OwnedReply> {
    build_service_specific_reply(
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0,
    )
}

fn synthetic_fallback_reply() -> parcel::OwnedReply {
    build_service_specific_reply(ResponseCode::SYSTEM_ERROR.0)
        .expect("synthetic system-error status should serialize")
}

fn synthetic_unknown_transaction_reply() -> SyntheticReply {
    SyntheticReply::Status(StatusCode::UnknownTransaction.into())
}

fn synthetic_parcel_reply(reply: parcel::OwnedReply) -> SyntheticReply {
    SyntheticReply::Parcel(Box::new(reply))
}

fn synthetic_reply_from_outbound(reply: Option<OutboundReply>) -> SyntheticReply {
    match reply {
        Some(OutboundReply::Parcel(reply)) => SyntheticReply::Parcel(reply),
        Some(OutboundReply::Status(status)) => SyntheticReply::Status(status),
        None => synthetic_parcel_reply(synthetic_fallback_reply()),
    }
}

fn synthetic_unknown_transaction_reply_for(
    kind: SyntheticTargetKind,
    code: u32,
) -> Option<SyntheticReply> {
    let unknown = match kind {
        SyntheticTargetKind::SecurityLevel => {
            identify::security_level_method_from_code(code).is_none()
        }
        SyntheticTargetKind::Operation => identify::operation_method_from_code(code).is_none(),
    };
    unknown.then(synthetic_unknown_transaction_reply)
}

fn build_precomputed_service_reply(
    precomputed: &PrecomputedServiceReply,
) -> anyhow::Result<OutboundReply> {
    match precomputed {
        PrecomputedServiceReply::GrantSuccess {
            target_key,
            grantee_uid,
            omk_grant,
        } => {
            tracker::remember_key_descriptor_route(omk_grant, RouteTarget::Omk);
            tracker::remember_grant_descriptor_for_ungrant(target_key, *grantee_uid, omk_grant);
            Ok(parcel::build_plain_reply(omk_grant)?.into())
        }
        PrecomputedServiceReply::UngrantSuccess {
            target_key,
            grantee_uid,
        } => {
            tracker::retire_grant_descriptor_after_ungrant(target_key, *grantee_uid);
            Ok(parcel::build_void_reply()?.into())
        }
        PrecomputedServiceReply::Error(PrecomputedErrorReply::Status(status)) => {
            build_omk_status_reply(status)
        }
        PrecomputedServiceReply::Error(PrecomputedErrorReply::StatusCode(status)) => {
            Ok(OutboundReply::Status(*status))
        }
    }
}

fn synthetic_descriptor(kind: SyntheticTargetKind) -> &'static str {
    match kind {
        SyntheticTargetKind::SecurityLevel => identify::KEYSTORE_SECURITY_LEVEL_INTERFACE,
        SyntheticTargetKind::Operation => identify::KEYSTORE_OPERATION_INTERFACE,
    }
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
            "[Injector][Synthetic] failed to resolve {} AIDL version from VINTF; using Android-version fallback v{}",
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
    for path in vintf_manifest_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        match parse_keystore2_aidl_version_xml(&contents) {
            Ok(Some(version)) => return Some(version),
            Ok(None) => {}
            Err(error) => {
                warn!(
                    "[Injector][Synthetic] ignoring invalid VINTF manifest {}: {error:#}",
                    path.display()
                );
            }
        }
    }
    None
}

fn vintf_manifest_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for directory in VINTF_MANIFEST_DIRS {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("xml") {
                paths.push(path);
            }
        }
    }
    for file in VINTF_MANIFEST_FILES {
        paths.push(PathBuf::from(file));
    }
    paths
}

fn parse_keystore2_aidl_version_xml(xml: &str) -> anyhow::Result<Option<i32>> {
    let manifest: VintfManifestXml = quick_xml::de::from_str(xml)
        .map_err(|error| anyhow::anyhow!("failed to deserialize VINTF XML: {error}"))?;
    for hal in manifest.hals {
        if !hal.references_keystore2_service() {
            continue;
        }
        for version in hal.versions {
            let version = version
                .trim()
                .parse::<i32>()
                .map_err(|error| anyhow::anyhow!("invalid keystore2 VINTF version: {error}"))?;
            if let Some(version) = normalize_keystore2_aidl_version(version) {
                return Ok(Some(version));
            }
        }
    }
    Ok(None)
}

fn normalize_keystore2_aidl_version(version: i32) -> Option<i32> {
    if (1..=kmr_common::consts::ANDROID_SYSTEM_KEYSTORE2_LATEST_AIDL_VERSION).contains(&version) {
        Some(version)
    } else {
        None
    }
}

impl VintfHalXml {
    fn references_keystore2_service(&self) -> bool {
        self.format
            .as_deref()
            .is_some_and(|format| format.trim() == "aidl")
            && self.name.as_deref().map(str::trim) == Some(KEYSTORE2_HAL_NAME)
            && self.references_instance(KEYSTORE2_SERVICE_INTERFACE, KEYSTORE2_SERVICE_INSTANCE)
    }

    fn references_instance(&self, interface: &str, instance: &str) -> bool {
        let fqname = format!("{interface}/{instance}");
        self.fqnames
            .iter()
            .any(|candidate| candidate.trim() == fqname)
            || self.interfaces.iter().any(|candidate| {
                candidate.name.as_deref().map(str::trim) == Some(interface)
                    && candidate
                        .instances
                        .iter()
                        .any(|candidate| candidate.trim() == instance)
            })
    }
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
                synthetic_descriptor(kind),
            )?),
            None => synthetic_unknown_transaction_reply(),
        },
        rsbinder::PING_TRANSACTION => synthetic_parcel_reply(parcel::build_empty_reply()),
        rsbinder::EXTENSION_TRANSACTION => {
            synthetic_parcel_reply(parcel::build_null_binder_reply()?)
        }
        rsbinder::DEBUG_PID_TRANSACTION => {
            synthetic_parcel_reply(parcel::build_raw_i32_reply(std::process::id() as i32)?)
        }
        rsbinder::SHELL_COMMAND_TRANSACTION | rsbinder::SYSPROPS_TRANSACTION => {
            synthetic_parcel_reply(parcel::build_empty_reply())
        }
        rsbinder::DUMP_TRANSACTION => {
            let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
            if let Err(error) =
                parcel::validate_dump_request(data, data_size, offsets, offsets_size)
            {
                warn!(
                    "[Injector][Synthetic] malformed DUMP_TRANSACTION for target ptr=0x{:x} cookie=0x{:x} kind={:?}: {:#}; returning BAD_TYPE",
                    target.ptr, target.cookie, kind, error
                );
                SyntheticReply::Status(StatusCode::BadType.into())
            } else {
                synthetic_parcel_reply(parcel::build_empty_reply())
            }
        }
        rsbinder::SET_RPC_CLIENT_TRANSACTION => {
            SyntheticReply::Status(StatusCode::InvalidOperation.into())
        }
        rsbinder::START_RECORDING_TRANSACTION | rsbinder::STOP_RECORDING_TRANSACTION => {
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
    fallback: &CallerIdentity,
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
) -> CallerIdentity {
    let uid = if tr.sender_euid >= 0 {
        tr.sender_euid as u32
    } else {
        fallback.uid
    };
    let pid = if tr.sender_pid != 0 {
        tr.sender_pid
    } else {
        fallback.pid
    };
    let sid = caller_sid
        .filter(|sid| !sid.is_empty())
        .unwrap_or_else(|| fallback.sid.clone());
    CallerIdentity::new(uid, pid).with_sid(sid)
}

fn synthetic_transaction_current_caller(
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
) -> CallerIdentity {
    let uid = if tr.sender_euid >= 0 {
        tr.sender_euid as u32
    } else {
        0
    };
    let pid = tr.sender_pid;
    let sid = caller_sid.filter(|sid| !sid.is_empty()).unwrap_or_default();
    CallerIdentity::new(uid, pid).with_sid(sid)
}

pub(super) unsafe fn handle_synthetic_br_transaction(
    tr: &binder_transaction_data,
    caller_sid: Option<String>,
    command_name: &str,
) -> Option<SyntheticReply> {
    let target = target_from_transaction(tr)?;
    let Some(info) = lookup_synthetic_target_info(target) else {
        if !is_synthetic_binder_target(target) {
            return None;
        }
        let reply = match synthetic_base_transaction_reply(None, target, tr) {
            Ok(Some(reply)) => reply,
            Ok(None) => synthetic_unknown_transaction_reply(),
            Err(error) => {
                warn!(
                    "[Injector][Synthetic] failed to handle stale {} target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}: {:#}; returning SYSTEM_ERROR",
                    command_name, target.ptr, target.cookie, tr.code, error
                );
                synthetic_parcel_reply(synthetic_fallback_reply())
            }
        };
        let reply = if (tr.flags & super::binder::TF_ONE_WAY) != 0 {
            SyntheticReply::NoReply
        } else {
            reply
        };
        warn!(
            "[Injector][Synthetic] consumed stale synthetic {} target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}",
            command_name, target.ptr, target.cookie, tr.code
        );
        return Some(reply);
    };
    let kind = info.kind;

    let result = build_synthetic_br_transaction_reply(tr, target, info, caller_sid, command_name);
    let reply = match result {
        Ok(reply) => reply,
        Err(error) => {
            warn!(
                "[Injector][Synthetic] failed to handle {} target=ptr:0x{:x}/cookie:0x{:x} kind={:?} code=0x{:x}: {:#}; returning SYSTEM_ERROR",
                command_name,
                target.ptr,
                target.cookie,
                kind,
                tr.code,
                error
            );
            if (tr.flags & super::binder::TF_ONE_WAY) != 0 {
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
    let expects_reply = (tr.flags & super::binder::TF_ONE_WAY) == 0;
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
        let request_interface = match parcel::parse_no_arg_request_interface(
            data,
            data_size,
            offsets,
            offsets_size,
        ) {
            Ok(interface) => interface,
            Err(error) => {
                warn!(
                        "[Injector][Synthetic] failed to read AIDL metadata interface token for target ptr=0x{:x} cookie=0x{:x} kind={:?} code=0x{:x}: {:#}; returning BAD_TYPE",
                        target.ptr, target.cookie, kind, tr.code, error
                    );
                return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
            }
        };
        let expected_interface = synthetic_descriptor(kind);
        if request_interface != expected_interface {
            warn!(
                "[Injector][Synthetic] synthetic {:?} target ptr=0x{:x} cookie=0x{:x} received metadata request for unexpected interface {}; returning BAD_TYPE",
                kind, target.ptr, target.cookie, request_interface
            );
            return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
        }
        return build_synthetic_aidl_metadata_reply(method);
    }

    let cfg = config::get();
    if !cfg.main.enabled {
        warn!(
            "[Injector][Synthetic] injector disabled while synthetic target ptr=0x{:x} cookie=0x{:x} is still live; returning SYSTEM_ERROR",
            target.ptr, target.cookie
        );
        return Ok(synthetic_parcel_reply(build_service_specific_reply(
            ResponseCode::SYSTEM_ERROR.0,
        )?));
    }

    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let request_interface = match parcel::peek_request_interface(
        data,
        data_size,
        offsets,
        offsets_size,
    ) {
        Ok(interface) => interface,
        Err(error) => {
            warn!(
                "[Injector][Synthetic] failed to read interface token for target ptr=0x{:x} cookie=0x{:x} kind={:?} code=0x{:x}: {:#}; returning BAD_TYPE",
                target.ptr, target.cookie, kind, tr.code, error
            );
            return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
        }
    };
    let caller = match kind {
        SyntheticTargetKind::SecurityLevel => synthetic_transaction_current_caller(tr, caller_sid),
        SyntheticTargetKind::Operation => {
            let fallback = info
                .caller
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing synthetic operation caller fallback"))?;
            synthetic_transaction_caller(fallback, tr, caller_sid)
        }
    };
    let decision = evaluate_caller(&caller, &cfg);

    match kind {
        SyntheticTargetKind::SecurityLevel => {
            if request_interface != identify::KEYSTORE_SECURITY_LEVEL_INTERFACE {
                warn!(
                    "[Injector][Synthetic] synthetic security-level target ptr=0x{:x} cookie=0x{:x} received unexpected interface {}; returning BAD_TYPE",
                    target.ptr, target.cookie, request_interface
                );
                return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
            }
            if let Some(reply) = synthetic_unknown_transaction_reply_for(kind, tr.code) {
                return Ok(reply);
            }
            let target_info = tracker::lookup_security_level_target(target)
                .ok_or_else(|| anyhow::anyhow!("missing synthetic security-level target info"))?;
            let request = match parcel::parse_security_level_request(
                data,
                data_size,
                offsets,
                offsets_size,
                tr.code,
            ) {
                Ok(request) => request,
                Err(error) => {
                    warn!(
                        "[Injector][Synthetic] failed to parse synthetic security-level request target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}: {:#}; returning BAD_VALUE",
                        target.ptr, target.cookie, tr.code, error
                    );
                    return Ok(SyntheticReply::Status(StatusCode::BadValue.into()));
                }
            };
            let method = request.method();
            let allow_unknown_omk_route =
                should_allow_omk_grant_security_level_request(&request, &decision, &caller);
            if !decision.allowed && !allow_unknown_omk_route {
                warn!(
                    "[Injector][Synthetic] denied security-level {:?} for uid={} pid={} packages={:?} reason={:?}; returning PERMISSION_DENIED",
                    method, caller.uid, caller.pid, decision.packages, decision.reason
                );
                return Ok(synthetic_parcel_reply(build_service_specific_reply(
                    ResponseCode::PERMISSION_DENIED.0,
                )?));
            }

            info!(
                "[Injector][Synthetic] handling {} security-level {:?} uid={} pid={} target=ptr:0x{:x}/cookie:0x{:x} security_level={:?} packages={:?}",
                command_name,
                method,
                caller.uid,
                caller.pid,
                target.ptr,
                target.cookie,
                target_info.security_level,
                decision.packages,
            );

            let pending = PendingSecurityLevelCall {
                request,
                method,
                caller,
                packages: decision.packages,
                route: RouteTarget::Omk,
                security_level: target_info.security_level,
            };
            let reply = build_security_level_reply_rewrite(tr, &pending)?;
            Ok(synthetic_reply_from_outbound(reply))
        }
        SyntheticTargetKind::Operation => {
            if request_interface != identify::KEYSTORE_OPERATION_INTERFACE {
                warn!(
                    "[Injector][Synthetic] synthetic operation target ptr=0x{:x} cookie=0x{:x} received unexpected interface {}; returning BAD_TYPE",
                    target.ptr, target.cookie, request_interface
                );
                return Ok(SyntheticReply::Status(StatusCode::BadType.into()));
            }
            if let Some(reply) = synthetic_unknown_transaction_reply_for(kind, tr.code) {
                return Ok(reply);
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
                    warn!(
                        "[Injector][Synthetic] failed to parse synthetic operation request target=ptr:0x{:x}/cookie:0x{:x} code=0x{:x}: {:#}; returning BAD_VALUE",
                        target.ptr, target.cookie, tr.code, error
                    );
                    return Ok(SyntheticReply::Status(StatusCode::BadValue.into()));
                }
            };
            let method = request.method();
            if !decision.allowed {
                warn!(
                    "[Injector][Synthetic] denied operation {:?} for uid={} pid={} packages={:?} reason={:?}; returning PERMISSION_DENIED",
                    method, caller.uid, caller.pid, decision.packages, decision.reason
                );
                return Ok(synthetic_parcel_reply(build_service_specific_reply(
                    ResponseCode::PERMISSION_DENIED.0,
                )?));
            }

            info!(
                "[Injector][Synthetic] handling {} operation {:?} uid={} pid={} target=ptr:0x{:x}/cookie:0x{:x} packages={:?}",
                command_name,
                method,
                caller.uid,
                caller.pid,
                target.ptr,
                target.cookie,
                decision.packages,
            );

            let pending = PendingOperationCall {
                request,
                method,
                caller,
                packages: decision.packages,
                target,
            };
            let reply = build_operation_reply_rewrite(&pending)?;
            Ok(synthetic_reply_from_outbound(reply))
        }
    }
}

fn build_no_carrier_omk_key_entry_reply(
    entry: KeyEntryResponse,
    caller: &CallerIdentity,
) -> anyhow::Result<parcel::OwnedReply> {
    tracker::remember_key_metadata_route(&entry.r#metadata, RouteTarget::Omk);
    let KeyEntryResponse {
        r#iSecurityLevel,
        r#metadata,
    } = entry;
    if r#iSecurityLevel.is_some() {
        let carrier = register_synthetic_security_level_carrier(
            r#metadata.keySecurityLevel,
            ServiceMethod::GetKeyEntry,
            caller,
        );
        return parcel::build_key_entry_reply_with_carrier_bytes(
            r#metadata,
            &carrier.bytes,
            carrier.is_object,
        );
    }

    parcel::build_key_entry_reply(KeyEntryResponse {
        r#iSecurityLevel: None,
        r#metadata,
    })
}

fn build_direct_omk_metadata_reply(metadata: KeyMetadata) -> anyhow::Result<parcel::OwnedReply> {
    tracker::remember_key_metadata_route(&metadata, RouteTarget::Omk);
    parcel::build_plain_reply(&metadata)
}

fn build_no_carrier_create_operation_reply(
    response: crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse,
    aad_allowed: bool,
    caller: &CallerIdentity,
) -> anyhow::Result<parcel::OwnedReply> {
    let crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse {
        r#iOperation,
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
    } = response;

    let Some(operation) = r#iOperation else {
        return parcel::build_create_operation_reply(
            crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse {
                r#iOperation: None,
                r#operationChallenge,
                r#parameters,
                r#upgradedBlob,
            },
        );
    };

    let carrier = register_synthetic_operation_carrier(operation, aad_allowed, caller);
    parcel::build_create_operation_reply_with_carrier_bytes(
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
        &carrier.bytes,
        carrier.is_object,
    )
}

fn build_direct_omk_security_level_reply(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    match ipc::with_omk_retry(|omk| Ok(omk.r#getSecurityLevel(security_level)?)) {
        Ok(_level) => {
            let carrier = register_synthetic_security_level_carrier(
                security_level,
                ServiceMethod::GetSecurityLevel,
                &pending.caller,
            );
            Ok(Some(
                parcel::build_get_security_level_reply_with_carrier_bytes(
                    &carrier.bytes,
                    carrier.is_object,
                )?
                .into(),
            ))
        }
        Err(error) => omk_error_reply_for_method("getSecurityLevel", &pending.caller, &error),
    }
}

unsafe fn observe_system_service_reply(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<()> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } => {
            let carrier = parcel::extract_direct_binder_reply_carrier(
                data,
                data_size,
                offsets,
                offsets_size,
            )?;
            register_security_level_carrier(
                &carrier,
                *security_level,
                RouteTarget::System,
                ServiceMethod::GetSecurityLevel,
            )?;
        }
        ParsedServiceRequest::GetKeyEntry { .. } => {
            let metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                match parcel::parse_key_entry_reply_metadata(data, data_size, offsets, offsets_size)
                {
                    Ok(response) => response,
                    Err(_) => return Ok(()),
                };
            let carrier =
                parcel::extract_key_entry_reply_carrier(data, data_size, offsets, offsets_size)?;
            register_security_level_carrier(
                &carrier,
                metadata.r#keySecurityLevel,
                RouteTarget::System,
                ServiceMethod::GetKeyEntry,
            )?;
            tracker::remember_key_metadata_route(&metadata, RouteTarget::System);
        }
        ParsedServiceRequest::DeleteKey { key } => {
            let status = match parcel::parse_reply_status(data, data_size, offsets, offsets_size) {
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

unsafe fn build_authorization_reply_mirror(
    tr: &binder_transaction_data,
    call: &PendingAuthorizationCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let status = parcel::parse_reply_status(data, data_size, offsets, offsets_size)?;
    if !status.is_ok() {
        debug!(
            "[Injector][Authorization] system {:?} failed with {}; skipping OMK mirror",
            call.method, status
        );
        return Ok(None);
    }
    log_dirty_mirror_retry(MirrorStateKind::Authorization, call.method, &call.caller);

    let caller = call.caller.to_caller_info();
    let mutates = authorization_mirror_mutates(call.method);
    let result = match &call.request {
        ParsedAuthorizationRequest::AddAuthToken { auth_token } => {
            ipc::with_omk_authorization_retry(|auth| {
                Ok(auth.r#addAuthToken(Some(&caller), auth_token)?)
            })
        }
        ParsedAuthorizationRequest::OnDeviceUnlocked { user_id, password } => {
            ipc::with_omk_authorization_retry(|auth| {
                Ok(auth.r#onDeviceUnlocked(Some(&caller), *user_id, password.as_deref())?)
            })
        }
        ParsedAuthorizationRequest::OnDeviceLocked {
            user_id,
            unlocking_sids,
            weak_unlock_enabled,
        } => ipc::with_omk_authorization_retry(|auth| {
            Ok(auth.r#onDeviceLocked(
                Some(&caller),
                *user_id,
                unlocking_sids,
                *weak_unlock_enabled,
            )?)
        }),
        ParsedAuthorizationRequest::OnUserStorageLocked { user_id } => {
            ipc::with_omk_authorization_retry(|auth| {
                Ok(auth.r#onUserStorageLocked(Some(&caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnWeakUnlockMethodsExpired { user_id } => {
            ipc::with_omk_authorization_retry(|auth| {
                Ok(auth.r#onWeakUnlockMethodsExpired(Some(&caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::OnNonLskfUnlockMethodsExpired { user_id } => {
            ipc::with_omk_authorization_retry(|auth| {
                Ok(auth.r#onNonLskfUnlockMethodsExpired(Some(&caller), *user_id)?)
            })
        }
        ParsedAuthorizationRequest::GetAuthTokensForCredStore { .. }
        | ParsedAuthorizationRequest::GetLastAuthTime { .. } => {
            debug!(
                "[Injector][Authorization] {:?} is read-only; preserving system reply",
                call.method
            );
            Ok(())
        }
    };

    match result {
        Ok(()) => {
            if mutates {
                clear_mirror_state_dirty(MirrorStateKind::Authorization, call.method, &call.caller);
                debug!(
                    "[Injector][Authorization] mirrored {:?} to OMK for uid={} pid={}",
                    call.method, call.caller.uid, call.caller.pid
                );
            }
        }
        Err(error) => {
            warn!(
                "[Injector][Authorization] failed to mirror {:?} to OMK for uid={} pid={}: {:#}",
                call.method, call.caller.uid, call.caller.pid, error
            );
            mark_mirror_state_dirty(MirrorStateKind::Authorization, call.method, &call.caller);
        }
    }

    Ok(None)
}

unsafe fn build_maintenance_reply_mirror(
    tr: &binder_transaction_data,
    call: &PendingMaintenanceCall,
) -> anyhow::Result<Option<parcel::OwnedReply>> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    let status = parcel::parse_reply_status(data, data_size, offsets, offsets_size)?;
    if !status.is_ok() {
        debug!(
            "[Injector][Maintenance] system {:?} failed with {}; skipping OMK mirror",
            call.method, status
        );
        return Ok(None);
    }
    log_dirty_mirror_retry(MirrorStateKind::Maintenance, call.method, &call.caller);

    let caller = call.caller.to_caller_info();
    let mutates = maintenance_mirror_mutates(call.method);
    let result = match &call.request {
        ParsedMaintenanceRequest::OnUserAdded { user_id } => {
            ipc::with_omk_maintenance_retry(|maintenance| {
                Ok(maintenance.r#onUserAdded(Some(&caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::InitUserSuperKeys {
            user_id,
            password,
            allow_existing,
        } => ipc::with_omk_maintenance_retry(|maintenance| {
            Ok(maintenance.r#initUserSuperKeys(
                Some(&caller),
                *user_id,
                password,
                *allow_existing,
            )?)
        }),
        ParsedMaintenanceRequest::OnUserRemoved { user_id } => {
            ipc::with_omk_maintenance_retry(|maintenance| {
                Ok(maintenance.r#onUserRemoved(Some(&caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::OnUserLskfRemoved { user_id } => {
            ipc::with_omk_maintenance_retry(|maintenance| {
                Ok(maintenance.r#onUserLskfRemoved(Some(&caller), *user_id)?)
            })
        }
        ParsedMaintenanceRequest::ClearNamespace { domain, nspace } => {
            ipc::with_omk_maintenance_retry(|maintenance| {
                Ok(maintenance.r#clearNamespace(Some(&caller), *domain, *nspace)?)
            })
        }
        ParsedMaintenanceRequest::EarlyBootEnded => {
            ipc::with_omk_maintenance_retry(|maintenance| {
                Ok(maintenance.r#earlyBootEnded(Some(&caller))?)
            })
        }
        ParsedMaintenanceRequest::MigrateKeyNamespace {
            source,
            destination,
        } => ipc::with_omk_maintenance_retry(|maintenance| {
            Ok(maintenance.r#migrateKeyNamespace(Some(&caller), source, destination)?)
        }),
        ParsedMaintenanceRequest::DeleteAllKeys => ipc::with_omk_maintenance_retry(|maintenance| {
            Ok(maintenance.r#deleteAllKeys(Some(&caller))?)
        }),
        ParsedMaintenanceRequest::GetAppUidsAffectedBySid { .. } => {
            debug!(
                "[Injector][Maintenance] {:?} is read-only; preserving system reply",
                call.method
            );
            Ok(())
        }
    };

    match result {
        Ok(()) => {
            if mutates {
                clear_mirror_state_dirty(MirrorStateKind::Maintenance, call.method, &call.caller);
                debug!(
                    "[Injector][Maintenance] mirrored {:?} to OMK for uid={} pid={}",
                    call.method, call.caller.uid, call.caller.pid
                );
            }
        }
        Err(error) => {
            warn!(
                "[Injector][Maintenance] failed to mirror {:?} to OMK for uid={} pid={}: {:#}",
                call.method, call.caller.uid, call.caller.pid, error
            );
            mark_mirror_state_dirty(MirrorStateKind::Maintenance, call.method, &call.caller);
        }
    }

    Ok(None)
}

unsafe fn build_service_reply_rewrite(
    tr: &binder_transaction_data,
    pending: &PendingServiceCall,
) -> anyhow::Result<Option<OutboundReply>> {
    if pending.route != RouteTarget::Omk {
        observe_system_service_reply(tr, pending)?;
        return Ok(None);
    }

    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();

    match &pending.request {
        ParsedServiceRequest::GetSecurityLevel { security_level } => {
            build_direct_omk_security_level_reply(*security_level, pending)
        }
        ParsedServiceRequest::GetKeyEntry { key } => {
            let entry = match ipc::with_omk_retry(|omk| Ok(omk.r#getKeyEntry(Some(&caller), key)?))
            {
                Ok(entry) => entry,
                Err(error) => {
                    return omk_error_reply_for_method("getKeyEntry", &pending.caller, &error);
                }
            };
            Ok(Some(
                build_no_carrier_omk_key_entry_reply(entry, &pending.caller)?.into(),
            ))
        }
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => {
            match ipc::with_omk_retry(|omk| {
                Ok(omk.r#updateSubcomponent(
                    Some(&caller),
                    key,
                    public_cert.as_deref(),
                    certificate_chain.as_deref(),
                )?)
            }) {
                Ok(()) => Ok(Some(parcel::build_void_reply()?.into())),
                Err(error) => {
                    omk_error_reply_for_method("updateSubcomponent", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::ListEntries { domain, nspace } => {
            match ipc::with_omk_retry(|omk| {
                Ok(omk.r#listEntries(Some(&caller), *domain, *nspace)?)
            }) {
                Ok(entries) => Ok(Some(parcel::build_plain_reply(&entries)?.into())),
                Err(error) => omk_error_reply_for_method("listEntries", &pending.caller, &error),
            }
        }
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => {
            let omk_grant = match ipc::with_omk_retry(|omk| {
                Ok(omk.r#grant(Some(&caller), key, *grantee_uid, *access_vector)?)
            }) {
                Ok(omk_grant) => omk_grant,
                Err(error) => return omk_error_reply_for_method("grant", &pending.caller, &error),
            };
            tracker::remember_key_descriptor_route(&omk_grant, RouteTarget::Omk);
            tracker::remember_grant_descriptor_for_ungrant(key, *grantee_uid, &omk_grant);
            Ok(Some(parcel::build_plain_reply(&omk_grant)?.into()))
        }
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            match ipc::with_omk_retry(|omk| Ok(omk.r#ungrant(Some(&caller), key, *grantee_uid)?)) {
                Ok(()) => {
                    tracker::retire_grant_descriptor_after_ungrant(key, *grantee_uid);
                    Ok(Some(parcel::build_void_reply()?.into()))
                }
                Err(error) => omk_error_reply_for_method("ungrant", &pending.caller, &error),
            }
        }
        ParsedServiceRequest::GetNumberOfEntries { domain, nspace } => {
            match ipc::with_omk_retry(|omk| {
                Ok(omk.r#getNumberOfEntries(Some(&caller), *domain, *nspace)?)
            }) {
                Ok(count) => Ok(Some(parcel::build_plain_reply(&count)?.into())),
                Err(error) => {
                    omk_error_reply_for_method("getNumberOfEntries", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::ListEntriesBatched {
            domain,
            nspace,
            starting_past_alias,
        } => {
            match ipc::with_omk_retry(|omk| {
                Ok(omk.r#listEntriesBatched(
                    Some(&caller),
                    *domain,
                    *nspace,
                    starting_past_alias.as_deref(),
                )?)
            }) {
                Ok(entries) => Ok(Some(parcel::build_plain_reply(&entries)?.into())),
                Err(error) => {
                    omk_error_reply_for_method("listEntriesBatched", &pending.caller, &error)
                }
            }
        }
        ParsedServiceRequest::GetSupplementaryAttestationInfo { tag } => {
            match ipc::with_omk_retry(|omk| Ok(omk.r#getSupplementaryAttestationInfo(*tag)?)) {
                Ok(info) => Ok(Some(parcel::build_plain_reply(&info)?.into())),
                Err(error) => omk_error_reply_for_method(
                    "getSupplementaryAttestationInfo",
                    &pending.caller,
                    &error,
                ),
            }
        }
        ParsedServiceRequest::DeleteKey { key } => {
            match ipc::with_omk_retry(|omk| Ok(omk.r#deleteKey(Some(&caller), key)?)) {
                Ok(()) => {
                    tracker::forget_key_descriptor_route(key);
                    Ok(Some(parcel::build_void_reply()?.into()))
                }
                Err(error) => omk_error_reply_for_method("deleteKey", &pending.caller, &error),
            }
        }
    }
}

unsafe fn observe_system_security_level_reply(
    tr: &binder_transaction_data,
    pending: &PendingSecurityLevelCall,
) -> anyhow::Result<()> {
    let (data, data_size, offsets, offsets_size) = transaction_parts(tr);
    match &pending.request {
        ParsedSecurityLevelRequest::GenerateKey { .. }
        | ParsedSecurityLevelRequest::ImportKey { .. }
        | ParsedSecurityLevelRequest::ImportWrappedKey { .. } => {
            let metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata =
                match parcel::parse_success_reply(data, data_size, offsets, offsets_size) {
                    Ok(metadata) => metadata,
                    Err(_) => return Ok(()),
                };
            tracker::remember_key_metadata_route(&metadata, RouteTarget::System);
        }
        ParsedSecurityLevelRequest::DeleteKey { key } => {
            let status = match parcel::parse_reply_status(data, data_size, offsets, offsets_size) {
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
) -> anyhow::Result<Option<OutboundReply>> {
    if pending.route != RouteTarget::Omk {
        observe_system_security_level_reply(tr, pending)?;
        return Ok(None);
    }

    let caller = pending.caller.to_caller_info();
    let _guard = BypassGuard::enter();
    let omk_level =
        match ipc::with_omk_retry(|omk| Ok(omk.r#getOhMySecurityLevel(pending.security_level)?)) {
            Ok(level) => level,
            Err(error) => {
                let method = format!("security-level lookup {:?}", pending.security_level);
                return omk_error_reply_for_method(&method, &pending.caller, &error);
            }
        };

    match &pending.request {
        ParsedSecurityLevelRequest::CreateOperation {
            key,
            operation_parameters,
            forced,
        } => {
            let omk_response = match omk_level.r#createOperation(
                Some(&caller),
                key,
                operation_parameters,
                *forced,
            ) {
                Ok(response) => response,
                Err(error) => {
                    return omk_status_reply_for_method("createOperation", &pending.caller, &error);
                }
            };
            Ok(Some(
                build_no_carrier_create_operation_reply(
                    omk_response,
                    operation_allows_aad(operation_parameters),
                    &pending.caller,
                )?
                .into(),
            ))
        }
        ParsedSecurityLevelRequest::GenerateKey {
            key,
            attestation_key,
            params,
            flags,
            entropy,
        } => {
            match omk_level.r#generateKey(
                Some(&caller),
                key,
                attestation_key.as_ref(),
                params,
                *flags,
                entropy,
            ) {
                Ok(metadata) => {
                    tracker::remember_key_descriptor_route(key, RouteTarget::Omk);
                    tracker::remember_key_metadata_route(&metadata, RouteTarget::Omk);
                    Ok(Some(parcel::build_plain_reply(&metadata)?.into()))
                }
                Err(error) => omk_status_reply_for_method("generateKey", &pending.caller, &error),
            }
        }
        ParsedSecurityLevelRequest::ImportKey {
            key,
            attestation_key,
            params,
            flags,
            key_data,
        } => {
            match omk_level.r#importKey(
                Some(&caller),
                key,
                attestation_key.as_ref(),
                params,
                *flags,
                key_data,
            ) {
                Ok(metadata) => {
                    tracker::remember_key_descriptor_route(key, RouteTarget::Omk);
                    Ok(Some(build_direct_omk_metadata_reply(metadata)?.into()))
                }
                Err(error) => omk_status_reply_for_method("importKey", &pending.caller, &error),
            }
        }
        ParsedSecurityLevelRequest::ImportWrappedKey {
            key,
            wrapping_key,
            masking_key,
            params,
            authenticators,
        } => {
            match omk_level.r#importWrappedKey(
                Some(&caller),
                key,
                wrapping_key,
                masking_key.as_deref(),
                params,
                authenticators,
            ) {
                Ok(metadata) => {
                    tracker::remember_key_descriptor_route(key, RouteTarget::Omk);
                    Ok(Some(build_direct_omk_metadata_reply(metadata)?.into()))
                }
                Err(error) => {
                    omk_status_reply_for_method("importWrappedKey", &pending.caller, &error)
                }
            }
        }
        ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key } => match omk_level
            .r#convertStorageKeyToEphemeral(Some(&caller), storage_key)
        {
            Ok(response) => Ok(Some(parcel::build_plain_reply(&response)?.into())),
            Err(error) => {
                omk_status_reply_for_method("convertStorageKeyToEphemeral", &pending.caller, &error)
            }
        },
        ParsedSecurityLevelRequest::DeleteKey { key } => {
            match omk_level.r#deleteKey(Some(&caller), key) {
                Ok(()) => {
                    tracker::forget_key_descriptor_route(key);
                    Ok(Some(parcel::build_void_reply()?.into()))
                }
                Err(error) => omk_status_reply_for_method("deleteKey", &pending.caller, &error),
            }
        }
    }
}

fn build_operation_reply_rewrite(
    pending: &PendingOperationCall,
) -> anyhow::Result<Option<OutboundReply>> {
    let Some(target) = lookup_operation_target(pending.target) else {
        if lookup_synthetic_target(pending.target) == Some(SyntheticTargetKind::Operation) {
            debug!(
                "[Injector][Reply] synthetic operation carrier ptr=0x{:x} cookie=0x{:x} has no live backend; returning INVALID_OPERATION_HANDLE",
                pending.target.ptr, pending.target.cookie
            );
            return Ok(Some(invalid_operation_handle_reply()?.into()));
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

    let Some(backend) = target.backend else {
        if target.finalized {
            if matches!(pending.request, ParsedOperationRequest::Abort) {
                debug!(
                    "[Injector][Reply] cleanup abort for finalized OMK operation carrier ptr=0x{:x} cookie=0x{:x}; returning INVALID_OPERATION_HANDLE",
                    pending.target.ptr, pending.target.cookie
                );
                forget_operation_target(pending.target);
                return Ok(Some(invalid_operation_handle_reply()?.into()));
            }
            return Ok(Some(invalid_operation_handle_reply()?.into()));
        }
        anyhow::bail!("missing OMK operation backend mapping");
    };
    let _guard = BypassGuard::enter();

    let reply = match &pending.request {
        ParsedOperationRequest::UpdateAad { aad_input } => {
            if !target.aad_allowed {
                debug!(
                    "[Injector][Reply] OMK-owned updateAad rejected on a non-AAD-capable operation; returning OMK status reply"
                );
            }
            match backend.r#updateAad(aad_input) {
                Ok(()) => parcel::build_void_reply()?.into(),
                Err(status) => build_omk_status_reply(&status)?,
            }
        }
        ParsedOperationRequest::Update { input } => match backend.r#update(input) {
            Ok(output) => parcel::build_plain_reply(&output)?.into(),
            Err(status) => build_omk_status_reply(&status)?,
        },
        ParsedOperationRequest::Finish { input, signature } => {
            match backend.r#finish(input.as_deref(), signature.as_deref()) {
                Ok(output) => {
                    mark_operation_target_finalized(pending.target);
                    parcel::build_plain_reply(&output)?.into()
                }
                Err(status) => build_omk_status_reply(&status)?,
            }
        }
        ParsedOperationRequest::Abort => match backend.r#abort() {
            Ok(()) => {
                forget_operation_target(pending.target);
                parcel::build_void_reply()?.into()
            }
            Err(status) => build_omk_status_reply(&status)?,
        },
    };

    Ok(Some(reply))
}

unsafe fn install_outbound_reply(tr: &mut binder_transaction_data, reply: OutboundReply) {
    match reply {
        OutboundReply::Parcel(reply) => {
            OUTBOUND_REPLY_BUFFERS.with(|slot| {
                let mut buffers = slot.borrow_mut();
                buffers.push(*reply);
                let reply = buffers.last().expect("outbound reply buffer just pushed");
                tr.flags &= !super::binder::TF_STATUS_CODE;
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
        OutboundReply::Status(status) => {
            OUTBOUND_STATUS_BUFFERS.with(|slot| {
                let mut buffers = slot.borrow_mut();
                buffers.push(status);
                let status = buffers.last().expect("outbound status buffer just pushed");
                tr.flags |= super::binder::TF_STATUS_CODE;
                tr.data_size = size_of::<i32>();
                tr.offsets_size = 0;
                tr.data.ptr.buffer = status as *const i32 as libc::c_ulong;
                tr.data.ptr.offsets = 0;
            });
        }
    }
}

unsafe fn install_inbound_request(
    tr: &mut binder_transaction_data,
    code: rsbinder::TransactionCode,
    request: parcel::OwnedReply,
) {
    INBOUND_REQUEST_BUFFERS.with(|slot| {
        let mut buffers = slot.borrow_mut();
        buffers.push(request);
        let request = buffers.last().expect("inbound request buffer just pushed");
        tr.code = code;
        tr.data_size = request.data_size();
        tr.offsets_size = request.offsets_size();
        tr.data.ptr.buffer = request.data_ptr() as libc::c_ulong;
        tr.data.ptr.offsets = if request.offsets.is_empty() {
            0
        } else {
            request.offsets.as_ptr() as libc::c_ulong
        };
    });
}

unsafe fn install_omk_grant_placeholder_request(
    tr: &mut binder_transaction_data,
) -> anyhow::Result<()> {
    let system_backend = {
        let _guard = BypassGuard::enter();
        ipc::get_system_keystore_service()?
    };
    let request = parcel::build_get_number_of_entries_request(&system_backend, Domain::APP, -1)?;
    install_inbound_request(tr, service_tx::r#getNumberOfEntries, request);
    Ok(())
}

fn push_pending_frame() {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().push_back(None));
}

fn replace_top_pending(pending: PendingCall) {
    PENDING_REPLY_QUEUE.with(|slot| {
        if let Some(back) = slot.borrow_mut().back_mut() {
            *back = Some(pending);
        }
    });
}

fn take_top_pending() -> Option<Option<PendingCall>> {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().pop_front())
}

fn pop_pending_frame() {
    // Pending frames are removed by take_top_pending() so replies consume
    // requests in binder processing order. Kept as a no-op for older tests and
    // to make the reply lifecycle explicit at call sites.
}

pub(super) fn clear_outbound_reply_buffers() {
    OUTBOUND_REPLY_BUFFERS.with(|slot| slot.borrow_mut().clear());
    OUTBOUND_STATUS_BUFFERS.with(|slot| slot.borrow_mut().clear());
    INBOUND_REQUEST_BUFFERS.with(|slot| slot.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use rsbinder::{Interface, Status, StatusCode};

    use crate::{
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
        android::system::keystore2::KeyDescriptor::KeyDescriptor,
        android::system::keystore2::KeyEntryResponse::KeyEntryResponse,
        android::system::keystore2::KeyMetadata::KeyMetadata,
        hook::binder::{
            binder_object_header, flat_binder_object, flat_binder_object_handle_or_ptr,
            BINDER_TYPE_BINDER, BINDER_TYPE_FD,
        },
        route,
    };

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
        ensure_binder_process_state();
        BnKeystoreSecurityLevel::new_binder(FakeAospSecurityLevel)
    }

    fn ensure_binder_process_state() {
        let _ = rsbinder::ProcessState::init_default();
    }

    fn sample_key_descriptor() -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: 7,
            alias: Some("alias".to_string()),
            blob: None,
        }
    }

    fn sample_service_requests() -> Vec<ParsedServiceRequest> {
        vec![
            ParsedServiceRequest::GetSecurityLevel {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            },
            ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            ParsedServiceRequest::UpdateSubcomponent {
                key: sample_key_descriptor(),
                public_cert: None,
                certificate_chain: None,
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
        ]
    }

    fn disabled_intercept_config() -> config::InterceptConfig {
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

    struct TestOperationBackend {
        update_output: Vec<u8>,
        aborts: Arc<AtomicUsize>,
        update_aad_status: Option<Status>,
    }

    impl Interface for TestOperationBackend {}

    impl AospKeystoreOperation for TestOperationBackend {
        fn r#updateAad(&self, _aad_input: &[u8]) -> rsbinder::status::Result<()> {
            match self.update_aad_status.as_ref() {
                Some(status) => Err(status.clone()),
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

    fn outbound_parcel(reply: OutboundReply) -> parcel::OwnedReply {
        match reply {
            OutboundReply::Parcel(reply) => *reply,
            OutboundReply::Status(status) => panic!("expected parcel reply, got status {status}"),
        }
    }

    fn assert_outbound_status(reply: OutboundReply, expected: StatusCode) {
        let OutboundReply::Status(status) = reply else {
            panic!("expected status reply");
        };
        assert_eq!(status, i32::from(expected));
    }

    fn assert_unknown_transaction_reply(reply: SyntheticReply) {
        let SyntheticReply::Status(status) = reply else {
            panic!("unknown transaction should be returned as a binder status code");
        };
        assert_eq!(status, i32::from(StatusCode::UnknownTransaction));
    }

    fn carrier_target(carrier: &parcel::ReplyBinderCarrier) -> LocalBinderTarget {
        unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
            .expect("synthetic carrier should expose a native target")
    }

    fn request_parcel(interface: &str) -> rsbinder::Parcel {
        let mut parcel = rsbinder::Parcel::new();
        parcel.write(&0i32).unwrap();
        parcel.write(&0i32).unwrap();
        parcel.write(&0u32).unwrap();
        parcel.write(&interface.to_string()).unwrap();
        parcel
    }

    fn transaction_for_parcel(
        target: LocalBinderTarget,
        code: rsbinder::TransactionCode,
        parcel: &rsbinder::Parcel,
    ) -> binder_transaction_data {
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.target.ptr = target.ptr;
        tr.data.ptr.buffer = parcel.as_ptr() as libc::c_ulong;
        tr.data.ptr.offsets = 0;
        tr.cookie = target.cookie;
        tr.code = code;
        tr.sender_euid = 10002;
        tr.sender_pid = 2000;
        tr.data_size = parcel.data_size();
        tr.offsets_size = 0;
        tr
    }

    fn transaction_for_raw_parts(
        target: LocalBinderTarget,
        code: rsbinder::TransactionCode,
        data: &mut [u8],
        offsets: &mut [usize],
    ) -> binder_transaction_data {
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.target.ptr = target.ptr;
        tr.data.ptr.buffer = data.as_mut_ptr() as libc::c_ulong;
        tr.data.ptr.offsets = offsets.as_mut_ptr() as libc::c_ulong;
        tr.cookie = target.cookie;
        tr.code = code;
        tr.sender_euid = 10002;
        tr.sender_pid = 2000;
        tr.data_size = data.len();
        tr.offsets_size = std::mem::size_of_val(offsets);
        tr
    }

    fn dump_transaction_data(argc: i32, args: &[String]) -> Vec<u8> {
        let mut tail = rsbinder::Parcel::new();
        tail.write(&argc).unwrap();
        for arg in args {
            tail.write(arg).unwrap();
        }

        let mut data = vec![0u8; size_of::<flat_binder_object>() + tail.data_size()];
        let object = flat_binder_object {
            hdr: binder_object_header {
                type_: BINDER_TYPE_FD,
            },
            flags: 0,
            handle_or_ptr: flat_binder_object_handle_or_ptr { handle: 0 },
            cookie: 0,
        };
        unsafe {
            std::ptr::write_unaligned(data.as_mut_ptr() as *mut flat_binder_object, object);
            std::ptr::copy_nonoverlapping(
                tail.as_ptr(),
                data.as_mut_ptr().add(size_of::<flat_binder_object>()),
                tail.data_size(),
            );
        }
        data
    }

    fn test_local_binder_carrier(
        ptr: libc::c_ulong,
        cookie: libc::c_ulong,
    ) -> parcel::ReplyBinderCarrier {
        let object = flat_binder_object {
            hdr: binder_object_header {
                type_: BINDER_TYPE_BINDER,
            },
            flags: 0,
            handle_or_ptr: flat_binder_object_handle_or_ptr { binder: ptr },
            cookie,
        };
        let mut bytes = vec![0u8; size_of::<flat_binder_object>() + size_of::<i32>()];
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr() as *mut flat_binder_object, object);
        }
        parcel::ReplyBinderCarrier {
            bytes,
            is_object: true,
        }
    }

    static MIRROR_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ROUTE_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_mirror_state_for_tests() {
        AUTHORIZATION_MIRROR_STATE_DIRTY.store(false, Ordering::SeqCst);
        MAINTENANCE_MIRROR_STATE_DIRTY.store(false, Ordering::SeqCst);
    }

    fn route_state_test_guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = ROUTE_STATE_TEST_LOCK
            .lock()
            .expect("route state test lock poisoned");
        reset_route_state_for_tests();
        guard
    }

    fn reset_route_state_for_tests() {
        tracker::clear_state_for_tests();
        clear_operation_state_for_tests();
        PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
        clear_outbound_reply_buffers();
    }

    fn clear_synthetic_targets_for_tests() {
        synthetic_security_level_targets()
            .lock()
            .expect("synthetic security-level target map poisoned")
            .clear();
        synthetic_targets()
            .lock()
            .expect("synthetic target map poisoned")
            .clear();
        NEXT_SYNTHETIC_BINDER_ID.store(1, Ordering::SeqCst);
    }

    fn clear_operation_state_for_tests() {
        operation_targets()
            .lock()
            .expect("operation target map poisoned")
            .clear();
        clear_synthetic_targets_for_tests();
    }

    #[test]
    fn omk_service_specific_error_can_replace_system_success_reply() {
        let status = Status::new_service_specific_error(7, None);
        let mut reply = outbound_parcel(
            build_omk_status_reply(&status).expect("service-specific status should serialize"),
        );
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");

        assert_eq!(
            parsed.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(parsed.service_specific_error(), 7);
    }

    #[test]
    fn omk_transaction_error_keeps_native_status_code() {
        let status: Status = StatusCode::UnknownTransaction.into();
        assert_outbound_status(
            build_omk_status_reply(&status)
                .expect("transaction status should be converted into a reply"),
            StatusCode::UnknownTransaction,
        );
    }

    #[test]
    fn synthetic_security_level_unknown_transaction_is_native_unknown_transaction() {
        let reply =
            synthetic_unknown_transaction_reply_for(SyntheticTargetKind::SecurityLevel, u32::MAX)
                .expect("unknown security-level code should produce a synthetic reply");

        assert_unknown_transaction_reply(reply);
    }

    #[test]
    fn synthetic_operation_unknown_transaction_is_native_unknown_transaction() {
        let reply =
            synthetic_unknown_transaction_reply_for(SyntheticTargetKind::Operation, u32::MAX)
                .expect("unknown operation code should produce a synthetic reply");

        assert_unknown_transaction_reply(reply);
    }

    #[test]
    fn stale_synthetic_magic_target_is_consumed() {
        let _guard = route_state_test_guard();
        let target = allocate_synthetic_target();
        assert!(is_synthetic_binder_target(target));

        let empty = rsbinder::Parcel::new();
        let shell_tr = transaction_for_parcel(target, rsbinder::SHELL_COMMAND_TRANSACTION, &empty);
        let shell = unsafe { handle_synthetic_br_transaction(&shell_tr, None, "BR_TRANSACTION") }
            .expect("stale synthetic shell should be consumed");
        let SyntheticReply::Parcel(shell) = shell else {
            panic!("stale synthetic shell should be an empty parcel reply");
        };
        assert_eq!(shell.data_size(), 0);
        assert_eq!(shell.offsets_size(), 0);

        let business_tr = transaction_for_parcel(target, rsbinder::FIRST_CALL_TRANSACTION, &empty);
        let business =
            unsafe { handle_synthetic_br_transaction(&business_tr, None, "BR_TRANSACTION") }
                .expect("stale synthetic business call should be consumed");
        assert_unknown_transaction_reply(business);

        let mut oneway_tr =
            transaction_for_parcel(target, rsbinder::START_RECORDING_TRANSACTION, &empty);
        oneway_tr.flags |= crate::hook::binder::TF_ONE_WAY;
        let oneway = unsafe { handle_synthetic_br_transaction(&oneway_tr, None, "BR_TRANSACTION") }
            .expect("stale synthetic oneway should be consumed");
        assert!(matches!(oneway, SyntheticReply::NoReply));

        assert!(handle_synthetic_ref_command(
            target,
            crate::hook::binder::BR_RELEASE_NR
        ));
        assert!(!handle_synthetic_ref_command(
            LocalBinderTarget {
                ptr: 0x1234,
                cookie: 0x5678,
            },
            crate::hook::binder::BR_RELEASE_NR
        ));
    }

    #[test]
    fn synthetic_base_transactions_do_not_require_interface_token() {
        let target = LocalBinderTarget {
            ptr: 0x4100,
            cookie: 0x5100,
        };
        let empty = rsbinder::Parcel::new();
        let ping_tr = transaction_for_parcel(target, rsbinder::PING_TRANSACTION, &empty);
        let ping = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &ping_tr,
            )
        }
        .expect("ping handling should not fail")
        .expect("ping should produce a reply");
        let SyntheticReply::Parcel(ping) = ping else {
            panic!("ping should be an empty parcel reply");
        };
        assert_eq!(ping.data_size(), 0);
        assert_eq!(ping.offsets_size(), 0);

        let shell_tr = transaction_for_parcel(target, rsbinder::SHELL_COMMAND_TRANSACTION, &empty);
        let shell = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &shell_tr,
            )
        }
        .expect("shell handling should not fail")
        .expect("shell should produce a reply");
        let SyntheticReply::Parcel(shell) = shell else {
            panic!("shell should be an empty parcel reply");
        };
        assert_eq!(shell.data_size(), 0);
        assert_eq!(shell.offsets_size(), 0);

        let sysprops_tr = transaction_for_parcel(target, rsbinder::SYSPROPS_TRANSACTION, &empty);
        let sysprops = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &sysprops_tr,
            )
        }
        .expect("sysprops handling should not fail")
        .expect("sysprops should produce a reply");
        let SyntheticReply::Parcel(sysprops) = sysprops else {
            panic!("sysprops should be an empty parcel reply");
        };
        assert_eq!(sysprops.data_size(), 0);
        assert_eq!(sysprops.offsets_size(), 0);

        let start_recording_tr =
            transaction_for_parcel(target, rsbinder::START_RECORDING_TRANSACTION, &empty);
        let start_recording = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &start_recording_tr,
            )
        }
        .expect("start-recording handling should not fail")
        .expect("start-recording should produce a reply");
        let SyntheticReply::Status(status) = start_recording else {
            panic!("unsupported base transaction should be a binder status code");
        };
        assert_eq!(status, i32::from(StatusCode::InvalidOperation));

        let malformed_dump_tr = transaction_for_parcel(target, rsbinder::DUMP_TRANSACTION, &empty);
        let malformed_dump = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &malformed_dump_tr,
            )
        }
        .expect("dump handling should not fail")
        .expect("dump should produce a reply");
        let SyntheticReply::Status(status) = malformed_dump else {
            panic!("malformed dump should be a binder status code");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));

        let mut dump_data = dump_transaction_data(0, &[]);
        let mut offsets = [0usize];
        let dump_tr = transaction_for_raw_parts(
            target,
            rsbinder::DUMP_TRANSACTION,
            &mut dump_data,
            &mut offsets,
        );
        let dump = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &dump_tr,
            )
        }
        .expect("dump handling should not fail")
        .expect("dump should produce a reply");
        let SyntheticReply::Parcel(dump) = dump else {
            panic!("valid dump should be an empty parcel reply");
        };
        assert_eq!(dump.data_size(), 0);
        assert_eq!(dump.offsets_size(), 0);

        let mut dump_with_args_data = dump_transaction_data(1, &[String::from("--proto")]);
        let dump_with_args_tr = transaction_for_raw_parts(
            target,
            rsbinder::DUMP_TRANSACTION,
            &mut dump_with_args_data,
            &mut offsets,
        );
        let dump_with_args = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &dump_with_args_tr,
            )
        }
        .expect("dump with args handling should not fail")
        .expect("dump with args should produce a reply");
        let SyntheticReply::Parcel(dump_with_args) = dump_with_args else {
            panic!("valid dump with args should be an empty parcel reply");
        };
        assert_eq!(dump_with_args.data_size(), 0);
        assert_eq!(dump_with_args.offsets_size(), 0);

        let mut negative_argc_data = dump_transaction_data(-1, &[]);
        let negative_argc_tr = transaction_for_raw_parts(
            target,
            rsbinder::DUMP_TRANSACTION,
            &mut negative_argc_data,
            &mut offsets,
        );
        let negative_argc = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &negative_argc_tr,
            )
        }
        .expect("negative argc dump handling should not fail")
        .expect("negative argc dump should produce a reply");
        let SyntheticReply::Status(status) = negative_argc else {
            panic!("negative argc dump should be a binder status code");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));

        let mut trailing_dump_data = dump_transaction_data(0, &[]);
        trailing_dump_data.extend_from_slice(&0x4f4d4bu32.to_ne_bytes());
        let trailing_dump_tr = transaction_for_raw_parts(
            target,
            rsbinder::DUMP_TRANSACTION,
            &mut trailing_dump_data,
            &mut offsets,
        );
        let trailing_dump = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &trailing_dump_tr,
            )
        }
        .expect("trailing dump handling should not fail")
        .expect("trailing dump should produce a reply");
        let SyntheticReply::Status(status) = trailing_dump else {
            panic!("trailing dump should be a binder status code");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));

        let unknown_tr = transaction_for_parcel(target, u32::MAX, &empty);
        let unknown = unsafe {
            synthetic_base_transaction_reply(
                Some(SyntheticTargetKind::SecurityLevel),
                target,
                &unknown_tr,
            )
        }
        .expect("unknown outside call range should not fail")
        .expect("unknown outside call range should produce a reply");
        assert_unknown_transaction_reply(unknown);
    }

    #[test]
    fn synthetic_security_level_aidl_metadata_returns_keystore2_version_and_hash() {
        let target = LocalBinderTarget {
            ptr: 0x5234,
            cookie: 0x9678,
        };
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::SecurityLevel,
            caller: None,
        };
        let hash_request = request_parcel(identify::KEYSTORE_SECURITY_LEVEL_INTERFACE);
        let hash_tr = transaction_for_parcel(
            target,
            identify::AIDL_GET_INTERFACE_HASH_TRANSACTION,
            &hash_request,
        );

        let reply = unsafe {
            build_synthetic_br_transaction_reply(
                &hash_tr,
                target,
                info.clone(),
                None,
                "BR_TRANSACTION",
            )
        }
        .expect("metadata hash should be handled");
        let SyntheticReply::Parcel(mut reply) = reply else {
            panic!("metadata hash should return a parcel reply");
        };
        let hash: String = parcel::parse_owned_success_reply(&mut reply)
            .expect("metadata hash reply should parse");
        let expected = keystore2_aidl_metadata().expect("keystore2 metadata should resolve");
        assert_eq!(hash, expected.hash);

        let version_request = request_parcel(identify::KEYSTORE_SECURITY_LEVEL_INTERFACE);
        let version_tr = transaction_for_parcel(
            target,
            identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION,
            &version_request,
        );
        let reply = unsafe {
            build_synthetic_br_transaction_reply(&version_tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("metadata version should be handled");
        let SyntheticReply::Parcel(mut reply) = reply else {
            panic!("metadata version should return a parcel reply");
        };
        let version: i32 = parcel::parse_owned_success_reply(&mut reply)
            .expect("metadata version reply should parse");
        assert_eq!(version, expected.version);
    }

    #[test]
    fn synthetic_operation_aidl_metadata_returns_keystore2_version() {
        let target = LocalBinderTarget {
            ptr: 0x6234,
            cookie: 0xa678,
        };
        let request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        let tr = transaction_for_parcel(
            target,
            identify::AIDL_GET_INTERFACE_VERSION_TRANSACTION,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("operation metadata version should be handled");
        let SyntheticReply::Parcel(mut reply) = reply else {
            panic!("operation metadata version should return a parcel reply");
        };
        let version: i32 = parcel::parse_owned_success_reply(&mut reply)
            .expect("metadata version reply should parse");
        let expected = keystore2_aidl_metadata().expect("keystore2 metadata should resolve");
        assert_eq!(version, expected.version);
    }

    #[test]
    fn synthetic_aidl_metadata_rejects_wrong_interface_token() {
        let target = LocalBinderTarget {
            ptr: 0x7234,
            cookie: 0xb678,
        };
        let request = request_parcel(identify::KEYSTORE_SERVICE_INTERFACE);
        let tr = transaction_for_parcel(
            target,
            identify::AIDL_GET_INTERFACE_HASH_TRANSACTION,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("wrong metadata interface should be handled");
        let SyntheticReply::Status(status) = reply else {
            panic!("wrong metadata interface should return a binder status");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));
    }

    #[test]
    fn synthetic_aidl_metadata_rejects_trailing_payload() {
        let target = LocalBinderTarget {
            ptr: 0x7334,
            cookie: 0xb778,
        };
        let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        request.write(&0x4f4d4bi32).unwrap();
        let tr = transaction_for_parcel(
            target,
            identify::AIDL_GET_INTERFACE_HASH_TRANSACTION,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("trailing metadata request should be handled");
        let SyntheticReply::Status(status) = reply else {
            panic!("trailing metadata request should return a binder status");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));
    }

    #[test]
    fn keystore2_vintf_parser_matches_fqname_and_interface_forms() {
        let xml = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.system.keystore2</name>
        <version>5</version>
        <fqname>IKeystoreService/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.system.keystore2</name>
        <version>4</version>
        <interface>
            <name>IKeystoreService</name>
            <instance>secondary</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert_eq!(parse_keystore2_aidl_version_xml(xml).unwrap(), Some(5));

        let xml = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.system.keystore2</name>
        <version>4</version>
        <interface>
            <name>IKeystoreService</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert_eq!(parse_keystore2_aidl_version_xml(xml).unwrap(), Some(4));
    }

    #[test]
    fn keystore2_vintf_parser_ignores_unrelated_and_invalid_versions() {
        let unrelated = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>5</version>
        <fqname>IKeystoreService/default</fqname>
    </hal>
</manifest>
"#;
        assert_eq!(parse_keystore2_aidl_version_xml(unrelated).unwrap(), None);

        let future = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.system.keystore2</name>
        <version>99</version>
        <fqname>IKeystoreService/default</fqname>
    </hal>
</manifest>
"#;
        assert_eq!(parse_keystore2_aidl_version_xml(future).unwrap(), None);
        assert!(parse_keystore2_aidl_version_xml("<manifest>").is_err());
    }

    #[test]
    fn synthetic_operation_malformed_finish_returns_bad_value_status() {
        let _guard = route_state_test_guard();

        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        let aborts = Arc::new(AtomicUsize::new(0));
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![5, 6, 7],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: Some(backend),
                finalized: false,
            },
        );

        let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        let input: Option<Vec<u8>> = None;
        request.write(&input).unwrap();
        let tr = transaction_for_parcel(
            target,
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#finish,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("malformed finish should be handled without fallback");
        let SyntheticReply::Status(status) = reply else {
            panic!("malformed finish should return a binder status, not a service reply");
        };
        assert_eq!(status, i32::from(StatusCode::BadValue));
        assert!(
            lookup_operation_target(target).is_some(),
            "malformed parse must not finalize the operation"
        );
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn synthetic_operation_trailing_abort_returns_bad_value_status() {
        let _guard = route_state_test_guard();

        let target = LocalBinderTarget {
            ptr: 0x1334,
            cookie: 0x5778,
        };
        let aborts = Arc::new(AtomicUsize::new(0));
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![5, 6, 7],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: Some(backend),
                finalized: false,
            },
        );

        let mut request = request_parcel(identify::KEYSTORE_OPERATION_INTERFACE);
        request.write(&0x4f4d4bi32).unwrap();
        let tr = transaction_for_parcel(
            target,
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("trailing abort should be handled without fallback");
        let SyntheticReply::Status(status) = reply else {
            panic!("trailing abort should return a binder status, not a service reply");
        };
        assert_eq!(status, i32::from(StatusCode::BadValue));
        assert!(
            lookup_operation_target(target).is_some(),
            "trailing data must not finalize the operation"
        );
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn synthetic_security_level_malformed_request_returns_bad_value_status() {
        let _guard = route_state_test_guard();

        let target = LocalBinderTarget {
            ptr: 0x2234,
            cookie: 0x6678,
        };
        tracker::remember_security_level_target(
            target,
            SecurityLevelTargetInfo {
                security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
                preferred_route: RouteTarget::Omk,
                source_method: ServiceMethod::GetKeyEntry,
            },
        );

        let request = request_parcel(identify::KEYSTORE_SECURITY_LEVEL_INTERFACE);
        let tr = transaction_for_parcel(
            target,
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#createOperation,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::SecurityLevel,
            caller: None,
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("malformed createOperation should be handled without fallback");
        let SyntheticReply::Status(status) = reply else {
            panic!("malformed createOperation should return a binder status, not a service reply");
        };
        assert_eq!(status, i32::from(StatusCode::BadValue));
    }

    #[test]
    fn synthetic_operation_unexpected_interface_returns_bad_type_status() {
        let _guard = route_state_test_guard();

        let target = LocalBinderTarget {
            ptr: 0x3234,
            cookie: 0x7678,
        };
        let request = request_parcel(identify::KEYSTORE_SERVICE_INTERFACE);
        let tr = transaction_for_parcel(
            target,
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#abort,
            &request,
        );
        let info = SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            caller: Some(CallerIdentity::new(10002, 2000)),
        };

        let reply = unsafe {
            build_synthetic_br_transaction_reply(&tr, target, info, None, "BR_TRANSACTION")
        }
        .expect("unexpected interface should be handled without fallback");
        let SyntheticReply::Status(status) = reply else {
            panic!("unexpected interface should return a binder status, not a service reply");
        };
        assert_eq!(status, i32::from(StatusCode::BadType));
    }

    #[test]
    fn plain_omk_error_becomes_system_error_reply() {
        let error = anyhow::anyhow!("plain OMK failure");
        let mut reply = outbound_parcel(
            build_omk_error_reply(&error).expect("plain error should produce a status reply"),
        );
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");

        assert_eq!(
            parsed.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(
            parsed.service_specific_error(),
            ResponseCode::SYSTEM_ERROR.0
        );
    }

    #[test]
    fn contextual_omk_status_error_keeps_service_specific_code() {
        let status = Status::new_service_specific_error(7, None);
        let error = anyhow::Error::new(status).context("wrapped OMK failure");
        let mut reply = outbound_parcel(
            build_omk_error_reply(&error).expect("wrapped status should produce a status reply"),
        );
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");

        assert_eq!(
            parsed.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(parsed.service_specific_error(), 7);
    }

    #[test]
    fn unavailable_omk_errors_preserve_system_reply() {
        for status in [
            StatusCode::DeadObject,
            StatusCode::NoInit,
            StatusCode::NameNotFound,
            StatusCode::Errno(libc::ECONNREFUSED),
            StatusCode::Errno(libc::EPIPE),
        ] {
            let error = anyhow::Error::new(Status::from(status));
            assert!(
                build_omk_error_reply_or_preserve_system(&error)
                    .expect("unavailable OMK errors should classify cleanly")
                    .is_none(),
                "{status:?} after retry means OMK is unavailable, not authoritative"
            );
        }

        let connect = anyhow::anyhow!("failed to connect to omk service");
        assert!(
            build_omk_error_reply_or_preserve_system(&connect)
                .expect("OMK connection errors should classify cleanly")
                .is_none(),
            "OMK connection errors without a Status should preserve system"
        );

        let missing_service = anyhow::Error::new(StatusCode::NameNotFound);
        assert!(
            build_omk_error_reply_or_preserve_system(&missing_service)
                .expect("missing RPC service should classify cleanly")
                .is_none(),
            "missing OMK RPC service means OMK is unavailable"
        );

        let local = anyhow::anyhow!("plain OMK failure");
        assert!(
            build_omk_error_reply_or_preserve_system(&local)
                .expect("plain OMK errors should classify cleanly")
                .is_some(),
            "non-connection OMK errors must be returned instead of preserving system"
        );
    }

    #[test]
    fn native_status_outbound_reply_installs_tf_status_code() {
        clear_outbound_reply_buffers();
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        let status = i32::from(StatusCode::UnknownTransaction);

        unsafe { install_outbound_reply(&mut tr, OutboundReply::Status(status)) };

        assert_ne!(tr.flags & crate::hook::binder::TF_STATUS_CODE, 0);
        assert_eq!(tr.data_size, size_of::<i32>());
        assert_eq!(tr.offsets_size, 0);
        assert_eq!(unsafe { tr.data.ptr.offsets }, 0);
        let installed = unsafe { *(tr.data.ptr.buffer as *const i32) };
        assert_eq!(installed, status);
        clear_outbound_reply_buffers();
    }

    #[test]
    fn reachable_omk_status_code_errors_keep_native_status_code() {
        for status in [
            StatusCode::RpcError,
            StatusCode::TimedOut,
            StatusCode::PermissionDenied,
            StatusCode::UnknownTransaction,
        ] {
            let error = anyhow::Error::new(status);
            assert_outbound_status(
                build_omk_error_reply_or_preserve_system(&error)
                    .expect("reachable OMK errors should classify cleanly")
                    .expect("non-dead OMK errors must replace system reply"),
                status,
            );
        }
    }

    #[test]
    fn grant_precompute_preserves_system_when_omk_is_unavailable() {
        let request = ParsedServiceRequest::Grant {
            key: sample_key_descriptor(),
            grantee_uid: 12345,
            access_vector: 7,
        };
        let caller = CallerIdentity::new(1000, 2000);

        let result = precompute_omk_grant_service_reply_with(
            &request,
            &caller,
            |_, _, _, _| Err(anyhow::Error::new(Status::from(StatusCode::DeadObject))),
            |_, _, _| panic!("grant requests must not call ungrant"),
        );

        assert!(matches!(result, OmkGrantPrecompute::PreserveSystem));
    }

    #[test]
    fn ungrant_precompute_preserves_system_when_omk_connect_fails() {
        let request = ParsedServiceRequest::Ungrant {
            key: sample_key_descriptor(),
            grantee_uid: 12345,
        };
        let caller = CallerIdentity::new(1000, 2000);

        let result = precompute_omk_grant_service_reply_with(
            &request,
            &caller,
            |_, _, _, _| panic!("ungrant requests must not call grant"),
            |_, _, _| Err(anyhow::anyhow!("failed to connect to omk service")),
        );

        assert!(matches!(result, OmkGrantPrecompute::PreserveSystem));
    }

    #[test]
    fn grant_precompute_returns_reachable_omk_business_error() {
        let request = ParsedServiceRequest::Grant {
            key: sample_key_descriptor(),
            grantee_uid: 12345,
            access_vector: 7,
        };
        let caller = CallerIdentity::new(1000, 2000);

        let result = precompute_omk_grant_service_reply_with(
            &request,
            &caller,
            |_, _, _, _| {
                Err(anyhow::Error::new(Status::new_service_specific_error(
                    7, None,
                )))
            },
            |_, _, _| panic!("grant requests must not call ungrant"),
        );

        let OmkGrantPrecompute::Reply(PrecomputedServiceReply::Error(
            PrecomputedErrorReply::Status(status),
        )) = result
        else {
            panic!("reachable OMK business error should be precomputed as an authoritative status");
        };
        assert_eq!(
            status.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(status.service_specific_error(), 7);
    }

    #[test]
    fn dirty_mirror_state_is_scoped_by_interface_kind() {
        let _guard = MIRROR_STATE_TEST_LOCK
            .lock()
            .expect("mirror state test lock poisoned");
        reset_mirror_state_for_tests();
        let caller = CallerIdentity::new(1000, 2000);

        mark_mirror_state_dirty(
            MirrorStateKind::Authorization,
            AuthorizationMethod::AddAuthToken,
            &caller,
        );

        assert!(mirror_state_dirty(MirrorStateKind::Authorization));
        assert!(!mirror_state_dirty(MirrorStateKind::Maintenance));

        clear_mirror_state_dirty(
            MirrorStateKind::Authorization,
            AuthorizationMethod::AddAuthToken,
            &caller,
        );

        assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
        assert!(!mirror_state_dirty(MirrorStateKind::Maintenance));
        reset_mirror_state_for_tests();
    }

    #[test]
    fn successful_mutating_mirror_clears_only_matching_dirty_state() {
        let _guard = MIRROR_STATE_TEST_LOCK
            .lock()
            .expect("mirror state test lock poisoned");
        reset_mirror_state_for_tests();
        AUTHORIZATION_MIRROR_STATE_DIRTY.store(true, Ordering::SeqCst);
        MAINTENANCE_MIRROR_STATE_DIRTY.store(true, Ordering::SeqCst);
        let caller = CallerIdentity::new(1000, 2000);

        clear_mirror_state_dirty(
            MirrorStateKind::Authorization,
            AuthorizationMethod::AddAuthToken,
            &caller,
        );

        assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
        assert!(mirror_state_dirty(MirrorStateKind::Maintenance));

        clear_mirror_state_dirty(
            MirrorStateKind::Maintenance,
            MaintenanceMethod::OnUserAdded,
            &caller,
        );

        assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
        assert!(!mirror_state_dirty(MirrorStateKind::Maintenance));
        reset_mirror_state_for_tests();
    }

    #[test]
    fn read_only_mirror_methods_do_not_count_as_recovery() {
        assert!(authorization_mirror_mutates(
            AuthorizationMethod::AddAuthToken
        ));
        assert!(authorization_mirror_mutates(
            AuthorizationMethod::OnDeviceUnlocked
        ));
        assert!(!authorization_mirror_mutates(
            AuthorizationMethod::GetAuthTokensForCredStore
        ));
        assert!(!authorization_mirror_mutates(
            AuthorizationMethod::GetLastAuthTime
        ));

        assert!(maintenance_mirror_mutates(MaintenanceMethod::OnUserAdded));
        assert!(maintenance_mirror_mutates(
            MaintenanceMethod::ClearNamespace
        ));
        assert!(!maintenance_mirror_mutates(
            MaintenanceMethod::GetAppUidsAffectedBySid
        ));
    }

    #[test]
    fn reachable_omk_status_error_becomes_authoritative_reply() {
        let status = Status::new_service_specific_error(7, None);
        let reply = build_omk_status_reply_or_preserve_system(&status)
            .expect("service-specific status should build")
            .expect("reachable OMK status should replace system");
        let mut reply = outbound_parcel(reply);
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");

        assert_eq!(
            parsed.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(parsed.service_specific_error(), 7);
    }

    #[test]
    fn local_service_target_extraction_is_stable() {
        let carrier = test_local_binder_carrier(0x1234, 0x5678);
        let first = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
            .expect("first extraction should succeed");
        let second = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
            .expect("second extraction should succeed");

        assert_eq!(first, second);
        assert_eq!(first.ptr, 0x1234);
        assert_eq!(first.cookie, 0x5678);
    }

    #[test]
    fn service_route_uses_omk_for_bridged_service_methods() {
        let _guard = route_state_test_guard();
        let intercept = config::InterceptConfig::default();

        for request in sample_service_requests() {
            assert_eq!(
                route_for_service_request(&request, &intercept),
                RouteTarget::Omk,
                "{:?} should use the OMK backend when the method is enabled",
                request.method()
            );
        }
    }

    #[test]
    fn service_route_uses_system_when_intercept_methods_are_disabled() {
        let _guard = route_state_test_guard();
        let intercept = disabled_intercept_config();

        for request in sample_service_requests() {
            assert_eq!(
                route_for_service_request(&request, &intercept),
                RouteTarget::System,
                "{:?} should use the system backend when the method is disabled",
                request.method()
            );
        }
    }

    #[test]
    fn service_route_preserves_tracked_system_grant_owner() {
        let _guard = route_state_test_guard();
        let intercept = config::InterceptConfig::default();
        let grant = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 123,
            alias: None,
            blob: None,
        };
        tracker::remember_key_descriptor_route(&grant, RouteTarget::System);

        assert_eq!(
            route_for_service_request(
                &ParsedServiceRequest::Ungrant {
                    key: grant,
                    grantee_uid: 10001,
                },
                &intercept
            ),
            RouteTarget::System
        );
    }

    #[test]
    fn tracked_grant_readback_bypasses_package_rejection() {
        let _guard = route_state_test_guard();
        let surfaced = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 123,
            alias: None,
            blob: None,
        };
        tracker::remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        let decision = crate::filter::FilterDecision {
            allowed: false,
            reason: crate::filter::FilterReason::RejectedUnknownPackage,
            packages: vec![],
        };
        let caller = CallerIdentity::new(10002, 2000);

        assert!(should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry { key: surfaced },
            &decision,
            &caller,
            |_, _| false,
        ));
    }

    #[test]
    fn unconfirmed_grant_readback_stays_rejected() {
        let _guard = route_state_test_guard();
        let decision = crate::filter::FilterDecision {
            allowed: false,
            reason: crate::filter::FilterReason::RejectedUnknownPackage,
            packages: vec![],
        };
        let caller = CallerIdentity::new(10002, 2000);
        let grant = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 123,
            alias: None,
            blob: None,
        };

        assert!(!should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry { key: grant.clone() },
            &decision,
            &caller,
            |_, _| false,
        ));
        tracker::remember_key_descriptor_route(&grant, RouteTarget::System);
        assert!(!should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry { key: grant },
            &decision,
            &caller,
            |_, _| false,
        ));
        assert!(!should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            &decision,
            &caller,
            |_, _| panic!("non-GRANT descriptors must not be probed"),
        ));
    }

    #[test]
    fn unknown_grant_readback_uses_positive_omk_probe() {
        let _guard = route_state_test_guard();
        let grant = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 123,
            alias: None,
            blob: None,
        };
        let decision = crate::filter::FilterDecision {
            allowed: false,
            reason: crate::filter::FilterReason::RejectedUnknownPackage,
            packages: vec![],
        };
        let caller = CallerIdentity::new(10002, 2000);

        assert!(should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry { key: grant.clone() },
            &decision,
            &caller,
            |probe_caller, probe_grant| {
                assert_eq!(probe_caller.uid, caller.uid);
                assert_eq!(probe_grant, &grant);
                true
            },
        ));
        assert_eq!(
            tracker::lookup_key_descriptor_route(&grant),
            Some(RouteTarget::Omk)
        );
    }

    #[test]
    fn unknown_grant_create_operation_uses_positive_omk_probe() {
        let _guard = route_state_test_guard();
        let grant = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 321,
            alias: None,
            blob: None,
        };
        let decision = crate::filter::FilterDecision {
            allowed: false,
            reason: crate::filter::FilterReason::RejectedUnknownPackage,
            packages: vec![],
        };
        let caller = CallerIdentity::new(10002, 2000);

        assert!(should_allow_omk_grant_security_level_request_with_probe(
            &ParsedSecurityLevelRequest::CreateOperation {
                key: grant.clone(),
                operation_parameters: vec![],
                forced: false,
            },
            &decision,
            &caller,
            |probe_caller, probe_grant| {
                assert_eq!(probe_caller.uid, caller.uid);
                assert_eq!(probe_grant, &grant);
                true
            },
        ));
        assert_eq!(
            tracker::lookup_key_descriptor_route(&grant),
            Some(RouteTarget::Omk)
        );
    }

    #[test]
    fn tracked_grant_readback_respects_non_unknown_package_rejection() {
        let _guard = route_state_test_guard();
        let surfaced = KeyDescriptor {
            domain: Domain::GRANT,
            nspace: 123,
            alias: None,
            blob: None,
        };
        tracker::remember_key_descriptor_route(&surfaced, RouteTarget::Omk);
        let decision = crate::filter::FilterDecision {
            allowed: false,
            reason: crate::filter::FilterReason::RejectedByDenylist,
            packages: vec!["com.blocked".to_string()],
        };
        let caller = CallerIdentity::new(10002, 2000);

        assert!(!should_allow_omk_grant_service_request_with_probe(
            &ParsedServiceRequest::GetKeyEntry { key: surfaced },
            &decision,
            &caller,
            |_, _| panic!("denylisted callers must not probe OMK grants"),
        ));
    }

    #[test]
    fn pending_reply_queue_consumes_requests_in_binder_order() {
        let _guard = route_state_test_guard();
        PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
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
        replace_top_pending(PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            method: ServiceMethod::GetKeyEntry,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        }));

        let first = take_top_pending();
        assert!(matches!(
            first,
            Some(Some(PendingCall::Service(PendingServiceCall {
                method: ServiceMethod::GetSecurityLevel,
                ..
            })))
        ));

        let second = take_top_pending();
        assert!(matches!(
            second,
            Some(Some(PendingCall::Service(PendingServiceCall {
                method: ServiceMethod::GetKeyEntry,
                ..
            })))
        ));
        assert!(take_top_pending().is_none());
    }

    #[test]
    fn rewrite_failures_preserve_system_only_for_non_omk_routes() {
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let caller = CallerIdentity::new(1000, 2000);
        let service_omk = PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            method: ServiceMethod::GetKeyEntry,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
        });
        let service_system = PendingCall::Service(PendingServiceCall {
            request: ParsedServiceRequest::GetKeyEntry {
                key: sample_key_descriptor(),
            },
            method: ServiceMethod::GetKeyEntry,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::System,
        });
        assert!(!pending_preserves_system_on_rewrite_failure(&service_omk));
        assert!(pending_preserves_system_on_rewrite_failure(&service_system));

        let security_omk = PendingCall::SecurityLevel(PendingSecurityLevelCall {
            request: ParsedSecurityLevelRequest::CreateOperation {
                key: sample_key_descriptor(),
                operation_parameters: vec![],
                forced: false,
            },
            method: SecurityLevelMethod::CreateOperation,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::Omk,
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        });
        let security_system = PendingCall::SecurityLevel(PendingSecurityLevelCall {
            request: ParsedSecurityLevelRequest::CreateOperation {
                key: sample_key_descriptor(),
                operation_parameters: vec![],
                forced: false,
            },
            method: SecurityLevelMethod::CreateOperation,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            route: RouteTarget::System,
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
        });
        assert!(!pending_preserves_system_on_rewrite_failure(&security_omk));
        assert!(pending_preserves_system_on_rewrite_failure(
            &security_system
        ));

        let omk_target = LocalBinderTarget {
            ptr: 0x1111,
            cookie: 0x2222,
        };
        remember_operation_target(
            omk_target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: None,
                finalized: false,
            },
        );
        let system_target = LocalBinderTarget {
            ptr: 0x3333,
            cookie: 0x4444,
        };
        remember_operation_target(
            system_target,
            OperationTargetInfo {
                route: RouteTarget::System,
                aad_allowed: true,
                backend: None,
                finalized: false,
            },
        );
        let operation_omk = PendingCall::Operation(PendingOperationCall {
            request: ParsedOperationRequest::Update { input: vec![1] },
            method: OperationMethod::Update,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            target: omk_target,
        });
        let operation_system = PendingCall::Operation(PendingOperationCall {
            request: ParsedOperationRequest::Update { input: vec![1] },
            method: OperationMethod::Update,
            caller: caller.clone(),
            packages: vec!["com.example".to_string()],
            target: system_target,
        });
        assert!(!pending_preserves_system_on_rewrite_failure(&operation_omk));
        assert!(pending_preserves_system_on_rewrite_failure(
            &operation_system
        ));

        let authorization = PendingCall::Authorization(PendingAuthorizationCall {
            request: ParsedAuthorizationRequest::AddAuthToken {
                auth_token: Default::default(),
            },
            method: AuthorizationMethod::AddAuthToken,
            caller: caller.clone(),
        });
        let maintenance = PendingCall::Maintenance(PendingMaintenanceCall {
            request: ParsedMaintenanceRequest::OnUserAdded { user_id: 10 },
            method: MaintenanceMethod::OnUserAdded,
            caller,
        });
        assert!(pending_preserves_system_on_rewrite_failure(&authorization));
        assert!(pending_preserves_system_on_rewrite_failure(&maintenance));
    }

    #[test]
    fn synthetic_transaction_caller_uses_registered_sid_when_secctx_is_absent() {
        let fallback = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.sender_euid = 10002;
        tr.sender_pid = 3456;

        let caller = synthetic_transaction_caller(&fallback, &tr, None);
        assert_eq!(caller.uid, 10002);
        assert_eq!(caller.pid, 3456);
        assert_eq!(caller.sid, fallback.sid);

        let caller = synthetic_transaction_caller(
            &fallback,
            &tr,
            Some("u:r:platform_app:s0:c1,c2".to_string()),
        );
        assert_eq!(caller.sid, "u:r:platform_app:s0:c1,c2");
    }

    #[test]
    fn synthetic_security_level_carrier_is_stable_per_security_level() {
        let _guard = route_state_test_guard();
        clear_synthetic_targets_for_tests();

        let first_caller =
            CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");
        let second_caller =
            CallerIdentity::new(10003, 3000).with_sid("u:r:untrusted_app:s0:c789,c012");
        let first = register_synthetic_security_level_carrier(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            ServiceMethod::GetSecurityLevel,
            &first_caller,
        );
        let second = register_synthetic_security_level_carrier(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            ServiceMethod::GetKeyEntry,
            &second_caller,
        );

        let target = carrier_target(&first);
        assert_eq!(target, carrier_target(&second));
        let synthetic_info =
            lookup_synthetic_target_info(target).expect("synthetic target should be tracked");
        assert_eq!(synthetic_info.kind, SyntheticTargetKind::SecurityLevel);
        assert!(synthetic_info.caller.is_none());
        let target_info = tracker::lookup_security_level_target(target)
            .expect("synthetic security-level target should be tracked");
        assert_eq!(
            target_info.security_level,
            SecurityLevel::TRUSTED_ENVIRONMENT
        );
        assert_eq!(target_info.source_method, ServiceMethod::GetKeyEntry);
    }

    #[test]
    fn synthetic_security_level_carrier_is_distinct_per_security_level() {
        let _guard = route_state_test_guard();
        clear_synthetic_targets_for_tests();

        let caller = CallerIdentity::new(10002, 2000);
        let tee = register_synthetic_security_level_carrier(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            ServiceMethod::GetSecurityLevel,
            &caller,
        );
        let strongbox = register_synthetic_security_level_carrier(
            SecurityLevel::STRONGBOX,
            ServiceMethod::GetSecurityLevel,
            &caller,
        );

        assert_ne!(carrier_target(&tee), carrier_target(&strongbox));
    }

    #[test]
    fn synthetic_security_level_caller_does_not_use_registered_fallback() {
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.sender_euid = 10003;
        tr.sender_pid = 3456;

        let caller = synthetic_transaction_current_caller(&tr, None);
        assert_eq!(caller.uid, 10003);
        assert_eq!(caller.pid, 3456);
        assert_eq!(caller.sid, "");

        let caller = synthetic_transaction_current_caller(
            &tr,
            Some("u:r:platform_app:s0:c1,c2".to_string()),
        );
        assert_eq!(caller.sid, "u:r:platform_app:s0:c1,c2");
    }

    #[test]
    fn no_carrier_omk_key_entry_reply_uses_returned_security_level_handle() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_synthetic_targets_for_tests();

        let security_level = SecurityLevel::TRUSTED_ENVIRONMENT;
        let metadata = KeyMetadata {
            key: KeyDescriptor {
                domain: Domain::KEY_ID,
                nspace: 0x1234,
                alias: None,
                blob: None,
            },
            keySecurityLevel: security_level,
            authorizations: vec![],
            certificate: None,
            certificateChain: None,
            modificationTimeMs: 0,
        };
        let caller = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");

        let mut reply = build_no_carrier_omk_key_entry_reply(
            KeyEntryResponse {
                r#iSecurityLevel: Some(fake_system_security_level_backend()),
                metadata,
            },
            &caller,
        )
        .expect("no-carrier OMK key-entry reply should serialize");
        let (reply_data, reply_data_size, reply_offsets, reply_offsets_size) =
            raw_parts(&mut reply);
        let parsed_metadata = unsafe {
            parcel::parse_key_entry_reply_metadata(
                reply_data,
                reply_data_size,
                reply_offsets,
                reply_offsets_size,
            )
        }
        .expect("rewritten key-entry metadata should parse");
        assert_eq!(parsed_metadata.r#key.nspace, 0x1234);
        assert_eq!(parsed_metadata.r#keySecurityLevel, security_level);

        let carrier = unsafe {
            parcel::extract_key_entry_reply_carrier(
                reply_data,
                reply_data_size,
                reply_offsets,
                reply_offsets_size,
            )
        }
        .expect("synthetic key-entry security-level carrier should parse");
        let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
            .expect("synthetic security-level carrier should expose a native target");
        assert_eq!(
            lookup_synthetic_target(target),
            Some(SyntheticTargetKind::SecurityLevel)
        );
        let synthetic_info =
            lookup_synthetic_target_info(target).expect("synthetic target should be tracked");
        assert_eq!(synthetic_info.kind, SyntheticTargetKind::SecurityLevel);
        assert!(synthetic_info.caller.is_none());
        let target_info = tracker::lookup_security_level_target(target)
            .expect("synthetic security-level target should be tracked");
        assert_eq!(target_info.preferred_route, RouteTarget::Omk);
        assert_eq!(target_info.security_level, security_level);
        assert_eq!(
            tracker::lookup_key_descriptor_route(&parsed_metadata.r#key),
            Some(RouteTarget::Omk)
        );
    }

    #[test]
    fn no_carrier_omk_pure_cert_key_entry_keeps_security_level_null() {
        let _guard = route_state_test_guard();
        clear_synthetic_targets_for_tests();

        let metadata = KeyMetadata {
            key: KeyDescriptor {
                domain: Domain::KEY_ID,
                nspace: 0x4321,
                alias: None,
                blob: None,
            },
            keySecurityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            authorizations: vec![],
            certificate: None,
            certificateChain: None,
            modificationTimeMs: 0,
        };
        let caller = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");

        let mut reply = build_no_carrier_omk_key_entry_reply(
            KeyEntryResponse {
                r#iSecurityLevel: None,
                metadata,
            },
            &caller,
        )
        .expect("pure cert OMK key-entry reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed_metadata = unsafe {
            parcel::parse_key_entry_reply_metadata(data, data_size, offsets, offsets_size)
        }
        .expect("direct OMK key-entry reply should parse");

        assert_eq!(parsed_metadata.r#key.nspace, 0x4321);
        assert_eq!(
            tracker::lookup_key_descriptor_route(&parsed_metadata.r#key),
            Some(RouteTarget::Omk)
        );
        let carrier = unsafe {
            parcel::extract_key_entry_reply_carrier(data, data_size, offsets, offsets_size)
        }
        .expect("pure certificate entries should still contain the nullable binder field");
        assert!(
            !carrier.is_object,
            "pure certificate entries must not expose a security-level binder object"
        );
    }

    #[test]
    fn no_carrier_create_operation_reply_uses_synthetic_operation_mapping() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let omk_aborts = Arc::new(AtomicUsize::new(0));
        let caller = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");

        let omk_backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![9, 9, 9],
            aborts: omk_aborts.clone(),
            update_aad_status: None,
        });
        let mut rewritten = build_no_carrier_create_operation_reply(
            CreateOperationResponse {
                r#iOperation: Some(omk_backend),
                r#operationChallenge: None,
                r#parameters: None,
                r#upgradedBlob: Some(vec![7, 7]),
            },
            true,
            &caller,
        )
        .expect("no-carrier createOperation reply should serialize");

        let (rewritten_data, rewritten_data_size, rewritten_offsets, rewritten_offsets_size) =
            raw_parts(&mut rewritten);
        let carrier = unsafe {
            parcel::extract_create_operation_reply_carrier(
                rewritten_data,
                rewritten_data_size,
                rewritten_offsets,
                rewritten_offsets_size,
            )
        }
        .expect("synthetic operation carrier should parse");
        let target = unsafe { parse_local_binder_target_from_parcel_bytes(&carrier.bytes) }
            .expect("synthetic operation carrier should expose a native target");
        assert_eq!(
            lookup_synthetic_target(target),
            Some(SyntheticTargetKind::Operation)
        );
        let target_info =
            lookup_operation_target(target).expect("synthetic operation target should be tracked");
        assert_eq!(target_info.route, RouteTarget::Omk);
        assert!(target_info.aad_allowed);
        assert!(target_info.backend.is_some());
        let synthetic_info =
            lookup_synthetic_target_info(target).expect("synthetic target should be tracked");
        let synthetic_caller = synthetic_info
            .caller
            .as_ref()
            .expect("synthetic operation target should keep caller fallback");
        assert_eq!(synthetic_caller.sid, caller.sid);
        assert_eq!(synthetic_caller.uid, caller.uid);

        let update_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Update {
                input: vec![4, 5, 6],
            },
            method: OperationMethod::Update,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("synthetic update rewrite should succeed")
        .expect("synthetic update should return an OMK-owned reply");
        let mut update_reply = outbound_parcel(update_reply);
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
        .expect("synthetic update reply should deserialize");
        assert_eq!(update_output.as_deref(), Some(&[9, 9, 9][..]));

        let abort_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Abort,
            method: OperationMethod::Abort,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("synthetic abort rewrite should succeed")
        .expect("synthetic abort should return an OMK-owned reply");
        let mut abort_reply = outbound_parcel(abort_reply);
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
        .expect("synthetic abort reply should deserialize");
        assert!(abort_status.is_ok());
        assert_eq!(omk_aborts.load(Ordering::SeqCst), 1);
        assert!(
            lookup_operation_target(target).is_none(),
            "abort should clear the synthetic operation mapping"
        );
        assert!(
            lookup_synthetic_target(target) == Some(SyntheticTargetKind::Operation),
            "abort should keep the synthetic target so stale calls receive a native-style error"
        );

        let stale_update_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Update {
                input: b"after_abort".to_vec(),
            },
            method: OperationMethod::Update,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("stale synthetic update rewrite should succeed")
        .expect("stale synthetic update should return a native-style error");
        let mut stale_update_reply = outbound_parcel(stale_update_reply);
        let (stale_data, stale_data_size, stale_offsets, stale_offsets_size) =
            raw_parts(&mut stale_update_reply);
        let stale_status = unsafe {
            parcel::parse_reply_status(
                stale_data,
                stale_data_size,
                stale_offsets,
                stale_offsets_size,
            )
        }
        .expect("stale update reply should deserialize");
        assert_eq!(
            stale_status.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(
            stale_status.service_specific_error(),
            crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE.0
        );
    }

    #[test]
    fn synthetic_operation_release_aborts_once_and_clears_mapping() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let aborts = Arc::new(AtomicUsize::new(0));
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![9, 9, 9],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        let caller = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");
        let carrier = register_synthetic_operation_carrier(backend, true, &caller);
        let target = carrier_target(&carrier);

        assert!(lookup_operation_target(target).is_some());
        assert_eq!(
            lookup_synthetic_target(target),
            Some(SyntheticTargetKind::Operation)
        );

        assert!(handle_synthetic_ref_command(
            target,
            crate::hook::binder::BR_RELEASE_NR
        ));
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
        assert!(
            lookup_operation_target(target).is_none(),
            "release should clear the live operation mapping"
        );
        assert_eq!(
            lookup_synthetic_target(target),
            Some(SyntheticTargetKind::Operation),
            "release should keep the synthetic target for stale native-style errors"
        );

        assert!(handle_synthetic_ref_command(
            target,
            crate::hook::binder::BR_RELEASE_NR
        ));
        assert_eq!(
            aborts.load(Ordering::SeqCst),
            1,
            "repeated release must not abort twice"
        );
    }

    #[test]
    fn synthetic_security_level_release_keeps_cached_target() {
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let caller = CallerIdentity::new(10002, 2000).with_sid("u:r:untrusted_app:s0:c123,c456");
        let first = register_synthetic_security_level_carrier(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            ServiceMethod::GetSecurityLevel,
            &caller,
        );
        let target = carrier_target(&first);

        assert!(handle_synthetic_ref_command(
            target,
            crate::hook::binder::BR_RELEASE_NR
        ));
        assert_eq!(
            lookup_synthetic_target(target),
            Some(SyntheticTargetKind::SecurityLevel)
        );

        let second = register_synthetic_security_level_carrier(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            ServiceMethod::GetSecurityLevel,
            &caller,
        );
        assert_eq!(carrier_target(&second), target);
    }

    #[test]
    fn raw_create_operation_reply_still_does_not_register_operation_mapping() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let omk_operation = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![9, 9, 9],
            aborts: Arc::new(AtomicUsize::new(0)),
            update_aad_status: None,
        });
        let mut reply = parcel::build_create_operation_reply(CreateOperationResponse {
            r#iOperation: Some(omk_operation),
            r#operationChallenge: None,
            r#parameters: None,
            r#upgradedBlob: Some(vec![7, 7]),
        })
        .expect("direct OMK createOperation reply should serialize");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed: CreateOperationResponse =
            unsafe { parcel::parse_success_reply(data, data_size, offsets, offsets_size) }
                .expect("direct OMK createOperation reply should parse");

        assert!(parsed.r#iOperation.is_some());
        assert_eq!(parsed.r#upgradedBlob.as_deref(), Some(&[7, 7][..]));
        assert!(
            operation_targets()
                .lock()
                .expect("operation target map poisoned")
                .is_empty(),
            "direct OMK replies should not register a fake system carrier mapping"
        );
    }

    #[test]
    fn system_route_invalid_update_aad_preserves_native_reply() {
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

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
                finalized: false,
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
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

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
                finalized: false,
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
        let mut reply = outbound_parcel(reply);
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

    #[test]
    fn omk_route_operation_transaction_error_uses_omk_status_mapping() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![1, 2, 3],
            aborts: Arc::new(AtomicUsize::new(0)),
            update_aad_status: Some(StatusCode::UnknownTransaction.into()),
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: false,
                backend: Some(backend),
                finalized: false,
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
        .expect("transaction status should be normalized into a reply")
        .expect("OMK transaction status should return an OMK-owned reply");
        assert_outbound_status(reply, StatusCode::UnknownTransaction);
    }

    #[test]
    fn omk_route_finish_rejects_late_cleanup_abort() {
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let aborts = Arc::new(AtomicUsize::new(0));
        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![5, 6, 7],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: Some(backend),
                finalized: false,
            },
        );

        let reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Finish {
                input: Some(vec![1, 2, 3]),
                signature: None,
            },
            method: OperationMethod::Finish,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("finish rewrite should succeed")
        .expect("OMK finish should return an OMK-owned reply");
        let mut reply = outbound_parcel(reply);
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let output: Option<Vec<u8>> =
            unsafe { parcel::parse_success_reply(data, data_size, offsets, offsets_size) }
                .expect("finish reply should deserialize");

        assert_eq!(output.as_deref(), Some(&[5, 6, 7][..]));
        let target_info = lookup_operation_target(target)
            .expect("finish should keep a finalized cleanup tombstone");
        assert_eq!(target_info.route, RouteTarget::Omk);
        assert!(target_info.finalized);
        assert!(target_info.backend.is_none());

        let cleanup_reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Abort,
            method: OperationMethod::Abort,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("cleanup abort rewrite should succeed")
        .expect("cleanup abort should return an OMK-owned reply");
        let mut cleanup_reply = outbound_parcel(cleanup_reply);
        let (cleanup_data, cleanup_data_size, cleanup_offsets, cleanup_offsets_size) =
            raw_parts(&mut cleanup_reply);
        let cleanup_status = unsafe {
            parcel::parse_reply_status(
                cleanup_data,
                cleanup_data_size,
                cleanup_offsets,
                cleanup_offsets_size,
            )
        }
        .expect("cleanup abort reply should deserialize");

        assert_eq!(
            cleanup_status.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(
            cleanup_status.service_specific_error(),
            crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE.0
        );
        assert_eq!(
            aborts.load(Ordering::SeqCst),
            0,
            "finalized cleanup should not abort the already-finished backend again"
        );
        assert!(
            lookup_operation_target(target).is_none(),
            "cleanup abort should clear the finalized tombstone"
        );
    }

    #[test]
    fn omk_route_abort_clears_operation_mapping() {
        ensure_binder_process_state();
        let _guard = route_state_test_guard();
        clear_operation_state_for_tests();

        let aborts = Arc::new(AtomicUsize::new(0));
        let target = LocalBinderTarget {
            ptr: 0x1234,
            cookie: 0x5678,
        };
        let backend = BnKeystoreOperation::new_binder(TestOperationBackend {
            update_output: vec![5, 6, 7],
            aborts: aborts.clone(),
            update_aad_status: None,
        });
        remember_operation_target(
            target,
            OperationTargetInfo {
                route: RouteTarget::Omk,
                aad_allowed: true,
                backend: Some(backend),
                finalized: false,
            },
        );

        let reply = build_operation_reply_rewrite(&PendingOperationCall {
            request: ParsedOperationRequest::Abort,
            method: OperationMethod::Abort,
            caller: CallerIdentity::new(1000, 2000),
            packages: vec!["com.example".to_string()],
            target,
        })
        .expect("abort rewrite should succeed")
        .expect("OMK abort should return an OMK-owned reply");
        let mut reply = outbound_parcel(reply);
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("abort reply should deserialize");

        assert!(status.is_ok());
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
        assert!(
            lookup_operation_target(target).is_none(),
            "abort should clear the operation mapping"
        );
    }
}
