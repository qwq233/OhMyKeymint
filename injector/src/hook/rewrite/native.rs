use super::pending::ReceivedCall;
#[cfg(test)]
use super::tests as rpc;
use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::security::authorization::IKeystoreAuthorization::transport as auth_codec;
use crate::android::system::keystore2::IKeystoreOperation::BnKeystoreOperation;
use crate::android::system::keystore2::{
    IKeystoreSecurityLevel::{transactions as level_codes, transport as level_codec},
    IKeystoreService::{
        transactions as service_codes, transport as service_codec, IKeystoreService,
        ParsedServiceRequest,
    },
    KeyEntryResponse::KeyEntryResponse,
};
use crate::config::InterceptConfig;
use crate::hook::binder::{self as hook_binder, SyntheticTargetKind, TF_ONE_WAY};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::{config, ipc};
use binder::binder_impl::{BorrowedParcel, IBinderInternal, Parcel};
use binder::ext::LocalBinderReceiver;
use binder::{FromIBinder, SpIBinder, Status, StatusCode, Strong, ThreadState};
#[cfg(not(test))]
use kmr_common::rpc;
use std::sync::{Arc, OnceLock};

fn framework_api_level() -> i32 {
    #[cfg(test)]
    if let Some(api) = FRAMEWORK_API_OVERRIDE.with_borrow(|api| *api) {
        return api;
    }
    binder::ext::api_level()
}

#[cfg(test)]
thread_local! {
    static FRAMEWORK_API_OVERRIDE: std::cell::RefCell<Option<i32>> = std::cell::RefCell::default();
}

pub(crate) struct SecurityLevelEndpoint {
    pub(in crate::hook) level: SecurityLevel,
    pub(in crate::hook) system: Arc<LocalBinderReceiver>,
    pub(in crate::hook) dump_peer: OnceLock<SpIBinder>,
}

impl SecurityLevelEndpoint {
    pub(in crate::hook) fn system_level(&self) -> Result<binder::Result<SpIBinder>, StatusCode> {
        self.system.with_binder(|binder| {
            let service: Strong<dyn IKeystoreService> = FromIBinder::try_from(binder)?;
            let level = service.getSecurityLevel(self.level)?.as_binder();
            if binder::ext::api_level() == 33 {
                let _ = self.dump_peer.set(level.clone());
            }
            Ok(level)
        })
    }
}

pub(in crate::hook) enum Endpoint {
    Service(Arc<LocalBinderReceiver>),
    SecurityLevel { level: OnceLock<SecurityLevel>, original: Arc<LocalBinderReceiver> },
    LevelRoute(Arc<SecurityLevelEndpoint>),
    Operation { epoch: u64, binder: Arc<BnKeystoreOperation>, system: Arc<LocalBinderReceiver> },
    Authorization(Arc<LocalBinderReceiver>),
    Maintenance(Arc<LocalBinderReceiver>),
}
impl Endpoint {
    pub(in crate::hook) fn original(&self) -> &Arc<LocalBinderReceiver> {
        match self {
            Self::Service(receiver)
            | Self::Authorization(receiver)
            | Self::Maintenance(receiver)
            | Self::SecurityLevel { original: receiver, .. } => receiver,
            Self::LevelRoute(endpoint) => &endpoint.system,
            Self::Operation { .. } => unreachable!("operations have no System route"),
        }
    }

    fn backend(&self) -> binder::Result<rpc::Backend<'_>> {
        Ok(match self {
            Self::Service(_) => rpc::Backend::Keystore,
            Self::Authorization(_) => rpc::Backend::Authorization,
            Self::Maintenance(_) => rpc::Backend::Maintenance,
            Self::LevelRoute(endpoint) => rpc::Backend::SecurityLevel(endpoint.level),
            Self::Operation { epoch, binder, .. } => {
                rpc::Backend::Operation { epoch: *epoch, binder }
            }
            Self::SecurityLevel { level, original } => {
                if level.get().is_none() {
                    let found = binder::ext::with_preserved_thread_state(
                        || -> binder::Result<_> {
                            let _guard = crate::forward::BypassGuard::enter();
                            let service: Strong<dyn IKeystoreService> = binder::check_interface(
                                "android.system.keystore2.IKeystoreService/default",
                            )?;
                            let mut failure = None;
                            for candidate in
                                [SecurityLevel::TRUSTED_ENVIRONMENT, SecurityLevel::STRONGBOX]
                            {
                                let binder = match service.getSecurityLevel(candidate) {
                                    Ok(binder) => binder,
                                    Err(error)
                                        if error.exception_code()
                                            == binder::ExceptionCode::SERVICE_SPECIFIC
                                            && error.service_specific_error()
                                                == ErrorCode::HARDWARE_TYPE_UNAVAILABLE.0 =>
                                    {
                                        continue
                                    }
                                    Err(error) => {
                                        failure.get_or_insert(error);
                                        continue;
                                    }
                                };
                                if original
                                    .with_binder(|original| original == binder.as_binder())?
                                {
                                    return Ok(candidate);
                                }
                            }
                            if let Some(error) = failure {
                                return Err(error);
                            }
                            panic!("qualified System security-level identity was not found: receiver={:#x}", original.identity())
                        },
                    )??;
                    let _ = level.set(found);
                }
                rpc::Backend::SecurityLevel(*level.get().expect("qualified System level"))
            }
        })
    }
}

pub(in crate::hook) fn init() -> anyhow::Result<()> {
    hook_binder::init_request_binders()?;
    #[cfg(not(test))]
    rpc::start()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Forward(bool),
    Mirror,
}

fn action(endpoint: &Endpoint, code: u32, intercept: &InterceptConfig) -> Option<Action> {
    let enabled = match endpoint {
        Endpoint::Service(_) => {
            service_codec::rpc_transaction(code)?;
            match code {
                service_codes::getSecurityLevel => intercept.get_security_level,
                service_codes::getKeyEntry => intercept.get_key_entry,
                service_codes::updateSubcomponent => intercept.update_subcomponent,
                service_codes::listEntries => intercept.list_entries,
                service_codes::deleteKey => intercept.delete_key,
                service_codes::grant => intercept.grant,
                service_codes::ungrant => intercept.ungrant,
                service_codes::getNumberOfEntries if framework_api_level() >= 34 => {
                    intercept.get_number_of_entries
                }
                service_codes::listEntriesBatched if framework_api_level() >= 34 => {
                    intercept.list_entries_batched
                }
                service_codes::getSupplementaryAttestationInfo if framework_api_level() >= 36 => {
                    intercept.get_supplementary_attestation_info
                }
                _ => return None,
            }
        }
        Endpoint::SecurityLevel { .. } | Endpoint::LevelRoute(_) => {
            level_codec::rpc_transaction(code)?;
            if !matches!(
                code,
                level_codes::createOperation
                    | level_codes::generateKey
                    | level_codes::importKey
                    | level_codes::importWrappedKey
                    | level_codes::convertStorageKeyToEphemeral
                    | level_codes::deleteKey
            ) {
                return None;
            }
            intercept.get_security_level || intercept.get_key_entry
        }
        Endpoint::Authorization(_) => {
            if !(framework_api_level() <= 34 && code == 2) {
                let public = kmr_common::rpc::authorization_code(framework_api_level(), code)?;
                auth_codec::rpc_transaction(public)?;
            }
            let mirrored = match framework_api_level() {
                33 | 34 => matches!(code, 1 | 2),
                35 | 36 => matches!(code, 1..=5),
                _ => matches!(code, 1..=6),
            };
            return mirrored.then_some(Action::Mirror);
        }
        Endpoint::Maintenance(_) => {
            kmr_common::rpc::maintenance_code(framework_api_level(), code)?;
            let (migrate, mirrored) = match framework_api_level() {
                33 | 34 => (8, matches!(code, 1..=4 | 6 | 9)),
                35 => (8, matches!(code, 1..=7 | 9)),
                _ => (7, matches!(code, 1..=6 | 8)),
            };
            return if code == migrate {
                Some(Action::Forward(true))
            } else {
                mirrored.then_some(Action::Mirror)
            };
        }
        Endpoint::Operation { .. } => unreachable!("operation ownership is fixed at creation"),
    };
    Some(Action::Forward(enabled))
}

fn native_caller() -> CallerInfo {
    let uid = ThreadState::get_calling_uid();
    CallerInfo {
        uid: if uid == u32::MAX { 0 } else { i64::from(uid) },
        pid: i64::from(ThreadState::get_calling_pid()),
        sid: ThreadState::with_calling_sid(|sid| sid.map(|sid| sid.to_string_lossy().into_owned()))
            .unwrap_or_default(),
    }
}

pub(in crate::hook) fn dispatch(
    endpoint: &Endpoint,
    code: u32,
    input: &BorrowedParcel<'_>,
    output: &mut BorrowedParcel<'_>,
    binder: usize,
    call: &ReceivedCall,
) -> Result<(), StatusCode> {
    let flags = call.flags;
    if let Endpoint::Operation { system, .. } = endpoint {
        use crate::android::system::keystore2::IKeystoreOperation::transactions;
        if matches!(code, transactions::getInterfaceHash | transactions::getInterfaceVersion) {
            let reply = system.with_binder(|binder| {
                binder.submit_transact(code, binder.prepare_transact()?, 0)
            })??;
            return if flags & TF_ONE_WAY == 0 { output.append_all_from(&reply) } else { Ok(()) };
        }
        if !matches!(
            code,
            transactions::updateAad
                | transactions::update
                | transactions::finish
                | transactions::abort
        ) {
            // SAFETY: The callback and its receipt retain this exact local receiver.
            let receiver = unsafe {
                hook_binder::local_binder_receiver(
                    call.target,
                    hook_binder::KEYSTORE_OPERATION_INTERFACE,
                )?
            }
            .expect("live operation carrier lost its native receiver");
            return receiver.default_callback(input, output, binder, code, flags);
        }
        let caller = native_caller();
        return forward(endpoint, code, input, output, call, &caller).map(|_| ());
    }
    let cfg = config::get();
    if !rpc::may_intercept() || !cfg.main.enabled || crate::forward::is_bypassed() {
        return dispatch_system(endpoint, code, flags, input, output, binder);
    }
    let Some(action) = action(endpoint, code, &cfg.intercept) else {
        if let Endpoint::LevelRoute(endpoint) = endpoint {
            if matches!(code, service_codes::getInterfaceVersion | service_codes::getInterfaceHash)
            {
                let reply = endpoint.system.with_binder(|binder| {
                    binder.submit_transact(code, binder.prepare_transact()?, flags)
                })??;
                return if flags & TF_ONE_WAY == 0 {
                    output.append_all_from(&reply)
                } else {
                    Ok(())
                };
            }
            return endpoint.system.default_callback(input, output, binder, code, flags);
        }
        return dispatch_system(endpoint, code, flags, input, output, binder);
    };
    if action == Action::Forward(false) {
        return dispatch_system(endpoint, code, flags, input, output, binder);
    }
    let caller = native_caller();
    let decision = binder::ext::with_preserved_thread_state(|| {
        super::evaluate_caller_with(&caller, &cfg, ipc::resolve_packages_for_caller_in_callback)
    })?;
    if action != Action::Mirror && decision.allowed() && !rpc::wait_until_ready() {
        return dispatch_system(endpoint, code, flags, input, output, binder);
    }
    log::info!(
        "event=route code=0x{code:x} uid={} pid={} backend={}",
        caller.uid,
        caller.pid,
        if decision.allowed() { "Omk" } else { "System" }
    );
    if action == Action::Mirror {
        let system = endpoint.original().transact_callback(input, binder, code, flags)?;
        system.status?;
        if system.parcel.read::<Status>().is_ok_and(|status| status.is_ok())
            && rpc::wait_until_ready()
        {
            let mut mirrored = Parcel::new();
            let result = forward(endpoint, code, input, &mut mirrored.borrowed(), call, &caller);
            if decision.allowed() {
                if result? && flags & TF_ONE_WAY == 0 {
                    let status =
                        binder::ext::with_parcel_position(mirrored.borrowed_ref(), 0, || {
                            mirrored.read::<Status>()
                        })??;
                    if !status.is_ok() {
                        return output.append_all_from(&mirrored);
                    }
                }
            } else if let Err(error) = result {
                log::warn!("event=mirror private backend failed: {error}");
            }
        }
        return if flags & TF_ONE_WAY == 0 {
            output.append_all_from(&system.parcel)
        } else {
            Ok(())
        };
    }
    if !decision.allowed() {
        return dispatch_system(endpoint, code, flags, input, output, binder);
    }
    if forward(endpoint, code, input, output, call, &caller)? {
        Ok(())
    } else {
        dispatch_system(endpoint, code, flags, input, output, binder)
    }
}

fn forward(
    endpoint: &Endpoint,
    code: u32,
    input: &BorrowedParcel<'_>,
    output: &mut BorrowedParcel<'_>,
    call: &ReceivedCall,
    caller: &CallerInfo,
) -> Result<bool, StatusCode> {
    let mut discard = Parcel::new();
    let mut destination =
        if call.flags & TF_ONE_WAY == 0 { output.reborrow() } else { discard.borrowed() };
    let result: binder::Result<_> = kmr_common::android_version::with_framework_parcel(
        framework_api_level(),
        || {
            binder::ext::with_preserved_thread_state(|| {
                rpc::dispatch(
                    endpoint.backend()?,
                    caller,
                    (code, call.flags),
                    input,
                    &mut destination,
                    |level| {
                        let Endpoint::Service(system) = endpoint else {
                            panic!("security-level publication outside service dispatch: code={code:#x}");
                        };
                        Ok(hook_binder::register_synthetic_security_level_binder(
                            level,
                            Arc::clone(system),
                        )?
                        .as_binder())
                    },
                    |epoch, remote| {
                        Ok(hook_binder::create_receiver_binder(
                            SyntheticTargetKind::Operation,
                            Some(Endpoint::Operation {
                                epoch,
                                binder: remote,
                                system: Arc::clone(endpoint.original()),
                            }),
                        )?
                        .as_binder())
                    },
                )
            })?
        },
    );
    match result {
        Ok(Some(())) => Ok(true),
        Ok(None) => Ok(false),
        Err(status) => destination.write(&status).map(|()| true),
    }
}

fn dispatch_system(
    endpoint: &Endpoint,
    code: u32,
    flags: u32,
    input: &BorrowedParcel<'_>,
    output: &mut BorrowedParcel<'_>,
    binder: usize,
) -> Result<(), StatusCode> {
    let receiver;
    let original = if let Endpoint::LevelRoute(endpoint) = endpoint {
        let level = match endpoint.system_level()? {
            Ok(level) => level,
            Err(status) => {
                return if flags & TF_ONE_WAY == 0 { output.write(&status) } else { Ok(()) }
            }
        };
        let mut carrier = Parcel::new();
        carrier.write(&level)?;
        // SAFETY: The native serialization retains the exact local System Binder.
        let target = unsafe {
            hook_binder::parse_local_binder_target_from_parcel_bytes(
                binder::ext::owned_parcel_view(&carrier)?.bytes,
            )
        }
        .expect("System returned a non-local security-level Binder");
        // SAFETY: The level and its native serialization retain this receiver during promotion.
        receiver = unsafe {
            hook_binder::local_binder_receiver(
                target,
                hook_binder::KEYSTORE_SECURITY_LEVEL_INTERFACE,
            )?
        }
        .expect("owned System security-level Binder lost its native receiver");
        &receiver
    } else {
        endpoint.original()
    };
    if flags & TF_ONE_WAY != 0 {
        return original.transact_callback(input, binder, code, flags)?.status;
    }
    original.transact_callback_into(input, output, binder, code, flags)?;
    if matches!(endpoint, Endpoint::Service(_)) {
        observe(|| observe_system_reply(input, output, code, original.identity()));
    }
    Ok(())
}

fn observe(invoke: impl FnOnce() -> anyhow::Result<()>) {
    if let Err(error) = invoke() {
        log::warn!("System reply observation failed: {error:#}");
    }
}

fn observe_system_reply(
    input: &BorrowedParcel<'_>,
    output: &BorrowedParcel<'_>,
    code: u32,
    system_identity: usize,
) -> anyhow::Result<()> {
    if !matches!(code, service_codes::getSecurityLevel | service_codes::getKeyEntry) {
        return Ok(());
    }
    binder::ext::with_preserved_thread_state(|| {
        binder::ext::with_parcel_position(output, 0, || -> anyhow::Result<()> {
            let status: Status = output.read()?;
            if !status.is_ok() {
                return Ok(());
            }
            let (binder, level) = if code == service_codes::getSecurityLevel {
                let request =
                    binder::ext::with_parcel_position(input, input.get_data_position(), || {
                        service_codec::read_request(code, input)
                    })??;
                let ParsedServiceRequest::GetSecurityLevel { security_level } = request else {
                    anyhow::bail!("SDK request kind mismatch");
                };
                (output.read::<Option<SpIBinder>>()?, security_level)
            } else {
                let entry: KeyEntryResponse = output.read()?;
                (
                    entry.iSecurityLevel.map(|level| level.as_binder()),
                    entry.metadata.keySecurityLevel,
                )
            };
            let Some(binder) = binder else { return Ok(()) };
            let mut carrier = Parcel::new();
            carrier.write(&binder)?;
            // SAFETY: Native serialization retains this local Binder for the entire observation.
            let target = unsafe {
                hook_binder::parse_local_binder_target_from_parcel_bytes(
                    binder::ext::owned_parcel_view(&carrier)?.bytes,
                )
            }
            .ok_or_else(|| anyhow::anyhow!("System security level is not local"))?;
            hook_binder::remember_security_level_target(target, level);
            if binder::ext::api_level() == 33 {
                hook_binder::remember_system_dump_peer(system_identity, level, binder);
            }
            Ok(())
        })?
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::system::keystore2::IKeystoreService::BnKeystoreService;
    use crate::android::system::keystore2::{
        CreateOperationResponse::CreateOperationResponse, ResponseCode::ResponseCode,
    };
    use crate::android::system::keystore2::{Domain::Domain, KeyDescriptor::KeyDescriptor};
    use crate::forward;
    use crate::hook::binder::{create_native_security_level_binder, create_receiver_binder};
    use crate::hook::rewrite::tests::{retained_receiver, TestService};
    use binder::binder_impl::{Binder, Remotable};
    use binder::{binder_fn_get_class, Interface};
    use std::ffi::CStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn forwarded(service: Binder<BnKeystoreService>, dead: bool) -> rpc::TestBackend {
        Arc::new(move |_, (code, _), input| {
            let mut reply = Parcel::new();
            let status =
                binder::ext::with_parcel_position(input, input.get_data_position(), || {
                    service.on_transact(code, input, &mut reply.borrowed())
                })?;
            // SAFETY: The complete SDK response is owned by this call.
            unsafe { reply.set_data_position(0)? };
            Ok(rpc::TestReply {
                status: if dead { Err(StatusCode::DEAD_OBJECT) } else { status },
                values: reply,
            })
        })
    }

    fn error_reply(calls: Arc<AtomicUsize>, native: bool) -> rpc::TestBackend {
        Arc::new(move |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut values = Parcel::new();
            values.write(&Status::new_service_specific_error(77, None))?;
            // SAFETY: The complete response is owned.
            unsafe { values.set_data_position(0)? };
            Ok(rpc::TestReply {
                status: if native { Err(StatusCode::NOT_ENOUGH_DATA) } else { Ok(()) },
                values,
            })
        })
    }

    #[test]
    fn service_requests_use_only_the_selected_backend() {
        super::init().unwrap();
        for mode in 0..5 {
            let system_calls = Arc::new(AtomicUsize::new(0));
            let omk_calls = Arc::new(AtomicUsize::new(0));
            let baseline = BnKeystoreService::new_binder(
                TestService { level: None, calls: Arc::clone(&system_calls) },
                binder::BinderFeatures::default(),
            );
            let proxy = create_receiver_binder(
                SyntheticTargetKind::Service,
                Some(Endpoint::Service(retained_receiver(
                    &baseline.as_binder(),
                    hook_binder::KEYSTORE_SERVICE_INTERFACE,
                ))),
            )
            .unwrap();
            let binder = proxy.as_binder();
            let backend = forwarded(
                BnKeystoreService::new_binder(
                    TestService { level: None, calls: Arc::clone(&omk_calls) },
                    binder::BinderFeatures::default(),
                )
                .as_binder()
                .try_into()
                .unwrap(),
                false,
            );
            let mut cfg = config::InjectorConfig::default();
            cfg.main.enabled = mode != 0;
            cfg.filter.enabled = false;
            cfg.intercept.get_key_entry = mode != 2;
            cfg.intercept.delete_key = mode != 3;
            config::with_test_config(cfg, || {
                rpc::with_test_backend((mode != 4).then_some(backend), || {
                    for domain in [Domain::APP, Domain::KEY_ID, Domain::GRANT] {
                        for code in [service_codes::getKeyEntry, service_codes::deleteKey] {
                            let mut request = binder.prepare_transact().unwrap();
                            request
                                .write(&KeyDescriptor {
                                    domain,
                                    nspace: 42,
                                    alias: Some("unchanged".into()),
                                    blob: None,
                                })
                                .unwrap();
                            let reply = proxy.transact(code, request, 0).unwrap();
                            assert_eq!(
                                reply.read::<Status>().unwrap().service_specific_error(),
                                17
                            );
                        }
                    }
                    assert_eq!(system_calls.load(Ordering::SeqCst), [6, 0, 3, 3, 6][mode]);
                    assert_eq!(omk_calls.load(Ordering::SeqCst), [0, 6, 3, 3, 0][mode]);
                })
            });
        }
    }

    #[test]
    fn first_generate_key_uses_the_ready_omk_session() {
        use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
        use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
        let system_calls = Arc::new(AtomicUsize::new(0));
        let service = BnKeystoreService::new_binder(
            TestService { level: None, calls: Arc::clone(&system_calls) },
            binder::BinderFeatures::default(),
        );
        let level = create_native_security_level_binder(Arc::new(SecurityLevelEndpoint {
            system: retained_receiver(
                &service.as_binder(),
                hook_binder::KEYSTORE_SERVICE_INTERFACE,
            ),
            level: SecurityLevel::TRUSTED_ENVIRONMENT,
            dump_peer: Default::default(),
        }))
        .unwrap();
        let omk_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&omk_calls);
        let backend: rpc::TestBackend = Arc::new(move |_, (code, _), _| {
            assert_eq!(code, level_codes::generateKey);
            calls.fetch_add(1, Ordering::SeqCst);
            let mut values = Parcel::new();
            values.write(&Status::ok())?;
            values.write(&KeyMetadata::default())?;
            Ok(rpc::TestReply { status: Ok(()), values })
        });
        let mut cfg = config::InjectorConfig::default();
        cfg.filter.enabled = false;
        config::with_test_config(cfg, || {
            rpc::with_test_backend(backend, || {
                let mut request = level.as_binder().prepare_transact().unwrap();
                request.write(&rpc::sample_key_descriptor()).unwrap();
                request.write(&Option::<KeyDescriptor>::None).unwrap();
                request.write(&Vec::<KeyParameter>::new()).unwrap();
                request.write(&0_i32).unwrap();
                request.write(&Vec::<u8>::new()).unwrap();
                let reply = level.transact(level_codes::generateKey, request, 0).unwrap();
                assert!(reply.read::<Status>().unwrap().is_ok());
                assert_eq!(omk_calls.load(Ordering::SeqCst), 1);
                assert_eq!(system_calls.load(Ordering::SeqCst), 0);
            });
        });
    }

    #[test]
    fn scooped_get_security_level_returns_the_omk_reply_without_calling_system() {
        super::init().unwrap();
        let system_calls = Arc::new(AtomicUsize::new(0));
        let service = BnKeystoreService::new_binder(
            TestService { level: None, calls: Arc::clone(&system_calls) },
            binder::BinderFeatures::default(),
        );
        let system =
            retained_receiver(&service.as_binder(), hook_binder::KEYSTORE_SERVICE_INTERFACE);
        let level = create_native_security_level_binder(Arc::new(SecurityLevelEndpoint {
            system: Arc::clone(&system),
            level: SecurityLevel::TRUSTED_ENVIRONMENT,
            dump_peer: Default::default(),
        }))
        .unwrap();
        let proxy =
            create_receiver_binder(SyntheticTargetKind::Service, Some(Endpoint::Service(system)))
                .unwrap();
        let mut cfg = config::InjectorConfig::default();
        cfg.filter.enabled = false;
        config::with_test_config(cfg, || {
            for success in [true, false] {
                let omk_calls = Arc::new(AtomicUsize::new(0));
                let backend = forwarded(
                    BnKeystoreService::new_binder(
                        TestService {
                            level: success
                                .then(|| FromIBinder::try_from(level.as_binder()).unwrap()),
                            calls: Arc::clone(&omk_calls),
                        },
                        binder::BinderFeatures::default(),
                    )
                    .as_binder()
                    .try_into()
                    .unwrap(),
                    false,
                );
                rpc::with_test_backend(backend, || {
                    let mut request = proxy.as_binder().prepare_transact().unwrap();
                    request.write(&SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
                    let reply =
                        proxy.transact(service_codes::getSecurityLevel, request, 0).unwrap();
                    let status: Status = reply.read().unwrap();
                    if success {
                        assert!(status.is_ok());
                        assert_eq!(reply.read::<SpIBinder>().unwrap(), level.as_binder());
                    } else {
                        assert_eq!(status.service_specific_error(), 17);
                    }
                    assert_eq!(omk_calls.load(Ordering::SeqCst), 1);
                    assert_eq!(system_calls.load(Ordering::SeqCst), 0);
                });
            }
        });
    }

    #[test]
    fn lifecycle_rules_use_each_release_transaction_constants() {
        let receiver = crate::hook::rewrite::tests::test_service_receiver();
        let auth = Endpoint::Authorization(Arc::clone(&receiver));
        let maintenance = Endpoint::Maintenance(receiver);
        for api in 33..=37 {
            FRAMEWORK_API_OVERRIDE.replace(Some(api));
            let cfg = InterceptConfig::default();
            assert_eq!(action(&auth, 3, &cfg), if api <= 34 { None } else { Some(Action::Mirror) });
            assert_eq!(action(&auth, 8, &cfg), None);
            assert_eq!(
                action(&maintenance, if api <= 35 { 8 } else { 7 }, &cfg),
                Some(Action::Forward(true))
            );
            assert_eq!(action(&maintenance, service_codes::getInterfaceVersion, &cfg), None);
        }
        FRAMEWORK_API_OVERRIDE.replace(None);
    }

    #[test]
    fn service_intercepts_select_only_their_own_sdk_transaction() {
        let endpoint = Endpoint::Service(crate::hook::rewrite::tests::test_service_receiver());
        type DisableIntercept = fn(&mut InterceptConfig);
        let switches: [(u32, DisableIntercept); 10] = [
            (service_codes::getSecurityLevel, |cfg| cfg.get_security_level = false),
            (service_codes::getKeyEntry, |cfg| cfg.get_key_entry = false),
            (service_codes::updateSubcomponent, |cfg| cfg.update_subcomponent = false),
            (service_codes::listEntries, |cfg| cfg.list_entries = false),
            (service_codes::deleteKey, |cfg| cfg.delete_key = false),
            (service_codes::grant, |cfg| cfg.grant = false),
            (service_codes::ungrant, |cfg| cfg.ungrant = false),
            (service_codes::getNumberOfEntries, |cfg| cfg.get_number_of_entries = false),
            (service_codes::listEntriesBatched, |cfg| cfg.list_entries_batched = false),
            (service_codes::getSupplementaryAttestationInfo, |cfg| {
                cfg.get_supplementary_attestation_info = false
            }),
        ];
        FRAMEWORK_API_OVERRIDE.replace(Some(37));
        for (disabled, disable) in switches {
            let mut cfg = InterceptConfig::default();
            disable(&mut cfg);
            for (code, _) in switches {
                assert_eq!(action(&endpoint, code, &cfg), Some(Action::Forward(code != disabled)));
            }
        }
        FRAMEWORK_API_OVERRIDE.replace(None);
    }
    struct RawSystemAuthorization {
        calls: Arc<AtomicUsize>,
        native_error: bool,
        success: bool,
    }
    impl Remotable for RawSystemAuthorization {
        fn get_descriptor() -> &'static str {
            hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE
        }
        fn on_transact(
            &self,
            code: u32,
            _: &BorrowedParcel<'_>,
            output: &mut BorrowedParcel<'_>,
        ) -> Result<(), StatusCode> {
            if code != 1 && code != 2 {
                return Err(StatusCode::UNKNOWN_TRANSACTION);
            }
            if forward::is_bypassed() {
                return Err(StatusCode::INVALID_OPERATION);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.native_error {
                return Err(StatusCode::BAD_VALUE);
            }
            output.write(&if self.success {
                Status::ok()
            } else {
                Status::new_service_specific_error(17, None)
            })?;
            output.write(&12345_i64)
        }
        fn on_dump(&self, _: &mut dyn std::io::Write, _: &[&CStr]) -> Result<(), StatusCode> {
            Ok(())
        }
        fn on_shell_command(
            &self,
            _: &mut dyn std::io::Read,
            _: &mut dyn std::io::Write,
            _: &mut dyn std::io::Write,
            _: &[&CStr],
        ) -> Result<(), StatusCode> {
            Ok(())
        }
        binder_fn_get_class!(Binder<Self>);
    }

    #[test]
    fn mirror_preserves_system_native_errors_and_complete_reply() {
        super::init().unwrap();
        for native_error in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let source = Binder::new(RawSystemAuthorization {
                calls: Arc::clone(&calls),
                native_error,
                success: false,
            })
            .as_binder();
            let receiver =
                retained_receiver(&source, hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE);
            let native = create_receiver_binder(
                SyntheticTargetKind::Authorization,
                Some(Endpoint::Authorization(receiver)),
            )
            .unwrap();
            let binder = native.as_binder();
            let result = native.transact(1, binder.prepare_transact().unwrap(), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if native_error {
                assert_eq!(result.err(), Some(StatusCode::BAD_VALUE));
            } else {
                let reply = result.unwrap();
                assert_eq!(reply.read::<Status>().unwrap().service_specific_error(), 17);
                assert_eq!(reply.read::<i64>().unwrap(), 12345);
                assert_eq!(reply.get_data_position(), reply.get_data_size());
            }
        }
    }

    #[test]
    fn rejected_legacy_event_never_reaches_omk() {
        super::init().unwrap();
        for api in [33, 34] {
            FRAMEWORK_API_OVERRIDE.replace(Some(api));
            let calls = Arc::new(AtomicUsize::new(0));
            let source = Binder::new(RawSystemAuthorization {
                calls: Arc::clone(&calls),
                native_error: false,
                success: false,
            })
            .as_binder();
            let receiver =
                retained_receiver(&source, hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE);
            let proxy = create_receiver_binder(
                SyntheticTargetKind::Authorization,
                Some(Endpoint::Authorization(receiver)),
            )
            .unwrap();
            let mut request = proxy.as_binder().prepare_transact().unwrap();
            request.write(&9_i32).unwrap();
            request.write(&12_i32).unwrap();
            request.write(&Option::<Vec<u8>>::None).unwrap();
            request.write(&Option::<Vec<i64>>::None).unwrap();
            let mut cfg = config::InjectorConfig::default();
            cfg.filter.enabled = false;
            let reject: rpc::TestBackend =
                Arc::new(|_, _, _| panic!("System-rejected legacy event reached OMK"));
            config::with_test_config(cfg, || {
                rpc::with_test_backend(reject, || {
                    let reply = proxy.transact(2, request, 0).unwrap();
                    assert_eq!(reply.read::<Status>().unwrap().service_specific_error(), 17);
                    assert_eq!(reply.read::<i64>().unwrap(), 12345);
                });
            });
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        FRAMEWORK_API_OVERRIDE.replace(None);
    }

    struct RpcErrorReply {
        calls: Arc<AtomicUsize>,
    }
    impl Remotable for RpcErrorReply {
        fn get_descriptor() -> &'static str {
            hook_binder::KEYSTORE_OPERATION_INTERFACE
        }
        fn on_transact(
            &self,
            _: u32,
            input: &BorrowedParcel<'_>,
            output: &mut BorrowedParcel<'_>,
        ) -> Result<(), StatusCode> {
            let _ = input;
            self.calls.fetch_add(1, Ordering::SeqCst);
            output.write(&Status::new_service_specific_error(77, None))
        }
        fn on_dump(&self, _: &mut dyn std::io::Write, _: &[&CStr]) -> Result<(), StatusCode> {
            Ok(())
        }
        fn on_shell_command(
            &self,
            _: &mut dyn std::io::Read,
            _: &mut dyn std::io::Write,
            _: &mut dyn std::io::Write,
            _: &[&CStr],
        ) -> Result<(), StatusCode> {
            Ok(())
        }
        binder_fn_get_class!(Binder<Self>);
    }

    #[derive(Default)]
    struct MirroredCalls {
        system: std::sync::Mutex<Vec<Vec<u8>>>,
        omk: std::sync::Mutex<Vec<MirroredCall>>,
    }
    type MirroredCall = (CallerInfo, u32, u32, Vec<u8>);
    macro_rules! system_mirror_spy {
        ($name:ident, $descriptor:path) => {
            struct $name(Arc<MirroredCalls>);
            impl Remotable for $name {
                fn get_descriptor() -> &'static str {
                    $descriptor
                }
                fn on_transact(
                    &self,
                    _: u32,
                    input: &BorrowedParcel<'_>,
                    output: &mut BorrowedParcel<'_>,
                ) -> Result<(), StatusCode> {
                    let mut copy = Parcel::new();
                    copy.append_all_from(input)?;
                    self.0.system.lock().unwrap().push(binder::ext::parcel_bytes(&copy)?);
                    output.write(&Status::ok())
                }
                fn on_dump(
                    &self,
                    _: &mut dyn std::io::Write,
                    _: &[&CStr],
                ) -> Result<(), StatusCode> {
                    Ok(())
                }
                fn on_shell_command(
                    &self,
                    _: &mut dyn std::io::Read,
                    _: &mut dyn std::io::Write,
                    _: &mut dyn std::io::Write,
                    _: &[&CStr],
                ) -> Result<(), StatusCode> {
                    Ok(())
                }
                binder_fn_get_class!(Binder<Self>);
            }
        };
    }
    system_mirror_spy!(SystemAuthorizationSpy, hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE);
    system_mirror_spy!(SystemMaintenanceSpy, hook_binder::KEYSTORE_MAINTENANCE_INTERFACE);
    fn mirror_spy(calls: Arc<MirroredCalls>, failure: bool) -> rpc::TestBackend {
        Arc::new(move |caller, (code, flags), input| {
            let mut snapshot = Parcel::new();
            snapshot.append_all_from(input)?;
            calls.omk.lock().unwrap().push((
                caller.clone(),
                code,
                flags,
                binder::ext::parcel_bytes(&snapshot)?,
            ));
            let mut values = Parcel::new();
            values.write(&if failure {
                Status::new_service_specific_error(17, None)
            } else {
                Status::ok()
            })?;
            // SAFETY: The complete response is owned.
            unsafe { values.set_data_position(0)? };
            Ok(rpc::TestReply { status: Ok(()), values })
        })
    }

    #[test]
    fn lifecycle_mirror_preserves_caller_flags_and_complete_payload() {
        use crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;
        for case in 0..3 {
            let authorization = case == 0;
            let migration = case == 2;
            for flags in [0, TF_ONE_WAY] {
                let calls = Arc::new(MirroredCalls::default());
                let (source, kind, descriptor) = if authorization {
                    (
                        Binder::new(SystemAuthorizationSpy(Arc::clone(&calls))).as_binder(),
                        SyntheticTargetKind::Authorization,
                        hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE,
                    )
                } else {
                    (
                        Binder::new(SystemMaintenanceSpy(Arc::clone(&calls))).as_binder(),
                        SyntheticTargetKind::Maintenance,
                        hook_binder::KEYSTORE_MAINTENANCE_INTERFACE,
                    )
                };
                let receiver = retained_receiver(&source, descriptor);
                let endpoint = if authorization {
                    Endpoint::Authorization(receiver)
                } else {
                    Endpoint::Maintenance(receiver)
                };
                let proxy = create_receiver_binder(kind, Some(endpoint)).unwrap();
                let mut request = proxy.as_binder().prepare_transact().unwrap();
                let code = if authorization {
                    request
                        .write(&HardwareAuthToken {
                            challenge: 37,
                            userId: 41,
                            authenticatorId: 43,
                            mac: vec![0x53; 32],
                            ..Default::default()
                        })
                        .unwrap();
                    1
                } else if migration {
                    for alias in ["source", "destination"] {
                        request
                            .write(&KeyDescriptor {
                                domain: Domain::APP,
                                nspace: -1,
                                alias: Some(alias.into()),
                                blob: None,
                            })
                            .unwrap();
                    }
                    if framework_api_level() <= 35 {
                        8
                    } else {
                        7
                    }
                } else {
                    request.write(&10_i32).unwrap();
                    if framework_api_level() <= 34 {
                        2
                    } else {
                        3
                    }
                };
                let bytes = binder::ext::parcel_bytes(&request).unwrap();
                let expected = native_caller();
                let mut cfg = config::InjectorConfig::default();
                cfg.filter.enabled = false;
                config::with_test_config(cfg, || {
                    rpc::with_test_backend(mirror_spy(Arc::clone(&calls), migration), || {
                        let reply = proxy.transact(code, request, flags).unwrap();
                        if flags == 0 {
                            let status: Status = reply.read().unwrap();
                            if migration {
                                assert_eq!(status.service_specific_error(), 17);
                            } else {
                                assert!(status.is_ok());
                            }
                        } else {
                            assert_eq!(reply.get_data_size(), 0);
                        }
                    })
                });
                assert_eq!(
                    *calls.system.lock().unwrap(),
                    if migration { Vec::new() } else { vec![bytes.clone()] }
                );
                let omk = calls.omk.lock().unwrap();
                assert_eq!(omk.len(), 1);
                let (caller, actual_code, actual_flags, actual_bytes) = &omk[0];
                assert_eq!(
                    (caller.uid, caller.pid, &caller.sid),
                    (expected.uid, expected.pid, &expected.sid)
                );
                assert_eq!((*actual_code, *actual_flags, actual_bytes), (code, flags, &bytes));
            }
        }
    }

    #[test]
    fn mirror_calls_system_once_and_keeps_the_frozen_error_policy() {
        for (allowed, ready, native_error, system_success) in [
            (true, true, false, false),
            (true, true, false, true),
            (true, true, true, true),
            (true, false, false, true),
            (false, true, false, true),
            (false, true, true, true),
        ] {
            let system_calls = Arc::new(AtomicUsize::new(0));
            let omk_calls = Arc::new(AtomicUsize::new(0));
            let system = Binder::new(RawSystemAuthorization {
                calls: Arc::clone(&system_calls),
                native_error: false,
                success: system_success,
            })
            .as_binder();
            let proxy = create_receiver_binder(
                SyntheticTargetKind::Authorization,
                Some(Endpoint::Authorization(retained_receiver(
                    &system,
                    hook_binder::KEYSTORE_AUTHORIZATION_INTERFACE,
                ))),
            )
            .unwrap();
            let mut cfg = config::InjectorConfig::default();
            cfg.filter.enabled = !allowed;
            config::with_test_config(cfg, || {
                rpc::with_test_backend(
                    ready.then(|| error_reply(Arc::clone(&omk_calls), native_error)),
                    || {
                        let result =
                            proxy.transact(1, proxy.as_binder().prepare_transact().unwrap(), 0);
                        assert_eq!(system_calls.load(Ordering::SeqCst), 1);
                        assert_eq!(
                            omk_calls.load(Ordering::SeqCst),
                            usize::from(ready && system_success)
                        );
                        if ready && allowed && system_success && native_error {
                            assert_eq!(result.err(), Some(StatusCode::NOT_ENOUGH_DATA));
                        } else {
                            let reply = result.unwrap();
                            let status: Status = reply.read().unwrap();
                            if !system_success {
                                assert_eq!(status.service_specific_error(), 17);
                            } else if ready && allowed {
                                assert_eq!(status.service_specific_error(), 77);
                            } else {
                                assert!(status.is_ok());
                            }
                            if !system_success || !allowed || !ready {
                                assert_eq!(reply.read::<i64>().unwrap(), 12345);
                            }
                        }
                        assert!(rpc::may_intercept());
                    },
                );
            });
        }
    }

    #[test]
    fn retirement_before_submit_does_not_repeat_system_or_reassign_operations() {
        let calls = Arc::new(AtomicUsize::new(0));
        let system = BnKeystoreService::new_binder(
            TestService { level: None, calls: Arc::clone(&calls) },
            binder::BinderFeatures::default(),
        );
        let proxy = create_receiver_binder(
            SyntheticTargetKind::Service,
            Some(Endpoint::Service(retained_receiver(
                &system.as_binder(),
                hook_binder::KEYSTORE_SERVICE_INTERFACE,
            ))),
        )
        .unwrap();
        let mut cfg = config::InjectorConfig::default();
        cfg.filter.enabled = false;
        config::with_test_config(cfg, || {
            rpc::with_test_backend(None, || {
                for flags in [0, TF_ONE_WAY] {
                    let before = calls.load(Ordering::SeqCst);
                    let mut request = proxy.as_binder().prepare_transact().unwrap();
                    request.write(&SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
                    let reply =
                        proxy.transact(service_codes::getSecurityLevel, request, flags).unwrap();
                    assert_eq!(calls.load(Ordering::SeqCst), before + 1);
                    if flags == 0 {
                        assert_eq!(reply.read::<Status>().unwrap().service_specific_error(), 17);
                    } else {
                        assert_eq!(reply.get_data_size(), 0);
                    }
                }
                let operation_calls = Arc::new(AtomicUsize::new(0));
                let path =
                    std::env::temp_dir().join(format!("omk-operation-{}.sock", std::process::id()));
                let server = binder::ext::rpc::RpcServer::setup_unix_server(&path).unwrap();
                let original =
                    Binder::new(RpcErrorReply { calls: Arc::clone(&operation_calls) }).as_binder();
                server.add_service("operation", original).unwrap();
                server.start().unwrap();
                let session = binder::ext::rpc::RpcSession::connect(&path, 1, 0).unwrap();
                let remote = session.get_interface::<dyn crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation>("operation").unwrap();
                let original = kmr_common::rpc::operation_proxy(&remote).unwrap();
                let operation = create_receiver_binder(
                    SyntheticTargetKind::Operation,
                    Some(Endpoint::Operation {
                        epoch: 1,
                        binder: original,
                        system: retained_receiver(
                            &system.as_binder(),
                            hook_binder::KEYSTORE_SERVICE_INTERFACE,
                        ),
                    }),
                )
                .unwrap();
                let code =
                    crate::android::system::keystore2::IKeystoreOperation::transactions::abort;
                let reply = operation
                    .transact(code, operation.as_binder().prepare_transact().unwrap(), 0)
                    .unwrap();
                assert_eq!(reply.read::<Status>().unwrap().service_specific_error(), 77);
                assert_eq!(operation_calls.load(Ordering::SeqCst), 1);
                drop(operation);
                session.shutdown().unwrap();
                server.shutdown().unwrap();
                std::fs::remove_file(path).unwrap();
            });
            let before = calls.load(Ordering::SeqCst);
            let omk_calls = Arc::new(AtomicUsize::new(0));
            let backend = forwarded(
                BnKeystoreService::new_binder(
                    TestService { level: None, calls: Arc::clone(&omk_calls) },
                    binder::BinderFeatures::default(),
                )
                .as_binder()
                .try_into()
                .unwrap(),
                true,
            );
            rpc::with_test_backend(backend, || {
                let mut request = proxy.as_binder().prepare_transact().unwrap();
                request.write(&crate::hook::rewrite::tests::sample_key_descriptor()).unwrap();
                assert_eq!(
                    proxy.transact(service_codes::deleteKey, request, 0).err(),
                    Some(StatusCode::DEAD_OBJECT),
                );
                assert_eq!(omk_calls.load(Ordering::SeqCst), 1);
                assert_eq!(calls.load(Ordering::SeqCst), before);
            });
        });
    }

    #[test]
    fn cached_level_routes_to_system_without_inventing_policy_errors() {
        use super::{SecurityLevel, SecurityLevelEndpoint};
        use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
        use crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec;
        use crate::android::system::keystore2::EphemeralStorageKeyResponse::EphemeralStorageKeyResponse;
        use crate::android::system::keystore2::IKeystoreSecurityLevel::{
            transactions, BnKeystoreSecurityLevel, IKeystoreSecurityLevel,
        };
        use crate::android::system::keystore2::IKeystoreService::BnKeystoreService;
        use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
        use crate::hook::rewrite::tests::{retained_receiver, sample_key_descriptor, TestService};
        struct Level(Arc<AtomicUsize>);
        impl Interface for Level {}
        impl IKeystoreSecurityLevel for Level {
            fn createOperation(
                &self,
                _: &KeyDescriptor,
                _: &[KeyParameter],
                _: bool,
            ) -> binder::Result<CreateOperationResponse> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(Status::new_service_specific_error(ResponseCode::KEY_NOT_FOUND.0, None))
            }
            fn generateKey(
                &self,
                _: &KeyDescriptor,
                _: Option<&KeyDescriptor>,
                _: &[KeyParameter],
                _: i32,
                _: &[u8],
            ) -> binder::Result<KeyMetadata> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importKey(
                &self,
                _: &KeyDescriptor,
                _: Option<&KeyDescriptor>,
                _: &[KeyParameter],
                _: i32,
                _: &[u8],
            ) -> binder::Result<KeyMetadata> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importWrappedKey(
                &self,
                _: &KeyDescriptor,
                _: &KeyDescriptor,
                _: Option<&[u8]>,
                _: &[KeyParameter],
                _: &[AuthenticatorSpec],
            ) -> binder::Result<KeyMetadata> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn convertStorageKeyToEphemeral(
                &self,
                _: &KeyDescriptor,
            ) -> binder::Result<EphemeralStorageKeyResponse> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn deleteKey(&self, key: &KeyDescriptor) -> binder::Result<()> {
                assert_eq!(key.alias.as_deref(), Some("alias"));
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(Status::new_service_specific_error(19, None))
            }
        }
        let _guard = hook_binder::state_test_guard();
        super::init().unwrap();
        for mode in 0..3 {
            let calls = Arc::new(AtomicUsize::new(0));
            let lookups = Arc::new(AtomicUsize::new(0));
            let level = BnKeystoreSecurityLevel::new_binder(
                Level(Arc::clone(&calls)),
                binder::BinderFeatures::default(),
            );
            let service = BnKeystoreService::new_binder(
                TestService { level: Some(level.clone()), calls: Arc::clone(&lookups) },
                binder::BinderFeatures::default(),
            );
            let endpoint = Arc::new(SecurityLevelEndpoint {
                level: SecurityLevel::TRUSTED_ENVIRONMENT,
                system: retained_receiver(
                    &service.as_binder(),
                    hook_binder::KEYSTORE_SERVICE_INTERFACE,
                ),
                dump_peer: Default::default(),
            });
            let mut cfg = config::InjectorConfig::default();
            match mode {
                0 => cfg.main.enabled = false,
                1 => {
                    cfg.intercept.get_security_level = false;
                    cfg.intercept.get_key_entry = false;
                }
                _ => {}
            }
            config::with_test_config(cfg, || {
                let native = create_native_security_level_binder(Arc::clone(&endpoint)).unwrap();
                let mut binder = native.as_binder();
                if mode == 0 && binder::ext::api_level() == 33 {
                    let fd = std::fs::File::open("/dev/null").unwrap();
                    for _ in 0..2 {
                        binder.dump(&fd, &["--test"]).unwrap();
                        assert_eq!(lookups.load(Ordering::SeqCst), 1);
                        assert_eq!(endpoint.dump_peer.get(), Some(&level.as_binder()));
                    }
                }
                let before = lookups.load(Ordering::SeqCst);
                let mut request = binder.prepare_transact().unwrap();
                request.write(&sample_key_descriptor()).unwrap();
                let result = native.transact(transactions::deleteKey, request, 0).unwrap();
                assert_eq!(result.read::<Status>().unwrap().service_specific_error(), 19);
                assert_eq!(lookups.load(Ordering::SeqCst), before + 1);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let baseline = service
                    .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
                    .unwrap()
                    .as_binder();
                let mut original = baseline.prepare_transact().unwrap();
                original.write(&sample_key_descriptor()).unwrap();
                let original =
                    baseline.submit_transact(transactions::deleteKey, original, 0).unwrap();
                assert_eq!(result.marshal(), original.marshal());
                if mode == 0 {
                    use crate::android::hardware::security::keymint::Tag::Tag;
                    for (api, tag) in [(33, 14), (37, 15)] {
                        FRAMEWORK_API_OVERRIDE.replace(Some(api));
                        let mut replies = Vec::new();
                        for target in [baseline.clone(), binder.clone()] {
                            let before = calls.load(Ordering::SeqCst);
                            let mut input = target.prepare_transact().unwrap();
                            input.write(&sample_key_descriptor()).unwrap();
                            input.write(&1_i32).unwrap();
                            input.write(&1_i32).unwrap();
                            input
                                .sized_write(|parcel| {
                                    parcel.write(&Tag::ML_DSA_VARIANT)?;
                                    parcel.write(&1_i32)?;
                                    parcel.write(&tag)?;
                                    if tag == 14 {
                                        parcel.write(&vec![1_u8])?;
                                    } else {
                                        parcel.write(&1_i32)?;
                                    }
                                    Ok(())
                                })
                                .unwrap();
                            input.write(&false).unwrap();
                            let reply =
                                kmr_common::android_version::with_framework_parcel(api, || {
                                    if target == binder {
                                        native.transact(transactions::createOperation, input, 0)
                                    } else {
                                        target.submit_transact(
                                            transactions::createOperation,
                                            input,
                                            0,
                                        )
                                    }
                                })
                                .unwrap();
                            assert_eq!(calls.load(Ordering::SeqCst) - before, 1);
                            replies.push(reply.marshal());
                        }
                        assert_eq!(replies[0], replies[1]);
                    }
                    FRAMEWORK_API_OVERRIDE.replace(None);
                }
            });
        }
    }
}
