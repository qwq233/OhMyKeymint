use super::{
    flat_binder_object, parse_local_binder_target_from_parcel_bytes, LocalBinderTarget,
    BINDER_TYPE_BINDER, FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
};
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::hook::rewrite::native::{self, Endpoint, SecurityLevelEndpoint};
use crate::hook::rewrite::pending;
use crate::hook::BinderStateKey;
use binder::binder_impl::{Binder, BorrowedParcel, IBinderInternal, Remotable, Stability};
use binder::ext::LocalBinderReceiver;
use binder::unstable_api::AsNative;
use binder::{binder_fn_get_class, Interface, SpIBinder, StatusCode};
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem::size_of;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

struct NativeBinderData {
    endpoint: Option<Endpoint>,
    target: OnceLock<LocalBinderTarget>,
    binder: OnceLock<usize>,
}

impl NativeBinderData {
    fn transact(
        &self,
        code: u32,
        input: &BorrowedParcel<'_>,
        output: &mut BorrowedParcel<'_>,
    ) -> Result<(), StatusCode> {
        let binder = *self.binder.get().expect("published native identity");
        let input_ptr = binder::ext::callback_parcel_view(input, binder)?.data_ptr() as usize;
        let call =
            pending::claim_callback(*self.target.get().expect("published target"), input_ptr);
        native::dispatch(
            self.endpoint.as_ref().expect("published carrier has no endpoint"),
            code,
            input,
            output,
            binder,
            &call,
        )
    }

    fn dump_peer(&self) -> Option<SpIBinder> {
        match self.endpoint.as_ref()? {
            Endpoint::LevelRoute(endpoint) => {
                endpoint.dump_peer.get().cloned().or_else(|| endpoint.system_level().ok()?.ok())
            }
            Endpoint::Operation { .. } => None,
            endpoint => endpoint.original().with_binder(|binder| binder).ok(),
        }
    }
}

macro_rules! carrier {
    ($name:ident, $descriptor:path) => {
        struct $name(Arc<NativeBinderData>);
        impl $name {
            unsafe extern "C" fn dump(
                binder: *mut binder::unstable_api::AIBinder,
                fd: i32,
                args: *mut *const std::ffi::c_char,
                count: u32,
            ) -> i32 {
                // SAFETY: This callback is installed only for this carrier's class.
                unsafe {
                    binder::ext::dispatch_android13_dump::<Self>(
                        binder,
                        fd,
                        args,
                        count,
                        |carrier| carrier.0.dump_peer(),
                    )
                }
            }
        }
        impl Remotable for $name {
            fn get_descriptor() -> &'static str {
                $descriptor
            }
            fn on_transact(
                &self,
                code: u32,
                input: &BorrowedParcel<'_>,
                output: &mut BorrowedParcel<'_>,
            ) -> Result<(), StatusCode> {
                self.0.transact(code, input, output)
            }
            fn on_dump(
                &self,
                output: &mut dyn std::io::Write,
                args: &[&CStr],
            ) -> Result<(), StatusCode> {
                Interface::dump(&(), output, args)
            }
            fn on_shell_command(
                &self,
                input: &mut dyn std::io::Read,
                output: &mut dyn std::io::Write,
                error: &mut dyn std::io::Write,
                args: &[&CStr],
            ) -> Result<(), StatusCode> {
                Interface::shell_command(&(), input, output, error, args)
            }
            // SAFETY: The class callback matches this carrier's userdata.
            binder_fn_get_class!(binder::ext::dump_interface_class::<Self>(Self::dump));
        }
    };
}

carrier!(SecurityLevelCarrier, super::KEYSTORE_SECURITY_LEVEL_INTERFACE);
carrier!(OperationCarrier, super::KEYSTORE_OPERATION_INTERFACE);
carrier!(ServiceCarrier, super::KEYSTORE_SERVICE_INTERFACE);
carrier!(AuthorizationCarrier, super::KEYSTORE_AUTHORIZATION_INTERFACE);
carrier!(MaintenanceCarrier, super::KEYSTORE_MAINTENANCE_INTERFACE);

pub(crate) struct NativeBinder {
    binder: SpIBinder,
    data: Arc<NativeBinderData>,
    target: LocalBinderTarget,
}

impl NativeBinder {
    pub(crate) fn target(&self) -> LocalBinderTarget {
        self.target
    }
    pub(crate) fn as_binder(&self) -> SpIBinder {
        self.binder.clone()
    }

    #[cfg(test)]
    pub(in crate::hook) fn transact(
        &self,
        code: u32,
        input: binder::binder_impl::Parcel,
        flags: u32,
    ) -> Result<binder::binder_impl::Parcel, StatusCode> {
        let input_ptr = binder::ext::owned_parcel_view(&input)?.data_ptr() as usize;
        struct Local(u64);
        impl Drop for Local {
            fn drop(&mut self) {
                pending::discard_received_frame(self.0);
            }
        }
        let _local = Local(
            pending::push_received_frame(
                None,
                self.target,
                input_ptr,
                flags,
                Some(self.as_binder()),
            )
            .expect("test callback receipt TLS unavailable"),
        );
        self.binder.submit_transact(code, input, flags)
    }
}

pub(in crate::hook) fn is_published_carrier(binder: &SpIBinder) -> bool {
    Binder::<OperationCarrier>::try_from(binder.clone()).is_ok()
        || Binder::<SecurityLevelCarrier>::try_from(binder.clone()).is_ok()
        || Binder::<ServiceCarrier>::try_from(binder.clone()).is_ok()
        || Binder::<AuthorizationCarrier>::try_from(binder.clone()).is_ok()
        || Binder::<MaintenanceCarrier>::try_from(binder.clone()).is_ok()
}

fn create_native_binder<T: Remotable>(
    object: T,
    data: Arc<NativeBinderData>,
) -> Result<NativeBinder, StatusCode> {
    let mut object = Binder::new_with_stability(object, Stability::Vintf);
    object.set_requesting_sid(true);
    let binder = object.as_binder();
    data.binder.set(binder.as_native() as usize).expect("native identity initialized once");
    let mut parcel = binder::binder_impl::Parcel::new();
    parcel.write(&binder)?;
    let bytes = binder::ext::owned_parcel_view(&parcel)?.bytes;
    assert_eq!(bytes.len(), size_of::<flat_binder_object>() + size_of::<i32>());
    // SAFETY: Native serialization produced a complete flat Binder object above.
    let flat = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<flat_binder_object>()) };
    assert_eq!(flat.hdr.type_, BINDER_TYPE_BINDER);
    assert_ne!(flat.flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX, 0);
    // SAFETY: The Binder and native serialization are still owned here.
    let target = unsafe { parse_local_binder_target_from_parcel_bytes(bytes) }
        .expect("new native Binder has a local target");
    data.target.set(target).expect("native target initialized once");
    Ok(NativeBinder { binder, data, target })
}

pub(in crate::hook) fn create_receiver_binder(
    kind: SyntheticTargetKind,
    endpoint: Option<Endpoint>,
) -> Result<NativeBinder, StatusCode> {
    let data =
        Arc::new(NativeBinderData { endpoint, target: OnceLock::new(), binder: OnceLock::new() });
    match kind {
        SyntheticTargetKind::Operation => {
            create_native_binder(OperationCarrier(Arc::clone(&data)), data)
        }
        SyntheticTargetKind::Service => {
            create_native_binder(ServiceCarrier(Arc::clone(&data)), data)
        }
        SyntheticTargetKind::SecurityLevel => {
            create_native_binder(SecurityLevelCarrier(Arc::clone(&data)), data)
        }
        SyntheticTargetKind::Authorization => {
            create_native_binder(AuthorizationCarrier(Arc::clone(&data)), data)
        }
        SyntheticTargetKind::Maintenance => {
            create_native_binder(MaintenanceCarrier(Arc::clone(&data)), data)
        }
    }
}

pub(crate) fn create_native_security_level_binder(
    endpoint: Arc<SecurityLevelEndpoint>,
) -> Result<NativeBinder, StatusCode> {
    create_receiver_binder(SyntheticTargetKind::SecurityLevel, Some(Endpoint::LevelRoute(endpoint)))
}

type ReceiverCache = HashMap<(BinderStateKey, LocalBinderTarget), Arc<NativeBinder>>;
static RECEIVERS: LazyLock<Mutex<ReceiverCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::hook) fn init_request_binders() -> anyhow::Result<()> {
    binder::ext::init_native_apis()?;
    Ok(())
}

/// # Safety
/// target is retained by the incoming driver transaction throughout qualification.
pub(in crate::hook) unsafe fn receiver_proxy(
    connection: BinderStateKey,
    target: LocalBinderTarget,
) -> Option<(SpIBinder, LocalBinderTarget)> {
    if !crate::hook::intercept::is_native_binder_connection(connection) {
        return None;
    }
    if let Some(proxy) =
        RECEIVERS.lock().expect("receiver cache poisoned").get(&(connection, target)).cloned()
    {
        return Some((proxy.as_binder(), proxy.target()));
    }
    for (kind, descriptor) in [
        (SyntheticTargetKind::Service, super::KEYSTORE_SERVICE_INTERFACE),
        (SyntheticTargetKind::SecurityLevel, super::KEYSTORE_SECURITY_LEVEL_INTERFACE),
        (SyntheticTargetKind::Authorization, super::KEYSTORE_AUTHORIZATION_INTERFACE),
        (SyntheticTargetKind::Maintenance, super::KEYSTORE_MAINTENANCE_INTERFACE),
    ] {
        // SAFETY: The caller retains the actual incoming receiver.
        let original = match unsafe { local_binder_receiver(target, descriptor) } {
            Ok(Some(receiver)) => Arc::new(receiver),
            Ok(None) => continue,
            Err(error) => {
                panic!("Binder receiver qualification failed: target={target:?}: {error}")
            }
        };
        if original.with_binder(|binder| is_published_carrier(&binder)).unwrap_or_else(|error| {
            panic!("Binder receiver inspection failed: target={target:?}: {error}")
        }) {
            return None;
        }
        let endpoint = match kind {
            SyntheticTargetKind::Service => Endpoint::Service(original),
            SyntheticTargetKind::SecurityLevel => {
                let level = OnceLock::new();
                if let Some(known) = lookup_security_level_target(target) {
                    let _ = level.set(known);
                }
                Endpoint::SecurityLevel { original, level }
            }
            SyntheticTargetKind::Authorization => Endpoint::Authorization(original),
            SyntheticTargetKind::Maintenance => Endpoint::Maintenance(original),
            SyntheticTargetKind::Operation => unreachable!(),
        };
        let candidate =
            Arc::new(create_receiver_binder(kind, Some(endpoint)).unwrap_or_else(|error| {
                panic!("Binder receiver publication failed: target={target:?}: {error}")
            }));
        let proxy = {
            let mut cache = RECEIVERS.lock().expect("receiver cache poisoned");
            Arc::clone(cache.entry((connection, target)).or_insert_with(|| Arc::clone(&candidate)))
        };
        return Some((proxy.as_binder(), proxy.target()));
    }
    None
}

pub(in crate::hook) fn retire_receivers(connection: BinderStateKey) {
    let retired = {
        let mut cache = RECEIVERS.lock().expect("receiver cache poisoned");
        cache
            .extract_if(|(owner, _), _| *owner == connection)
            .map(|(_, binder)| binder)
            .collect::<Vec<_>>()
    };
    drop(retired);
}

/// # Safety
/// The target must retain the driver weak reference from its native BR_TRANSACTION.
pub(in crate::hook) unsafe fn local_binder_receiver(
    target: LocalBinderTarget,
    expected: &str,
) -> Result<Option<LocalBinderReceiver>, StatusCode> {
    unsafe {
        binder::ext::local_binder_receiver(target.ptr as usize, target.cookie as usize, expected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::hook) enum SyntheticTargetKind {
    Service,
    Operation,
    SecurityLevel,
    Authorization,
    Maintenance,
}

type SecurityLevelCache = HashMap<(usize, SecurityLevel), Arc<NativeBinder>>;
static LEVELS: LazyLock<Mutex<SecurityLevelCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::hook) fn register_synthetic_security_level_binder(
    level: SecurityLevel,
    system: Arc<binder::ext::LocalBinderReceiver>,
) -> Result<Arc<NativeBinder>, binder::StatusCode> {
    let key = (system.identity(), level);
    if let Some(native) = LEVELS.lock().expect("level cache poisoned").get(&key).cloned() {
        return Ok(native);
    }
    let candidate =
        Arc::new(create_native_security_level_binder(Arc::new(SecurityLevelEndpoint {
            level,
            system,
            dump_peer: Default::default(),
        }))?);
    let native = {
        let mut levels = LEVELS.lock().expect("level cache poisoned");
        Arc::clone(levels.entry(key).or_insert_with(|| Arc::clone(&candidate)))
    };
    Ok(native)
}

pub(in crate::hook) fn remember_system_dump_peer(
    identity: usize,
    level: SecurityLevel,
    peer: binder::SpIBinder,
) {
    let native = LEVELS.lock().expect("level cache poisoned").get(&(identity, level)).cloned();
    if let Some(native) = native {
        if let Some(Endpoint::LevelRoute(endpoint)) = &native.data.endpoint {
            let _ = endpoint.dump_peer.set(peer);
        }
    }
}

static SECURITY_LEVEL_TARGETS: LazyLock<Mutex<HashMap<LocalBinderTarget, SecurityLevel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::hook) fn remember_security_level_target(
    target: LocalBinderTarget,
    security_level: SecurityLevel,
) {
    SECURITY_LEVEL_TARGETS
        .lock()
        .expect("security level target map poisoned")
        .insert(target, security_level);
}

fn lookup_security_level_target(target: LocalBinderTarget) -> Option<SecurityLevel> {
    SECURITY_LEVEL_TARGETS.lock().expect("security level target map poisoned").get(&target).copied()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::MutexGuard;

    static STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(in crate::hook) fn state_test_guard() -> MutexGuard<'static, ()> {
        let guard = STATE_TEST_LOCK.lock().expect("tracker test lock poisoned");
        SECURITY_LEVEL_TARGETS.lock().expect("security level target map poisoned").clear();
        guard
    }

    #[test]
    fn published_identity_uses_exact_class_and_userdata() {
        let operation = create_receiver_binder(SyntheticTargetKind::Service, None).unwrap();
        let receiver = unsafe {
            local_binder_receiver(
                operation.target(),
                crate::hook::binder::KEYSTORE_SERVICE_INTERFACE,
            )
        }
        .unwrap()
        .unwrap();
        assert!(receiver.with_binder(|binder| is_published_carrier(&binder)).unwrap());
        let foreign = crate::hook::rewrite::tests::test_service_receiver();
        assert!(!foreign.with_binder(|binder| is_published_carrier(&binder)).unwrap());
    }

    #[test]
    fn receiving_interface_uses_native_descriptor_and_releases_promotions() {
        let native = create_receiver_binder(SyntheticTargetKind::SecurityLevel, None).unwrap();
        let mut binder = native.as_binder();
        let weak = binder.downgrade();
        let flags = binder::ext::last_transaction_flags().unwrap();
        let receiver = unsafe {
            local_binder_receiver(
                native.target(),
                crate::hook::binder::KEYSTORE_SECURITY_LEVEL_INTERFACE,
            )
        }
        .unwrap()
        .unwrap();
        assert!(unsafe {
            local_binder_receiver(
                native.target(),
                crate::hook::binder::KEYSTORE_MAINTENANCE_INTERFACE,
            )
        }
        .unwrap()
        .is_none());
        assert_eq!(binder::ext::last_transaction_flags().unwrap(), flags);
        let owner = receiver.with_binder(|owner| owner).unwrap();
        assert_eq!(owner, binder);
        drop(binder);
        drop(native);
        assert!(weak.promote().is_some());
        drop(receiver);
        assert!(weak.promote().is_some());
        drop(owner);
        assert!(weak.promote().is_none());
    }

    #[test]
    fn native_interface_check_consumes_header_and_restores_outgoing_context() {
        let native = create_receiver_binder(SyntheticTargetKind::SecurityLevel, None).unwrap();
        let binder = native.as_binder();
        let original = binder.prepare_transact().unwrap().clone();
        let baseline = binder::ext::parcel_bytes(&original).unwrap();
        let mut incoming = original.clone();
        let end = incoming.get_data_size();
        unsafe {
            incoming.set_data_position(0).unwrap();
        }
        incoming.write(&0x1234_i32).unwrap();
        incoming.write(&12345_i32).unwrap();
        unsafe {
            incoming.set_data_position(end).unwrap();
        }
        incoming.write(&77_i32).unwrap();
        unsafe {
            incoming.set_data_position(0).unwrap();
        }
        binder::ext::enforce_interface(
            &incoming,
            crate::hook::binder::KEYSTORE_SECURITY_LEVEL_INTERFACE,
        )
        .unwrap();
        assert_eq!(incoming.read::<i32>().unwrap(), 77);
        let after = binder.prepare_transact().unwrap().clone();
        assert_eq!(binder::ext::parcel_bytes(&after).unwrap(), baseline);
    }

    #[test]
    fn native_dispatch_error_preserves_status_and_device_cleans_partial_objects() {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
        static FREE_TARGET: AtomicUsize = AtomicUsize::new(0);
        static FREE_LEN: AtomicUsize = AtomicUsize::new(0);
        static FREE_STATE: AtomicU8 = AtomicU8::new(0);
        static ORIGINAL_FREE: omhook::OriginalPointerCell = omhook::OriginalPointerCell::new();
        // Keep the test observer resident rather than unhooking amid background Binder frees.
        static FREE_HOOK: OnceLock<omhook::PltHookHandle> = OnceLock::new();
        unsafe extern "C" fn observe_free(pointer: *mut std::ffi::c_void) {
            let target = FREE_TARGET.load(Ordering::Acquire);
            if target != 0
                && target == pointer as usize
                && FREE_TARGET
                    .compare_exchange(target, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let len = FREE_LEN.load(Ordering::Relaxed);
                // SAFETY: This exact live native payload is being passed to free; inspect it before release.
                let zeroed = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) }
                    .iter()
                    .all(|byte| *byte == 0);
                FREE_STATE.store(if zeroed { 2 } else { 1 }, Ordering::Release);
            }
            // SAFETY: The installer publishes the actual non-null C free pointer before replacing its slot.
            let original: unsafe extern "C" fn(*mut std::ffi::c_void) = unsafe {
                std::mem::transmute(ORIGINAL_FREE.get().expect("published free original"))
            };
            // SAFETY: Forward the original allocation exactly once, after observing it while still live.
            unsafe { original(pointer) };
        }
        struct Disarm;
        impl Drop for Disarm {
            fn drop(&mut self) {
                FREE_TARGET.store(0, Ordering::Release);
            }
        }
        struct PartialReplyCarrier {
            data: Arc<NativeBinderData>,
            sdk: Binder<crate::android::system::keystore2::IKeystoreService::BnKeystoreService>,
            weak: Arc<std::sync::Mutex<Option<binder::WpIBinder>>>,
            write_end: Arc<std::sync::Mutex<Option<std::os::fd::OwnedFd>>>,
            receiver: Option<binder::ext::LocalBinderReceiver>,
        }

        impl Remotable for PartialReplyCarrier {
            fn get_descriptor() -> &'static str {
                ServiceCarrier::get_descriptor()
            }

            fn on_transact(
                &self,
                code: u32,
                input: &BorrowedParcel<'_>,
                output: &mut BorrowedParcel<'_>,
            ) -> Result<(), StatusCode> {
                let binder = *self.data.binder.get().ok_or(StatusCode::INVALID_OPERATION)?;
                binder::ext::callback_parcel_view(input, binder)?;
                binder::ext::callback_parcel_view(output, binder)?;
                if let Some(receiver) = &self.receiver {
                    output.mark_sensitive();
                    let position = input.get_data_position();
                    let result = receiver.transact_callback_into(input, output, binder, code, 0);
                    assert_eq!(input.get_data_position(), position);
                    return result;
                }
                let object = Binder::new(());
                let mut strong = object.as_binder();
                let weak = strong.downgrade();
                *self.weak.lock().unwrap() = Some(weak);
                output.write(&binder::Status::ok())?;
                output.write(&strong)?;
                let (read_end, write_end) = nix::unistd::pipe().unwrap();
                *self.write_end.lock().unwrap() = Some(write_end);
                output.write(&binder::ParcelFileDescriptor::new(std::fs::File::from(read_end)))?;
                drop(strong);
                drop(object);
                let result = if code
                    == crate::android::system::keystore2::IKeystoreService::transactions::getSecurityLevel {
                    Ok(())
                } else {
                    self.sdk.on_transact(code, input, output)
                };
                let view = binder::ext::callback_parcel_view(output, binder)?;
                assert!(!view.bytes.is_empty() && view.bytes.iter().any(|byte| *byte != 0));
                FREE_LEN.store(view.bytes.len(), Ordering::Relaxed);
                FREE_STATE.store(0, Ordering::Relaxed);
                FREE_TARGET.store(view.data_ptr() as usize, Ordering::Release);
                result
            }

            fn on_dump(
                &self,
                file: &mut dyn std::io::Write,
                args: &[&CStr],
            ) -> Result<(), StatusCode> {
                self.sdk.on_dump(file, args)
            }

            fn on_shell_command(
                &self,
                stdin: &mut dyn std::io::Read,
                stdout: &mut dyn std::io::Write,
                stderr: &mut dyn std::io::Write,
                args: &[&CStr],
            ) -> Result<(), StatusCode> {
                self.sdk.on_shell_command(stdin, stdout, stderr, args)
            }

            binder_fn_get_class!(Binder<Self>);
        }

        let _guard = state_test_guard();
        FREE_HOOK.get_or_init(|| {
            let maps = omhook::read_self_maps().unwrap();
            let library = maps
                .iter()
                .find(|map| {
                    map.path.as_deref().is_some_and(|path| {
                        path.file_name() == Some(std::ffi::OsStr::new("libbinder.so"))
                    })
                })
                .unwrap();
            let library = omhook::ElfImageSelector::new(library.device, library.inode).unwrap();
            let request = omhook::PltHookRequest::new(&library, c"free", observe_free as *const ())
                .unwrap()
                .require_non_null_previous()
                .with_original_pointer_cell(&ORIGINAL_FREE);
            // SAFETY: The loaded system Binder and static observer stay live for this test process;
            // no loader transition or other test replaces this slot. Other frees simply call the original.
            unsafe { omhook::install_hook(request) }.unwrap()
        });
        fn data() -> Arc<NativeBinderData> {
            Arc::new(NativeBinderData {
                endpoint: None,
                target: OnceLock::new(),
                binder: OnceLock::new(),
            })
        }
        fn sdk() -> Binder<crate::android::system::keystore2::IKeystoreService::BnKeystoreService> {
            crate::android::system::keystore2::IKeystoreService::BnKeystoreService::new_binder(
                crate::hook::rewrite::tests::TestService {
                    level: None,
                    calls: Arc::new(AtomicUsize::new(0)),
                },
                binder::BinderFeatures::default(),
            )
            .as_binder()
            .try_into()
            .unwrap()
        }
        let original_data = data();
        let weak = Arc::new(std::sync::Mutex::new(None));
        let write_end = Arc::new(std::sync::Mutex::new(None));
        let native = create_native_binder(
            PartialReplyCarrier {
                data: Arc::clone(&original_data),
                sdk: sdk(),
                weak: Arc::clone(&weak),
                write_end: Arc::clone(&write_end),
                receiver: None,
            },
            original_data,
        )
        .unwrap();
        let receiver = unsafe {
            local_binder_receiver(native.target(), crate::hook::binder::KEYSTORE_SERVICE_INTERFACE)
        }
        .unwrap()
        .unwrap();
        let original_data = data();
        let forwarded = create_native_binder(
            PartialReplyCarrier {
                data: Arc::clone(&original_data),
                sdk: sdk(),
                weak: Arc::clone(&weak),
                write_end: Arc::clone(&write_end),
                receiver: Some(receiver),
            },
            original_data,
        )
        .unwrap();
        for (index, target) in [native.as_binder(), forwarded.as_binder()].into_iter().enumerate() {
            for success in [false, true] {
                for flags in [0, binder::binder_impl::FLAG_CLEAR_BUF] {
                    let disarm = Disarm;
                    FREE_STATE.store(0, Ordering::Relaxed);
                    let code = if success {
                        crate::android::system::keystore2::IKeystoreService::transactions::getSecurityLevel
                    } else {
                        crate::android::system::keystore2::IKeystoreService::transactions::getKeyEntry
                    };
                    let result =
                        target.submit_transact(code, target.prepare_transact().unwrap(), flags);
                    let error = match result {
                        Ok(reply) => {
                            assert!(reply.read::<binder::Status>().unwrap().is_ok());
                            let object = reply.read::<binder::SpIBinder>().unwrap();
                            let received = reply.read::<binder::ParcelFileDescriptor>().unwrap();
                            assert!(
                                unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } >= 0
                            );
                            drop((reply, object, received));
                            None
                        }
                        Err(error) => Some(error),
                    };
                    let observed = FREE_STATE.load(Ordering::Acquire);
                    drop(disarm);
                    assert_eq!(
                        error,
                        if success { None } else { Some(StatusCode::NOT_ENOUGH_DATA) }
                    );
                    assert!(weak.lock().unwrap().as_ref().unwrap().promote().is_none());
                    let writer = write_end.lock().unwrap().take().unwrap();
                    let mut readiness =
                        libc::pollfd { fd: writer.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
                    // SAFETY: The write end remains owned; zero timeout only reads this pipe's readiness.
                    assert_eq!(unsafe { libc::poll(&mut readiness, 1, 0) }, 1);
                    assert_ne!(
                        readiness.revents & libc::POLLERR,
                        0,
                        "all native read-end copies must be closed"
                    );
                    assert_eq!(
                        observed,
                        if index == 1 || flags != 0 { 2 } else { 1 },
                        "free must observe the final native payload before release"
                    );
                }
            }
        }
    }
}
