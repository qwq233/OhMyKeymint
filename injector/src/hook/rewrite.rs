use crate::config;
use crate::filter::{self, FilterDecision, PackageResolution};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;

pub(super) use pending::{clear_binder_fd_thread_state, discard_received_frame};

pub(in crate::hook) mod native;
pub(in crate::hook) mod pending;

fn evaluate_caller_with(
    caller: &CallerInfo,
    cfg: &config::InjectorConfig,
    resolve: impl FnOnce(&CallerInfo) -> (u32, PackageResolution),
) -> FilterDecision {
    let preflight =
        filter::evaluate(&cfg.scoop, &cfg.filter, caller.uid as u32, &PackageResolution::Unknown);
    if matches!(preflight, FilterDecision::RejectedAndroidPackage | FilterDecision::Disabled) {
        return preflight;
    }
    let (uid, packages) = resolve(caller);
    let decision = filter::evaluate(&cfg.scoop, &cfg.filter, uid, &packages);
    log::debug!("event=route identity uid={} pid={} package_uid={uid} packages={packages:?} decision={decision:?}", caller.uid, caller.pid);
    decision
}

#[cfg(test)]
pub(in crate::hook) mod tests {
    use crate::android::hardware::security::keymint::{SecurityLevel::SecurityLevel, Tag::Tag};
    use crate::android::system::keystore2::IKeystoreOperation::BnKeystoreOperation;
    use crate::android::system::keystore2::{
        Domain::Domain,
        IKeystoreSecurityLevel::IKeystoreSecurityLevel,
        IKeystoreService::{BnKeystoreService, IKeystoreService},
        KeyDescriptor::KeyDescriptor,
        KeyEntryResponse::KeyEntryResponse,
    };
    use crate::hook::binder as hook_binder;
    use crate::hook::binder::parse_local_binder_target_from_parcel_bytes;
    use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
    use binder::binder_impl::{BorrowedParcel, Parcel};
    use binder::{Interface, SpIBinder, Status, StatusCode, Strong};
    pub use kmr_common::rpc::Backend;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    pub(in crate::hook) fn retained_receiver(
        binder: &SpIBinder,
        descriptor: &str,
    ) -> Arc<binder::ext::LocalBinderReceiver> {
        let mut parcel = binder::binder_impl::Parcel::new();
        parcel.write(binder).unwrap();
        // SAFETY: parcel and binder retain the matching local object throughout promotion.
        let target = unsafe {
            parse_local_binder_target_from_parcel_bytes(
                &binder::ext::parcel_bytes(&parcel).unwrap(),
            )
        }
        .unwrap();
        Arc::new(
            unsafe {
                binder::ext::local_binder_receiver(
                    target.ptr as usize,
                    target.cookie as usize,
                    descriptor,
                )
            }
            .unwrap()
            .unwrap(),
        )
    }

    pub(in crate::hook) struct TestService {
        pub(in crate::hook) level: Option<Strong<dyn IKeystoreSecurityLevel>>,
        pub(in crate::hook) calls: Arc<AtomicUsize>,
    }
    impl Interface for TestService {}
    impl IKeystoreService for TestService {
        fn getSecurityLevel(
            &self,
            _: SecurityLevel,
        ) -> binder::Result<Strong<dyn IKeystoreSecurityLevel>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.level.clone().ok_or_else(|| Status::new_service_specific_error(17, None))
        }
        fn getKeyEntry(&self, _: &KeyDescriptor) -> binder::Result<KeyEntryResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(Status::new_service_specific_error(17, None))
        }
        fn updateSubcomponent(
            &self,
            _: &KeyDescriptor,
            _: Option<&[u8]>,
            _: Option<&[u8]>,
        ) -> binder::Result<()> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn listEntries(&self, _: Domain, _: i64) -> binder::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn deleteKey(&self, _: &KeyDescriptor) -> binder::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(Status::new_service_specific_error(17, None))
        }
        fn grant(&self, _: &KeyDescriptor, _: i32, _: i32) -> binder::Result<KeyDescriptor> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn ungrant(&self, _: &KeyDescriptor, _: i32) -> binder::Result<()> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn getNumberOfEntries(&self, _: Domain, _: i64) -> binder::Result<i32> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn listEntriesBatched(
            &self,
            _: Domain,
            _: i64,
            _: Option<&str>,
        ) -> binder::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
        fn getSupplementaryAttestationInfo(&self, _: Tag) -> binder::Result<Vec<u8>> {
            Err(StatusCode::UNKNOWN_TRANSACTION.into())
        }
    }

    pub(in crate::hook) fn test_service_receiver() -> Arc<binder::ext::LocalBinderReceiver> {
        let service = BnKeystoreService::new_binder(
            TestService { level: None, calls: Arc::new(AtomicUsize::new(0)) },
            binder::BinderFeatures::default(),
        );
        retained_receiver(&service.as_binder(), hook_binder::KEYSTORE_SERVICE_INTERFACE)
    }

    pub(super) fn sample_key_descriptor() -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: 7,
            alias: Some("alias".to_string()),
            blob: None,
        }
    }

    #[test]
    fn application_owner_controls_scope_without_changing_caller() {
        use super::*;
        let caller = CallerInfo { uid: 99_001, pid: 2000, sid: "isolated".into() };
        let cfg = config::InjectorConfig {
            scoop: vec!["com.example.scooped".into()],
            filter: config::FilterConfig {
                deny_packages: vec!["com.example.denied".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        for (owner, packages, expected) in [
            (10_123, vec!["com.example.scooped"], FilterDecision::Allowed),
            (10_124, vec!["com.example.other"], FilterDecision::RejectedNotInScope),
            (
                10_123,
                vec!["com.example.scooped", "com.example.denied"],
                FilterDecision::RejectedByDenylist,
            ),
            (1000, vec!["com.example.scooped"], FilterDecision::RejectedAndroidPackage),
            (10_123, vec!["android"], FilterDecision::RejectedAndroidPackage),
        ] {
            let actual = evaluate_caller_with(&caller, &cfg, |actual| {
                assert!(std::ptr::eq(actual, &caller));
                (owner, PackageResolution::Known(packages.into_iter().map(str::to_owned).collect()))
            });
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn owner_resolution_preserves_preflight_and_unknown_policy() {
        use super::*;
        let mut cfg = config::InjectorConfig::default();
        let mut caller = CallerInfo { uid: 1000, pid: 2000, sid: "system".into() };
        assert_eq!(
            evaluate_caller_with(&caller, &cfg, |_| panic!("core caller queried packages")),
            FilterDecision::RejectedAndroidPackage
        );
        caller.uid = 99_001;
        cfg.filter.enabled = false;
        assert_eq!(
            evaluate_caller_with(&caller, &cfg, |_| panic!("disabled filter queried packages")),
            FilterDecision::Disabled
        );
        cfg.filter.enabled = true;
        for allowed in [false, true] {
            cfg.filter.allow_unknown_package = allowed;
            assert_eq!(
                evaluate_caller_with(&caller, &cfg, |_| (99_001, PackageResolution::Unknown))
                    .allowed(),
                allowed
            );
        }
    }

    pub(in crate::hook) struct TestReply {
        pub status: Result<(), StatusCode>,
        pub values: Parcel,
    }
    pub(in crate::hook) type TestBackend =
        Arc<dyn Fn(&CallerInfo, (u32, u32), &BorrowedParcel<'_>) -> binder::Result<TestReply>>;
    #[derive(Clone)]
    struct TestConnection {
        backend: Option<TestBackend>,
        ready: bool,
    }
    thread_local! { static BACKEND: RefCell<Option<TestConnection>> = RefCell::default(); }
    pub(in crate::hook) fn may_intercept() -> bool {
        BACKEND.with_borrow(Option::is_some) || kmr_common::rpc::may_intercept()
    }
    pub(in crate::hook) fn wait_until_ready() -> bool {
        BACKEND.with_borrow_mut(|slot| {
            let Some(connection) = slot else { return false };
            connection.ready = true;
            true
        }) || kmr_common::rpc::wait_until_ready()
    }
    pub(in crate::hook) fn dispatch(
        backend: Backend<'_>,
        caller: &CallerInfo,
        transaction: (u32, u32),
        input: &BorrowedParcel<'_>,
        output: &mut BorrowedParcel<'_>,
        level: impl FnOnce(SecurityLevel) -> Result<SpIBinder, StatusCode>,
        operation: impl FnOnce(u64, Arc<BnKeystoreOperation>) -> Result<SpIBinder, StatusCode>,
    ) -> binder::Result<Option<()>> {
        if !matches!(backend, Backend::Operation { .. }) {
            if let Some(connection) = BACKEND.with_borrow(Clone::clone) {
                let Some(target) = connection.backend.filter(|_| connection.ready) else {
                    return Ok(None);
                };
                let reply = target(caller, transaction, input)?;
                reply.status?;
                output.append_all_from(&reply.values)?;
                return Ok(Some(()));
            }
        }
        kmr_common::rpc::dispatch(backend, caller, transaction, input, output, level, operation)
    }
    pub(in crate::hook) fn with_test_backend<T>(
        backend: impl Into<Option<TestBackend>>,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<TestConnection>);
        impl Drop for Restore {
            fn drop(&mut self) {
                drop(BACKEND.replace(self.0.take()));
            }
        }
        let _restore = Restore(
            BACKEND.replace(Some(TestConnection { backend: backend.into(), ready: false })),
        );
        run()
    }
}
