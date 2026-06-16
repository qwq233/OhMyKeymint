use std::cell::RefCell;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::thread::LocalKey;

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::rpc;
use log::{debug, warn};
use rsbinder::rpc::RpcSession;
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, FromIBinder, Status, StatusCode, Strong, WIBinder,
};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::android::system::keystore2::IKeystoreService::IKeystoreService;
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::IOhMyAuthorizationService;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMyMaintenanceService::IOhMyMaintenanceService;

const SYSTEM_KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

thread_local! {
    static OMK: RefCell<Option<Strong<dyn IOhMyKsService>>> = const { RefCell::new(None) };
    static OMK_AUTHORIZATION: RefCell<Option<Strong<dyn IOhMyAuthorizationService>>> = const { RefCell::new(None) };
    static OMK_MAINTENANCE: RefCell<Option<Strong<dyn IOhMyMaintenanceService>>> = const { RefCell::new(None) };
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = const { RefCell::new(None) };
    static SYSTEM_KEYSTORE: RefCell<Option<Strong<dyn IKeystoreService>>> = const { RefCell::new(None) };
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
    static SYSTEM_KEYSTORE_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
}

static PROCESS_STATE_INIT: Once = Once::new();
static SESSION: Mutex<Option<RpcSession>> = Mutex::new(None);

struct CachedBinderDeath {
    tag: &'static str,
    clear: fn(),
}

impl DeathRecipient for CachedBinderDeath {
    fn binder_died(&self, _who: &WIBinder) {
        (self.clear)();
        warn!("{} binder died; cache cleared", self.tag);
    }
}

pub fn ensure_process_state() {
    PROCESS_STATE_INIT.call_once(|| {
        let _ = rsbinder::ProcessState::init_default();
        debug!("rsbinder process state initialized");
    });
}

pub fn install_rpc_session_from_fd(raw_fd: RawFd) -> Result<()> {
    if raw_fd < 0 {
        bail!("invalid OMK RPC fd {raw_fd}");
    }

    ensure_process_state();
    clear_rpc_caches();

    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let session = RpcSession::from_preconnected_fd(fd, rpc::WIRE_MAX_VERSION)
        .context("failed to initialize OMK RPC session from preconnected fd")?;
    *SESSION.lock().expect("RPC session cache poisoned") = Some(session);
    Ok(())
}

fn get_cached_binder<T>(
    service_name: &'static str,
    connect_context: &'static str,
    death_context: &'static str,
    tag: &'static str,
    slot: &'static LocalKey<RefCell<Option<Strong<T>>>>,
    death_slot: &'static LocalKey<RefCell<Option<Arc<dyn DeathRecipient>>>>,
    clear: fn(),
) -> Result<Strong<T>>
where
    T: FromIBinder + ?Sized + 'static,
{
    ensure_process_state();
    slot.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<T> = hub::get_interface(service_name).context(connect_context)?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(CachedBinderDeath { tag, clear });
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context(death_context)?;
        death_slot.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

fn get_rpc_session(connect_context: &'static str) -> Result<RpcSession> {
    let slot = SESSION.lock().expect("RPC session cache poisoned");
    if let Some(session) = slot.as_ref() {
        return Ok(session.clone());
    }

    Err(anyhow!("OMK RPC session is not initialized")).context(connect_context)
}

fn get_cached_rpc_binder<T>(
    service_name: &'static str,
    connect_context: &'static str,
    slot: &'static LocalKey<RefCell<Option<Strong<T>>>>,
) -> Result<Strong<T>>
where
    T: FromIBinder + ?Sized + 'static,
{
    slot.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let session = get_rpc_session(connect_context)?;
        let binder = session.get_service(service_name).context(connect_context)?;
        let client: Strong<T> = <T as FromIBinder>::try_from(binder).context(connect_context)?;
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

fn with_dead_object_retry<T, B, Get, Clear, F>(
    tag: &'static str,
    mut get: Get,
    mut clear: Clear,
    mut f: F,
) -> Result<T>
where
    B: FromIBinder + ?Sized,
    Get: FnMut() -> Result<Strong<B>>,
    Clear: FnMut(),
    F: FnMut(&Strong<B>) -> Result<T>,
{
    let client = get()?;
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if is_dead_object_error(&error) => {
            warn!("{tag} transaction hit DeadObject; clearing cache and retrying once");
            clear();
            let client = get()?;
            f(&client)
        }
        Err(error) => Err(error),
    }
}

pub fn get_omk() -> Result<Strong<dyn IOhMyKsService>> {
    get_cached_rpc_binder(rpc::SERVICE, "failed to connect to omk service", &OMK)
}

pub fn with_omk_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IOhMyKsService>) -> Result<T>,
{
    with_dead_object_retry("omk", get_omk, clear_rpc_caches, &mut f)
}

pub fn get_omk_authorization() -> Result<Strong<dyn IOhMyAuthorizationService>> {
    get_cached_rpc_binder(
        rpc::AUTHORIZATION_SERVICE,
        "failed to connect to omk_authorization service",
        &OMK_AUTHORIZATION,
    )
}

pub fn with_omk_authorization_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IOhMyAuthorizationService>) -> Result<T>,
{
    with_dead_object_retry(
        rpc::AUTHORIZATION_SERVICE,
        get_omk_authorization,
        clear_rpc_caches,
        &mut f,
    )
}

pub fn get_omk_maintenance() -> Result<Strong<dyn IOhMyMaintenanceService>> {
    get_cached_rpc_binder(
        rpc::MAINTENANCE_SERVICE,
        "failed to connect to omk_maintenance service",
        &OMK_MAINTENANCE,
    )
}

pub fn with_omk_maintenance_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IOhMyMaintenanceService>) -> Result<T>,
{
    with_dead_object_retry(
        rpc::MAINTENANCE_SERVICE,
        get_omk_maintenance,
        clear_rpc_caches,
        &mut f,
    )
}

pub fn resolve_packages_for_uid(uid: u32) -> PackageResolution {
    ensure_process_state();
    match resolve_package_names_for_uid(uid) {
        Ok(packages) => {
            if packages.is_empty() {
                PackageResolution::Unknown
            } else {
                PackageResolution::Known(packages)
            }
        }
        Err(error) => {
            warn!("failed to resolve packages for uid {}: {:#}", uid, error);
            PackageResolution::Unknown
        }
    }
}

fn resolve_package_names_for_uid(uid: u32) -> Result<Vec<String>> {
    if crate::legacy::should_use_aaid_provider() {
        crate::legacy::resolve_package_names_for_uid(uid)
    } else {
        resolve_package_names_for_uid_once(uid)
    }
}

fn resolve_package_names_for_uid_once(uid: u32) -> Result<Vec<String>> {
    let app_id = with_pm_retry(|pm| {
        pm.getKeyAttestationApplicationId(uid as i32)
            .context("getKeyAttestationApplicationId failed")
    })?;
    Ok(app_id
        .packageInfos
        .into_iter()
        .map(|pkg| pkg.packageName)
        .filter(|pkg| !pkg.is_empty())
        .collect())
}

pub fn get_system_keystore_service() -> Result<Strong<dyn IKeystoreService>> {
    get_cached_binder(
        SYSTEM_KEYSTORE_SERVICE,
        "failed to connect to android.system.keystore2.IKeystoreService/default",
        "failed to watch system keystore death",
        SYSTEM_KEYSTORE_SERVICE,
        &SYSTEM_KEYSTORE,
        &SYSTEM_KEYSTORE_DEATH,
        clear_system_keystore_cache,
    )
}

pub fn with_system_keystore_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeystoreService>) -> Result<T>,
{
    with_dead_object_retry(
        "system keystore",
        get_system_keystore_service,
        clear_system_keystore_cache,
        &mut f,
    )
}

fn get_pm() -> Result<Strong<dyn IKeyAttestationApplicationIdProvider>> {
    get_cached_binder(
        "sec_key_att_app_id_provider",
        "failed to connect to sec_key_att_app_id_provider",
        "failed to watch sec_key_att_app_id_provider death",
        "sec_key_att_app_id_provider",
        &PM,
        &PM_DEATH,
        clear_pm_cache,
    )
}

fn with_pm_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeyAttestationApplicationIdProvider>) -> Result<T>,
{
    with_dead_object_retry(
        "sec_key_att_app_id_provider",
        get_pm,
        clear_pm_cache,
        &mut f,
    )
}

pub(crate) fn is_dead_object_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<Status>()
            .is_some_and(is_dead_object_status)
            || cause
                .downcast_ref::<StatusCode>()
                .is_some_and(|status| *status == StatusCode::DeadObject)
    })
}

fn is_dead_object_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::DeadObject
}

fn clear_rpc_caches() {
    OMK.with(|slot| *slot.borrow_mut() = None);
    OMK_AUTHORIZATION.with(|slot| *slot.borrow_mut() = None);
    OMK_MAINTENANCE.with(|slot| *slot.borrow_mut() = None);
    *SESSION.lock().expect("RPC session cache poisoned") = None;
}

fn clear_pm_cache() {
    PM.with(|slot| *slot.borrow_mut() = None);
    PM_DEATH.with(|slot| *slot.borrow_mut() = None);
}

fn clear_system_keystore_cache() {
    SYSTEM_KEYSTORE.with(|slot| *slot.borrow_mut() = None);
    SYSTEM_KEYSTORE_DEATH.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_dead_object_status() {
        let status = Status::from(StatusCode::DeadObject);
        assert!(is_dead_object_status(&status));
    }

    #[test]
    fn ignores_non_dead_object_status() {
        let status = Status::from(StatusCode::Ok);
        assert!(!is_dead_object_status(&status));
    }

    #[test]
    fn missing_rpc_session_keeps_connect_context() {
        clear_rpc_caches();

        let error = match get_rpc_session("failed to connect to omk service") {
            Ok(_) => panic!("missing preconnected RPC session should fail"),
            Err(error) => error,
        };

        assert!(error
            .chain()
            .any(|cause| cause.to_string() == "failed to connect to omk service"));
    }
}
