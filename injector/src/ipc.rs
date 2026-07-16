use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::thread::LocalKey;
use std::time::{Duration, Instant};
use std::{cmp, thread};

use anyhow::{Context, Result};
use kmr_common::rpc;
use log::{debug, warn};
use rsbinder::rpc::RpcSession;
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, FromIBinder, Status, StatusCode, Strong, WIBinder,
};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::IOhMyAuthorizationService;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMyMaintenanceService::IOhMyMaintenanceService;

const RPC_READY_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_READY_RETRY_DELAY: Duration = Duration::from_millis(200);
const PM_SERVICE: &str = "sec_key_att_app_id_provider";

thread_local! {
    static OMK: RefCell<Option<Strong<dyn IOhMyKsService>>> = const { RefCell::new(None) };
    static OMK_AUTHORIZATION: RefCell<Option<Strong<dyn IOhMyAuthorizationService>>> = const { RefCell::new(None) };
    static OMK_MAINTENANCE: RefCell<Option<Strong<dyn IOhMyMaintenanceService>>> = const { RefCell::new(None) };
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = const { RefCell::new(None) };
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
}

static PROCESS_STATE_INIT: Once = Once::new();
static SESSION: Mutex<Option<RpcSession>> = Mutex::new(None);

struct PmDeathRecipient;

impl DeathRecipient for PmDeathRecipient {
    fn binder_died(&self, _who: &WIBinder) {
        clear_pm_cache();
        warn!("{} binder died; cache cleared", PM_SERVICE);
    }
}

pub fn ensure_process_state() {
    PROCESS_STATE_INIT.call_once(|| {
        let _ = rsbinder::ProcessState::init_default();
        debug!("rsbinder process state initialized");
    });
}

pub fn install_direct_rpc_session() -> Result<()> {
    ensure_process_state();
    clear_rpc_caches();

    let session = connect_rpc_session("failed to connect OMK RPC socket")?;
    *SESSION.lock().expect("RPC session cache poisoned") = Some(session);
    Ok(())
}

fn connect_rpc_session(connect_context: &'static str) -> Result<RpcSession> {
    let start = Instant::now();
    loop {
        match connect_rpc_session_once(connect_context) {
            Ok(session) => return Ok(session),
            Err(error) if start.elapsed() >= RPC_READY_TIMEOUT => {
                return Err(error).context("OMK RPC server did not become ready in time");
            }
            Err(_) => thread::sleep(cmp::min(
                RPC_READY_RETRY_DELAY,
                RPC_READY_TIMEOUT.saturating_sub(start.elapsed()),
            )),
        }
    }
}

fn connect_rpc_session_once(connect_context: &'static str) -> Result<RpcSession> {
    let session = RpcSession::setup_unix_client_android13plus(rpc::SOCKET, rpc::WIRE_MAX_VERSION)
        .context(connect_context)?;
    session.get_service(rpc::SERVICE).context(connect_context)?;
    Ok(session)
}

fn get_rpc_session(connect_context: &'static str) -> Result<RpcSession> {
    let mut slot = SESSION.lock().expect("RPC session cache poisoned");
    if let Some(session) = slot.as_ref() {
        return Ok(session.clone());
    }

    let session = connect_rpc_session(connect_context)?;
    *slot = Some(session.clone());
    Ok(session)
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
        Ok(packages) if packages.is_empty() => PackageResolution::Unknown,
        Ok(packages) => PackageResolution::Known(packages),
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

fn get_pm() -> Result<Strong<dyn IKeyAttestationApplicationIdProvider>> {
    ensure_process_state();
    PM.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<dyn IKeyAttestationApplicationIdProvider> =
            hub::get_interface(PM_SERVICE)
                .context("failed to connect to sec_key_att_app_id_provider")?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(PmDeathRecipient);
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context("failed to watch sec_key_att_app_id_provider death")?;
        PM_DEATH.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_object_status_classification() {
        let status = Status::from(StatusCode::DeadObject);
        assert!(is_dead_object_status(&status));

        let status = Status::from(StatusCode::Ok);
        assert!(!is_dead_object_status(&status));
    }
}
