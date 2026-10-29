use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::IOhMyAuthorizationService;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMyMaintenanceService::IOhMyMaintenanceService;
use anyhow::{Context, Result};
use kmr_common::rpc;
use log::{debug, warn};
use rsbinder::rpc::{RpcClientConfig, RpcSession};
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, FromIBinder, Status, StatusCode, Strong, WIBinder,
};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::LocalKey;

#[cfg(test)]
mod tests;

const PM_SERVICE: &str = "sec_key_att_app_id_provider";

type CachedRpcClient<T> = Option<Arc<RpcClient<T>>>;

thread_local! {
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = const { RefCell::new(None) };
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
    static LOCAL_SERVICE: RefCell<CachedRpcClient<Strong<dyn IOhMyKsService>>> = RefCell::default();
    static LOCAL_AUTH_TOKEN: RefCell<CachedRpcClient<Strong<dyn IOhMyAuthorizationService>>> = RefCell::default();
    static LOCAL_LIFECYCLE: RefCell<CachedRpcClient<LifecycleServices>> = RefCell::default();
}

static PROCESS_STATE_INIT: Once = Once::new();

static RPC_CACHE: Mutex<RpcCache> =
    Mutex::new(RpcCache { service: None, auth_token: None, lifecycle: None });
static SERVICE_CONNECT: Mutex<()> = Mutex::new(());
static AUTH_TOKEN_CONNECT: Mutex<()> = Mutex::new(());
static LIFECYCLE_CONNECT: Mutex<()> = Mutex::new(());

struct RpcClient<T> {
    session: RpcSession,
    service: T,
    active: AtomicBool,
}

impl<T> RpcClient<T> {
    fn is_current(&self) -> bool {
        self.active.load(Ordering::Acquire) && !self.session.is_ended()
    }
}

struct LifecycleServices {
    authorization: Strong<dyn IOhMyAuthorizationService>,
    maintenance: Strong<dyn IOhMyMaintenanceService>,
}

struct RpcCache {
    service: CachedRpcClient<Strong<dyn IOhMyKsService>>,
    auth_token: CachedRpcClient<Strong<dyn IOhMyAuthorizationService>>,
    lifecycle: CachedRpcClient<LifecycleServices>,
}

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

fn with_rpc_client<T: 'static, R>(
    connect: impl FnOnce() -> Result<RpcSession>,
    cache: &Mutex<RpcCache>,
    connecting: &Mutex<()>,
    local: &'static LocalKey<RefCell<CachedRpcClient<T>>>,
    slot: fn(&mut RpcCache) -> &mut CachedRpcClient<T>,
    resolve: impl FnOnce(&RpcSession) -> Result<T>,
    f: impl FnOnce(&T) -> Result<R>,
) -> Result<R> {
    ensure_process_state();
    let get_cached = || {
        let (client, retired) = {
            let mut cache = cache.lock().expect("RPC cache poisoned");
            let slot = slot(&mut cache);
            let retired = if slot.as_ref().is_some_and(|client| !client.is_current()) {
                slot.take()
            } else {
                None
            };
            (slot.as_ref().map(Arc::clone), retired)
        };
        drop(retired);
        client
    };
    let invoke = |client: &Arc<RpcClient<T>>| {
        let result = f(&client.service);
        if client.session.is_ended()
            || result.as_ref().err().is_some_and(is_rpc_cache_invalidating_error)
        {
            client.active.store(false, Ordering::Release);
            let retired = {
                let mut cache = cache.lock().expect("RPC cache poisoned");
                let slot = slot(&mut cache);
                if slot.as_ref().is_some_and(|cached| Arc::ptr_eq(cached, client)) {
                    slot.take()
                } else {
                    None
                }
            };
            drop(retired);
        }
        result
    };
    local.with(|local| {
        if let Ok(cached) = local.try_borrow() {
            if let Some(client) = cached.as_ref().filter(|client| client.is_current()) {
                return invoke(client);
            }
        }
        let client = match get_cached() {
            Some(client) => client,
            None => {
                let _connecting = connecting.lock().expect("RPC connector poisoned");
                match get_cached() {
                    Some(client) => client,
                    None => {
                        let session = connect()?;
                        let service = resolve(&session)?;
                        let client =
                            Arc::new(RpcClient { session, service, active: AtomicBool::new(true) });
                        {
                            let mut cache = cache.lock().expect("RPC cache poisoned");
                            *slot(&mut cache) = Some(Arc::clone(&client));
                        }
                        client
                    }
                }
            }
        };
        // A reentrant call may borrow the old TLS entry; its slow path must not replace it.
        let retired =
            local.try_borrow_mut().ok().and_then(|mut cached| cached.replace(Arc::clone(&client)));
        drop(retired);
        invoke(&client)
    })
}

fn connect_rpc_session(outgoing_connections: u32) -> Result<RpcSession> {
    RpcSession::setup_client_android13plus_with_config(
        RpcClientConfig::unix(std::path::Path::new(rpc::SOCKET), rpc::WIRE_MAX_VERSION)
            .outgoing_connections(outgoing_connections),
    )
    .context("failed to connect OMK RPC socket")
}

pub fn with_omk_once<T>(f: impl FnOnce(&Strong<dyn IOhMyKsService>) -> Result<T>) -> Result<T> {
    with_rpc_client(
        || connect_rpc_session(num_cpus::get() as u32),
        &RPC_CACHE,
        &SERVICE_CONNECT,
        &LOCAL_SERVICE,
        |cache| &mut cache.service,
        |session| session.get_interface(rpc::SERVICE).context("failed to connect to omk service"),
        f,
    )
}

pub fn with_omk_auth_token_once<T>(
    f: impl FnOnce(&Strong<dyn IOhMyAuthorizationService>) -> Result<T>,
) -> Result<T> {
    with_rpc_client(
        || connect_rpc_session(1),
        &RPC_CACHE,
        &AUTH_TOKEN_CONNECT,
        &LOCAL_AUTH_TOKEN,
        |cache| &mut cache.auth_token,
        |session| {
            session
                .get_interface(rpc::AUTHORIZATION_SERVICE)
                .context("failed to connect to omk_authorization service")
        },
        f,
    )
}

fn with_lifecycle_once<T>(f: impl FnOnce(&LifecycleServices) -> Result<T>) -> Result<T> {
    with_rpc_client(
        || connect_rpc_session(1),
        &RPC_CACHE,
        &LIFECYCLE_CONNECT,
        &LOCAL_LIFECYCLE,
        |cache| &mut cache.lifecycle,
        |session| {
            Ok(LifecycleServices {
                authorization: session
                    .get_interface(rpc::AUTHORIZATION_SERVICE)
                    .context("failed to connect to omk_authorization service")?,
                maintenance: session
                    .get_interface(rpc::MAINTENANCE_SERVICE)
                    .context("failed to connect to omk_maintenance service")?,
            })
        },
        f,
    )
}

pub fn with_omk_authorization_once<T>(
    f: impl FnOnce(&Strong<dyn IOhMyAuthorizationService>) -> Result<T>,
) -> Result<T> {
    with_lifecycle_once(|services| f(&services.authorization))
}

pub fn with_omk_maintenance_once<T>(
    f: impl FnOnce(&Strong<dyn IOhMyMaintenanceService>) -> Result<T>,
) -> Result<T> {
    with_lifecycle_once(|services| f(&services.maintenance))
}

fn with_binder_retry<T, B, Get, Clear, Retry, F>(
    tag: &'static str,
    mut get: Get,
    mut clear: Clear,
    retryable: Retry,
    mut f: F,
) -> Result<T>
where
    B: FromIBinder + ?Sized,
    Get: FnMut() -> Result<Strong<B>>,
    Clear: FnMut(&Strong<B>),
    Retry: Fn(&anyhow::Error) -> bool,
    F: FnMut(&Strong<B>) -> Result<T>,
{
    let client = get()?;
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if retryable(&error) => {
            warn!("{tag} transaction hit a stale Binder; refreshing client and retrying once");
            clear(&client);
            let client = get()?;
            let result = f(&client);
            if result.as_ref().err().is_some_and(retryable) {
                clear(&client);
            }
            result
        }
        Err(error) => Err(error),
    }
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
            hub::check_interface(PM_SERVICE)
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
    with_binder_retry(
        "sec_key_att_app_id_provider",
        get_pm,
        |_| clear_pm_cache(),
        is_dead_object_error,
        &mut f,
    )
}

pub(crate) fn is_dead_object_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<Status>().is_some_and(is_dead_object_status)
            || cause
                .downcast_ref::<StatusCode>()
                .is_some_and(|status| *status == StatusCode::DeadObject)
    })
}

pub(crate) fn is_stale_rpc_status_code(status: StatusCode) -> bool {
    matches!(status, StatusCode::DeadObject | StatusCode::RpcError | StatusCode::NotEnoughData)
}

pub(crate) fn is_rpc_cache_invalidating_status_code(status: StatusCode) -> bool {
    is_stale_rpc_status_code(status)
        || status == StatusCode::NoInit
        || matches!(status, StatusCode::Errno(errno) if matches!(
            errno.abs(),
            libc::ENOENT | libc::ECONNREFUSED | libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE
        ))
}

fn is_rpc_cache_invalidating_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<Status>().is_some_and(|status| {
            status.exception_code() == ExceptionCode::TransactionFailed
                && (is_rpc_cache_invalidating_status_code(status.transaction_error())
                    || status.transaction_error() == StatusCode::Unknown)
        }) || cause
            .downcast_ref::<StatusCode>()
            .is_some_and(|status| is_rpc_cache_invalidating_status_code(*status))
    })
}

fn is_dead_object_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::DeadObject
}

fn clear_pm_cache() {
    PM.with(|slot| *slot.borrow_mut() = None);
    PM_DEATH.with(|slot| *slot.borrow_mut() = None);
}
