use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Condvar, LazyLock, Mutex, Once};
use std::time::{Duration, Instant};
use std::{cmp, thread};

use anyhow::{Context, Result};
use kmr_common::rpc;
use log::{debug, warn};
use rsbinder::rpc::RpcSession;
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, FromIBinder, SIBinder, Status, StatusCode, Strong, WIBinder,
};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::IOhMyAuthorizationService;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMyMaintenanceService::IOhMyMaintenanceService;

const RPC_READY_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_READY_RETRY_DELAY: Duration = Duration::from_millis(200);
const PACKAGE_CACHE_TTL: Duration = Duration::from_secs(30);
const PM_SERVICE: &str = "sec_key_att_app_id_provider";

thread_local! {
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = const { RefCell::new(None) };
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
}

static PROCESS_STATE_INIT: Once = Once::new();
static PACKAGE_CACHE: LazyLock<Mutex<HashMap<u32, PackageCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static RPC_CACHE: Mutex<RpcCacheState> = Mutex::new(RpcCacheState {
    generation: 0,
    cache: None,
    connecting: None,
    next_connect_attempt: 0,
    last_connect_error: None,
});
static RPC_CACHE_READY: Condvar = Condvar::new();

#[derive(Clone)]
struct PackageCacheEntry {
    resolution: PackageResolution,
    expires_at: Instant,
}

struct RpcCacheState {
    generation: u64,
    cache: Option<RpcCache>,
    connecting: Option<u64>,
    next_connect_attempt: u64,
    last_connect_error: Option<Arc<anyhow::Error>>,
}

struct RpcCache {
    session: RpcSession,
    services: HashMap<&'static str, SIBinder>,
}

#[derive(Clone)]
struct SharedRpcConnectError(Arc<anyhow::Error>);

impl fmt::Debug for SharedRpcConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_ref(), f)
    }
}

impl fmt::Display for SharedRpcConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl std::error::Error for SharedRpcConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

fn shared_rpc_connect_error(error: &Arc<anyhow::Error>) -> anyhow::Error {
    anyhow::Error::new(SharedRpcConnectError(Arc::clone(error)))
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

pub fn install_direct_rpc_session() -> Result<()> {
    ensure_process_state();
    let cache = connect_rpc_session("failed to connect OMK RPC socket")?;
    let old = {
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        state.generation = state.generation.wrapping_add(1);
        state.last_connect_error = None;
        state.cache.replace(cache)
    };
    RPC_CACHE_READY.notify_all();
    drop(old);
    Ok(())
}

fn connect_rpc_session(connect_context: &'static str) -> Result<RpcCache> {
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

fn connect_rpc_session_once(connect_context: &'static str) -> Result<RpcCache> {
    let session = RpcSession::setup_unix_client_android13plus(rpc::SOCKET, rpc::WIRE_MAX_VERSION)
        .context(connect_context)?;
    let service = session.get_service(rpc::SERVICE).context(connect_context)?;
    Ok(RpcCache {
        session,
        services: HashMap::from([(rpc::SERVICE, service)]),
    })
}

fn ensure_rpc_cache(connect_context: &'static str) -> Result<()> {
    loop {
        let (generation, attempt) = {
            let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
            if state.cache.is_some() {
                return Ok(());
            }
            if let Some(attempt) = state.connecting {
                state = RPC_CACHE_READY
                    .wait_while(state, |state| {
                        state.cache.is_none() && state.connecting == Some(attempt)
                    })
                    .expect("RPC cache poisoned");
                if state.cache.is_some() {
                    return Ok(());
                }
                if state.connecting != Some(attempt) {
                    if let Some(error) = state.last_connect_error.as_ref() {
                        return Err(shared_rpc_connect_error(error));
                    }
                }
                drop(state);
                continue;
            }

            let attempt = state.next_connect_attempt;
            state.next_connect_attempt = state.next_connect_attempt.wrapping_add(1);
            state.connecting = Some(attempt);
            (state.generation, attempt)
        };

        let candidate = connect_rpc_session(connect_context);
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        if state.connecting == Some(attempt) {
            state.connecting = None;
        }
        let mut stale_cache = None;
        let outcome = if state.cache.is_none() && state.generation == generation {
            match candidate {
                Ok(cache) => {
                    state.cache = Some(cache);
                    state.generation = state.generation.wrapping_add(1);
                    state.last_connect_error = None;
                    Some(Ok(()))
                }
                Err(error) => {
                    let error = Arc::new(error);
                    state.last_connect_error = Some(Arc::clone(&error));
                    Some(Err(shared_rpc_connect_error(&error)))
                }
            }
        } else {
            if let Ok(cache) = candidate {
                stale_cache = Some(cache);
            }
            None
        };
        RPC_CACHE_READY.notify_all();
        drop(state);
        drop(stale_cache);
        if let Some(outcome) = outcome {
            return outcome;
        }
    }
}

fn get_rpc_binder<T>(
    service_name: &'static str,
    connect_context: &'static str,
    refresh: bool,
) -> Result<Strong<T>>
where
    T: FromIBinder + ?Sized + 'static,
{
    let mut reconnected = false;
    loop {
        ensure_rpc_cache(connect_context)?;
        let (session, identity, cached) = {
            let state = RPC_CACHE.lock().expect("RPC cache poisoned");
            let Some(cache) = state.cache.as_ref() else {
                continue;
            };
            (
                cache.session.clone(),
                cache
                    .services
                    .get(rpc::SERVICE)
                    .expect("RPC cache missing base service")
                    .clone(),
                cache.services.get(service_name).cloned(),
            )
        };

        if let Some(binder) = cached.filter(|_| !refresh) {
            let client = <T as FromIBinder>::try_from(binder).context(connect_context)?;
            let state = RPC_CACHE.lock().expect("RPC cache poisoned");
            if state
                .cache
                .as_ref()
                .and_then(|cache| cache.services.get(rpc::SERVICE))
                == Some(&identity)
            {
                return Ok(client);
            }
            continue;
        }

        let result = session.get_service(service_name);
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        if state
            .cache
            .as_ref()
            .and_then(|cache| cache.services.get(rpc::SERVICE))
            != Some(&identity)
        {
            drop(state);
            continue;
        }

        match result {
            Ok(binder) => {
                let client =
                    <T as FromIBinder>::try_from(binder.clone()).context(connect_context)?;
                let cache = state.cache.as_mut().expect("RPC cache identity matched");
                let old = cache.services.insert(service_name, binder);
                drop(state);
                drop(old);
                return Ok(client);
            }
            Err(StatusCode::NameNotFound) => {
                return Err(StatusCode::NameNotFound).context(connect_context);
            }
            Err(error) => {
                state.generation = state.generation.wrapping_add(1);
                let old = state.cache.take();
                drop(state);
                drop(old);
                if reconnected {
                    return Err(error).context(connect_context);
                }
                reconnected = true;
                warn!("cached RPC session failed before transaction ({error:#}); reconnecting");
            }
        }
    }
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

fn with_binder_once<T, B, Get, Clear, Stale, F>(
    get: Get,
    clear: Clear,
    stale: Stale,
    f: F,
) -> Result<T>
where
    B: FromIBinder + ?Sized,
    Get: FnOnce() -> Result<Strong<B>>,
    Clear: FnOnce(&Strong<B>),
    Stale: FnOnce(&anyhow::Error) -> bool,
    F: FnOnce(&Strong<B>) -> Result<T>,
{
    let client = get()?;
    let result = f(&client);
    if result.as_ref().err().is_some_and(stale) {
        clear(&client);
    }
    result
}

pub fn get_omk() -> Result<Strong<dyn IOhMyKsService>> {
    get_rpc_binder(rpc::SERVICE, "failed to connect to omk service", false)
}

pub fn with_omk_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IOhMyKsService>) -> Result<T>,
{
    with_binder_retry(
        "omk",
        get_omk,
        |client| {
            clear_rpc_cache_if(rpc::SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        &mut f,
    )
}

pub fn with_omk_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IOhMyKsService>) -> Result<T>,
{
    with_binder_once(
        || get_rpc_binder(rpc::SERVICE, "failed to connect to omk service", true),
        |client| {
            clear_rpc_cache_if(rpc::SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

fn get_omk_authorization_fresh() -> Result<Strong<dyn IOhMyAuthorizationService>> {
    get_rpc_binder(
        rpc::AUTHORIZATION_SERVICE,
        "failed to connect to omk_authorization service",
        true,
    )
}

pub fn with_omk_authorization_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IOhMyAuthorizationService>) -> Result<T>,
{
    with_binder_once(
        get_omk_authorization_fresh,
        |client| {
            clear_rpc_cache_if(rpc::AUTHORIZATION_SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

fn get_omk_maintenance_fresh() -> Result<Strong<dyn IOhMyMaintenanceService>> {
    get_rpc_binder(
        rpc::MAINTENANCE_SERVICE,
        "failed to connect to omk_maintenance service",
        true,
    )
}

pub fn with_omk_maintenance_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IOhMyMaintenanceService>) -> Result<T>,
{
    with_binder_once(
        get_omk_maintenance_fresh,
        |client| {
            clear_rpc_cache_if(rpc::MAINTENANCE_SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

pub fn resolve_packages_for_uid(uid: u32) -> PackageResolution {
    if let Some(cached) = cached_packages(uid) {
        return cached;
    }
    let resolution = resolve_packages_for_uid_uncached(uid);
    store_package_cache(uid, resolution.clone());
    resolution
}

fn resolve_packages_for_uid_uncached(uid: u32) -> PackageResolution {
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

fn package_cache_lock() -> std::sync::MutexGuard<'static, HashMap<u32, PackageCacheEntry>> {
    PACKAGE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached_packages(uid: u32) -> Option<PackageResolution> {
    let mut cache = package_cache_lock();
    let expired = cache
        .get(&uid)
        .is_some_and(|entry| Instant::now() >= entry.expires_at);
    if expired {
        cache.remove(&uid);
        return None;
    }
    cache.get(&uid).map(|entry| entry.resolution.clone())
}

fn store_package_cache(uid: u32, resolution: PackageResolution) {
    package_cache_lock().insert(
        uid,
        PackageCacheEntry {
            resolution,
            expires_at: Instant::now() + PACKAGE_CACHE_TTL,
        },
    );
}

pub(crate) fn clear_package_cache() {
    package_cache_lock().clear();
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
        cause
            .downcast_ref::<Status>()
            .is_some_and(is_dead_object_status)
            || cause
                .downcast_ref::<StatusCode>()
                .is_some_and(|status| *status == StatusCode::DeadObject)
    })
}

pub(crate) fn is_stale_rpc_status_code(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::DeadObject | StatusCode::RpcError | StatusCode::NotEnoughData
    )
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
    clear_package_cache();
}

fn clear_rpc_cache_if(service_name: &'static str, failed: &SIBinder) {
    let old = {
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        let still_failed = state
            .cache
            .as_ref()
            .and_then(|cache| cache.services.get(service_name))
            == Some(failed);
        still_failed.then(|| {
            state.generation = state.generation.wrapping_add(1);
            state.cache.take()
        })
    }
    .flatten();
    drop(old);
}

#[cfg(test)]
mod tests;
