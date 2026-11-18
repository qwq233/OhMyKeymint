use super::{
    is_rpc_cache_invalidating_status, AUTHORIZATION_SERVICE, MAINTENANCE_SERVICE,
    SERVICE as SERVICE_NAME, SOCKET,
};
use crate::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::aidl::android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel;
use crate::aidl::top::qwq2333::ohmykeymint::{
    IOhMyAuthorizationService::{
        BnOhMyAuthorizationService, BpOhMyAuthorizationService, IOhMyAuthorizationService,
    },
    IOhMyKsService::{BnOhMyKsService, BpOhMyKsService, IOhMyKsService},
    IOhMyMaintenanceService::{
        BnOhMyMaintenanceService, BpOhMyMaintenanceService, IOhMyMaintenanceService,
    },
    IOhMySecurityLevel::{BnOhMySecurityLevel, BpOhMySecurityLevel},
};
use binder::binder_impl::Proxy;
use binder::ext::rpc::RpcSession;
use binder::{DeathRecipient, Status};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::LocalKey;
use std::time::{Duration, Instant};

pub(super) struct Client<T> {
    pub epoch: u64,
    session: Arc<RpcSession>,
    _death: Option<DeathRecipient>,
    pub service: T,
}
impl<T> Drop for Client<T> {
    fn drop(&mut self) {
        let _ = self.session.shutdown();
    }
}
pub(super) struct Keystore {
    pub service: BnOhMyKsService,
    levels: Mutex<HashMap<SecurityLevel, Arc<BnOhMySecurityLevel>>>,
    pub public_levels: Mutex<HashMap<SecurityLevel, binder::Strong<dyn IKeystoreSecurityLevel>>>,
}
struct Lifecycle {
    authorization: BnOhMyAuthorizationService,
    maintenance: BnOhMyMaintenanceService,
}
struct Connections {
    alive: Arc<AtomicBool>,
    service: Arc<Client<Keystore>>,
    auth_token: Arc<Client<BnOhMyAuthorizationService>>,
    lifecycle: Arc<Client<Lifecycle>>,
}

thread_local! {
    static SERVICE: RefCell<Option<Arc<Client<Keystore>>>> = RefCell::default();
    static AUTH_TOKEN: RefCell<Option<Arc<Client<BnOhMyAuthorizationService>>>> = RefCell::default();
    static LIFECYCLE: RefCell<Option<Arc<Client<Lifecycle>>>> = RefCell::default();
}
static CONNECTIONS: Mutex<Option<Connections>> = Mutex::new(None);
static RECOVER: Condvar = Condvar::new();
// Zero means unavailable. Only published connection groups receive epochs above STARTING.
const STARTING: u64 = 1;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
static ROUTE: RouteState = RouteState::new();
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(STARTING + 1);
static STARTED: AtomicBool = AtomicBool::new(false);

struct RouteState {
    epoch: AtomicU64,
    startup_deadline: Mutex<Option<Instant>>,
    startup_done: Condvar,
}

impl RouteState {
    const fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            startup_deadline: Mutex::new(None),
            startup_done: Condvar::new(),
        }
    }

    fn begin_startup(&self, deadline: Instant) {
        *self.startup_deadline.lock().expect("RPC startup poisoned") = Some(deadline);
        self.epoch.store(STARTING, Ordering::Release);
    }

    fn finish_startup(&self) {
        let mut deadline = self.startup_deadline.lock().expect("RPC startup poisoned");
        if deadline.take().is_some() {
            let _ = self.epoch.compare_exchange(STARTING, 0, Ordering::AcqRel, Ordering::Acquire);
            self.startup_done.notify_all();
        }
    }

    fn wait_until_ready(&self) -> bool {
        let epoch = self.epoch.load(Ordering::Acquire);
        if epoch != STARTING {
            return epoch > STARTING;
        }
        self.wait_for_startup(self.startup_deadline.lock().expect("RPC startup poisoned"))
    }

    fn wait_for_startup(&self, deadline: std::sync::MutexGuard<'_, Option<Instant>>) -> bool {
        if let Some(until) = *deadline {
            let (guard, timeout) = self
                .startup_done
                .wait_timeout_while(
                    deadline,
                    until.saturating_duration_since(Instant::now()),
                    |deadline| deadline.is_some(),
                )
                .expect("RPC startup wait poisoned");
            drop(guard);
            if timeout.timed_out() {
                self.finish_startup();
            }
        }
        self.epoch.load(Ordering::Acquire) > STARTING
    }
}

pub fn may_intercept() -> bool {
    ROUTE.epoch.load(Ordering::Acquire) != 0
}

pub fn available() -> bool {
    ROUTE.epoch.load(Ordering::Acquire) > STARTING
}

pub fn wait_until_ready() -> bool {
    ROUTE.wait_until_ready()
}

pub fn start() -> anyhow::Result<()> {
    RpcSession::init_client_apis()?;
    if STARTED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        ROUTE.begin_startup(Instant::now() + CONNECT_TIMEOUT);
        if let Err(error) =
            std::thread::Builder::new().name("omk-rpc-recovery".into()).spawn(recover)
        {
            ROUTE.finish_startup();
            STARTED.store(false, Ordering::Release);
            return Err(error.into());
        }
    }
    Ok(())
}

fn fail(epoch: u64) {
    {
        let _connections = CONNECTIONS.lock().expect("RPC connections poisoned");
        if ROUTE.epoch.compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
    }
    RECOVER.notify_one();
    log::warn!("event=route OMK transport unavailable; entering System passthrough");
}

fn with_client<T, R>(
    local: &'static LocalKey<RefCell<Option<Arc<Client<T>>>>>,
    select: impl FnOnce(&Connections) -> &Arc<Client<T>>,
    call: impl FnOnce(&Client<T>) -> binder::Result<Option<R>>,
) -> binder::Result<Option<R>> {
    let epoch = ROUTE.epoch.load(Ordering::Acquire);
    if epoch <= STARTING {
        return Ok(None);
    }
    let invoke = |client: &Client<T>| {
        if binder::ext::api_level() == 33 {
            if let Err(error) = client.session.ping() {
                let error = Status::from(error);
                if is_rpc_cache_invalidating_status(&error) {
                    fail(client.epoch);
                    return Ok(None);
                }
                return Err(error);
            }
        } else if client.session.is_ended() {
            fail(client.epoch);
            return Ok(None);
        }
        if ROUTE.epoch.load(Ordering::Acquire) != client.epoch {
            return Ok(None);
        }
        call(client)
    };
    local.with(|slot| {
        if let Ok(cached) = slot.try_borrow() {
            if let Some(client) = cached.as_ref().filter(|client| client.epoch == epoch) {
                return invoke(client);
            }
        }
        let client = {
            let connections = CONNECTIONS.lock().expect("RPC connections poisoned");
            let Some(connections) = connections.as_ref() else { return Ok(None) };
            let client = select(connections);
            if client.epoch != epoch {
                return Ok(None);
            }
            Arc::clone(client)
        };
        let retired =
            slot.try_borrow_mut().ok().and_then(|mut cached| cached.replace(Arc::clone(&client)));
        drop(retired);
        invoke(&client)
    })
}

fn connect<T>(
    epoch: u64,
    alive: &Arc<AtomicBool>,
    threads: usize,
    resolve: impl FnOnce(&RpcSession) -> binder::Result<T>,
) -> anyhow::Result<Arc<Client<T>>> {
    // Native setup is not externally cancellable before it installs its shutdown trigger.
    let incoming = usize::from(binder::ext::api_level() >= 34);
    let session = Arc::new(RpcSession::connect(SOCKET, threads, incoming)?);
    let deadline_session = Arc::clone(&session);
    let (done, completion) = std::sync::mpsc::channel();
    let deadline = std::thread::Builder::new()
        .name("omk-rpc-deadline".into())
        .spawn(move || {
            let result = completion.recv_timeout(CONNECT_TIMEOUT);
            if result.is_err() {
                let _ = deadline_session.shutdown();
            }
            result
        })
        .inspect_err(|_| {
            let _ = session.shutdown();
        })?;
    let result = (|| {
        let death = if incoming != 0 {
            let alive = Arc::clone(alive);
            let mut death = DeathRecipient::new(move || {
                alive.store(false, Ordering::Release);
                // The recovery owner releases native objects outside this callback and its locks.
                fail(epoch);
            });
            session.link_to_death(&mut death)?;
            Some(death)
        } else {
            None
        };
        resolve(&session).map(|service| (service, death))
    })();
    let _ = done.send(());
    deadline.join().map_err(|_| {
        let _ = session.shutdown();
        anyhow::anyhow!("RPC deadline thread panicked")
    })??;
    match result {
        Ok((service, death)) => Ok(Arc::new(Client { epoch, session, _death: death, service })),
        Err(error) => {
            let _ = session.shutdown();
            Err(error.into())
        }
    }
}

fn connect_all(epoch: u64) -> anyhow::Result<Connections> {
    let alive = Arc::new(AtomicBool::new(true));
    let service = connect(
        epoch,
        &alive,
        std::thread::available_parallelism().map_or(1, usize::from),
        |session| {
            let remote = session.get_interface::<dyn IOhMyKsService>(SERVICE_NAME)?;
            Ok(Keystore {
                service: BnOhMyKsService(Box::new(BpOhMyKsService::from_binder(
                    remote.as_binder(),
                )?)),
                levels: Mutex::new(HashMap::new()),
                public_levels: Mutex::new(HashMap::new()),
            })
        },
    )?;
    let auth_token = connect(epoch, &alive, 1, |session| {
        let remote =
            session.get_interface::<dyn IOhMyAuthorizationService>(AUTHORIZATION_SERVICE)?;
        Ok(BnOhMyAuthorizationService(Box::new(BpOhMyAuthorizationService::from_binder(
            remote.as_binder(),
        )?)))
    })?;
    let lifecycle = connect(epoch, &alive, 1, |session| {
        let authorization =
            session.get_interface::<dyn IOhMyAuthorizationService>(AUTHORIZATION_SERVICE)?;
        let maintenance =
            session.get_interface::<dyn IOhMyMaintenanceService>(MAINTENANCE_SERVICE)?;
        Ok(Lifecycle {
            authorization: BnOhMyAuthorizationService(Box::new(
                BpOhMyAuthorizationService::from_binder(authorization.as_binder())?,
            )),
            maintenance: BnOhMyMaintenanceService(Box::new(BpOhMyMaintenanceService::from_binder(
                maintenance.as_binder(),
            )?)),
        })
    })?;
    Ok(Connections { alive, service, auth_token, lifecycle })
}

fn recover() {
    loop {
        let mut connections = CONNECTIONS.lock().expect("RPC connections poisoned");
        while available() {
            connections = RECOVER.wait(connections).expect("RPC recovery wait poisoned");
        }
        let retired = connections.take();
        drop(connections);
        if let Some(retired) = retired {
            for session in
                [&retired.service.session, &retired.auth_token.session, &retired.lifecycle.session]
            {
                let _ = session.shutdown();
            }
        }
        let epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        match connect_all(epoch) {
            Ok(candidate) => {
                let retired = {
                    let mut connections = CONNECTIONS.lock().expect("RPC connections poisoned");
                    if !candidate.alive.load(Ordering::Acquire) {
                        drop(connections);
                        ROUTE.finish_startup();
                        drop(candidate);
                        continue;
                    }
                    let retired = connections.replace(candidate);
                    ROUTE.epoch.store(epoch, Ordering::Release);
                    retired
                };
                ROUTE.finish_startup();
                drop(retired);
                log::info!("event=route private RPC ready; interception resumed epoch={epoch}");
            }
            Err(error) => {
                ROUTE.finish_startup();
                log::debug!("private RPC recovery pending: {error}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

pub(super) fn remote_result<T>(epoch: u64, result: binder::Result<T>) -> binder::Result<T> {
    if let Err(error) = &result {
        if is_rpc_cache_invalidating_status(error) {
            fail(epoch);
        }
    }
    result
}

pub(super) fn with_keystore<T>(
    call: impl FnOnce(&Client<Keystore>) -> binder::Result<T>,
) -> binder::Result<Option<T>> {
    with_client(&SERVICE, |ready| &ready.service, |client| call(client).map(Some))
}

pub(super) fn level(
    client: &Client<Keystore>,
    level: SecurityLevel,
) -> binder::Result<Arc<BnOhMySecurityLevel>> {
    let cached = cached_level(client, level);
    if let Some(binder) = cached {
        return Ok(binder);
    }
    let remote = remote_result(client.epoch, client.service.service.0.getOhMySecurityLevel(level))?;
    let candidate = Arc::new(BnOhMySecurityLevel(Box::new(BpOhMySecurityLevel::from_binder(
        remote.as_binder(),
    )?)));
    let binder = {
        let mut levels = client.service.levels.lock().expect("level cache poisoned");
        levels.entry(level).or_insert_with(|| Arc::clone(&candidate)).clone()
    };
    Ok(binder)
}

pub(super) fn cached_level(
    client: &Client<Keystore>,
    level: SecurityLevel,
) -> Option<Arc<BnOhMySecurityLevel>> {
    client.service.levels.lock().expect("level cache poisoned").get(&level).cloned()
}

pub(super) fn with_authorization<T>(
    auth_token: bool,
    call: impl FnOnce(u64, &BnOhMyAuthorizationService) -> binder::Result<T>,
) -> binder::Result<Option<T>> {
    if auth_token {
        with_client(
            &AUTH_TOKEN,
            |ready| &ready.auth_token,
            |client| call(client.epoch, &client.service).map(Some),
        )
    } else {
        with_client(
            &LIFECYCLE,
            |ready| &ready.lifecycle,
            |client| call(client.epoch, &client.service.authorization).map(Some),
        )
    }
}

pub(super) fn with_maintenance<T>(
    call: impl FnOnce(u64, &BnOhMyMaintenanceService) -> binder::Result<T>,
) -> binder::Result<Option<T>> {
    with_client(
        &LIFECYCLE,
        |ready| &ready.lifecycle,
        |client| call(client.epoch, &client.service.maintenance).map(Some),
    )
}

pub fn with_admin<T>(
    call: impl FnOnce(&dyn IOhMyKsService) -> binder::Result<T>,
) -> binder::Result<Option<T>> {
    if !wait_until_ready() {
        return Ok(None);
    }
    with_keystore(|client| remote_result(client.epoch, call(&*client.service.service.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_waiters_share_the_first_result() {
        for ready in [false, true] {
            let state = RouteState::new();
            state.begin_startup(Instant::now() + CONNECT_TIMEOUT);
            let (enter, entered) = std::sync::mpsc::channel();
            let (done, results) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                for _ in 0..2 {
                    scope.spawn(|| {
                        let guard = state.startup_deadline.lock().unwrap();
                        enter.send(()).unwrap();
                        done.send(state.wait_for_startup(guard)).unwrap();
                    });
                }
                for _ in 0..2 {
                    entered.recv().unwrap();
                }
                if ready {
                    state.epoch.store(STARTING + 1, Ordering::Release);
                }
                state.finish_startup();
                for _ in 0..2 {
                    assert_eq!(results.recv_timeout(Duration::from_secs(1)).unwrap(), ready);
                }
            });
            state.epoch.store(0, Ordering::Release);
            assert!(!state.wait_until_ready());
        }
    }

    #[test]
    fn an_expired_startup_deadline_allows_late_publication() {
        let state = RouteState::new();
        state.begin_startup(Instant::now());
        assert!(!state.wait_until_ready());
        assert_eq!(state.epoch.load(Ordering::Acquire), 0);
        assert!(!state.wait_until_ready());
        state.epoch.store(STARTING + 1, Ordering::Release);
        state.finish_startup();
        assert!(state.wait_until_ready());
    }
}
