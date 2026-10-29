use super::*;

#[cfg(test)]
pub(super) mod tests;

#[derive(Default)]
pub(super) struct BinderFdLifecycleState {
    pub(super) generation: u64,
    pub(super) in_flight: usize,
    pub(super) retired: bool,
    pub(super) protocol_error: bool,
}

pub(super) struct BinderFdLifecycle {
    pub(super) connection: BinderStateKey,
    pub(super) state: Mutex<BinderFdLifecycleState>,
    // Closing a Binder dup flushes and wakes every looper, so keep one pin per connection.
    pub(super) pinned_fd: OnceLock<c_int>,
}

impl Drop for BinderFdLifecycle {
    fn drop(&mut self) {
        let error = unsafe { *libc::__errno() };
        if let Some(&fd) = self.pinned_fd.get() {
            unsafe {
                libc::syscall(libc::SYS_close, fd);
            }
        }
        unsafe {
            *libc::__errno() = error;
        }
    }
}

#[derive(Default)]
struct BinderFdRegistry {
    by_fd: HashMap<c_int, Arc<BinderFdLifecycle>>,
    by_connection: HashMap<BinderStateKey, Arc<BinderFdLifecycle>>,
}

static NEXT_BINDER_CONNECTION: AtomicU64 = AtomicU64::new(1);
static BINDER_FD_REGISTRY: LazyLock<Mutex<BinderFdRegistry>> =
    LazyLock::new(|| Mutex::new(BinderFdRegistry::default()));
static OPERATION_PUBLICATION_WAKE: LazyLock<(Mutex<()>, Condvar)> =
    LazyLock::new(|| (Mutex::new(()), Condvar::new()));
static OPERATION_PUBLICATION_WORKER: OnceLock<Result<(), String>> = OnceLock::new();

pub(in crate::hook) fn wake_operation_publication_worker() {
    let (lock, wake) = &*OPERATION_PUBLICATION_WAKE;
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    wake.notify_one();
}

pub(in crate::hook) fn start_operation_publication_worker() -> Result<(), String> {
    match OPERATION_PUBLICATION_WORKER.get_or_init(|| {
        std::thread::Builder::new()
            .name("omk-binder-publication".to_string())
            .spawn(operation_publication_worker)
            .map(|_| ())
            .map_err(|error| format!("failed to start operation publication worker: {error}"))
    }) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.clone()),
    }
}

fn operation_publication_worker() {
    loop {
        wait_for_operation_publication_deadline();

        let old_ioctl = OLD_IOCTL.load(Ordering::Acquire);
        if old_ioctl.is_null() {
            warn!("event=synthetic operation publication worker stopped because original ioctl is unavailable");
            return;
        }
        let old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int =
            unsafe { std::mem::transmute(old_ioctl) };
        unsafe { super::ioctl::flush_native_binder_lifecycle(old_ioctl_fn) };
    }
}

fn wait_for_operation_publication_deadline() {
    let (lock, wake) = &*OPERATION_PUBLICATION_WAKE;
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    loop {
        match next_operation_publication_probe_deadline() {
            None => {
                guard = wake.wait(guard).unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Some(deadline) => {
                let now = Instant::now();
                if deadline <= now {
                    return;
                }
                let (next_guard, _) = wake
                    .wait_timeout(guard, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard = next_guard;
            }
        }
    }
}

struct SignalMaskGuard {
    previous: libc::sigset_t,
    active: bool,
}

impl SignalMaskGuard {
    fn block() -> Self {
        unsafe {
            let mut blocked = std::mem::zeroed();
            let mut previous = std::mem::zeroed();
            let active = libc::sigfillset(&mut blocked) == 0
                && libc::sigdelset(&mut blocked, libc::SIGKILL) == 0
                && libc::sigdelset(&mut blocked, libc::SIGSTOP) == 0
                && libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) == 0;
            Self { previous, active }
        }
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            }
        }
    }
}

struct BinderFdRegistryGuard {
    registry: MutexGuard<'static, BinderFdRegistry>,
    _signals: SignalMaskGuard,
}

impl BinderFdRegistryGuard {
    fn unlock(self) -> SignalMaskGuard {
        let Self { registry, _signals } = self;
        drop(registry);
        _signals
    }
}

impl Deref for BinderFdRegistryGuard {
    type Target = BinderFdRegistry;

    fn deref(&self) -> &Self::Target {
        &self.registry
    }
}

impl DerefMut for BinderFdRegistryGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registry
    }
}

fn binder_fd_registry() -> BinderFdRegistryGuard {
    let signals = SignalMaskGuard::block();
    let registry = BINDER_FD_REGISTRY.lock().expect("binder fd registry poisoned");
    BinderFdRegistryGuard { registry, _signals: signals }
}

fn ensure_binder_fd_lifecycle(
    registry: &mut BinderFdRegistry,
    fd: c_int,
) -> Arc<BinderFdLifecycle> {
    if let Some(lifecycle) = registry.by_fd.get(&fd) {
        return lifecycle.clone();
    }
    let lifecycle = Arc::new(BinderFdLifecycle {
        connection: NEXT_BINDER_CONNECTION.fetch_add(1, Ordering::Relaxed),
        state: Mutex::new(BinderFdLifecycleState::default()),
        pinned_fd: OnceLock::new(),
    });
    registry.by_connection.insert(lifecycle.connection, lifecycle.clone());
    registry.by_fd.insert(fd, lifecycle.clone());
    lifecycle
}

pub(super) fn binder_fd_token(fd: c_int) -> BinderFdToken {
    let mut registry = binder_fd_registry();
    let lifecycle = ensure_binder_fd_lifecycle(&mut registry, fd);
    let generation = lifecycle.state.lock().expect("binder fd lifecycle poisoned").generation;
    BinderFdToken { fd, generation, connection: lifecycle.connection }
}

pub(super) fn binder_connection_cleanup_ready(connection: BinderStateKey) -> bool {
    let registry = binder_fd_registry();
    let Some(lifecycle) = registry.by_connection.get(&connection) else {
        return true;
    };
    let state = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
    state.retired && state.in_flight == 0
}

pub(super) fn binder_connection_is_retired(token: BinderFdToken) -> bool {
    let registry = binder_fd_registry();
    let Some(lifecycle) = registry.by_connection.get(&token.connection) else {
        return true;
    };
    let state = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
    state.generation != token.generation || state.retired && state.in_flight == 0
}

fn retire_unaliased_lifecycle(
    registry: &mut BinderFdRegistry,
    lifecycle: &Arc<BinderFdLifecycle>,
) -> bool {
    if registry.by_fd.values().any(|candidate| Arc::ptr_eq(candidate, lifecycle)) {
        return false;
    }
    let mut state = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
    state.retired = true;
    state.generation = state.generation.wrapping_add(1);
    if state.in_flight == 0 {
        registry.by_connection.remove(&lifecycle.connection);
    }
    true
}

pub(super) fn invalidate_binder_fd_token(token: BinderFdToken) -> Option<BinderStateKey> {
    let mut registry = binder_fd_registry();
    let lifecycle = registry.by_fd.get(&token.fd).cloned()?;
    let generation = lifecycle.state.lock().expect("binder fd lifecycle poisoned").generation;
    if lifecycle.connection != token.connection || generation != token.generation {
        return None;
    }
    registry.by_fd.remove(&token.fd);
    retire_unaliased_lifecycle(&mut registry, &lifecycle).then_some(lifecycle.connection)
}

pub(super) unsafe fn close_with_binder_fd_lifecycle<F>(fd: c_int, close: F) -> c_int
where
    F: FnOnce() -> c_int,
{
    if fd < 0 {
        return close();
    }
    let mut registry = binder_fd_registry();
    let lifecycle = registry.by_fd.get(&fd).cloned();
    let result = close();
    let error = *libc::__errno();
    let retired = lifecycle.and_then(|lifecycle| {
        registry.by_fd.remove(&fd);
        retire_unaliased_lifecycle(&mut registry, &lifecycle).then_some(lifecycle.connection)
    });
    let signals = registry.unlock();
    forget_current_thread_binder_fd(fd, retired);
    drop(signals);
    *libc::__errno() = error;
    result
}

pub(super) unsafe fn duplicate_binder_fd_with_lifecycle<F>(
    old_fd: c_int,
    new_fd: Option<c_int>,
    duplicate: F,
) -> c_int
where
    F: FnOnce() -> c_int,
{
    unsafe fn is_binder_driver_fd(fd: c_int) -> bool {
        let saved_errno = *libc::__errno();
        let mut stat: libc::stat = std::mem::zeroed();
        let is_character_device =
            libc::fstat(fd, &mut stat) == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFCHR;
        let mut version = binder_version::default();
        let is_binder = is_character_device
            && libc::syscall(libc::SYS_ioctl, fd, BINDER_VERSION as libc::c_ulong, &mut version)
                == 0;
        *libc::__errno() = saved_errno;
        is_binder
    }

    if new_fd == Some(old_fd) {
        return duplicate();
    }
    let mut registry = binder_fd_registry();
    let source = registry.by_fd.get(&old_fd).cloned().or_else(|| {
        is_binder_driver_fd(old_fd).then(|| ensure_binder_fd_lifecycle(&mut registry, old_fd))
    });
    let result = duplicate();
    let error = *libc::__errno();
    let destination = new_fd.unwrap_or(result);
    let retired = (result >= 0)
        .then(|| {
            let previous = registry.by_fd.remove(&destination);
            if let Some(source) = source {
                registry.by_fd.insert(destination, source);
            }
            previous.and_then(|previous| {
                retire_unaliased_lifecycle(&mut registry, &previous).then_some(previous.connection)
            })
        })
        .flatten();
    let signals = registry.unlock();
    if result >= 0 {
        forget_current_thread_binder_fd(destination, retired);
    }
    drop(signals);
    *libc::__errno() = error;
    result
}

pub(super) struct BinderIoctlGuard {
    pub(super) lifecycle: Arc<BinderFdLifecycle>,
    pinned_fd: c_int,
}

impl BinderIoctlGuard {
    pub(super) fn begin(token: BinderFdToken) -> Result<Self, c_int> {
        let registry = binder_fd_registry();
        let lifecycle = registry.by_fd.get(&token.fd).ok_or(libc::EBADF)?.clone();
        if lifecycle.connection != token.connection {
            return Err(libc::ESTALE);
        }
        let mut state = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
        if state.retired || state.generation != token.generation {
            return Err(libc::ESTALE);
        }
        if state.protocol_error {
            return Err(libc::EPROTO);
        }
        let pinned_fd = if let Some(&pinned_fd) = lifecycle.pinned_fd.get() {
            pinned_fd
        } else {
            let raw_pin = unsafe {
                libc::syscall(libc::SYS_fcntl, token.fd, libc::F_DUPFD_CLOEXEC, 0) as c_int
            };
            #[cfg(not(test))]
            if raw_pin < 0 {
                return Err(unsafe { *libc::__errno() });
            }
            // Mock-ioctl tests use synthetic fd numbers; real-fd tests still exercise the pin.
            if raw_pin < 0 {
                token.fd
            } else {
                lifecycle
                    .pinned_fd
                    .set(raw_pin)
                    .expect("binder fd pin initialized once under registry lock");
                raw_pin
            }
        };
        state.in_flight += 1;
        drop(state);
        drop(registry);
        Ok(Self { lifecycle, pinned_fd })
    }

    pub(super) fn fd(&self) -> c_int {
        self.pinned_fd
    }
}

impl Drop for BinderIoctlGuard {
    fn drop(&mut self) {
        let error = unsafe { *libc::__errno() };
        let mut registry = binder_fd_registry();
        let mut state = self.lifecycle.state.lock().expect("binder fd lifecycle poisoned");
        state.in_flight = state.in_flight.saturating_sub(1);
        let retired = (state.retired && state.in_flight == 0).then_some(self.lifecycle.connection);
        if retired.is_some() {
            registry.by_connection.remove(&self.lifecycle.connection);
        }
        drop(state);
        drop(registry);
        if let Some(connection) = retired {
            retire_binder_connection_publications(connection);
        }
        unsafe {
            *libc::__errno() = error;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BinderIoctlCall {
    Called(c_int),
    Stale,
    Retired,
}

pub(super) unsafe fn call_binder_ioctl(
    token: BinderFdToken,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    request: c_int,
    arg: *mut c_void,
) -> BinderIoctlCall {
    let Ok(guard) = BinderIoctlGuard::begin(token) else {
        return BinderIoctlCall::Stale;
    };
    BinderIoctlCall::Called(old_ioctl_fn(guard.fd(), request, arg))
}

pub(super) unsafe fn call_binder_connection_ioctl(
    token: BinderFdToken,
    old_ioctl_fn: unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int,
    request: c_int,
    arg: *mut c_void,
) -> BinderIoctlCall {
    let (fd, lifecycle, generation) = {
        let registry = binder_fd_registry();
        let Some(lifecycle) = registry.by_connection.get(&token.connection).cloned() else {
            return BinderIoctlCall::Retired;
        };
        let fd = registry
            .by_fd
            .iter()
            .find_map(|(fd, candidate)| Arc::ptr_eq(candidate, &lifecycle).then_some(*fd));
        let Some(fd) = fd else {
            return BinderIoctlCall::Stale;
        };
        let generation = lifecycle.state.lock().expect("binder fd lifecycle poisoned").generation;
        (fd, lifecycle, generation)
    };
    let current = BinderFdToken { fd, generation, connection: lifecycle.connection };
    if generation != token.generation {
        return BinderIoctlCall::Retired;
    }
    call_binder_ioctl(current, old_ioctl_fn, request, arg)
}

pub(in crate::hook) unsafe fn new_close(fd: c_int) -> c_int {
    let mut old_close = OLD_CLOSE.load(Ordering::Relaxed);
    if old_close.is_null() {
        extern "C" {
            fn close(fd: c_int) -> c_int;
        }
        old_close = close as *mut c_void;
    }
    let close: unsafe extern "C" fn(c_int) -> c_int = std::mem::transmute(old_close);
    close_with_binder_fd_lifecycle(fd, || close(fd))
}

pub(in crate::hook) unsafe fn new_fdsan_close(fd: c_int, tag: u64) -> c_int {
    let old_close = OLD_FDSAN_CLOSE.load(Ordering::Relaxed);
    if old_close.is_null() {
        return new_close(fd);
    }
    let close: unsafe extern "C" fn(c_int, u64) -> c_int = std::mem::transmute(old_close);
    close_with_binder_fd_lifecycle(fd, || close(fd, tag))
}

pub(in crate::hook) unsafe fn new_dup(fd: c_int) -> c_int {
    let mut old_dup = OLD_DUP.load(Ordering::Relaxed);
    if old_dup.is_null() {
        extern "C" {
            fn dup(fd: c_int) -> c_int;
        }
        old_dup = dup as *mut c_void;
    }
    let dup: unsafe extern "C" fn(c_int) -> c_int = std::mem::transmute(old_dup);
    duplicate_binder_fd_with_lifecycle(fd, None, || dup(fd))
}

pub(in crate::hook) unsafe fn new_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    let mut old_dup2 = OLD_DUP2.load(Ordering::Relaxed);
    if old_dup2.is_null() {
        extern "C" {
            fn dup2(old_fd: c_int, new_fd: c_int) -> c_int;
        }
        old_dup2 = dup2 as *mut c_void;
    }
    let dup2: unsafe extern "C" fn(c_int, c_int) -> c_int = std::mem::transmute(old_dup2);
    duplicate_binder_fd_with_lifecycle(old_fd, Some(new_fd), || dup2(old_fd, new_fd))
}

pub(in crate::hook) unsafe fn new_dup3(old_fd: c_int, new_fd: c_int, flags: c_int) -> c_int {
    let mut old_dup3 = OLD_DUP3.load(Ordering::Relaxed);
    if old_dup3.is_null() {
        extern "C" {
            fn dup3(old_fd: c_int, new_fd: c_int, flags: c_int) -> c_int;
        }
        old_dup3 = dup3 as *mut c_void;
    }
    let dup3: unsafe extern "C" fn(c_int, c_int, c_int) -> c_int = std::mem::transmute(old_dup3);
    duplicate_binder_fd_with_lifecycle(old_fd, Some(new_fd), || dup3(old_fd, new_fd, flags))
}

pub(in crate::hook) unsafe fn new_fcntl(fd: c_int, command: c_int, arg: libc::c_ulong) -> c_int {
    let mut old_fcntl = OLD_FCNTL.load(Ordering::Relaxed);
    if old_fcntl.is_null() {
        extern "C" {
            fn fcntl(fd: c_int, command: c_int, arg: libc::c_ulong) -> c_int;
        }
        old_fcntl = fcntl as *mut c_void;
    }
    let fcntl: unsafe extern "C" fn(c_int, c_int, libc::c_ulong) -> c_int =
        std::mem::transmute(old_fcntl);
    if matches!(command, libc::F_DUPFD | libc::F_DUPFD_CLOEXEC) {
        duplicate_binder_fd_with_lifecycle(fd, None, || fcntl(fd, command, arg))
    } else {
        fcntl(fd, command, arg)
    }
}
