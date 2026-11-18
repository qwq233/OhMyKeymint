use super::*;
use std::os::unix::fs::MetadataExt;

#[derive(Default)]
pub(super) struct BinderFdLifecycleState {
    pub(super) generation: u64,
    pub(super) in_flight: usize,
    pub(super) retired: bool,
}

pub(super) struct BinderFdLifecycle {
    pub(super) connection: BinderStateKey,
    pub(super) state: Mutex<BinderFdLifecycleState>,
    // Closing a Binder dup flushes and wakes every looper, so keep one pin per connection.
    pub(super) pinned_fd: OnceLock<c_int>,
    native: OnceLock<bool>,
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
        native: OnceLock::new(),
    });
    registry.by_connection.insert(lifecycle.connection, lifecycle.clone());
    registry.by_fd.insert(fd, lifecycle.clone());
    lifecycle
}

#[cfg(test)]
pub(super) fn binder_fd_token(fd: c_int) -> BinderFdToken {
    let mut registry = binder_fd_registry();
    let lifecycle = ensure_binder_fd_lifecycle(&mut registry, fd);
    let generation = lifecycle.state.lock().expect("binder fd lifecycle poisoned").generation;
    BinderFdToken { fd, generation, connection: lifecycle.connection }
}

pub(in crate::hook) fn is_native_binder_connection(connection: BinderStateKey) -> bool {
    binder_fd_registry()
        .by_connection
        .get(&connection)
        .and_then(|lifecycle| lifecycle.native.get().copied())
        .unwrap_or(false)
}

fn is_native_driver(fd: c_int) -> bool {
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut info) } < 0 {
        return false;
    }
    if info.st_mode & libc::S_IFMT == libc::S_IFCHR {
        for (path, native) in
            [("/dev/binder", true), ("/dev/hwbinder", false), ("/dev/vndbinder", true)]
        {
            if std::fs::metadata(path).is_ok_and(|node| node.rdev() == info.st_rdev) {
                return native;
            }
        }
    }
    false
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
    pub(super) token: BinderFdToken,
    pinned_fd: c_int,
}

impl BinderIoctlGuard {
    pub(super) fn begin(fd: c_int) -> Option<Self> {
        let mut registry = binder_fd_registry();
        let lifecycle = ensure_binder_fd_lifecycle(&mut registry, fd);
        let mut state = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
        assert!(!state.retired, "active Binder fd refers to a retired connection: fd={fd}");
        let token =
            BinderFdToken { fd, generation: state.generation, connection: lifecycle.connection };
        let pinned_fd = if let Some(&pinned_fd) = lifecycle.pinned_fd.get() {
            pinned_fd
        } else {
            let raw_pin = unsafe {
                libc::syscall(libc::SYS_fcntl, token.fd, libc::F_DUPFD_CLOEXEC, 0) as c_int
            };
            #[cfg(not(test))]
            if raw_pin < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBADF) {
                    drop(state);
                    registry.by_fd.remove(&fd);
                    retire_unaliased_lifecycle(&mut registry, &lifecycle);
                    return None;
                }
                panic!("failed to pin Binder fd={fd} connection={}: {error}", token.connection);
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
        lifecycle.native.get_or_init(|| is_native_driver(pinned_fd));
        state.in_flight += 1;
        drop(state);
        drop(registry);
        Some(Self { lifecycle, token, pinned_fd })
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
            reset_current_thread_binder_state(connection);
            crate::hook::binder::retire_receivers(connection);
        }
        unsafe {
            *libc::__errno() = error;
        }
    }
}

/// # Safety
///
/// Called by the installed close hook with the same ABI and fd validity
/// requirements as libc close.
pub(in crate::hook) unsafe extern "C" fn new_close(fd: c_int) -> c_int {
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

/// # Safety
///
/// Called by the installed fdsan hook with the same ABI and ownership-tag
/// requirements as `android_fdsan_close_with_tag`.
pub(in crate::hook) unsafe extern "C" fn new_fdsan_close(fd: c_int, tag: u64) -> c_int {
    let old_close = OLD_FDSAN_CLOSE.load(Ordering::Relaxed);
    if old_close.is_null() {
        return new_close(fd);
    }
    let close: unsafe extern "C" fn(c_int, u64) -> c_int = std::mem::transmute(old_close);
    close_with_binder_fd_lifecycle(fd, || close(fd, tag))
}

/// # Safety
///
/// Called by the installed dup hook with the same ABI and fd validity
/// requirements as libc dup.
pub(in crate::hook) unsafe extern "C" fn new_dup(fd: c_int) -> c_int {
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

/// # Safety
///
/// Called by the installed dup2 hook with the same ABI and fd validity
/// requirements as libc dup2.
pub(in crate::hook) unsafe extern "C" fn new_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
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

/// # Safety
///
/// Called by the installed dup3 hook with the same ABI and fd/flag validity
/// requirements as libc dup3.
pub(in crate::hook) unsafe extern "C" fn new_dup3(
    old_fd: c_int,
    new_fd: c_int,
    flags: c_int,
) -> c_int {
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

/// # Safety
///
/// Called by the installed fcntl hook. Bionic ignores `arg` for commands that
/// do not consume the variadic third argument.
pub(in crate::hook) unsafe extern "C" fn new_fcntl(
    fd: c_int,
    command: c_int,
    arg: libc::c_ulong,
) -> c_int {
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

#[cfg(test)]
pub(super) mod tests {
    use crate::hook::intercept::tests::{reset_binder_fd_for_test, SYNTHETIC_REPLY_TEST_LOCK};
    use std::sync::{Barrier, LazyLock};
    use std::time::Duration;

    use super::*;

    #[test]
    fn blocking_binder_read_does_not_hold_the_fd_lifecycle_lock() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let fd = pipe[0];
        reset_binder_fd_for_test(fd);
        let token = binder_fd_token(fd);
        let lifecycle = existing_binder_fd_lifecycle(fd).unwrap();
        let ioctl_thread = std::thread::spawn(move || unsafe {
            let guard = BinderIoctlGuard::begin(token.fd).unwrap();
            blocking_ioctl(guard.fd(), BINDER_WRITE_READ as c_int, std::ptr::null_mut())
        });
        PINNED_IOCTL_ENTERED.wait();
        let pinned_fd = *lifecycle.pinned_fd.get().unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let close_thread = std::thread::spawn(move || {
            let result = unsafe { close_with_binder_fd_lifecycle(fd, || 7) };
            done_tx.send(result).unwrap();
        });
        let close_result = done_rx.recv_timeout(Duration::from_secs(1));
        assert!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) } >= 0);
        PINNED_IOCTL_RELEASE.wait();

        assert_eq!(ioctl_thread.join().unwrap(), 0);
        close_thread.join().unwrap();
        assert_eq!(close_result.unwrap(), 7);
        drop(lifecycle);
        assert_eq!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) }, -1);
        unsafe {
            libc::syscall(libc::SYS_close, pipe[0]);
            libc::syscall(libc::SYS_close, pipe[1]);
        }
        reset_binder_fd_for_test(fd);
    }

    #[test]
    fn binder_ioctl_reuses_one_pin_until_connection_retires() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let fd = pipe[0];
        reset_binder_fd_for_test(fd);
        let token = binder_fd_token(fd);

        let first = BinderIoctlGuard::begin(token.fd).unwrap();
        let pinned_fd = first.fd();
        assert_ne!(pinned_fd, fd);
        drop(first);
        assert!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) } >= 0);

        let second = BinderIoctlGuard::begin(token.fd).unwrap();
        assert_eq!(second.fd(), pinned_fd);
        drop(second);

        assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
        assert_eq!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        unsafe { libc::close(pipe[1]) };
    }

    #[test]
    fn real_fd_replacement_selects_the_current_lifecycle_and_preserves_inflight_pin() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for hold_old in [false, true] {
            let mut first = [-1; 2];
            let mut second = [-1; 2];
            assert_eq!(unsafe { libc::pipe2(first.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            assert_eq!(unsafe { libc::pipe2(second.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let fd = first[0];
            reset_binder_fd_for_test(fd);
            reset_binder_fd_for_test(second[0]);
            let old_token = binder_fd_token(fd);
            let source = binder_fd_token(second[0]);
            let old_guard = hold_old.then(|| BinderIoctlGuard::begin(fd).unwrap());
            assert_eq!(
                unsafe {
                    duplicate_binder_fd_with_lifecycle(second[0], Some(fd), || {
                        libc::dup2(second[0], fd)
                    })
                },
                fd
            );
            let current = BinderIoctlGuard::begin(fd).unwrap();
            assert_ne!(current.token.connection, old_token.connection);
            assert_eq!(current.token.connection, source.connection);
            assert_eq!(unsafe { libc::write(second[1], b"n".as_ptr().cast(), 1) }, 1);
            let mut value = 0_u8;
            assert_eq!(unsafe { libc::read(current.fd(), (&mut value as *mut u8).cast(), 1) }, 1);
            assert_eq!(value, b'n');
            if let Some(old) = old_guard {
                assert_eq!(unsafe { libc::write(first[1], b"o".as_ptr().cast(), 1) }, 1);
                assert_eq!(unsafe { libc::read(old.fd(), (&mut value as *mut u8).cast(), 1) }, 1);
                assert_eq!(value, b'o');
                drop(old);
            }
            drop(current);
            assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
            assert_eq!(
                unsafe { close_with_binder_fd_lifecycle(second[0], || libc::close(second[0])) },
                0
            );
            unsafe {
                libc::close(first[1]);
                libc::close(second[1]);
            }
            reset_binder_fd_for_test(fd);
            reset_binder_fd_for_test(second[0]);
        }
    }
    #[test]
    fn binder_fd_duplicated_before_first_io_shares_its_lifecycle() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = unsafe { libc::open(c"/dev/binder".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(fd >= 0, "test requires the Android Binder driver");
        assert!(existing_binder_fd_lifecycle(fd).is_none());

        let alias = unsafe { duplicate_binder_fd_with_lifecycle(fd, None, || libc::dup(fd)) };
        assert!(alias >= 0);
        let source = existing_binder_fd_lifecycle(fd).expect("source should be registered");
        let destination =
            existing_binder_fd_lifecycle(alias).expect("destination should inherit source");
        assert!(Arc::ptr_eq(&source, &destination));

        assert_eq!(unsafe { close_with_binder_fd_lifecycle(alias, || libc::close(alias)) }, 0);
        assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
    }

    #[test]
    fn binder_fd_close_and_replacement_serialize_with_ioctl() {
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let fd = 91;
        reset_binder_fd_for_test(fd);
        let original = binder_fd_token(fd);
        assert!(binder_fd_token_is_current(original));
        let lifecycle = binder_fd_lifecycle(fd);
        let ioctl = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let close_thread = std::thread::spawn(move || {
            let result = unsafe {
                close_with_binder_fd_lifecycle(fd, || {
                    started_tx.send(()).unwrap();
                    0
                })
            };
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.try_recv().is_err());
        drop(ioctl);
        assert_eq!(done_rx.recv().unwrap(), 0);
        close_thread.join().unwrap();
        assert!(!binder_fd_token_is_current(original));

        let after_close = binder_fd_token(fd);
        unsafe { *libc::__errno() = libc::EIO };
        assert_eq!(
            unsafe {
                duplicate_binder_fd_with_lifecycle(fd + 1, Some(fd), || {
                    *libc::__errno() = libc::EPERM;
                    -1
                })
            },
            -1
        );
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        assert!(binder_fd_token_is_current(after_close));
        assert_eq!(unsafe { duplicate_binder_fd_with_lifecycle(fd + 1, Some(fd), || fd) }, fd);
        assert!(!binder_fd_token_is_current(after_close));
        reset_binder_fd_for_test(fd);
        reset_binder_fd_for_test(fd + 1);
    }

    static PINNED_IOCTL_ENTERED: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));
    static PINNED_IOCTL_RELEASE: LazyLock<Barrier> = LazyLock::new(|| Barrier::new(2));

    unsafe extern "C" fn blocking_ioctl(_fd: c_int, _request: c_int, _arg: *mut c_void) -> c_int {
        PINNED_IOCTL_ENTERED.wait();
        PINNED_IOCTL_RELEASE.wait();
        0
    }

    fn binder_fd_lifecycle(fd: c_int) -> Arc<BinderFdLifecycle> {
        let mut registry = binder_fd_registry();
        ensure_binder_fd_lifecycle(&mut registry, fd)
    }

    fn existing_binder_fd_lifecycle(fd: c_int) -> Option<Arc<BinderFdLifecycle>> {
        binder_fd_registry().by_fd.get(&fd).cloned()
    }

    pub(in crate::hook::intercept) fn binder_fd_token_is_current(token: BinderFdToken) -> bool {
        existing_binder_fd_lifecycle(token.fd).is_some_and(|lifecycle| {
            lifecycle.connection == token.connection
                && lifecycle.state.lock().expect("binder fd lifecycle poisoned").generation
                    == token.generation
        })
    }

    pub(in crate::hook::intercept) fn invalidate_binder_fd(fd: c_int) {
        let _ = invalidate_binder_fd_token(binder_fd_token(fd));
    }

    #[test]
    fn driver_identity_uses_the_connection_pin_after_original_fd_closes() {
        use std::os::fd::IntoRawFd;
        let _guard =
            SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut checked = 0;
        for (path, expected) in [
            ("/dev/binder", Some(true)),
            ("/dev/hwbinder", Some(false)),
            ("/dev/vndbinder", Some(true)),
            ("/dev/null", None),
        ] {
            let Ok(file) = std::fs::OpenOptions::new().read(true).write(true).open(path) else {
                continue;
            };
            let fd = file.into_raw_fd();
            reset_binder_fd_for_test(fd);
            let token = binder_fd_token(fd);
            let pin = BinderIoctlGuard::begin(fd).unwrap();
            assert_eq!(is_native_binder_connection(token.connection), expected.unwrap_or(false));
            assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
            assert_eq!(is_native_binder_connection(token.connection), expected.unwrap_or(false));
            drop(pin);
            assert!(!is_native_binder_connection(token.connection));
            checked += 1;
        }
        assert!(checked >= 2);
    }
}
