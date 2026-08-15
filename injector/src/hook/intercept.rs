use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use log::{debug, warn};
use nix::unistd::Pid;

use super::binder::{
    _ioc_dir, _ioc_nr, _ioc_size, binder_node_debug_info, binder_ptr_cookie,
    binder_transaction_data, binder_transaction_data_secctx, binder_transaction_data_sg,
    binder_version, binder_write_read, format_target, log_write_transaction,
    preview_transaction_parcel, BC_ACQUIRE_DONE_CMD, BC_FREE_BUFFER_NR, BC_REPLY_NR,
    BC_REPLY_SG_NR, BC_TRANSACTION_NR, BC_TRANSACTION_SG_NR, BINDER_GET_NODE_DEBUG_INFO,
    BINDER_VERSION, BINDER_WRITE_READ, BR_ACQUIRE_NR, BR_DEAD_REPLY_NR, BR_FAILED_REPLY_NR,
    BR_FROZEN_REPLY_NR, BR_ONEWAY_SPAM_SUSPECT_NR, BR_REPLY_NR, BR_TRANSACTION_COMPLETE_CMD,
    BR_TRANSACTION_NR, BR_TRANSACTION_PENDING_FROZEN_NR, TF_ONE_WAY,
};
#[cfg(test)]
use super::binder::{BC_FREE_BUFFER_CMD, BC_REPLY_CMD, BR_NOOP_CMD, BR_TRANSACTION_CMD};
use super::rewrite::{
    abort_bc_reply, cancel_operation_publication_acquire_pending, clear_binder_fd_thread_state,
    clear_outbound_reply_buffers, commit_bc_reply, finish_operation_publication_probe,
    handle_bc_reply, handle_br_transaction, lookup_synthetic_target,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, next_operation_publication_probe_deadline,
    operation_publication_acquire_is_pending, operation_publication_pending_acquire,
    push_pending_frame, retire_binder_connection_publications,
    retire_synthetic_operation_retirement, take_operation_publication_probe,
    OperationPublicationProbe,
};
#[cfg(test)]
use super::rewrite::{
    bind_operation_publication_connection, finish_local_operation_publication,
    register_operation_publication_for_test, route_state_test_guard,
};
use super::{
    BinderFdToken, BinderStateKey, OLD_CLOSE, OLD_DUP, OLD_DUP2, OLD_DUP3, OLD_FCNTL,
    OLD_FDSAN_CLOSE, OLD_IOCTL,
};
use crate::hook::binder::{LocalBinderTarget, NativeBinderRetirement};

mod fd;
mod ioctl;

use fd::*;
pub(super) use fd::{
    new_close, new_dup, new_dup2, new_dup3, new_fcntl, new_fdsan_close,
    start_operation_publication_worker, wake_operation_publication_worker,
};
pub(super) use ioctl::new_ioctl;

struct PendingTransactionCompletion {
    is_reply: bool,
    expects_reply: bool,
    operation_target: Option<NativeBinderRetirement>,
}

#[derive(Clone, Copy)]
struct PreparedBcReply {
    frame_id: Option<u64>,
    data_ptr: usize,
    transaction: binder_transaction_data,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncTransactionState {
    PendingCompletion,
    AwaitingReply,
}

thread_local! {
    static PENDING_TRANSACTION_COMPLETIONS: RefCell<HashMap<BinderStateKey, VecDeque<PendingTransactionCompletion>>> = RefCell::default();
    static SYNC_TRANSACTIONS: RefCell<HashMap<BinderStateKey, Vec<SyncTransactionState>>> = RefCell::default();
    static PREPARED_BC_REPLIES: RefCell<HashMap<BinderStateKey, VecDeque<PreparedBcReply>>> = RefCell::default();
    static OBSERVED_BINDER_FD_TOKENS: RefCell<HashMap<c_int, BinderFdToken>> = RefCell::default();
    static PENDING_IOCTL_COPYBACKS: RefCell<HashMap<BinderStateKey, PendingIoctlCopyback>> = RefCell::default();
}

struct PendingIoctlCopyback {
    arg: usize,
    write_buffer: libc::c_ulong,
    read_buffer: libc::c_ulong,
    write_size: usize,
    read_size: usize,
    read: PendingReadCopyback,
    output: binder_write_read,
    read_effects: PendingReadEffects,
    freed_inbound_shadows: Vec<(usize, usize)>,
    ret: c_int,
    errno: c_int,
}

enum PendingReadCopyback {
    None,
    Unread { address: usize, len: usize },
    Processed { address: usize, data: Vec<u8> },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InboundTransactionShadowState {
    Staged,
    Live,
    KernelFreedPendingAck,
}

struct InboundTransactionShadow {
    payload: TransactionPayloadShadow,
    state: InboundTransactionShadowState,
}

struct PendingReadEffects {
    connection: BinderStateKey,
    staged_inbound_shadows: Vec<usize>,
    operation_acquires: Vec<NativeBinderRetirement>,
}

static INBOUND_TRANSACTION_SHADOWS: LazyLock<
    Mutex<HashMap<(BinderStateKey, usize), InboundTransactionShadow>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn copy_from_process(address: usize, destination: &mut [u8]) -> bool {
    crate::sys::read_process_exact(Pid::this(), address, destination).is_ok()
}

fn copy_to_process(address: usize, source: &[u8]) -> bool {
    crate::sys::write_process_exact(Pid::this(), address, source).is_ok()
}

const IOCTL_SCRATCH_POOL_LIMIT: usize = 4;

thread_local! {
    static IOCTL_SCRATCH_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

struct IoctlScratch(Vec<u8>);

impl IoctlScratch {
    fn acquire() -> Self {
        Self(IOCTL_SCRATCH_POOL.with(|pool| pool.borrow_mut().pop().unwrap_or_default()))
    }

    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for IoctlScratch {
    fn drop(&mut self) {
        let mut buffer = std::mem::take(&mut self.0);
        buffer.clear();
        IOCTL_SCRATCH_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < IOCTL_SCRATCH_POOL_LIMIT {
                pool.push(buffer);
            }
        });
    }
}

fn fill_process_buffer(buffer: &mut Vec<u8>, address: usize, size: usize) -> Result<(), c_int> {
    buffer.clear();
    if size == 0 {
        return Ok(());
    }
    buffer.try_reserve(size).map_err(|_| libc::ENOMEM)?;
    buffer.resize(size, 0);
    if copy_from_process(address, buffer) {
        Ok(())
    } else {
        buffer.clear();
        Err(libc::EFAULT)
    }
}

fn copy_process_buffer(address: usize, size: usize) -> Result<Vec<u8>, c_int> {
    let mut buffer = Vec::new();
    fill_process_buffer(&mut buffer, address, size)?;
    Ok(buffer)
}

fn copy_process_c_string(address: usize) -> Option<String> {
    if address == 0 {
        return None;
    }
    let mut bytes = Vec::new();
    while bytes.len() < 4096 {
        let current = address.checked_add(bytes.len())?;
        let chunk_len = (4096 - bytes.len()).min(256).min(4096 - (current & 4095));
        let mut chunk = [0; 256];
        if !copy_from_process(current, &mut chunk[..chunk_len]) {
            return None;
        }
        if let Some(end) = chunk[..chunk_len].iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk[..chunk_len]);
    }
    None
}

fn copy_process_value(value: *const binder_write_read) -> Option<binder_write_read> {
    if value.is_null() {
        return None;
    }
    let mut copy: binder_write_read = unsafe { std::mem::zeroed() };
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut copy as *mut binder_write_read).cast::<u8>(),
            size_of::<binder_write_read>(),
        )
    };
    copy_from_process(value as usize, bytes).then_some(copy)
}

fn write_process_value<T: Copy>(destination: *mut T, value: &T) -> bool {
    let bytes =
        unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
    copy_to_process(destination as usize, bytes)
}

fn retry_pending_ioctl_copyback(
    fd: c_int,
    connection: BinderStateKey,
    arg: *mut c_void,
) -> Option<c_int> {
    let mut pending = PENDING_IOCTL_COPYBACKS.with(|slot| slot.borrow_mut().remove(&connection))?;
    if pending.arg != arg as usize {
        PENDING_IOCTL_COPYBACKS.with(|slot| {
            slot.borrow_mut().insert(connection, pending);
        });
        unsafe { *libc::__errno() = libc::EBUSY };
        return Some(-1);
    }

    let current = copy_process_value(arg.cast::<binder_write_read>());
    let identity_matches = current.is_some_and(|current| {
        current.write_buffer == pending.write_buffer
            && current.read_buffer == pending.read_buffer
            && current.write_size == pending.write_size
            && current.read_size == pending.read_size
    });
    if !identity_matches {
        PENDING_IOCTL_COPYBACKS.with(|slot| {
            slot.borrow_mut().insert(connection, pending);
        });
        unsafe { *libc::__errno() = libc::EFAULT };
        return Some(-1);
    }

    let (read, read_ok, effects) =
        match std::mem::replace(&mut pending.read, PendingReadCopyback::None) {
            PendingReadCopyback::None => (PendingReadCopyback::None, true, None),
            PendingReadCopyback::Processed { address, data } => {
                let copied = copy_to_process(address, &data);
                (
                    PendingReadCopyback::Processed { address, data },
                    copied,
                    None,
                )
            }
            PendingReadCopyback::Unread { address, len } => match copy_process_buffer(address, len)
            {
                Ok(mut data) => {
                    let effects = unsafe { ioctl::parse_read_buffer(fd, &mut data) };
                    let copied = copy_to_process(address, &data);
                    (
                        PendingReadCopyback::Processed { address, data },
                        copied,
                        Some(effects),
                    )
                }
                Err(_) => (PendingReadCopyback::Unread { address, len }, false, None),
            },
        };
    pending.read = read;
    if let Some(effects) = effects {
        pending.read_effects = effects;
    }
    let counters_ok =
        read_ok && write_process_value(arg.cast::<binder_write_read>(), &pending.output);
    if !counters_ok {
        PENDING_IOCTL_COPYBACKS.with(|slot| {
            slot.borrow_mut().insert(connection, pending);
        });
        unsafe { *libc::__errno() = libc::EFAULT };
        return Some(-1);
    }

    pending.read_effects.commit();
    unsafe { *libc::__errno() = pending.errno };
    Some(pending.ret)
}

struct TransactionPayloadShadow {
    data: Vec<u8>,
    offsets: Vec<usize>,
    original_buffer: libc::c_ulong,
    original_offsets: libc::c_ulong,
}

impl TransactionPayloadShadow {
    unsafe fn read(tr: &binder_transaction_data) -> Option<Self> {
        let original_buffer = tr.data.ptr.buffer;
        let original_offsets = tr.data.ptr.offsets;
        let data = copy_process_buffer(original_buffer as usize, tr.data_size).ok()?;
        if !tr.offsets_size.is_multiple_of(size_of::<usize>()) {
            return None;
        }
        let mut offsets = Vec::new();
        let count = tr.offsets_size / size_of::<usize>();
        offsets.try_reserve_exact(count).ok()?;
        offsets.resize(count, 0);
        let offset_bytes =
            std::slice::from_raw_parts_mut(offsets.as_mut_ptr().cast::<u8>(), tr.offsets_size);
        if !copy_from_process(original_offsets as usize, offset_bytes) {
            return None;
        }
        Some(Self {
            data,
            offsets,
            original_buffer,
            original_offsets,
        })
    }

    unsafe fn install(&mut self, tr: &mut binder_transaction_data) {
        if tr.data_size != 0 {
            tr.data.ptr.buffer = self.data.as_mut_ptr() as libc::c_ulong;
        }
        if tr.offsets_size != 0 {
            tr.data.ptr.offsets = self.offsets.as_mut_ptr() as libc::c_ulong;
        }
    }

    unsafe fn restore(&self, tr: &mut binder_transaction_data) {
        if tr.data_size != 0 && tr.data.ptr.buffer == self.data.as_ptr() as libc::c_ulong {
            tr.data.ptr.buffer = self.original_buffer;
        }
        if tr.offsets_size != 0 && tr.data.ptr.offsets == self.offsets.as_ptr() as libc::c_ulong {
            tr.data.ptr.offsets = self.original_offsets;
        }
    }

    fn data_ptr(&self) -> usize {
        self.data.as_ptr() as usize
    }
}

fn retain_inbound_transaction_shadow(
    connection: BinderStateKey,
    shadow: TransactionPayloadShadow,
) -> usize {
    debug_assert!(!shadow.data.is_empty());
    let shadow_buffer = shadow.data_ptr();
    let key = (connection, shadow_buffer);
    let previous = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned")
        .insert(
            key,
            InboundTransactionShadow {
                payload: shadow,
                state: InboundTransactionShadowState::Staged,
            },
        );
    debug_assert!(previous.is_none());
    shadow_buffer
}

fn publish_inbound_transaction_shadows(connection: BinderStateKey, shadows: &[usize]) {
    let mut entries = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned");
    for shadow_buffer in shadows {
        if let Some(shadow) = entries.get_mut(&(connection, *shadow_buffer)) {
            if shadow.state == InboundTransactionShadowState::Staged {
                shadow.state = InboundTransactionShadowState::Live;
            }
        }
    }
}

fn inbound_transaction_original_buffer(
    connection: BinderStateKey,
    shadow_buffer: usize,
) -> Option<libc::c_ulong> {
    INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned")
        .get(&(connection, shadow_buffer))
        .filter(|shadow| shadow.state == InboundTransactionShadowState::Live)
        .map(|shadow| shadow.payload.original_buffer)
}

#[cfg(test)]
fn clear_inbound_transaction_shadows(connection: BinderStateKey) {
    INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned")
        .retain(|(shadow_connection, _), _| *shadow_connection != connection);
}

impl PendingReadEffects {
    fn new(connection: BinderStateKey) -> Self {
        Self {
            connection,
            staged_inbound_shadows: Vec::new(),
            operation_acquires: Vec::new(),
        }
    }

    fn commit(&mut self) {
        publish_inbound_transaction_shadows(self.connection, &self.staged_inbound_shadows);
        self.staged_inbound_shadows.clear();
        self.operation_acquires.clear();
    }
}

impl Drop for PendingReadEffects {
    fn drop(&mut self) {
        {
            let mut entries = INBOUND_TRANSACTION_SHADOWS
                .lock()
                .expect("inbound transaction shadow map poisoned");
            for shadow_buffer in self.staged_inbound_shadows.drain(..) {
                let key = (self.connection, shadow_buffer);
                if entries
                    .get(&key)
                    .is_some_and(|shadow| shadow.state == InboundTransactionShadowState::Staged)
                {
                    entries.remove(&key);
                }
            }
        }

        let canceled_acquire = !self.operation_acquires.is_empty();
        for retirement in self.operation_acquires.drain(..) {
            cancel_operation_publication_acquire_pending(retirement);
        }
        if canceled_acquire && binder_connection_cleanup_ready(self.connection) {
            retire_binder_connection_publications(self.connection);
        }
    }
}

impl Drop for PendingIoctlCopyback {
    fn drop(&mut self) {
        ioctl::complete_inbound_free_buffers(
            self.read_effects.connection,
            &self.freed_inbound_shadows,
            self.output.write_consumed,
        );
    }
}

fn observed_binder_fd_token(fd: c_int) -> BinderFdToken {
    OBSERVED_BINDER_FD_TOKENS
        .with(|observed| observed.borrow().get(&fd).copied())
        .unwrap_or_else(|| binder_fd_token(fd))
}

fn binder_state_key(fd: c_int) -> BinderStateKey {
    observed_binder_fd_token(fd).connection
}

fn reset_current_thread_binder_state(connection: BinderStateKey) {
    ioctl::abort_prepared_bc_replies_for_connection(connection);
    clear_binder_fd_thread_state(connection);
    PENDING_IOCTL_COPYBACKS.with(|pending| {
        pending.borrow_mut().remove(&connection);
    });
    SYNC_TRANSACTIONS.with(|transactions| {
        transactions.borrow_mut().remove(&connection);
    });
    let completions = PENDING_TRANSACTION_COMPLETIONS
        .with(|pending| pending.borrow_mut().remove(&connection))
        .unwrap_or_default();
    for target in completions
        .into_iter()
        .filter_map(|completion| completion.operation_target)
    {
        retire_synthetic_operation_retirement(target);
    }
    debug!("event=binder cleared stale thread state for connection={connection}");
}

fn forget_current_thread_binder_fd(fd: c_int, retired: Option<BinderStateKey>) {
    if let Some(connection) = retired {
        reset_current_thread_binder_state(connection);
        if binder_connection_cleanup_ready(connection) {
            retire_binder_connection_publications(connection);
        }
    }
    OBSERVED_BINDER_FD_TOKENS.with(|observed| {
        observed.borrow_mut().remove(&fd);
    });
}

fn cleanup_retired_current_thread_connections() {
    let mut connections = HashSet::new();
    PENDING_TRANSACTION_COMPLETIONS.with(|state| {
        connections.extend(state.borrow().keys().copied());
    });
    SYNC_TRANSACTIONS.with(|state| {
        connections.extend(state.borrow().keys().copied());
    });
    PREPARED_BC_REPLIES.with(|state| {
        connections.extend(state.borrow().keys().copied());
    });
    PENDING_IOCTL_COPYBACKS.with(|state| {
        connections.extend(state.borrow().keys().copied());
    });
    OBSERVED_BINDER_FD_TOKENS.with(|state| {
        connections.extend(state.borrow().values().map(|token| token.connection));
    });

    for connection in connections
        .into_iter()
        .filter(|connection| binder_connection_cleanup_ready(*connection))
    {
        reset_current_thread_binder_state(connection);
        OBSERVED_BINDER_FD_TOKENS.with(|observed| {
            observed
                .borrow_mut()
                .retain(|_, token| token.connection != connection);
        });
    }
}

fn synchronize_binder_fd_generation(fd: c_int) -> Result<BinderFdToken, BinderFdToken> {
    let token = binder_fd_token(fd);
    let previous = OBSERVED_BINDER_FD_TOKENS.with(|observed| observed.borrow().get(&fd).copied());
    if let Some(previous) = previous.filter(|previous| *previous != token) {
        if binder_connection_is_retired(previous) {
            reset_current_thread_binder_state(previous.connection);
        }
        OBSERVED_BINDER_FD_TOKENS.with(|observed| {
            observed.borrow_mut().insert(fd, token);
        });
        return Err(previous);
    }
    if previous.is_none() {
        OBSERVED_BINDER_FD_TOKENS.with(|observed| {
            observed.borrow_mut().insert(fd, token);
        });
    }
    Ok(token)
}

#[cfg(test)]
static SYNTHETIC_REPLY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
fn reset_binder_fd_for_test(fd: c_int) {
    let retired = invalidate_binder_fd_token(binder_fd_token(fd));
    forget_current_thread_binder_fd(fd, retired);
}
