use super::binder::{
    _ioc_dir, _ioc_nr, _ioc_size, binder_transaction_data, binder_transaction_data_secctx,
    binder_transaction_data_sg, binder_version, binder_write_read, log_write_transaction,
    BC_REPLY_NR, BC_REPLY_SG_NR, BC_TRANSACTION_NR, BC_TRANSACTION_SG_NR, BINDER_VERSION,
    BINDER_WRITE_READ, BR_TRANSACTION_NR,
};
use super::rewrite::{clear_binder_fd_thread_state, discard_received_frame};
use super::{
    BinderFdToken, BinderStateKey, OLD_CLOSE, OLD_DUP, OLD_DUP2, OLD_DUP3, OLD_FCNTL,
    OLD_FDSAN_CLOSE, OLD_IOCTL,
};
use crate::hook::binder::LocalBinderTarget;
use log::debug;
use nix::unistd::Pid;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::ops::{Deref, DerefMut, Range};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};

pub(in crate::hook) use fd::is_native_binder_connection;
use fd::*;
pub(super) use fd::{new_close, new_dup, new_dup2, new_dup3, new_fcntl, new_fdsan_close};
pub(super) use ioctl::new_ioctl;

mod fd;
mod ioctl;

#[cfg(test)]
use super::binder::TF_ONE_WAY;

thread_local! {
    static OBSERVED_BINDER_FD_TOKENS: RefCell<HashMap<c_int, BinderFdToken>> = RefCell::default();
}

struct PendingReadEffects {
    frames: Vec<u64>,
}

fn next_binder_command(
    bytes: &[u8],
    offset: &mut usize,
) -> anyhow::Result<Option<(u32, Range<usize>)>> {
    if *offset == bytes.len() {
        return Ok(None);
    }
    let remaining = bytes.len() - *offset;
    if remaining < size_of::<u32>() {
        anyhow::bail!("truncated binder command header: remaining={remaining}");
    }
    let cmd = u32::from_ne_bytes(
        bytes[*offset..*offset + size_of::<u32>()].try_into().expect("checked command word size"),
    );
    let start = *offset + size_of::<u32>();
    let size = _ioc_size(cmd);
    if size > bytes.len() - start {
        anyhow::bail!(
            "truncated binder command payload: nr={} size={size} remaining={}",
            _ioc_nr(cmd),
            bytes.len() - start
        );
    }
    *offset = start + size;
    Ok(Some((cmd, start..*offset)))
}

fn copy_from_process(address: usize, destination: &mut [u8]) -> anyhow::Result<()> {
    crate::sys::read_process_exact(Pid::this(), address, destination)
}

fn copy_to_process(address: usize, source: &[u8]) -> anyhow::Result<()> {
    crate::sys::write_process_exact(Pid::this(), address, source)
}

fn zeroed_buffer(size: usize) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .unwrap_or_else(|error| panic!("Binder shadow allocation failed: size={size}: {error}"));
    buffer.resize(size, 0);
    buffer
}

fn copy_process_buffer(address: usize, size: usize) -> anyhow::Result<Vec<u8>> {
    let mut buffer = zeroed_buffer(size);
    copy_from_process(address, &mut buffer)?;
    Ok(buffer)
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
    copy_from_process(value as usize, bytes).ok().map(|()| copy)
}

fn write_process_value<T: Copy>(destination: *mut T, value: &T) -> anyhow::Result<()> {
    let bytes =
        unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
    copy_to_process(destination as usize, bytes)
}

impl PendingReadEffects {
    fn new() -> Self {
        Self { frames: Vec::new() }
    }

    fn commit(&mut self) {
        for frame in self.frames.drain(..) {
            crate::hook::rewrite::pending::mark_delivered(frame);
        }
    }
}

impl Drop for PendingReadEffects {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            discard_received_frame(frame);
        }
    }
}

#[cfg(test)]
fn observed_binder_fd_token(fd: c_int) -> BinderFdToken {
    OBSERVED_BINDER_FD_TOKENS
        .try_with(|observed| observed.borrow().get(&fd).copied())
        .ok()
        .flatten()
        .unwrap_or_else(|| binder_fd_token(fd))
}

#[cfg(test)]
fn binder_state_key(fd: c_int) -> BinderStateKey {
    observed_binder_fd_token(fd).connection
}

fn reset_current_thread_binder_state(connection: BinderStateKey) {
    clear_binder_fd_thread_state(connection);
    debug!("event=binder cleared stale thread state for connection={connection}");
}

fn forget_current_thread_binder_fd(fd: c_int, retired: Option<BinderStateKey>) {
    if let Some(connection) = retired {
        if binder_connection_cleanup_ready(connection) {
            reset_current_thread_binder_state(connection);
            crate::hook::binder::retire_receivers(connection);
        }
    }
    let _ = OBSERVED_BINDER_FD_TOKENS.try_with(|observed| {
        observed.borrow_mut().remove(&fd);
    });
}

fn cleanup_retired_current_thread_connections() {
    let mut connections = HashSet::new();
    let _ = OBSERVED_BINDER_FD_TOKENS.try_with(|state| {
        connections.extend(state.borrow().values().map(|token| token.connection));
    });

    for connection in
        connections.into_iter().filter(|connection| binder_connection_cleanup_ready(*connection))
    {
        reset_current_thread_binder_state(connection);
        let _ = OBSERVED_BINDER_FD_TOKENS.try_with(|observed| {
            observed.borrow_mut().retain(|_, token| token.connection != connection);
        });
    }
}

fn synchronize_binder_fd_generation(token: BinderFdToken) {
    let fd = token.fd;
    let previous =
        OBSERVED_BINDER_FD_TOKENS.with(|observed| observed.borrow_mut().insert(fd, token));
    if let Some(previous) = previous.filter(|previous| *previous != token) {
        if binder_connection_is_retired(previous)
            && binder_connection_cleanup_ready(previous.connection)
        {
            reset_current_thread_binder_state(previous.connection);
        }
    }
}

#[cfg(test)]
pub(in crate::hook) mod tests {
    use libc::c_int;
    use std::sync::Mutex;

    pub(super) use crate::hook::binder::tests::{BC_FREE_BUFFER_CMD, BC_REPLY_CMD, BR_NOOP_CMD};

    pub(super) static SYNTHETIC_REPLY_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub(super) fn reset_binder_fd_for_test(fd: c_int) {
        let retired = super::invalidate_binder_fd_token(super::binder_fd_token(fd));
        super::forget_current_thread_binder_fd(fd, retired);
    }
}
