use super::read::{complete_transaction_submission, observe_operation_acquire};
use super::*;
use crate::hook::intercept::fd::tests::{binder_fd_token_is_current, invalidate_binder_fd};
use crate::hook::intercept::tests::{
    bind_operation_publication_connection, clear_inbound_transaction_shadows,
    finish_local_operation_publication, register_operation_publication_for_test,
    reset_binder_fd_for_test, BC_FREE_BUFFER_CMD, BC_REPLY_CMD, BR_NOOP_CMD, BR_TRANSACTION_CMD,
    SYNTHETIC_REPLY_TEST_LOCK,
};
use crate::hook::rewrite::tests::{
    pending_reply_frame_claims_for_test, pending_reply_frame_count_for_test,
    reset_pending_reply_frames_for_test,
};

mod completion;
mod copyback;
mod fd_generation;
mod shadow_copyback;
mod write_read;

static CAPTURED_REPLY_DATA: Mutex<Option<Vec<u8>>> = Mutex::new(None);

unsafe extern "C" fn capture_reply_ioctl(_fd: c_int, request: c_int, arg: *mut c_void) -> c_int {
    if request != BINDER_WRITE_READ as c_int || arg.is_null() {
        return -1;
    }

    let bwr = &mut *(arg as *mut binder_write_read);
    let write = if bwr.write_size == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(bwr.write_buffer as *const u8, bwr.write_size)
    };
    let mut offset = 0usize;
    let mut captured = None;
    while offset + size_of::<u32>() <= write.len() {
        let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
        offset += size_of::<u32>();
        match cmd {
            BC_FREE_BUFFER_CMD => {
                offset = offset.saturating_add(size_of::<libc::c_ulong>());
            }
            BC_REPLY_CMD => {
                if offset + size_of::<binder_transaction_data>() > write.len() {
                    return -1;
                }
                let tr = std::ptr::read_unaligned(
                    write.as_ptr().add(offset) as *const binder_transaction_data
                );
                offset += size_of::<binder_transaction_data>();
                captured = Some(
                    std::slice::from_raw_parts(tr.data.ptr.buffer as *const u8, tr.data_size)
                        .to_vec(),
                );
            }
            _ => return -1,
        }
    }

    if captured.is_some() {
        *CAPTURED_REPLY_DATA
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = captured;
    }
    bwr.write_consumed = bwr.write_size;
    0
}

pub(super) fn drain_transaction_completions(fd: c_int) {
    while complete_transaction_submission(fd).is_some() {}
    abort_prepared_bc_replies(fd);
    let connection = binder_state_key(fd);
    clear_outbound_reply_buffers(connection);
    SYNC_TRANSACTIONS.with(|transactions| {
        transactions.borrow_mut().remove(&connection);
    });
}

pub(super) fn push_unaligned<T: Copy>(out: &mut Vec<u8>, value: &T) {
    let start = out.len();
    out.resize(start + size_of::<T>(), 0);
    // SAFETY: resize allocated space for T at start, and write_unaligned permits
    // any alignment.
    unsafe {
        std::ptr::write_unaligned(out.as_mut_ptr().add(start) as *mut T, *value);
    }
}
