use super::super::tests::push_unaligned;
use super::*;
use crate::hook::intercept::tests::{
    bind_operation_publication_connection, clear_inbound_transaction_shadows,
    finish_local_operation_publication, register_operation_publication_for_test,
    BC_FREE_BUFFER_CMD, BC_REPLY_CMD, SYNTHETIC_REPLY_TEST_LOCK,
};
use crate::hook::rewrite::tests::reset_pending_reply_frames_for_test;

#[test]
fn write_parser_tracks_transaction_and_reply_completions() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = crate::tracker::tests::state_test_guard();
    reset_pending_reply_frames_for_test(0, 0);
    let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let mut write = Vec::new();
    let bc_transaction_cmd = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
    push_unaligned(&mut write, &bc_transaction_cmd);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_ACQUIRE_DONE_CMD);
    let acquire_target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
    let acquire_retirement = register_operation_publication_for_test(acquire_target);
    let connection = binder_state_key(20);
    bind_operation_publication_connection(acquire_retirement, connection);
    assert_eq!(
        mark_operation_publication_acquire_pending(acquire_target, connection),
        Some(acquire_retirement)
    );
    push_unaligned(
        &mut write,
        &binder_ptr_cookie { ptr: acquire_target.ptr, cookie: acquire_target.cookie },
    );

    let completions = unsafe { parse_write_buffer(20, &mut write) };
    assert_eq!(completions.len(), 3);
    assert_eq!(completions[0].1, None);
    assert!(completions[0].2);
    assert_eq!(completions[0].3, None);
    assert_eq!(completions[1].1, Some(0));
    assert!(!completions[1].2);
    assert_eq!(completions[1].3, None);
    assert_eq!(completions[2].3, Some(acquire_retirement));
    abort_prepared_bc_replies(20);
    cancel_operation_publication_acquire_pending(acquire_retirement);
    finish_local_operation_publication(acquire_retirement);
}

#[test]
fn inbound_shadow_free_is_translated_and_released_only_after_consumption() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let connection = binder_state_key(20);
    clear_inbound_transaction_shadows(connection);
    let original = [1u8, 2, 3, 4];
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = original.len();
    tr.data.ptr.buffer = original.as_ptr() as libc::c_ulong;
    let shadow = unsafe { TransactionPayloadShadow::read(&tr) }
        .expect("readable transaction should create a shadow");
    let shadow_buffer = retain_inbound_transaction_shadow(connection, shadow);
    publish_inbound_transaction_shadows(connection, &[shadow_buffer]);

    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &shadow_buffer);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    assert!(!unsafe { write_buffer_is_safe_to_intercept(&write) });

    let rewritten = unsafe { rewrite_inbound_free_buffers(connection, &mut write) };
    let command_end = size_of::<u32>() + size_of::<libc::c_ulong>();
    assert_eq!(rewritten, vec![(command_end, shadow_buffer)]);
    assert_eq!(
        unsafe { std::ptr::read_unaligned(write.as_ptr().add(size_of::<u32>()) as *const usize) },
        original.as_ptr() as usize
    );

    complete_inbound_free_buffers(connection, &rewritten, command_end - 1);
    assert_eq!(
        inbound_transaction_original_buffer(connection, shadow_buffer),
        Some(original.as_ptr() as libc::c_ulong)
    );
    mark_inbound_free_buffers_consumed(connection, &rewritten, command_end);
    complete_inbound_free_buffers(connection, &rewritten, command_end);
    assert_eq!(inbound_transaction_original_buffer(connection, shadow_buffer), None);
}

#[test]
fn preflight_snapshots_all_replies_before_claiming_frames() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().expect("synthetic reply test lock poisoned");
    let _route_guard = crate::tracker::tests::state_test_guard();
    let fd = 23;
    let connection = binder_state_key(fd);
    reset_pending_reply_frames_for_test(connection, 2);
    let first = [1u8, 2, 3, 4];
    // SAFETY: All fields and union members contain integer types that permit zero.
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = first.len();
    tr.data.ptr.buffer = first.as_ptr() as libc::c_ulong;
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    tr.data.ptr.buffer = 1;
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    // SAFETY: The command bytes are live; preflight rejects unreadable payload
    // addresses.
    assert!(unsafe { prepare_write_buffer(fd, &write, true) }.is_none());
    assert_eq!(
        crate::hook::rewrite::tests::pending_reply_frame_claims_for_test(connection),
        vec![false, false]
    );
    reset_pending_reply_frames_for_test(connection, 0);
}

#[test]
fn parser_consumes_preflight_payloads_without_reading_them_again() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().expect("synthetic reply test lock poisoned");
    let _route_guard = crate::tracker::tests::state_test_guard();
    let fd = 24;
    let connection = binder_state_key(fd);
    reset_pending_reply_frames_for_test(connection, 2);
    let data = [1u8, 2, 3, 4];
    // SAFETY: All fields and union members contain integer types that permit zero.
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = data.len();
    tr.data.ptr.buffer = data.as_ptr() as libc::c_ulong;
    let mut write = Vec::new();
    for _ in 0..2 {
        push_unaligned(&mut write, &BC_REPLY_CMD);
        push_unaligned(&mut write, &tr);
    }
    // SAFETY: write and data remain live while preflight copies their transaction
    // payloads.
    let mut prepared = unsafe { prepare_write_buffer(fd, &write, true) }.unwrap();
    assert_eq!(prepared.reply_payloads.len(), 2);
    assert_eq!(prepared.reply_payloads[0].as_ref().unwrap().data, data);
    for index in 0..2 {
        let offset =
            index * (size_of::<u32>() + size_of::<binder_transaction_data>()) + size_of::<u32>();
        let mut changed = tr;
        changed.data.ptr.buffer = 1;
        // SAFETY: offset covers a complete transaction in write; alignment is not
        // required.
        unsafe {
            std::ptr::write_unaligned(
                write.as_mut_ptr().add(offset).cast::<binder_transaction_data>(),
                changed,
            )
        };
    }
    // SAFETY: prepared owns both snapshots; parsing uses their bytes rather than
    // dereferencing the intentionally invalid payload addresses.
    let completions = unsafe { parse_prepared_write_buffer(fd, &mut write, Some(&mut prepared)) };
    assert_eq!(completions.len(), 2);
    assert!(prepared.reply_payloads.is_empty());
    assert_eq!(
        crate::hook::rewrite::tests::pending_reply_frame_claims_for_test(connection),
        vec![true, true]
    );
    abort_prepared_bc_replies(fd);
}

unsafe fn write_buffer_is_safe_to_intercept(write: &[u8]) -> bool {
    prepare_write_buffer(0, write, true).is_some()
}

unsafe fn parse_write_buffer(
    fd: c_int,
    write: &mut [u8],
) -> Vec<(usize, Option<usize>, bool, Option<NativeBinderRetirement>)> {
    parse_prepared_write_buffer(fd, write, None)
}
