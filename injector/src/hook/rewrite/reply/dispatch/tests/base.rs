use std::mem::size_of;

use super::*;
use crate::hook::binder::{
    binder_object_header, flat_binder_object, flat_binder_object_handle_or_ptr, BINDER_TYPE_BINDER,
    BINDER_TYPE_FD,
};

fn base_reply(code: rsbinder::TransactionCode) -> SyntheticReply {
    let target = LocalBinderTarget { ptr: 0x4100, cookie: 0x5100 };
    let empty = rsbinder::Parcel::new();
    let (tr, _data) = transaction_for_parcel(target, code, empty);
    unsafe { synthetic_base_transaction_reply(Some(SyntheticTargetKind::Operation), target, &tr) }
        .expect("base transaction handling should not fail")
        .expect("base transaction should produce a reply")
}

fn transaction_for_raw_parts(
    target: LocalBinderTarget,
    code: rsbinder::TransactionCode,
    data: &mut [u8],
    offsets: &mut [usize],
) -> binder_transaction_data {
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.target.ptr = target.ptr;
    tr.data.ptr.buffer = data.as_mut_ptr() as libc::c_ulong;
    tr.data.ptr.offsets = offsets.as_mut_ptr() as libc::c_ulong;
    tr.cookie = target.cookie;
    tr.code = code;
    tr.sender_euid = 10002;
    tr.sender_pid = 2000;
    tr.data_size = data.len();
    tr.offsets_size = std::mem::size_of_val(offsets);
    tr
}

fn dump_transaction_data(argc: i32, args: &[String]) -> Vec<u8> {
    let mut tail = rsbinder::to_bytes(&argc).unwrap();
    for arg in args {
        tail.extend_from_slice(&rsbinder::to_bytes(arg).unwrap());
    }

    let mut data = vec![0u8; size_of::<flat_binder_object>() + tail.len()];
    let object = flat_binder_object {
        hdr: binder_object_header { type_: BINDER_TYPE_FD },
        flags: 0,
        handle_or_ptr: flat_binder_object_handle_or_ptr { handle: 0 },
        cookie: 0,
    };
    unsafe {
        std::ptr::write_unaligned(data.as_mut_ptr() as *mut flat_binder_object, object);
        std::ptr::copy_nonoverlapping(
            tail.as_ptr(),
            data.as_mut_ptr().add(size_of::<flat_binder_object>()),
            tail.len(),
        );
    }
    data
}

fn dump_reply(data: &mut [u8], offsets: &mut [usize]) -> SyntheticReply {
    let target = LocalBinderTarget { ptr: 0x4100, cookie: 0x5100 };
    let tr = transaction_for_raw_parts(target, rsbinder::DUMP_TRANSACTION, data, offsets);
    unsafe { synthetic_base_transaction_reply(Some(SyntheticTargetKind::Operation), target, &tr) }
        .expect("dump handling should not fail")
        .expect("dump should produce a reply")
}

#[test]
fn synthetic_ping_returns_empty_parcel_without_interface_token() {
    assert_synthetic_empty_parcel_reply(base_reply(rsbinder::PING_TRANSACTION), "ping");
}

#[test]
fn synthetic_debug_pid_uses_process_identity_without_interface_token() {
    let target = LocalBinderTarget { ptr: 0x4100, cookie: 0x5100 };
    let empty = rsbinder::Parcel::new();
    let (mut tr, _data) = transaction_for_parcel(target, rsbinder::DEBUG_PID_TRANSACTION, empty);
    tr.sender_pid = if synthetic_debug_pid() == 2000 { 2001 } else { 2000 };

    let reply = unsafe {
        synthetic_base_transaction_reply(Some(SyntheticTargetKind::Operation), target, &tr)
    }
    .expect("debug pid handling should not fail")
    .expect("debug pid should produce a reply");
    assert_synthetic_raw_i32_reply(reply, synthetic_debug_pid());
    assert_ne!(synthetic_debug_pid(), tr.sender_pid);
}

#[test]
fn synthetic_shell_and_sysprops_return_empty_parcels_without_interface_token() {
    for (code, label) in [
        (rsbinder::SHELL_COMMAND_TRANSACTION, "shell"),
        (rsbinder::SYSPROPS_TRANSACTION, "sysprops"),
    ] {
        assert_synthetic_empty_parcel_reply(base_reply(code), label);
    }
}

#[test]
fn unsupported_base_transaction_returns_invalid_operation() {
    assert_synthetic_status(
        base_reply(rsbinder::START_RECORDING_TRANSACTION),
        StatusCode::InvalidOperation,
    );
}

#[test]
fn unknown_base_transaction_returns_unknown_transaction() {
    assert_unknown_transaction_reply(base_reply(u32::MAX));
}

#[test]
fn dump_without_fd_returns_bad_type() {
    let target = LocalBinderTarget { ptr: 0x4100, cookie: 0x5100 };
    let empty = rsbinder::Parcel::new();
    let (tr, _) = transaction_for_parcel(target, rsbinder::DUMP_TRANSACTION, empty);
    let reply = unsafe {
        synthetic_base_transaction_reply(Some(SyntheticTargetKind::Operation), target, &tr)
    }
    .expect("dump handling should not fail")
    .expect("dump should produce a reply");
    assert_synthetic_status(reply, StatusCode::BadType);
}

#[test]
fn dump_with_fd_and_no_args_succeeds() {
    let mut data = dump_transaction_data(0, &[]);
    let mut offsets = [0usize];
    assert_synthetic_empty_parcel_reply(dump_reply(&mut data, &mut offsets), "valid dump");
}

#[test]
fn dump_tolerates_missing_or_negative_arg_count() {
    let mut offsets = [0usize];

    let mut missing_argc = dump_transaction_data(0, &[]);
    missing_argc.truncate(size_of::<flat_binder_object>());
    assert_synthetic_empty_parcel_reply(
        dump_reply(&mut missing_argc, &mut offsets),
        "missing argc dump",
    );

    let mut missing_arg = dump_transaction_data(1, &[]);
    assert_synthetic_empty_parcel_reply(
        dump_reply(&mut missing_arg, &mut offsets),
        "missing arg dump",
    );

    let mut negative_argc = dump_transaction_data(-1, &[]);
    assert_synthetic_empty_parcel_reply(
        dump_reply(&mut negative_argc, &mut offsets),
        "negative argc dump",
    );
}

#[test]
fn dump_accepts_arguments_and_ignores_trailing_bytes() {
    let mut offsets = [0usize];
    let mut with_args = dump_transaction_data(1, &[String::from("--proto")]);
    assert_synthetic_empty_parcel_reply(
        dump_reply(&mut with_args, &mut offsets),
        "valid dump with args",
    );

    let mut trailing = dump_transaction_data(0, &[]);
    trailing.extend_from_slice(&0x4f4d4bu32.to_ne_bytes());
    assert_synthetic_empty_parcel_reply(dump_reply(&mut trailing, &mut offsets), "trailing dump");
}

#[test]
fn dump_ignores_trailing_binder_objects() {
    let mut data = dump_transaction_data(0, &[]);
    while !data.len().is_multiple_of(size_of::<usize>()) {
        data.push(0);
    }
    let object_offset = data.len();
    data.resize(object_offset + size_of::<flat_binder_object>(), 0);
    let object = flat_binder_object {
        hdr: binder_object_header { type_: BINDER_TYPE_BINDER },
        flags: 0,
        handle_or_ptr: flat_binder_object_handle_or_ptr { binder: 0 },
        cookie: 0,
    };
    unsafe {
        std::ptr::write_unaligned(
            data.as_mut_ptr().add(object_offset) as *mut flat_binder_object,
            object,
        );
    }
    let mut offsets = [0usize, object_offset];
    assert_synthetic_empty_parcel_reply(
        dump_reply(&mut data, &mut offsets),
        "trailing object dump",
    );
}
