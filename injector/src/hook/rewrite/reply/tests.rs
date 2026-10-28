pub(in crate::hook::rewrite) use super::dispatch::tests::handle_synthetic_br_transaction;
use std::mem::size_of;

use rsbinder::{ExceptionCode, Status, StatusCode};

use super::*;
use crate::hook::rewrite::tests::*;

pub(super) fn assert_unknown_transaction_reply(reply: SyntheticReply) {
    let SyntheticReply::Status(status) = reply else {
        panic!("unknown transaction should be returned as a binder status code");
    };
    assert_eq!(status, i32::from(StatusCode::UnknownTransaction));
}

pub(super) fn assert_synthetic_status(reply: SyntheticReply, expected: StatusCode) {
    let SyntheticReply::Status(status) = reply else {
        panic!("expected synthetic binder status");
    };
    assert_eq!(status, i32::from(expected));
}

pub(super) fn assert_synthetic_ok_reply(reply: SyntheticReply, label: &str) {
    let SyntheticReply::Parcel(mut reply) = reply else {
        panic!("{label} should be a status-bearing parcel reply");
    };
    assert_eq!(reply.offsets_size(), 0);
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");
    assert!(status.is_ok(), "{label} should be OK");
}

pub(super) fn assert_synthetic_empty_parcel_reply(reply: SyntheticReply, label: &str) {
    let SyntheticReply::Parcel(reply) = reply else {
        panic!("{label} should be an empty parcel reply");
    };
    assert_eq!(reply.data_size(), 0, "{label} data size");
    assert_eq!(reply.offsets_size(), 0, "{label} offsets size");
}

pub(super) fn assert_synthetic_exception_reply(reply: SyntheticReply, expected: ExceptionCode) {
    let SyntheticReply::Parcel(mut reply) = reply else {
        panic!("expected synthetic status parcel reply");
    };
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");
    assert_eq!(status.exception_code(), expected);
}

pub(super) fn assert_synthetic_raw_i32_reply(reply: SyntheticReply, expected: i32) {
    let SyntheticReply::Parcel(mut reply) = reply else {
        panic!("raw i32 reply should be a parcel");
    };
    assert_eq!(reply.data_size(), size_of::<i32>());
    assert_eq!(reply.offsets_size(), 0);
    let (data, _, _, _) = raw_parts(&mut reply);
    let value = unsafe { std::ptr::read_unaligned(data as *const i32) };
    assert_eq!(value, expected);
}

#[test]
fn plain_omk_error_becomes_system_error_reply() {
    let error = anyhow::anyhow!("plain OMK failure");
    let mut reply =
        build_omk_error_reply(&error).expect("plain error should produce a status reply");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");

    assert_eq!(
        parsed.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(
        parsed.service_specific_error(),
        ResponseCode::SYSTEM_ERROR.0
    );
}

#[test]
fn contextual_omk_status_error_keeps_service_specific_code() {
    let status = Status::new_service_specific_error(ResponseCode::PERMISSION_DENIED.0, None);
    let error = anyhow::Error::new(status).context("wrapped OMK failure");
    let mut reply =
        build_omk_error_reply(&error).expect("wrapped status should produce a status reply");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");

    assert_eq!(
        parsed.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(
        parsed.service_specific_error(),
        ResponseCode::PERMISSION_DENIED.0
    );
}

#[test]
fn unavailable_omk_errors_return_system_error_without_fallback() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    for code in [
        StatusCode::DeadObject,
        StatusCode::RpcError,
        StatusCode::NotEnoughData,
        StatusCode::NoInit,
        StatusCode::NameNotFound,
        StatusCode::Errno(libc::ECONNREFUSED),
        StatusCode::Errno(libc::EPIPE),
    ] {
        for error in [
            anyhow::Error::new(Status::from(code)).context("wrapped status"),
            anyhow::Error::new(code).context("wrapped status code"),
        ] {
            let mut reply = omk_error_reply_for_method("test", &caller, &error)
                .unwrap()
                .expect("selected OMK failure must replace System success");
            let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
            // SAFETY: reply owns the data and offsets buffers throughout status parsing.
            let actual =
                unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap();
            assert_eq!(actual.exception_code(), ExceptionCode::ServiceSpecific);
            assert_eq!(
                actual.service_specific_error(),
                ResponseCode::SYSTEM_ERROR.0
            );
        }
    }
}

#[test]
fn reachable_non_stale_omk_status_code_errors_become_system_error_reply() {
    // AOSP keystore2 maps a bare transport StatusCode through
    // map_binder_status_code -> Error::BinderTransaction -> SYSTEM_ERROR,
    // surfaced as a service-specific parcel, never a raw transport status.
    for status in [
        StatusCode::TimedOut,
        StatusCode::PermissionDenied,
        StatusCode::UnknownTransaction,
    ] {
        let error = anyhow::Error::new(status);
        let mut reply = build_omk_error_reply(&error)
            .expect("reachable OMK errors must produce a status reply");
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
            .expect("status reply should parse");
        assert_eq!(
            parsed.exception_code(),
            rsbinder::ExceptionCode::ServiceSpecific
        );
        assert_eq!(
            parsed.service_specific_error(),
            ResponseCode::SYSTEM_ERROR.0
        );
    }
}

#[test]
fn reachable_omk_status_error_becomes_authoritative_reply() {
    let status = Status::new_service_specific_error(ResponseCode::PERMISSION_DENIED.0, None);
    let reply = build_omk_status_reply(&status).expect("service-specific status should build");
    let mut reply = reply;
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed = unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("status reply should parse");

    assert_eq!(
        parsed.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(
        parsed.service_specific_error(),
        ResponseCode::PERMISSION_DENIED.0
    );
}
