use super::*;
use crate::hook::rewrite::tests::raw_parts;

#[test]
fn system_failure_and_read_only_calls_skip_mirror() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let cfg = config::InjectorConfig::default();
    for (status, requires_mirror) in [
        (
            Status::new_service_specific_error(ResponseCode::SYSTEM_ERROR.0, None),
            true,
        ),
        (Status::from(StatusCode::Ok), false),
    ] {
        let mut reply = parcel::build_status_reply(&status).unwrap();
        let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
        // SAFETY: All fields and union members contain integer types that permit zero.
        let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
        tr.data.ptr.buffer = data as libc::c_ulong;
        tr.data.ptr.offsets = offsets as libc::c_ulong;
        tr.data_size = data_size;
        tr.offsets_size = offsets_size;
        // SAFETY: reply owns both transaction buffers throughout the mirror call.
        assert!(unsafe {
            build_mirror_reply(&tr, &caller, &cfg, requires_mirror, || {
                panic!("System failure and read-only calls must not reach OMK")
            })
        }
        .unwrap()
        .is_none());
    }
}

#[test]
fn mirror_is_synchronous_single_pass_and_failure_does_not_block_next_call() {
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let mut system_reply = parcel::build_void_reply().unwrap();
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut system_reply);
    // SAFETY: All fields and union members contain integer types that permit zero.
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data.ptr.buffer = data as libc::c_ulong;
    tr.data.ptr.offsets = offsets as libc::c_ulong;
    tr.data_size = data_size;
    tr.offsets_size = offsets_size;

    for in_scope in [false, true] {
        let mut cfg = config::InjectorConfig::default();
        cfg.filter.enabled = !in_scope;
        for status in [
            Status::new_service_specific_error(ResponseCode::PERMISSION_DENIED.0, None),
            Status::from(StatusCode::DeadObject),
        ] {
            let mut calls = 0;
            // SAFETY: system_reply keeps the original transaction buffers live and
            // unchanged.
            let reply = unsafe {
                build_mirror_reply(&tr, &caller, &cfg, true, || {
                    assert!(forward::is_bypassed());
                    calls += 1;
                    Err(anyhow::Error::new(status.clone()))
                })
            }
            .unwrap();
            assert_eq!(calls, 1);
            if in_scope {
                let mut reply = reply.expect("in-scope mirror failure must replace System success");
                let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
                // SAFETY: reply owns the replacement buffers throughout status parsing.
                let actual =
                    unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }
                        .unwrap();
                let expected = if status.exception_code() == ExceptionCode::ServiceSpecific {
                    status.service_specific_error()
                } else {
                    ResponseCode::SYSTEM_ERROR.0
                };
                assert_eq!(actual.exception_code(), ExceptionCode::ServiceSpecific);
                assert_eq!(actual.service_specific_error(), expected);
            } else {
                assert!(reply.is_none());
            }

            // SAFETY: system_reply still owns the unchanged original transaction buffers.
            assert!(unsafe {
                build_mirror_reply(&tr, &caller, &cfg, true, || {
                    calls += 1;
                    Ok(())
                })
            }
            .unwrap()
            .is_none());
            assert_eq!(
                calls, 2,
                "a later request must not replay the failed update"
            );
        }
    }
}
