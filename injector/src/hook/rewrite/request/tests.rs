use super::*;
use crate::hook::rewrite::tests::*;
use crate::{
    android::system::keystore2::Domain::Domain,
    android::system::keystore2::IKeystoreService::transactions as service_tx,
    android::system::keystore2::KeyDescriptor::KeyDescriptor,
};
use rsbinder::{Status, StatusCode};
use std::mem::size_of;

#[test]
fn omk_grant_blocker_preserves_inbound_binder_buffer() {
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.code = service_tx::r#grant;
    tr.data_size = 64;
    tr.offsets_size = size_of::<usize>();
    tr.data.ptr.buffer = 0x1000;
    tr.data.ptr.offsets = 0x2000;

    block_system_request(&mut tr);

    assert_eq!(tr.code, u32::MAX);
    assert_eq!(tr.data_size, 64);
    assert_eq!(tr.offsets_size, size_of::<usize>());
    assert_eq!(unsafe { tr.data.ptr.buffer }, 0x1000);
    assert_eq!(unsafe { tr.data.ptr.offsets }, 0x2000);
}

#[test]
fn grant_and_ungrant_return_system_error_when_omk_unavailable() {
    let _guard = route_state_test_guard();
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::from(StatusCode::RpcError))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("OMK transport failure must return an error");
    };
    assert_eq!(status.service_specific_error(), ResponseCode::SYSTEM_ERROR.0);

    let request =
        ParsedServiceRequest::Ungrant { key: sample_key_descriptor(), grantee_uid: 12345 };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| panic!("ungrant requests must not call grant"),
        |_, _, _| Err(anyhow::Error::new(Status::from(StatusCode::NotEnoughData))),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("OMK transport failure must return an error");
    };
    assert_eq!(status.service_specific_error(), ResponseCode::SYSTEM_ERROR.0);
}

#[test]
fn grant_precompute_returns_reachable_omk_business_error() {
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo { uid: 1000, sid: String::new(), pid: 2000 };

    let result = precompute_omk_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::new_service_specific_error(7, None))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let PrecomputedServiceReply::Error(status) = result else {
        panic!("reachable OMK business error should be precomputed as an authoritative status");
    };
    assert_eq!(status.exception_code(), rsbinder::ExceptionCode::ServiceSpecific);
    assert_eq!(status.service_specific_error(), 7);
}

#[test]
fn service_route_respects_intercept_configuration() {
    let _guard = route_state_test_guard();
    let intercept = config::InterceptConfig::default();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, true, &intercept),
            RouteTarget::Omk,
            "{:?} should use the OMK backend when the method is enabled",
            request.method()
        );
    }

    let intercept = disabled_intercept_config();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, true, &intercept),
            RouteTarget::System,
            "{:?} should use the system backend when the method is disabled",
            request.method()
        );
    }

    let mut intercept = disabled_intercept_config();
    intercept.get_key_entry = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_key_entry = false;
    intercept.get_security_level = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_security_level = false;
    assert!(!security_level_scoop_enabled(&intercept));
}

#[test]
fn descriptor_domain_does_not_bypass_scope_or_intercept() {
    for domain in [Domain::APP, Domain::KEY_ID, Domain::GRANT] {
        let request = ParsedServiceRequest::GetKeyEntry {
            key: KeyDescriptor { domain, nspace: 123, alias: None, blob: None },
        };
        for allowed in [false, true] {
            for enabled in [false, true] {
                let mut intercept = disabled_intercept_config();
                intercept.get_key_entry = enabled;
                assert_eq!(
                    route_for_service_request(&request, allowed, &intercept),
                    if allowed && enabled { RouteTarget::Omk } else { RouteTarget::System }
                );
            }
        }
    }
}
