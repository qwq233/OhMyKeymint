use super::*;

#[test]
fn authorization_non_null_arrays_reject_null() {
    assert_status_code(
        parse_authorization_request_as_method(AuthorizationMethod::OnDeviceLocked, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&-1i32).unwrap();
            parcel.write(&false).unwrap();
        }),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_authorization_request_as_method(AuthorizationMethod::GetLastAuthTime, |parcel| {
            parcel.write(&0i64).unwrap();
            parcel.write(&-1i32).unwrap();
        }),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn authorization_preserves_empty_password() {
    let parsed =
        parse_authorization_request_as_method(AuthorizationMethod::OnDeviceUnlocked, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&Some(Vec::<u8>::new())).unwrap();
        })
        .expect("empty onDeviceUnlocked password should parse");
    let ParsedAuthorizationRequest::OnDeviceUnlocked { password, .. } = parsed else {
        panic!("onDeviceUnlocked request should parse");
    };
    assert_eq!(password, Some(Vec::new()));
}

#[test]
fn authorization_accepts_empty_unlocking_sids() {
    let parsed =
        parse_authorization_request_as_method(AuthorizationMethod::OnDeviceLocked, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&Vec::<i64>::new()).unwrap();
            parcel.write(&false).unwrap();
        })
        .expect("empty onDeviceLocked unlockingSids should parse");
    let ParsedAuthorizationRequest::OnDeviceLocked { unlocking_sids, .. } = parsed else {
        panic!("onDeviceLocked request should parse");
    };
    assert!(unlocking_sids.is_empty());
}

#[test]
fn authorization_accepts_empty_authenticator_types() {
    let parsed =
        parse_authorization_request_as_method(AuthorizationMethod::GetLastAuthTime, |parcel| {
            parcel.write(&0i64).unwrap();
            parcel.write(&Vec::<HardwareAuthenticatorType>::new()).unwrap();
        })
        .expect("empty getLastAuthTime authTypes should parse");
    let ParsedAuthorizationRequest::GetLastAuthTime { auth_types, .. } = parsed else {
        panic!("getLastAuthTime request should parse");
    };
    assert!(auth_types.is_empty());
}

#[test]
fn authorization_request_accepts_trailing_payload() {
    let parsed =
        parse_authorization_request_as_method(AuthorizationMethod::GetLastAuthTime, |parcel| {
            parcel.write(&0i64).unwrap();
            parcel.write(&Vec::<HardwareAuthenticatorType>::new()).unwrap();
            parcel.write(&0x4f4d4bi32).unwrap();
        })
        .expect("authorization mirror request with trailing payload should parse");
    let ParsedAuthorizationRequest::GetLastAuthTime { auth_types, .. } = parsed else {
        panic!("authorization request should parse as GetLastAuthTime");
    };
    assert!(auth_types.is_empty());
}
