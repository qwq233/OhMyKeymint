// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Error handling tests.

use super::*;
use crate::selinux;
use anyhow::{anyhow, Context};
use rsbinder::{status::Result as BinderResult, ExceptionCode, Status as BinderStatus, StatusCode};

fn nested_nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
    Err(anyhow!(Error::Rc(rc))).context("nested nested rc")
}

fn nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
    nested_nested_rc(rc).context("nested rc")
}

fn nested_nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
    Err(anyhow!(Error::Km(ec))).context("nested nested ec")
}

fn nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
    nested_nested_ec(ec).context("nested ec")
}

fn nested_nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
    Ok(rc)
}

fn nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
    nested_nested_ok(rc).context("nested ok")
}

fn nested_nested_selinux_perm() -> anyhow::Result<()> {
    Err(anyhow!(selinux::Error::perm())).context("nested nexted selinux permission denied")
}

fn nested_selinux_perm() -> anyhow::Result<()> {
    nested_nested_selinux_perm().context("nested selinux permission denied")
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("TestError::Fail")]
    Fail = 0,
}

fn nested_nested_other_error() -> anyhow::Result<()> {
    Err(anyhow!(TestError::Fail)).context("nested nested other error")
}

fn nested_other_error() -> anyhow::Result<()> {
    nested_nested_other_error().context("nested other error")
}

fn binder_sse_error(sse: i32) -> BinderResult<()> {
    Err(BinderStatus::new_service_specific_error(sse, None))
}

fn binder_exception(ex: ExceptionCode) -> BinderResult<()> {
    Err(BinderStatus::from(ex))
}

#[test]
fn keystore_error_test() -> anyhow::Result<(), String> {
    crate::keymaster::utils::init_test_logging();
    // All Error::Rc(x) get mapped on a service specific error
    // code of x.
    for rc in ResponseCode::LOCKED.0..ResponseCode::BACKEND_BUSY.0 {
        assert_eq!(
            Result::<(), i32>::Err(rc),
            nested_rc(ResponseCode(rc))
                .map_err(into_logged_binder)
                .map_err(|s| s.service_specific_error())
        );
    }

    // All Keystore Error::Km(x) get mapped on a service
    // specific error of x.
    for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
        assert_eq!(
            Result::<(), i32>::Err(ec),
            nested_ec(ErrorCode(ec))
                .map_err(into_logged_binder)
                .map_err(|s| s.service_specific_error())
        );
    }

    // All Keymint errors x received through a Binder Result get mapped on
    // a service specific error of x.
    for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
        assert_eq!(
            Result::<(), i32>::Err(ec),
            map_km_error(binder_sse_error(ec))
                .with_context(|| format!("Km error code: {ec}."))
                .map_err(into_logged_binder)
                .map_err(|s| s.service_specific_error())
        );
    }

    // map_km_error creates an Error::Binder variant storing
    // ExceptionCode::SERVICE_SPECIFIC and the given
    // service specific error.
    let sse = map_km_error(binder_sse_error(1));
    assert_eq!(Err(Error::Binder(ExceptionCode::ServiceSpecific, 1)), sse);
    // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
    assert_eq!(
        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
        sse.context("Non negative service specific error.")
            .map_err(into_logged_binder)
            .map_err(|s| ResponseCode(s.service_specific_error()))
    );

    // map_km_error creates a Error::Binder variant storing the given exception code.
    let binder_exception = map_km_error(binder_exception(ExceptionCode::TransactionFailed));
    assert_eq!(
        Err(Error::BinderTransaction(StatusCode::FailedTransaction)),
        binder_exception
    );
    // into_binder then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
    assert_eq!(
        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
        binder_exception
            .context("Binder Exception.")
            .map_err(into_logged_binder)
            .map_err(|s| ResponseCode(s.service_specific_error()))
    );

    // selinux::Error::Perm() needs to be mapped to ResponseCode::PERMISSION_DENIED
    assert_eq!(
        Result::<(), ResponseCode>::Err(ResponseCode::PERMISSION_DENIED),
        nested_selinux_perm()
            .map_err(into_logged_binder)
            .map_err(|s| ResponseCode(s.service_specific_error()))
    );

    // All other errors get mapped on System Error.
    assert_eq!(
        Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
        nested_other_error()
            .map_err(into_logged_binder)
            .map_err(|s| ResponseCode(s.service_specific_error()))
    );

    // Result::Ok variants get passed to the ok handler.
    assert_eq!(
        Ok(ResponseCode::LOCKED),
        nested_ok(ResponseCode::LOCKED).map_err(into_logged_binder)
    );
    assert_eq!(
        Ok(ResponseCode::SYSTEM_ERROR),
        nested_ok(ResponseCode::SYSTEM_ERROR).map_err(into_logged_binder)
    );

    Ok(())
}

//Helper function to test whether error cases are handled as expected.
pub fn check_result_contains_error_string<T>(
    result: anyhow::Result<T>,
    expected_error_string: &str,
) {
    let error_str = format!(
        "{:#?}",
        result
            .err()
            .unwrap_or_else(|| panic!("Expected the error: {expected_error_string}"))
    );
    assert!(
        error_str.contains(expected_error_string),
        "The string \"{error_str}\" should contain \"{expected_error_string}\""
    );
}
