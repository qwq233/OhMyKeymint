use crate::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::aidl::android::system::keystore2::IKeystoreOperation::BnKeystoreOperation;
use binder::StatusCode;

mod client;
mod compat;
mod dispatch;

pub use binder::ext::rpc::RpcServer as Server;
pub use client::{available, may_intercept, start, wait_until_ready, with_admin};
pub use compat::{authorization_code, maintenance_code};
pub use dispatch::{dispatch, operation_proxy};

pub const SOCKET: &str = "/data/misc/keystore/omk/rpc.sock";
pub const SERVICE: &str = "omk";
pub const AUTHORIZATION_SERVICE: &str = "omk_authorization";
pub const MAINTENANCE_SERVICE: &str = "omk_maintenance";
pub const METRICS_SERVICE: &str = "omk_metrics";

pub enum Backend<'a> {
    Keystore,
    SecurityLevel(SecurityLevel),
    Authorization,
    Maintenance,
    Operation { epoch: u64, binder: &'a BnKeystoreOperation },
}

pub fn is_stale_rpc_status_code(status: StatusCode) -> bool {
    matches!(status, StatusCode::DEAD_OBJECT | StatusCode::NOT_ENOUGH_DATA)
}

pub fn is_rpc_cache_invalidating_status_code(status: StatusCode) -> bool {
    is_stale_rpc_status_code(status) || status == StatusCode::NO_INIT
}

pub fn is_rpc_cache_invalidating_status(status: &binder::Status) -> bool {
    status.exception_code() == binder::ExceptionCode::TRANSACTION_FAILED
        && (is_rpc_cache_invalidating_status_code(status.transaction_error())
            || status.transaction_error() == StatusCode::UNKNOWN_ERROR)
}
