use kmr_wire::keymint::KeyParam;
use rsbinder::Interface;

use crate::{android::hardware::security::keymint::{HardwareAuthToken::HardwareAuthToken, IKeyMintOperation::IKeyMintOperation, SecurityLevel::SecurityLevel}, keymaster::{error::map_ks_error, keymint_device::{KeyMintWrapper, get_keymint_wrapper}}};


pub struct OKeyMintOperation {
    security_level: SecurityLevel,
    pub challenge: i64,
    pub params: Vec<KeyParam>,
    // Extra for internal use: returned by bottom half of KeyMint implementation, used on
    // all subsequent operation methods to identify the operation.
    pub op_handle: i64,
}

impl Interface for OKeyMintOperation {
}

impl OKeyMintOperation {
    pub fn new(security_level: SecurityLevel, challenge: i64, params: Vec<KeyParam>, op_handle: i64) -> Self {
        OKeyMintOperation {
            security_level,
            challenge,
            params,
            op_handle,
        }
    }
}

#[allow(non_snake_case, unused_variables)]
impl IKeyMintOperation for OKeyMintOperation {
    fn r#updateAad(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
    ) -> rsbinder::status::Result<()> {
        get_keymint_wrapper(self.security_level).unwrap().op_update_aad(self.op_handle, input, authToken, timeStampToken)
            .map_err(|e| map_ks_error(e))?;
        Ok(())
    }

    fn r#update(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
    ) -> rsbinder::status::Result<Vec<u8>> {
        get_keymint_wrapper(self.security_level).unwrap().op_update(self.op_handle, input, authToken, timeStampToken)
            .map_err(|e| map_ks_error(e))
            .and_then(|rsp: Vec<u8>| {Ok(rsp.to_vec())})
    }

    fn r#finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        authToken: Option<&HardwareAuthToken>,
        timestampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
        confirmationToken: Option<&[u8]>,
    ) -> rsbinder::status::Result<Vec<u8>> {
        get_keymint_wrapper(self.security_level).unwrap().op_finish(self.op_handle, input, signature, authToken, timestampToken, confirmationToken)
            .map_err(|e| map_ks_error(e))
            .and_then(|rsp: Vec<u8>| {Ok(rsp.to_vec())})
    }

    fn r#abort(&self) -> rsbinder::status::Result<()> {
        get_keymint_wrapper(self.security_level).unwrap().op_abort(self.op_handle)
            .map_err(|e| map_ks_error(e))
    }
}

