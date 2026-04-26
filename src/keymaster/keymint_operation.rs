use kmr_wire::keymint::KeyParam;
use rsbinder::Interface;

use crate::{
    android::hardware::security::keymint::{
        HardwareAuthToken::HardwareAuthToken, IKeyMintOperation::IKeyMintOperation,
    },
    keymaster::{error::map_ks_error, keymint_device::KeyMintWrapper},
};

pub struct KeyMintOperation {
    wrapper: KeyMintWrapper,
    pub challenge: i64,
    pub params: Vec<KeyParam>,
    // Extra for internal use: returned by bottom half of KeyMint implementation, used on
    // all subsequent operation methods to identify the operation.
    pub op_handle: i64,
}

impl Interface for KeyMintOperation {}

impl KeyMintOperation {
    pub fn new(
        wrapper: KeyMintWrapper,
        challenge: i64,
        params: Vec<KeyParam>,
        op_handle: i64,
    ) -> Self {
        KeyMintOperation {
            wrapper,
            challenge,
            params,
            op_handle,
        }
    }
}

#[allow(non_snake_case, unused_variables)]
impl IKeyMintOperation for KeyMintOperation {
    fn r#updateAad(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> rsbinder::status::Result<()> {
        self.wrapper
            .op_update_aad(self.op_handle, input, authToken, timeStampToken)
            .map_err(map_ks_error)?;
        Ok(())
    }

    fn r#update(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> rsbinder::status::Result<Vec<u8>> {
        self.wrapper
            .op_update(self.op_handle, input, authToken, timeStampToken)
            .map_err(map_ks_error)
            .map(|rsp: Vec<u8>| rsp.to_vec())
    }

    fn r#finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        authToken: Option<&HardwareAuthToken>,
        timestampToken: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
        confirmationToken: Option<&[u8]>,
    ) -> rsbinder::status::Result<Vec<u8>> {
        self.wrapper
            .op_finish(
                self.op_handle,
                input,
                signature,
                authToken,
                timestampToken,
                confirmationToken,
            )
            .map_err(map_ks_error)
            .map(|rsp: Vec<u8>| rsp.to_vec())
    }

    fn r#abort(&self) -> rsbinder::status::Result<()> {
        self.wrapper.op_abort(self.op_handle).map_err(map_ks_error)
    }
}
