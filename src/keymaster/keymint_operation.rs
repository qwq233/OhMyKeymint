use binder::Interface;

use crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;
use crate::android::hardware::security::keymint::IKeyMintOperation::IKeyMintOperation;
use crate::keymaster::error::map_ks_error;
use crate::keymaster::keymint_device::KeyMintWrapper;

pub struct KeyMintOperation {
    wrapper: KeyMintWrapper,
    // Extra for internal use: returned by bottom half of KeyMint implementation, used on
    // all subsequent operation methods to identify the operation.
    pub op_handle: i64,
}

impl Interface for KeyMintOperation {}

impl KeyMintOperation {
    pub fn new(wrapper: KeyMintWrapper, op_handle: i64) -> Self {
        KeyMintOperation { wrapper, op_handle }
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
    ) -> binder::Result<()> {
        self.wrapper
            .op_update_aad(self.op_handle, input, authToken, timeStampToken)
            .map_err(map_ks_error)
    }

    fn r#update(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> binder::Result<Vec<u8>> {
        self.wrapper
            .op_update(self.op_handle, input, authToken, timeStampToken)
            .map_err(map_ks_error)
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
    ) -> binder::Result<Vec<u8>> {
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
    }

    fn r#abort(&self) -> binder::Result<()> {
        self.wrapper.op_abort(self.op_handle).map_err(map_ks_error)
    }
}
