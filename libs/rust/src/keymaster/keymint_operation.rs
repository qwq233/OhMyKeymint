use kmr_wire::keymint::KeyParam;
use rsbinder::Interface;

use crate::android::hardware::security::keymint::{HardwareAuthToken::HardwareAuthToken, IKeyMintOperation::IKeyMintOperation};


pub struct KeyMintOperation {
    pub challenge: i64,
    pub params: Vec<KeyParam>,
    // Extra for internal use: returned by bottom half of KeyMint implementation, used on
    // all subsequent operation methods to identify the operation.
    pub op_handle: i64,
}
impl Interface for KeyMintOperation {}


#[allow(non_snake_case, unused_variables)]
impl IKeyMintOperation for KeyMintOperation {
    fn r#updateAad(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
    ) -> rsbinder::status::Result<()> {
        todo!()
    }

    fn r#update(
        &self,
        input: &[u8],
        authToken: Option<&HardwareAuthToken>,
        timeStampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
    ) -> rsbinder::status::Result<Vec<u8>> {
        todo!()
    }

    fn r#finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        authToken: Option<&HardwareAuthToken>,
        timestampToken: Option<&crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken>,
        confirmationToken: Option<&[u8]>,
    ) -> rsbinder::status::Result<Vec<u8>> {
        todo!()
    }

    fn r#abort(&self) -> rsbinder::status::Result<()> {
        todo!()
    }
}