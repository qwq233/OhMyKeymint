// Copyright 2022, The Android Open Source Project
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

//! KeyMint HAL device implementation.

use crate::binder;
use crate::hal::{
    failed_conversion, keymint, keymint::IKeyMintOperation::IKeyMintOperation,
    secureclock::TimeStampToken::TimeStampToken, Innto, TryInnto,
};
use crate::{ChannelHalService, SerializedChannel};
use kmr_wire::{keymint::KeyParam, AsCborValue, *};
use log::warn;
use std::ffi::CString;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

/// Maximum overhead size from CBOR serialization of operation messages.
///
/// A serialized `FinishRequest` includes the following additional bytes over and
/// above the size of the input (at most):
/// -    1: array wrapper (0x86)
///   -  9: int (0x1b + u64) [op_handle]
///   -  1: array wrapper (0x81) [input]
///      -  9: input data length
///      - XX:  input data
///   -  1: array wrapper (0x81) [signature]
///      - 5: signature data length
///      - 132: signature data (P-521 point)
///   -  1: array wrapper (0x81) [auth_token]
///      -  9: int (0x1b + u64) [challenge]
///      -  9: int (0x1b + u64) [user_id]
///      -  9: int (0x1b + u64) [authenticator_id]
///      -  9: int (0x1b + u64) [authenticator_type]
///      -  1: array wrapper (0x81)[timestamp]
///         -  9: int (0x1b + u64) [user_id]
///      -  2: bstr header [mac]
///      - 32: bstr [mac]
///   -  1: array wrapper (0x81) [timestamp_token]
///      -  1: array wrapper [TimeStampToken]
///         -  9: int (0x1b + u64) [challenge]
///         -  1: array wrapper (0x81)[timestamp]
///            -  9: int (0x1b + u64) [user_id]
///         -  2: bstr header [mac]
///         - 32: bstr [mac]
///   -  1: array wrapper (0x81) [confirmation_token]
///      -  2: bstr header [confirmation token]
///      - 32: bstr [confirmation token (HMAC-SHA256)]
///
/// Add some leeway in case encodings change.
pub const MAX_CBOR_OVERHEAD: usize = 350;

/// IKeyMintDevice implementation which converts all method invocations to serialized
/// requests that are sent down the associated channel.
pub struct Device<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + 'static> Device<T> {
    /// Construct a new instance that uses the provided channel.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }

    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder(
        channel: Arc<Mutex<T>>,
    ) -> binder::Strong<dyn keymint::IKeyMintDevice::IKeyMintDevice> {
        keymint::IKeyMintDevice::BnKeyMintDevice::new_binder(
            Self::new(channel),
            binder::BinderFeatures::default(),
        )
    }
}

impl<T: SerializedChannel> ChannelHalService<T> for Device<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }
}

impl<T: SerializedChannel> binder::Interface for Device<T> {}

impl<T: SerializedChannel> keymint::IKeyMintDevice::IKeyMintDevice for Device<T> {
    fn getHardwareInfo(&self) -> binder::Result<keymint::KeyMintHardwareInfo::KeyMintHardwareInfo> {
        let rsp: GetHardwareInfoResponse = self.execute(GetHardwareInfoRequest {})?;
        Ok(rsp.ret.innto())
    }
    fn addRngEntropy(&self, data: &[u8]) -> binder::Result<()> {
        let _rsp: AddRngEntropyResponse =
            self.execute(AddRngEntropyRequest { data: data.to_vec() })?;
        Ok(())
    }
    fn generateKey(
        &self,
        keyParams: &[keymint::KeyParameter::KeyParameter],
        attestationKey: Option<&keymint::AttestationKey::AttestationKey>,
    ) -> binder::Result<keymint::KeyCreationResult::KeyCreationResult> {
        let rsp: GenerateKeyResponse = self.execute(GenerateKeyRequest {
            key_params: keyParams
                .iter()
                .filter_map(|p| p.try_innto().transpose())
                .collect::<Result<Vec<KeyParam>, _>>()
                .map_err(failed_conversion)?,
            attestation_key: match attestationKey {
                None => None,
                Some(k) => Some(k.clone().try_innto().map_err(failed_conversion)?),
            },
        })?;
        Ok(rsp.ret.innto())
    }
    fn importKey(
        &self,
        keyParams: &[keymint::KeyParameter::KeyParameter],
        keyFormat: keymint::KeyFormat::KeyFormat,
        keyData: &[u8],
        attestationKey: Option<&keymint::AttestationKey::AttestationKey>,
    ) -> binder::Result<keymint::KeyCreationResult::KeyCreationResult> {
        let rsp: ImportKeyResponse = self.execute(ImportKeyRequest {
            key_params: keyParams
                .iter()
                .filter_map(|p| p.try_innto().transpose())
                .collect::<Result<Vec<KeyParam>, _>>()
                .map_err(failed_conversion)?,
            key_format: keyFormat.try_innto().map_err(failed_conversion)?,
            key_data: keyData.to_vec(),
            attestation_key: match attestationKey {
                None => None,
                Some(k) => Some(k.clone().try_innto().map_err(failed_conversion)?),
            },
        })?;
        Ok(rsp.ret.innto())
    }
    fn importWrappedKey(
        &self,
        wrappedKeyData: &[u8],
        wrappingKeyBlob: &[u8],
        maskingKey: &[u8],
        unwrappingParams: &[keymint::KeyParameter::KeyParameter],
        passwordSid: i64,
        biometricSid: i64,
    ) -> binder::Result<keymint::KeyCreationResult::KeyCreationResult> {
        let rsp: ImportWrappedKeyResponse = self.execute(ImportWrappedKeyRequest {
            wrapped_key_data: wrappedKeyData.to_vec(),
            wrapping_key_blob: wrappingKeyBlob.to_vec(),
            masking_key: maskingKey.to_vec(),
            unwrapping_params: unwrappingParams
                .iter()
                .filter_map(|p| p.try_innto().transpose())
                .collect::<Result<Vec<KeyParam>, _>>()
                .map_err(failed_conversion)?,
            password_sid: passwordSid,
            biometric_sid: biometricSid,
        })?;
        Ok(rsp.ret.innto())
    }
    fn upgradeKey(
        &self,
        keyBlobToUpgrade: &[u8],
        upgradeParams: &[keymint::KeyParameter::KeyParameter],
    ) -> binder::Result<Vec<u8>> {
        let rsp: UpgradeKeyResponse = self.execute(UpgradeKeyRequest {
            key_blob_to_upgrade: keyBlobToUpgrade.to_vec(),
            upgrade_params: upgradeParams
                .iter()
                .filter_map(|p| p.try_innto().transpose())
                .collect::<Result<Vec<KeyParam>, _>>()
                .map_err(failed_conversion)?,
        })?;
        Ok(rsp.ret)
    }
    fn deleteKey(&self, keyBlob: &[u8]) -> binder::Result<()> {
        let _rsp: DeleteKeyResponse =
            self.execute(DeleteKeyRequest { key_blob: keyBlob.to_vec() })?;
        Ok(())
    }
    fn deleteAllKeys(&self) -> binder::Result<()> {
        let _rsp: DeleteAllKeysResponse = self.execute(DeleteAllKeysRequest {})?;
        Ok(())
    }
    fn destroyAttestationIds(&self) -> binder::Result<()> {
        let _rsp: DestroyAttestationIdsResponse = self.execute(DestroyAttestationIdsRequest {})?;
        Ok(())
    }
    fn begin(
        &self,
        purpose: keymint::KeyPurpose::KeyPurpose,
        keyBlob: &[u8],
        params: &[keymint::KeyParameter::KeyParameter],
        authToken: Option<&keymint::HardwareAuthToken::HardwareAuthToken>,
    ) -> binder::Result<keymint::BeginResult::BeginResult> {
        let rsp: BeginResponse = self.execute(BeginRequest {
            purpose: purpose.try_innto().map_err(failed_conversion)?,
            key_blob: keyBlob.to_vec(),
            params: params
                .iter()
                .filter_map(|p| p.try_innto().transpose())
                .collect::<Result<Vec<KeyParam>, _>>()
                .map_err(failed_conversion)?,
            auth_token: match authToken {
                None => None,
                Some(t) => Some(t.clone().try_innto().map_err(failed_conversion)?),
            },
        })?;
        // The `begin()` method is a special case.
        // - Internally, the in-progress operation is identified by an opaque handle value.
        // - Externally, the in-progress operation is represented as an `IKeyMintOperation` Binder
        //   object.
        // The `WireOperation` struct contains the former, and acts as the latter.
        let op = Operation::new_as_binder(self.channel.clone(), rsp.ret.op_handle);
        Ok(keymint::BeginResult::BeginResult {
            challenge: rsp.ret.challenge,
            params: rsp.ret.params.innto(),
            operation: Some(op),
        })
    }
    fn deviceLocked(
        &self,
        _passwordOnly: bool,
        _timestampToken: Option<&TimeStampToken>,
    ) -> binder::Result<()> {
        // This method is deprecated and unused, so just fail with error UNIMPLEMENTED.
        warn!("Deprecated method devicedLocked() was called");
        Err(binder::Status::new_service_specific_error(
            keymint::ErrorCode::ErrorCode::UNIMPLEMENTED.0,
            Some(&CString::new("Deprecated method deviceLocked() is not implemented").unwrap()),
        ))
    }
    fn earlyBootEnded(&self) -> binder::Result<()> {
        let _rsp: EarlyBootEndedResponse = self.execute(EarlyBootEndedRequest {})?;
        Ok(())
    }
    fn convertStorageKeyToEphemeral(&self, storageKeyBlob: &[u8]) -> binder::Result<Vec<u8>> {
        let rsp: ConvertStorageKeyToEphemeralResponse =
            self.execute(ConvertStorageKeyToEphemeralRequest {
                storage_key_blob: storageKeyBlob.to_vec(),
            })?;
        Ok(rsp.ret)
    }
    fn getKeyCharacteristics(
        &self,
        keyBlob: &[u8],
        appId: &[u8],
        appData: &[u8],
    ) -> binder::Result<Vec<keymint::KeyCharacteristics::KeyCharacteristics>> {
        let rsp: GetKeyCharacteristicsResponse = self.execute(GetKeyCharacteristicsRequest {
            key_blob: keyBlob.to_vec(),
            app_id: appId.to_vec(),
            app_data: appData.to_vec(),
        })?;
        Ok(rsp.ret.innto())
    }
    #[cfg(feature = "hal_v2")]
    fn getRootOfTrustChallenge(&self) -> binder::Result<[u8; 16]> {
        let rsp: GetRootOfTrustChallengeResponse =
            self.execute(GetRootOfTrustChallengeRequest {})?;
        Ok(rsp.ret)
    }
    #[cfg(feature = "hal_v2")]
    fn getRootOfTrust(&self, challenge: &[u8; 16]) -> binder::Result<Vec<u8>> {
        let rsp: GetRootOfTrustResponse =
            self.execute(GetRootOfTrustRequest { challenge: *challenge })?;
        Ok(rsp.ret)
    }
    #[cfg(feature = "hal_v2")]
    fn sendRootOfTrust(&self, root_of_trust: &[u8]) -> binder::Result<()> {
        let _rsp: SendRootOfTrustResponse =
            self.execute(SendRootOfTrustRequest { root_of_trust: root_of_trust.to_vec() })?;
        Ok(())
    }
    #[cfg(feature = "hal_v4")]
    fn setAdditionalAttestationInfo(
        &self,
        info: &[keymint::KeyParameter::KeyParameter],
    ) -> binder::Result<()> {
        let _rsp: SetAdditionalAttestationInfoResponse =
            self.execute(SetAdditionalAttestationInfoRequest {
                info: info
                    .iter()
                    .filter_map(|p| p.try_innto().transpose())
                    .collect::<Result<Vec<KeyParam>, _>>()
                    .map_err(failed_conversion)?,
            })?;
        Ok(())
    }
}

/// Representation of an in-progress KeyMint operation on a `SerializedChannel`.
#[derive(Debug)]
struct Operation<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
    op_handle: RwLock<Option<i64>>,
}

impl<T: SerializedChannel + 'static> Drop for Operation<T> {
    fn drop(&mut self) {
        // Ensure that the TA is kept up-to-date by calling `abort()`, but ignore the result.
        let _ = self.abort();
    }
}

impl<T: SerializedChannel> ChannelHalService<T> for Operation<T> {
    fn channel(&self) -> MutexGuard<T> {
        self.channel.lock().unwrap()
    }

    /// Execute the given request as part of the operation.  If the request fails, the operation is
    /// invalidated (and any future requests for the operation will fail).
    fn execute<R, S>(&self, req: R) -> binder::Result<S>
    where
        R: AsCborValue + Code<KeyMintOperation>,
        S: AsCborValue + Code<KeyMintOperation>,
    {
        let result = super::channel_execute(self.channel().deref_mut(), req);
        if result.is_err() {
            // Any failed method on an operation terminates the operation.
            self.invalidate();
        }
        result
    }
}

impl<T: SerializedChannel> binder::Interface for Operation<T> {}

impl<T: SerializedChannel + 'static> Operation<T> {
    /// Create a new `Operation` wrapped in a proxy object.
    fn new_as_binder(
        channel: Arc<Mutex<T>>,
        op_handle: i64,
    ) -> binder::Strong<dyn keymint::IKeyMintOperation::IKeyMintOperation> {
        let op = Self { channel, op_handle: RwLock::new(Some(op_handle)) };
        keymint::IKeyMintOperation::BnKeyMintOperation::new_binder(
            op,
            binder::BinderFeatures::default(),
        )
    }
}

impl<T: SerializedChannel> Operation<T> {
    // Maximum size allowed for the operation data.
    const MAX_DATA_SIZE: usize = T::MAX_SIZE - MAX_CBOR_OVERHEAD;

    /// Invalidate the operation.
    fn invalidate(&self) {
        *self.op_handle.write().unwrap() = None;
    }

    /// Retrieve the operation handle, if not already failed.
    fn validate_handle(&self) -> binder::Result<i64> {
        self.op_handle.read().unwrap().ok_or_else(|| {
            binder::Status::new_service_specific_error(
                keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE.0,
                Some(&CString::new("Operation handle not valid").unwrap()),
            )
        })
    }
}

/// Implement the `IKeyMintOperation` interface for a [`Operation`].  Each method invocation is
/// serialized into a request message that is sent over the `Operation`'s channel, and a
/// corresponding response message is read.  This response message is deserialized back into the
/// method's output value(s).
impl<T: SerializedChannel + 'static> keymint::IKeyMintOperation::IKeyMintOperation
    for Operation<T>
{
    fn updateAad(
        &self,
        mut input: &[u8],
        authToken: Option<&keymint::HardwareAuthToken::HardwareAuthToken>,
        timeStampToken: Option<&TimeStampToken>,
    ) -> binder::Result<()> {
        let req_template = UpdateAadRequest {
            op_handle: self.validate_handle()?,
            input: vec![],
            auth_token: match authToken {
                None => None,
                Some(t) => Some(t.clone().try_innto().map_err(failed_conversion)?),
            },
            timestamp_token: timeStampToken.map(|t| t.clone().innto()),
        };
        while !input.is_empty() {
            let mut req = req_template.clone();
            let batch_len = core::cmp::min(Self::MAX_DATA_SIZE, input.len());
            req.input = input[..batch_len].to_vec();
            input = &input[batch_len..];
            let _rsp: UpdateAadResponse = self.execute(req).inspect_err(|_| {
                // Any failure invalidates the operation
                self.invalidate();
            })?;
        }
        Ok(())
    }
    fn update(
        &self,
        mut input: &[u8],
        authToken: Option<&keymint::HardwareAuthToken::HardwareAuthToken>,
        timeStampToken: Option<&TimeStampToken>,
    ) -> binder::Result<Vec<u8>> {
        let req_template = UpdateRequest {
            op_handle: self.validate_handle()?,
            input: input.to_vec(),
            auth_token: match authToken {
                None => None,
                Some(t) => Some(t.clone().try_innto().map_err(failed_conversion)?),
            },
            timestamp_token: timeStampToken.map(|t| t.clone().innto()),
        };
        let mut output = vec![];
        while !input.is_empty() {
            let mut req = req_template.clone();
            let batch_len = core::cmp::min(Self::MAX_DATA_SIZE, input.len());
            req.input = input[..batch_len].to_vec();
            input = &input[batch_len..];
            let rsp: UpdateResponse = self.execute(req).inspect_err(|_| {
                self.invalidate();
            })?;
            output.extend_from_slice(&rsp.ret);
        }
        Ok(output)
    }
    fn finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        authToken: Option<&keymint::HardwareAuthToken::HardwareAuthToken>,
        timestampToken: Option<&TimeStampToken>,
        confirmationToken: Option<&[u8]>,
    ) -> binder::Result<Vec<u8>> {
        let op_handle = self.validate_handle()?;
        let auth_token = match authToken {
            None => None,
            Some(t) => Some(t.clone().try_innto().map_err(failed_conversion)?),
        };
        let timestamp_token = timestampToken.map(|t| t.clone().innto());
        let confirmation_token = confirmationToken.map(|v| v.to_vec());

        let mut output = vec![];
        let result: binder::Result<FinishResponse> = if let Some(mut input) = input {
            let MAX_DATA_SIZE = Self::MAX_DATA_SIZE;
            while input.len() > MAX_DATA_SIZE {
                let req = UpdateRequest {
                    op_handle,
                    input: input[..MAX_DATA_SIZE].to_vec(),
                    auth_token: auth_token.clone(),
                    timestamp_token: timestamp_token.clone(),
                };
                input = &input[MAX_DATA_SIZE..];
                let rsp: UpdateResponse = self.execute(req).inspect_err(|_| {
                    self.invalidate();
                })?;
                output.extend_from_slice(&rsp.ret);
            }

            self.execute(FinishRequest {
                op_handle,
                input: Some(input.to_vec()),
                signature: signature.map(|v| v.to_vec()),
                auth_token,
                timestamp_token,
                confirmation_token,
            })
        } else {
            self.execute(FinishRequest {
                op_handle,
                input: None,
                signature: signature.map(|v| v.to_vec()),
                auth_token,
                timestamp_token,
                confirmation_token,
            })
        };
        // Finish always invalidates the operation.
        self.invalidate();
        result.map(|rsp| {
            output.extend_from_slice(&rsp.ret);
            output
        })
    }
    fn abort(&self) -> binder::Result<()> {
        let result: binder::Result<AbortResponse> =
            self.execute(AbortRequest { op_handle: self.validate_handle()? });
        // Abort always invalidates the operation.
        self.invalidate();
        let _ = result?;
        Ok(())
    }
}
