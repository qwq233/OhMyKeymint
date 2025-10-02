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

//! RemotelyProvisionedComponent HAL device implementation.

use super::{ChannelHalService, SerializedChannel};
use crate::binder;
use crate::hal::{rkp, Innto};
use kmr_wire::*;
use std::sync::{Arc, Mutex, MutexGuard};

/// `IRemotelyProvisionedComponent` implementation which converts all method invocations to
/// serialized requests that are sent down the associated channel.
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
    ) -> binder::Strong<dyn rkp::IRemotelyProvisionedComponent::IRemotelyProvisionedComponent> {
        rkp::IRemotelyProvisionedComponent::BnRemotelyProvisionedComponent::new_binder(
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

impl<T: SerializedChannel> rkp::IRemotelyProvisionedComponent::IRemotelyProvisionedComponent
    for Device<T>
{
    fn getHardwareInfo(&self) -> binder::Result<rkp::RpcHardwareInfo::RpcHardwareInfo> {
        let rsp: GetRpcHardwareInfoResponse = self.execute(GetRpcHardwareInfoRequest {})?;
        Ok(rsp.ret.innto())
    }
    fn generateEcdsaP256KeyPair(
        &self,
        testMode: bool,
        macedPublicKey: &mut rkp::MacedPublicKey::MacedPublicKey,
    ) -> binder::Result<Vec<u8>> {
        let rsp: GenerateEcdsaP256KeyPairResponse =
            self.execute(GenerateEcdsaP256KeyPairRequest { test_mode: testMode })?;
        *macedPublicKey = rsp.maced_public_key.innto();
        Ok(rsp.ret)
    }
    fn generateCertificateRequest(
        &self,
        testMode: bool,
        keysToSign: &[rkp::MacedPublicKey::MacedPublicKey],
        endpointEncryptionCertChain: &[u8],
        challenge: &[u8],
        deviceInfo: &mut rkp::DeviceInfo::DeviceInfo,
        protectedData: &mut rkp::ProtectedData::ProtectedData,
    ) -> binder::Result<Vec<u8>> {
        let rsp: GenerateCertificateRequestResponse =
            self.execute(GenerateCertificateRequestRequest {
                test_mode: testMode,
                keys_to_sign: keysToSign.iter().map(|k| k.innto()).collect(),
                endpoint_encryption_cert_chain: endpointEncryptionCertChain.to_vec(),
                challenge: challenge.to_vec(),
            })?;
        *deviceInfo = rsp.device_info.innto();
        *protectedData = rsp.protected_data.innto();
        Ok(rsp.ret)
    }
    fn generateCertificateRequestV2(
        &self,
        keysToSign: &[rkp::MacedPublicKey::MacedPublicKey],
        challenge: &[u8],
    ) -> binder::Result<Vec<u8>> {
        let rsp: GenerateCertificateRequestV2Response =
            self.execute(GenerateCertificateRequestV2Request {
                keys_to_sign: keysToSign.iter().map(|k| k.innto()).collect(),
                challenge: challenge.to_vec(),
            })?;
        Ok(rsp.ret)
    }
}
