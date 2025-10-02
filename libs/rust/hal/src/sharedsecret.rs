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

//! SharedSecret HAL device implementation.

use crate::binder;
use crate::hal::{
    sharedsecret::{ISharedSecret, SharedSecretParameters::SharedSecretParameters},
    Innto,
};
use crate::{ChannelHalService, SerializedChannel};
use kmr_wire::*;
use std::sync::{Arc, Mutex, MutexGuard};

/// `ISharedSecret` implementation which converts all method invocations to serialized requests that
/// are sent down the associated channel.
pub struct Device<T: SerializedChannel + 'static> {
    channel: Arc<Mutex<T>>,
}

impl<T: SerializedChannel + Send> binder::Interface for Device<T> {}

impl<T: SerializedChannel + 'static> Device<T> {
    /// Construct a new instance that uses the provided channel.
    pub fn new(channel: Arc<Mutex<T>>) -> Self {
        Self { channel }
    }
    /// Create a new instance wrapped in a proxy object.
    pub fn new_as_binder(
        channel: Arc<Mutex<T>>,
    ) -> binder::Strong<dyn ISharedSecret::ISharedSecret> {
        ISharedSecret::BnSharedSecret::new_binder(
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

impl<T: SerializedChannel> ISharedSecret::ISharedSecret for Device<T> {
    fn getSharedSecretParameters(&self) -> binder::Result<SharedSecretParameters> {
        let rsp: GetSharedSecretParametersResponse =
            self.execute(GetSharedSecretParametersRequest {})?;
        Ok(rsp.ret.innto())
    }
    fn computeSharedSecret(&self, params: &[SharedSecretParameters]) -> binder::Result<Vec<u8>> {
        let rsp: ComputeSharedSecretResponse =
            self.execute(ComputeSharedSecretRequest { params: params.to_vec().innto() })?;
        Ok(rsp.ret)
    }
}
