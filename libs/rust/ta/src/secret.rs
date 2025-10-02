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

//! TA functionality for shared secret negotiation.

use crate::device::DeviceHmac;
use kmr_common::{crypto, crypto::hmac, km_err, vec_try, Error, FallibleAllocExt};
use kmr_wire::{keymint::Digest, sharedsecret::SharedSecretParameters};
use log::info;

impl crate::KeyMintTa {
    pub(crate) fn get_shared_secret_params(&mut self) -> Result<SharedSecretParameters, Error> {
        if self.shared_secret_params.is_none() {
            let mut nonce = vec_try![0u8; 32]?;
            self.imp.rng.fill_bytes(&mut nonce);
            self.shared_secret_params = Some(SharedSecretParameters { seed: Vec::new(), nonce });
        }
        Ok(self.shared_secret_params.as_ref().unwrap().clone()) // safe: filled above
    }

    pub(crate) fn compute_shared_secret(
        &mut self,
        params: &[SharedSecretParameters],
    ) -> Result<Vec<u8>, Error> {
        info!("Setting HMAC key from {} shared secret parameters", params.len());
        let local_params = match &self.shared_secret_params {
            Some(params) => params,
            None => return Err(km_err!(HardwareNotYetAvailable, "no local shared secret params")),
        };

        let context = shared_secret_context(params, local_params)?;
        let key = hmac::Key(self.imp.ckdf.ckdf(
            &self.dev.keys.kak()?,
            kmr_wire::sharedsecret::KEY_AGREEMENT_LABEL.as_bytes(),
            &[&context],
            kmr_common::crypto::SHA256_DIGEST_LEN,
        )?);

        // Potentially hand the negotiated HMAC key off to hardware.
        self.device_hmac = Some(self.dev.keys.hmac_key_agreed(&key).unwrap_or_else(|| {
            // Key not installed into hardware, so build & use a local impl.
            Box::new(SoftDeviceHmac { key })
        }));
        self.device_hmac(kmr_wire::sharedsecret::KEY_CHECK_LABEL.as_bytes())
    }
}

/// Build the shared secret context from the given `params`, which
/// is required to include `must_include` (our own parameters).
pub fn shared_secret_context(
    params: &[SharedSecretParameters],
    must_include: &SharedSecretParameters,
) -> Result<Vec<u8>, crate::Error> {
    let mut result = Vec::new();
    let mut seen = false;
    for param in params {
        result.try_extend_from_slice(&param.seed)?;
        if param.nonce.len() != 32 {
            return Err(km_err!(InvalidArgument, "nonce len {} not 32", param.nonce.len()));
        }
        result.try_extend_from_slice(&param.nonce)?;
        if param == must_include {
            seen = true;
        }
    }
    if !seen {
        Err(km_err!(InvalidArgument, "shared secret params missing local value"))
    } else {
        Ok(result)
    }
}

/// Device HMAC implementation that holds the HMAC key in memory.
struct SoftDeviceHmac {
    key: crypto::hmac::Key,
}

impl DeviceHmac for SoftDeviceHmac {
    fn hmac(&self, imp: &dyn crypto::Hmac, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut hmac_op = imp.begin(self.key.clone().into(), Digest::Sha256)?;
        hmac_op.update(data)?;
        hmac_op.finish()
    }

    fn get_hmac_key(&self) -> Option<crypto::hmac::Key> {
        Some(self.key.clone())
    }
}
