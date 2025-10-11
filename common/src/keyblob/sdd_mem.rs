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

//! In-memory secure deletion secret manager.
//!
//! Only suitable for development/testing (as secrets are lost on restart).

use super::{SecureDeletionData, SecureDeletionSecretManager, SecureDeletionSlot, SlotPurpose};
use crate::{crypto, km_err, Error};

/// Secure deletion secret manager that keeps state in memory. Provided as an example only; do not
/// use in a real system (keys will not survive reboot if you do).
pub struct InMemorySlotManager<const N: usize> {
    factory_secret: Option<[u8; 32]>,
    slots: [Option<SecureDeletionData>; N],
}

impl<const N: usize> Default for InMemorySlotManager<N> {
    fn default() -> Self {
        Self {
            factory_secret: None,
            // Work around Rust limitation that `[None; N]` doesn't work.
            slots: [(); N].map(|_| Option::<SecureDeletionData>::default()),
        }
    }
}

impl<const N: usize> SecureDeletionSecretManager for InMemorySlotManager<N> {
    fn get_or_create_factory_reset_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<SecureDeletionData, Error> {
        if self.factory_secret.is_none() {
            // No factory reset secret created yet, so do so now.
            let mut secret = [0; 32];
            rng.fill_bytes(&mut secret[..]);
            self.factory_secret = Some(secret);
        }
        self.get_factory_reset_secret()
    }

    fn get_factory_reset_secret(&self) -> Result<SecureDeletionData, Error> {
        match self.factory_secret {
            Some(secret) => Ok(SecureDeletionData {
                factory_reset_secret: secret,
                secure_deletion_secret: [0; 16],
            }),
            None => Err(km_err!(UnknownError, "no factory secret available!")),
        }
    }

    fn new_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
        _purpose: SlotPurpose,
    ) -> Result<(SecureDeletionSlot, SecureDeletionData), Error> {
        for idx in 0..N {
            if self.slots[idx].is_none() {
                let mut sdd = self.get_or_create_factory_reset_secret(rng)?;
                rng.fill_bytes(&mut sdd.secure_deletion_secret[..]);
                self.slots[idx] = Some(sdd.clone());
                return Ok((SecureDeletionSlot(idx as u32), sdd));
            }
        }
        Err(km_err!(RollbackResistanceUnavailable, "full"))
    }

    fn get_secret(&self, slot: SecureDeletionSlot) -> Result<SecureDeletionData, Error> {
        let idx = slot.0 as usize;
        if !(0..N).contains(&idx) {
            return Err(km_err!(InvalidKeyBlob, "slot idx out of bounds"));
        }
        match &self.slots[idx] {
            Some(data) => Ok(data.clone()),
            None => Err(km_err!(InvalidKeyBlob, "slot idx empty")),
        }
    }

    fn delete_secret(&mut self, slot: SecureDeletionSlot) -> Result<(), Error> {
        match self.slots[slot.0 as usize].take() {
            Some(_data) => Ok(()),
            None => Err(km_err!(InvalidKeyBlob, "slot idx empty")),
        }
    }

    fn delete_all(&mut self) {
        self.factory_secret = None;
        for idx in 0..N {
            self.slots[idx] = None;
        }
    }
}
