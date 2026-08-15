// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Host-file secure deletion data manager.
//! Secrets live under `/data/misc/keystore/omk/data/` and are not readable by
//! ordinary Android apps. They are not isolated from a privileged host.

use crate::proto::storage;
use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use kmr_common::{crypto, keyblob, km_err, Error};
use log::error;
use log::info;
use prost::Message;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

pub(crate) const SECURE_DELETION_DATA_FILE: &str = "/data/misc/keystore/omk/data/keymint.dat";
pub(crate) const STRONGBOX_SECURE_DELETION_DATA_FILE: &str =
    "/data/misc/keystore/omk/data/keymint-strongbox.dat";

fn read_sdd_file(path: &Path) -> Result<storage::SecureDeletionData, Error> {
    let f = fs::File::open(path).map_err(|e| {
        km_err!(
            SecureHwCommunicationFailed,
            "failed to open secure deletion data file: {:?}",
            e
        )
    })?;
    let mut buf = std::io::BufReader::new(f);
    let mut buf = buf.fill_buf().map_err(|e| {
        km_err!(
            SecureHwCommunicationFailed,
            "failed to read secure deletion data file: {:?}",
            e
        )
    })?;
    storage::SecureDeletionData::decode(&mut buf).map_err(|e| {
        km_err!(
            SecureHwCommunicationFailed,
            "failed to parse secure deletion data: {:?}",
            e
        )
    })
}

fn sdd_file_owner(path: &Path) -> (u32, u32) {
    if path.starts_with("/data/misc/keystore/omk/data") {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn write_sdd_file(path: &Path, data: &storage::SecureDeletionData) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(data.encoded_len());
    data.encode(&mut buf).map_err(|e| {
        km_err!(
            SecureHwCommunicationFailed,
            "failed to encode secure deletion data: {:?}",
            e
        )
    })?;
    let (uid, gid) = sdd_file_owner(path);
    atomic_replace_preserving_metadata(path, &buf, 0o600, uid, gid).map_err(|e| {
        km_err!(
            SecureHwCommunicationFailed,
            "failed to write secure deletion data file: {:?}",
            e
        )
    })
}

pub struct HostSddManager {
    path: PathBuf,
    // Local cache of data stored on disk.
    data: storage::SecureDeletionData,
}

impl HostSddManager {
    fn randomize_factory_secret(data: &mut storage::SecureDeletionData, rng: &mut dyn crypto::Rng) {
        data.factory_secret.resize(32, 0);
        rng.fill_bytes(&mut data.factory_secret[..]);
    }

    fn validate_loaded_data(data: &mut storage::SecureDeletionData) -> Result<(), String> {
        if data.factory_secret.len() != 32 {
            return Err(format!(
                "factory_secret must be 32 bytes, got {}",
                data.factory_secret.len()
            ));
        }
        if data.factory_secret.iter().all(|byte| *byte == 0) {
            return Err("factory_secret must not be all zero".to_string());
        }

        let mut max_slot = 0u32;
        for (slot, secret) in &data.secure_deletion_secrets {
            if secret.len() != 16 {
                return Err(format!(
                    "secure deletion secret for slot {} must be 16 bytes, got {}",
                    slot,
                    secret.len()
                ));
            }
            max_slot = max_slot.max(*slot);
        }
        if data.last_free_slot < max_slot {
            data.last_free_slot = max_slot;
        }
        Ok(())
    }

    fn init(&mut self, rng: &mut dyn crypto::Rng) -> Result<(), Error> {
        // Restore data from disk if it was previously saved.
        if self.path.exists() {
            info!("parsing existing secure deletion data file");
            self.data = read_sdd_file(&self.path)?;
            if let Err(reason) = Self::validate_loaded_data(&mut self.data) {
                error!("secure deletion data is invalid: {reason}");
                return Err(km_err!(
                    SecureHwCommunicationFailed,
                    "invalid secure deletion data: {reason}"
                ));
            }
            return Ok(());
        }

        info!("creating secure deletion data file");

        // Initialize factory reset secret.
        Self::randomize_factory_secret(&mut self.data, rng);

        // Create secure deletion data file.
        write_sdd_file(&self.path, &self.data)
    }

    pub fn new(rng: &mut dyn crypto::Rng) -> Result<Self, Error> {
        Self::new_with_path(rng, SECURE_DELETION_DATA_FILE)
    }

    pub fn new_with_path(
        rng: &mut dyn crypto::Rng,
        path: impl Into<PathBuf>,
    ) -> Result<Self, Error> {
        let mut sdd_mgr = Self {
            path: path.into(),
            data: storage::SecureDeletionData::default(),
        };
        sdd_mgr.init(rng).map(|_| sdd_mgr)
    }
}

impl keyblob::SecureDeletionSecretManager for HostSddManager {
    fn get_or_create_factory_reset_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        if self.data.factory_secret.is_empty() {
            self.init(rng)?;
        }
        self.get_factory_reset_secret()
    }

    fn get_factory_reset_secret(&self) -> Result<keyblob::SecureDeletionData, Error> {
        if self.data.factory_secret.len() != 32 {
            return Err(km_err!(UnknownError, "no factory secret available"));
        }
        Ok(keyblob::SecureDeletionData {
            factory_reset_secret: self.data.factory_secret.clone().try_into().unwrap(),
            secure_deletion_secret: [0; 16],
        })
    }

    fn new_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
        _purpose: keyblob::SlotPurpose,
    ) -> Result<(keyblob::SecureDeletionSlot, keyblob::SecureDeletionData), Error> {
        // Allocate new slot ID.
        let slot_id = self.data.last_free_slot.checked_add(1).ok_or(km_err!(
            RollbackResistanceUnavailable,
            "ran out of slot IDs"
        ))?;

        info!("generating secure deletion secret slot_id={:?}", slot_id);

        assert!(
            !self.data.secure_deletion_secrets.contains_key(&slot_id),
            "Slot ID already in use: {:?}",
            slot_id
        );

        // Generate new sdd.
        let mut sdd = self.get_or_create_factory_reset_secret(rng)?;
        rng.fill_bytes(&mut sdd.secure_deletion_secret[..]);

        // Cache the secure deletion secret locally.
        self.data
            .secure_deletion_secrets
            .insert(slot_id, sdd.secure_deletion_secret.to_vec());
        self.data.last_free_slot = slot_id;

        // Save the secure deletion secret on disk.
        match write_sdd_file(&self.path, &self.data) {
            Ok(_) => Ok((keyblob::SecureDeletionSlot(slot_id), sdd)),
            Err(e) => {
                // Restore cached state.
                self.data.secure_deletion_secrets.remove(&slot_id).unwrap();
                self.data.last_free_slot = slot_id - 1;
                Err(e)
            }
        }
    }

    fn get_secret(
        &self,
        slot: keyblob::SecureDeletionSlot,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        let slot_id = slot.0;
        info!("fetching secure deletion secret slot_id={:?}", slot_id);

        let secret = self
            .data
            .secure_deletion_secrets
            .get(&slot_id)
            .ok_or(km_err!(InvalidKeyBlob, "slot ID: {:?} not found.", slot_id))?;
        Ok(keyblob::SecureDeletionData {
            factory_reset_secret: self.data.factory_secret.clone().try_into().unwrap(),
            secure_deletion_secret: secret.clone().try_into().unwrap(),
        })
    }

    fn delete_secret(&mut self, slot: keyblob::SecureDeletionSlot) -> Result<(), Error> {
        let slot_id = slot.0;
        info!("deleting secure deletion secret slot_id={:?}", slot_id);

        let secret = self
            .data
            .secure_deletion_secrets
            .remove(&slot_id)
            .ok_or(km_err!(InvalidKeyBlob, "slot ID not found."))?;

        // Save the secure deletion secret on disk.
        if let Err(e) = write_sdd_file(&self.path, &self.data) {
            // Restore cached state.
            self.data
                .secure_deletion_secrets
                .insert(slot_id, secret)
                .unwrap();
            return Err(e);
        }
        Ok(())
    }

    fn delete_all(&mut self) -> Result<(), Error> {
        info!("deleting all secure deletion secrets");
        self.data = storage::SecureDeletionData::default();
        if !self.path.exists() {
            return Ok(());
        }
        for _ in 0..5 {
            match fs::remove_file(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => error!("failed to delete secure deletion data file: {:?}", e),
            }
        }
        Err(km_err!(
            SecureHwCommunicationFailed,
            "failed to delete secure deletion data file"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_common::keyblob::{SecureDeletionSecretManager, SlotPurpose};
    use kmr_crypto_boring::rng::BoringRng;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_sdd_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "omk-sdd-{}-{}-{}.dat",
            label,
            std::process::id(),
            TEST_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn separate_paths_do_not_share_factory_secrets() {
        let mut rng = BoringRng;
        let tee_path = temp_sdd_path("tee");
        let strongbox_path = temp_sdd_path("strongbox");
        let tee = HostSddManager::new_with_path(&mut rng, &tee_path).unwrap();
        let strongbox = HostSddManager::new_with_path(&mut rng, &strongbox_path).unwrap();
        let tee_secret = tee.get_factory_reset_secret().unwrap();
        let strongbox_secret = strongbox.get_factory_reset_secret().unwrap();
        assert_ne!(
            tee_secret.factory_reset_secret,
            strongbox_secret.factory_reset_secret
        );
        let _ = fs::remove_file(tee_path);
        let _ = fs::remove_file(strongbox_path);
    }

    #[test]
    fn delete_all_on_one_path_does_not_wipe_the_other() {
        let mut rng = BoringRng;
        let tee_path = temp_sdd_path("tee-keep");
        let strongbox_path = temp_sdd_path("strongbox-wipe");
        let mut tee = HostSddManager::new_with_path(&mut rng, &tee_path).unwrap();
        let mut strongbox = HostSddManager::new_with_path(&mut rng, &strongbox_path).unwrap();
        let (_slot, tee_sdd) = tee
            .new_secret(&mut rng, SlotPurpose::KeyGeneration)
            .unwrap();
        strongbox.delete_all().unwrap();
        let tee_after = tee.get_factory_reset_secret().unwrap();
        assert_eq!(tee_sdd.factory_reset_secret, tee_after.factory_reset_secret);
        assert!(!strongbox_path.exists());
        let _ = fs::remove_file(tee_path);
    }

    #[test]
    fn invalid_file_is_not_reinitialized() {
        let path = temp_sdd_path("torn");
        fs::write(&path, b"not-a-valid-protobuf").unwrap();
        let mut rng = BoringRng;
        assert!(HostSddManager::new_with_path(&mut rng, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not-a-valid-protobuf");
        let _ = fs::remove_file(path);
    }
}
