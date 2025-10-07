// Copyright 2021, The Android Open Source Project
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

//! Provide the [`KeyMintDevice`] wrapper for operating directly on a KeyMint device.

use std::sync::{Arc, OnceLock};

use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    IKeyMintOperation::IKeyMintOperation, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::global::AID_KEYSTORE;
use crate::keymint::{clock, sdd, soft};
use crate::{
    android::hardware::security::keymint::ErrorCode::ErrorCode,
    err,
    keymaster::{
        db::{
            BlobInfo, BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry,
            KeyEntryLoadBits, KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType,
            KeymasterDb as KeystoreDB, SubComponentType,
        },
        error::KsError as Error,
        super_key::KeyBlob,
    },
    watchdog as wd,
};
use anyhow::{anyhow, Context, Result};
use kmr_crypto_boring::ec::BoringEc;
use kmr_crypto_boring::hmac::BoringHmac;
use kmr_crypto_boring::rng::BoringRng;
use kmr_crypto_boring::rsa::BoringRsa;
use kmr_ta::device::CsrSigningAlgorithm;
use kmr_ta::{HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::KeyMintHardwareInfo;
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;
use log::error;
use rsbinder::Strong;

/// Wrapper for operating directly on a KeyMint device.
/// These methods often mirror methods in [`crate::security_level`]. However
/// the functions in [`crate::security_level`] make assumptions that hold, and has side effects
/// that make sense, only if called by an external client through binder.
/// In addition we are trying to maintain a separation between interface services
/// so that the architecture is compatible with a future move to multiple thread pools.
/// So the simplest approach today is to write new implementations of them for internal use.
/// Because these methods run very early, we don't even try to cooperate with
/// the operation slot database; we assume there will be plenty of slots.
pub struct KeyMintDevice {
    km_dev: KeyMintWrapper,
    version: i32,
    security_level: SecurityLevel,
}

impl KeyMintDevice {
    /// Version number of KeyMasterDevice@V4_0
    pub const KEY_MASTER_V4_0: i32 = 40;
    /// Version number of KeyMasterDevice@V4_1
    pub const KEY_MASTER_V4_1: i32 = 41;
    /// Version number of KeyMintDevice@V1
    pub const KEY_MINT_V1: i32 = 100;
    /// Version number of KeyMintDevice@V2
    pub const KEY_MINT_V2: i32 = 200;
    /// Version number of KeyMintDevice@V3
    pub const KEY_MINT_V3: i32 = 300;

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`]
    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let (km_dev, hw_info) =
            get_keymint_device(security_level).context(err!("get_keymint_device failed"))?;

        Ok(KeyMintDevice {
            km_dev,
            version: hw_info.version_number,
            security_level: get_keymaster_security_level(hw_info.security_level)?,
        })
    }

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`], return
    /// [`None`] if the error `HARDWARE_TYPE_UNAVAILABLE` is returned
    pub fn get_or_none(security_level: SecurityLevel) -> Result<Option<KeyMintDevice>> {
        KeyMintDevice::get(security_level).map(Some).or_else(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)) => Ok(None),
                _ => Err(e),
            }
        })
    }

    /// Returns the version of the underlying KeyMint/KeyMaster device.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the self advertised security level of the KeyMint device.
    /// This may differ from the requested security level if the best security level
    /// on the device is Software.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Create a KM key and store in the database.
    pub fn create_and_store_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        creator: F,
    ) -> Result<()>
    where
        F: FnOnce(KeyMintWrapper) -> Result<KeyCreationResult, rsbinder::Status>,
    {
        let creation_result = creator(self.km_dev).context(err!("creator failed"))?;
        let key_parameters = crate::keymaster::utils::key_characteristics_to_internal(
            creation_result.keyCharacteristics,
        );

        let creation_date = DateTime::now().context(err!("DateTime::now() failed"))?;

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::CreationDate(creation_date));

        db.store_new_key(
            key_desc,
            key_type,
            &key_parameters,
            &BlobInfo::new(&creation_result.keyBlob, &blob_metadata),
            &CertificateInfo::new(None, None),
            &key_metadata,
        )
        .context(err!("store_new_key failed"))?;
        Ok(())
    }

    /// Generate a KeyDescriptor for internal-use keys.
    pub fn internal_descriptor(alias: String) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: AID_KEYSTORE as i64,
            alias: Some(alias),
            blob: None,
        }
    }

    /// Look up an internal-use key in the database given a key descriptor.
    fn lookup_from_desc(
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        db.load_key_entry(key_desc, key_type, KeyEntryLoadBits::KM, AID_KEYSTORE)
            .context(err!("load_key_entry failed."))
    }

    /// Look up the key in the database, and return None if it is absent.
    fn not_found_is_none(
        lookup: Result<(KeyIdGuard, KeyEntry)>,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        match lookup {
            Ok(result) => Ok(Some(result)),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                _ => Err(e),
            },
        }
    }

    /// This does the lookup and store in separate transactions; caller must
    /// hold a lock before calling.
    pub fn lookup_or_generate_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        params: &[KeyParameter],
        validate_characteristics: F,
    ) -> Result<(KeyIdGuard, KeyBlob)>
    where
        F: FnOnce(&[KeyCharacteristics]) -> bool,
    {
        // We use a separate transaction for the lookup than for the store
        // - to keep the code simple
        // - because the caller needs to hold a lock in any case
        // - because it avoids holding database locks during slow
        //   KeyMint operations
        let lookup = Self::not_found_is_none(Self::lookup_from_desc(db, key_desc, key_type))
            .context(err!("first lookup failed"))?;

        if let Some((key_id_guard, mut key_entry)) = lookup {
            // If the key is associated with a different km instance
            // or if there is no blob metadata for some reason the key entry
            // is considered corrupted and needs to be replaced with a new one.
            let key_blob = key_entry
                .take_key_blob_info()
                .and_then(|(key_blob, blob_metadata)| Some(key_blob));

            if let Some(key_blob_vec) = key_blob {
                let (key_characteristics, key_blob) = self
                    .upgrade_keyblob_if_required_with(
                        db,
                        &key_id_guard,
                        KeyBlob::NonSensitive(key_blob_vec),
                        |key_blob| {
                            let _wp = wd::watch(concat!(
                                "KeyMintDevice::lookup_or_generate_key: ",
                                "calling IKeyMintDevice::getKeyCharacteristics."
                            ));
                            self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                        },
                    )
                    .context(err!("calling getKeyCharacteristics"))?;

                if validate_characteristics(&key_characteristics) {
                    return Ok((key_id_guard, key_blob));
                }

                // If this point is reached the existing key is considered outdated or corrupted
                // in some way. It will be replaced with a new key below.
            };
        }

        self.create_and_store_key(db, key_desc, key_type, |km_dev| {
            km_dev.generateKey(params, None)
        })
        .context(err!("generate_and_store_key failed"))?;
        Self::lookup_from_desc(db, key_desc, key_type)
            .and_then(|(key_id_guard, mut key_entry)| {
                Ok((
                    key_id_guard,
                    key_entry
                        .take_key_blob_info()
                        .ok_or(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                        .map(|(key_blob, _)| KeyBlob::NonSensitive(key_blob))
                        .context(err!("Missing key blob info."))?,
                ))
            })
            .context(err!("second lookup failed"))
    }

    /// Call the passed closure; if it returns `KEY_REQUIRES_UPGRADE`, call upgradeKey, and
    /// write the upgraded key to the database.
    fn upgrade_keyblob_if_required_with<'a, T, F>(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        key_blob: KeyBlob<'a>,
        f: F,
    ) -> Result<(T, KeyBlob<'a>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let (f_result, upgraded_blob) = crate::keymaster::utils::upgrade_keyblob_if_required_with(
            &self.km_dev,
            self.version(),
            &key_blob,
            &[],
            f,
            |upgraded_blob| {
                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                db.set_blob(
                    key_id_guard,
                    SubComponentType::KEY_BLOB,
                    Some(upgraded_blob),
                    Some(&new_blob_metadata),
                )
                .context(err!("Failed to insert upgraded blob into the database"))?;
                Ok(())
            },
        )?;
        let returned_blob = match upgraded_blob {
            None => key_blob,
            Some(upgraded_blob) => KeyBlob::NonSensitive(upgraded_blob),
        };
        Ok((f_result, returned_blob))
    }

    /// Use the created key in an operation that can be done with
    /// a call to begin followed by a call to finish.
    pub fn use_key_in_one_step(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        key_blob: &[u8],
        purpose: KeyPurpose,
        operation_parameters: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let key_blob = KeyBlob::Ref(key_blob);

        let (begin_result, _) = self
            .upgrade_keyblob_if_required_with(db, key_id_guard, key_blob, |blob| {
                let _wp =
                    wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::begin");
                self.km_dev
                    .begin(purpose, blob, operation_parameters, auth_token)
            })
            .context(err!("Failed to begin operation."))?;
        let operation: Strong<dyn IKeyMintOperation> = begin_result
            .operation
            .ok_or_else(Error::sys)
            .context(err!("Operation missing"))?;
        let _wp = wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::finish");
        operation
            .finish(Some(input), None, None, None, None)
            .context(err!("Failed to finish operation."))
    }
}

static mut KM_WRAPPER_STRONGBOX: OnceLock<KeyMintWrapper> = OnceLock::new();

static mut KM_WRAPPER_TEE: OnceLock<KeyMintWrapper> = OnceLock::new();

struct KeyMintWrapper {
    km: KeyMintTa,
    security_level: SecurityLevel,
}

unsafe impl Sync for KeyMintWrapper {}

impl KeyMintWrapper {
    fn new(security_level: SecurityLevel) -> Result<Self> {
        Ok(KeyMintWrapper {
            km: init_keymint_ta(security_level)?,
            security_level: security_level.clone(),
        })
    }

    fn begin(
        &self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
    ) -> Result<crate::android::hardware::security::keymint::KeyMintOperationResult> {
        let calling_context = CallingContext::get();
        self.km
            .begin(
                &calling_context,
                purpose,
                key_blob,
                params,
                auth_token,
                None,
            )
            .map_err(|e| anyhow!(err!("KeyMintWrapper::begin failed: {:?}", e)))
    }
}

pub fn get_keymint_security_level(
    security_level: SecurityLevel,
) -> Result<kmr_wire::keymint::SecurityLevel> {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            Ok(kmr_wire::keymint::SecurityLevel::TrustedEnvironment)
        }
        SecurityLevel::STRONGBOX => Ok(kmr_wire::keymint::SecurityLevel::Strongbox),
        _ => Err(anyhow::anyhow!(err!("Unknown security level"))),
    }
}

pub fn get_keymaster_security_level(
    security_level: kmr_wire::keymint::SecurityLevel,
) -> Result<SecurityLevel> {
    match security_level {
        kmr_wire::keymint::SecurityLevel::TrustedEnvironment => {
            Ok(SecurityLevel::TRUSTED_ENVIRONMENT)
        }
        kmr_wire::keymint::SecurityLevel::Strongbox => Ok(SecurityLevel::STRONGBOX),
        _ => Err(anyhow::anyhow!(err!("Unknown security level"))),
    }
}

fn init_keymint_ta(security_level: SecurityLevel) -> Result<KeyMintTa> {
    let security_level = get_keymint_security_level(security_level)?;

    let hw_info = HardwareInfo {
        version_number: 2,
        security_level,
        impl_name: "Qualcomm QTEE KeyMint 2",
        author_name: "Qualcomm Technologies",
        unique_id: "Qualcomm QTEE KeyMint 2",
    };

    let rpc_sign_algo = CsrSigningAlgorithm::EdDSA;
    let rpc_info_v3 = RpcInfoV3 {
        author_name: "Qualcomm Technologies",
        unique_id: "Qualcomm QTEE KeyMint 2",
        fused: false,
        supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    let mut rng = BoringRng;

    let sdd_mgr: Option<Box<dyn kmr_common::keyblob::SecureDeletionSecretManager>> =
        match sdd::HostSddManager::new(&mut rng) {
            Ok(v) => Some(Box::new(v)),
            Err(e) => {
                error!("Failed to initialize secure deletion data manager: {:?}", e);
                None
            }
        };

    let clock = clock::StdClock;
    let rsa = BoringRsa::default();
    let ec = BoringEc::default();
    let hkdf: Box<dyn kmr_common::crypto::Hkdf> = Box::new(BoringHmac);
    let imp = kmr_common::crypto::Implementation {
        rng: Box::new(rng),
        clock: Some(Box::new(clock)),
        compare: Box::new(kmr_crypto_boring::eq::BoringEq),
        aes: Box::new(kmr_crypto_boring::aes::BoringAes),
        des: Box::new(kmr_crypto_boring::des::BoringDes),
        hmac: Box::new(BoringHmac),
        rsa: Box::new(rsa),
        ec: Box::new(ec),
        ckdf: Box::new(kmr_crypto_boring::aes_cmac::BoringAesCmac),
        hkdf,
        sha256: Box::new(kmr_crypto_boring::sha256::BoringSha256),
    };

    let keys: Box<dyn kmr_ta::device::RetrieveKeyMaterial> = Box::new(soft::Keys);
    let rpc: Box<dyn kmr_ta::device::RetrieveRpcArtifacts> = Box::new(soft::RpcArtifacts::new(
        soft::Derive::default(),
        rpc_sign_algo,
    ));

    let dev = kmr_ta::device::Implementation {
        keys,
        // Cuttlefish has `remote_provisioning.tee.rkp_only=1` so don't support batch signing
        // of keys.  This can be reinstated with:
        // ```
        // sign_info: Some(kmr_ta_nonsecure::attest::CertSignInfo::new()),
        // ```
        sign_info: Some(Box::new(crate::keymint::attest::CertSignInfo::new())),
        // HAL populates attestation IDs from properties.
        attest_ids: None,
        sdd_mgr,
        // `BOOTLOADER_ONLY` keys not supported.
        bootloader: Box::new(kmr_ta::device::BootloaderDone),
        // `STORAGE_KEY` keys not supported.
        sk_wrapper: None,
        // `TRUSTED_USER_PRESENCE_REQUIRED` keys not supported
        tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
        // No support for converting previous implementation's keyblobs.
        legacy_key: None,
        rpc,
    };

    Ok(KeyMintTa::new(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev))
}

fn get_keymint_device(
    security_level: SecurityLevel,
) -> Result<(KeyMintWrapper, KeyMintHardwareInfo)> {
    match security_level {
        SecurityLevel::STRONGBOX => {
            let strongbox = unsafe {
                *KM_WRAPPER_STRONGBOX.get_or_init(|| {
                    KeyMintWrapper::new(SecurityLevel::STRONGBOX)
                        .expect(err!("Failed to init strongbox wrapper"))
                })
            };
            let info = strongbox
                .km
                .get_hardware_info()
                .expect(err!("Failed to get hardware info"));
            Ok((strongbox, info))
        }
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            let tee = unsafe {
                *KM_WRAPPER_TEE.get_or_init(|| {
                    KeyMintWrapper::new(SecurityLevel::TRUSTED_ENVIRONMENT)
                        .expect(err!("Failed to init tee wrapper"))
                })
            };
            let info = tee
                .km
                .get_hardware_info()
                .expect(err!("Failed to get hardware info"));
            Ok((tee, info))
        }
        SecurityLevel::SOFTWARE => Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
            .context(err!("Software KeyMint not supported")),
        _ => Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
            .context(err!("Unknown security level")),
    }
}
