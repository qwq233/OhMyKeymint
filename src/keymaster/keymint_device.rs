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

use std::sync::{OnceLock, RwLock};

use crate::android::hardware::security::keymint::IKeyMintOperation::BnKeyMintOperation;
use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    IKeyMintOperation::IKeyMintOperation, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::config::CONFIG;
use crate::global::{AID_KEYSTORE, DB};
use crate::keymaster::apex::encode_module_info;
use crate::keymaster::db::Uuid;
use crate::keymaster::error::{map_binder_status, map_ks_error, map_ks_result};
use crate::keymaster::utils::{key_creation_result_to_aidl, key_param_to_aidl};
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
use anyhow::{Context, Ok, Result};
use kmr_common::crypto::Rng;
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::ec::BoringEc;
use kmr_crypto_boring::hmac::BoringHmac;
use kmr_crypto_boring::rng::BoringRng;
use kmr_crypto_boring::rsa::BoringRsa;
use kmr_crypto_boring::sha256::BoringSha256;
use kmr_ta::device::CsrSigningAlgorithm;
use kmr_ta::{HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::{AttestationKey, KeyParam};
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;
use kmr_wire::*;
use log::{error, warn};
use rsbinder::{ExceptionCode, Interface, Status, Strong};

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
    km_uuid: RwLock<Uuid>,
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
        let km_dev = KeyMintWrapper::new(security_level)
            .expect(err!("Failed to init strongbox wrapper").as_str());
        let hw_info = km_dev.get_hardware_info().unwrap();

        let km_uuid = RwLock::new(Uuid::from(security_level));
        let wrapper: KeyMintWrapper = KeyMintWrapper::new(security_level).unwrap();
        Ok(KeyMintDevice {
            km_dev: wrapper,
            version: hw_info.version_number,
            km_uuid,
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

    pub fn uuid(&self) -> Uuid {
        *self.km_uuid.read().unwrap()
    }

    pub fn terminate_uuid(&mut self) -> Result<()> {
        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.terminate_uuid(&self.km_uuid.read().unwrap())
                .context(err!("terminate_uuid failed"))
        })?;

        self.km_uuid = RwLock::new(Uuid::from(self.security_level));
        Ok(())
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
        F: FnOnce(&dyn IKeyMintDevice) -> Result<KeyCreationResult, rsbinder::Status>,
    {
        let creation_result = creator(&self.km_dev).context(err!("creator failed"))?;
        let key_parameters = crate::keymaster::utils::key_characteristics_to_internal(
            creation_result.keyCharacteristics,
        );

        let creation_date = DateTime::now().context(err!("DateTime::now() failed"))?;

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
        let mut blob_metadata = BlobMetaData::new();
        blob_metadata.add(BlobMetaEntry::KmUuid(*self.km_uuid.read().unwrap()));

        db.store_new_key(
            key_desc,
            key_type,
            &key_parameters,
            &BlobInfo::new(&creation_result.keyBlob, &blob_metadata),
            &CertificateInfo::new(None, None),
            &key_metadata,
            &*self.km_uuid.read().unwrap(),
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
            Result::Ok(result) => Ok(Some(result)),
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
    ) -> Result<(KeyIdGuard, KeyBlob<'_>)>
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
                .and_then(|(key_blob, blob_metadata)| {
                    if Some(*self.km_uuid.read().unwrap()) == blob_metadata.km_uuid().copied() {
                        Some(key_blob)
                    } else {
                        None
                    }
                });

            if let Some(key_blob_vec) = key_blob {
                let (key_characteristics, key_blob) = self
                    .upgrade_keyblob_if_required_with(
                        db,
                        &key_id_guard,
                        KeyBlob::NonSensitive(key_blob_vec),
                        |key_blob| {
                            map_binder_status({
                                let _wp = wd::watch(concat!(
                                    "KeyMintDevice::lookup_or_generate_key: ",
                                    "calling IKeyMintDevice::getKeyCharacteristics."
                                ));
                                self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                            })
                        },
                    )
                    .context(err!("calling getKeyCharacteristics"))?;

                if validate_characteristics(&key_characteristics[..]) {
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
            self.security_level.clone(),
            self.version(),
            &key_blob,
            &[],
            f,
            |upgraded_blob| {
                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(*self.km_uuid.read().unwrap()));

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
                let result: std::result::Result<
                    crate::android::hardware::security::keymint::BeginResult::BeginResult,
                    Status,
                > = self
                    .km_dev
                    .begin(purpose, blob, operation_parameters, auth_token);
                map_binder_status(result)
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

use std::sync::Mutex;

static KM_WRAPPER_STRONGBOX: OnceLock<Mutex<KeyMintWrapper>> = OnceLock::new();

static KM_WRAPPER_TEE: OnceLock<Mutex<KeyMintWrapper>> = OnceLock::new();

pub struct KeyMintWrapper {
    security_level: SecurityLevel,
    keymint: Mutex<KeyMintTa>,
}

unsafe impl Sync for KeyMintWrapper {}

impl Interface for KeyMintWrapper {}

#[allow(non_snake_case)]
impl IKeyMintDevice for KeyMintWrapper {
    fn begin(
        &self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
    ) -> Result<crate::android::hardware::security::keymint::BeginResult::BeginResult, Status> {
        let km_params: Result<Vec<KeyParam>> = params.iter().cloned().map(|p| p.to_km()).collect();
        let km_params = km_params.map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT));
        let km_params = map_ks_result(km_params)?;

        let req = PerformOpReq::DeviceBegin(BeginRequest {
            purpose: kmr_wire::keymint::KeyPurpose::try_from(purpose.0).map_err(|_| {
                Status::new_service_specific_error(ErrorCode::INVALID_ARGUMENT.0, None)
            })?,
            key_blob: key_blob.to_vec(),
            params: km_params.clone(),
            auth_token: auth_token.map(|at| at.to_km()).transpose().map_err(|_| {
                Status::new_service_specific_error(ErrorCode::INVALID_ARGUMENT.0, None)
            })?,
        });

        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result: InternalBeginResult = match result.rsp.unwrap() {
            PerformOpRsp::DeviceBegin(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        let operation = crate::keymaster::keymint_operation::KeyMintOperation::new(
            self.security_level.clone(),
            result.challenge,
            km_params,
            result.op_handle,
        );
        let operation = BnKeyMintOperation::new_binder(operation);

        let resp = crate::android::hardware::security::keymint::BeginResult::BeginResult {
            operation: Some(operation),
            challenge: result.challenge,
            params: params.to_vec(),
        };

        Result::Ok(resp)
    }

    fn getHardwareInfo(
        &self,
    ) -> Result<
        crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo,
        Status,
    > {
        let hardware_info: keymint::KeyMintHardwareInfo =
            self.keymint.lock().unwrap().get_hardware_info().unwrap();

        let resp =
            crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo {
                securityLevel: match hardware_info.security_level {
                    kmr_wire::keymint::SecurityLevel::Software => SecurityLevel::SOFTWARE,
                    kmr_wire::keymint::SecurityLevel::TrustedEnvironment => {
                        SecurityLevel::TRUSTED_ENVIRONMENT
                    }
                    kmr_wire::keymint::SecurityLevel::Strongbox => SecurityLevel::STRONGBOX,
                    _ => {
                        return Err(Status::new_service_specific_error(
                            ErrorCode::UNKNOWN_ERROR.0,
                            None,
                        ))
                    }
                },
                versionNumber: hardware_info.version_number,
                keyMintName: hardware_info.key_mint_name,
                keyMintAuthorName: hardware_info.key_mint_author_name,
                timestampTokenRequired: hardware_info.timestamp_token_required,
            };

        Result::Ok(resp)
    }

    fn addRngEntropy(&self, data: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceAddRngEntropy(AddRngEntropyRequest {
            data: data.to_vec(),
        });

        let result = self.keymint.lock().unwrap().process_req(req);
        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn generateKey(
        &self,
        keyParams: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        attestation_key: Option<
            &crate::android::hardware::security::keymint::AttestationKey::AttestationKey,
        >,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let key_parameters: Result<Vec<KeyParam>> =
            keyParams.iter().cloned().map(|p| p.to_km()).collect();
        let key_parameters = key_parameters
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
            .map_err(map_ks_error)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters: Result<Vec<KeyParam>> = ak
                .attestKeyParams
                .iter()
                .cloned()
                .map(|p| p.to_km())
                .collect();

            let key_parameters = key_parameters
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;
            Some(AttestationKey {
                key_blob: ak.keyBlob.clone(),
                attest_key_params: key_parameters,
                issuer_subject_name: ak.issuerSubjectName.clone(),
            })
        } else {
            None
        };

        let req = PerformOpReq::DeviceGenerateKey(GenerateKeyRequest {
            key_params: key_parameters,
            attestation_key,
        });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceGenerateKey(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        let resp = key_creation_result_to_aidl(result)?;

        Result::Ok(resp)
    }

    fn importKey(
        &self,
        key_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        key_format: crate::android::hardware::security::keymint::KeyFormat::KeyFormat,
        key_data: &[u8],
        attestation_key: Option<
            &crate::android::hardware::security::keymint::AttestationKey::AttestationKey,
        >,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let key_parameters: Result<Vec<KeyParam>> =
            key_params.iter().cloned().map(|p| p.to_km()).collect();
        let key_parameters = key_parameters
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
            .map_err(map_ks_error)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters: Result<Vec<KeyParam>> = ak
                .attestKeyParams
                .iter()
                .cloned()
                .map(|p| p.to_km())
                .collect();

            let key_parameters = key_parameters
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;
            Some(AttestationKey {
                key_blob: ak.keyBlob.clone(),
                attest_key_params: key_parameters,
                issuer_subject_name: ak.issuerSubjectName.clone(),
            })
        } else {
            None
        };

        let key_format = kmr_wire::keymint::KeyFormat::try_from(key_format.0)
            .map_err(|_| Status::new_service_specific_error(ErrorCode::INVALID_ARGUMENT.0, None))?;

        let req = PerformOpReq::DeviceImportKey(ImportKeyRequest {
            key_params: key_parameters,
            key_format,
            key_data: key_data.to_vec(),
            attestation_key,
        });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceImportKey(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        let resp = key_creation_result_to_aidl(result)?;

        Result::Ok(resp)
    }

    fn importWrappedKey(
        &self,
        wrapped_key_data: &[u8],
        wrapping_key_blob: &[u8],
        masking_key: &[u8],
        unwrapping_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
        password_sid: i64,
        biometric_sid: i64,
    ) -> rsbinder::status::Result<
        crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult,
    > {
        let unwrapping_params: Result<Vec<KeyParam>> = unwrapping_params
            .iter()
            .cloned()
            .map(|p| p.to_km())
            .collect();
        let unwrapping_params = unwrapping_params
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
            .map_err(map_ks_error)?;

        let req = PerformOpReq::DeviceImportWrappedKey(ImportWrappedKeyRequest {
            wrapped_key_data: wrapped_key_data.to_vec(),
            wrapping_key_blob: wrapping_key_blob.to_vec(),
            masking_key: masking_key.to_vec(),
            unwrapping_params,
            password_sid,
            biometric_sid,
        });

        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceImportWrappedKey(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };
        let resp = key_creation_result_to_aidl(result)?;

        Result::Ok(resp)
    }

    fn upgradeKey(
        &self,
        key_blob_to_upgrade: &[u8],
        upgrade_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let upgrade_params: Result<Vec<KeyParam>> =
            upgrade_params.iter().cloned().map(|p| p.to_km()).collect();
        let upgrade_params = upgrade_params
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
            .map_err(map_ks_error)?;

        let req = PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
            key_blob_to_upgrade: key_blob_to_upgrade.to_vec(),
            upgrade_params,
        });

        let result = self.keymint.lock().unwrap().process_req(req);

        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceUpgradeKey(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        Result::Ok(result)
    }

    fn deleteKey(&self, key_blob: &[u8]) -> rsbinder::status::Result<()> {
        let key_blob = key_blob.to_vec();
        let req = PerformOpReq::DeviceDeleteKey(DeleteKeyRequest { key_blob });
        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn deleteAllKeys(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDeleteAllKeys(DeleteAllKeysRequest {});

        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn destroyAttestationIds(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDestroyAttestationIds(DestroyAttestationIdsRequest {});

        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn deviceLocked(
        &self,
        _password_only: bool,
        _timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> rsbinder::status::Result<()> {
        Result::Err(Status::from(ExceptionCode::UnsupportedOperation))
    }

    fn earlyBootEnded(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceEarlyBootEnded(EarlyBootEndedRequest {});

        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn convertStorageKeyToEphemeral(
        &self,
        storage_key_blob: &[u8],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let req =
            PerformOpReq::DeviceConvertStorageKeyToEphemeral(ConvertStorageKeyToEphemeralRequest {
                storage_key_blob: storage_key_blob.to_vec(),
            });

        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceConvertStorageKeyToEphemeral(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        Result::Ok(result)
    }

    fn getKeyCharacteristics(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        app_data: &[u8],
    ) -> rsbinder::status::Result<
        Vec<crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics>,
    > {
        let req = PerformOpReq::DeviceGetKeyCharacteristics(GetKeyCharacteristicsRequest {
            key_blob: key_blob.to_vec(),
            app_id: app_id.to_vec(),
            app_data: app_data.to_vec(),
        });

        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::DeviceGetKeyCharacteristics(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        let result: Result<Vec<crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics>, rsbinder::Status> = result.iter().map(|kc| {
            let params: Result<Vec<crate::android::hardware::security::keymint::KeyParameter::KeyParameter>, rsbinder::Status> = kc.authorizations.iter().map(|p| {
                    key_param_to_aidl(p.clone())
                        .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                        .map_err(|e| map_ks_error(e))
            }).collect();
            let params = params?;

            Result::Ok(crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics {
                authorizations: params,
                securityLevel: match kc.security_level {
                    kmr_wire::keymint::SecurityLevel::Software => SecurityLevel::SOFTWARE,
                    kmr_wire::keymint::SecurityLevel::TrustedEnvironment => {
                        SecurityLevel::TRUSTED_ENVIRONMENT
                    }
                    kmr_wire::keymint::SecurityLevel::Strongbox => SecurityLevel::STRONGBOX,
                    _ => {
                        return Err(rsbinder::Status::new_service_specific_error(
                            ErrorCode::UNKNOWN_ERROR.0,
                            None,
                        ))
                    }
                },
            })

        }).collect();
        let result = result?;

        Result::Ok(result)
    }

    fn getRootOfTrustChallenge(&self) -> rsbinder::status::Result<[u8; 16]> {
        let req = PerformOpReq::GetRootOfTrustChallenge(GetRootOfTrustChallengeRequest {});

        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::GetRootOfTrustChallenge(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        Result::Ok(result)
    }

    fn getRootOfTrust(&self, challenge: &[u8; 16]) -> rsbinder::status::Result<Vec<u8>> {
        let req = PerformOpReq::GetRootOfTrust(GetRootOfTrustRequest {
            challenge: *challenge,
        });

        let result = self.keymint.lock().unwrap().process_req(req);

        if let None = result.rsp {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }
        let result = match result.rsp.unwrap() {
            PerformOpRsp::GetRootOfTrust(rsp) => rsp.ret,
            _ => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
        };

        Result::Ok(result)
    }

    fn sendRootOfTrust(&self, root_of_trust: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::SendRootOfTrust(SendRootOfTrustRequest {
            root_of_trust: root_of_trust.to_vec(),
        });

        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }

    fn setAdditionalAttestationInfo(
        &self,
        info: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<()> {
        let additional_info: Result<Vec<KeyParam>> =
            info.iter().cloned().map(|p| p.to_km()).collect();
        let additional_info = additional_info
            .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
            .map_err(map_ks_error)?;

        let req = PerformOpReq::SetAdditionalAttestationInfo(SetAdditionalAttestationInfoRequest {
            info: additional_info,
        });

        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Status::new_service_specific_error(result.error_code, None));
        }

        Result::Ok(())
    }
}

impl KeyMintWrapper {
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        Ok(KeyMintWrapper {
            security_level: security_level.clone(),
            keymint: Mutex::new(init_keymint_ta(security_level)?),
        })
    }

    pub fn reset_keymint_ta(&self) -> Result<()> {
        let mut keymint = self.keymint.lock().unwrap();
        *keymint = init_keymint_ta(self.security_level.clone())?;
        Ok(())
    }

    pub fn get_hardware_info(&self) -> Result<keymint::KeyMintHardwareInfo, Error> {
        self.keymint
            .lock()
            .unwrap()
            .get_hardware_info()
            .map_err(|_| Error::Km(ErrorCode::UNKNOWN_ERROR))
    }

    pub fn op_update_aad(
        &self,
        op_handle: i64,
        input: &[u8],
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> Result<(), Error> {
        let hardware_auth_token = if let Some(at) = auth_token {
            Some(at.to_km()?)
        } else {
            None
        };
        let timestamp_token = if let Some(tt) = timestamp_token {
            Some(kmr_wire::secureclock::TimeStampToken {
                challenge: tt.challenge,
                timestamp: kmr_wire::secureclock::Timestamp {
                    milliseconds: tt.timestamp.milliSeconds,
                },
                mac: tt.mac.clone(),
            })
        } else {
            None
        };

        let req = PerformOpReq::OperationUpdateAad(UpdateAadRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token: timestamp_token,
        });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Error::Binder(
                ExceptionCode::ServiceSpecific,
                result.error_code,
            ));
        }
        let _result: UpdateAadResponse = match result.rsp.unwrap() {
            PerformOpRsp::OperationUpdateAad(rsp) => rsp,
            _ => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
        };

        Result::Ok(())
    }

    pub fn op_update(
        &self,
        op_handle: i64,
        input: &[u8],
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
    ) -> Result<Vec<u8>, Error> {
        let hardware_auth_token = if let Some(at) = auth_token {
            Some(at.to_km()?)
        } else {
            None
        };
        let timestamp_token = if let Some(tt) = timestamp_token {
            Some(kmr_wire::secureclock::TimeStampToken {
                challenge: tt.challenge,
                timestamp: kmr_wire::secureclock::Timestamp {
                    milliseconds: tt.timestamp.milliSeconds,
                },
                mac: tt.mac.clone(),
            })
        } else {
            None
        };

        let req = PerformOpReq::OperationUpdate(UpdateRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token: timestamp_token,
        });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Error::Binder(
                ExceptionCode::ServiceSpecific,
                result.error_code,
            ));
        }
        let result: UpdateResponse = match result.rsp.unwrap() {
            PerformOpRsp::OperationUpdate(rsp) => rsp,
            _ => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
        };

        Result::Ok(result.ret)
    }

    pub fn op_finish(
        &self,
        op_handle: i64,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        auth_token: Option<
            &crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken,
        >,
        timestamp_token: Option<
            &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
        >,
        confirmation_token: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let hardware_auth_token = if let Some(at) = auth_token {
            Some(at.to_km()?)
        } else {
            None
        };
        let timestamp_token = if let Some(tt) = timestamp_token {
            Some(kmr_wire::secureclock::TimeStampToken {
                challenge: tt.challenge,
                timestamp: kmr_wire::secureclock::Timestamp {
                    milliseconds: tt.timestamp.milliSeconds,
                },
                mac: tt.mac.clone(),
            })
        } else {
            None
        };
        let input = input.map(|i| i.to_vec());
        let signature = signature.map(|s| s.to_vec());
        let confirmation_token = confirmation_token.map(|c| c.to_vec());

        let req = PerformOpReq::OperationFinish(FinishRequest {
            op_handle,
            input: input,
            signature: signature,
            auth_token: hardware_auth_token,
            timestamp_token: timestamp_token,
            confirmation_token: confirmation_token,
        });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Error::Binder(
                ExceptionCode::ServiceSpecific,
                result.error_code,
            ));
        }
        let result: FinishResponse = match result.rsp.unwrap() {
            PerformOpRsp::OperationFinish(rsp) => rsp,
            _ => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
        };

        Result::Ok(result.ret)
    }

    pub fn op_abort(&self, op_handle: i64) -> Result<(), Error> {
        let req = PerformOpReq::OperationAbort(AbortRequest { op_handle });
        let result = self.keymint.lock().unwrap().process_req(req);
        if let None = result.rsp {
            return Err(Error::Binder(
                ExceptionCode::ServiceSpecific,
                result.error_code,
            ));
        }
        let _result: AbortResponse = match result.rsp.unwrap() {
            PerformOpRsp::OperationAbort(rsp) => rsp,
            _ => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
        };

        Result::Ok(())
    }

    #[allow(non_snake_case)]
    pub fn delete_Key(&self, key_blob: &[u8]) -> Result<(), Error> {
        let req = PerformOpReq::DeviceDeleteKey(DeleteKeyRequest {
            key_blob: key_blob.to_vec(),
        });
        let result = self.keymint.lock().unwrap().process_req(req);

        if result.error_code != 0 {
            return Err(Error::Binder(
                ExceptionCode::ServiceSpecific,
                result.error_code,
            ));
        }

        Result::Ok(())
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
    let config = CONFIG.read().unwrap();
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
            Result::Ok(v) => Some(Box::new(v)),
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

    let keys: Box<dyn kmr_ta::device::RetrieveKeyMaterial> = Box::new(soft::Keys::new(
        config.crypto.root_kek_seed.clone(),
        config.crypto.kak_seed.clone(),
    ));
    let rpc: Box<dyn kmr_ta::device::RetrieveRpcArtifacts> = Box::new(soft::RpcArtifacts::new(
        soft::Derive::default(),
        rpc_sign_algo,
    ));

    let dev = kmr_ta::device::Implementation {
        keys,
        sign_info: Some(Box::new(crate::keybox::KeyboxManager {})),
        // HAL populates attestation IDs from properties.
        attest_ids: Some(Box::new(crate::att_mgr::AttestationIdMgr {})),
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

    let mut ta = KeyMintTa::new(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev);

    let mut rng = BoringRng {};

    let mut vb_hash = vec![0u8; 32];
    rng.fill_bytes(&mut vb_hash);
    let mut vb_key = vec![0u8; 32];
    rng.fill_bytes(&mut vb_key);

    let patch_level = config.trust.security_patch.replace("-", "");
    let patch_level = patch_level.parse::<u32>().unwrap_or(20250605);
    let boot_patchlevel = patch_level;
    let os_patchlevel = patch_level / 100;

    let req = PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
        verified_boot_state: if config.trust.verified_boot_state {
            0
        } else {
            2
        },
        verified_boot_hash: config.trust.vb_hash.clone().to_vec(),
        verified_boot_key: config.trust.vb_key.clone().to_vec(),
        device_boot_locked: config.trust.device_locked,
        boot_patchlevel,
    });
    let resp = ta.process_req(req);
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set boot info"));
    }

    let req = PerformOpReq::SetHalInfo(kmr_wire::SetHalInfoRequest {
        os_version: config.trust.os_version as u32,
        os_patchlevel,
        vendor_patchlevel: os_patchlevel,
    });
    let resp = ta.process_req(req);
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set HAL info"));
    }

    let module_hash =
        crate::global::ENCODED_MODULE_INFO.get_or_try_init(|| -> Result<Vec<u8>, anyhow::Error> {
            let apex_info = crate::global::APEX_MODULE_HASH
                .as_ref()
                .map_err(|_| anyhow::anyhow!("Failed to get APEX module info."))?;

            let encoding = encode_module_info(apex_info)
                .map_err(|_| anyhow::anyhow!("Failed to encode module info."))?;

            let sha256 = BoringSha256 {};

            let hash = sha256
                .hash(&encoding)
                .map_err(|_| anyhow::anyhow!("Failed to hash module info."))?;

            Ok(hash.to_vec())
        });

    if let Result::Ok(hash) = module_hash {
        let module_hash = KeyParam::ModuleHash(hash.to_vec());
        let req = PerformOpReq::SetAdditionalAttestationInfo(
            kmr_wire::SetAdditionalAttestationInfoRequest {
                info: vec![module_hash],
            },
        );
        let resp = ta.process_req(req);
        if resp.error_code != 0 {
            return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                .context(err!("Failed to set additional attestation info"));
        }
    } else {
        warn!("Failed to get module hash: {:?}", module_hash.err());
    }

    Ok(ta)
}

pub fn get_keymint_wrapper<'a>(
    security_level: SecurityLevel,
) -> Result<std::sync::MutexGuard<'a, KeyMintWrapper>> {
    match security_level {
        SecurityLevel::STRONGBOX => {
            let wrapper = KM_WRAPPER_STRONGBOX.get_or_init(|| {
                Mutex::new(
                    KeyMintWrapper::new(security_level)
                        .expect(err!("Failed to init strongbox wrapper").as_str()),
                )
            });

            Ok(wrapper.lock().expect("Failed to lock KM_WRAPPER_STRONGBOX"))
        }
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            let wrapper = KM_WRAPPER_TEE.get_or_init(|| {
                Mutex::new(
                    KeyMintWrapper::new(security_level)
                        .expect(err!("Failed to init tee wrapper").as_str()),
                )
            });

            Ok(wrapper.lock().expect("Failed to lock KM_WRAPPER_TEE"))
        }
        SecurityLevel::SOFTWARE => Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
            .context(err!("Software KeyMint not supported")),
        _ => Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
            .context(err!("Unknown security level")),
    }
}
