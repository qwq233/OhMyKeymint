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

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::android::hardware::security::keymint::IKeyMintOperation::BnKeyMintOperation;
use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    IKeyMintOperation::IKeyMintOperation, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::config::{config, CryptoConfig};
use crate::global::DB;
use crate::keymaster::db::Uuid;
use crate::keymaster::error::{map_km_error, map_ks_error};
use crate::keymaster::utils::{
    key_characteristics_to_internal, key_creation_result_to_aidl,
    key_parameter_conversion_error_code, key_parameters_to_km, key_params_to_aidl, AppUid,
};
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
use anyhow::{Context, Result};
use kmr_common::consts::AID_KEYSTORE;
use kmr_crypto_boring::ec::BoringEc;
use kmr_crypto_boring::hmac::BoringHmac;
use kmr_crypto_boring::rng::BoringRng;
use kmr_crypto_boring::rsa::BoringRsa;
use kmr_ta::device::CsrSigningAlgorithm;
use kmr_ta::{HardwareInfo, KeyMintHalVersion, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::{AttestationKey, KeyParam};
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;
use kmr_wire::*;
use log::{error, info, warn};
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
    /// Version number of KeyMintDevice@V4
    pub const KEY_MINT_V4: i32 = 400;
    /// Version number of KeyMintDevice@V5
    pub const KEY_MINT_V5: i32 = 500;

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`]
    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let km_uuid = RwLock::new(Uuid::from(security_level));
        let wrapper: KeyMintWrapper = KeyMintWrapper::new(security_level)?;
        let version = wrapper
            .get_hardware_info()
            .context(err!("Failed to get hardware info"))?
            .version_number;
        Ok(KeyMintDevice {
            km_dev: wrapper,
            version,
            km_uuid,
            security_level,
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
        let creation_result =
            map_km_error(creator(&self.km_dev)).context(err!("creator failed"))?;
        let key_parameters = key_characteristics_to_internal(creation_result.keyCharacteristics);

        let creation_date = DateTime::now().context(err!("DateTime::now() failed"))?;

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
        let mut blob_metadata = BlobMetaData::new();
        let km_uuid = *self.km_uuid.read().unwrap();
        blob_metadata.add(BlobMetaEntry::KmUuid(km_uuid));

        db.store_new_key(
            key_desc,
            key_type,
            &key_parameters,
            &BlobInfo::new(&creation_result.keyBlob, &blob_metadata),
            &CertificateInfo::new(None, None),
            &key_metadata,
            &km_uuid,
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
        db.load_key_entry(
            key_desc,
            key_type,
            KeyEntryLoadBits::KM,
            AppUid(AID_KEYSTORE as i64),
            |_, _| Ok(()),
        )
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
                            map_km_error({
                                let _wp = wd::watch(concat!(
                                    "KeyMintDevice::lookup_or_generate_key: ",
                                    "calling IKeyMintDevice::getKeyCharacteristics."
                                ));
                                self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                            })
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
        one_step: OneStepKeyOperation<'_>,
    ) -> Result<Vec<u8>> {
        let key_blob = KeyBlob::Ref(one_step.key_blob);

        let (begin_result, _) = self
            .upgrade_keyblob_if_required_with(db, key_id_guard, key_blob, |blob| {
                let _wp =
                    wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::begin");
                let result: std::result::Result<
                    crate::android::hardware::security::keymint::BeginResult::BeginResult,
                    Status,
                > = self.km_dev.begin(
                    one_step.purpose,
                    blob,
                    one_step.parameters,
                    one_step.auth_token,
                );
                map_km_error(result)
            })
            .context(err!("Failed to begin operation."))?;
        let operation: Strong<dyn IKeyMintOperation> = begin_result
            .operation
            .ok_or_else(Error::sys)
            .context(err!("Operation missing"))?;
        let _wp = wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::finish");
        map_km_error(operation.finish(Some(one_step.input), None, None, None, None))
            .context(err!("Failed to finish operation."))
    }
}

pub struct OneStepKeyOperation<'a> {
    pub key_blob: &'a [u8],
    pub purpose: KeyPurpose,
    pub parameters: &'a [KeyParameter],
    pub auth_token: Option<&'a HardwareAuthToken>,
    pub input: &'a [u8],
}
static KM_WRAPPER_STRONGBOX: OnceLock<Arc<KeyMintWrapperInner>> = OnceLock::new();

static KM_WRAPPER_TEE: OnceLock<Arc<KeyMintWrapperInner>> = OnceLock::new();

#[derive(Clone)]
pub struct KeyMintWrapper {
    security_level: SecurityLevel,
    inner: Arc<KeyMintWrapperInner>,
}

struct KeyMintWrapperInner {
    keymint: Mutex<KeyMintTa>,
}

impl Interface for KeyMintWrapper {}

fn key_parameter_conversion_status(error: ValueNotRecognized) -> Status {
    map_ks_error(Error::Km(key_parameter_conversion_error_code(error)))
}

fn begin_key_parameters_to_km(
    params: &[KeyParameter],
    version_number: i32,
) -> std::result::Result<Vec<KeyParam>, ValueNotRecognized> {
    let mut filtered = Vec::with_capacity(params.len());
    for param in params {
        match param.r#tag {
            Tag::ASSOCIATED_DATA | Tag::CONFIRMATION_TOKEN | Tag::UNIQUE_ID => match &param.r#value
            {
                KeyParameterValue::Blob(_) => continue,
                _ => return Err(ValueNotRecognized::Blob),
            },
            Tag::MIN_SECONDS_BETWEEN_OPS => match &param.r#value {
                KeyParameterValue::Integer(_) => continue,
                _ => return Err(ValueNotRecognized::Integer),
            },
            Tag::HARDWARE_TYPE => match &param.r#value {
                KeyParameterValue::SecurityLevel(_) => continue,
                _ => return Err(ValueNotRecognized::SecurityLevel),
            },
            Tag::IDENTITY_CREDENTIAL_KEY => match &param.r#value {
                KeyParameterValue::BoolValue(true) => continue,
                _ => return Err(ValueNotRecognized::Bool),
            },
            _ => filtered.push(param.clone()),
        }
    }
    key_parameters_to_km(&filtered, version_number)
}

#[allow(non_snake_case)]
impl IKeyMintDevice for KeyMintWrapper {
    fn begin(
        &self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
    ) -> Result<crate::android::hardware::security::keymint::BeginResult::BeginResult, Status> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let km_params = begin_key_parameters_to_km(params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceBegin(BeginRequest {
            purpose: kmr_wire::keymint::KeyPurpose::try_from(purpose.0)
                .map_err(key_parameter_conversion_status)?,
            key_blob: key_blob.to_vec(),
            params: km_params.clone(),
            auth_token: auth_token.map(|at| at.to_km()).transpose().map_err(|_| {
                Status::new_service_specific_error(ErrorCode::INVALID_ARGUMENT.0, None)
            })?,
        });

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result: InternalBeginResult = match result.rsp {
            Some(PerformOpRsp::DeviceBegin(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        let operation = crate::keymaster::keymint_operation::KeyMintOperation::new(
            self.clone(),
            result.challenge,
            km_params,
            result.op_handle,
        );
        let operation = BnKeyMintOperation::new_binder(operation);

        let out_params = key_params_to_aidl(&result.params, version_number);
        let out_params = out_params.map_err(|error| {
            log::error!("failed to convert begin out params to AIDL: {error:#}");
            Status::new_service_specific_error(ErrorCode::UNKNOWN_ERROR.0, None)
        })?;

        Ok(
            crate::android::hardware::security::keymint::BeginResult::BeginResult {
                operation: Some(operation),
                challenge: result.challenge,
                params: out_params,
            },
        )
    }

    fn getHardwareInfo(
        &self,
    ) -> Result<
        crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo,
        Status,
    > {
        let hardware_info: keymint::KeyMintHardwareInfo = self
            .inner
            .keymint
            .lock()
            .unwrap()
            .get_hardware_info()
            .unwrap();

        Ok(
            crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo {
                securityLevel: SecurityLevel(hardware_info.security_level as i32),
                versionNumber: hardware_info.version_number,
                keyMintName: hardware_info.key_mint_name,
                keyMintAuthorName: hardware_info.key_mint_author_name,
                timestampTokenRequired: hardware_info.timestamp_token_required,
            },
        )
    }

    fn addRngEntropy(&self, data: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceAddRngEntropy(AddRngEntropyRequest {
            data: data.to_vec(),
        });
        self.process_status_only(req).map_err(map_ks_error)
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
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let key_parameters = key_parameters_to_km(keyParams, version_number)
            .map_err(key_parameter_conversion_status)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters = key_parameters_to_km(&ak.attestKeyParams, version_number)
                .map_err(key_parameter_conversion_status)?;
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
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceGenerateKey(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
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
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let key_parameters = key_parameters_to_km(key_params, version_number)
            .map_err(key_parameter_conversion_status)?;
        let attestation_key = if let Some(ak) = attestation_key {
            let key_parameters = key_parameters_to_km(&ak.attestKeyParams, version_number)
                .map_err(key_parameter_conversion_status)?;
            Some(AttestationKey {
                key_blob: ak.keyBlob.clone(),
                attest_key_params: key_parameters,
                issuer_subject_name: ak.issuerSubjectName.clone(),
            })
        } else {
            None
        };

        let key_format = kmr_wire::keymint::KeyFormat::try_from(key_format.0)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceImportKey(ImportKeyRequest {
            key_params: key_parameters,
            key_format,
            key_data: key_data.to_vec(),
            attestation_key,
        });
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceImportKey(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
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
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let unwrapping_params = key_parameters_to_km(unwrapping_params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceImportWrappedKey(ImportWrappedKeyRequest {
            wrapped_key_data: wrapped_key_data.to_vec(),
            wrapping_key_blob: wrapping_key_blob.to_vec(),
            masking_key: masking_key.to_vec(),
            unwrapping_params,
            password_sid,
            biometric_sid,
        });

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceImportWrappedKey(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        key_creation_result_to_aidl(result, version_number)
    }

    fn upgradeKey(
        &self,
        key_blob_to_upgrade: &[u8],
        upgrade_params: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let upgrade_params = key_parameters_to_km(upgrade_params, version_number)
            .map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::DeviceUpgradeKey(UpgradeKeyRequest {
            key_blob_to_upgrade: key_blob_to_upgrade.to_vec(),
            upgrade_params,
        });

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceUpgradeKey(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn deleteKey(&self, key_blob: &[u8]) -> rsbinder::status::Result<()> {
        self.delete_Key(key_blob).map_err(map_ks_error)
    }

    fn deleteAllKeys(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDeleteAllKeys(DeleteAllKeysRequest {});
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn destroyAttestationIds(&self) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::DeviceDestroyAttestationIds(DestroyAttestationIdsRequest {});
        self.process_status_only(req).map_err(map_ks_error)
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
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn convertStorageKeyToEphemeral(
        &self,
        storage_key_blob: &[u8],
    ) -> rsbinder::status::Result<Vec<u8>> {
        let req =
            PerformOpReq::DeviceConvertStorageKeyToEphemeral(ConvertStorageKeyToEphemeralRequest {
                storage_key_blob: storage_key_blob.to_vec(),
            });

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceConvertStorageKeyToEphemeral(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
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

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::DeviceGetKeyCharacteristics(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        let version_number = resolve_hardware_profile(self.security_level).version_number;
        result.iter().map(|kc| {
            let params = key_params_to_aidl(&kc.authorizations, version_number)
                .map_err(|_| Error::Km(ErrorCode::INVALID_ARGUMENT))
                .map_err(map_ks_error)?;

            Ok(crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics {
                authorizations: params,
                securityLevel: SecurityLevel(kc.security_level as i32),
            })
        }).collect()
    }

    fn getRootOfTrustChallenge(&self) -> rsbinder::status::Result<[u8; 16]> {
        let req = PerformOpReq::GetRootOfTrustChallenge(GetRootOfTrustChallengeRequest {});

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::GetRootOfTrustChallenge(rsp)) => rsp.ret,
            Some(_) => {
                return Err(Status::new_service_specific_error(
                    ErrorCode::UNKNOWN_ERROR.0,
                    None,
                ))
            }
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn getRootOfTrust(&self, challenge: &[u8; 16]) -> rsbinder::status::Result<Vec<u8>> {
        let req = PerformOpReq::GetRootOfTrust(GetRootOfTrustRequest {
            challenge: *challenge,
        });

        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let result = match result.rsp {
            Some(PerformOpRsp::GetRootOfTrust(rsp)) => rsp.ret,
            Some(_) => unreachable!("Unexpected response type"),
            None => return Err(Status::new_service_specific_error(result.error_code, None)),
        };

        Ok(result)
    }

    fn sendRootOfTrust(&self, root_of_trust: &[u8]) -> rsbinder::status::Result<()> {
        let req = PerformOpReq::SendRootOfTrust(SendRootOfTrustRequest {
            root_of_trust: root_of_trust.to_vec(),
        });
        self.process_status_only(req).map_err(map_ks_error)
    }

    fn setAdditionalAttestationInfo(
        &self,
        info: &[crate::android::hardware::security::keymint::KeyParameter::KeyParameter],
    ) -> rsbinder::status::Result<()> {
        let version_number = resolve_hardware_profile(self.security_level).version_number;
        let additional_info =
            key_parameters_to_km(info, version_number).map_err(key_parameter_conversion_status)?;

        let req = PerformOpReq::SetAdditionalAttestationInfo(SetAdditionalAttestationInfoRequest {
            info: additional_info,
        });
        self.process_status_only(req).map_err(map_ks_error)
    }
}

impl KeyMintWrapper {
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        if security_level == SecurityLevel::STRONGBOX
            && !crate::plat::keymint_profile::strongbox_keymint_present()
        {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("StrongBox KeyMint HAL is not present"));
        }

        Ok(KeyMintWrapper {
            security_level,
            inner: shared_keymint_wrapper_inner(security_level)?,
        })
    }

    pub fn reset_keymint_ta(&self) -> Result<()> {
        let mut keymint = self.inner.keymint.lock().unwrap();
        *keymint = init_keymint_ta(self.security_level)?;
        Ok(())
    }

    pub fn clear_attestation_cache(&self) {
        self.inner.keymint.lock().unwrap().clear_attestation_cache();
    }

    pub fn localize_auth_token(&self, auth_token: &HardwareAuthToken) -> Result<HardwareAuthToken> {
        let km_token = auth_token
            .to_km()
            .context(err!("invalid auth token fields"))?;
        let mac_input = kmr_ta::hardware_auth_token_mac_input(&km_token)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("failed to build auth token MAC input"))?;
        let hmac_key = self
            .inner
            .keymint
            .lock()
            .unwrap()
            .get_hmac_key()
            .ok_or(Error::Km(ErrorCode::HARDWARE_NOT_YET_AVAILABLE))
            .context(err!("auth-token HMAC key is not initialized"))?;
        let mac = kmr_common::crypto::hmac_sha256(&BoringHmac, &hmac_key.0, &mac_input)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("failed to localize auth token MAC"))?;

        let mut localized = auth_token.clone();
        localized.mac = mac;
        Ok(localized)
    }

    pub fn get_hardware_info(&self) -> Result<keymint::KeyMintHardwareInfo, Error> {
        self.inner
            .keymint
            .lock()
            .unwrap()
            .get_hardware_info()
            .map_err(|_| Error::Km(ErrorCode::UNKNOWN_ERROR))
    }

    fn process_status_only(&self, req: PerformOpReq) -> Result<(), Error> {
        let error_code = self
            .inner
            .keymint
            .lock()
            .unwrap()
            .process_req(req)
            .error_code;
        match error_code {
            0 => Ok(()),
            _ => Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        }
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
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);

        let req = PerformOpReq::OperationUpdateAad(UpdateAadRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token,
        });
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let error_code = result.error_code;
        let _result: UpdateAadResponse = match result.rsp {
            Some(PerformOpRsp::OperationUpdateAad(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(())
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
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);

        let req = PerformOpReq::OperationUpdate(UpdateRequest {
            op_handle,
            input: input.to_vec(),
            auth_token: hardware_auth_token,
            timestamp_token,
        });
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let error_code = result.error_code;
        let result: UpdateResponse = match result.rsp {
            Some(PerformOpRsp::OperationUpdate(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(result.ret)
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
        let hardware_auth_token = auth_token.map(|at| at.to_km()).transpose()?;
        let timestamp_token = timestamp_token.map(timestamp_token_to_wire);
        let input = input.map(|i| i.to_vec());
        let signature = signature.map(|s| s.to_vec());
        let confirmation_token = confirmation_token.map(|c| c.to_vec());

        let req = PerformOpReq::OperationFinish(FinishRequest {
            op_handle,
            input,
            signature,
            auth_token: hardware_auth_token,
            timestamp_token,
            confirmation_token,
        });
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let error_code = result.error_code;
        let result: FinishResponse = match result.rsp {
            Some(PerformOpRsp::OperationFinish(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(result.ret)
    }

    pub fn op_abort(&self, op_handle: i64) -> Result<(), Error> {
        let req = PerformOpReq::OperationAbort(AbortRequest { op_handle });
        let result = self.inner.keymint.lock().unwrap().process_req(req);
        let error_code = result.error_code;
        let _result: AbortResponse = match result.rsp {
            Some(PerformOpRsp::OperationAbort(rsp)) => rsp,
            Some(_) => return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)),
            None => return Err(Error::Binder(ExceptionCode::ServiceSpecific, error_code)),
        };

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn delete_Key(&self, key_blob: &[u8]) -> Result<(), Error> {
        self.process_status_only(PerformOpReq::DeviceDeleteKey(DeleteKeyRequest {
            key_blob: key_blob.to_vec(),
        }))
    }
}

fn timestamp_token_to_wire(
    token: &crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken,
) -> kmr_wire::secureclock::TimeStampToken {
    kmr_wire::secureclock::TimeStampToken {
        challenge: token.challenge,
        timestamp: kmr_wire::secureclock::Timestamp {
            milliseconds: token.timestamp.milliSeconds,
        },
        mac: token.mac.clone(),
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

#[derive(Clone, Copy)]
struct ResolvedHardwareProfile {
    version_number: i32,
    impl_name: &'static str,
    author_name: &'static str,
    unique_id: &'static str,
}

fn resolve_hardware_profile(security_level: SecurityLevel) -> ResolvedHardwareProfile {
    static TEE_PROFILE: OnceLock<ResolvedHardwareProfile> = OnceLock::new();
    static STRONGBOX_PROFILE: OnceLock<ResolvedHardwareProfile> = OnceLock::new();
    let build = || {
        let profile = crate::plat::keymint_profile::resolve_hardware_profile(security_level);
        ResolvedHardwareProfile {
            version_number: profile.version_number,
            impl_name: Box::leak(profile.impl_name.into_boxed_str()),
            author_name: Box::leak(profile.author_name.into_boxed_str()),
            unique_id: Box::leak(profile.unique_id.into_boxed_str()),
        }
    };

    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => *TEE_PROFILE.get_or_init(build),
        SecurityLevel::STRONGBOX => *STRONGBOX_PROFILE.get_or_init(build),
        _ => build(),
    }
}

fn bootstrap_auth_token_hmac(ta: &mut KeyMintTa, crypto: &CryptoConfig) -> Result<()> {
    if let Some(key) = crypto.auth_token_hmac_key {
        ta.set_device_hmac_key(&key)
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .context(err!("Failed to configure auth-token HMAC key"))?;
        info!("initialized auth-token HMAC key from configured key material");
        return Ok(());
    }

    let params = kmr_wire::sharedsecret::SharedSecretParameters {
        seed: crypto.shared_secret_seed.to_vec(),
        nonce: crypto.shared_secret_nonce.to_vec(),
    };

    ta.set_shared_secret_params(params.clone())
        .map_err(|error| anyhow::anyhow!("{error:?}"))
        .context(err!("Failed to configure shared secret parameters"))?;

    let req = PerformOpReq::SharedSecretComputeSharedSecret(ComputeSharedSecretRequest {
        params: vec![params],
    });
    let resp = ta.process_req(req);
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
            .context(err!("Failed to bootstrap auth-token HMAC key"));
    }
    match resp.rsp {
        Some(PerformOpRsp::SharedSecretComputeSharedSecret(rsp)) if rsp.ret.len() == 32 => {
            info!("initialized auth-token HMAC key from configured shared-secret parameters");
            Ok(())
        }
        _ => Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
            .context(err!("Unexpected shared-secret bootstrap response")),
    }
}

fn init_keymint_ta(security_level: SecurityLevel) -> Result<KeyMintTa> {
    let config = config().read().unwrap();
    let security_level = get_keymint_security_level(security_level)?;
    let profile = resolve_hardware_profile(get_keymaster_security_level(security_level)?);

    let hw_info = HardwareInfo {
        version_number: profile.version_number,
        security_level,
        impl_name: profile.impl_name,
        author_name: profile.author_name,
        unique_id: profile.unique_id,
    };

    let rpc_info_v3 = RpcInfoV3 {
        author_name: profile.author_name,
        unique_id: profile.unique_id,
        fused: false,
        supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    let mut rng = BoringRng;

    let sdd_mgr: Option<Box<dyn kmr_common::keyblob::SecureDeletionSecretManager>> =
        match sdd::HostSddManager::new(&mut rng) {
            Result::Ok(v) => Some(Box::new(v)),
            Err(e) => {
                error!("failed to initialize secure deletion data manager: {:?}", e);
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
        mldsa: Box::new(kmr_crypto_boring::mldsa::BoringMlDsa),
    };

    let keys: Box<dyn kmr_ta::device::RetrieveKeyMaterial> = Box::new(soft::Keys::new(
        config.crypto.root_kek_seed,
        config.crypto.kak_seed,
    ));
    let rpc: Box<dyn kmr_ta::device::RetrieveRpcArtifacts> = Box::new(soft::RpcArtifacts::new(
        soft::Derive::default(),
        CsrSigningAlgorithm::EdDSA,
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

    let allowed_aidl_versions = match profile.version_number {
        100 => vec![KeyMintHalVersion::V1],
        200 => vec![KeyMintHalVersion::V2],
        300 => vec![KeyMintHalVersion::V3],
        400 => vec![KeyMintHalVersion::V4],
        500 => vec![KeyMintHalVersion::V5],
        _ => Vec::new(),
    };

    let mut ta = KeyMintTa::new_allowing_versions(
        hw_info,
        RpcInfo::V3(rpc_info_v3),
        imp,
        dev,
        allowed_aidl_versions,
    );
    bootstrap_auth_token_hmac(&mut ta, &config.crypto)?;

    let patch_level = config
        .trust
        .security_patch
        .replace('-', "")
        .parse::<u32>()
        .unwrap_or(20250605);
    let boot_patchlevel = patch_level;
    let os_patchlevel = patch_level / 100;

    let resp = ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
        verified_boot_state: if config.trust.verified_boot_state {
            0
        } else {
            2
        },
        verified_boot_hash: config.trust.vb_hash.clone().to_vec(),
        verified_boot_key: config.trust.vb_key.clone().to_vec(),
        device_boot_locked: config.trust.device_locked,
        boot_patchlevel,
    }));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set boot info"));
    }

    let resp = ta.process_req(PerformOpReq::SetHalInfo(kmr_wire::SetHalInfoRequest {
        os_version: config.trust.os_version as u32,
        os_patchlevel,
        vendor_patchlevel: boot_patchlevel,
    }));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set HAL info"));
    }

    let resp = ta.process_req(PerformOpReq::SetHalVersion(
        kmr_wire::SetHalVersionRequest {
            aidl_version: profile.version_number as u32,
        },
    ));
    if resp.error_code != 0 {
        return Err(Error::Km(ErrorCode::UNKNOWN_ERROR)).context(err!("Failed to set HAL version"));
    }

    if profile.version_number >= KeyMintDevice::KEY_MINT_V4 {
        if let Some(bundle) = crate::global::module_info_bundle() {
            let resp = ta.process_req(PerformOpReq::SetAdditionalAttestationInfo(
                kmr_wire::SetAdditionalAttestationInfoRequest {
                    info: vec![KeyParam::ModuleHash(bundle.sha256.clone())],
                },
            ));
            if resp.error_code != 0 {
                return Err(Error::Km(ErrorCode::UNKNOWN_ERROR))
                    .context(err!("Failed to set additional attestation info"));
            }
        } else {
            warn!("moduleHash attestation bootstrap skipped because APEX module info bundle is unavailable");
        }
    } else {
        info!(
            "Skipping moduleHash attestation bootstrap for KeyMint version {}",
            profile.version_number
        );
    }

    Ok(ta)
}

pub fn get_keymint_wrapper(security_level: SecurityLevel) -> Result<KeyMintWrapper> {
    KeyMintWrapper::new(security_level)
}

pub fn localize_auth_token_for_omk(auth_token: &HardwareAuthToken) -> Result<HardwareAuthToken> {
    get_keymint_wrapper(SecurityLevel::TRUSTED_ENVIRONMENT)?.localize_auth_token(auth_token)
}

pub fn reset_initialized_keymint_wrappers() -> Result<()> {
    if let Some(wrapper) = KM_WRAPPER_TEE.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            inner: wrapper.clone(),
        };
        keymint
            .reset_keymint_ta()
            .context(err!("Failed to reset TEE keymint wrapper"))?;
    }

    if let Some(wrapper) = KM_WRAPPER_STRONGBOX.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::STRONGBOX,
            inner: wrapper.clone(),
        };
        if let Err(error) = keymint.reset_keymint_ta() {
            log::warn!("failed to reset optional StrongBox keymint wrapper: {error:#}");
        }
    }

    Ok(())
}

pub fn clear_initialized_attestation_caches() {
    if let Some(wrapper) = KM_WRAPPER_TEE.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::TRUSTED_ENVIRONMENT,
            inner: wrapper.clone(),
        };
        keymint.clear_attestation_cache();
    }

    if let Some(wrapper) = KM_WRAPPER_STRONGBOX.get() {
        let keymint = KeyMintWrapper {
            security_level: SecurityLevel::STRONGBOX,
            inner: wrapper.clone(),
        };
        keymint.clear_attestation_cache();
    }
}

fn shared_keymint_wrapper_inner(security_level: SecurityLevel) -> Result<Arc<KeyMintWrapperInner>> {
    let wrapper = match security_level {
        SecurityLevel::STRONGBOX => &KM_WRAPPER_STRONGBOX,
        SecurityLevel::TRUSTED_ENVIRONMENT => &KM_WRAPPER_TEE,
        SecurityLevel::SOFTWARE => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("Software KeyMint not supported"))
        }
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("Unknown security level"))
        }
    };
    wrapper
        .get_or_try_init(|| {
            Ok(Arc::new(KeyMintWrapperInner {
                keymint: Mutex::new(init_keymint_ta(security_level)?),
            }))
        })
        .map(Arc::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(tag: Tag, value: KeyParameterValue) -> KeyParameter {
        KeyParameter { tag, value }
    }

    #[test]
    fn begin_conversion_skips_plain_accepted_metadata_tags() {
        let params = vec![
            param(
                Tag::PURPOSE,
                KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
            ),
            param(Tag::ASSOCIATED_DATA, KeyParameterValue::Blob(vec![1])),
            param(Tag::CONFIRMATION_TOKEN, KeyParameterValue::Blob(vec![2])),
            param(Tag::MIN_SECONDS_BETWEEN_OPS, KeyParameterValue::Integer(30)),
            param(
                Tag::HARDWARE_TYPE,
                KeyParameterValue::SecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT),
            ),
            param(Tag::UNIQUE_ID, KeyParameterValue::Blob(vec![3])),
            param(
                Tag::IDENTITY_CREDENTIAL_KEY,
                KeyParameterValue::BoolValue(true),
            ),
        ];

        assert_eq!(
            begin_key_parameters_to_km(&params, KeyMintDevice::KEY_MINT_V5).unwrap(),
            vec![KeyParam::Purpose(kmr_wire::keymint::KeyPurpose::Sign)]
        );
    }

    #[test]
    fn begin_conversion_keeps_malformed_begin_params_rejected() {
        assert!(matches!(
            begin_key_parameters_to_km(
                &[param(Tag::USER_AUTH_TYPE, KeyParameterValue::Integer(2))],
                KeyMintDevice::KEY_MINT_V5
            ),
            Err(ValueNotRecognized::HardwareAuthenticatorType)
        ));
        assert!(matches!(
            begin_key_parameters_to_km(
                &[param(
                    Tag::IDENTITY_CREDENTIAL_KEY,
                    KeyParameterValue::BoolValue(false),
                )],
                KeyMintDevice::KEY_MINT_V5
            ),
            Err(ValueNotRecognized::Bool)
        ));
    }

    fn test_crypto() -> kmr_common::crypto::Implementation {
        kmr_common::crypto::Implementation {
            rng: Box::new(BoringRng),
            clock: Some(Box::new(clock::StdClock)),
            compare: Box::new(kmr_crypto_boring::eq::BoringEq),
            aes: Box::new(kmr_crypto_boring::aes::BoringAes),
            des: Box::new(kmr_crypto_boring::des::BoringDes),
            hmac: Box::new(BoringHmac),
            rsa: Box::new(BoringRsa::default()),
            ec: Box::new(BoringEc::default()),
            ckdf: Box::new(kmr_crypto_boring::aes_cmac::BoringAesCmac),
            hkdf: Box::new(BoringHmac),
            sha256: Box::new(kmr_crypto_boring::sha256::BoringSha256),
            mldsa: Box::new(kmr_crypto_boring::mldsa::BoringMlDsa),
        }
    }

    fn test_ta() -> KeyMintTa {
        let hw_info = HardwareInfo {
            version_number: KeyMintDevice::KEY_MINT_V5,
            security_level: kmr_wire::keymint::SecurityLevel::TrustedEnvironment,
            impl_name: "test",
            author_name: "test",
            unique_id: "test",
        };
        let rpc_info = RpcInfoV3 {
            author_name: "test",
            unique_id: "test",
            fused: false,
            supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
        };
        let dev = kmr_ta::device::Implementation {
            keys: Box::new(soft::Keys::new([0; 32], [1; 32])),
            sign_info: None,
            attest_ids: None,
            sdd_mgr: None,
            bootloader: Box::new(kmr_ta::device::BootloaderDone),
            sk_wrapper: None,
            tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
            legacy_key: None,
            rpc: Box::new(kmr_ta::device::NoOpRetrieveRpcArtifacts),
        };

        KeyMintTa::new_allowing_versions(
            hw_info,
            RpcInfo::V3(rpc_info),
            test_crypto(),
            dev,
            vec![KeyMintHalVersion::V5],
        )
    }

    fn set_boot_info(ta: &mut KeyMintTa) -> i32 {
        ta.process_req(PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
            verified_boot_state: 0,
            verified_boot_hash: vec![0; 32],
            verified_boot_key: vec![0; 32],
            device_boot_locked: true,
            boot_patchlevel: 20250605,
        }))
        .error_code
    }

    #[test]
    fn keymint_ta_early_boot_ended_rejects_late_boot_info() {
        let mut ta = test_ta();
        assert_eq!(set_boot_info(&mut ta), 0);

        let resp = ta.process_req(PerformOpReq::DeviceEarlyBootEnded(EarlyBootEndedRequest {}));
        assert_eq!(resp.error_code, 0);

        assert_eq!(set_boot_info(&mut ta), ErrorCode::EARLY_BOOT_ENDED.0);
    }
}
