// Copyright 2020, The Android Open Source Project
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

//! This crate implements the IKeystoreSecurityLevel interface.

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, AttestationKey::AttestationKey,
    HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
    KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat,
    KeyMintHardwareInfo::KeyMintHardwareInfo, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::security::metrics::OperationType::OperationType;
use crate::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, CreateOperationResponse::CreateOperationResponse,
    Domain::Domain, EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
    IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::BnKeystoreSecurityLevel,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata, KeyParameters::KeyParameters, ResponseCode::ResponseCode,
};
use crate::err as ks_err;
use crate::global::{DB, ENFORCEMENTS, SUPER_KEY};
use crate::keymaster::attestation_key_utils::{get_attest_key_info, AttestationKeyInfo};
use crate::keymaster::audit_log::{
    log_key_deleted, log_key_generated, log_key_imported, log_key_integrity_violation,
};
use crate::keymaster::db::{
    BlobInfo, BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry, KeyEntryLoadBits,
    KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType, SubComponentType, Uuid,
};
use crate::keymaster::error::{self, into_logged_binder, map_km_error, Error, ErrorCode};
use crate::keymaster::id_rotation::IdRotationState;
use crate::keymaster::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::keymaster::key_parameter::{KeyParameter as KsKeyParam, KmKeyParameter};
use crate::keymaster::keymint_device::{get_keymint_wrapper, KeyMintWrapper};
use crate::keymaster::metrics_store::{
    log_key_creation_event_stats, log_operation_latency, parse_key_parameters,
};
use crate::keymaster::operation::{KeystoreOperation, LoggingInfo, OperationDb};
use crate::keymaster::permission::{
    check_device_attestation_permissions, check_key_permission,
    check_unique_id_attestation_permissions, require_forwarded_context, KeyPerm,
};
use crate::keymaster::security_level_manager;
use crate::keymaster::super_key::{KeyBlob, SuperKeyManager};
use crate::keymaster::utils::{
    app_info_for_uid, count_key_entries, is_device_id_attestation_tag, is_imei_attestation_tag,
    key_characteristics_to_internal, key_parameters_to_authorizations, log_security_safe_params,
    upgrade_keyblob_if_required_with, AndroidUserId, AppUid, Challenge, UNDEFINED_NOT_AFTER,
};
use crate::plat::utils as plat_utils;
use crate::top::qwq2333::ohmykeymint::{
    CallerInfo::CallerInfo,
    IOhMySecurityLevel::{BnOhMySecurityLevel, IOhMySecurityLevel},
};
use crate::watchdog as wd;
use anyhow::{Context, Result};
use log::error;
use std::convert::TryInto;
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;

use rsbinder as binder;
use rsbinder::thread_state::CallingContext;
use rsbinder::{Status, Strong};

/// The fallback limit on the number of keys per app.  All apps must stay within this limit.
const DEFAULT_PER_UID_KEY_LIMIT: i32 = 200_000;

/// The limit on the number of keys per app for apps with a target SDK level of 37+.
const API_37_PER_UID_KEY_LIMIT: i32 = 50_000;

/// Implementation of the IKeystoreSecurityLevel Interface.
pub struct KeystoreSecurityLevel {
    security_level: SecurityLevel,
    keymint: KeyMintWrapper,
    hw_info: KeyMintHardwareInfo,
    operation_db: OperationDb,
    id_rotation_state: IdRotationState,
}

struct AospSecurityLevelWrapper {
    inner: Arc<KeystoreSecurityLevel>,
}

struct OmkSecurityLevelWrapper {
    inner: Arc<KeystoreSecurityLevel>,
}

impl Deref for AospSecurityLevelWrapper {
    type Target = KeystoreSecurityLevel;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Deref for OmkSecurityLevelWrapper {
    type Target = KeystoreSecurityLevel;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Blob of 32 zeroes used as empty masking key.
static ZERO_BLOB_32: &[u8] = &[0; 32];

impl KeystoreSecurityLevel {
    fn new(security_level: SecurityLevel, id_rotation_state: IdRotationState) -> Result<Self> {
        let dev =
            get_keymint_wrapper(security_level).context(ks_err!("KeystoreSecurityLevel::new."))?;
        let hw_info = map_km_error(dev.getHardwareInfo())
            .context(ks_err!("KeystoreSecurityLevel::new: getHardwareInfo."))?;
        Ok(Self {
            security_level,
            keymint: dev,
            hw_info,
            operation_db: OperationDb::new(),
            id_rotation_state,
        })
    }

    pub fn new_binders(
        security_level: SecurityLevel,
        id_rotation_state: IdRotationState,
    ) -> Result<(
        Strong<dyn IKeystoreSecurityLevel>,
        Strong<dyn IOhMySecurityLevel>,
    )> {
        let inner = Arc::new(Self::new(security_level, id_rotation_state)?);
        let aosp = BnKeystoreSecurityLevel::new_binder_with_features(
            AospSecurityLevelWrapper {
                inner: inner.clone(),
            },
            crate::consts::sid_features(),
        );
        let omk = BnOhMySecurityLevel::new_binder_with_features(
            OmkSecurityLevelWrapper { inner },
            crate::consts::sid_features(),
        );
        Ok((aosp, omk))
    }

    /// Creates a new security level instance wrapped in a
    /// BnKeystoreSecurityLevel proxy object. It also enables
    /// `BinderFeatures::set_requesting_sid` on the new interface, because
    /// we need it for checking keystore permissions.
    pub fn new_native_binder(
        security_level: SecurityLevel,
        id_rotation_state: IdRotationState,
    ) -> Result<(Strong<dyn IKeystoreSecurityLevel>, Uuid)> {
        let km_uuid = Uuid::from(security_level);
        let (result, _) = Self::new_binders(security_level, id_rotation_state)
            .context(ks_err!("KeystoreSecurityLevel::new_native_binder."))?;
        Ok((result, km_uuid))
    }

    fn watch_millis(&self, id: &'static str, millis: u64) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, millis, sec_level)
    }

    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
    }

    fn store_new_key(
        &self,
        key: KeyDescriptor,
        creation_result: KeyCreationResult,
        user: AndroidUserId,
        flags: Option<i32>,
    ) -> Result<KeyMetadata> {
        let KeyCreationResult {
            keyBlob: key_blob,
            keyCharacteristics: key_characteristics,
            certificateChain: mut certificate_chain,
        } = creation_result;

        // Unify the possible contents of the certificate chain.  The first entry in the `Vec` is
        // always the leaf certificate (if present), but the rest of the chain may be present as
        // either:
        //  - `certificate_chain[1..n]`: each entry holds a single certificate, as returned by
        //    KeyMint, or
        //  - `certificate_chain[1]`: a single `Certificate` that actually (and confusingly) holds
        //    the DER-encoded certs of the chain concatenated together.
        let mut cert_info: CertificateInfo = CertificateInfo::new(
            // Leaf is always a single cert in the first entry, if present.
            match certificate_chain.len() {
                0 => None,
                _ => Some(certificate_chain.remove(0).encodedCertificate),
            },
            // Remainder may be either `[1..n]` individual certs, or just `[1]` holding a
            // concatenated chain. Convert the former to the latter.
            match certificate_chain.len() {
                0 => None,
                _ => Some(
                    certificate_chain
                        .iter()
                        .flat_map(|c| c.encodedCertificate.iter())
                        .copied()
                        .collect(),
                ),
            },
        );

        let mut key_parameters = key_characteristics_to_internal(key_characteristics);

        key_parameters.push(KsKeyParam::new(
            KsKeyParamValue::UserID(user.0),
            SecurityLevel::SOFTWARE,
        ));

        let creation_date = DateTime::now().context(ks_err!("Trying to make creation time."))?;

        let key = match key.domain {
            Domain::BLOB => KeyDescriptor {
                domain: Domain::BLOB,
                blob: Some(key_blob.to_vec()),
                ..Default::default()
            },
            _ => DB
                .with::<_, Result<KeyDescriptor>>(|db| {
                    let mut db = db.borrow_mut();

                    let (key_blob, mut blob_metadata) = SUPER_KEY
                        .read()
                        .unwrap()
                        .handle_super_encryption_on_key_init(
                            &mut db,
                            &(key.domain),
                            &key_parameters,
                            flags,
                            user,
                            &key_blob,
                        )
                        .context(ks_err!("Failed to handle super encryption."))?;

                    let km_uuid = Uuid::from(self.security_level);
                    let mut key_metadata = KeyMetaData::new();
                    key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
                    blob_metadata.add(BlobMetaEntry::KmUuid(km_uuid));

                    let key_id = db
                        .store_new_key(
                            &key,
                            KeyType::Client,
                            &key_parameters,
                            &BlobInfo::new(&key_blob, &blob_metadata),
                            &cert_info,
                            &key_metadata,
                            &km_uuid,
                        )
                        .context(ks_err!())?;
                    Ok(KeyDescriptor {
                        domain: Domain::KEY_ID,
                        nspace: key_id.id(),
                        ..Default::default()
                    })
                })
                .context(ks_err!())?,
        };

        Ok(KeyMetadata {
            key,
            keySecurityLevel: self.security_level,
            certificate: cert_info.take_cert(),
            certificateChain: cert_info.take_cert_chain(),
            authorizations: key_parameters_to_authorizations(key_parameters),
            modificationTimeMs: creation_date.to_millis_epoch(),
        })
    }

    fn create_operation(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse> {
        let caller_uid = caller_uid(ctx);
        // We use `scoping_blob` to extend the life cycle of the blob loaded from the database,
        // so that we can use it by reference like the blob provided by the key descriptor.
        // Otherwise, we would have to clone the blob from the key descriptor.
        let scoping_blob: Vec<u8>;
        let mut is_attested = false;
        let (km_blob, key_properties, key_id_guard, blob_metadata) = match key.domain {
            Domain::BLOB => {
                check_key_permission(KeyPerm::Use, key, None, ctx)
                    .context(ks_err!("checking use permission for Domain::BLOB."))?;
                if forced {
                    check_key_permission(KeyPerm::ReqForcedOp, key, None, ctx)
                        .context(ks_err!("checking forced permission for Domain::BLOB."))?;
                }
                (
                    match &key.blob {
                        Some(blob) => blob,
                        None => {
                            return Err(Error::sys()).context(ks_err!(
                                "Key blob must be specified when \
                                using Domain::BLOB."
                            ));
                        }
                    },
                    None,
                    None,
                    BlobMetaData::new(),
                )
            }
            _ => {
                let (key_id_guard, mut key_entry) = DB
                    .with::<_, Result<(KeyIdGuard, KeyEntry)>>(|db| {
                        db.borrow_mut().load_key_entry(
                            key,
                            KeyType::Client,
                            KeyEntryLoadBits::BOTH,
                            caller_uid,
                            |k, av| {
                                check_key_permission(KeyPerm::Use, k, av.as_ref(), ctx)?;
                                if forced {
                                    check_key_permission(
                                        KeyPerm::ReqForcedOp,
                                        k,
                                        av.as_ref(),
                                        ctx,
                                    )?;
                                }
                                Ok(())
                            },
                        )
                    })
                    .context(ks_err!("Failed to load key blob."))?;

                is_attested = key_entry.is_attested();

                let (blob, blob_metadata) = key_entry
                    .take_key_blob_info()
                    .ok_or_else(Error::sys)
                    .context(ks_err!(
                    "Successfully loaded key entry, \
                        but KM blob was missing."
                ))?;
                scoping_blob = blob;

                (
                    &scoping_blob,
                    Some((key_id_guard.id(), key_entry.into_key_parameters())),
                    Some(key_id_guard),
                    blob_metadata,
                )
            }
        };

        let purpose = operation_parameters
            .iter()
            .find(|p| p.tag == Tag::PURPOSE)
            .map_or(
                Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(ks_err!("No operation purpose specified.")),
                |kp| match kp.value {
                    KeyParameterValue::KeyPurpose(p) => Ok(p),
                    _ => Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                        .context(ks_err!("Malformed KeyParameter.")),
                },
            )?;

        // Remove Tag::PURPOSE from the operation_parameters, since some keymaster devices return
        // an error on begin() if Tag::PURPOSE is in the operation_parameters.
        let op_params: Vec<KeyParameter> = operation_parameters
            .iter()
            .filter(|p| p.tag != Tag::PURPOSE)
            .cloned()
            .collect();
        let operation_parameters = op_params.as_slice();

        let (immediate_hat, mut auth_info) = ENFORCEMENTS
            .authorize_create(
                purpose,
                key_properties.as_ref(),
                operation_parameters.as_ref(),
                self.hw_info.timestampTokenRequired,
            )
            .context(ks_err!())?;

        let km_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&blob_metadata, km_blob)
            .context(ks_err!("Failed to handle super encryption."))?;

        let (begin_result, upgraded_blob) = self
            .upgrade_keyblob_if_required_with(
                key_id_guard,
                &km_blob,
                blob_metadata.km_uuid().copied(),
                operation_parameters,
                |blob| loop {
                    match map_km_error({
                        let _wp = self.watch(
                            "KeystoreSecurityLevel::create_operation: calling IKeyMintDevice::begin",
                        );
                        self.keymint.begin(
                            purpose,
                            blob,
                            operation_parameters,
                            immediate_hat.as_ref(),
                        )
                    }) {
                        Err(Error::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                            self.operation_db.prune(caller_uid, forced)?;
                            continue;
                        }
                        v @ Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)) => {
                            if let Some((key_id, _)) = key_properties {
                                if let Ok(Some(key)) =
                                    DB.with(|db| db.borrow_mut().load_key_descriptor(key_id))
                                {
                                    log_key_integrity_violation(&key);
                                } else {
                                    error!("Failed to load key descriptor for audit log");
                                }
                            }
                            return v;
                        }
                        v => return v,
                    }
                },
            )
            .context(ks_err!("Failed to begin operation."))?;

        let operation_challenge =
            auth_info.finalize_create_authorization(Challenge(begin_result.challenge));

        let op_params: Vec<KeyParameter> = operation_parameters.to_vec();

        let (algorithm, _, _) = if let Some((_, ref props)) = key_properties {
            let km_props: Vec<KmKeyParameter> = props
                .iter()
                .map(|kp| kp.clone().into_key_parameter())
                .collect();
            parse_key_parameters(&km_props)
        } else {
            parse_key_parameters(operation_parameters)
        };

        let operation = match begin_result.operation {
            Some(km_op) => self.operation_db.create_operation(
                km_op,
                caller_uid,
                auth_info,
                forced,
                LoggingInfo::new(
                    self.security_level,
                    purpose,
                    algorithm,
                    op_params,
                    upgraded_blob.is_some(),
                    is_attested,
                ),
            ),
            None => {
                return Err(Error::sys()).context(ks_err!(
                    "Begin operation returned successfully, \
                    but did not return a valid operation."
                ));
            }
        };

        let op_binder: binder::Strong<dyn IKeystoreOperation> =
            KeystoreOperation::new_native_binder(operation)
                .as_binder()
                .into_interface()
                .context(ks_err!("Failed to create IKeystoreOperation."))?;

        Ok(CreateOperationResponse {
            iOperation: Some(op_binder),
            operationChallenge: operation_challenge,
            parameters: match begin_result.params.len() {
                0 => None,
                _ => Some(KeyParameters {
                    keyParameter: begin_result.params,
                }),
            },
            // An upgraded blob should only be returned if the caller has permission
            // to use Domain::BLOB keys. If we got to this point, we already checked
            // that the caller had that permission.
            upgradedBlob: if key.domain == Domain::BLOB {
                upgraded_blob
            } else {
                None
            },
        })
    }

    fn add_required_parameters(
        &self,
        ctx: Option<&CallerInfo>,
        uid: AppUid,
        params: &[KeyParameter],
        key: &KeyDescriptor,
    ) -> Result<Vec<KeyParameter>> {
        let mut result = params.to_vec();

        // Prevent callers from specifying the CREATION_DATETIME tag.
        if params.iter().any(|kp| kp.tag == Tag::CREATION_DATETIME) {
            return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(ks_err!(
                "KeystoreSecurityLevel::add_required_parameters: \
                Specifying Tag::CREATION_DATETIME is not allowed."
            ));
        }

        // Use this variable to refer to notion of "now". This eliminates discrepancies from
        // quering the clock multiple times.
        let creation_datetime = SystemTime::now();

        // Add CREATION_DATETIME only if the backend version Keymint V1 (100) or newer.
        if self.hw_info.versionNumber >= 100 {
            result.push(KeyParameter {
                tag: Tag::CREATION_DATETIME,
                value: KeyParameterValue::DateTime(
                    creation_datetime
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .context(ks_err!(
                            "KeystoreSecurityLevel::add_required_parameters: \
                                Failed to get epoch time."
                        ))?
                        .as_millis()
                        .try_into()
                        .context(ks_err!(
                            "KeystoreSecurityLevel::add_required_parameters: \
                                Failed to convert epoch time."
                        ))?,
                ),
            });
        }

        // If there is an attestation challenge we need to get an application id.
        if params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE) {
            let _wp =
                self.watch(" KeystoreSecurityLevel::add_required_parameters: calling get_aaid");
            let aaid = plat_utils::get_aaid(uid.0 as u32)
                .context(ks_err!("Attestation ID retrieval error."))?;
            result.push(KeyParameter {
                tag: Tag::ATTESTATION_APPLICATION_ID,
                value: KeyParameterValue::Blob(aaid),
            });
        }

        if params.iter().any(|kp| kp.tag == Tag::INCLUDE_UNIQUE_ID) {
            if check_key_permission(KeyPerm::GenUniqueId, key, None, ctx).is_err()
                && check_unique_id_attestation_permissions(ctx).is_err()
            {
                return Err(Error::perm()).context(ks_err!(
                    "Caller does not have the permission to generate a unique ID"
                ));
            }
            if self
                .id_rotation_state
                .had_factory_reset_since_id_rotation(&creation_datetime)
                .context(ks_err!(
                    "Call to had_factory_reset_since_id_rotation failed."
                ))?
            {
                result.push(KeyParameter {
                    tag: Tag::RESET_SINCE_ID_ROTATION,
                    value: KeyParameterValue::BoolValue(true),
                })
            }
        }

        // If the caller requests any device identifier attestation tag, check that they hold the
        // correct Android permission.
        if params.iter().any(|kp| is_device_id_attestation_tag(kp.tag)) {
            check_device_attestation_permissions(ctx).context(ks_err!(
                "Caller does not have the permission to attest device identifiers."
            ))?;
        }

        // If we are generating/importing an asymmetric key, we need to make sure
        // that NOT_BEFORE and NOT_AFTER are present.
        match params.iter().find(|kp| kp.tag == Tag::ALGORITHM) {
            Some(KeyParameter {
                tag: _,
                value: KeyParameterValue::Algorithm(Algorithm::RSA),
            })
            | Some(KeyParameter {
                tag: _,
                value: KeyParameterValue::Algorithm(Algorithm::EC),
            })
            | Some(KeyParameter {
                tag: _,
                value: KeyParameterValue::Algorithm(Algorithm::ML_DSA),
            }) => {
                if !params
                    .iter()
                    .any(|kp| kp.tag == Tag::CERTIFICATE_NOT_BEFORE)
                {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_BEFORE,
                        value: KeyParameterValue::DateTime(0),
                    })
                }
                if !params.iter().any(|kp| kp.tag == Tag::CERTIFICATE_NOT_AFTER) {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_AFTER,
                        value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
                    })
                }
            }
            _ => {}
        }
        Ok(result)
    }

    /// Check whether new key generation should be failed due to excessive per-uid key counts.
    fn check_key_counts(&self, key: &KeyDescriptor) -> Result<()> {
        if !crate::keymaster::flags::limit_keys_per_uid() {
            return Ok(());
        }
        if key.domain != Domain::APP {
            // Only limit app keys.
            return Ok(());
        }
        let uid = AppUid(key.nspace);

        // See how many keys this uid already owns.
        let Ok(count) =
            DB.with(|db| count_key_entries(&mut db.borrow_mut(), key.domain, key.nspace))
        else {
            // Fail open if we can't count the keys for some reason.
            error!("failed to count keys for {uid:?}");
            return Ok(());
        };

        // The per-uid limits for keys are based on the app's target SDK.
        // Determining the target SDK involves PackageManager round trips, so only
        // check target SDK if necessary.
        if count < API_37_PER_UID_KEY_LIMIT {
            // Below the lower limit => definitely OK.
            return Ok(());
        }
        let info = app_info_for_uid(uid);
        let targets_sdk37 = matches!(info.target_sdk, Some(target_sdk) if target_sdk >= 37);
        let limit = if info.is_system_app {
            // System apps get the higher limit.
            DEFAULT_PER_UID_KEY_LIMIT
        } else if targets_sdk37 {
            // Apps targeting SDK37+ get the lower limit.
            API_37_PER_UID_KEY_LIMIT
        } else {
            // Everything else gets the default (higher) limit.
            DEFAULT_PER_UID_KEY_LIMIT
        };

        if count >= limit {
            error!("failing key creation for {uid:?} with excessive ({count}) keys",);
            if targets_sdk37 {
                // Apps targeting SDK37+ can cope with the new error code.
                Err(error::Error::Rc(ResponseCode::TOO_MANY_APP_KEYS_SDK37)).context(ks_err!(
                    "failed key creation as {uid:?} (targeting SDK37+) has too many ({count}) existing keys",
                ))
            } else {
                Err(error::Error::Rc(ResponseCode::TOO_MANY_APP_KEYS)).context(ks_err!(
                    "failed key creation as {uid:?} has too many ({count}) existing keys",
                ))
            }
        } else {
            Ok(())
        }
    }

    // Generates a key and retries with swapped IMEI if an attestation ID mismatch error occurs.
    // This is a workaround for the fact that KeyMint was not required to support reordering
    // of IMEIs, even though the OS does not guarantee that the IMEI values are stably ordered.
    // This method can likely be safely removed in 34q2, once all devices still receiving
    // updates have KeyMint instances that are guaranteed to support this flexible ordering.
    fn generate_key_and_retry_on_att_id_mismatch(
        &self,
        params: &[KeyParameter],
        attest_key: Option<&AttestationKey>,
    ) -> Result<KeyCreationResult, Error> {
        let result = map_km_error({
            let _wp = self.watch_millis(
                "KeystoreSecurityLevel::generate_key: calling IKeyMintDevice::generateKey",
                5000,
            );
            self.keymint.generateKey(params, attest_key)
        });

        match &result {
            Err(Error::Km(ErrorCode::CANNOT_ATTEST_IDS))
            | Err(Error::Km(ErrorCode::INVALID_TAG))
            | Err(Error::Km(ErrorCode::ATTESTATION_IDS_NOT_PROVISIONED)) => {}
            _ => {
                // Not an error we can handle by retrying.
                return result;
            }
        }

        // The aforementioned errors might occur because the IMEI values are in the wrong order
        // which could only occur on KM instances that support multiple IMEIs in the first place.
        if self.hw_info.versionNumber < 300
            || self.hw_info.versionNumber >= 500
            || !params.iter().any(|p| is_imei_attestation_tag(p.tag))
        {
            return result;
        }

        // Try swapping the IMEI parameters, for those that are present.
        let swapped_params: Vec<KeyParameter> = params
            .iter()
            .map(|p| {
                let mut new_p = p.clone();
                match new_p.tag {
                    Tag::ATTESTATION_ID_IMEI => {
                        new_p.tag = Tag::ATTESTATION_ID_SECOND_IMEI;
                    }
                    Tag::ATTESTATION_ID_SECOND_IMEI => {
                        new_p.tag = Tag::ATTESTATION_ID_IMEI;
                    }
                    _ => {}
                }
                new_p
            })
            .collect();
        map_km_error({
            let _wp = self.watch_millis(
                concat!(
                    "KeystoreSecurityLevel::generate_key: calling ",
                    "IKeyMintDevice::generateKey, (retrying with swapped IMEIs)."
                ),
                5000,
            );
            self.keymint.generateKey(&swapped_params, attest_key)
        })
    }

    fn generate_key(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        attest_key_descriptor: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        _entropy: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Alias must be specified"));
        }
        let caller_uid = caller_uid(ctx);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid.0,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };
        self.check_key_counts(&key)?;

        // generate_key requires the rebind permission.
        // Must return on error for security reasons.
        check_key_permission(KeyPerm::Rebind, &key, None, ctx).context(ks_err!())?;

        let attestation_key_info = match (key.domain, attest_key_descriptor) {
            (Domain::BLOB, _) => None,
            _ => DB
                .with(|db| {
                    get_attest_key_info(
                        ctx,
                        caller_uid,
                        attest_key_descriptor,
                        params,
                        &mut db.borrow_mut(),
                    )
                })
                .context(ks_err!("Trying to get an attestation key"))?,
        };
        let params = self
            .add_required_parameters(ctx, caller_uid, params, &key)
            .context(ks_err!("Trying to get aaid."))?;

        let creation_result = match attestation_key_info {
            Some(AttestationKeyInfo::UserGenerated {
                key_id_guard,
                blob,
                blob_metadata,
                issuer_subject,
            }) => self
                .upgrade_keyblob_if_required_with(
                    Some(key_id_guard),
                    &KeyBlob::Ref(&blob),
                    blob_metadata.km_uuid().copied(),
                    &params,
                    |blob| {
                        let attest_key = Some(AttestationKey {
                            keyBlob: blob.to_vec(),
                            attestKeyParams: vec![],
                            issuerSubjectName: issuer_subject.clone(),
                        });
                        self.generate_key_and_retry_on_att_id_mismatch(&params, attest_key.as_ref())
                    },
                )
                .context(ks_err!(
                    "While generating with a user-generated \
                      attestation key, params: {:?}.",
                    log_security_safe_params(&params)
                ))
                .map(|(result, _)| result),
            None => self
                .generate_key_and_retry_on_att_id_mismatch(&params, None)
                .context(ks_err!(
                    "While generating without a provided \
                 attestation key and params: {:?}.",
                    log_security_safe_params(&params)
                )),
        }
        .context(ks_err!())?;

        let user = caller_uid.owning_user();
        self.store_new_key(key, creation_result, user, Some(flags))
            .context(ks_err!())
    }

    fn import_key(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        _attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Alias must be specified"));
        }
        let caller_uid = caller_uid(ctx);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid.0,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };
        self.check_key_counts(&key)?;

        // import_key requires the rebind permission.
        check_key_permission(KeyPerm::Rebind, &key, None, ctx)
            .context(ks_err!("In import_key."))?;

        let params = self
            .add_required_parameters(ctx, caller_uid, params, &key)
            .context(ks_err!("Trying to get aaid."))?;

        let format = params
            .iter()
            .find(|p| p.tag == Tag::ALGORITHM)
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("No KeyParameter 'Algorithm'."))
            .and_then(|p| match &p.value {
                KeyParameterValue::Algorithm(Algorithm::AES)
                | KeyParameterValue::Algorithm(Algorithm::HMAC)
                | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES) => Ok(KeyFormat::RAW),
                KeyParameterValue::Algorithm(Algorithm::RSA)
                | KeyParameterValue::Algorithm(Algorithm::EC)
                | KeyParameterValue::Algorithm(Algorithm::ML_DSA) => Ok(KeyFormat::PKCS8),
                v => Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(ks_err!("Unknown Algorithm {:?}.", v)),
            })
            .context(ks_err!())?;

        let km_dev = &self.keymint;
        let creation_result = map_km_error({
            let _wp =
                self.watch("KeystoreSecurityLevel::import_key: calling IKeyMintDevice::importKey.");
            km_dev.importKey(&params, format, key_data, None /* attestKey */)
        })
        .context(ks_err!("Trying to call importKey"))?;

        let user = caller_uid.owning_user();
        self.store_new_key(key, creation_result, user, Some(flags))
            .context(ks_err!())
    }

    fn import_wrapped_key(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata> {
        let wrapped_data: &[u8] = match key {
            KeyDescriptor {
                domain: Domain::APP,
                blob: Some(ref blob),
                alias: Some(_),
                ..
            }
            | KeyDescriptor {
                domain: Domain::SELINUX,
                blob: Some(ref blob),
                alias: Some(_),
                ..
            } => blob,
            _ => {
                return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(ks_err!(
                    "Alias and blob must be specified and domain must be APP or SELINUX. {:?}",
                    key
                ));
            }
        };

        if wrapping_key.domain == Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(ks_err!(
                "Import wrapped key not supported for self managed blobs."
            ));
        }

        let caller_uid = caller_uid(ctx);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid.0,
                alias: key.alias.clone(),
                blob: None,
            },
            Domain::SELINUX => KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: key.nspace,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => panic!("Unreachable."),
        };
        self.check_key_counts(&key)?;

        // Import_wrapped_key requires the rebind permission for the new key.
        check_key_permission(KeyPerm::Rebind, &key, None, ctx).context(ks_err!())?;

        let user = caller_uid.owning_user();

        let (wrapping_key_id_guard, mut wrapping_key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    wrapping_key,
                    KeyType::Client,
                    KeyEntryLoadBits::KM,
                    caller_uid,
                    |k, av| check_key_permission(KeyPerm::Use, k, av.as_ref(), ctx),
                )
            })
            .context(ks_err!("Failed to load wrapping key."))?;

        let (wrapping_key_blob, wrapping_blob_metadata) = wrapping_key_entry
            .take_key_blob_info()
            .ok_or_else(error::Error::sys)
            .context(ks_err!(
                "No km_blob after successfully loading key. This should never happen."
            ))?;

        let wrapping_key_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&wrapping_blob_metadata, &wrapping_key_blob)
            .context(ks_err!(
                "Failed to handle super encryption for wrapping key."
            ))?;

        // km_dev.importWrappedKey does not return a certificate chain.
        // TODO Do we assume that all wrapped keys are symmetric?
        // let certificate_chain: Vec<KmCertificate> = Default::default();

        let pw_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::PASSWORD => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let fp_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::FINGERPRINT => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let masking_key = masking_key.unwrap_or(ZERO_BLOB_32);

        let (creation_result, _) = self
            .upgrade_keyblob_if_required_with(
                Some(wrapping_key_id_guard),
                &wrapping_key_blob,
                wrapping_blob_metadata.km_uuid().copied(),
                &[],
                |wrapping_blob| {
                    let _wp = self.watch(
                        "KeystoreSecurityLevel::import_wrapped_key: calling IKeyMintDevice::importWrappedKey.",
                    );
                    let creation_result = map_km_error(self.keymint.importWrappedKey(
                        wrapped_data,
                        wrapping_blob,
                        masking_key,
                        params,
                        pw_sid,
                        fp_sid,
                    ))?;
                    Ok(creation_result)
                },
            )
            .context(ks_err!())?;

        self.store_new_key(key, creation_result, user, None)
            .context(ks_err!("Trying to store the new key for {user:?}"))
    }

    fn store_upgraded_keyblob(
        key_id_guard: KeyIdGuard,
        km_uuid: Option<Uuid>,
        key_blob: &KeyBlob,
        upgraded_blob: &[u8],
    ) -> Result<()> {
        let (upgraded_blob_to_be_stored, new_blob_metadata) =
            SuperKeyManager::reencrypt_if_required(key_blob, upgraded_blob)
                .context(ks_err!("Failed to handle super encryption."))?;

        let mut new_blob_metadata = new_blob_metadata.unwrap_or_default();
        if let Some(uuid) = km_uuid {
            new_blob_metadata.add(BlobMetaEntry::KmUuid(uuid));
        }

        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.set_blob(
                &key_id_guard,
                SubComponentType::KEY_BLOB,
                Some(&upgraded_blob_to_be_stored),
                Some(&new_blob_metadata),
            )
        })
        .context(ks_err!("Failed to insert upgraded blob into the database."))
    }

    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        mut key_id_guard: Option<KeyIdGuard>,
        key_blob: &KeyBlob,
        km_uuid: Option<Uuid>,
        params: &[KeyParameter],
        f: F,
    ) -> Result<(T, Option<Vec<u8>>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let (v, upgraded_blob) = upgrade_keyblob_if_required_with(
            &self.keymint,
            self.hw_info.versionNumber,
            key_blob,
            params,
            f,
            |upgraded_blob| {
                if key_id_guard.is_some() {
                    // Unwrap cannot panic, because the is_some was true.
                    let kid = key_id_guard.take().unwrap();
                    Self::store_upgraded_keyblob(kid, km_uuid, key_blob, upgraded_blob)
                        .context(ks_err!("store_upgraded_keyblob failed"))
                } else {
                    Ok(())
                }
            },
        )
        .context(ks_err!(
            "upgrade_keyblob_if_required_with(key_id={:?})",
            key_id_guard
        ))?;

        // If no upgrade was needed, use the opportunity to reencrypt the blob if required
        // and if the a key_id_guard is held. Note: key_id_guard can only be Some if no
        // upgrade was performed above and if one was given in the first place.
        if key_blob.force_reencrypt() {
            if let Some(kid) = key_id_guard {
                Self::store_upgraded_keyblob(kid, km_uuid, key_blob, key_blob)
                    .context(ks_err!("store_upgraded_keyblob failed in forced reencrypt"))?;
            }
        }
        Ok((v, upgraded_blob))
    }

    fn convert_storage_key_to_ephemeral(
        &self,
        ctx: Option<&CallerInfo>,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse> {
        if storage_key.domain != Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Key must be of Domain::BLOB"));
        }
        let key_blob = storage_key
            .blob
            .as_ref()
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("No key blob specified"))?;

        // convert_storage_key_to_ephemeral requires the associated permission
        check_key_permission(
            KeyPerm::ConvertStorageKeyToEphemeral,
            storage_key,
            None,
            ctx,
        )
        .context(ks_err!("Check permission"))?;

        let km_dev = &self.keymint;
        let res = {
            let _wp = self.watch(concat!(
                "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
                "calling IKeyMintDevice::convertStorageKeyToEphemeral (1)"
            ));
            map_km_error(km_dev.convertStorageKeyToEphemeral(key_blob))
        };
        match res {
            Ok(result) => Ok(EphemeralStorageKeyResponse {
                ephemeralKey: result,
                upgradedBlob: None,
            }),
            Err(error::Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = {
                    let _wp = self.watch("IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: calling IKeyMintDevice::upgradeKey");
                    map_km_error(km_dev.upgradeKey(key_blob, &[]))
                }
                .context(ks_err!("Failed to upgrade key blob."))?;
                let ephemeral_key = {
                    let _wp = self.watch(concat!(
                        "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
                        "calling IKeyMintDevice::convertStorageKeyToEphemeral (2)"
                    ));
                    map_km_error(km_dev.convertStorageKeyToEphemeral(&upgraded_blob))
                }
                .context(ks_err!("Failed to retrieve ephemeral key (after upgrade)."))?;
                Ok(EphemeralStorageKeyResponse {
                    ephemeralKey: ephemeral_key,
                    upgradedBlob: Some(upgraded_blob),
                })
            }
            Err(e) => Err(e).context(ks_err!("Failed to retrieve ephemeral key.")),
        }
    }

    fn delete_key(&self, ctx: Option<&CallerInfo>, key: &KeyDescriptor) -> Result<()> {
        if key.domain != Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("delete_key: Key must be of Domain::BLOB"));
        }

        let key_blob = key
            .blob
            .as_ref()
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("delete_key: No key blob specified"))?;

        check_key_permission(KeyPerm::Delete, key, None, ctx)
            .context(ks_err!("delete_key: Checking delete permissions"))?;

        let km_dev = &self.keymint;
        {
            let _wp =
                self.watch("KeystoreSecuritylevel::delete_key: calling IKeyMintDevice::deleteKey");
            map_km_error(km_dev.deleteKey(key_blob)).context(ks_err!("keymint device deleteKey"))
        }
    }
}

fn caller_uid(ctx: Option<&CallerInfo>) -> AppUid {
    AppUid(
        ctx.map(|ctx| ctx.callingUid)
            .unwrap_or_else(|| CallingContext::default().uid.into()),
    )
}

fn require_omk_ctx<'a>(
    ctx: Option<&'a CallerInfo>,
    label: &str,
) -> std::result::Result<&'a CallerInfo, Status> {
    require_forwarded_context(ctx, label).map_err(into_logged_binder)
}

impl binder::Interface for AospSecurityLevelWrapper {}
impl binder::Interface for OmkSecurityLevelWrapper {}

impl IKeystoreSecurityLevel for AospSecurityLevelWrapper {
    fn createOperation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::createOperation");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) =
            crate::timed_call!(self.create_operation(None, key, operation_parameters, forced));
        log_operation_latency(
            OperationType::CREATE_OPERATION,
            self.security_level,
            operation_parameters,
            result.is_ok(),
            latency,
        );
        result.map_err(into_logged_binder)
    }
    fn generateKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> Result<KeyMetadata, Status> {
        // Duration is set to 5 seconds, because generateKey - especially for RSA keys, takes more
        // time than other operations
        let _wp = self.watch_millis("IKeystoreSecurityLevel::generateKey", 5000);
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) = crate::timed_call!(self.generate_key(
            None,
            key,
            attestation_key,
            params,
            flags,
            entropy
        ));
        log_key_creation_event_stats(
            caller_uid(None).0 as i32,
            self.security_level,
            params,
            KeyOrigin::GENERATED,
            &result,
        );
        log_operation_latency(
            OperationType::GENERATE_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_generated(key, caller_uid(None).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn importKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> Result<KeyMetadata, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::importKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) = crate::timed_call!(self.import_key(
            None,
            key,
            attestation_key,
            params,
            flags,
            key_data
        ));
        log_key_creation_event_stats(
            caller_uid(None).0 as i32,
            self.security_level,
            params,
            KeyOrigin::IMPORTED,
            &result,
        );
        log_operation_latency(
            OperationType::IMPORT_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_imported(key, caller_uid(None).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn importWrappedKey(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::importWrappedKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) = crate::timed_call!(self.import_wrapped_key(
            None,
            key,
            wrapping_key,
            masking_key,
            params,
            authenticators
        ));
        log_key_creation_event_stats(
            caller_uid(None).0 as i32,
            self.security_level,
            params,
            KeyOrigin::SECURELY_IMPORTED,
            &result,
        );
        log_operation_latency(
            OperationType::IMPORT_WRAPPED_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_imported(key, caller_uid(None).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn convertStorageKeyToEphemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::convertStorageKeyToEphemeral");
        security_level_manager::notify_operation_performed(self.security_level);
        self.convert_storage_key_to_ephemeral(None, storage_key)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::deleteKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let result = self.delete_key(None, key);
        log_key_deleted(key, caller_uid(None).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }
}

impl IOhMySecurityLevel for OmkSecurityLevelWrapper {
    fn createOperation(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse, Status> {
        let ctx = Some(require_omk_ctx(ctx, "IOhMySecurityLevel::createOperation")?);
        let _wp = self.watch("IOhMySecurityLevel::createOperation");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) =
            crate::timed_call!(self.create_operation(ctx, key, operation_parameters, forced));
        log_operation_latency(
            OperationType::CREATE_OPERATION,
            self.security_level,
            operation_parameters,
            result.is_ok(),
            latency,
        );
        result.map_err(into_logged_binder)
    }

    fn generateKey(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> Result<KeyMetadata, Status> {
        let ctx = Some(require_omk_ctx(ctx, "IOhMySecurityLevel::generateKey")?);
        let _wp = self.watch_millis("IOhMySecurityLevel::generateKey", 5000);
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) = crate::timed_call!(self.generate_key(
            ctx,
            key,
            attestation_key,
            params,
            flags,
            entropy
        ));
        log_key_creation_event_stats(
            caller_uid(ctx).0 as i32,
            self.security_level,
            params,
            KeyOrigin::GENERATED,
            &result,
        );
        log_operation_latency(
            OperationType::GENERATE_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_generated(key, caller_uid(ctx).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }

    fn importKey(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> Result<KeyMetadata, Status> {
        let ctx = Some(require_omk_ctx(ctx, "IOhMySecurityLevel::importKey")?);
        let _wp = self.watch("IOhMySecurityLevel::importKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) =
            crate::timed_call!(self.import_key(ctx, key, attestation_key, params, flags, key_data));
        log_key_creation_event_stats(
            caller_uid(ctx).0 as i32,
            self.security_level,
            params,
            KeyOrigin::IMPORTED,
            &result,
        );
        log_operation_latency(
            OperationType::IMPORT_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_imported(key, caller_uid(ctx).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }

    fn importWrappedKey(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata, Status> {
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMySecurityLevel::importWrappedKey",
        )?);
        let _wp = self.watch("IOhMySecurityLevel::importWrappedKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let (latency, result) = crate::timed_call!(self.import_wrapped_key(
            ctx,
            key,
            wrapping_key,
            masking_key,
            params,
            authenticators
        ));
        log_key_creation_event_stats(
            caller_uid(ctx).0 as i32,
            self.security_level,
            params,
            KeyOrigin::SECURELY_IMPORTED,
            &result,
        );
        log_operation_latency(
            OperationType::IMPORT_WRAPPED_KEY,
            self.security_level,
            params,
            result.is_ok(),
            latency,
        );
        log_key_imported(key, caller_uid(ctx).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }

    fn convertStorageKeyToEphemeral(
        &self,
        ctx: Option<&CallerInfo>,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse, Status> {
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMySecurityLevel::convertStorageKeyToEphemeral",
        )?);
        let _wp = self.watch("IOhMySecurityLevel::convertStorageKeyToEphemeral");
        security_level_manager::notify_operation_performed(self.security_level);
        self.convert_storage_key_to_ephemeral(ctx, storage_key)
            .map_err(into_logged_binder)
    }

    fn deleteKey(&self, ctx: Option<&CallerInfo>, key: &KeyDescriptor) -> Result<(), Status> {
        let ctx = Some(require_omk_ctx(ctx, "IOhMySecurityLevel::deleteKey")?);
        let _wp = self.watch("IOhMySecurityLevel::deleteKey");
        security_level_manager::notify_operation_performed(self.security_level);
        let result = self.delete_key(ctx, key);
        log_key_deleted(key, caller_uid(ctx).0 as libc::uid_t, result.is_ok());
        result.map_err(into_logged_binder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigFile, ResolvedTrust, TrustValueSource};
    use std::sync::Once;
    use tempfile::TempDir;

    static CONFIG_INIT: Once = Once::new();

    fn install_test_config() {
        CONFIG_INIT.call_once(|| {
            crate::config::install_runtime_config(
                ConfigFile::default(),
                ResolvedTrust {
                    os_version: 16,
                    security_patch: "2025-06-05".to_string(),
                    vb_key: [0; 32],
                    vb_hash: [0; 32],
                    vb_key_source: TrustValueSource::ExplicitHex,
                    vb_hash_source: TrustValueSource::ExplicitHex,
                    verified_boot_state: true,
                    device_locked: true,
                },
            )
            .unwrap();
        });
    }

    fn test_security_level() -> (TempDir, KeystoreSecurityLevel) {
        crate::keymaster::utils::init_test_logging();
        install_test_config();
        let temp_dir = TempDir::new().unwrap();
        let security_level = KeystoreSecurityLevel::new(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            IdRotationState::new(temp_dir.path()),
        )
        .unwrap();
        (temp_dir, security_level)
    }

    fn blob_descriptor(blob: Option<Vec<u8>>) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::BLOB,
            nspace: 0,
            alias: None,
            blob,
        }
    }

    fn untrusted_app() -> CallerInfo {
        CallerInfo {
            callingUid: 10123,
            callingSid: "u:r:untrusted_app:s0".to_string(),
            callingPid: 1234,
        }
    }

    fn service_specific<T>(result: anyhow::Result<T>) -> i32 {
        match result {
            Ok(_) => panic!("expected service-specific error"),
            Err(error) => into_logged_binder(error).service_specific_error(),
        }
    }

    #[test]
    fn convert_storage_key_to_ephemeral_rejects_blob_null_before_permission() {
        let (_temp_dir, security_level) = test_security_level();
        let key = blob_descriptor(None);

        assert_eq!(
            ErrorCode::INVALID_ARGUMENT.0,
            service_specific(
                security_level.convert_storage_key_to_ephemeral(Some(&untrusted_app()), &key)
            )
        );
    }

    #[test]
    fn delete_key_rejects_blob_null_before_permission() {
        let (_temp_dir, security_level) = test_security_level();
        let key = blob_descriptor(None);

        assert_eq!(
            ErrorCode::INVALID_ARGUMENT.0,
            service_specific(security_level.delete_key(Some(&untrusted_app()), &key))
        );
    }

    #[test]
    fn convert_storage_key_to_ephemeral_keeps_empty_blob_on_permission_path() {
        let (_temp_dir, security_level) = test_security_level();
        let key = blob_descriptor(Some(Vec::new()));

        assert_eq!(
            ResponseCode::PERMISSION_DENIED.0,
            service_specific(
                security_level.convert_storage_key_to_ephemeral(Some(&untrusted_app()), &key)
            )
        );
    }

    #[test]
    fn delete_key_keeps_empty_blob_on_permission_path() {
        let (_temp_dir, security_level) = test_security_level();
        let key = blob_descriptor(Some(Vec::new()));

        assert_eq!(
            ResponseCode::PERMISSION_DENIED.0,
            service_specific(security_level.delete_key(Some(&untrusted_app()), &key))
        );
    }
}
