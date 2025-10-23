use std::time::SystemTime;

use crate::{
    android::{
        hardware::security::keymint::{
            Algorithm::Algorithm, AttestationKey::AttestationKey, ErrorCode::ErrorCode,
            HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
            KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat, KeyParameter::KeyParameter,
            KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
        },
        system::keystore2::{
            AuthenticatorSpec::AuthenticatorSpec, CreateOperationResponse::CreateOperationResponse,
            Domain::Domain, EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
            IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
            KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata, KeyParameters::KeyParameters,
            ResponseCode::ResponseCode,
        },
    },
    err,
    global::{DB, ENFORCEMENTS, SUPER_KEY, UNDEFINED_NOT_AFTER},
    keymaster::{
        attestation_key_utils::{get_attest_key_info, AttestationKeyInfo},
        db::{
            BlobInfo, BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry,
            KeyEntryLoadBits, KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType, SubComponentType,
            Uuid,
        },
        error::{into_logged_binder, map_binder_status, KsError},
        keymint_device::KeyMintWrapper,
        metrics_store::log_key_creation_event_stats,
        operation::{KeystoreOperation, LoggingInfo, OperationDb},
        super_key::{KeyBlob, SuperKeyManager},
        utils::{key_characteristics_to_internal, key_parameters_to_authorizations, log_params},
    },
    plat::utils::multiuser_get_user_id,
    top::qwq2333::ohmykeymint::{CallerInfo::CallerInfo, IOhMySecurityLevel::IOhMySecurityLevel},
};

use crate::keymaster::key_parameter::KeyParameter as KsKeyParam;
use crate::keymaster::key_parameter::KeyParameterValue as KsKeyParamValue;

use crate::watchdog as wd;

use anyhow::{anyhow, Context, Result};
use kmr_wire::keymint::KeyMintHardwareInfo;
use log::debug;
use rsbinder::{thread_state::CallingContext, Interface, Status};

// Blob of 32 zeroes used as empty masking key.
static ZERO_BLOB_32: &[u8] = &[0; 32];

pub struct KeystoreSecurityLevel {
    security_level: SecurityLevel,
    km_wrapper: KeyMintWrapper,
    hw_info: KeyMintHardwareInfo,
    km_uuid: Uuid,
    operation_db: OperationDb,
}

impl KeystoreSecurityLevel {
    pub fn new(security_level: SecurityLevel, km_uuid: Uuid) -> Result<Self> {
        let km_wrapper = KeyMintWrapper::new(security_level)
            .expect(err!("Failed to init strongbox wrapper").as_str());

        let hw_info = km_wrapper
            .get_hardware_info()
            .context(err!("Failed to get hardware info."))?;

        Ok(KeystoreSecurityLevel {
            security_level,
            km_wrapper,
            hw_info,
            km_uuid,
            operation_db: OperationDb::new(),
        })
    }

    fn watch_millis(&self, id: &'static str, millis: u64) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, millis, sec_level)
    }

    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
    }

    fn get_keymint_wrapper(&self) -> &KeyMintWrapper {
        &self.km_wrapper
    }

    fn store_upgraded_keyblob(
        key_id_guard: KeyIdGuard,
        km_uuid: Option<Uuid>,
        key_blob: &KeyBlob,
        upgraded_blob: &[u8],
    ) -> Result<()> {
        let (upgraded_blob_to_be_stored, new_blob_metadata) =
            SuperKeyManager::reencrypt_if_required(key_blob, upgraded_blob)
                .context(err!("Failed to handle super encryption."))?;

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
        .context(err!("Failed to insert upgraded blob into the database."))
    }

    fn add_required_parameters(
        &self,
        uid: u32,
        params: &[KeyParameter],
        key: &KeyDescriptor,
    ) -> Result<Vec<KeyParameter>> {
        debug!(
            "KeystoreSecurityLevel::add_required_parameters: params={:?}, key={:?}",
            log_params(params),
            key
        );
        let mut result = params.to_vec();

        // Prevent callers from specifying the CREATION_DATETIME tag.
        if params.iter().any(|kp| kp.tag == Tag::CREATION_DATETIME) {
            return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                "KeystoreSecurityLevel::add_required_parameters: \
                Specifying Tag::CREATION_DATETIME is not allowed."
            ));
        }

        // Use this variable to refer to notion of "now". This eliminates discrepancies from
        // quering the clock multiple times.
        let creation_datetime = SystemTime::now();

        // Add CREATION_DATETIME only if the backend version Keymint V1 (100) or newer.
        if self.hw_info.version_number >= 100 {
            result.push(KeyParameter {
                tag: Tag::CREATION_DATETIME,
                value: KeyParameterValue::DateTime(
                    creation_datetime
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .context(err!(
                            "KeystoreSecurityLevel::add_required_parameters: \
                                Failed to get epoch time."
                        ))?
                        .as_millis()
                        .try_into()
                        .context(err!(
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
            match crate::plat::utils::get_aaid(uid) {
                Ok(aaid_ok) => {
                    result.push(KeyParameter {
                        tag: Tag::ATTESTATION_APPLICATION_ID,
                        value: KeyParameterValue::Blob(aaid_ok),
                    });
                }
                Err(e) => return Err(anyhow!(e)).context(err!("Attestation ID retrieval error.")),
            }
        }

        // if params.iter().any(|kp| kp.tag == Tag::INCLUDE_UNIQUE_ID) {
        //     if check_key_permission(KeyPerm::GenUniqueId, key, &None).is_err()
        //         && check_unique_id_attestation_permissions().is_err()
        //     {
        //         return Err(Error::perm()).context(err!(
        //             "Caller does not have the permission to generate a unique ID"
        //         ));
        //     }
        //     if self
        //         .id_rotation_state
        //         .had_factory_reset_since_id_rotation(&creation_datetime)
        //         .context(err!("Call to had_factory_reset_since_id_rotation failed."))?
        //     {
        //         result.push(KeyParameter {
        //             tag: Tag::RESET_SINCE_ID_ROTATION,
        //             value: KeyParameterValue::BoolValue(true),
        //         })
        //     }
        // }

        // If the caller requests any device identifier attestation tag, check that they hold the
        // correct Android permission.
        // if params.iter().any(|kp| is_device_id_attestation_tag(kp.tag)) {
        //     check_device_attestation_permissions().context(err!(
        //         "Caller does not have the permission to attest device identifiers."
        //     ))?;
        // }

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

    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        mut key_id_guard: Option<KeyIdGuard>,
        key_blob: &KeyBlob,
        km_uuid: Option<Uuid>,
        params: &[KeyParameter],
        f: F,
    ) -> Result<(T, Option<Vec<u8>>)>
    where
        F: Fn(&[u8]) -> Result<T, KsError>,
    {
        let (v, upgraded_blob) = crate::keymaster::utils::upgrade_keyblob_if_required_with(
            self.security_level,
            self.hw_info.version_number,
            key_blob,
            params,
            f,
            |upgraded_blob| {
                if key_id_guard.is_some() {
                    // Unwrap cannot panic, because the is_some was true.
                    let kid = key_id_guard.take().unwrap();
                    Self::store_upgraded_keyblob(kid, km_uuid, key_blob, upgraded_blob)
                        .context(err!("store_upgraded_keyblob failed"))
                } else {
                    Ok(())
                }
            },
        )
        .context(err!(
            "upgrade_keyblob_if_required_with(key_id={:?})",
            key_id_guard
        ))?;

        // If no upgrade was needed, use the opportunity to reencrypt the blob if required
        // and if the a key_id_guard is held. Note: key_id_guard can only be Some if no
        // upgrade was performed above and if one was given in the first place.
        if key_blob.force_reencrypt() {
            if let Some(kid) = key_id_guard {
                Self::store_upgraded_keyblob(kid, km_uuid, key_blob, key_blob)
                    .context(err!("store_upgraded_keyblob failed in forced reencrypt"))?;
            }
        }
        Ok((v, upgraded_blob))
    }

    fn store_new_key(
        &self,
        key: KeyDescriptor,
        creation_result: KeyCreationResult,
        user_id: u32,
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
        //  - `certificate[1`]: a single `Certificate` from RKP that actually (and confusingly)
        //    holds the DER-encoded certs of the chain concatenated together.
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
            KsKeyParamValue::UserID(user_id as i32),
            SecurityLevel::SOFTWARE,
        ));

        let creation_date = DateTime::now().context(err!("Trying to make creation time."))?;

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
                            user_id,
                            &key_blob,
                        )
                        .context(err!("Failed to handle super encryption."))?;

                    let mut key_metadata = KeyMetaData::new();
                    key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
                    blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                    let key_id = db
                        .store_new_key(
                            &key,
                            KeyType::Client,
                            &key_parameters,
                            &BlobInfo::new(&key_blob, &blob_metadata),
                            &cert_info,
                            &key_metadata,
                            &self.km_uuid,
                        )
                        .context(err!())?;
                    Ok(KeyDescriptor {
                        domain: Domain::KEY_ID,
                        nspace: key_id.id(),
                        ..Default::default()
                    })
                })
                .context(err!())?,
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

    #[allow(unused_variables)]
    pub fn generate_key(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        attest_key_descriptor: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        _entropy: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                .context(err!("Alias must be provided for non-BLOB domains"));
        }
        let calling_uid = if let Some(ctx) = ctx {
            ctx.callingUid
        } else {
            CallingContext::default().uid.into()
        } as u32;

        debug!("KeystoreSecurityLevel::generate_key: uid={:?} key={:?}, attest_key_descriptor={:?}, params={:?}, flags={}", calling_uid, key, attest_key_descriptor, log_params(params), flags);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: calling_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // TODO: check perms

        let attestation_key_info = match (key.domain, attest_key_descriptor) {
            (Domain::BLOB, _) => None,
            _ => DB
                .with(|db| {
                    get_attest_key_info(
                        &key,
                        calling_uid,
                        attest_key_descriptor,
                        params,
                        &mut db.borrow_mut(),
                    )
                })
                .context(err!("Trying to get an attestation key"))?,
        };

        let params = self
            .add_required_parameters(calling_uid, params, &key)
            .context(err!("Trying to get aaid."))?;

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
                        let _wp = self.watch_millis(
                            concat!(
                                "KeystoreSecurityLevel::generate_key (UserGenerated): ",
                                "calling IKeyMintDevice::generate_key"
                            ),
                            5000, // Generate can take a little longer.
                        );
                        let result = self
                            .get_keymint_wrapper()
                            .generateKey(&params, attest_key.as_ref());
                        map_binder_status(result)
                    },
                )
                .context(err!(
                    "While generating with a user-generated \
                      attestation key, params: {:?}.",
                    log_params(&params)
                ))
                .map(|(result, _)| result),
            None => {
                let _wp = self.watch_millis(
                    concat!(
                        "KeystoreSecurityLevel::generate_key (No attestation key): ",
                        "calling IKeyMintDevice::generate_key",
                    ),
                    5000, // Generate can take a little longer.
                );
                self.get_keymint_wrapper().generateKey(&params, None)
            }
            .context(err!(
                "While generating without a provided \
                 attestation key and params: {:?}.",
                log_params(&params)
            )),
            _ => unreachable!(), // Other branches of get_attest_key_info are not possible here.
        }?;

        let user_id = crate::plat::utils::multiuser_get_user_id(calling_uid);
        self.store_new_key(key, creation_result, user_id, Some(flags))
            .context(err!())
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
            return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                .context(err!("Alias must be specified"));
        }

        let caller_uid = if let Some(ctx) = ctx {
            ctx.callingUid
        } else {
            CallingContext::default().uid.into()
        } as u32;

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // import_key requires the rebind permission.
        // check_key_permission(KeyPerm::Rebind, &key, &None).context(err!("In import_key."))?;

        let params = self
            .add_required_parameters(caller_uid, params, &key)
            .context(err!("Trying to get aaid."))?;

        let format = params
            .iter()
            .find(|p| p.tag == Tag::ALGORITHM)
            .ok_or(KsError::Km(ErrorCode::INVALID_ARGUMENT))
            .context(err!("No KeyParameter 'Algorithm'."))
            .and_then(|p| match &p.value {
                KeyParameterValue::Algorithm(Algorithm::AES)
                | KeyParameterValue::Algorithm(Algorithm::HMAC)
                | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES) => Ok(KeyFormat::RAW),
                KeyParameterValue::Algorithm(Algorithm::RSA)
                | KeyParameterValue::Algorithm(Algorithm::EC) => Ok(KeyFormat::PKCS8),
                v => Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(err!("Unknown Algorithm {:?}.", v)),
            })
            .context(err!())?;

        let km_dev = self.get_keymint_wrapper();
        let creation_result = map_binder_status({
            let _wp =
                self.watch("KeystoreSecurityLevel::import_key: calling IKeyMintDevice::importKey.");
            km_dev.importKey(&params, format, key_data, None /* attestKey */)
        })
        .context(err!("Trying to call importKey"))?;

        let user_id = multiuser_get_user_id(caller_uid);
        self.store_new_key(key, creation_result, user_id, Some(flags))
            .context(err!())
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
                return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT)).context(err!(
                    "Alias and blob must be specified and domain must be APP or SELINUX. {:?}",
                    key
                ));
            }
        };

        if wrapping_key.domain == Domain::BLOB {
            return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT)).context(err!(
                "Import wrapped key not supported for self managed blobs."
            ));
        }

        let caller_uid = if let Some(ctx) = ctx {
            ctx.callingUid
        } else {
            CallingContext::default().uid.into()
        } as u32;
        let user_id = multiuser_get_user_id(caller_uid);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
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

        // Import_wrapped_key requires the rebind permission for the new key.
        // check_key_permission(KeyPerm::Rebind, &key, &None).context(err!())?;

        let super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(user_id);

        let (wrapping_key_id_guard, mut wrapping_key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    wrapping_key,
                    KeyType::Client,
                    KeyEntryLoadBits::KM,
                    caller_uid,
                )
            })
            .context(err!("Failed to load wrapping key."))?;

        let (wrapping_key_blob, wrapping_blob_metadata) = wrapping_key_entry
            .take_key_blob_info()
            .ok_or_else(KsError::sys)
            .context(err!(
                "No km_blob after successfully loading key. This should never happen."
            ))?;

        let wrapping_key_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&wrapping_blob_metadata, &wrapping_key_blob)
            .context(err!("Failed to handle super encryption for wrapping key."))?;

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
                    let km_dev = self.get_keymint_wrapper();
                    let creation_result = map_binder_status(km_dev.importWrappedKey(
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
            .context(err!())?;

        self.store_new_key(key, creation_result, user_id, None)
            .context(err!("Trying to store the new key."))
    }

    fn convert_storage_key_to_ephemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse> {
        if storage_key.domain != Domain::BLOB {
            return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                .context(err!("Key must be of Domain::BLOB"));
        }
        let key_blob = storage_key
            .blob
            .as_ref()
            .ok_or(KsError::Km(ErrorCode::INVALID_ARGUMENT))
            .context(err!("No key blob specified"))?;

        // convert_storage_key_to_ephemeral requires the associated permission
        // check_key_permission(KeyPerm::ConvertStorageKeyToEphemeral, storage_key, &None)
        //     .context(err!("Check permission"))?;

        let km_dev = self.get_keymint_wrapper();
        let res = {
            let _wp = self.watch(concat!(
                "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
                "calling IKeyMintDevice::convertStorageKeyToEphemeral (1)"
            ));
            map_binder_status(km_dev.convertStorageKeyToEphemeral(key_blob))
        };
        match res {
            Ok(result) => Ok(EphemeralStorageKeyResponse {
                ephemeralKey: result,
                upgradedBlob: None,
            }),
            Err(KsError::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = {
                    let _wp = self.watch("IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: calling IKeyMintDevice::upgradeKey");
                    map_binder_status(km_dev.upgradeKey(key_blob, &[]))
                }
                .context(err!("Failed to upgrade key blob."))?;
                let ephemeral_key = {
                    let _wp = self.watch(concat!(
                        "IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
                        "calling IKeyMintDevice::convertStorageKeyToEphemeral (2)"
                    ));
                    map_binder_status(km_dev.convertStorageKeyToEphemeral(&upgraded_blob))
                }
                .context(err!("Failed to retrieve ephemeral key (after upgrade)."))?;
                Ok(EphemeralStorageKeyResponse {
                    ephemeralKey: ephemeral_key,
                    upgradedBlob: Some(upgraded_blob),
                })
            }
            Err(e) => Err(e).context(err!("Failed to retrieve ephemeral key.")),
        }
    }

    fn create_operation(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse> {
        let caller_uid = if let Some(ctx) = ctx {
            ctx.callingUid
        } else {
            CallingContext::default().uid.into()
        } as u32;
        // We use `scoping_blob` to extend the life cycle of the blob loaded from the database,
        // so that we can use it by reference like the blob provided by the key descriptor.
        // Otherwise, we would have to clone the blob from the key descriptor.
        let scoping_blob: Vec<u8>;
        let (km_blob, key_properties, key_id_guard, blob_metadata) = match key.domain {
            Domain::BLOB => {
                // check_key_permission(KeyPerm::Use, key, &None)
                //     .context(err!("checking use permission for Domain::BLOB."))?;
                // if forced {
                //     check_key_permission(KeyPerm::ReqForcedOp, key, &None)
                //         .context(err!("checking forced permission for Domain::BLOB."))?;
                // }
                (
                    match &key.blob {
                        Some(blob) => blob,
                        None => {
                            return Err(KsError::sys()).context(err!(
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
                let super_key = SUPER_KEY
                    .read()
                    .unwrap()
                    .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));
                let (key_id_guard, mut key_entry) = DB
                    .with::<_, Result<(KeyIdGuard, KeyEntry)>>(|db| {
                        db.borrow_mut().load_key_entry(
                            key,
                            KeyType::Client,
                            KeyEntryLoadBits::KM,
                            caller_uid,
                            // |k, av| {
                            //     check_key_permission(KeyPerm::Use, k, &av)?;
                            //     if forced {
                            //         check_key_permission(KeyPerm::ReqForcedOp, k, &av)?;
                            //     }
                            //     Ok(())
                            // },
                        )
                    })
                    .context(err!("Failed to load key blob."))?;

                let (blob, blob_metadata) = key_entry
                    .take_key_blob_info()
                    .ok_or_else(KsError::sys)
                    .context(err!(
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
                Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(err!("No operation purpose specified.")),
                |kp| match kp.value {
                    KeyParameterValue::KeyPurpose(p) => Ok(p),
                    _ => Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                        .context(err!("Malformed KeyParameter.")),
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
                false,
            )
            .context(err!())?;

        let km_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&blob_metadata, km_blob)
            .context(err!("Failed to handle super encryption."))?;

        let (begin_result, upgraded_blob) = self
            .upgrade_keyblob_if_required_with(
                key_id_guard,
                &km_blob,
                blob_metadata.km_uuid().copied(),
                operation_parameters,
                |blob| loop {
                    match map_binder_status({
                        let _wp = self.watch(
                            "KeystoreSecurityLevel::create_operation: calling IKeyMintDevice::begin",
                        );
                        let km_dev = self.get_keymint_wrapper();
                        km_dev.begin(
                            purpose,
                            blob,
                            operation_parameters,
                            immediate_hat.as_ref(),
                        )
                    }) {
                        Err(KsError::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                            self.operation_db.prune(caller_uid, forced)?;
                            continue;
                        }
                        v @ Err(KsError::Km(ErrorCode::INVALID_KEY_BLOB)) => {
                            if let Some((key_id, _)) = key_properties {
                                if let Ok(Some(key)) =
                                    DB.with(|db| db.borrow_mut().load_key_descriptor(key_id))
                                {
                                    log::error!("Key integrity violation detected for key id {}", key_id);
                                } else {
                                    log::error!("Failed to load key descriptor for audit log");
                                }
                            }
                            return v;
                        }
                        v => return v,
                    }
                },
            )
            .context(err!("Failed to begin operation."))?;

        let operation_challenge = auth_info.finalize_create_authorization(begin_result.challenge);

        let op_params: Vec<KeyParameter> = operation_parameters.to_vec();

        let operation = match begin_result.operation {
            Some(km_op) => self.operation_db.create_operation(
                km_op,
                caller_uid,
                auth_info,
                forced,
                LoggingInfo::new(
                    self.security_level,
                    purpose,
                    op_params,
                    upgraded_blob.is_some(),
                ),
            ),
            None => {
                return Err(KsError::sys()).context(err!(
                    "Begin operation returned successfully, \
                    but did not return a valid operation."
                ));
            }
        };

        let op_binder: rsbinder::Strong<dyn IKeystoreOperation> =
            KeystoreOperation::new_native_binder(operation)
                .as_binder()
                .into_interface()
                .context(err!("Failed to create IKeystoreOperation."))?;

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

    fn delete_key(&self, key: &KeyDescriptor) -> Result<()> {
        if key.domain != Domain::BLOB {
            return Err(KsError::Km(ErrorCode::INVALID_ARGUMENT))
                .context(err!("delete_key: Key must be of Domain::BLOB"));
        }

        let key_blob = key
            .blob
            .as_ref()
            .ok_or(KsError::Km(ErrorCode::INVALID_ARGUMENT))
            .context(err!("delete_key: No key blob specified"))?;

        // check_key_permission(KeyPerm::Delete, key, &None)
        //     .context(err!("delete_key: Checking delete permissions"))?;

        let km_dev = self.get_keymint_wrapper();
        {
            let _wp =
                self.watch("KeystoreSecuritylevel::delete_key: calling IKeyMintDevice::deleteKey");
            map_binder_status(km_dev.deleteKey(key_blob)).context(err!("keymint device deleteKey"))
        }
    }
}

impl Interface for KeystoreSecurityLevel {}

impl IKeystoreSecurityLevel for KeystoreSecurityLevel {
    fn createOperation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::createOperation");
        Ok(self
            .create_operation(None, key, operation_parameters, forced)
            .map_err(into_logged_binder)?)
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
        let result = self.generate_key(None, key, attestation_key, params, flags, entropy);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "generateKey: calling uid: {}, result: {:02x?}",
            CallingContext::default().uid,
            result
        );
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
        let result = self.import_key(None, key, attestation_key, params, flags, key_data);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "importKey: calling uid: {}, result: {:?}",
            CallingContext::default().uid,
            result
        );
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
        let result =
            self.import_wrapped_key(None, key, wrapping_key, masking_key, params, authenticators);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "importWrappedKey: calling uid: {}, result: {:?}",
            CallingContext::default().uid,
            result
        );
        result.map_err(into_logged_binder)
    }
    fn convertStorageKeyToEphemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse, Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::convertStorageKeyToEphemeral");
        self.convert_storage_key_to_ephemeral(storage_key)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = self.watch("IKeystoreSecurityLevel::deleteKey");
        let result = self.delete_key(key);
        debug!(
            "deleteKey: calling uid: {}, result: {:?}",
            CallingContext::default().uid,
            result
        );
        result.map_err(into_logged_binder)
    }
}

impl IOhMySecurityLevel for KeystoreSecurityLevel {
    fn createOperation(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse, Status> {
        let _wp = self.watch("IOhMySecurityLevel::createOperation");
        Ok(self
            .create_operation(ctx, key, operation_parameters, forced)
            .map_err(into_logged_binder)?)
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
        // Duration is set to 5 seconds, because generateKey - especially for RSA keys, takes more
        // time than other operations
        let _wp = self.watch_millis("IOhMySecurityLevel::generateKey", 5000);
        let result = self.generate_key(ctx, key, attestation_key, params, flags, entropy);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "generateKey: calling uid: {}, result: {:02x?}",
            ctx.is_some()
                .then(|| ctx.unwrap().callingUid)
                .unwrap_or(CallingContext::default().uid.into()),
            result
        );
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
        let _wp = self.watch("IOhMySecurityLevel::importKey");
        let result = self.import_key(ctx, key, attestation_key, params, flags, key_data);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "importKey: calling uid: {}, result: {:?}",
            ctx.is_some()
                .then(|| ctx.unwrap().callingUid)
                .unwrap_or(CallingContext::default().uid.into()),
            result
        );
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
        let _wp = self.watch("IOhMySecurityLevel::importWrappedKey");
        let result =
            self.import_wrapped_key(ctx, key, wrapping_key, masking_key, params, authenticators);
        log_key_creation_event_stats(self.security_level, params, &result);
        debug!(
            "importWrappedKey: calling uid: {}, result: {:?}",
            ctx.is_some()
                .then(|| ctx.unwrap().callingUid)
                .unwrap_or(CallingContext::default().uid.into()),
            result
        );
        result.map_err(into_logged_binder)
    }
    fn convertStorageKeyToEphemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse, Status> {
        let _wp = self.watch("IOhMySecurityLevel::convertStorageKeyToEphemeral");
        self.convert_storage_key_to_ephemeral(storage_key)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = self.watch("IOhMySecurityLevel::deleteKey");
        let result = self.delete_key(key);
        debug!(
            "deleteKey: calling uid: {}, result: {:?}",
            CallingContext::default().uid,
            result
        );
        result.map_err(into_logged_binder)
    }
}
