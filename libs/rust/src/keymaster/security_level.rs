use std::time::SystemTime;

use crate::{
    android::{
        hardware::security::keymint::{
            Algorithm::Algorithm, AttestationKey::AttestationKey, ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag
        },
        system::keystore2::{
            Domain::Domain, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
            ResponseCode::ResponseCode,
        },
    },
    err,
    global::{DB, SUPER_KEY, UNDEFINED_NOT_AFTER},
    keymaster::{
        attestation_key_utils::{AttestationKeyInfo, get_attest_key_info},
        db::{
            BlobInfo, BlobMetaEntry, CertificateInfo, DateTime, DateTimeError, KeyIdGuard,
            KeyMetaData, KeyMetaEntry, KeyType, SubComponentType, Uuid,
        },
        error::{KsError, map_binder_status},
        keymint_device::{KeyMintDevice, KeyMintWrapper, get_keymint_wrapper},
        super_key::{KeyBlob, SuperKeyManager},
        utils::{key_characteristics_to_internal, key_parameters_to_authorizations, log_params},
    },
};

use crate::keymaster::key_parameter::KeyParameter as KsKeyParam;
use crate::keymaster::key_parameter::KeyParameterValue as KsKeyParamValue;

use crate::watchdog as wd;

use anyhow::{anyhow, Context, Result};
use kmr_ta::HardwareInfo;
use rsbinder::{Strong, thread_state::CallingContext};

pub struct KeystoreSecurityLevel<'a> {
    security_level: SecurityLevel,
    hw_info: HardwareInfo,
    km_uuid: Uuid,
    keymint: &'a dyn IKeyMintDevice,
}

impl<'a> KeystoreSecurityLevel<'a> {
    pub fn new(
        security_level: SecurityLevel,
        hw_info: HardwareInfo,
        km_uuid: Uuid,
    ) -> Self {
        KeystoreSecurityLevel {
            security_level,
            hw_info,
            km_uuid,
            keymint: get_keymint_wrapper(security_level).unwrap(),
        }
    }

    fn watch_millis(&self, id: &'static str, millis: u64) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, millis, sec_level)
    }

    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, sec_level)
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
        _key: &KeyDescriptor,
    ) -> Result<Vec<KeyParameter>> {
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
            match crate::plat::utils::get_aaid(uid) {
                Ok(aaid_ok) => {
                    result.push(KeyParameter {
                        tag: Tag::ATTESTATION_APPLICATION_ID,
                        value: KeyParameterValue::Blob(aaid_ok.into_bytes()),
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
            get_keymint_wrapper(self.security_level).unwrap(),
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
        let calling_context = CallingContext::default();
        let calling_uid = calling_context.uid;

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
                        let result = self.keymint.generateKey(&params, attest_key.as_ref());
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
                self.keymint.generateKey(&params, None)
            }
            .context(err!(
                "While generating without a provided \
                 attestation key and params: {:?}.",
                log_params(&params)
            )),
            _ => unreachable!(), // Other branches of get_attest_key_info are not possible here.
        }?;

        let user_id = crate::plat::utils::uid_to_android_user(calling_uid);
        self.store_new_key(key, creation_result, user_id, Some(flags))
            .context(err!())
    }
}
