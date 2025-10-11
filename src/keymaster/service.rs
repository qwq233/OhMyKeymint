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

//! This crate implement the core Keystore 2.0 service API as defined by the Keystore 2.0
//! AIDL spec.

use std::collections::HashMap;

use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
use crate::android::system::keystore2::IKeystoreSecurityLevel::BnKeystoreSecurityLevel;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::err;
use crate::global::ENCODED_MODULE_INFO;
use crate::keymaster::apex::ApexModuleInfo;
use crate::keymaster::database::utils::{count_key_entries, list_key_entries};
use crate::keymaster::db::KEYSTORE_UUID;
use crate::keymaster::db::{KeyEntryLoadBits, KeyType, SubComponentType};
use crate::keymaster::error::{into_logged_binder, KsError as Error};
use crate::keymaster::permission::KeyPermSet;
use crate::keymaster::security_level::KeystoreSecurityLevel;
use crate::keymaster::utils::key_parameters_to_authorizations;
use crate::plat::utils::multiuser_get_user_id;
use crate::watchdog as wd;
use crate::{
    global::{DB, SUPER_KEY},
    keymaster::db::Uuid,
};

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::BnKeystoreService, IKeystoreService::IKeystoreService,
    KeyDescriptor::KeyDescriptor, KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata,
};
use anyhow::{Context, Ok, Result};
use der::Encode;
use der::asn1::SetOfVec;
use kmr_crypto_boring::sha256::BoringSha256;
use kmr_common::crypto::Sha256;
use log::debug;
use rsbinder::thread_state::CallingContext;
use rsbinder::{Status, Strong};


fn encode_module_info(module_info: Vec<ApexModuleInfo>) -> Result<Vec<u8>, der::Error> {
    SetOfVec::<ApexModuleInfo>::from_iter(module_info.into_iter())?.to_der()
}

/// Implementation of the IKeystoreService.
#[derive(Default)]
pub struct KeystoreService {
    i_sec_level_by_uuid: HashMap<Uuid, Strong<dyn IKeystoreSecurityLevel>>,
    uuid_by_sec_level: HashMap<SecurityLevel, Uuid>,
}

impl KeystoreService {
    /// Create a new instance of the Keystore 2.0 service.
    pub fn new_native_binder(
    ) -> Result<Strong<dyn IKeystoreService>> {
        let mut result: Self = Default::default();

        let (dev, uuid) = match KeystoreSecurityLevel::new(
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ) {
            Result::Ok(v) => v,
            Err(e) => {
                log::error!("Failed to construct mandatory security level TEE: {e:?}");
                log::error!("Does the device have a /default Keymaster or KeyMint instance?");
                return Err(e.context(err!("Trying to construct mandatory security level TEE")));
            }
        };

        let dev: Strong<dyn IKeystoreSecurityLevel> = BnKeystoreSecurityLevel::new_binder(dev);

        result.i_sec_level_by_uuid.insert(uuid, dev);
        result
            .uuid_by_sec_level
            .insert(SecurityLevel::TRUSTED_ENVIRONMENT, uuid);

        // Strongbox is optional, so we ignore errors and turn the result into an Option.
        if let Result::Ok((dev, uuid)) =
            KeystoreSecurityLevel::new(SecurityLevel::STRONGBOX)
        {
            let dev: Strong<dyn IKeystoreSecurityLevel> = BnKeystoreSecurityLevel::new_binder(dev);
            result.i_sec_level_by_uuid.insert(uuid, dev);
            result
                .uuid_by_sec_level
                .insert(SecurityLevel::STRONGBOX, uuid);
        }

        Ok(BnKeystoreService::new_binder(
            result
        ))
    }

    fn uuid_to_sec_level(&self, uuid: &Uuid) -> SecurityLevel {
        self.uuid_by_sec_level
            .iter()
            .find(|(_, v)| **v == *uuid)
            .map(|(s, _)| *s)
            .unwrap_or(SecurityLevel::SOFTWARE)
    }

    fn get_i_sec_level_by_uuid(&self, uuid: &Uuid) -> Result<Strong<dyn IKeystoreSecurityLevel>> {
        if let Some(dev) = self.i_sec_level_by_uuid.get(uuid) {
            Ok(dev.clone())
        } else {
            Err(Error::sys()).context(err!("KeyMint instance for key not found."))
        }
    }

    fn get_security_level(
        &self,
        sec_level: SecurityLevel,
    ) -> Result<Strong<dyn IKeystoreSecurityLevel>> {
        if let Some(dev) = self
            .uuid_by_sec_level
            .get(&sec_level)
            .and_then(|uuid| self.i_sec_level_by_uuid.get(uuid))
        {
            Ok(dev.clone())
        } else {
            Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("No such security level."))
        }
    }

    fn get_key_entry(&self, key: &KeyDescriptor) -> Result<KeyEntryResponse> {
        let caller_uid = CallingContext::default().uid;

        let super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        let (key_id_guard, mut key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    key,
                    KeyType::Client,
                    KeyEntryLoadBits::PUBLIC,
                    caller_uid,
                )
            })
            .context(err!("while trying to load key info."))?;

        let i_sec_level = if !key_entry.pure_cert() {
            Some(
                self.get_i_sec_level_by_uuid(key_entry.km_uuid())
                    .context(err!("Trying to get security level proxy."))?,
            )
        } else {
            None
        };

        Ok(KeyEntryResponse {
            iSecurityLevel: i_sec_level,
            metadata: KeyMetadata {
                key: KeyDescriptor {
                    domain: Domain::KEY_ID,
                    nspace: key_id_guard.id(),
                    ..Default::default()
                },
                keySecurityLevel: self.uuid_to_sec_level(key_entry.km_uuid()),
                certificate: key_entry.take_cert(),
                certificateChain: key_entry.take_cert_chain(),
                modificationTimeMs: key_entry
                    .metadata()
                    .creation_date()
                    .map(|d| d.to_millis_epoch())
                    .ok_or(Error::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context(err!("Trying to get creation date."))?,
                authorizations: key_parameters_to_authorizations(key_entry.into_key_parameters()),
            },
        })
    }

    fn update_subcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<()> {
        let caller_uid = CallingContext::default().uid;
        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        DB.with::<_, Result<()>>(|db| {
            let entry = match db.borrow_mut().load_key_entry(
                key,
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                caller_uid,
            ) {
                Err(e) => match e.root_cause().downcast_ref::<Error>() {
                    Some(Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                    _ => Err(e),
                },
                Result::Ok(v) => Ok(Some(v)),
            }?;

            let mut db = db.borrow_mut();
            if let Some((key_id_guard, _key_entry)) = entry {
                db.set_blob(&key_id_guard, SubComponentType::CERT, public_cert, None)
                    .context(err!("Failed to update cert subcomponent."))?;

                db.set_blob(
                    &key_id_guard,
                    SubComponentType::CERT_CHAIN,
                    certificate_chain,
                    None,
                )
                .context(err!("Failed to update cert chain subcomponent."))?;
                return Ok(());
            }

            // If we reach this point we have to check the special condition where a certificate
            // entry may be made.
            if !(public_cert.is_none() && certificate_chain.is_some()) {
                return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                    .context(err!("No key to update."));
            }

            // So we know that we have a certificate chain and no public cert.
            // Now check that we have everything we need to make a new certificate entry.
            let key = match (key.domain, &key.alias) {
                (Domain::APP, Some(ref alias)) => KeyDescriptor {
                    domain: Domain::APP,
                    nspace: CallingContext::default().uid as i64,
                    alias: Some(alias.clone()),
                    blob: None,
                },
                (Domain::SELINUX, Some(_)) => key.clone(),
                _ => {
                    return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                        "Domain must be APP or SELINUX to insert a certificate."
                    ))
                }
            };

            // Security critical: This must return on failure. Do not remove the `?`;
            // check_key_permission(KeyPerm::Rebind, &key, &None)
            //     .context(err!("Caller does not have permission to insert this certificate."))?;

            db.store_new_certificate(
                &key,
                KeyType::Client,
                certificate_chain.unwrap(),
                &KEYSTORE_UUID,
            )
            .context(err!("Failed to insert new certificate."))?;
            Ok(())
        })
        .context(err!())
    }

    fn get_key_descriptor_for_lookup(
        &self,
        domain: Domain,
        namespace: i64,
    ) -> Result<KeyDescriptor> {
        let k = match domain {
            Domain::APP => KeyDescriptor {
                domain,
                nspace: CallingContext::default().uid as u64 as i64,
                ..Default::default()
            },
            Domain::SELINUX => KeyDescriptor {
                domain,
                nspace: namespace,
                ..Default::default()
            },
            _ => {
                return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                    "List entries is only supported for Domain::APP and Domain::SELINUX."
                ))
            }
        };

        // First we check if the caller has the info permission for the selected domain/namespace.
        // By default we use the calling uid as namespace if domain is Domain::APP.
        // If the first check fails we check if the caller has the list permission allowing to list
        // any namespace. In that case we also adjust the queried namespace if a specific uid was
        // selected.
        // if let Err(e) = check_key_permission(KeyPerm::GetInfo, &k, &None) {
        //     if let Some(selinux::Error::PermissionDenied) =
        //         e.root_cause().downcast_ref::<selinux::Error>()
        //     {
        //         check_keystore_permission(KeystorePerm::List)
        //             .context(err!("While checking keystore permission."))?;
        //         if namespace != -1 {
        //             k.nspace = namespace;
        //         }
        //     } else {
        //         return Err(e).context(err!("While checking key permission."))?;
        //     }
        // }
        Ok(k)
    }

    fn list_entries(&self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>> {
        let k = self.get_key_descriptor_for_lookup(domain, namespace)?;

        DB.with(|db| list_key_entries(&mut db.borrow_mut(), k.domain, k.nspace, None))
    }

    fn count_num_entries(&self, domain: Domain, namespace: i64) -> Result<i32> {
        let k = self.get_key_descriptor_for_lookup(domain, namespace)?;

        DB.with(|db| count_key_entries(&mut db.borrow_mut(), k.domain, k.nspace))
    }

    fn get_supplementary_attestation_info(&self, tag: Tag) -> Result<Vec<u8>> {
        match tag {
            Tag::MODULE_HASH => {
                let info = ENCODED_MODULE_INFO.get_or_try_init(|| -> Result<Vec<u8>, anyhow::Error> {
                    let apex_info = crate::plat::utils::get_apex_module_info()?;

                    let encoding = encode_module_info(apex_info)
                        .map_err(|_| anyhow::anyhow!("Failed to encode module info."))?;

                    let sha256 = BoringSha256 {};

                    let hash = sha256.hash(&encoding).map_err(|_| anyhow::anyhow!("Failed to hash module info."))?;

                    Ok(hash.to_vec())
                })?;

                Ok(info.clone())
            }
            _ => Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                "Tag {tag:?} not supported for getSupplementaryAttestationInfo."
            )),
        }
    }

    fn list_entries_batched(
        &self,
        domain: Domain,
        namespace: i64,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>> {
        let k = self.get_key_descriptor_for_lookup(domain, namespace)?;
        DB.with(|db| list_key_entries(&mut db.borrow_mut(), k.domain, k.nspace, start_past_alias))
    }

    fn delete_key(&self, key: &KeyDescriptor) -> Result<()> {
        let caller_uid = CallingContext::default().uid;
        let super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        DB.with(|db| db.borrow_mut().unbind_key(key, KeyType::Client, caller_uid))
            .context(err!("Trying to unbind the key."))?;
        Ok(())
    }

    fn grant(
        &self,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: KeyPermSet,
    ) -> Result<KeyDescriptor> {
        let caller_uid = CallingContext::default().uid;
        let super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        DB.with(|db| {
            db.borrow_mut()
                .grant(key, caller_uid, grantee_uid as u32, access_vector)
        })
        .context(err!("KeystoreService::grant."))
    }

    fn ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> Result<()> {
        DB.with(|db| {
            db.borrow_mut()
                .ungrant(key, CallingContext::default().uid, grantee_uid as u32)
        })
        .context(err!("KeystoreService::ungrant."))
    }
}

impl rsbinder::Interface for KeystoreService {}

// Implementation of IKeystoreService. See AIDL spec at
// system/security/keystore2/binder/android/security/keystore2/IKeystoreService.aidl
impl IKeystoreService for KeystoreService {
    fn getSecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Strong<dyn IKeystoreSecurityLevel>, Status> {
        let _wp = wd::watch_millis_with("IKeystoreService::getSecurityLevel", 500, security_level);
        self.get_security_level(security_level)
            .map_err(into_logged_binder)
    }
    fn getKeyEntry(&self, key: &KeyDescriptor) -> Result<KeyEntryResponse, Status> {
        let _wp = wd::watch("IKeystoreService::get_key_entry");
        self.get_key_entry(key).map_err(into_logged_binder)
    }
    fn updateSubcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::updateSubcomponent");
        self.update_subcomponent(key, public_cert, certificate_chain)
            .map_err(into_logged_binder)
    }
    fn listEntries(&self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IKeystoreService::listEntries");
        self.list_entries(domain, namespace)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::deleteKey");
        let result = self.delete_key(key);
        debug!(
            "deleteKey: key={:?}, uid={}",
            key,
            CallingContext::default().uid
        );
        result.map_err(into_logged_binder)
    }
    fn grant(
        &self,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: i32,
    ) -> Result<KeyDescriptor, Status> {
        let _wp = wd::watch("IKeystoreService::grant");
        self.grant(key, grantee_uid, access_vector.into())
            .map_err(into_logged_binder)
    }
    fn ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::ungrant");
        self.ungrant(key, grantee_uid).map_err(into_logged_binder)
    }
    fn listEntriesBatched(
        &self,
        domain: Domain,
        namespace: i64,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IKeystoreService::listEntriesBatched");
        self.list_entries_batched(domain, namespace, start_past_alias)
            .map_err(into_logged_binder)
    }

    fn getNumberOfEntries(&self, domain: Domain, namespace: i64) -> Result<i32, Status> {
        let _wp = wd::watch("IKeystoreService::getNumberOfEntries");
        self.count_num_entries(domain, namespace)
            .map_err(into_logged_binder)
    }

    fn getSupplementaryAttestationInfo(&self, tag: Tag) -> Result<Vec<u8>, Status> {
        let _wp = wd::watch("IKeystoreService::getSupplementaryAttestationInfo");
        self.get_supplementary_attestation_info(tag).map_err(|e| {
            log::error!("Failed to get supplementary attestation info: {}", e);
            // pretend as it's not supported
            Status::from(rsbinder::StatusCode::UnknownTransaction)
        })
    }
}
