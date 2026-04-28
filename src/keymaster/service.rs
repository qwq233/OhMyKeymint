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
use std::sync::RwLock;

use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::err;
use crate::keybox;
use crate::keymaster::database::utils::{count_key_entries, list_key_entries};
use crate::keymaster::db::KEYSTORE_UUID;
use crate::keymaster::db::{KeyEntryLoadBits, KeyType, SubComponentType};
use crate::keymaster::error::{into_logged_binder, KsError as Error};
use crate::keymaster::id_rotation::IdRotationState;
use crate::keymaster::permission::{
    check_grant_permission, check_key_permission, check_keystore_permission, KeyPerm, KeyPermSet,
    KeystorePerm,
};
use crate::keymaster::security_level::KeystoreSecurityLevel;
use crate::keymaster::utils::key_parameters_to_authorizations;
use crate::plat::utils::multiuser_get_user_id;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMySecurityLevel::IOhMySecurityLevel;
use crate::watchdog as wd;
use crate::{
    global::{DB, SUPER_KEY},
    keymaster::db::Uuid,
};

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
    KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata,
};
use anyhow::{Context, Result};
use log::debug;
use rsbinder::thread_state::CallingContext;
use rsbinder::{Status, Strong};

/// Implementation of the IKeystoreService.
pub struct KeystoreService {
    security_levels: RwLock<SecurityLevels>,
    id_rotation_state: IdRotationState,
}

impl Default for KeystoreService {
    fn default() -> Self {
        Self {
            security_levels: RwLock::new(Default::default()),
            id_rotation_state: IdRotationState::new_default(),
        }
    }
}

#[derive(Default, Clone)]
struct SecurityLevels {
    i_sec_level_by_uuid: HashMap<Uuid, Strong<dyn IKeystoreSecurityLevel>>,
    i_osec_level_by_uuid: HashMap<Uuid, Strong<dyn IOhMySecurityLevel>>,
    uuid_by_sec_level: HashMap<SecurityLevel, Uuid>,
}

impl KeystoreService {
    /// Create a new instance of the Keystore 2.0 service.
    pub fn new_native_binder() -> Result<KeystoreService> {
        let result: Self = Default::default();

        match result.register_security_level(SecurityLevel::TRUSTED_ENVIRONMENT) {
            Result::Ok(v) => v,
            Err(e) => {
                log::error!("Failed to construct mandatory security level TEE: {e:?}");
                log::error!("Does the device have a /default Keymaster or KeyMint instance?");
                return Err(e.context(err!("Trying to construct mandatory security level TEE")));
            }
        };

        match result.register_security_level(SecurityLevel::STRONGBOX) {
            Result::Ok(v) => v,
            Err(e) => {
                log::error!("Failed to construct mandatory security level StrongBox: {e:?}");
                log::error!("But we ignore this error because StrongBox is optional.");
            }
        };

        Ok(result)
    }

    fn ensure_security_levels_current(&self) -> Result<()> {
        let tee_uuid = Uuid::from(SecurityLevel::TRUSTED_ENVIRONMENT);
        let refresh_tee = {
            let security_levels = self.security_levels.read().unwrap();
            security_levels
                .uuid_by_sec_level
                .get(&SecurityLevel::TRUSTED_ENVIRONMENT)
                .copied()
                != Some(tee_uuid)
        };

        if refresh_tee {
            self.register_security_level(SecurityLevel::TRUSTED_ENVIRONMENT)
                .context(err!("refreshing TEE security level after keybox change"))?;
        }

        let strongbox_uuid = Uuid::from(SecurityLevel::STRONGBOX);
        let refresh_strongbox = {
            let security_levels = self.security_levels.read().unwrap();
            security_levels
                .uuid_by_sec_level
                .get(&SecurityLevel::STRONGBOX)
                .copied()
                != Some(strongbox_uuid)
        };

        if refresh_strongbox {
            if let Err(error) = self.register_security_level(SecurityLevel::STRONGBOX) {
                log::warn!(
                    "Failed to refresh optional StrongBox security level after keybox change: {error:#}"
                );
            }
        }

        Ok(())
    }

    fn register_security_level(&self, sec_level: SecurityLevel) -> Result<()> {
        debug!("Registering security level {sec_level:?}");
        let uuid = Uuid::from(sec_level);

        // Check if we need to terminate old UUID and do it before acquiring write lock
        let old_uuid_to_terminate = {
            let security_levels = self.security_levels.read().unwrap();
            if let Some(&cur_uuid) = security_levels.uuid_by_sec_level.get(&sec_level) {
                if uuid != cur_uuid {
                    Some(cur_uuid)
                } else {
                    None
                }
            } else {
                None
            }
        }; // Release read lock

        if let Some(cur_uuid) = old_uuid_to_terminate {
            log::warn!("Security level {sec_level:?} was registered with a different UUID {cur_uuid:?}, overwriting with {uuid:?}.");
            log::warn!("Terminating the old UUID from database.");

            DB.with(|db| {
                log::warn!("Terminating old UUID {cur_uuid:?} from database.");
                db.borrow_mut().terminate_uuid(&cur_uuid).map_err(|e| {
                    anyhow::anyhow!(err!("Failed to terminate old UUID {cur_uuid:?}: {e:?}"))
                })
            })?;
        }

        // Create security level instances BEFORE acquiring write lock to avoid holding lock during hardware calls
        debug!("Creating security level instance (may involve hardware calls)");
        let (i_sec_level, i_osec_level) = match KeystoreSecurityLevel::new_binders(
            sec_level,
            uuid,
            self.id_rotation_state.clone(),
        ) {
            Result::Ok(v) => v,
            Err(e) => {
                log::error!("Failed to construct security level {sec_level:?}: {e:?}");
                return Err(e.context(err!("Trying to construct security level {sec_level:?}")));
            }
        };

        // Now acquire write lock only for the minimal time needed to update the maps
        debug!("Obtaining exclusive lock to register security level");
        let mut security_levels = self.security_levels.write().unwrap();
        debug!("Obtained exclusive lock to register security level");

        if security_levels.uuid_by_sec_level.contains_key(&sec_level) {
            // Unregister if already registered
            let cur_uuid = security_levels
                .uuid_by_sec_level
                .get(&sec_level)
                .cloned()
                .unwrap();
            security_levels.i_sec_level_by_uuid.remove(&cur_uuid);
            security_levels.i_osec_level_by_uuid.remove(&cur_uuid);
            security_levels.uuid_by_sec_level.remove(&sec_level);
            log::warn!("Security level {sec_level:?} was already registered, overwriting.");
        }

        security_levels
            .i_sec_level_by_uuid
            .insert(uuid, i_sec_level);
        security_levels
            .i_osec_level_by_uuid
            .insert(uuid, i_osec_level);
        security_levels.uuid_by_sec_level.insert(sec_level, uuid);

        Ok(())
    }

    fn uuid_to_sec_level(&self, uuid: &Uuid) -> SecurityLevel {
        self.security_levels
            .read()
            .unwrap()
            .uuid_by_sec_level
            .iter()
            .find(|(_, v)| **v == *uuid)
            .map(|(s, _)| *s)
            .unwrap_or(SecurityLevel::SOFTWARE)
    }

    fn get_i_sec_level_by_uuid(&self, uuid: &Uuid) -> Result<Strong<dyn IKeystoreSecurityLevel>> {
        let security_levels = self.security_levels.read().unwrap();
        if let Some(dev) = security_levels.i_sec_level_by_uuid.get(uuid) {
            Ok(dev.clone())
        } else {
            Err(Error::sys()).context(err!("KeyMint instance for key not found."))
        }
    }

    fn get_security_level(
        &self,
        _ctx: Option<&CallerInfo>, // reserved for future use
        sec_level: SecurityLevel,
    ) -> Result<Strong<dyn IKeystoreSecurityLevel>> {
        self.ensure_security_levels_current()?;
        let security_levels = self.security_levels.read().unwrap();
        if let Some(uuid) = security_levels.uuid_by_sec_level.get(&sec_level) {
            if let Some(dev) = security_levels.i_sec_level_by_uuid.get(uuid) {
                Ok(dev.clone())
            } else {
                Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                    .context(err!("No such security level."))
            }
        } else {
            Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("No such security level."))
        }
    }

    fn get_iohmy_security_level(
        &self,
        _ctx: Option<&CallerInfo>, // reserved for future use
        sec_level: SecurityLevel,
    ) -> Result<Strong<dyn IOhMySecurityLevel>> {
        self.ensure_security_levels_current()?;
        let security_levels = self.security_levels.read().unwrap();
        if let Some(dev) = security_levels
            .uuid_by_sec_level
            .get(&sec_level)
            .and_then(|uuid| security_levels.i_osec_level_by_uuid.get(uuid))
        {
            Ok(dev.clone())
        } else {
            Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                .context(err!("No such security level."))
        }
    }

    pub fn get_key_entry(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
    ) -> Result<KeyEntryResponse> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx);

        debug!("get_key_entry: key={:?}, uid={}", key, caller_uid);

        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        let resolved = DB
            .with(|db| {
                db.borrow_mut()
                    .resolve_key_permission(key, KeyType::Client, caller_uid)
            })
            .context(err!("while trying to resolve key permissions."))?;
        check_key_permission(
            KeyPerm::GetInfo,
            &resolved.descriptor,
            resolved.access_vector.as_ref(),
            ctx,
        )
        .context(err!("Caller does not have permission to inspect this key."))?;

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
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<()> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx);
        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));
        let existing_key = match DB.with(|db| {
            db.borrow_mut()
                .resolve_key_permission(key, KeyType::Client, caller_uid)
        }) {
            Ok(resolved) => Some(resolved),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Rc(ResponseCode::KEY_NOT_FOUND)) => None,
                _ => return Err(e).context(err!("Failed to resolve key permissions.")),
            },
        };

        if let Some(resolved) = existing_key {
            check_key_permission(
                KeyPerm::Update,
                &resolved.descriptor,
                resolved.access_vector.as_ref(),
                ctx,
            )
            .context(err!("Caller does not have permission to update this key."))?;

            return DB
                .with::<_, Result<()>>(|db| {
                    let (key_id_guard, _) = db.borrow_mut().load_key_entry(
                        key,
                        KeyType::Client,
                        KeyEntryLoadBits::NONE,
                        caller_uid,
                    )?;
                    let mut db = db.borrow_mut();
                    db.set_blob(&key_id_guard, SubComponentType::CERT, public_cert, None)
                        .context(err!("Failed to update cert subcomponent."))?;
                    db.set_blob(
                        &key_id_guard,
                        SubComponentType::CERT_CHAIN,
                        certificate_chain,
                        None,
                    )
                    .context(err!("Failed to update cert chain subcomponent."))?;
                    Ok(())
                })
                .context(err!());
        }

        if !(public_cert.is_none() && certificate_chain.is_some()) {
            return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND)).context(err!("No key to update."));
        }

        let key = match (key.domain, &key.alias) {
            (Domain::APP, Some(ref alias)) => KeyDescriptor {
                domain: Domain::APP,
                nspace: caller_uid as i64,
                alias: Some(alias.clone()),
                blob: None,
            },
            (Domain::SELINUX, Some(_)) => key.clone(),
            _ => {
                return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                    "Domain must be APP or SELINUX to insert a certificate."
                ));
            }
        };

        check_key_permission(KeyPerm::Rebind, &key, None, ctx).context(err!(
            "Caller does not have permission to insert this certificate."
        ))?;

        DB.with::<_, Result<()>>(|db| {
            db.borrow_mut().store_new_certificate(
                &key,
                KeyType::Client,
                certificate_chain.unwrap(),
                &KEYSTORE_UUID,
            )?;
            Ok(())
        })
        .context(err!("Failed to insert new certificate."))
    }

    fn get_key_descriptor_for_lookup(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
    ) -> Result<KeyDescriptor> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx) as i64;

        let mut k = match domain {
            Domain::APP => KeyDescriptor {
                domain,
                nspace: caller_uid,
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
        if let Err(e) = check_key_permission(KeyPerm::GetInfo, &k, None, ctx) {
            if is_permission_denied(&e) {
                check_keystore_permission(KeystorePerm::List, ctx)
                    .context(err!("While checking keystore permission."))?;
                if namespace != -1 {
                    k.nspace = namespace;
                }
            } else {
                return Err(e).context(err!("While checking key permission."));
            }
        }
        Ok(k)
    }

    fn list_entries(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
    ) -> Result<Vec<KeyDescriptor>> {
        let k = self.get_key_descriptor_for_lookup(ctx, domain, namespace)?;

        DB.with(|db| list_key_entries(&mut db.borrow_mut(), k.domain, k.nspace, None))
    }

    fn count_num_entries(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
    ) -> Result<i32> {
        let k = self.get_key_descriptor_for_lookup(ctx, domain, namespace)?;

        DB.with(|db| count_key_entries(&mut db.borrow_mut(), k.domain, k.nspace))
    }

    fn get_supplementary_attestation_info(&self, tag: Tag) -> Result<Vec<u8>> {
        match tag {
            Tag::MODULE_HASH => crate::global::module_info_bundle()
                .map(|bundle| bundle.encoded_der.clone())
                .ok_or_else(|| Error::Rc(ResponseCode::INFO_NOT_AVAILABLE))
                .context(err!("MODULE_HASH supplementary info is unavailable")),
            _ => Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                "Tag {tag:?} not supported for getSupplementaryAttestationInfo."
            )),
        }
    }

    fn list_entries_batched(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>> {
        let k = self.get_key_descriptor_for_lookup(ctx, domain, namespace)?;
        DB.with(|db| list_key_entries(&mut db.borrow_mut(), k.domain, k.nspace, start_past_alias))
    }

    fn delete_key(&self, ctx: Option<&CallerInfo>, key: &KeyDescriptor) -> Result<()> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx);
        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        let resolved = DB
            .with(|db| {
                db.borrow_mut()
                    .resolve_key_permission(key, KeyType::Client, caller_uid)
            })
            .context(err!("Trying to resolve key permissions."))?;
        check_key_permission(
            KeyPerm::Delete,
            &resolved.descriptor,
            resolved.access_vector.as_ref(),
            ctx,
        )
        .context(err!("Caller does not have permission to delete this key."))?;

        DB.with(|db| db.borrow_mut().unbind_key(key, KeyType::Client, caller_uid))
            .context(err!("Trying to unbind the key."))?;
        Ok(())
    }

    fn grant(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: KeyPermSet,
    ) -> Result<KeyDescriptor> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx);
        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_after_first_unlock_key_by_user_id(multiuser_get_user_id(caller_uid));

        let resolved = DB
            .with(|db| {
                db.borrow_mut()
                    .resolve_key_permission(key, KeyType::Client, caller_uid)
            })
            .context(err!("KeystoreService::grant: resolving permissions"))?;
        check_grant_permission(access_vector, &resolved.descriptor, ctx)
            .context(err!("KeystoreService::grant: permission denied"))?;

        DB.with(|db| {
            db.borrow_mut()
                .grant(key, caller_uid, grantee_uid as u32, access_vector)
        })
        .context(err!("KeystoreService::grant."))
    }

    fn ungrant(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        grantee_uid: i32,
    ) -> Result<()> {
        self.ensure_security_levels_current()?;
        let caller_uid = calling_uid(ctx);
        let resolved = DB
            .with(|db| {
                db.borrow_mut()
                    .resolve_key_permission(key, KeyType::Client, caller_uid)
            })
            .context(err!("KeystoreService::ungrant: resolving permissions"))?;
        check_key_permission(
            KeyPerm::Grant,
            &resolved.descriptor,
            resolved.access_vector.as_ref(),
            ctx,
        )
        .context(err!("KeystoreService::ungrant: permission denied"))?;
        DB.with(|db| db.borrow_mut().ungrant(key, caller_uid, grantee_uid as u32))
            .context(err!("KeystoreService::ungrant."))
    }

    fn enforce_keybox_admin(&self) -> Result<()> {
        let calling_uid: i64 = CallingContext::default().uid.into();
        match calling_uid {
            0 | 1000 | 1017 => Ok(()),
            uid => Err(Error::perm()).context(err!(
                "keybox update requires root/system/keystore caller, got uid={uid}"
            )),
        }
    }
}

fn calling_uid(ctx: Option<&CallerInfo>) -> u32 {
    ctx.map(|ctx| ctx.callingUid)
        .unwrap_or(CallingContext::default().uid.into()) as u32
}

fn is_permission_denied(error: &anyhow::Error) -> bool {
    matches!(
        error.root_cause().downcast_ref::<Error>(),
        Some(Error::Rc(ResponseCode::PERMISSION_DENIED))
    )
}

impl rsbinder::Interface for KeystoreService {}

// Implementation of IKeystoreService. See AIDL spec at
// system/security/keystore2/binder/android/security/keystore2/IKeystoreService.aidl
#[allow(non_snake_case)]
impl IKeystoreService for KeystoreService {
    fn getSecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Strong<dyn IKeystoreSecurityLevel>, Status> {
        let _wp = wd::watch_millis_with("IKeystoreService::getSecurityLevel", 500, security_level);
        self.get_security_level(None, security_level)
            .map_err(into_logged_binder)
    }
    fn getKeyEntry(&self, key: &KeyDescriptor) -> Result<KeyEntryResponse, Status> {
        let _wp = wd::watch("IKeystoreService::get_key_entry");
        self.get_key_entry(None, key).map_err(into_logged_binder)
    }
    fn updateSubcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::updateSubcomponent");
        self.update_subcomponent(None, key, public_cert, certificate_chain)
            .map_err(into_logged_binder)
    }
    fn listEntries(&self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IKeystoreService::listEntries");
        self.list_entries(None, domain, namespace)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::deleteKey");
        let result = self.delete_key(None, key);
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
        self.grant(None, key, grantee_uid, access_vector.into())
            .map_err(into_logged_binder)
    }
    fn ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreService::ungrant");
        self.ungrant(None, key, grantee_uid)
            .map_err(into_logged_binder)
    }
    fn getNumberOfEntries(&self, domain: Domain, namespace: i64) -> Result<i32, Status> {
        let _wp = wd::watch("IKeystoreService::getNumberOfEntries");
        self.count_num_entries(None, domain, namespace)
            .map_err(into_logged_binder)
    }

    fn listEntriesBatched(
        &self,
        domain: Domain,
        namespace: i64,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IKeystoreService::listEntriesBatched");
        self.list_entries_batched(None, domain, namespace, start_past_alias)
            .map_err(into_logged_binder)
    }

    fn getSupplementaryAttestationInfo(&self, tag: Tag) -> Result<Vec<u8>, Status> {
        let _wp = wd::watch("IKeystoreService::getSupplementaryAttestationInfo");
        self.get_supplementary_attestation_info(tag)
            .map_err(into_logged_binder)
    }
}

impl IOhMyKsService for KeystoreService {
    fn getSecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Strong<dyn IKeystoreSecurityLevel>, Status> {
        let _wp = wd::watch_millis_with("IOhMyKsService::getSecurityLevel", 500, security_level);
        self.get_security_level(None, security_level)
            .map_err(into_logged_binder)
    }
    fn getOhMySecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Strong<dyn IOhMySecurityLevel>, Status> {
        let _wp = wd::watch_millis_with("IOhMyKsService::getSecurityLevel", 500, security_level);
        self.get_iohmy_security_level(None, security_level)
            .map_err(into_logged_binder)
    }
    fn getKeyEntry(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
    ) -> Result<KeyEntryResponse, Status> {
        let _wp = wd::watch("IOhMyKsService::get_key_entry");
        self.get_key_entry(ctx, key).map_err(into_logged_binder)
    }
    fn updateSubcomponent(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<(), Status> {
        let _wp = wd::watch("IOhMyKsService::updateSubcomponent");
        self.update_subcomponent(ctx, key, public_cert, certificate_chain)
            .map_err(into_logged_binder)
    }
    fn listEntries(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
    ) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IOhMyKsService::listEntries");
        self.list_entries(ctx, domain, namespace)
            .map_err(into_logged_binder)
    }
    fn deleteKey(&self, ctx: Option<&CallerInfo>, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = wd::watch("IOhMyKsService::deleteKey");
        let result = self.delete_key(ctx, key);
        debug!(
            "deleteKey: key={:?}, uid={}",
            key,
            ctx.is_some()
                .then(|| ctx.unwrap().callingUid)
                .unwrap_or(CallingContext::default().uid.into())
        );
        result.map_err(into_logged_binder)
    }
    fn grant(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: i32,
    ) -> Result<KeyDescriptor, Status> {
        let _wp = wd::watch("IOhMyKsService::grant");
        self.grant(ctx, key, grantee_uid, access_vector.into())
            .map_err(into_logged_binder)
    }
    fn ungrant(
        &self,
        ctx: Option<&CallerInfo>,
        key: &KeyDescriptor,
        grantee_uid: i32,
    ) -> Result<(), Status> {
        let _wp = wd::watch("IOhMyKsService::ungrant");
        self.ungrant(ctx, key, grantee_uid)
            .map_err(into_logged_binder)
    }
    fn getNumberOfEntries(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
    ) -> Result<i32, Status> {
        let _wp = wd::watch("IOhMyKsService::getNumberOfEntries");
        self.count_num_entries(ctx, domain, namespace)
            .map_err(into_logged_binder)
    }

    fn listEntriesBatched(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        namespace: i64,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>, Status> {
        let _wp = wd::watch("IOhMyKsService::listEntriesBatched");
        self.list_entries_batched(ctx, domain, namespace, start_past_alias)
            .map_err(into_logged_binder)
    }

    fn getSupplementaryAttestationInfo(&self, tag: Tag) -> Result<Vec<u8>, Status> {
        let _wp = wd::watch("IOhMyKsService::getSupplementaryAttestationInfo");
        self.get_supplementary_attestation_info(tag)
            .map_err(into_logged_binder)
    }

    fn updateEcKeybox(
        &self,
        key: &[u8],
        chain: &[crate::android::hardware::security::keymint::Certificate::Certificate],
    ) -> rsbinder::status::Result<()> {
        self.enforce_keybox_admin().map_err(into_logged_binder)?;
        let chain: Vec<kmr_wire::keymint::Certificate> = chain
            .iter()
            .map(|c| kmr_wire::keymint::Certificate {
                encoded_certificate: c.encodedCertificate.clone(),
            })
            .collect();

        keybox::update_ec_keybox(key.to_vec(), chain).map_err(into_logged_binder)?;
        self.ensure_security_levels_current()
            .map_err(into_logged_binder)?;
        Ok(())
    }

    fn updateRsaKeybox(
        &self,
        key: &[u8],
        chain: &[crate::android::hardware::security::keymint::Certificate::Certificate],
    ) -> rsbinder::status::Result<()> {
        self.enforce_keybox_admin().map_err(into_logged_binder)?;
        let chain: Vec<kmr_wire::keymint::Certificate> = chain
            .iter()
            .map(|c| kmr_wire::keymint::Certificate {
                encoded_certificate: c.encodedCertificate.clone(),
            })
            .collect();

        keybox::update_rsa_keybox(key.to_vec(), chain).map_err(into_logged_binder)?;
        self.ensure_security_levels_current()
            .map_err(into_logged_binder)?;
        Ok(())
    }
}
