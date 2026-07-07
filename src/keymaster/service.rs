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

use kmr_common::consts::{AID_KEYSTORE, AID_ROOT, AID_SYSTEM};

use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
    KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
};
use crate::err;
use crate::global::{db_root_path, DB, SUPER_KEY};
use crate::keybox;
use crate::keymaster::audit_log::log_key_deleted;
use crate::keymaster::db::Uuid;
use crate::keymaster::db::KEYSTORE_UUID;
use crate::keymaster::db::{KeyEntryLoadBits, KeyType, SubComponentType};
use crate::keymaster::error::{into_logged_binder, KsError as Error};
use crate::keymaster::id_rotation::IdRotationState;
use crate::keymaster::permission::{
    check_grant_permission, check_key_permission, check_keystore_permission,
    require_forwarded_context, KeyPerm, KeyPermSet, KeystorePerm,
};
use crate::keymaster::security_level::KeystoreSecurityLevel;
use crate::keymaster::utils::{
    count_key_entries, key_parameters_to_authorizations, list_key_entries, AppUid,
};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMySecurityLevel::IOhMySecurityLevel;
use crate::watchdog as wd;
use anyhow::{Context, Result};
use log::debug;
use rsbinder::thread_state::CallingContext;
use rsbinder::{Status, Strong};

/// Implementation of the IKeystoreService.
pub struct KeystoreService {
    security_levels: RwLock<SecurityLevels>,
    id_rotation_state: IdRotationState,
    strongbox_enabled: bool,
}

impl Default for KeystoreService {
    fn default() -> Self {
        Self {
            security_levels: RwLock::new(Default::default()),
            id_rotation_state: IdRotationState::new(db_root_path()),
            strongbox_enabled: false,
        }
    }
}

#[derive(Default, Clone)]
struct SecurityLevels {
    i_sec_level_by_uuid: HashMap<Uuid, Strong<dyn IKeystoreSecurityLevel>>,
    i_osec_level_by_uuid: HashMap<Uuid, Strong<dyn IOhMySecurityLevel>>,
    uuid_by_sec_level: HashMap<SecurityLevel, Uuid>,
}

impl SecurityLevels {
    fn unregister(&mut self, sec_level: SecurityLevel) -> Option<Uuid> {
        let cur_uuid = self.uuid_by_sec_level.remove(&sec_level)?;
        self.i_sec_level_by_uuid.remove(&cur_uuid);
        self.i_osec_level_by_uuid.remove(&cur_uuid);
        Some(cur_uuid)
    }
}

impl KeystoreService {
    /// Create a new instance of the Keystore 2.0 service.
    pub fn new_native_binder() -> Result<KeystoreService> {
        let result = Self {
            strongbox_enabled: crate::plat::keymint_profile::strongbox_keymint_present(),
            ..Default::default()
        };

        let retired = result.retire_stale_keybox_bound_entries().context(err!(
            "retiring stale keybox-bound entries during service startup"
        ))?;
        if retired != 0 {
            log::info!("retired {retired} stale keybox-bound entries during service startup");
        }

        match result.register_security_level(SecurityLevel::TRUSTED_ENVIRONMENT) {
            Result::Ok(v) => v,
            Err(e) => {
                log::error!("Failed to construct mandatory security level TEE: {e:?}");
                log::error!("Does the device have a /default Keymaster or KeyMint instance?");
                return Err(e.context(err!("Trying to construct mandatory security level TEE")));
            }
        };

        if result.strongbox_enabled {
            match result.register_security_level(SecurityLevel::STRONGBOX) {
                Result::Ok(v) => v,
                Err(e) => {
                    log::error!("Failed to construct optional security level StrongBox: {e:?}");
                    log::error!("But we ignore this error because StrongBox is optional.");
                }
            };
        } else {
            log::info!("StrongBox KeyMint HAL is not present; skipping optional security level.");
        }

        Ok(result)
    }

    fn retire_stale_keybox_bound_entries(&self) -> Result<usize> {
        if !keybox::db_retirement_allowed() {
            log::warn!(
                "Skipping stale keybox-bound entry retirement while keybox fallback is active."
            );
            return Ok(0);
        }

        DB.with(|db| {
            db.borrow_mut()
                .retire_stale_keybox_bound_entries(keybox::current_identity_digest())
        })
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

        if self.strongbox_enabled {
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
        }

        Ok(())
    }

    fn register_security_level(&self, sec_level: SecurityLevel) -> Result<()> {
        debug!("Registering security level {sec_level:?}");
        let uuid = Uuid::from(sec_level);

        let old_uuid_to_terminate = {
            let security_levels = self.security_levels.read().unwrap();
            if let Some(&cur_uuid) = security_levels.uuid_by_sec_level.get(&sec_level) {
                (uuid != cur_uuid).then_some(cur_uuid)
            } else {
                None
            }
        };

        if let Some(cur_uuid) = old_uuid_to_terminate {
            log::warn!("Security level {sec_level:?} was registered with a different UUID {cur_uuid:?}, overwriting with {uuid:?}.");
            log::warn!("Retiring stale keybox-bound entries from database.");

            self.retire_stale_keybox_bound_entries().map_err(|e| {
                anyhow::anyhow!(err!(
                    "Failed to retire stale keybox-bound entries for old UUID {cur_uuid:?}: {e:?}"
                ))
            })?;

            let mut security_levels = self.security_levels.write().unwrap();
            if security_levels.uuid_by_sec_level.get(&sec_level) == Some(&cur_uuid) {
                security_levels.unregister(sec_level);
                log::warn!(
                    "Unregistered stale security level {sec_level:?} for UUID {cur_uuid:?}."
                );
            }
        }

        let (i_sec_level, i_osec_level) =
            match KeystoreSecurityLevel::new_binders(sec_level, self.id_rotation_state.clone()) {
                Result::Ok(v) => v,
                Err(e) => {
                    log::error!("Failed to construct security level {sec_level:?}: {e:?}");
                    return Err(e.context(err!("Trying to construct security level {sec_level:?}")));
                }
            };

        let mut security_levels = self.security_levels.write().unwrap();
        if let Some(cur_uuid) = security_levels.unregister(sec_level) {
            log::warn!("Security level {sec_level:?} was already registered, overwriting.");
            if cur_uuid != uuid {
                log::warn!(
                    "Overwriting stale security level {sec_level:?} UUID {cur_uuid:?} with {uuid:?}."
                );
            }
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
        _ctx: Option<&CallerInfo>,
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
        _ctx: Option<&CallerInfo>,
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

        let _super_key = SUPER_KEY
            .read()
            .unwrap()
            .get_credential_encrypted_key_by_user_id(caller_uid.owning_user());

        let (key_id_guard, mut key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    key,
                    KeyType::Client,
                    KeyEntryLoadBits::PUBLIC,
                    caller_uid,
                    |k, av| check_key_permission(KeyPerm::GetInfo, k, av.as_ref(), ctx),
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
            .get_credential_encrypted_key_by_user_id(caller_uid.owning_user());
        let existing_key = match DB.with(|db| {
            db.borrow_mut().load_key_entry(
                key,
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                caller_uid,
                |k, av| check_key_permission(KeyPerm::Update, k, av.as_ref(), ctx),
            )
        }) {
            Ok((key_id_guard, key_entry)) => Some((key_id_guard, key_entry)),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Rc(ResponseCode::KEY_NOT_FOUND)) => None,
                _ => return Err(e).context(err!("Failed to resolve key permissions.")),
            },
        };

        if let Some((key_id_guard, _key_entry)) = existing_key {
            return DB
                .with::<_, Result<()>>(|db| {
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
                nspace: caller_uid.0,
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
        let caller_uid = calling_uid(ctx);

        let mut k = match domain {
            Domain::APP => KeyDescriptor {
                domain,
                nspace: caller_uid.0,
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
                .ok_or(Error::Rc(ResponseCode::INFO_NOT_AVAILABLE))
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
            .get_credential_encrypted_key_by_user_id(caller_uid.owning_user());

        DB.with(|db| {
            db.borrow_mut()
                .unbind_key(key, KeyType::Client, caller_uid, |k, av| {
                    check_key_permission(KeyPerm::Delete, k, av.as_ref(), ctx)
                })
        })
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
            .get_credential_encrypted_key_by_user_id(caller_uid.owning_user());

        DB.with(|db| {
            db.borrow_mut().grant(
                key,
                caller_uid,
                AppUid(grantee_uid as i64),
                access_vector,
                |k, av| check_grant_permission(*av, k, ctx),
            )
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
        DB.with(|db| {
            db.borrow_mut()
                .ungrant(key, caller_uid, AppUid(grantee_uid as i64), |k| {
                    check_key_permission(KeyPerm::Grant, k, None, ctx)
                })
        })
        .context(err!("KeystoreService::ungrant."))
    }

    fn is_omk_grant(&self, ctx: Option<&CallerInfo>, grant: &KeyDescriptor) -> Result<bool> {
        if grant.domain != Domain::GRANT {
            return Ok(false);
        }

        let caller_uid = calling_uid(ctx);
        match DB.with(|db| {
            db.borrow_mut().load_key_entry(
                grant,
                KeyType::Client,
                KeyEntryLoadBits::NONE,
                caller_uid,
                |_k, _av| Ok(()),
            )
        }) {
            Ok(_) => Ok(true),
            Err(error) => match error.root_cause().downcast_ref::<Error>() {
                Some(Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(false),
                _ => Err(error).context(err!("KeystoreService::is_omk_grant.")),
            },
        }
    }

    fn enforce_keybox_admin(&self, ctx: &CallerInfo) -> Result<()> {
        match ctx.callingUid as u32 {
            AID_ROOT | AID_SYSTEM | AID_KEYSTORE => Ok(()),
            uid => Err(Error::perm()).context(err!(
                "keybox update requires root/system/keystore caller, got uid={uid}"
            )),
        }
    }
}

fn calling_uid(ctx: Option<&CallerInfo>) -> AppUid {
    AppUid(
        ctx.map(|ctx| ctx.callingUid)
            .unwrap_or(CallingContext::default().uid.into()),
    )
}

fn require_omk_ctx<'a>(ctx: Option<&'a CallerInfo>, label: &str) -> Result<&'a CallerInfo, Status> {
    require_forwarded_context(ctx, label).map_err(into_logged_binder)
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
        log_key_deleted(key, calling_uid(None).0 as libc::uid_t, result.is_ok());
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

#[allow(non_snake_case)]
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::getKeyEntry")?);
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::updateSubcomponent")?);
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::listEntries")?);
        self.list_entries(ctx, domain, namespace)
            .map_err(into_logged_binder)
    }

    fn deleteKey(&self, ctx: Option<&CallerInfo>, key: &KeyDescriptor) -> Result<(), Status> {
        let _wp = wd::watch("IOhMyKsService::deleteKey");
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::deleteKey")?);
        let result = self.delete_key(ctx, key);
        log_key_deleted(key, calling_uid(ctx).0 as libc::uid_t, result.is_ok());
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::grant")?);
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::ungrant")?);
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::getNumberOfEntries")?);
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
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::listEntriesBatched")?);
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
        ctx: Option<&CallerInfo>,
        key: &[u8],
        chain: &[crate::android::hardware::security::keymint::Certificate::Certificate],
    ) -> rsbinder::status::Result<()> {
        let ctx = require_omk_ctx(ctx, "IOhMyKsService::updateEcKeybox")?;
        self.enforce_keybox_admin(ctx).map_err(into_logged_binder)?;
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
        ctx: Option<&CallerInfo>,
        key: &[u8],
        chain: &[crate::android::hardware::security::keymint::Certificate::Certificate],
    ) -> rsbinder::status::Result<()> {
        let ctx = require_omk_ctx(ctx, "IOhMyKsService::updateRsaKeybox")?;
        self.enforce_keybox_admin(ctx).map_err(into_logged_binder)?;
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

    fn isOmkGrant(&self, ctx: Option<&CallerInfo>, grant: &KeyDescriptor) -> Result<bool, Status> {
        let _wp = wd::watch("IOhMyKsService::isOmkGrant");
        let ctx = Some(require_omk_ctx(ctx, "IOhMyKsService::isOmkGrant")?);
        self.is_omk_grant(ctx, grant).map_err(into_logged_binder)
    }
}
