use anyhow::{Context, Result};
use rsbinder::{Interface, Status, Strong};

use crate::android::hardware::security::keymint::{
    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
};
use crate::android::security::maintenance::IKeystoreMaintenance::{
    BnKeystoreMaintenance, IKeystoreMaintenance,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::err;
use crate::global::{DB, SUPER_KEY};
use crate::keymaster::db::{KeyEntryLoadBits, KeyType};
use crate::keymaster::error::{into_logged_binder, map_km_error, KsError};
use crate::keymaster::keymint_device::{get_keymint_wrapper, KeyMintWrapper};
use crate::keymaster::permission::{
    check_forwarded_context, check_key_permission, check_keystore_permission,
    check_manage_users_permission, require_forwarded_context, CallerCtx, KeyPerm, KeystorePerm,
};
use crate::keymaster::utils::{AndroidUserId, AppUid, SecureUserId};
use crate::top::qwq2333::ohmykeymint::{
    CallerInfo::CallerInfo,
    IOhMyMaintenanceService::{BnOhMyMaintenanceService, IOhMyMaintenanceService},
};
use crate::watchdog as wd;

pub struct MaintenanceManager;

impl MaintenanceManager {
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreMaintenance>> {
        Ok(BnKeystoreMaintenance::new_binder_with_features(
            Self,
            crate::consts::sid_features(),
        ))
    }

    pub fn new_omk_binder() -> Result<Strong<dyn IOhMyMaintenanceService>> {
        Ok(BnOhMyMaintenanceService::new_binder_with_features(
            Self,
            crate::consts::sid_features(),
        ))
    }

    fn on_user_added(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "onUserAdded")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        self.remove_user_state(user_id)
    }

    fn init_user_super_keys(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "initUserSuperKeys")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        let password = password.into();
        DB.with(|db| {
            SUPER_KEY.write().unwrap().initialize_user(
                &mut db.borrow_mut(),
                user_id,
                &password,
                allow_existing,
            )
        })
        .context(err!("initializing user {user_id:?} super keys"))
    }

    fn on_user_password_changed(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangePassword, ctx, "onUserPasswordChanged")
            .context(err!("caller missing change_password permission"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| {
            let mut db = db.borrow_mut();
            let mut super_key = SUPER_KEY.write().unwrap();
            match password {
                Some(password) => {
                    let password = password.into();
                    super_key.unlock_or_initialize_user(&mut db, user_id, &password)
                }
                None => super_key.reset_lskf_bound_state(&mut db, user_id),
            }
        })
        .context(err!("handling legacy password change for user {user_id:?}"))
    }

    fn on_user_removed(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "onUserRemoved")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        self.remove_user_state(user_id)
    }

    fn on_user_lskf_removed(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangePassword, ctx, "onUserLskfRemoved")
            .context(err!("caller missing change_password permission"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| db.borrow_mut().unbind_auth_bound_keys_for_user(user_id))
            .context(err!("unbinding auth-bound keys for user {user_id:?}"))
    }

    fn clear_namespace(&self, ctx: Option<&CallerInfo>, domain: Domain, nspace: i64) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ClearUID, ctx, "clearNamespace")
            .context(err!("caller missing clear_uid permission"))?;
        DB.with(|db| db.borrow_mut().unbind_keys_for_namespace(domain, nspace))
            .context(err!("clearing namespace domain={domain:?} nspace={nspace}"))
    }

    fn early_boot_ended(&self, ctx: Option<&CallerInfo>) -> Result<()> {
        check_maintenance_permission(KeystorePerm::EarlyBootEnded, ctx, "earlyBootEnded")
            .context(err!("caller missing early_boot_ended permission"))?;
        DB.with(|db| {
            crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
                &SUPER_KEY,
                &mut db.borrow_mut(),
            )
        })
        .context(err!("setting up boot-level key cache"))?;
        replay_early_boot_ended()?;
        Ok(())
    }

    fn migrate_key_namespace(
        &self,
        ctx: Option<&CallerInfo>,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> Result<()> {
        check_forwarded_context(ctx, "migrateKeyNamespace")?;

        match source.domain {
            Domain::SELINUX | Domain::KEY_ID | Domain::APP => (),
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                    "Source domain must be one of APP, SELINUX, or KEY_ID."
                ));
            }
        };

        let caller = CallerCtx::from_caller_info(ctx);
        let destination = normalize_migration_destination(destination, caller.uid)?;

        let caller_uid = AppUid(caller.uid as i64);
        let key_id_guard = DB
            .with(|db| {
                db.borrow_mut()
                    .load_key_entry(
                        source,
                        KeyType::Client,
                        KeyEntryLoadBits::NONE,
                        caller_uid,
                        |descriptor, access_vector| {
                            check_key_permission(
                                KeyPerm::Use,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!("caller missing use permission for migration source"))?;
                            check_key_permission(
                                KeyPerm::Delete,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!(
                                "caller missing delete permission for migration source"
                            ))?;
                            check_key_permission(
                                KeyPerm::Grant,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!("caller missing grant permission for migration source"))
                        },
                    )
                    .map(|(key_id_guard, _)| key_id_guard)
            })
            .context(err!("resolving source key permissions for migration"))?;

        DB.with(|db| {
            db.borrow_mut().migrate_key_namespace(
                key_id_guard,
                &destination,
                caller_uid,
                |descriptor| {
                    check_key_permission(KeyPerm::Rebind, descriptor, None, ctx).context(err!(
                        "caller missing rebind permission for migration destination"
                    ))
                },
            )
        })
        .context(err!("migrating key namespace"))
    }

    fn delete_all_keys(&self, ctx: Option<&CallerInfo>) -> Result<()> {
        check_maintenance_permission(KeystorePerm::DeleteAllKeys, ctx, "deleteAllKeys")
            .context(err!("caller missing delete_all_keys permission"))?;
        call_keymint_wrappers("deleteAllKeys", |keymint| keymint.deleteAllKeys())?;
        DB.with(|db| db.borrow_mut().unbind_all_keys())
            .context(err!(
                "removing all key database entries after deleteAllKeys"
            ))
    }

    fn get_app_uids_affected_by_sid(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        sid: i64,
    ) -> Result<Vec<i64>> {
        check_forwarded_context(ctx, "getAppUidsAffectedBySid")?;
        check_manage_users_permission(ctx).context(err!("caller missing MANAGE_USERS"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| {
            db.borrow_mut()
                .get_app_uids_affected_by_sid(user_id, SecureUserId(sid))
        })
        .map(|uids| uids.into_iter().map(|uid| uid.0).collect())
        .context(err!("querying app UIDs affected by SID"))
    }

    fn remove_user_state(&self, user_id: AndroidUserId) -> Result<()> {
        DB.with(|db| {
            SUPER_KEY
                .write()
                .unwrap()
                .remove_user(&mut db.borrow_mut(), user_id)
        })
        .context(err!("removing user {user_id:?} keys"))
    }
}

fn check_maintenance_permission(
    permission: KeystorePerm,
    ctx: Option<&CallerInfo>,
    label: &str,
) -> Result<()> {
    check_forwarded_context(ctx, label)?;
    check_keystore_permission(permission, ctx)
}

fn require_omk_ctx<'a>(
    ctx: Option<&'a CallerInfo>,
    label: &str,
) -> std::result::Result<&'a CallerInfo, Status> {
    require_forwarded_context(ctx, label).map_err(into_logged_binder)
}

fn checked_user_id(user_id: i32) -> Result<AndroidUserId> {
    if user_id < 0 {
        return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("user_id must be non-negative"));
    }
    Ok(AndroidUserId(user_id))
}

fn normalize_migration_destination(
    destination: &KeyDescriptor,
    caller_uid: u32,
) -> Result<KeyDescriptor> {
    let Some(alias) = destination.alias.as_ref() else {
        return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("migration destination must specify an alias"));
    };

    match destination.domain {
        Domain::APP => Ok(KeyDescriptor {
            domain: Domain::APP,
            nspace: caller_uid as i64,
            alias: Some(alias.clone()),
            blob: None,
        }),
        Domain::SELINUX => Ok(KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: destination.nspace,
            alias: Some(alias.clone()),
            blob: None,
        }),
        _ => Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("migration destination must be APP or SELINUX")),
    }
}

fn keymint_unavailable(error: &anyhow::Error) -> bool {
    matches!(
        error.root_cause().downcast_ref::<KsError>(),
        Some(KsError::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
    )
}

pub(crate) fn replay_early_boot_ended() -> Result<()> {
    call_keymint_wrappers("earlyBootEnded", |keymint| keymint.earlyBootEnded())
}

fn call_keymint_wrappers<F>(label: &'static str, mut call: F) -> Result<()>
where
    F: FnMut(&KeyMintWrapper) -> rsbinder::status::Result<()>,
{
    let tee = get_keymint_wrapper(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context(err!("opening mandatory TEE KeyMint for {label}"))?;
    map_km_error(call(&tee)).context(err!("calling TEE KeyMint {label}"))?;

    match get_keymint_wrapper(SecurityLevel::STRONGBOX) {
        Ok(strongbox) => {
            map_km_error(call(&strongbox))
                .context(err!("calling optional StrongBox KeyMint {label}"))?;
        }
        Err(error) if keymint_unavailable(&error) => {
            log::debug!("optional StrongBox KeyMint unavailable for {label}");
        }
        Err(error) => return Err(error).context(err!("opening optional StrongBox KeyMint")),
    }

    Ok(())
}

impl Interface for MaintenanceManager {}

#[allow(non_snake_case)]
impl IKeystoreMaintenance for MaintenanceManager {
    fn onUserAdded(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserAdded");
        self.on_user_added(None, user_id)
            .map_err(into_logged_binder)
    }

    fn initUserSuperKeys(
        &self,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::initUserSuperKeys");
        self.init_user_super_keys(None, user_id, password, allow_existing)
            .map_err(into_logged_binder)
    }

    fn onUserRemoved(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserRemoved");
        self.on_user_removed(None, user_id)
            .map_err(into_logged_binder)
    }

    fn onUserLskfRemoved(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserLskfRemoved");
        self.on_user_lskf_removed(None, user_id)
            .map_err(into_logged_binder)
    }

    fn clearNamespace(&self, domain: Domain, nspace: i64) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::clearNamespace");
        self.clear_namespace(None, domain, nspace)
            .map_err(into_logged_binder)
    }

    fn earlyBootEnded(&self) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::earlyBootEnded");
        self.early_boot_ended(None).map_err(into_logged_binder)
    }

    fn migrateKeyNamespace(
        &self,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::migrateKeyNamespace");
        self.migrate_key_namespace(None, source, destination)
            .map_err(into_logged_binder)
    }

    fn deleteAllKeys(&self) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::deleteAllKeys");
        self.delete_all_keys(None).map_err(into_logged_binder)
    }

    fn getAppUidsAffectedBySid(
        &self,
        user_id: i32,
        sid: i64,
    ) -> rsbinder::status::Result<Vec<i64>> {
        let _wp = wd::watch("IKeystoreMaintenance::getAppUidsAffectedBySid");
        self.get_app_uids_affected_by_sid(None, user_id, sid)
            .map_err(into_logged_binder)
    }
}

#[allow(non_snake_case)]
impl IOhMyMaintenanceService for MaintenanceManager {
    fn onUserAdded(&self, ctx: Option<&CallerInfo>, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::onUserAdded");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::onUserAdded",
        )?);
        self.on_user_added(ctx, user_id).map_err(into_logged_binder)
    }

    fn initUserSuperKeys(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::initUserSuperKeys");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::initUserSuperKeys",
        )?);
        self.init_user_super_keys(ctx, user_id, password, allow_existing)
            .map_err(into_logged_binder)
    }

    fn onUserRemoved(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::onUserRemoved");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::onUserRemoved",
        )?);
        self.on_user_removed(ctx, user_id)
            .map_err(into_logged_binder)
    }

    fn onUserLskfRemoved(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::onUserLskfRemoved");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::onUserLskfRemoved",
        )?);
        self.on_user_lskf_removed(ctx, user_id)
            .map_err(into_logged_binder)
    }

    fn clearNamespace(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        nspace: i64,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::clearNamespace");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::clearNamespace",
        )?);
        self.clear_namespace(ctx, domain, nspace)
            .map_err(into_logged_binder)
    }

    fn earlyBootEnded(&self, ctx: Option<&CallerInfo>) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::earlyBootEnded");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::earlyBootEnded",
        )?);
        self.early_boot_ended(ctx).map_err(into_logged_binder)
    }

    fn migrateKeyNamespace(
        &self,
        ctx: Option<&CallerInfo>,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::migrateKeyNamespace");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::migrateKeyNamespace",
        )?);
        self.migrate_key_namespace(ctx, source, destination)
            .map_err(into_logged_binder)
    }

    fn deleteAllKeys(&self, ctx: Option<&CallerInfo>) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::deleteAllKeys");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::deleteAllKeys",
        )?);
        self.delete_all_keys(ctx).map_err(into_logged_binder)
    }

    fn getAppUidsAffectedBySid(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        sid: i64,
    ) -> rsbinder::status::Result<Vec<i64>> {
        let _wp = wd::watch("IOhMyMaintenanceService::getAppUidsAffectedBySid");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::getAppUidsAffectedBySid",
        )?);
        self.get_app_uids_affected_by_sid(ctx, user_id, sid)
            .map_err(into_logged_binder)
    }

    fn onUserPasswordChanged(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyMaintenanceService::onUserPasswordChanged");
        let ctx = Some(require_omk_ctx(
            ctx,
            "IOhMyMaintenanceService::onUserPasswordChanged",
        )?);
        self.on_user_password_changed(ctx, user_id, password)
            .map_err(into_logged_binder)
    }
}
