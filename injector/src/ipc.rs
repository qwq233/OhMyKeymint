use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Once;

use anyhow::{Context, Result};
use log::{debug, warn};
use rsbinder::{hub, DeathRecipient, ExceptionCode, Status, StatusCode, Strong, WIBinder};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::android::system::keystore2::IKeystoreService::IKeystoreService;
use crate::filter::PackageResolution;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;

const SYSTEM_KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

thread_local! {
    static OMK: RefCell<Option<Strong<dyn IOhMyKsService>>> = RefCell::new(None);
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = RefCell::new(None);
    static SYSTEM_KEYSTORE: RefCell<Option<Strong<dyn IKeystoreService>>> = RefCell::new(None);
    static OMK_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = RefCell::new(None);
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = RefCell::new(None);
    static SYSTEM_KEYSTORE_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = RefCell::new(None);
}

static PROCESS_STATE_INIT: Once = Once::new();

struct CachedBinderDeath {
    tag: &'static str,
    clear: fn(),
}

impl DeathRecipient for CachedBinderDeath {
    fn binder_died(&self, _who: &WIBinder) {
        (self.clear)();
        warn!("[Injector][IPC] {} binder died; cache cleared", self.tag);
    }
}

pub fn ensure_process_state() {
    PROCESS_STATE_INIT.call_once(|| {
        rsbinder::ProcessState::init_default();
        debug!("[Injector][IPC] rsbinder process state initialized");
    });
}

pub fn get_omk() -> Result<Strong<dyn IOhMyKsService>> {
    ensure_process_state();
    OMK.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<dyn IOhMyKsService> =
            hub::get_interface("omk").context("failed to connect to omk service")?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(CachedBinderDeath {
            tag: "omk",
            clear: clear_omk_cache,
        });
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context("failed to watch omk death")?;
        OMK_DEATH.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

pub fn with_omk_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IOhMyKsService>) -> Result<T>,
{
    let client = get_omk()?;
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if is_dead_object_error(&error) => {
            warn!(
                "[Injector][IPC] omk transaction hit DeadObject; clearing cache and retrying once"
            );
            clear_omk_cache();
            let client = get_omk()?;
            f(&client)
        }
        Err(error) => Err(error),
    }
}

pub fn resolve_packages_for_uid(uid: u32) -> PackageResolution {
    ensure_process_state();
    match with_pm_retry(|pm| {
        pm.getKeyAttestationApplicationId(uid as i32)
            .context("getKeyAttestationApplicationId failed")
    }) {
        Ok(app_id) => {
            let packages: Vec<String> = app_id
                .packageInfos
                .into_iter()
                .map(|pkg| pkg.packageName)
                .filter(|pkg| !pkg.is_empty())
                .collect();
            if packages.is_empty() {
                PackageResolution::Unknown
            } else {
                PackageResolution::Known(packages)
            }
        }
        Err(error) => {
            warn!(
                "[Injector][IPC] failed to resolve packages for uid {}: {:#}",
                uid, error
            );
            clear_pm_cache();
            PackageResolution::Unknown
        }
    }
}

pub fn get_system_keystore_service() -> Result<Strong<dyn IKeystoreService>> {
    ensure_process_state();
    SYSTEM_KEYSTORE.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<dyn IKeystoreService> = hub::get_interface(SYSTEM_KEYSTORE_SERVICE)
            .with_context(|| format!("failed to connect to {SYSTEM_KEYSTORE_SERVICE}"))?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(CachedBinderDeath {
            tag: SYSTEM_KEYSTORE_SERVICE,
            clear: clear_system_keystore_cache,
        });
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context("failed to watch system keystore death")?;
        SYSTEM_KEYSTORE_DEATH.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

pub fn with_system_keystore_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeystoreService>) -> Result<T>,
{
    let client = get_system_keystore_service()?;
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if is_dead_object_error(&error) => {
            warn!(
                "[Injector][IPC] system keystore transaction hit DeadObject; clearing cache and retrying once"
            );
            clear_system_keystore_cache();
            let client = get_system_keystore_service()?;
            f(&client)
        }
        Err(error) => Err(error),
    }
}

fn get_pm() -> Result<Strong<dyn IKeyAttestationApplicationIdProvider>> {
    PM.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<dyn IKeyAttestationApplicationIdProvider> =
            hub::get_interface("sec_key_att_app_id_provider")
                .context("failed to connect to sec_key_att_app_id_provider")?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(CachedBinderDeath {
            tag: "sec_key_att_app_id_provider",
            clear: clear_pm_cache,
        });
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context("failed to watch sec_key_att_app_id_provider death")?;
        PM_DEATH.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

fn with_pm_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeyAttestationApplicationIdProvider>) -> Result<T>,
{
    let client = get_pm()?;
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if is_dead_object_error(&error) => {
            warn!(
                "[Injector][IPC] sec_key_att_app_id_provider transaction hit DeadObject; clearing cache and retrying once"
            );
            clear_pm_cache();
            let client = get_pm()?;
            f(&client)
        }
        Err(error) => Err(error),
    }
}

fn is_dead_object_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<Status>())
        .any(is_dead_object_status)
}

fn is_dead_object_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::DeadObject
}

fn clear_omk_cache() {
    OMK.with(|slot| *slot.borrow_mut() = None);
    OMK_DEATH.with(|slot| *slot.borrow_mut() = None);
}

fn clear_pm_cache() {
    PM.with(|slot| *slot.borrow_mut() = None);
    PM_DEATH.with(|slot| *slot.borrow_mut() = None);
}

fn clear_system_keystore_cache() {
    SYSTEM_KEYSTORE.with(|slot| *slot.borrow_mut() = None);
    SYSTEM_KEYSTORE_DEATH.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_dead_object_status() {
        let status = Status::from(StatusCode::DeadObject);
        assert!(is_dead_object_status(&status));
    }

    #[test]
    fn ignores_non_dead_object_status() {
        let status = Status::from(StatusCode::Ok);
        assert!(!is_dead_object_status(&status));
    }
}
