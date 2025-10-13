use std::sync::{Arc, Mutex};

use anyhow::Ok;
use log::debug;
use rsbinder::{hub, DeathRecipient};
use x509_cert::der::asn1::OctetString;

use crate::android::content::pm::IPackageManager::IPackageManager;
use crate::android::apex::IApexService::IApexService;
use crate::err;
use crate::keymaster::apex::ApexModuleInfo;

use std::cell::RefCell;

thread_local! {
    static PM: Mutex<Option<rsbinder::Strong<dyn IPackageManager>>> = Mutex::new(None);
    static APEX: Mutex<Option<rsbinder::Strong<dyn IApexService>>> = Mutex::new(None);
}

struct PmDeathRecipient;

impl rsbinder::DeathRecipient for PmDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        PM.with(|p| {
            *p.lock().unwrap() = None;
        });
        debug!("PackageManager died, cleared PM instance");
    }
}

struct ApexDeathRecipient;

impl rsbinder::DeathRecipient for ApexDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        APEX.with(|p| {
            *p.lock().unwrap() = None;
        });
        debug!("ApexService died, cleared APEX instance");
    }
}

#[allow(non_snake_case)]
fn get_pm() -> anyhow::Result<rsbinder::Strong<dyn IPackageManager>> {
    PM.with(|p| {
        let mut guard = p.lock().unwrap();
        if let Some(iPm) = guard.as_ref() {
            Ok(iPm.clone())
        } else {
            let pm: rsbinder::Strong<dyn IPackageManager> = hub::get_interface("package")?;
            let recipient = Arc::new(PmDeathRecipient {});

            pm.as_binder()
                .link_to_death(Arc::downgrade(&(recipient as Arc<dyn DeathRecipient>)))?;

            *guard = Some(pm.clone());
            Ok(pm)
        }
    })
}

#[allow(non_snake_case)]
fn get_apex() -> anyhow::Result<rsbinder::Strong<dyn IApexService>> {
    APEX.with(|p| {
        let mut guard = p.lock().unwrap();
        if let Some(iApex) = guard.as_ref() {
            Ok(iApex.clone())
        } else {
            let apex: rsbinder::Strong<dyn IApexService> = hub::get_interface("apexservice")?;
            let recipient = Arc::new(ApexDeathRecipient {});

            apex.as_binder()
                .link_to_death(Arc::downgrade(&(recipient as Arc<dyn DeathRecipient>)))?;

            *guard = Some(apex.clone());
            Ok(apex)
        }
    })
}

pub fn get_aaid(uid: u32) -> anyhow::Result<String> {
    if (uid == 0) || (uid == 1000) {
        return Ok("android".to_string());
    } // system or root
    let pm = get_pm()?;
    let package_names = pm.getPackagesForUid(uid as i32)
        .map_err(|e| anyhow::anyhow!(err!("getPackagesForUid failed: {:?}", e)))?;

    debug!("get_aaid: package_name = {:?}", package_names);

    Ok(package_names[0].clone())
}

pub fn get_apex_module_info() -> anyhow::Result<Vec<ApexModuleInfo>> {
    let apex = get_apex()?;
    let result: Vec<crate::android::apex::ApexInfo::ApexInfo> = apex.getAllPackages()
        .map_err(|e| anyhow::anyhow!(err!("getAllPackages failed: {:?}", e)))?;

    let result: Vec<ApexModuleInfo> = result
        .iter()
        .map(|i| {
            Ok(ApexModuleInfo {
                package_name: OctetString::new(i.moduleName.as_bytes())?,
                version_code: i.versionCode as u64,
            })
        })
        .collect::<anyhow::Result<Vec<ApexModuleInfo>>>()
        .map_err(|e| anyhow::anyhow!(err!("ApexModuleInfo conversion failed: {:?}", e)))?;

    Ok(result)
}

pub const AID_USER_OFFSET: u32 = 100000;

/// Gets the user id from a uid.
pub fn multiuser_get_user_id(uid: u32) -> u32 {
    uid / AID_USER_OFFSET
}

/// Gets the app id from a uid.
pub fn multiuser_get_app_id(uid: u32) -> u32 {
    uid % AID_USER_OFFSET
}

/// Extracts the android user from the given uid.
pub fn uid_to_android_user(uid: u32) -> u32 {
    multiuser_get_user_id(uid)
}
