use std::sync::Arc;

use anyhow::Ok;
use log::debug;
use rsbinder::{hub, DeathRecipient};

use crate::android::content::pm::IPackageManager::IPackageManager;

use std::cell::RefCell;

thread_local! {
    static PM: RefCell<Option<rsbinder::Strong<dyn IPackageManager>>> = RefCell::new(None);
}

struct MyDeathRecipient;

impl rsbinder::DeathRecipient for MyDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        PM.with(|p| {
            *p.borrow_mut() = None;
        });
        debug!("PackageManager died, cleared PM instance");
    }
}

#[allow(non_snake_case)]
fn get_pm() -> anyhow::Result<rsbinder::Strong<dyn IPackageManager>> {
    PM.with(|p| {
        if let Some(iPm) = p.borrow().as_ref() {
            Ok(iPm.clone())
        } else {
            let pm: rsbinder::Strong<dyn IPackageManager> = hub::get_interface("package")?;
            let recipient = Arc::new(MyDeathRecipient {});

            pm.as_binder()
                .link_to_death(Arc::downgrade(&(recipient as Arc<dyn DeathRecipient>)))?;

            *p.borrow_mut() = Some(pm.clone());
            Ok(pm)
        }
    })
}

pub fn get_aaid(uid: u32) -> anyhow::Result<String> {
    if (uid == 0) || (uid == 1000) {
        return Ok("android".to_string());
    } // system or root
    let pm = get_pm()?;
    let package_names = pm.getPackagesForUid(uid as i32)?;

    debug!("get_aaid: package_name = {:?}", package_names);

    Ok(package_names[0].clone())
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
