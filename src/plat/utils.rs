use std::sync::{Arc, Mutex};

use anyhow::Ok;
use der::asn1::SetOfVec;
use der::Encode;
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use log::{debug, error};
use rsbinder::{hub, DeathRecipient};

use crate::android::apex::IApexService::IApexService;
use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::android::security::keystore::KeyAttestationApplicationId::KeyAttestationApplicationId;
use crate::android::security::keystore::KeyAttestationPackageInfo::KeyAttestationPackageInfo;
use crate::err;
use crate::keymaster::apex::ApexModuleInfo;

thread_local! {
    static PM: Mutex<Option<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>>> = Mutex::new(None);
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
fn get_pm() -> anyhow::Result<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>> {
    PM.with(|p| {
        let mut guard = p.lock().unwrap();
        if let Some(iPm) = guard.as_ref() {
            Ok(iPm.clone())
        } else {
            let pm: rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider> =
                hub::get_interface("sec_key_att_app_id_provider")?;
            let recipient = Arc::new(PmDeathRecipient {});

            pm.as_binder()
                .link_to_death(Arc::downgrade(&(recipient as Arc<dyn DeathRecipient>)))?;

            *guard = Some(pm.clone());
            Ok(pm)
        }
    })
}

fn reset_pm() {
    PM.with(|p| {
        *p.lock().unwrap() = None;
    });
    debug!("Reset PM instance to None");
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

pub fn get_aaid(uid: u32) -> anyhow::Result<Vec<u8>> {
    debug!("Getting AAID for UID: {}", uid);
    let application_id = if (uid == 0) || (uid == 1000) {
        let mut info = KeyAttestationPackageInfo::default();
        info.packageName = "AndroidSystem".to_string();
        info.versionCode = 1;
        KeyAttestationApplicationId {
            packageInfos: vec![info],
        }
    } else {
        let _wd = crate::watchdog::watch("get_aaid: Retrieving AAID by calling service");
        let mut tried = 0;
        loop {
            let pm = get_pm()?;
            let result = {
                let current_uid = unsafe { libc::getuid() };
                let current_euid = unsafe { libc::geteuid() };
                debug!("Current UID: {}, EUID: {}", current_uid, current_euid);
                // unsafe {
                //     libc::seteuid(1017); // KEYSTORE_UID
                // }
                let result = pm.getKeyAttestationApplicationId(uid as i32);
                // unsafe {
                //     libc::seteuid(current_euid);
                // }
                result
            };
            if let Result::Ok(application_id) = result {
                break application_id;
            } else {
                let e = result.unwrap_err();
                if e.exception_code() == rsbinder::ExceptionCode::TransactionFailed && tried < 2 {
                    error!("Transaction failed when calling getKeyAttestationApplicationId for UID {}: {:?}", uid, e);
                    error!("Trying to reset the PM instance to None");
                    reset_pm();
                    tried += 1;
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to get KeyAttestationApplicationId for UID {}, Error: {:?}",
                        uid,
                        e
                    ));
                }
            }
        }
    };

    debug!("Application ID: {:?}", application_id);

    encode_application_id(application_id)
}

fn encode_application_id(
    application_id: KeyAttestationApplicationId,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut package_info_set = SetOfVec::new();
    let mut signature_digests = SetOfVec::new();
    let sha256 = BoringSha256 {};

    for pkg in application_id.packageInfos {
        for sig in pkg.signatures {
            let result = sha256
                .hash(sig.data.as_slice())
                .map_err(|e| anyhow::anyhow!("Failed to hash signature: {:?}", e))?;

            let octet_string = x509_cert::der::asn1::OctetString::new(&result)?;

            let result = signature_digests.insert_ordered(octet_string).map_err(|e| {
                anyhow::anyhow!(err!("Failed to encode AttestationApplicationId: {:?}", e))
            });
            if result.is_err() {
                error!(
                    "Failed to insert signature digest: {:?}",
                    result.unwrap_err()
                );
            }
        }

        let package_info = super::aaid::PackageInfoRecord {
            package_name: der::asn1::OctetString::new(pkg.packageName.as_bytes())?,
            version: pkg.versionCode,
        };
        package_info_set.insert_ordered(package_info).map_err(|e| {
            anyhow::anyhow!(err!("Failed to encode AttestationApplicationId: {:?}", e))
        })?;
    }

    let result = super::aaid::AttestationApplicationId {
        package_info_records: package_info_set,
        signature_digests: signature_digests,
    };

    result
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode AttestationApplicationId: {:?}", e))
}

pub fn get_apex_module_info() -> anyhow::Result<Vec<ApexModuleInfo>> {
    let apex = get_apex()?;
    let result: Vec<crate::android::apex::ApexInfo::ApexInfo> = apex
        .getAllPackages()
        .map_err(|e| anyhow::anyhow!(err!("getAllPackages failed: {:?}", e)))?;

    let result: Vec<ApexModuleInfo> = result
        .iter()
        .map(|i| {
            Ok(ApexModuleInfo {
                package_name: der::asn1::OctetString::new(i.moduleName.as_bytes())?,
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
