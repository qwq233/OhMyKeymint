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
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::err;
use crate::keymaster::apex::ApexModuleInfo;
use crate::keymaster::error::KsError;

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

const ERROR_GET_ATTESTATION_APPLICATION_ID_FAILED: i32 = 1;
const KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE: usize = 1024;
const AAID_PKG_INFO_OVERHEAD: usize = 15;
const AAID_SIGNATURE_SIZE: usize = 34;
const AAID_GENERAL_OVERHEAD: usize = 16;

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
        let info = KeyAttestationPackageInfo {
            packageName: "AndroidSystem".to_string(),
            versionCode: 1,
            ..Default::default()
        };
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

                // unsafe {
                //     libc::seteuid(current_euid);
                // }
                pm.getKeyAttestationApplicationId(uid as i32)
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
                } else if e.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
                    && e.service_specific_error() == ERROR_GET_ATTESTATION_APPLICATION_ID_FAILED
                {
                    return Err(anyhow::anyhow!(KsError::Rc(
                        ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED
                    )));
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
    let sha256 = BoringSha256 {};
    let package_infos = application_id.packageInfos;
    let first_package = package_infos
        .first()
        .ok_or_else(|| anyhow::anyhow!("AttestationApplicationId has no package info"))?;

    let mut estimated_encoded_size = AAID_GENERAL_OVERHEAD;

    let mut package_info_records = Vec::new();
    for pkg in &package_infos {
        let package_name = pkg.packageName.as_bytes();
        let package_info = super::aaid::PackageInfoRecord {
            package_name: der::asn1::OctetString::new(package_name)?,
            version: pkg.versionCode as u64,
        };

        estimated_encoded_size = estimated_encoded_size
            .saturating_add(AAID_PKG_INFO_OVERHEAD)
            .saturating_add(package_name.len());
        if estimated_encoded_size > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE {
            break;
        }
        package_info_records.push(package_info);
    }
    let package_info_set = SetOfVec::from_iter(package_info_records).map_err(|e| {
        anyhow::anyhow!(err!(
            "Failed to encode AttestationApplicationId package infos: {:?}",
            e
        ))
    })?;

    let mut signature_digests = Vec::new();
    for sig in &first_package.signatures {
        let result = sha256
            .hash(sig.data.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to hash signature: {:?}", e))?;
        signature_digests.push(result);
    }

    let mut signature_digest_records = Vec::new();
    for sig_digest in signature_digests {
        estimated_encoded_size = estimated_encoded_size.saturating_add(AAID_SIGNATURE_SIZE);
        if estimated_encoded_size > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE {
            break;
        }
        signature_digest_records.push(x509_cert::der::asn1::OctetString::new(sig_digest)?);
    }
    let signature_digests = SetOfVec::from_iter(signature_digest_records).map_err(|e| {
        anyhow::anyhow!(err!(
            "Failed to encode AttestationApplicationId signature digests: {:?}",
            e
        ))
    })?;

    let result = super::aaid::AttestationApplicationId {
        package_info_records: package_info_set,
        signature_digests,
    };

    result
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode AttestationApplicationId: {:?}", e))
}

pub fn get_apex_module_info() -> anyhow::Result<Vec<ApexModuleInfo>> {
    let apex = get_apex()?;
    let result: Vec<crate::android::apex::ApexInfo::ApexInfo> =
        apex.getActivePackages().map_err(|e| {
            log::error!("Failed to get active packages: {:?}", e);
            anyhow::anyhow!(err!("getActivePackages failed: {:?}", e))
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::security::keystore::Signature::Signature;
    use crate::plat::aaid::AttestationApplicationId as DerAttestationApplicationId;
    use der::Decode;

    fn signature(data: &[u8]) -> Signature {
        Signature {
            data: data.to_vec(),
        }
    }

    fn package(
        package_name: &str,
        version_code: i64,
        signatures: Vec<Signature>,
    ) -> KeyAttestationPackageInfo {
        KeyAttestationPackageInfo {
            packageName: package_name.to_string(),
            versionCode: version_code,
            signatures,
        }
    }

    #[test]
    fn aaid_encoder_uses_first_package_signatures_and_sorts_sets() {
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![
                package("z.example", 2, vec![signature(b"shared-signature")]),
                package("a.example", 1, vec![signature(b"shared-signature")]),
            ],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert_eq!(parsed.package_info_records.len(), 2);
        assert_eq!(parsed.signature_digests.len(), 1);
    }

    #[test]
    fn aaid_encoder_uses_aosp_package_size_limit() {
        let mut package_infos = Vec::new();
        for idx in 0..9 {
            let package_name = format!("pkg{:02}.{}", idx, "a".repeat(94));
            package_infos.push(package(
                &package_name,
                idx,
                vec![
                    signature(b"signature-1"),
                    signature(b"signature-2"),
                    signature(b"signature-3"),
                ],
            ));
        }

        let der = encode_application_id(KeyAttestationApplicationId {
            packageInfos: package_infos,
        })
        .expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert!(der.len() <= KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE);
        assert_eq!(parsed.package_info_records.len(), 8);
        assert_eq!(parsed.signature_digests.len(), 0);
    }

    #[test]
    fn aaid_encoder_uses_aosp_signature_size_limit() {
        let signatures = (0..35)
            .map(|idx| signature(format!("signature-{idx}").as_bytes()))
            .collect();
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![package("a", 1, signatures)],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert!(der.len() <= KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE);
        assert_eq!(parsed.package_info_records.len(), 1);
        assert_eq!(parsed.signature_digests.len(), 29);
    }

    #[test]
    fn aaid_encoder_casts_version_code_to_unsigned() {
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![package("negative.version", -1, vec![])],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert_eq!(
            parsed
                .package_info_records
                .get(0)
                .expect("package info")
                .version,
            u64::MAX
        );
    }
}
