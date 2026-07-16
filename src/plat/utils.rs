use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::LocalKey;

use der::asn1::SetOfVec;
use der::Encode;
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use log::{debug, error};
use rsbinder::{hub, DeathRecipient, FromIBinder, Strong};

use crate::android::apex::IApexService::IApexService;
use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::android::security::keystore::KeyAttestationApplicationId::KeyAttestationApplicationId;
use crate::android::security::keystore::KeyAttestationPackageInfo::KeyAttestationPackageInfo;
use crate::android::system::keystore2::{
    IKeystoreService::IKeystoreService, ResponseCode::ResponseCode,
};
use crate::err;
use crate::keymaster::apex::ApexModuleInfo;
use crate::keymaster::error::KsError;

thread_local! {
    static PM: Mutex<Option<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>>> = Mutex::new(None);
    static APEX: Mutex<Option<rsbinder::Strong<dyn IApexService>>> = Mutex::new(None);
}

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

static KEYSTORE_CACHE: OnceLock<Mutex<KeystoreServiceCache>> = OnceLock::new();
static KEYSTORE_INIT: OnceLock<Mutex<()>> = OnceLock::new();
static KEYSTORE_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct KeystoreServiceCache {
    service: Option<rsbinder::Strong<dyn IKeystoreService>>,
    death_recipient: Option<Arc<dyn DeathRecipient>>,
    generation: u64,
}

fn keystore_cache() -> &'static Mutex<KeystoreServiceCache> {
    KEYSTORE_CACHE.get_or_init(Default::default)
}

fn keystore_init_lock() -> &'static Mutex<()> {
    KEYSTORE_INIT.get_or_init(|| Mutex::new(()))
}

fn keystore_service_is_alive(service: &rsbinder::Strong<dyn IKeystoreService>) -> bool {
    service.as_binder().ping_binder().is_ok()
}

struct PmDeathRecipient;

impl rsbinder::DeathRecipient for PmDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        PM.with(|p| {
            *p.lock().unwrap() = None;
        });
        debug!("package manager binder died; cleared cached PM instance");
    }
}

struct ApexDeathRecipient;

impl rsbinder::DeathRecipient for ApexDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        APEX.with(|p| {
            *p.lock().unwrap() = None;
        });
        debug!("apex service binder died; cleared cached instance");
    }
}

struct KeystoreDeathRecipient {
    died: AtomicBool,
    generation: u64,
}

impl rsbinder::DeathRecipient for KeystoreDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        self.died.store(true, Ordering::Release);
        let mut guard = keystore_cache().lock().unwrap();
        if guard.generation != self.generation {
            return;
        }
        guard.service = None;
        guard.death_recipient = None;
        debug!("system keystore binder died; cleared cached instance");
    }
}

#[allow(non_snake_case)]
fn get_pm() -> anyhow::Result<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>> {
    get_thread_local_binder(&PM, "sec_key_att_app_id_provider", || PmDeathRecipient {})
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
    debug!("reset cached PM instance to None");
}

pub fn get_keystore_service() -> anyhow::Result<rsbinder::Strong<dyn IKeystoreService>> {
    let _init_guard = keystore_init_lock().lock().unwrap();
    let cached = keystore_cache().lock().unwrap().service.clone();
    if let Some(service) = cached {
        if keystore_service_is_alive(&service) {
            return Ok(service);
        }

        let mut guard = keystore_cache().lock().unwrap();
        guard.service = None;
        guard.death_recipient = None;
    }

    let service: rsbinder::Strong<dyn IKeystoreService> = hub::get_interface(KEYSTORE_SERVICE)
        .map_err(|error| anyhow::anyhow!("failed to connect to {KEYSTORE_SERVICE}: {error:?}"))?;
    let generation = KEYSTORE_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let recipient = Arc::new(KeystoreDeathRecipient {
        died: AtomicBool::new(false),
        generation,
    });
    let death_recipient: Arc<dyn DeathRecipient> = recipient.clone();
    service
        .as_binder()
        .link_to_death(Arc::downgrade(&death_recipient))?;
    if recipient.died.load(Ordering::Acquire) || !keystore_service_is_alive(&service) {
        return Err(anyhow::anyhow!(
            "connected to {KEYSTORE_SERVICE} but binder died during initialization"
        ));
    }

    let mut guard = keystore_cache().lock().unwrap();
    guard.death_recipient = Some(death_recipient);
    guard.service = Some(service.clone());
    guard.generation = generation;
    if recipient.died.load(Ordering::Acquire) {
        guard.service = None;
        guard.death_recipient = None;
        return Err(anyhow::anyhow!(
            "connected to {KEYSTORE_SERVICE} but binder died during initialization"
        ));
    }

    Ok(service)
}

#[allow(non_snake_case)]
fn get_apex() -> anyhow::Result<rsbinder::Strong<dyn IApexService>> {
    get_thread_local_binder(&APEX, "apexservice", || ApexDeathRecipient {})
}

fn get_thread_local_binder<T, R>(
    slot: &'static LocalKey<Mutex<Option<Strong<T>>>>,
    service_name: &'static str,
    make_recipient: impl FnOnce() -> R,
) -> anyhow::Result<Strong<T>>
where
    T: FromIBinder + ?Sized + 'static,
    R: DeathRecipient + 'static,
{
    slot.with(|slot| {
        let mut guard = slot.lock().unwrap();
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<T> = hub::get_interface(service_name)?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(make_recipient());
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))?;
        *guard = Some(client.clone());
        Ok(client)
    })
}

pub fn get_aaid(uid: u32) -> anyhow::Result<Vec<u8>> {
    debug!("resolving AAID uid={}", uid);
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
        get_application_id_from_provider(uid)?
    };

    debug!("resolved application_id={:?}", application_id);

    encode_application_id(application_id)
}

fn get_application_id_from_provider(uid: u32) -> anyhow::Result<KeyAttestationApplicationId> {
    let _wd = crate::watchdog::watch("get_aaid: Retrieving AAID by calling service");
    let use_legacy = super::legacy::should_use_aaid_provider();
    let mut tried = 0;
    loop {
        let result = if use_legacy {
            super::legacy::get_application_id(uid)
        } else {
            let pm = get_pm()?;
            let current_uid = unsafe { libc::getuid() };
            let current_euid = unsafe { libc::geteuid() };
            debug!(
                "calling AAID provider as uid={} euid={}",
                current_uid, current_euid
            );
            pm.getKeyAttestationApplicationId(uid as i32)
                .map_err(anyhow::Error::new)
        };

        match result {
            Result::Ok(application_id) => return Ok(application_id),
            Err(error) => {
                if is_transaction_failed_error(&error) && tried < 2 {
                    error!(
                        "getKeyAttestationApplicationId transaction failed uid={}: {:?}",
                        uid, error
                    );
                    error!("resetting cached PM instance after AAID transaction failure");
                    if use_legacy {
                        super::legacy::clear_provider_cache();
                    } else {
                        reset_pm();
                    }
                    tried += 1;
                } else if is_get_attestation_application_id_failed(&error) {
                    return Err(anyhow::anyhow!(KsError::Rc(
                        ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED
                    )));
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to get KeyAttestationApplicationId for UID {}, Error: {:?}",
                        uid,
                        error
                    ));
                }
            }
        }
    }
}

fn is_transaction_failed_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rsbinder::Status>()
            .is_some_and(|status| {
                status.exception_code() == rsbinder::ExceptionCode::TransactionFailed
            })
            || cause
                .downcast_ref::<rsbinder::StatusCode>()
                .is_some_and(|status| *status == rsbinder::StatusCode::DeadObject)
    })
}

fn is_get_attestation_application_id_failed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rsbinder::Status>()
            .is_some_and(|status| {
                status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
                    && status.service_specific_error()
                        == ERROR_GET_ATTESTATION_APPLICATION_ID_FAILED
            })
    })
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
        signature_digest_records.push(der::asn1::OctetString::new(sig_digest)?);
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
            log::error!("failed to get active packages: {:?}", e);
            anyhow::anyhow!(err!("getActivePackages failed: {:?}", e))
        })?;

    result
        .iter()
        .map(|i| {
            Ok(ApexModuleInfo {
                package_name: der::asn1::OctetString::new(i.moduleName.as_bytes())?,
                version_code: i.versionCode as u64,
            })
        })
        .collect::<anyhow::Result<Vec<ApexModuleInfo>>>()
        .map_err(|e| anyhow::anyhow!(err!("ApexModuleInfo conversion failed: {:?}", e)))
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
