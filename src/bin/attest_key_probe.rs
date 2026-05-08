use anyhow::{anyhow, Context, Result};
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use rsbinder::{hub, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
};
use top::qwq2333::ohmykeymint::{CallerInfo::CallerInfo, IOhMyKsService::IOhMyKsService};

const OMK_SERVICE: &str = "omk";
const PROBE_UID: i64 = 10465;
const PROBE_SID: &str = "u:r:untrusted_app:s0:c209,c257,c512,c768";

fn main() {
    if let Err(error) = run() {
        eprintln!("attest key probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    rsbinder::ProcessState::init_default();

    let service: Strong<dyn IOhMyKsService> =
        hub::get_interface(OMK_SERVICE).context("failed to connect to omk service")?;
    let level = service
        .getOhMySecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getOhMySecurityLevel(TRUSTED_ENVIRONMENT) failed")?;

    let caller = CallerInfo {
        callingUid: PROBE_UID,
        callingPid: std::process::id() as i64,
        callingSid: PROBE_SID.to_string(),
    };

    let suffix = format!("{}-{}", std::process::id(), monotonic_suffix());
    let attest_alias = format!("omk-attest-key-probe-attester-{suffix}");
    let subject_alias = format!("omk-attest-key-probe-subject-{suffix}");
    let attest_desc = app_descriptor(&attest_alias);
    let subject_desc = app_descriptor(&subject_alias);

    let _cleanup = Cleanup {
        service: service.clone(),
        calling_pid: caller.callingPid,
        keys: vec![subject_desc.clone(), attest_desc.clone()],
    };

    delete_if_exists(&service, &caller, &subject_desc);
    delete_if_exists(&service, &caller, &attest_desc);

    let attest_metadata = level
        .generateKey(
            Some(&caller),
            &attest_desc,
            None,
            &attest_key_params(),
            0,
            &[],
        )
        .context("generateKey(PURPOSE=ATTEST_KEY) failed")?;
    let attest_digest = metadata_cert_digest(&attest_metadata)?;
    println!(
        "attest key generated: alias={} security_level={:?} cert_sha256={}",
        attest_alias, attest_metadata.keySecurityLevel, attest_digest
    );

    let fetched = service
        .getKeyEntry(Some(&caller), &attest_desc)
        .context("getKeyEntry(attest key) failed")?;
    let fetched_digest = metadata_cert_digest(&fetched.metadata)?;
    if fetched_digest != attest_digest {
        return Err(anyhow!(
            "fetched attest key cert digest mismatch: generated={} fetched={}",
            attest_digest,
            fetched_digest
        ));
    }
    println!("attest key getKeyEntry matched generated certificate");

    let subject_metadata = level
        .generateKey(
            Some(&caller),
            &subject_desc,
            Some(&attest_desc),
            &subject_key_params(),
            0,
            &[],
        )
        .context("generateKey(with user-generated attest key) failed")?;
    let subject_digest = metadata_cert_digest(&subject_metadata)?;
    println!(
        "subject key generated with attest key: alias={} security_level={:?} cert_sha256={}",
        subject_alias, subject_metadata.keySecurityLevel, subject_digest
    );

    println!("attest key probe passed");
    Ok(())
}

struct Cleanup {
    service: Strong<dyn IOhMyKsService>,
    calling_pid: i64,
    keys: Vec<KeyDescriptor>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let caller = CallerInfo {
            callingUid: PROBE_UID,
            callingPid: self.calling_pid,
            callingSid: PROBE_SID.to_string(),
        };
        for key in &self.keys {
            let _ = self.service.deleteKey(Some(&caller), key);
        }
    }
}

fn delete_if_exists(
    service: &Strong<dyn IOhMyKsService>,
    caller: &CallerInfo,
    key: &KeyDescriptor,
) {
    let _ = service.deleteKey(Some(caller), key);
}

fn app_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        alias: Some(alias.to_string()),
        ..Default::default()
    }
}

fn kp(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn base_ec_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        kp(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        kp(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
    ]
}

fn attest_key_params() -> Vec<KeyParameter> {
    let mut params = base_ec_params();
    params.push(kp(
        Tag::PURPOSE,
        KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY),
    ));
    params.push(kp(
        Tag::ATTESTATION_CHALLENGE,
        KeyParameterValue::Blob(b"omk-attest-key-probe-attester".to_vec()),
    ));
    params
}

fn subject_key_params() -> Vec<KeyParameter> {
    let mut params = base_ec_params();
    params.push(kp(
        Tag::PURPOSE,
        KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
    ));
    params.push(kp(
        Tag::ATTESTATION_CHALLENGE,
        KeyParameterValue::Blob(b"omk-attest-key-probe-subject".to_vec()),
    ));
    params
}

fn metadata_cert_digest(metadata: &KeyMetadata) -> Result<String> {
    let leaf = metadata
        .certificate
        .as_deref()
        .context("metadata missing leaf certificate")?;
    let mut bytes = Vec::from(leaf);
    if let Some(chain) = metadata.certificateChain.as_deref() {
        bytes.extend_from_slice(chain);
    }
    let digest = BoringSha256
        .hash(&bytes)
        .map_err(|error| anyhow!("failed to hash certificate material: {error:?}"))?;
    Ok(hex::encode(digest))
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
