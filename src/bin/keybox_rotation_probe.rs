use std::{fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use regex::Regex;
use rsbinder::{hub, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, Certificate::Certificate, Digest::Digest, EcCurve::EcCurve,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
    ResponseCode::ResponseCode,
};
use top::qwq2333::ohmykeymint::{CallerInfo::CallerInfo, IOhMyKsService::IOhMyKsService};

const OMK_SERVICE: &str = "omk";
const KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";
const PROBE_UID: i64 = 10465;
const PROBE_SID: &str = "u:r:untrusted_app:s0:c209,c257,c512,c768";

fn main() {
    if let Err(error) = run() {
        eprintln!("keybox rotation probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let new_key_path = args
        .next()
        .context("usage: keybox_rotation_probe <new-ec-sec1-der> <new-ec-cert-der>")?;
    let new_cert_path = args
        .next()
        .context("usage: keybox_rotation_probe <new-ec-sec1-der> <new-ec-cert-der>")?;
    if args.next().is_some() {
        bail!("usage: keybox_rotation_probe <new-ec-sec1-der> <new-ec-cert-der>");
    }

    rsbinder::ProcessState::init_default();

    let service: Strong<dyn IOhMyKsService> =
        hub::get_interface(OMK_SERVICE).context("failed to connect to omk service")?;
    let original_ec = parse_ec_keybox(Path::new(KEYBOX_PATH))
        .with_context(|| format!("failed to parse original keybox from {KEYBOX_PATH}"))?;
    println!(
        "original EC keybox material: key_sha256={} cert_chain_sha256={}",
        sha256_hex(&original_ec.key_der)?,
        sha256_hex(&concat_chain(&original_ec.chain))?
    );

    let restore = RestoreEcKeybox {
        service: service.clone(),
        original_ec: original_ec.clone(),
        restored: false,
    };
    let mut restore = Some(restore);

    let caller = CallerInfo {
        callingUid: PROBE_UID,
        callingPid: std::process::id() as i64,
        callingSid: PROBE_SID.to_string(),
    };
    let suffix = format!("{}-{}", std::process::id(), monotonic_suffix());
    let attest_alias = format!("omk-keybox-rotation-attester-{suffix}");
    let subject_alias = format!("omk-keybox-rotation-subject-{suffix}");
    let attest_desc = app_descriptor(&attest_alias);
    let subject_desc = app_descriptor(&subject_alias);
    let cleanup = Cleanup {
        service: service.clone(),
        calling_pid: caller.callingPid,
        keys: vec![subject_desc.clone(), attest_desc.clone()],
    };

    delete_if_exists(&service, &caller, &subject_desc);
    delete_if_exists(&service, &caller, &attest_desc);

    let level = service
        .getOhMySecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getOhMySecurityLevel(TRUSTED_ENVIRONMENT) failed before rotation")?;

    let first_attest = level
        .generateKey(
            Some(&caller),
            &attest_desc,
            None,
            &attest_key_params(b"omk-keybox-rotation-before"),
            0,
            &[],
        )
        .context("generateKey(PURPOSE=ATTEST_KEY) failed before rotation")?;
    let first_digest = metadata_cert_digest(&first_attest)?;
    println!(
        "pre-rotation attestKey generated: alias={} cert_sha256={}",
        attest_alias, first_digest
    );

    let new_ec = EcKeyboxMaterial {
        key_der: fs::read(&new_key_path)
            .with_context(|| format!("failed to read new EC key DER from {new_key_path}"))?,
        chain: vec![Certificate {
            encodedCertificate: fs::read(&new_cert_path).with_context(|| {
                format!("failed to read new EC certificate DER from {new_cert_path}")
            })?,
        }],
    };
    println!(
        "rotating EC keybox material: key_sha256={} cert_chain_sha256={}",
        sha256_hex(&new_ec.key_der)?,
        sha256_hex(&concat_chain(&new_ec.chain))?
    );
    update_ec_keybox(&service, &new_ec).context("updateEcKeybox(new EC keybox) failed")?;
    println!("EC keybox rotated through updateEcKeybox");

    match service.getKeyEntry(Some(&caller), &attest_desc) {
        Err(status) if is_key_not_found(&status) => {
            println!("old attestKey alias retired after keybox rotation: KEY_NOT_FOUND");
        }
        Err(status) => {
            return Err(anyhow!(
                "old attestKey alias returned unexpected status after rotation: exception={:?} service_specific={} transaction={:?}",
                status.exception_code(),
                status.service_specific_error(),
                status.transaction_error()
            ));
        }
        Ok(response) => {
            let digest = metadata_cert_digest(&response.metadata)?;
            return Err(anyhow!(
                "old attestKey alias remained visible after keybox rotation: cert_sha256={digest}"
            ));
        }
    }

    let rotated_level = service
        .getOhMySecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getOhMySecurityLevel(TRUSTED_ENVIRONMENT) failed after rotation")?;
    let second_attest = rotated_level
        .generateKey(
            Some(&caller),
            &attest_desc,
            None,
            &attest_key_params(b"omk-keybox-rotation-after"),
            0,
            &[],
        )
        .context("regenerate attestKey alias after rotation failed")?;
    let second_digest = metadata_cert_digest(&second_attest)?;
    if second_digest == first_digest {
        return Err(anyhow!(
            "regenerated attestKey certificate digest unexpectedly matched pre-rotation digest"
        ));
    }
    println!(
        "post-rotation attestKey regenerated: alias={} cert_sha256={}",
        attest_alias, second_digest
    );

    let fetched = service
        .getKeyEntry(Some(&caller), &attest_desc)
        .context("getKeyEntry(regenerated attestKey) failed")?;
    let fetched_digest = metadata_cert_digest(&fetched.metadata)?;
    if fetched_digest != second_digest {
        return Err(anyhow!(
            "regenerated attestKey fetch mismatch: generated={} fetched={}",
            second_digest,
            fetched_digest
        ));
    }
    println!("post-rotation attestKey getKeyEntry matched regenerated certificate");

    let subject = rotated_level
        .generateKey(
            Some(&caller),
            &subject_desc,
            Some(&attest_desc),
            &subject_key_params(),
            0,
            &[],
        )
        .context("generateKey(subject with regenerated attestKey) failed")?;
    println!(
        "post-rotation subject attestation succeeded: alias={} cert_sha256={}",
        subject_alias,
        metadata_cert_digest(&subject)?
    );

    drop(cleanup);
    if let Some(mut restore) = restore.take() {
        restore
            .restore()
            .context("restoring original EC keybox failed")?;
    }
    println!("original EC keybox restored");
    println!("keybox rotation attestKey probe passed");
    Ok(())
}

struct EcKeyboxMaterial {
    key_der: Vec<u8>,
    chain: Vec<Certificate>,
}

impl Clone for EcKeyboxMaterial {
    fn clone(&self) -> Self {
        Self {
            key_der: self.key_der.clone(),
            chain: self
                .chain
                .iter()
                .map(|certificate| Certificate {
                    encodedCertificate: certificate.encodedCertificate.clone(),
                })
                .collect(),
        }
    }
}

struct RestoreEcKeybox {
    service: Strong<dyn IOhMyKsService>,
    original_ec: EcKeyboxMaterial,
    restored: bool,
}

impl RestoreEcKeybox {
    fn restore(&mut self) -> Result<()> {
        update_ec_keybox(&self.service, &self.original_ec)?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for RestoreEcKeybox {
    fn drop(&mut self) {
        if !self.restored {
            if let Err(error) = self.restore() {
                eprintln!("failed to restore original EC keybox in cleanup: {error:#}");
            }
        }
    }
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

fn update_ec_keybox(
    service: &Strong<dyn IOhMyKsService>,
    material: &EcKeyboxMaterial,
) -> Result<()> {
    service
        .updateEcKeybox(&material.key_der, &material.chain)
        .map_err(|status| {
            anyhow!(
                "updateEcKeybox failed: exception={:?} service_specific={} transaction={:?}",
                status.exception_code(),
                status.service_specific_error(),
                status.transaction_error()
            )
        })
}

fn parse_ec_keybox(path: &Path) -> Result<EcKeyboxMaterial> {
    let xml = fs::read_to_string(path)
        .with_context(|| format!("failed to read keybox XML {}", path.display()))?;
    let block_re = Regex::new(r#"(?s)<Key\s+algorithm="(?:ecdsa|ec)">\s*(.*?)\s*</Key>"#)
        .context("failed to compile EC keybox regex")?;
    let private_key_re = Regex::new(r#"(?s)<PrivateKey[^>]*>\s*(.*?)\s*</PrivateKey>"#)
        .context("failed to compile private key regex")?;
    let cert_re = Regex::new(r#"(?s)<Certificate(?:\s+[^>]*)?>\s*(.*?)\s*</Certificate>"#)
        .context("failed to compile certificate regex")?;

    let block = block_re
        .captures(&xml)
        .and_then(|captures| captures.get(1))
        .map(|m| m.as_str())
        .context("missing EC key block in keybox XML")?;
    let key_pem = private_key_re
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|m| m.as_str())
        .context("missing EC private key in keybox XML")?;
    let key_der = decode_pem(key_pem).context("failed to decode EC private key PEM")?;
    let chain = cert_re
        .captures_iter(block)
        .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
        .map(|pem| {
            decode_pem(pem)
                .map(|encoded_certificate| Certificate {
                    encodedCertificate: encoded_certificate,
                })
                .context("failed to decode EC certificate PEM")
        })
        .collect::<Result<Vec<_>>>()?;
    if chain.is_empty() {
        bail!("EC keybox certificate chain is empty");
    }
    Ok(EcKeyboxMaterial { key_der, chain })
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();
    if base64_body.is_empty() {
        bail!("empty PEM payload");
    }
    STANDARD
        .decode(base64_body.as_bytes())
        .context("failed to decode PEM payload")
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

fn attest_key_params(challenge: &[u8]) -> Vec<KeyParameter> {
    let mut params = base_ec_params();
    params.push(kp(
        Tag::PURPOSE,
        KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY),
    ));
    params.push(kp(
        Tag::ATTESTATION_CHALLENGE,
        KeyParameterValue::Blob(challenge.to_vec()),
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
        KeyParameterValue::Blob(b"omk-keybox-rotation-subject".to_vec()),
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
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> Result<String> {
    let digest = BoringSha256
        .hash(bytes)
        .map_err(|error| anyhow!("failed to hash bytes: {error:?}"))?;
    Ok(hex::encode(digest))
}

fn concat_chain(chain: &[Certificate]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for certificate in chain {
        bytes.extend_from_slice(&certificate.encodedCertificate);
    }
    bytes
}

fn is_key_not_found(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ResponseCode::KEY_NOT_FOUND.0
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
