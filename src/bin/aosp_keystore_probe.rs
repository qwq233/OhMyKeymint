use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::{Decode, Reader, SliceReader};
use hex::encode as hex_encode;
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use rsbinder::{hub, SIBinder, Status, StatusCode, Strong};
use x509_cert::Certificate;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
};
use android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse,
    Domain::Domain,
    IKeystoreOperation::IKeystoreOperation,
    IKeystoreService::{transactions as service_tx, IKeystoreService},
    KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata,
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

fn main() {
    if let Err(error) = run() {
        eprintln!("AOSP keystore probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    rsbinder::ProcessState::init_default();

    let service: Strong<dyn IKeystoreService> = hub::get_interface(KEYSTORE_SERVICE)
        .context("failed to connect to android.system.keystore2.IKeystoreService/default")?;
    match service.getSupplementaryAttestationInfo(Tag::MODULE_HASH) {
        Ok(module_info_der) => {
            if module_info_der.len() <= 32 {
                return Err(anyhow!(
                    "MODULE_HASH supplementary info is too short to be DER module info: {} bytes",
                    module_info_der.len()
                ));
            }
            let module_info_hash = BoringSha256 {}.hash(&module_info_der).map_err(|error| {
                anyhow!("failed to hash MODULE_HASH supplementary info: {error:?}")
            })?;
            println!(
                "module info exposed on AOSP surface: der_len={} sha256={}",
                module_info_der.len(),
                hex_encode(module_info_hash)
            );
        }
        Err(status) if is_expected_module_hash_status(&status) => {
            println!(
                "module info not exposed on AOSP surface as expected: exception={:?} service_specific={} transaction={:?}",
                status.exception_code(),
                status.service_specific_error(),
                status.transaction_error()
            );
        }
        Err(status) => {
            return Err(anyhow!(
                "getSupplementaryAttestationInfo(MODULE_HASH) returned unexpected status: {status:?}"
            ));
        }
    }

    let tee = get_security_level_with_diagnostics(&service)?;

    let alias = format!("aosp-probe-{}", std::process::id());
    let app_key = app_descriptor(&alias);
    let attested = tee
        .generateKey(&app_key, None, &attested_ec_params(), 0, &[])
        .context("generateKey(attested EC app key) failed")?;
    let attestation_digest = cert_chain_digest(&attested)?;
    let attestation_issuer = leaf_issuer_cn(&attested)?;
    println!(
        "attested app key generated: alias={} issuer={} chain_sha256={}",
        alias, attestation_issuer, attestation_digest
    );
    print_pem_chain("generated_attestation", &attested)
        .context("failed to print generated attestation chain")?;

    let fetched = service
        .getKeyEntry(&app_key)
        .context("getKeyEntry(app alias) failed")?;
    let fetched_digest = cert_digest_parts(
        fetched.metadata.certificate.as_deref(),
        fetched.metadata.certificateChain.as_deref(),
    )?;
    if fetched_digest != attestation_digest {
        return Err(anyhow!(
            "getKeyEntry returned a different attestation chain digest: generated={} fetched={}",
            attestation_digest,
            fetched_digest
        ));
    }
    println!("getKeyEntry matched generated attestation chain");
    print_pem_chain("fetched_attestation", &fetched.metadata)
        .context("failed to print fetched attestation chain")?;

    service
        .deleteKey(&app_key)
        .context("deleteKey(app alias) failed")?;

    let op_alias = format!("aosp-probe-op-{}", std::process::id());
    let op_key = app_descriptor(&op_alias);
    let generated = tee
        .generateKey(&op_key, None, &aes_gcm_key_params(), 0, &[])
        .context("generateKey(APP AES-GCM key) failed")?;
    println!(
        "generated operation key: alias={} security_level={:?} cert_len={} chain_len={}",
        op_alias,
        generated.keySecurityLevel,
        generated.certificate.as_ref().map_or(0, Vec::len),
        generated.certificateChain.as_ref().map_or(0, Vec::len),
    );

    let operation = tee
        .createOperation(&op_key, &aes_gcm_op_params(), false)
        .context("createOperation(APP AES-GCM key) failed")
        .and_then(expect_operation)?;
    exercise_operation(&operation).context("operation lifecycle smoke failed")?;

    let abort_operation = tee
        .createOperation(&op_key, &aes_gcm_op_params(), false)
        .context("second createOperation(APP AES-GCM key) failed")
        .and_then(expect_operation)?;
    abort_operation.abort().context("abort() failed")?;

    service
        .deleteKey(&op_key)
        .context("deleteKey(APP AES-GCM key) failed")?;

    println!("AOSP keystore probe passed");
    Ok(())
}

fn get_security_level_with_diagnostics(
    service: &Strong<dyn IKeystoreService>,
) -> Result<Strong<dyn android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel>>
{
    match service.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT) {
        Ok(level) => Ok(level),
        Err(error) => {
            let diagnostic = raw_get_security_level_diagnostic(service)
                .unwrap_or_else(|diag_error| format!("raw diagnostic failed: {diag_error:#}"));
            Err(anyhow!(
                "getSecurityLevel(TRUSTED_ENVIRONMENT) failed: {error:#}\nRaw reply diagnostic:\n{diagnostic}"
            ))
        }
    }
}

fn raw_get_security_level_diagnostic(service: &Strong<dyn IKeystoreService>) -> Result<String> {
    let binder = service.as_binder();
    let proxy = binder
        .as_proxy()
        .context("IKeystoreService binder was unexpectedly local in probe")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare raw getSecurityLevel transaction")?;
    data.write(&SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to encode raw getSecurityLevel argument")?;
    let mut reply = proxy
        .submit_transact(service_tx::r#getSecurityLevel, &data, 0)
        .context("raw getSecurityLevel transact failed")?
        .context("raw getSecurityLevel transact returned no reply")?;

    let mut lines = Vec::new();
    lines.push(format!("reply_debug={reply:?}"));

    reply.set_data_position(0);
    match reply.read::<Status>() {
        Ok(status) => {
            lines.push(format!(
                "status={{exception={:?}, service_specific={}, transaction_failed={}}}",
                status.exception_code(),
                status.service_specific_error(),
                status.transaction_error() != StatusCode::Ok
            ));
            if status.is_ok() {
                match reply.read::<SIBinder>() {
                    Ok(raw_binder) => {
                        lines.push(format!(
                            "sibinder={{descriptor={}, remote={}}}",
                            raw_binder.descriptor(),
                            raw_binder.as_proxy().is_some()
                        ));
                        match reply.read::<i32>() {
                            Ok(extra) => lines.push(format!("extra_i32_after_binder=0x{extra:x}")),
                            Err(extra_error) => {
                                lines.push(format!(
                                    "extra_i32_after_binder_read_error={extra_error:#}"
                                ));
                            }
                        }
                    }
                    Err(read_error) => {
                        lines.push(format!("sibinder_read_error={read_error:#}"));
                    }
                }
            }
        }
        Err(status_error) => {
            lines.push(format!("status_read_error={status_error:#}"));
        }
    }

    Ok(lines.join("\n"))
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

fn attested_ec_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        kp(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        kp(
            Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::Blob(b"aosp-probe-challenge".to_vec()),
        ),
    ]
}

fn aes_gcm_key_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::AES)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(128)),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::MIN_MAC_LENGTH, KeyParameterValue::Integer(128)),
    ]
}

fn aes_gcm_op_params() -> Vec<KeyParameter> {
    vec![
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::MAC_LENGTH, KeyParameterValue::Integer(128)),
    ]
}

fn expect_operation(response: CreateOperationResponse) -> Result<Strong<dyn IKeystoreOperation>> {
    response
        .iOperation
        .context("createOperation returned no IKeystoreOperation")
}

fn exercise_operation(operation: &Strong<dyn IKeystoreOperation>) -> Result<()> {
    operation.updateAad(b"a").context("updateAad() failed")?;
    let first_chunk = operation.update(b"hello").context("update() failed")?;
    println!(
        "operation update output size: {}",
        first_chunk.as_ref().map_or(0, Vec::len)
    );
    let finish_chunk = operation.finish(None, None).context("finish() failed")?;
    println!(
        "operation finish output size: {}",
        finish_chunk.as_ref().map_or(0, Vec::len)
    );
    Ok(())
}

fn cert_chain_digest(metadata: &KeyMetadata) -> Result<String> {
    cert_digest_parts(
        metadata.certificate.as_deref(),
        metadata.certificateChain.as_deref(),
    )
}

fn cert_digest_parts(leaf: Option<&[u8]>, chain: Option<&[u8]>) -> Result<String> {
    let mut material = Vec::new();
    let leaf = leaf.context("missing attestation leaf certificate")?;
    material.extend_from_slice(leaf);
    if let Some(chain) = chain {
        material.extend_from_slice(chain);
    }
    let digest = BoringSha256
        .hash(&material)
        .map_err(|error| anyhow!("failed to hash certificate chain: {error:?}"))?;
    Ok(hex_encode(digest))
}

fn leaf_issuer_cn(metadata: &KeyMetadata) -> Result<String> {
    let leaf = metadata
        .certificate
        .as_deref()
        .context("missing attestation leaf certificate")?;
    let leaf = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    Ok(format!("{:?}", leaf.tbs_certificate.issuer))
}

fn collect_chain_der(metadata: &KeyMetadata) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    certs.push(
        metadata
            .certificate
            .as_ref()
            .context("missing attestation leaf certificate")?
            .clone(),
    );

    let mut remaining = metadata.certificateChain.as_deref().unwrap_or_default();
    while !remaining.is_empty() {
        let mut reader =
            SliceReader::new(remaining).context("failed to create DER reader for chain bytes")?;
        let _ = Certificate::decode(&mut reader).context("failed to decode chain certificate")?;
        let remaining_len = usize::try_from(reader.remaining_len())
            .context("failed to convert DER remaining length to usize")?;
        let consumed = remaining
            .len()
            .checked_sub(remaining_len)
            .context("chain reader consumed more data than available")?;
        certs.push(remaining[..consumed].to_vec());
        remaining = &remaining[consumed..];
    }

    Ok(certs)
}

fn print_pem_chain(label: &str, metadata: &KeyMetadata) -> Result<()> {
    let certs = collect_chain_der(metadata)?;
    println!("{label}_cert_count={}", certs.len());
    for (index, cert_der) in certs.iter().enumerate() {
        println!("{label}_cert_{index}_begin");
        println!("{}", encode_pem(cert_der));
        println!("{label}_cert_{index}_end");
    }
    Ok(())
}

fn encode_pem(cert_der: &[u8]) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let base64 = STANDARD.encode(cert_der);
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

#[allow(dead_code)]
fn expect_invalid_argument(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ErrorCode::INVALID_ARGUMENT.0
}

fn is_expected_module_hash_status(status: &rsbinder::Status) -> bool {
    (status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
        && status.service_specific_error()
            == android::system::keystore2::ResponseCode::ResponseCode::INFO_NOT_AVAILABLE.0)
        || status.exception_code() == rsbinder::ExceptionCode::TransactionFailed
            && status.transaction_error() == StatusCode::UnknownTransaction
}
