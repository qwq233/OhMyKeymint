use anyhow::{anyhow, Context, Result};
use rsbinder::{hub, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
    IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

fn main() {
    if let Err(error) = run() {
        eprintln!("aosp_keystore_smoke failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let _ = rsbinder::ProcessState::init_default();

    let service: Strong<dyn IKeystoreService> = hub::get_interface(KEYSTORE_SERVICE)
        .context("failed to connect to android.system.keystore2.IKeystoreService/default")?;
    let tee = service
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getSecurityLevel(TRUSTED_ENVIRONMENT) failed")?;

    let alias = format!("aosp-smoke-{}", std::process::id());
    let app_key = app_descriptor(&alias);
    let generated = tee
        .generateKey(&app_key, None, &app_aes_gcm_key_params(), 0, &[])
        .context("generateKey(APP AES-GCM key) failed")?;
    println!(
        "generated app key: alias={} security_level={:?} cert_len={} chain_len={}",
        alias,
        generated.keySecurityLevel,
        generated.certificate.as_ref().map_or(0, Vec::len),
        generated.certificateChain.as_ref().map_or(0, Vec::len),
    );

    let fetched = service
        .getKeyEntry(&app_key)
        .context("getKeyEntry(APP AES-GCM key) failed")?;
    ensure_matching_key_entry(&generated, &fetched.metadata)
        .context("getKeyEntry did not match generated metadata")?;
    println!("getKeyEntry matched generated APP key metadata");

    exercise_aes_gcm_round_trip(&tee, &app_key).context("AES-GCM round-trip smoke failed")?;

    let abort_operation = tee
        .createOperation(&app_key, &aes_gcm_encrypt_params(), false)
        .context("second createOperation(APP AES-GCM key) failed")?
        .iOperation
        .context("second createOperation returned no IKeystoreOperation")?;
    abort_operation.abort().context("abort() failed")?;

    service
        .deleteKey(&app_key)
        .context("deleteKey(APP AES-GCM key) failed")?;

    println!("AOSP keystore smoke passed");
    Ok(())
}

fn app_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        alias: Some(alias.to_string()),
        ..Default::default()
    }
}

fn ensure_matching_key_entry(
    generated: &android::system::keystore2::KeyMetadata::KeyMetadata,
    fetched: &android::system::keystore2::KeyMetadata::KeyMetadata,
) -> Result<()> {
    if generated.key.domain != fetched.key.domain {
        return Err(anyhow!(
            "key domain mismatch: generated={:?} fetched={:?}",
            generated.key.domain,
            fetched.key.domain
        ));
    }
    if generated.key.alias != fetched.key.alias {
        return Err(anyhow!(
            "key alias mismatch: generated={:?} fetched={:?}",
            generated.key.alias,
            fetched.key.alias
        ));
    }
    if generated.keySecurityLevel != fetched.keySecurityLevel {
        return Err(anyhow!(
            "keySecurityLevel mismatch: generated={:?} fetched={:?}",
            generated.keySecurityLevel,
            fetched.keySecurityLevel
        ));
    }
    if generated.certificate != fetched.certificate {
        return Err(anyhow!("leaf certificate mismatch"));
    }
    if generated.certificateChain != fetched.certificateChain {
        return Err(anyhow!("certificate chain mismatch"));
    }
    Ok(())
}

fn kp(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn app_aes_gcm_key_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::AES)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(128)),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        kp(Tag::MIN_MAC_LENGTH, KeyParameterValue::Integer(128)),
    ]
}

fn aes_gcm_encrypt_params() -> Vec<KeyParameter> {
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

fn aes_gcm_decrypt_params(nonce: &[u8]) -> Vec<KeyParameter> {
    vec![
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
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
        kp(Tag::NONCE, KeyParameterValue::Blob(nonce.to_vec())),
    ]
}

fn expect_operation(response: CreateOperationResponse) -> Result<Strong<dyn IKeystoreOperation>> {
    response
        .iOperation
        .context("createOperation returned no IKeystoreOperation")
}

fn extract_nonce(response: &CreateOperationResponse) -> Result<Vec<u8>> {
    response
        .parameters
        .as_ref()
        .and_then(|parameters| {
            parameters.keyParameter.iter().find_map(|parameter| {
                if parameter.tag == Tag::NONCE {
                    match &parameter.value {
                        KeyParameterValue::Blob(nonce) => Some(nonce.clone()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
        })
        .context("encrypt createOperation response did not return a NONCE")
}

fn finish_with_input(operation: &Strong<dyn IKeystoreOperation>, input: &[u8]) -> Result<Vec<u8>> {
    Ok(operation.finish(Some(input), None)?.unwrap_or_default())
}

fn exercise_aes_gcm_round_trip(
    level: &Strong<dyn IKeystoreSecurityLevel>,
    key: &KeyDescriptor,
) -> Result<()> {
    let plaintext = b"duck_aes_gcm_probe";

    let encrypt_response = level
        .createOperation(key, &aes_gcm_encrypt_params(), false)
        .context("createOperation(AES-GCM encrypt) failed")?;
    let nonce = extract_nonce(&encrypt_response)?;
    let encrypt_operation = expect_operation(encrypt_response)?;
    let ciphertext = finish_with_input(&encrypt_operation, plaintext)
        .context("finish(AES-GCM encrypt input) failed")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("AES-GCM encrypt returned empty ciphertext"));
    }

    let decrypt_response = level
        .createOperation(key, &aes_gcm_decrypt_params(&nonce), false)
        .context("createOperation(AES-GCM decrypt) failed")?;
    let decrypt_operation = expect_operation(decrypt_response)?;
    let decrypted = finish_with_input(&decrypt_operation, &ciphertext)
        .context("finish(AES-GCM decrypt input) failed")?;
    if decrypted != plaintext {
        return Err(anyhow!(
            "AES-GCM round-trip mismatch: plaintext_len={} decrypted_len={} ciphertext_len={} nonce_len={}",
            plaintext.len(),
            decrypted.len(),
            ciphertext.len(),
            nonce.len()
        ));
    }

    println!(
        "AES-GCM round-trip ok: plaintext_len={} ciphertext_len={} nonce_len={}",
        plaintext.len(),
        ciphertext.len(),
        nonce.len()
    );
    Ok(())
}
