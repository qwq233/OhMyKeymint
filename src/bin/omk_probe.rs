use anyhow::{anyhow, Context, Result};
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use rsbinder::{hub, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, ErrorCode::ErrorCode, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, CreateOperationResponse::CreateOperationResponse,
    Domain::Domain, EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
    IKeystoreOperation::IKeystoreOperation, KeyDescriptor::KeyDescriptor,
    ResponseCode::ResponseCode,
};
use top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use top::qwq2333::ohmykeymint::IOhMySecurityLevel::IOhMySecurityLevel;

const OMK_SERVICE: &str = "omk";

fn main() {
    if let Err(error) = run() {
        eprintln!("OMK probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let _ = rsbinder::ProcessState::init_default();

    let service: Strong<dyn IOhMyKsService> =
        hub::get_interface(OMK_SERVICE).context("failed to connect to omk service")?;

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
                "module info exposed on OMK wrapper surface: der_len={} sha256={}",
                module_info_der.len(),
                hex::encode(module_info_hash)
            );
        }
        Err(status) if is_expected_module_hash_status(&status) => {
            println!(
                "module info unavailable on OMK wrapper surface: exception={:?} service_specific={} transaction={:?}",
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

    let _ = service
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getSecurityLevel(TRUSTED_ENVIRONMENT) failed")?;
    let level = service
        .getOhMySecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("getOhMySecurityLevel(TRUSTED_ENVIRONMENT) failed")?;

    match service.getOhMySecurityLevel(SecurityLevel::STRONGBOX) {
        Ok(_) => println!("StrongBox IOhMySecurityLevel is available"),
        Err(error) => println!("StrongBox IOhMySecurityLevel unavailable: {:?}", error),
    }

    let generated = match level.generateKey(
        None,
        &blob_descriptor(None),
        None,
        &generate_aes_gcm_params(),
        0,
        &[],
    ) {
        Ok(generated) => generated,
        Err(status) if is_permission_denied(&status) => {
            println!(
                "direct BLOB generateKey denied for the current caller as expected; skipping manage_blob-dependent OMK extension checks"
            );
            println!("OMK probe passed");
            return Ok(());
        }
        Err(status) => return Err(status).context("generateKey(AES-GCM blob) failed"),
    };
    let generated_key = expect_blob_key(&generated.key, "generated AES-GCM key")?;

    exercise_aes_gcm_round_trip(&level, &generated_key)
        .context("AES-GCM round-trip smoke failed")?;

    let abort_response = level
        .createOperation(None, &generated_key, &create_operation_params(), false)
        .context("second createOperation(AES-GCM) failed")?;
    let abort_operation = abort_response
        .iOperation
        .context("second createOperation returned no IKeystoreOperation")?;
    abort_operation
        .abort()
        .context("abort() on second operation failed")?;

    level
        .deleteKey(None, &generated_key)
        .context("deleteKey(generated AES-GCM key) failed")?;

    let imported_storage = match level.importKey(
        None,
        &blob_descriptor(None),
        None,
        &import_storage_key_params(),
        0,
        &[0x11; 32],
    ) {
        Ok(imported) => imported,
        Err(status) if is_permission_denied(&status) => {
            println!(
                "direct BLOB importKey denied for the current caller as expected; skipping remaining manage_blob-dependent OMK extension checks"
            );
            println!("OMK probe passed");
            return Ok(());
        }
        Err(status) => return Err(status).context("importKey(storage key) failed"),
    };
    let imported_storage_key = expect_blob_key(&imported_storage.key, "imported storage key")?;

    match level.convertStorageKeyToEphemeral(None, &imported_storage_key) {
        Ok(EphemeralStorageKeyResponse {
            ephemeralKey,
            upgradedBlob,
        }) => {
            if ephemeralKey.is_empty() {
                return Err(anyhow!("convertStorageKeyToEphemeral returned empty key"));
            }
            println!(
                "convertStorageKeyToEphemeral succeeded (upgraded_blob={})",
                upgradedBlob.is_some()
            );
        }
        Err(error) => {
            println!(
                "convertStorageKeyToEphemeral returned best-effort error: {:?}",
                error
            );
        }
    }

    level
        .deleteKey(None, &imported_storage_key)
        .context("deleteKey(imported storage key) failed")?;

    negative_import_wrapped_smoke(&level, &generated_key)
        .context("negative importWrappedKey smoke failed")?;

    println!("OMK probe passed");
    Ok(())
}

fn blob_descriptor(blob: Option<Vec<u8>>) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::BLOB,
        blob,
        ..Default::default()
    }
}

fn expect_blob_key(key: &KeyDescriptor, label: &str) -> Result<KeyDescriptor> {
    if key.domain != Domain::BLOB {
        return Err(anyhow!("{label} did not return a Domain::BLOB key"));
    }
    if key.blob.as_ref().is_none_or(|blob| blob.is_empty()) {
        return Err(anyhow!("{label} returned an empty key blob"));
    }
    Ok(key.clone())
}

fn kp(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn generate_aes_gcm_params() -> Vec<KeyParameter> {
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

fn create_operation_params() -> Vec<KeyParameter> {
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

fn create_decrypt_operation_params(nonce: &[u8]) -> Vec<KeyParameter> {
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

fn import_storage_key_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::AES)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        kp(Tag::STORAGE_KEY, KeyParameterValue::BoolValue(true)),
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
    level: &Strong<dyn IOhMySecurityLevel>,
    key: &KeyDescriptor,
) -> Result<()> {
    let plaintext = b"duck_aes_gcm_probe";

    let encrypt_response = level
        .createOperation(None, key, &create_operation_params(), false)
        .context("createOperation(AES-GCM encrypt) failed")?;
    let nonce = extract_nonce(&encrypt_response)?;
    let encrypt_operation = expect_operation(encrypt_response)?;
    let ciphertext = finish_with_input(&encrypt_operation, plaintext)
        .context("finish(AES-GCM encrypt input) failed")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("AES-GCM encrypt returned empty ciphertext"));
    }

    let decrypt_response = level
        .createOperation(None, key, &create_decrypt_operation_params(&nonce), false)
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

fn negative_import_wrapped_smoke(
    level: &Strong<dyn IOhMySecurityLevel>,
    wrapping_key: &KeyDescriptor,
) -> Result<()> {
    let wrapped_key = KeyDescriptor {
        domain: Domain::APP,
        alias: Some("negative-wrapped-key".to_string()),
        blob: Some(vec![0x01, 0x02, 0x03]),
        ..Default::default()
    };
    let authenticators: Vec<AuthenticatorSpec> = Vec::new();
    match level.importWrappedKey(None, &wrapped_key, wrapping_key, None, &[], &authenticators) {
        Err(status)
            if status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
                && status.service_specific_error() == ErrorCode::INVALID_ARGUMENT.0 =>
        {
            println!("negative importWrappedKey smoke returned INVALID_ARGUMENT as expected");
            Ok(())
        }
        Err(status) => Err(anyhow!(
            "negative importWrappedKey smoke returned unexpected status: {:?}",
            status
        )),
        Ok(_) => Err(anyhow!(
            "negative importWrappedKey smoke unexpectedly succeeded"
        )),
    }
}

fn is_permission_denied(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ResponseCode::PERMISSION_DENIED.0
}

fn is_expected_module_hash_status(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ResponseCode::INFO_NOT_AVAILABLE.0
}
