use anyhow::{anyhow, Context, Result};
use rsbinder::{hub, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android::system::keystore2::{
    Domain::Domain, IKeystoreOperation::IKeystoreOperation, IKeystoreService::IKeystoreService,
    KeyDescriptor::KeyDescriptor,
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

fn main() {
    if let Err(error) = run() {
        eprintln!("aosp_keystore_smoke failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    rsbinder::ProcessState::init_default();

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

    let operation = tee
        .createOperation(&app_key, &aes_gcm_op_params(), false)
        .context("createOperation(APP AES-GCM key) failed")?
        .iOperation
        .context("createOperation returned no IKeystoreOperation")?;
    exercise_operation(&operation).context("operation lifecycle smoke failed")?;

    let abort_operation = tee
        .createOperation(&app_key, &aes_gcm_op_params(), false)
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

fn exercise_operation(operation: &Strong<dyn IKeystoreOperation>) -> Result<()> {
    operation.updateAad(b"aad").context("updateAad() failed")?;
    let update_output = operation.update(b"hello").context("update() failed")?;
    println!(
        "operation update output size={}",
        update_output.as_ref().map_or(0, Vec::len)
    );
    let finish_output = operation.finish(None, None).context("finish() failed")?;
    println!(
        "operation finish output size={}",
        finish_output.as_ref().map_or(0, Vec::len)
    );
    Ok(())
}
