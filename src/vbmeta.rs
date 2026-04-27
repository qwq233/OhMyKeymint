use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use der::{oid::ObjectIdentifier, Decode};
use kmr_common::crypto::{Rng, Sha256};
use kmr_crypto_boring::{rng::BoringRng, sha256::BoringSha256};
use rsbinder::{hub, Strong};
use x509_cert::Certificate;

use crate::{
    android::{
        hardware::security::keymint::{
            Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyParameter::KeyParameter,
            KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
            SecurityLevel::SecurityLevel, Tag::Tag,
        },
        system::keystore2::{
            Domain::Domain,
            IKeystoreSecurityLevel::IKeystoreSecurityLevel,
            IKeystoreService::IKeystoreService,
            KeyDescriptor::KeyDescriptor,
            KeyMetadata::KeyMetadata,
        },
    },
    config::{
        ConfigFile, ResolvedTrust, TrustRecord, TrustValueSource, TrustValueSpec,
    },
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const VBMETA_KEY_PROP: &str = "ro.boot.vbmeta.public_key_digest";
const VBMETA_HASH_PROP: &str = "ro.boot.vbmeta.digest";
const ANDROID_ATTESTATION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const ORIGINAL_HASH_TIMEOUT: Duration = Duration::from_secs(5);
const AVB_HEADER_SIZE: usize = 256;

const RESETPROP_FALLBACKS: &[ResetpropSpec] = &[
    ResetpropSpec::direct("/system_ext/bin/resetprop"),
    ResetpropSpec::direct("/system/bin/resetprop"),
    ResetpropSpec::direct("/data/adb/ksu/bin/resetprop"),
    ResetpropSpec::subcommand("/data/adb/ksud", "resetprop"),
];

#[derive(Clone, Copy)]
struct ResetpropSpec {
    program: &'static str,
    prepend_arg: Option<&'static str>,
}

impl ResetpropSpec {
    const fn direct(program: &'static str) -> Self {
        Self {
            program,
            prepend_arg: None,
        }
    }

    const fn subcommand(program: &'static str, prepend_arg: &'static str) -> Self {
        Self {
            program,
            prepend_arg: Some(prepend_arg),
        }
    }
}

#[derive(Clone)]
struct ResolvedField {
    value: [u8; 32],
    source: TrustValueSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlvClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    class: TlvClass,
    constructed: bool,
    tag_number: u32,
    value: &'a [u8],
}

pub fn bootstrap_vbmeta(config_file: &mut ConfigFile) -> Result<ResolvedTrust> {
    let slot_suffix = read_string_property("ro.boot.slot_suffix").unwrap_or_default();
    let build_fingerprint = read_string_property("ro.build.fingerprint").unwrap_or_default();

    let vb_key = resolve_vb_key(&config_file.trust.vb_key, config_file.trust.device_locked, &slot_suffix);
    let vb_hash = resolve_vb_hash(&config_file.trust.vb_hash);

    let vb_key = match vb_key {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to resolve vb_key: {error:#}");
            return Err(error);
        }
    };
    let vb_hash = match vb_hash {
        Ok(value) => value,
        Err(error) => {
            log::error!("Failed to resolve vb_hash: {error:#}");
            return Err(error);
        }
    };

    sync_sysprops_if_needed(&vb_key, &vb_hash)?;
    update_trust_record(&mut config_file.trust_record, &build_fingerprint, &slot_suffix, &vb_key, &vb_hash);

    let vb_key_hex = hex::encode(vb_key.value);
    let vb_hash_hex = hex::encode(vb_hash.value);
    log::info!(
        "Resolved vbmeta trust: vb_key={} source={} vb_hash={} source={}",
        vb_key_hex,
        vb_key.source,
        vb_hash_hex,
        vb_hash.source
    );

    Ok(ResolvedTrust {
        os_version: config_file.trust.os_version,
        security_patch: config_file.trust.security_patch.clone(),
        vb_key: vb_key.value,
        vb_hash: vb_hash.value,
        vb_key_source: vb_key.source,
        vb_hash_source: vb_hash.source,
        verified_boot_state: config_file.trust.verified_boot_state,
        device_locked: config_file.trust.device_locked,
    })
}

fn resolve_vb_key(
    spec: &TrustValueSpec,
    device_locked: bool,
    slot_suffix: &str,
) -> Result<ResolvedField> {
    match spec {
        TrustValueSpec::Hex(value) => Ok(ResolvedField {
            value: *value,
            source: TrustValueSource::ExplicitHex,
        }),
        TrustValueSpec::Random => Ok(random_field(TrustValueSource::RandomExplicit)),
        TrustValueSpec::Auto => {
            if let Some(value) = read_hex_property(VBMETA_KEY_PROP) {
                return Ok(ResolvedField {
                    value,
                    source: TrustValueSource::Property,
                });
            }

            match compute_vbmeta_public_key_digest(slot_suffix, device_locked) {
                Ok(value) => Ok(ResolvedField {
                    value,
                    source: TrustValueSource::Computed,
                }),
                Err(error) => {
                    log::warn!("Computed vbmeta public key digest unavailable: {error:#}");
                    Ok(random_field(TrustValueSource::RandomFallback))
                }
            }
        }
    }
}

fn resolve_vb_hash(spec: &TrustValueSpec) -> Result<ResolvedField> {
    match spec {
        TrustValueSpec::Hex(value) => Ok(ResolvedField {
            value: *value,
            source: TrustValueSource::ExplicitHex,
        }),
        TrustValueSpec::Random => Ok(random_field(TrustValueSource::RandomExplicit)),
        TrustValueSpec::Auto => {
            if let Some(value) = read_hex_property(VBMETA_HASH_PROP) {
                return Ok(ResolvedField {
                    value,
                    source: TrustValueSource::Property,
                });
            }

            match probe_original_verified_boot_hash_with_timeout(ORIGINAL_HASH_TIMEOUT) {
                Ok(value) => Ok(ResolvedField {
                    value,
                    source: TrustValueSource::Original,
                }),
                Err(error) => {
                    log::warn!("Original verified boot hash unavailable: {error:#}");
                    Ok(random_field(TrustValueSource::RandomFallback))
                }
            }
        }
    }
}

fn random_field(source: TrustValueSource) -> ResolvedField {
    let mut rng = BoringRng {};
    let mut value = [0u8; 32];
    rng.fill_bytes(&mut value);
    ResolvedField { value, source }
}

fn update_trust_record(
    record: &mut TrustRecord,
    build_fingerprint: &str,
    slot_suffix: &str,
    vb_key: &ResolvedField,
    vb_hash: &ResolvedField,
) {
    *record = TrustRecord::default();

    if vb_key.source.should_record_in_config() {
        record.vb_key = Some(hex::encode(vb_key.value));
        record.vb_key_source = Some(vb_key.source);
    }

    if vb_hash.source.should_record_in_config() {
        record.vb_hash = Some(hex::encode(vb_hash.value));
        record.vb_hash_source = Some(vb_hash.source);
    }

    if !record.is_empty() {
        if !build_fingerprint.is_empty() {
            record.build_fingerprint = Some(build_fingerprint.to_string());
        }
        if !slot_suffix.is_empty() {
            record.slot_suffix = Some(slot_suffix.to_string());
        }
    }
}

fn sync_sysprops_if_needed(vb_key: &ResolvedField, vb_hash: &ResolvedField) -> Result<()> {
    let command = match find_resetprop_command() {
        Ok(command) => command,
        Err(error) if !vb_key.source.needs_sysprop_write() && !vb_hash.source.needs_sysprop_write() => {
            log::debug!("No sysprop write needed, skipping resetprop lookup failure: {error:#}");
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    if vb_key.source.needs_sysprop_write() {
        let value = hex::encode(vb_key.value);
        write_and_verify_property(&command, VBMETA_KEY_PROP, &value)?;
    }

    if vb_hash.source.needs_sysprop_write() {
        let value = hex::encode(vb_hash.value);
        write_and_verify_property(&command, VBMETA_HASH_PROP, &value)?;
    }

    Ok(())
}

fn write_and_verify_property(command: &ResetpropCommand, property: &str, value: &str) -> Result<()> {
    let mut process = Command::new(&command.program);
    if let Some(prepend_arg) = &command.prepend_arg {
        process.arg(prepend_arg);
    }
    let status = process
        .arg(property)
        .arg(value)
        .status()
        .with_context(|| format!("failed to execute resetprop for {property}"))?;
    if !status.success() {
        bail!("resetprop failed for {property} with status {status}");
    }

    let actual = read_string_property(property)
        .ok_or_else(|| anyhow!("property {property} missing after resetprop write"))?;
    if actual.trim().eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        bail!(
            "property verification failed for {property}: expected {value}, got {}",
            actual.trim()
        )
    }
}

fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_hex_property(name: &str) -> Option<[u8; 32]> {
    let value = read_string_property(name)?;
    match parse_hex_32(&value) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            log::warn!("Ignoring invalid property {name}={value}: {error:#}");
            None
        }
    }
}

fn parse_hex_32(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("invalid hex value {value}"))?;
    if decoded.len() != 32 {
        bail!("hex value must be 32 bytes, got {}", decoded.len());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn find_resetprop_command() -> Result<ResetpropCommand> {
    if let Some(program) = find_program_in_path("resetprop") {
        return Ok(ResetpropCommand {
            program,
            prepend_arg: None,
        });
    }

    for fallback in RESETPROP_FALLBACKS {
        if Path::new(fallback.program).exists() {
            return Ok(ResetpropCommand {
                program: fallback.program.to_string(),
                prepend_arg: fallback.prepend_arg.map(str::to_string),
            });
        }
    }

    Err(anyhow!("no usable resetprop binary found"))
}

fn find_program_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

struct ResetpropCommand {
    program: String,
    prepend_arg: Option<String>,
}

impl TrustValueSource {
    fn needs_sysprop_write(self) -> bool {
        matches!(
            self,
            TrustValueSource::Computed
                | TrustValueSource::Original
                | TrustValueSource::RandomExplicit
                | TrustValueSource::RandomFallback
        )
    }

    fn should_record_in_config(self) -> bool {
        matches!(self, TrustValueSource::Computed | TrustValueSource::Original)
    }
}

fn compute_vbmeta_public_key_digest(slot_suffix: &str, device_locked: bool) -> Result<[u8; 32]> {
    if !device_locked {
        return Ok([0u8; 32]);
    }

    let path = find_top_level_vbmeta_path(slot_suffix)?;
    let vbmeta_bytes = load_vbmeta_blob(&path)
        .with_context(|| format!("failed to read vbmeta image {}", path.display()))?;
    compute_vbmeta_public_key_digest_from_bytes(&vbmeta_bytes)
}

fn find_top_level_vbmeta_path(slot_suffix: &str) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if !slot_suffix.is_empty() {
        candidates.push(PathBuf::from(format!("/dev/block/by-name/vbmeta{slot_suffix}")));
        candidates.push(PathBuf::from(format!(
            "/dev/block/bootdevice/by-name/vbmeta{slot_suffix}"
        )));
    }
    candidates.push(PathBuf::from("/dev/block/by-name/vbmeta"));
    candidates.push(PathBuf::from("/dev/block/bootdevice/by-name/vbmeta"));

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "no top-level vbmeta partition found for slot suffix '{}'",
        slot_suffix
    ))
}

fn load_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open vbmeta image {}", path.display()))?;
    let mut header = [0u8; AVB_HEADER_SIZE];
    file.read_exact(&mut header)
        .with_context(|| format!("failed to read vbmeta header from {}", path.display()))?;

    if &header[..4] != b"AVB0" {
        bail!("{} does not start with AVB0 magic", path.display());
    }

    let auth_block_size = be_u64(&header[12..20])?;
    let aux_block_size = be_u64(&header[20..28])?;
    let total_size = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .and_then(|value| value.checked_add(aux_block_size))
        .ok_or_else(|| anyhow!("vbmeta size overflow"))?;

    let mut blob = vec![0u8; total_size];
    blob[..AVB_HEADER_SIZE].copy_from_slice(&header);
    file.read_exact(&mut blob[AVB_HEADER_SIZE..]).with_context(|| {
        format!(
            "failed to read {} bytes of vbmeta data from {}",
            total_size - AVB_HEADER_SIZE,
            path.display()
        )
    })?;
    Ok(blob)
}

fn compute_vbmeta_public_key_digest_from_bytes(vbmeta_bytes: &[u8]) -> Result<[u8; 32]> {
    if vbmeta_bytes.len() < AVB_HEADER_SIZE {
        bail!("vbmeta blob too small");
    }
    if &vbmeta_bytes[..4] != b"AVB0" {
        bail!("vbmeta blob missing AVB0 magic");
    }

    let auth_block_size = be_u64(&vbmeta_bytes[12..20])?;
    let public_key_offset = be_u64(&vbmeta_bytes[64..72])?;
    let public_key_size = be_u64(&vbmeta_bytes[72..80])?;
    if public_key_size == 0 {
        bail!("vbmeta public key size is zero");
    }

    let key_start = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .and_then(|value| value.checked_add(public_key_offset))
        .ok_or_else(|| anyhow!("vbmeta public key start overflow"))?;
    let key_end = key_start
        .checked_add(public_key_size)
        .ok_or_else(|| anyhow!("vbmeta public key end overflow"))?;
    if key_end > vbmeta_bytes.len() {
        bail!(
            "vbmeta public key range [{}..{}) exceeds blob length {}",
            key_start,
            key_end,
            vbmeta_bytes.len()
        );
    }

    BoringSha256 {}
        .hash(&vbmeta_bytes[key_start..key_end])
        .map_err(|error| anyhow!("failed to hash vbmeta public key: {error:?}"))
}

fn be_u64(bytes: &[u8]) -> Result<usize> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 8 bytes, got {}", bytes.len()))?;
    usize::try_from(u64::from_be_bytes(array)).context("value does not fit in usize")
}

fn probe_original_verified_boot_hash_with_timeout(timeout: Duration) -> Result<[u8; 32]> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = probe_original_verified_boot_hash_inner().map_err(|error| format!("{error:#}"));
        let _ = sender.send(result);
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(anyhow!(error)),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(anyhow!("timed out while probing system verified boot hash"))
        }
        Err(error) => Err(anyhow!("system verified boot hash probe failed: {error}")),
    }
}

fn probe_original_verified_boot_hash_inner() -> Result<[u8; 32]> {
    let service: Strong<dyn IKeystoreService> =
        hub::get_interface(KEYSTORE_SERVICE).context("failed to connect to system keystore")?;
    let tee = service
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to get system TEE security level")?;

    if let Ok(metadata) = generate_blob_attested_key(&tee) {
        return extract_verified_boot_hash_from_metadata(&metadata);
    }

    let alias = format!(
        "omk-vbhash-probe-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let descriptor = app_descriptor(&alias);
    let result = tee.generateKey(&descriptor, None, &attested_ec_params(), 0, &[]);
    let metadata = result.context("fallback APP attestation key generation failed")?;
    let extracted = extract_verified_boot_hash_from_metadata(&metadata);
    if let Err(error) = service.deleteKey(&descriptor) {
        log::warn!("Failed to delete fallback APP vbhash probe key {alias}: {error:?}");
    }
    extracted
}

fn generate_blob_attested_key(
    security_level: &Strong<dyn IKeystoreSecurityLevel>,
) -> Result<KeyMetadata> {
    let descriptor = KeyDescriptor {
        domain: Domain::BLOB,
        nspace: 0,
        alias: None,
        blob: None,
    };
    security_level
        .generateKey(&descriptor, None, &attested_ec_params(), 0, &[])
        .context("BLOB attestation key generation failed")
}

fn app_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        nspace: 0,
        alias: Some(alias.to_string()),
        blob: None,
    }
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
            KeyParameterValue::Blob(b"omk-vbmeta-probe".to_vec()),
        ),
    ]
}

fn kp(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn extract_verified_boot_hash_from_metadata(metadata: &KeyMetadata) -> Result<[u8; 32]> {
    let leaf = metadata
        .certificate
        .as_deref()
        .ok_or_else(|| anyhow!("attestation leaf certificate missing"))?;
    extract_verified_boot_hash_from_leaf_certificate(leaf)
}

fn extract_verified_boot_hash_from_leaf_certificate(leaf: &[u8]) -> Result<[u8; 32]> {
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| anyhow!("attestation leaf has no extensions"))?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == ANDROID_ATTESTATION_OID)
        .ok_or_else(|| anyhow!("Android attestation extension missing"))?;
    extract_verified_boot_hash_from_attestation_extension(extension.extn_value.as_bytes())
}

fn extract_verified_boot_hash_from_attestation_extension(bytes: &[u8]) -> Result<[u8; 32]> {
    let (top_level, rest) = parse_tlv(bytes)?;
    ensure_sequence(top_level, "attestation extension")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after attestation extension");
    }

    let mut fields = top_level.value;
    for _ in 0..6 {
        let (_, next) = parse_tlv(fields)?;
        fields = next;
    }

    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (hardware_enforced, rest) = parse_tlv(fields)?;
    ensure_sequence(hardware_enforced, "hardwareEnforced")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after hardwareEnforced");
    }

    extract_verified_boot_hash_from_authorization_list(hardware_enforced.value)
}

fn extract_verified_boot_hash_from_authorization_list(mut bytes: &[u8]) -> Result<[u8; 32]> {
    while !bytes.is_empty() {
        let (field, rest) = parse_tlv(bytes)?;
        bytes = rest;
        if field.class == TlvClass::ContextSpecific && field.tag_number == 704 {
            return extract_verified_boot_hash_from_root_of_trust(field.value);
        }
    }

    Err(anyhow!("RootOfTrust tag 704 missing from authorization list"))
}

fn extract_verified_boot_hash_from_root_of_trust(bytes: &[u8]) -> Result<[u8; 32]> {
    let (sequence, rest) = parse_tlv(bytes)?;
    ensure_sequence(sequence, "RootOfTrust")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after RootOfTrust");
    }

    let mut fields = sequence.value;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (verified_boot_hash, rest) = parse_tlv(fields)?;
    ensure_octet_string(verified_boot_hash, "RootOfTrust.verifiedBootHash")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after verifiedBootHash");
    }

    if verified_boot_hash.value.len() != 32 {
        bail!(
            "verifiedBootHash must be 32 bytes, got {}",
            verified_boot_hash.value.len()
        );
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(verified_boot_hash.value);
    Ok(bytes)
}

fn parse_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if input.is_empty() {
        bail!("unexpected end of DER input");
    }

    let first = input[0];
    let class = match first >> 6 {
        0 => TlvClass::Universal,
        1 => TlvClass::Application,
        2 => TlvClass::ContextSpecific,
        _ => TlvClass::Private,
    };
    let constructed = (first & 0x20) != 0;
    let mut tag_number = u32::from(first & 0x1f);
    let mut offset = 1usize;

    if tag_number == 0x1f {
        tag_number = 0;
        loop {
            if offset >= input.len() {
                bail!("truncated high-tag DER field");
            }
            let byte = input[offset];
            offset += 1;
            tag_number = (tag_number << 7) | u32::from(byte & 0x7f);
            if (byte & 0x80) == 0 {
                break;
            }
        }
    }

    let (length, length_bytes) = parse_der_length(&input[offset..])?;
    offset += length_bytes;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("DER length overflow"))?;
    if end > input.len() {
        bail!("DER field exceeds remaining input");
    }

    Ok((
        Tlv {
            class,
            constructed,
            tag_number,
            value: &input[offset..end],
        },
        &input[end..],
    ))
}

fn parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        bail!("missing DER length");
    }
    let first = input[0];
    if (first & 0x80) == 0 {
        return Ok((usize::from(first), 1));
    }

    let count = usize::from(first & 0x7f);
    if count == 0 {
        bail!("indefinite DER lengths are not supported");
    }
    if count > std::mem::size_of::<usize>() || input.len() < count + 1 {
        bail!("invalid DER length encoding");
    }

    let mut value = 0usize;
    for byte in &input[1..=count] {
        value = (value << 8) | usize::from(*byte);
    }
    Ok((value, count + 1))
}

fn ensure_sequence(field: Tlv<'_>, label: &str) -> Result<()> {
    if field.class == TlvClass::Universal && field.constructed && field.tag_number == 16 {
        Ok(())
    } else {
        bail!("{label} is not a DER SEQUENCE")
    }
}

fn ensure_octet_string(field: Tlv<'_>, label: &str) -> Result<()> {
    if field.class == TlvClass::Universal && !field.constructed && field.tag_number == 4 {
        Ok(())
    } else {
        bail!("{label} is not a DER OCTET STRING")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avb_public_key_digest_matches_embedded_blob_hash() {
        let public_key = b"test-public-key-material";
        let vbmeta = build_test_vbmeta(public_key, 64, 96);
        let digest = compute_vbmeta_public_key_digest_from_bytes(&vbmeta).unwrap();
        let expected = BoringSha256 {}.hash(public_key).unwrap();
        assert_eq!(digest, expected);
    }

    #[test]
    fn attestation_extension_parser_extracts_verified_boot_hash() {
        let expected = [0xabu8; 32];
        let extension = build_test_attestation_extension(expected);
        let parsed = extract_verified_boot_hash_from_attestation_extension(&extension).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn trust_record_persists_only_deterministic_sources() {
        let mut record = TrustRecord::default();
        let vb_key = ResolvedField {
            value: [0x11; 32],
            source: TrustValueSource::Computed,
        };
        let vb_hash = ResolvedField {
            value: [0x22; 32],
            source: TrustValueSource::Original,
        };
        let expected_vb_key = hex::encode([0x11; 32]);
        let expected_vb_hash = hex::encode([0x22; 32]);

        update_trust_record(&mut record, "fingerprint", "_b", &vb_key, &vb_hash);

        assert_eq!(record.vb_key.as_deref(), Some(expected_vb_key.as_str()));
        assert_eq!(record.vb_key_source, Some(TrustValueSource::Computed));
        assert_eq!(record.vb_hash.as_deref(), Some(expected_vb_hash.as_str()));
        assert_eq!(record.vb_hash_source, Some(TrustValueSource::Original));
        assert_eq!(record.build_fingerprint.as_deref(), Some("fingerprint"));
        assert_eq!(record.slot_suffix.as_deref(), Some("_b"));
    }

    #[test]
    fn trust_record_skips_random_sources() {
        let mut record = TrustRecord::default();
        let vb_key = ResolvedField {
            value: [0x33; 32],
            source: TrustValueSource::RandomExplicit,
        };
        let vb_hash = ResolvedField {
            value: [0x44; 32],
            source: TrustValueSource::RandomFallback,
        };

        update_trust_record(&mut record, "fingerprint", "_a", &vb_key, &vb_hash);

        assert!(record.is_empty());
    }

    #[test]
    fn random_sources_still_require_sysprop_writeback() {
        assert!(TrustValueSource::RandomExplicit.needs_sysprop_write());
        assert!(TrustValueSource::RandomFallback.needs_sysprop_write());
        assert!(!TrustValueSource::ExplicitHex.needs_sysprop_write());
        assert!(!TrustValueSource::Property.needs_sysprop_write());
    }

    fn build_test_vbmeta(public_key: &[u8], auth_block_size: usize, aux_block_size: usize) -> Vec<u8> {
        let total_size = AVB_HEADER_SIZE + auth_block_size + aux_block_size;
        let mut blob = vec![0u8; total_size];
        blob[..4].copy_from_slice(b"AVB0");
        blob[12..20].copy_from_slice(&(auth_block_size as u64).to_be_bytes());
        blob[20..28].copy_from_slice(&(aux_block_size as u64).to_be_bytes());
        blob[64..72].copy_from_slice(&(0u64).to_be_bytes());
        blob[72..80].copy_from_slice(&(public_key.len() as u64).to_be_bytes());
        let start = AVB_HEADER_SIZE + auth_block_size;
        blob[start..start + public_key.len()].copy_from_slice(public_key);
        blob
    }

    fn build_test_attestation_extension(hash: [u8; 32]) -> Vec<u8> {
        let root_of_trust = encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &[
                encode_tlv(TlvClass::Universal, false, 4, &[0x11; 32]),
                encode_tlv(TlvClass::Universal, false, 1, &[0xff]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x00]),
                encode_tlv(TlvClass::Universal, false, 4, &hash),
            ]
            .concat(),
        );

        let sw = encode_tlv(TlvClass::Universal, true, 16, &[]);
        let hw = encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &encode_tlv(TlvClass::ContextSpecific, true, 704, &root_of_trust),
        );

        encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &[
                encode_tlv(TlvClass::Universal, false, 2, &[0x03]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 2, &[0x64]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 4, b"challenge"),
                encode_tlv(TlvClass::Universal, false, 4, b"unique"),
                sw,
                hw,
            ]
            .concat(),
        )
    }

    fn encode_tlv(class: TlvClass, constructed: bool, tag_number: u32, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let class_bits = match class {
            TlvClass::Universal => 0u8,
            TlvClass::Application => 1u8 << 6,
            TlvClass::ContextSpecific => 2u8 << 6,
            TlvClass::Private => 3u8 << 6,
        };
        let constructed_bit = if constructed { 0x20 } else { 0x00 };
        if tag_number < 31 {
            out.push(class_bits | constructed_bit | tag_number as u8);
        } else {
            out.push(class_bits | constructed_bit | 0x1f);
            let mut stack = Vec::new();
            let mut value_bits = tag_number;
            stack.push((value_bits & 0x7f) as u8);
            value_bits >>= 7;
            while value_bits != 0 {
                stack.push(((value_bits & 0x7f) as u8) | 0x80);
                value_bits >>= 7;
            }
            for byte in stack.iter().rev() {
                out.push(*byte);
            }
        }

        encode_length(value.len(), &mut out);
        out.extend_from_slice(value);
        out
    }

    fn encode_length(length: usize, out: &mut Vec<u8>) {
        if length < 0x80 {
            out.push(length as u8);
            return;
        }

        let mut bytes = Vec::new();
        let mut remaining = length;
        while remaining != 0 {
            bytes.push((remaining & 0xff) as u8);
            remaining >>= 8;
        }
        out.push(0x80 | (bytes.len() as u8));
        for byte in bytes.iter().rev() {
            out.push(*byte);
        }
    }
}
