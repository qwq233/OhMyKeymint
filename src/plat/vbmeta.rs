use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::crypto::{Rng, Sha256};
use kmr_crypto_boring::{rng::BoringRng, sha256::BoringSha256};
use rsbinder::Strong;

use crate::{
    android::{
        hardware::security::keymint::{
            Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyParameter::KeyParameter,
            KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
            SecurityLevel::SecurityLevel, Tag::Tag,
        },
        system::keystore2::{
            Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
            KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
        },
    },
    config::{
        ConfigFile, OsVersionSpec, RawTrustConfig, ResolvedTrust, TrustValueSource, TrustValueSpec,
    },
    plat::{attestation, resetprop, utils::get_keystore_service},
};

const SECURITY_PATCH_PROP: &str = "ro.build.version.security_patch";
const SECURITY_PATCH_FALLBACK: &str = "2025-06-05";
const VENDOR_PATCH_PROP: &str = "ro.vendor.build.security_patch";
const BOOT_PATCH_PROP: &str = "ro.vendor.boot_security_patch";
const VBMETA_KEY_PROP: &str = "ro.boot.vbmeta.public_key_digest";
const VBMETA_HASH_PROP: &str = "ro.boot.vbmeta.digest";
const ORIGINAL_HASH_TIMEOUT: Duration = Duration::from_secs(5);
const AVB_HEADER_SIZE: usize = 256;
const AVB_FOOTER_SIZE: usize = 64;
const AVB_MAX_VBMETA_SIZE: usize = 64 * 1024;
const AVB_VERSION_MAJOR: u32 = 1;
const AVB_VERSION_MINOR: u32 = 4;
const AVB_DESCRIPTOR_SIZE: usize = 16;
const AVB_PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const AVB_PROPERTY_TAG: u64 = 0;
const BOOT_AVB_PROPERTY: &[u8] = b"com.android.build.boot.security_patch";
const BOOT_HEADER_PREFIX_SIZE: usize = 48;
const BOOT_HEADER_VERSION_OFFSET: usize = 40;
const BOOT_HEADER_V3_OS_VERSION_OFFSET: usize = 16;
const BOOT_HEADER_LEGACY_OS_VERSION_OFFSET: usize = 44;
const BUILD_PROP_PATHS: &[&str] = &[
    "/system/build.prop",
    "/system/system/build.prop",
    "/product/build.prop",
    "/system_ext/build.prop",
    "/vendor/build.prop",
    "/odm/build.prop",
    "/vendor/default.prop",
    "/default.prop",
];

#[derive(Clone)]
struct ResolvedField {
    value: [u8; 32],
    source: TrustValueSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPatchLevels {
    pub security_patch: String,
    pub os_patchlevel: String,
    pub vendor_patchlevel: String,
    pub boot_patchlevel: String,
    pub observed_security_patch: Option<String>,
    pub write_security_patch: bool,
}

pub fn bootstrap_vbmeta(config_file: &mut ConfigFile) -> Result<ResolvedTrust> {
    let slot_suffix = resetprop::read_string_property("ro.boot.slot_suffix").unwrap_or_default();
    let patches = resolve_patch_levels(&config_file.trust)?;
    let os_version = match config_file.trust.os_version {
        OsVersionSpec::Auto => kmr_common::android_version::android_major_version().unwrap_or(16),
        OsVersionSpec::Fixed(value) => value,
    };

    let vb_key =
        resolve_vb_key(&config_file.trust.vb_key, config_file.trust.device_locked, &slot_suffix);
    let vb_hash = resolve_vb_hash(&config_file.trust.vb_hash);

    let pinned = pin_random_fallback_values(config_file, &vb_key, &vb_hash);
    if pinned {
        crate::config::persist_config_file(config_file)
            .context("failed to pin random fallback vbmeta trust values")?;
        log::info!("Pinned random fallback vbmeta trust values in config.toml");
    }

    sync_sysprops_if_needed(&vb_key, &vb_hash);
    if patches.write_security_patch {
        write_security_patch_with_rollback(
            resetprop::direct_write_and_verify_property,
            resetprop::read_string_property,
            &patches.security_patch,
            patches.observed_security_patch.as_deref(),
        )?;
    }

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
        os_version,
        security_patch: patches.security_patch,
        os_patchlevel: patches.os_patchlevel,
        vendor_patchlevel: patches.vendor_patchlevel,
        boot_patchlevel: patches.boot_patchlevel,
        vb_key: vb_key.value,
        vb_hash: vb_hash.value,
        vb_key_source: vb_key.source,
        vb_hash_source: vb_hash.source,
        verified_boot_state: config_file.trust.verified_boot_state,
        device_locked: config_file.trust.device_locked,
    })
}

pub(crate) fn write_runtime_security_patch(desired: &str, previous: Option<&str>) -> Result<()> {
    write_security_patch_with_rollback(
        resetprop::runtime_write_and_verify_property,
        resetprop::read_string_property,
        desired,
        previous,
    )
}

fn resolve_vb_key(spec: &TrustValueSpec, device_locked: bool, slot_suffix: &str) -> ResolvedField {
    match spec {
        TrustValueSpec::Hex(value) => {
            ResolvedField { value: *value, source: TrustValueSource::ExplicitHex }
        }
        TrustValueSpec::Random => random_field(TrustValueSource::RandomExplicit),
        TrustValueSpec::Auto => {
            if let Some(value) = read_hex_property(VBMETA_KEY_PROP) {
                return ResolvedField { value, source: TrustValueSource::Property };
            }

            match compute_vbmeta_public_key_digest(slot_suffix, device_locked) {
                Ok(value) => ResolvedField { value, source: TrustValueSource::Computed },
                Err(error) => {
                    log::warn!("computed vbmeta public key digest unavailable: {error:#}");
                    random_field(TrustValueSource::RandomFallback)
                }
            }
        }
    }
}

fn resolve_vb_hash(spec: &TrustValueSpec) -> ResolvedField {
    match spec {
        TrustValueSpec::Hex(value) => {
            ResolvedField { value: *value, source: TrustValueSource::ExplicitHex }
        }
        TrustValueSpec::Random => random_field(TrustValueSource::RandomExplicit),
        TrustValueSpec::Auto => {
            if let Some(value) = read_hex_property(VBMETA_HASH_PROP) {
                return ResolvedField { value, source: TrustValueSource::Property };
            }

            match probe_original_verified_boot_hash_with_timeout(ORIGINAL_HASH_TIMEOUT) {
                Ok(value) => ResolvedField { value, source: TrustValueSource::Original },
                Err(error) => {
                    log::warn!("original verified boot hash unavailable: {error:#}");
                    random_field(TrustValueSource::RandomFallback)
                }
            }
        }
    }
}

fn pin_random_fallback_values(
    config_file: &mut ConfigFile,
    vb_key: &ResolvedField,
    vb_hash: &ResolvedField,
) -> bool {
    let mut pinned = false;
    if vb_key.source == TrustValueSource::RandomFallback {
        config_file.trust.vb_key = TrustValueSpec::Hex(vb_key.value);
        pinned = true;
    }
    if vb_hash.source == TrustValueSource::RandomFallback {
        config_file.trust.vb_hash = TrustValueSpec::Hex(vb_hash.value);
        pinned = true;
    }
    pinned
}

fn random_field(source: TrustValueSource) -> ResolvedField {
    let mut rng = BoringRng {};
    let mut value = [0u8; 32];
    rng.fill_bytes(&mut value);
    ResolvedField { value, source }
}

pub(crate) fn resolve_patch_levels(trust: &RawTrustConfig) -> Result<ResolvedPatchLevels> {
    let observed_security_patch = resetprop::read_string_property(SECURITY_PATCH_PROP);
    let security_patch =
        observed_security_patch.clone().or_else(|| read_build_prop_value(SECURITY_PATCH_PROP));
    if security_patch.is_none() {
        log::warn!(
            "failed to read {SECURITY_PATCH_PROP} from properties or build.prop; using {SECURITY_PATCH_FALLBACK}"
        );
    }
    let vendor_patch = resetprop::read_string_property(VENDOR_PATCH_PROP)
        .or_else(|| read_build_prop_value(VENDOR_PATCH_PROP));
    let property_boot_patch = resetprop::read_string_property(BOOT_PATCH_PROP)
        .or_else(|| read_build_prop_value(BOOT_PATCH_PROP));
    let boot_patch = if trust.boot_patchlevel.trim() == "auto" {
        match read_abl_boot_patchlevel() {
            Ok(value) => Some(value),
            Err(error) => {
                log::warn!(
                    "failed to resolve boot patch level from boot metadata: {error:#}; using property fallback"
                );
                property_boot_patch
            }
        }
    } else {
        property_boot_patch
    };
    let latest = [
        trust.security_patch.as_str(),
        trust.os_patchlevel.as_str(),
        trust.vendor_patchlevel.as_str(),
        trust.boot_patchlevel.as_str(),
    ]
    .iter()
    .any(|value| value.trim() == "latest")
    .then(current_patchlevel)
    .transpose()?;
    resolve_patch_levels_from(
        trust,
        security_patch.as_deref(),
        vendor_patch.as_deref(),
        boot_patch.as_deref(),
        observed_security_patch.as_deref(),
        latest.as_deref(),
    )
}

fn resolve_patch_levels_from(
    trust: &RawTrustConfig,
    security_property: Option<&str>,
    vendor_property: Option<&str>,
    boot_property: Option<&str>,
    observed_security_property: Option<&str>,
    latest: Option<&str>,
) -> Result<ResolvedPatchLevels> {
    let security_auto = security_property.unwrap_or(SECURITY_PATCH_FALLBACK);
    let security_patch =
        resolve_security_patch_value(&trust.security_patch, security_auto, latest)?;
    let os_patchlevel =
        resolve_patchlevel_mode("os_patchlevel", &trust.os_patchlevel, &security_patch, latest)?;
    let vendor_auto = vendor_property.unwrap_or(&os_patchlevel);
    let vendor_patchlevel = resolve_patchlevel_mode(
        "vendor_patchlevel",
        &trust.vendor_patchlevel,
        vendor_auto,
        latest,
    )?;
    let boot_auto = boot_property.unwrap_or(&os_patchlevel);
    let boot_patchlevel =
        resolve_patchlevel_mode("boot_patchlevel", &trust.boot_patchlevel, boot_auto, latest)?;
    let write_security_patch = observed_security_property.is_some()
        && trust.security_patch.trim() != "auto"
        && observed_security_property != Some(security_patch.as_str());

    Ok(ResolvedPatchLevels {
        security_patch,
        os_patchlevel,
        vendor_patchlevel,
        boot_patchlevel,
        observed_security_patch: observed_security_property.map(str::to_string),
        write_security_patch,
    })
}

fn resolve_security_patch_value(mode: &str, auto: &str, latest: Option<&str>) -> Result<String> {
    match mode.trim() {
        "auto" => Ok(auto.to_string()),
        "latest" => latest
            .map(str::to_string)
            .ok_or_else(|| anyhow!("latest value was not resolved for security_patch")),
        value if crate::config::is_security_patch_date(value) => Ok(value.to_string()),
        value => Err(anyhow!("invalid security_patch value: {value}")),
    }
}

fn resolve_patchlevel_mode(
    field: &str,
    mode: &str,
    auto: &str,
    latest: Option<&str>,
) -> Result<String> {
    match mode.trim() {
        "auto" => Ok(auto.to_string()),
        "latest" => latest
            .map(str::to_string)
            .ok_or_else(|| anyhow!("latest value was not resolved for {field}")),
        value if !value.is_empty() => Ok(value.to_string()),
        value => Err(anyhow!("invalid {field} value: {value}")),
    }
}

fn current_patchlevel() -> Result<String> {
    let (year, month) = current_year_month()?;
    Ok(format!("{year:04}-{month:02}-05"))
}

fn read_build_prop_value(key: &str) -> Option<String> {
    BUILD_PROP_PATHS.iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|contents| parse_build_prop_value(&contents, key))
    })
}

fn parse_build_prop_value(contents: &str, key: &str) -> Option<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let (candidate_key, candidate_value) = line.split_once('=')?;
            (candidate_key.trim() == key).then(|| candidate_value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

fn write_security_patch_with_rollback<W, R>(
    mut writer: W,
    reader: R,
    desired: &str,
    previous: Option<&str>,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
{
    let previous = previous
        .ok_or_else(|| anyhow!("{SECURITY_PATCH_PROP} is missing; refusing to create it"))?;
    let current = reader(SECURITY_PATCH_PROP)
        .ok_or_else(|| anyhow!("{SECURITY_PATCH_PROP} disappeared; refusing to create it"))?;
    if current != previous {
        bail!(
            "{SECURITY_PATCH_PROP} changed while the update was prepared; refusing to overwrite it"
        );
    }

    let write_error = match writer(SECURITY_PATCH_PROP, desired) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    let actual = reader(SECURITY_PATCH_PROP);
    if actual.as_deref() == Some(desired) {
        log::warn!("security patch writer returned an error, but the desired value was verified");
        return Ok(());
    }
    if actual.as_deref() == Some(previous) {
        return Err(write_error).context("security patch write failed without changing property");
    }
    if actual.is_none() {
        return Err(write_error)
            .context("security patch write failed and property disappeared; rollback skipped");
    }

    let rollback_error = writer(SECURITY_PATCH_PROP, previous).err();
    let actual = reader(SECURITY_PATCH_PROP);
    if actual.as_deref() == Some(previous) {
        return Err(write_error).context("security patch write failed; previous state restored");
    }
    if actual.as_deref() == Some(desired) {
        log::warn!(
            "security patch rollback could not be confirmed, but the desired value was verified"
        );
        return Ok(());
    }
    Err(anyhow!(
        "security patch write failed: {write_error:#}; rollback failed: {}; current property state: {}",
        rollback_error
            .map(|error| format!("{error:#}"))
            .unwrap_or_else(|| "property verification did not restore the previous state".into()),
        actual.as_deref().unwrap_or("<missing>")
    ))
}

fn current_year_month() -> Result<(i32, u32)> {
    #[cfg(unix)]
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        if now < 0 {
            bail!("libc::time returned a negative timestamp");
        }
        let mut local = std::mem::zeroed::<libc::tm>();
        if libc::localtime_r(&now, &mut local).is_null() {
            bail!("libc::localtime_r failed");
        }
        Ok((local.tm_year + 1900, (local.tm_mon + 1) as u32))
    }

    #[cfg(not(unix))]
    {
        Err(anyhow!("current_year_month is unsupported on this platform"))
    }
}

fn sync_sysprops_if_needed(vb_key: &ResolvedField, vb_hash: &ResolvedField) {
    for (name, field) in [(VBMETA_KEY_PROP, vb_key), (VBMETA_HASH_PROP, vb_hash)] {
        let result = sync_sysprop_with_runtime_property(
            name,
            field,
            resetprop::read_string_property,
            resetprop::direct_write_and_verify_property,
        );
        if let Err(error) = result {
            // A failed sysprop re-write only degrades attested-versus-runtime
            // consistency; it must not keep keymint from serving keys.
            log::warn!("failed to sync {name} with resolved trust value: {error:#}");
        }
    }
}

/// Re-apply a resolved trust value whenever the live system property does not already
/// carry it.
///
/// init rebuilds the property area from the kernel command line on every boot, so a
/// value that was not sourced from the live property itself (explicit config hex, a
/// pinned random fallback, a computed digest, or an original-TEE probe) must be
/// rewritten on every keymint start. Otherwise the value written on the first boot
/// disappears after the next reboot while attestation keeps reporting the pinned
/// value: on devices whose bootloader passes no `androidboot.vbmeta.digest` (for
/// example MuMu) `ro.boot.vbmeta.digest` reads empty again from the second boot
/// onward. This mirrors TEESimulator-RS, which re-runs `resetprop` for its persisted
/// boot hash whenever the runtime property does not already hold the value in use.
fn sync_sysprop_with_runtime_property(
    name: &str,
    field: &ResolvedField,
    read_property: impl Fn(&str) -> Option<String>,
    write_property: impl FnOnce(&str, &str) -> Result<()>,
) -> Result<()> {
    let value = hex::encode(field.value);
    if runtime_property_matches(read_property(name).as_deref(), &value) {
        log::debug!("runtime property {name} already carries the resolved trust value");
        return Ok(());
    }
    log::info!("rewriting {name} to match the resolved trust value (source={})", field.source);
    write_property(name, &value)
}

/// True when the live property already carries `value`, ignoring case and surrounding
/// whitespace.
fn runtime_property_matches(current: Option<&str>, value: &str) -> bool {
    match current.map(str::trim) {
        Some(current) => !current.is_empty() && current.eq_ignore_ascii_case(value),
        None => false,
    }
}

fn read_hex_property(name: &str) -> Option<[u8; 32]> {
    let value = resetprop::read_string_property(name)?;
    parse_hex_32(&value)
        .map_err(|error| {
            log::warn!("ignoring invalid property {name}={value}: {error:#}");
        })
        .ok()
}

fn parse_hex_32(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("invalid hex value {value}"))?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| anyhow!("hex value must be 32 bytes, got {}", decoded.len()))
}

fn read_abl_boot_patchlevel() -> Result<String> {
    let slot_suffix = resetprop::read_string_property("ro.boot.slot_suffix").unwrap_or_default();
    let boot_path = find_avb_partition_path(&slot_suffix, "boot")
        .context("failed to locate active boot partition")?;
    read_abl_boot_patchlevel_from_paths(find_top_level_vbmeta_path(&slot_suffix), &boot_path)
        .map(|value| value.to_string())
}

fn read_abl_boot_patchlevel_from_paths(
    top_level_path: Result<PathBuf>,
    boot_path: &Path,
) -> Result<u32> {
    let top_level_error = match top_level_path {
        Ok(path) => {
            let top_level = load_vbmeta_blob(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            if let Some(value) = vbmeta_boot_patchlevel(&top_level)? {
                return Ok(value);
            }
            None
        }
        Err(error) => {
            log::debug!("failed to locate top-level vbmeta; checking boot image: {error:#}");
            Some(error)
        }
    };

    match load_embedded_vbmeta_blob(boot_path) {
        Ok(embedded) => {
            if let Some(value) = vbmeta_boot_patchlevel(&embedded)? {
                return Ok(value);
            }
        }
        Err(error) => {
            if let Some(top_level_error) = top_level_error {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read top-level vbmeta from {} after {top_level_error:#}",
                        boot_path.display()
                    )
                });
            }
            log::debug!(
                "failed to read embedded boot vbmeta from {}; using boot header: {error:#}",
                boot_path.display()
            );
        }
    }
    read_boot_header_patchlevel(boot_path)
}

fn vbmeta_boot_patchlevel(vbmeta: &[u8]) -> Result<Option<u32>> {
    if let Some(value) = avb_property_value(vbmeta, BOOT_AVB_PROPERTY)? {
        return parse_boot_patchlevel_property(value)
            .map(Some)
            .ok_or_else(|| anyhow!("invalid com.android.build.boot.security_patch AVB property"));
    }
    Ok(None)
}

fn avb_property_value<'a>(vbmeta: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut descriptors = avb_descriptors(vbmeta)?;
    while !descriptors.is_empty() {
        let descriptor = take_avb_descriptor(&mut descriptors)?;
        if be_u64(&descriptor[..8])? as u64 != AVB_PROPERTY_TAG
            || descriptor.len() < AVB_PROPERTY_DESCRIPTOR_SIZE
        {
            continue;
        }

        let key_len = be_u64(&descriptor[16..24])?;
        let value_len = be_u64(&descriptor[24..32])?;
        let Some(key_end) = AVB_PROPERTY_DESCRIPTOR_SIZE.checked_add(key_len) else {
            continue;
        };
        let Some(value_start) = key_end.checked_add(1) else {
            continue;
        };
        let Some(value_end) = value_start.checked_add(value_len) else {
            continue;
        };
        let Some(value_nul) = value_end.checked_add(1) else {
            continue;
        };
        if value_nul > descriptor.len()
            || descriptor.get(key_end) != Some(&0)
            || descriptor.get(value_end) != Some(&0)
        {
            continue;
        }
        if descriptor.get(AVB_PROPERTY_DESCRIPTOR_SIZE..key_end) == Some(key) {
            return Ok(descriptor.get(value_start..value_end));
        }
    }
    Ok(None)
}

fn avb_descriptors(vbmeta: &[u8]) -> Result<&[u8]> {
    let total_size = validated_vbmeta_size(vbmeta)?;
    if total_size > vbmeta.len() {
        bail!("vbmeta block sizes exceed the available data");
    }

    let auth_block_size = be_u64(&vbmeta[12..20])?;
    let aux_block_size = be_u64(&vbmeta[20..28])?;
    let descriptors_offset = be_u64(&vbmeta[96..104])?;
    let descriptors_size = be_u64(&vbmeta[104..112])?;
    let aux_start = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .ok_or_else(|| anyhow!("vbmeta auxiliary block start overflow"))?;
    let aux_end = aux_start
        .checked_add(aux_block_size)
        .ok_or_else(|| anyhow!("vbmeta auxiliary block end overflow"))?;
    let descriptors_start = aux_start
        .checked_add(descriptors_offset)
        .ok_or_else(|| anyhow!("vbmeta descriptor start overflow"))?;
    let descriptors_end = descriptors_start
        .checked_add(descriptors_size)
        .ok_or_else(|| anyhow!("vbmeta descriptor end overflow"))?;
    if aux_end > total_size || descriptors_end > aux_end {
        bail!("vbmeta descriptor range is outside the auxiliary block");
    }
    Ok(&vbmeta[descriptors_start..descriptors_end])
}

fn take_avb_descriptor<'a>(descriptors: &mut &'a [u8]) -> Result<&'a [u8]> {
    if descriptors.len() < AVB_DESCRIPTOR_SIZE {
        bail!("truncated AVB descriptor header");
    }
    let bytes_following = be_u64(&descriptors[8..16])?;
    if bytes_following & 7 != 0 {
        bail!("AVB descriptor size is not divisible by 8");
    }
    let total_size = AVB_DESCRIPTOR_SIZE
        .checked_add(bytes_following)
        .ok_or_else(|| anyhow!("AVB descriptor size overflow"))?;
    if total_size > descriptors.len() {
        bail!("AVB descriptor exceeds the descriptor block");
    }
    let (descriptor, remaining) = descriptors.split_at(total_size);
    *descriptors = remaining;
    Ok(descriptor)
}

fn parse_boot_patchlevel_property(value: &[u8]) -> Option<u32> {
    crate::keymaster::keymint_device::extract_patchlevel(std::str::from_utf8(value).ok()?).ok()
}

fn read_boot_header_patchlevel(path: &Path) -> Result<u32> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open boot image {}", path.display()))?;
    let mut header = [0u8; BOOT_HEADER_PREFIX_SIZE];
    file.read_exact(&mut header)
        .with_context(|| format!("failed to read boot image header from {}", path.display()))?;
    boot_header_patchlevel(&header)
}

fn boot_header_patchlevel(header: &[u8]) -> Result<u32> {
    if header.len() < BOOT_HEADER_PREFIX_SIZE || &header[..8] != b"ANDROID!" {
        bail!("invalid boot image header");
    }

    let header_version =
        le_u32(&header[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4])?;
    let os_version_offset = if header_version >= 3 {
        if header_version > 4 {
            bail!("unsupported boot image header version {header_version}");
        }
        BOOT_HEADER_V3_OS_VERSION_OFFSET
    } else {
        BOOT_HEADER_LEGACY_OS_VERSION_OFFSET
    };
    let os_version = le_u32(&header[os_version_offset..os_version_offset + 4])?;
    let year = 2000 + ((os_version >> 4) & 0x7f);
    let month = os_version & 0xf;
    Ok(year * 10_000 + month * 100)
}

fn validated_vbmeta_size(header: &[u8]) -> Result<usize> {
    if header.len() < AVB_HEADER_SIZE || &header[..4] != b"AVB0" {
        bail!("invalid vbmeta header");
    }
    let required_major = be_u32(&header[4..8])?;
    let required_minor = be_u32(&header[8..12])?;
    if required_major != AVB_VERSION_MAJOR || required_minor > AVB_VERSION_MINOR {
        bail!("unsupported required libavb version {required_major}.{required_minor}");
    }
    if header[175] != 0 {
        bail!("vbmeta release string is not NUL-terminated");
    }

    let auth_block_size = be_u64(&header[12..20])?;
    let aux_block_size = be_u64(&header[20..28])?;
    if auth_block_size & 63 != 0 || aux_block_size & 63 != 0 {
        bail!("vbmeta inner block size is not divisible by 64");
    }
    let total_size = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .and_then(|value| value.checked_add(aux_block_size))
        .ok_or_else(|| anyhow!("vbmeta size overflow"))?;
    if total_size > AVB_MAX_VBMETA_SIZE {
        bail!("vbmeta image exceeds the 64 KiB libavb limit");
    }
    Ok(total_size)
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
    find_avb_partition_path(slot_suffix, "vbmeta")
}

fn find_avb_partition_path(slot_suffix: &str, partition_name: &str) -> Result<PathBuf> {
    let mut names = Vec::with_capacity(2);
    if !slot_suffix.is_empty() {
        names.push(format!("{partition_name}{slot_suffix}"));
    }
    names.push(partition_name.to_string());

    for candidate in names.into_iter().flat_map(|name| {
        [
            PathBuf::from(format!("/dev/block/by-name/{name}")),
            PathBuf::from(format!("/dev/block/bootdevice/by-name/{name}")),
        ]
    }) {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(anyhow!("no {partition_name} partition found for slot suffix '{slot_suffix}'"))
}

fn load_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open vbmeta image {}", path.display()))?;
    load_vbmeta_blob_at(&mut file, 0, None)
        .with_context(|| format!("failed to load vbmeta image {}", path.display()))
}

fn load_embedded_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open partition {}", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("failed to read partition magic from {}", path.display()))?;
    if &magic == b"AVB0" {
        return load_vbmeta_blob_at(&mut file, 0, None)
            .with_context(|| format!("failed to load standalone vbmeta from {}", path.display()));
    }

    let partition_size = file
        .seek(SeekFrom::End(0))
        .with_context(|| format!("failed to determine partition size for {}", path.display()))?;
    let footer_offset = partition_size
        .checked_sub(AVB_FOOTER_SIZE as u64)
        .ok_or_else(|| anyhow!("partition is smaller than an AVB footer"))?;
    file.seek(SeekFrom::Start(footer_offset)).context("failed to seek to AVB footer")?;
    let mut footer = [0u8; AVB_FOOTER_SIZE];
    file.read_exact(&mut footer).context("failed to read AVB footer")?;
    if &footer[..4] != b"AVBf" {
        bail!("partition has neither AVB0 header nor AVBf footer");
    }
    if be_u32(&footer[4..8])? > 1 {
        bail!("unsupported AVB footer major version");
    }

    let vbmeta_offset = be_u64(&footer[20..28])?;
    let vbmeta_size = be_u64(&footer[28..36])?;
    if vbmeta_size < AVB_HEADER_SIZE {
        bail!("AVB footer declares a vbmeta block smaller than its header");
    }
    if vbmeta_size > AVB_MAX_VBMETA_SIZE {
        bail!("AVB footer vbmeta block exceeds the 64 KiB libavb limit");
    }
    let vbmeta_offset_u64 = u64::try_from(vbmeta_offset).context("vbmeta offset is too large")?;
    let vbmeta_size_u64 = u64::try_from(vbmeta_size).context("vbmeta size is too large")?;
    let vbmeta_end = vbmeta_offset_u64
        .checked_add(vbmeta_size_u64)
        .ok_or_else(|| anyhow!("embedded vbmeta range overflow"))?;
    if vbmeta_end > partition_size {
        bail!("embedded vbmeta range exceeds the partition");
    }
    load_vbmeta_blob_at(&mut file, vbmeta_offset_u64, Some(vbmeta_size))
        .with_context(|| format!("failed to load embedded vbmeta from {}", path.display()))
}

fn load_vbmeta_blob_at(
    file: &mut File,
    offset: u64,
    maximum_size: Option<usize>,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).context("failed to seek to vbmeta header")?;
    let mut header = [0u8; AVB_HEADER_SIZE];
    file.read_exact(&mut header).context("failed to read vbmeta header")?;

    let total_size = validated_vbmeta_size(&header)?;
    if let Some(maximum_size) = maximum_size {
        if total_size > maximum_size {
            bail!("vbmeta header exceeds its containing block");
        }
    }

    let mut blob = vec![0u8; total_size];
    blob[..AVB_HEADER_SIZE].copy_from_slice(&header);
    file.read_exact(&mut blob[AVB_HEADER_SIZE..]).with_context(|| {
        format!("failed to read {} bytes of vbmeta data", total_size - AVB_HEADER_SIZE)
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
    let array: [u8; 8] =
        bytes.try_into().map_err(|_| anyhow!("expected 8 bytes, got {}", bytes.len()))?;
    usize::try_from(u64::from_be_bytes(array)).context("value does not fit in usize")
}

fn be_u32(bytes: &[u8]) -> Result<u32> {
    let array: [u8; 4] =
        bytes.try_into().map_err(|_| anyhow!("expected 4 bytes, got {}", bytes.len()))?;
    Ok(u32::from_be_bytes(array))
}

fn le_u32(bytes: &[u8]) -> Result<u32> {
    let array: [u8; 4] =
        bytes.try_into().map_err(|_| anyhow!("expected 4 bytes, got {}", bytes.len()))?;
    Ok(u32::from_le_bytes(array))
}

fn probe_original_verified_boot_hash_with_timeout(timeout: Duration) -> Result<[u8; 32]> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result =
            probe_original_verified_boot_hash_inner().map_err(|error| format!("{error:#}"));
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
    let service = get_keystore_service().context("failed to connect to system keystore")?;
    let tee = service
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to get system TEE security level")?;

    if let Ok(metadata) = generate_blob_attested_key(&tee) {
        return extract_verified_boot_hash_from_metadata(&metadata);
    }

    let alias = format!(
        "omk-vbhash-probe-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
    );
    let descriptor = app_descriptor(&alias);
    let result = tee.generateKey(&descriptor, None, &attested_ec_params(), 0, &[]);
    let metadata = result.context("fallback APP attestation key generation failed")?;
    let extracted = extract_verified_boot_hash_from_metadata(&metadata);
    if let Err(error) = service.deleteKey(&descriptor) {
        log::warn!("failed to delete fallback APP vbhash probe key {alias}: {error:?}");
    }
    extracted
}

fn generate_blob_attested_key(
    security_level: &Strong<dyn IKeystoreSecurityLevel>,
) -> Result<KeyMetadata> {
    let descriptor = KeyDescriptor { domain: Domain::BLOB, nspace: 0, alias: None, blob: None };
    security_level
        .generateKey(&descriptor, None, &attested_ec_params(), 0, &[])
        .context("BLOB attestation key generation failed")
}

fn app_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor { domain: Domain::APP, nspace: 0, alias: Some(alias.to_string()), blob: None }
}

fn attested_ec_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        kp(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        kp(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        kp(Tag::ATTESTATION_CHALLENGE, KeyParameterValue::Blob(b"omk-vbmeta-probe".to_vec())),
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
    attestation::extract_verified_boot_hash_from_leaf_certificate(leaf)
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
    fn boot_patchlevel_uses_vbmeta_property_then_header() {
        let direct = build_test_vbmeta_with_descriptors(
            0,
            &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-02-01"),
        );
        assert_eq!(vbmeta_boot_patchlevel(&direct).unwrap(), Some(20260201));

        let mut duplicate = build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-13-01");
        duplicate.extend(build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-02-01"));
        let first_invalid = build_test_vbmeta_with_descriptors(0, &duplicate);
        assert!(vbmeta_boot_patchlevel(&first_invalid).is_err());

        let no_property = build_test_vbmeta_with_descriptors(0, &[]);
        assert_eq!(vbmeta_boot_patchlevel(&no_property).unwrap(), None);
    }

    #[test]
    fn boot_patchlevel_uses_embedded_vbmeta_before_header() {
        let dir = tempfile::tempdir().unwrap();
        let top_level_path = dir.path().join("vbmeta");
        let boot_path = dir.path().join("boot");
        std::fs::write(&top_level_path, build_test_vbmeta_with_descriptors(0, &[])).unwrap();

        let embedded = build_test_vbmeta_with_descriptors(
            0,
            &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-02-01"),
        );
        std::fs::write(&boot_path, build_test_boot_image(Some(&embedded))).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20260201
        );

        let mut zero_header = build_test_boot_image(Some(&embedded));
        zero_header[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4].fill(0);
        std::fs::write(&boot_path, zero_header).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20260201
        );
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(
                Err(anyhow!("missing top-level vbmeta")),
                &boot_path,
            )
            .unwrap(),
            20260201
        );

        let embedded_without_property = build_test_vbmeta_with_descriptors(0, &[]);
        std::fs::write(&boot_path, build_test_boot_image(Some(&embedded_without_property)))
            .unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20250900
        );

        std::fs::write(&boot_path, build_test_boot_image(None)).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20250900
        );

        std::fs::write(
            &top_level_path,
            build_test_vbmeta_with_descriptors(
                0,
                &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2027-01-01"),
            ),
        )
        .unwrap();
        let mut zero_header = build_test_boot_image(Some(&embedded));
        zero_header[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4].fill(0);
        std::fs::write(&boot_path, zero_header).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path), &boot_path).unwrap(),
            20270101
        );
    }

    #[test]
    fn boot_header_patchlevel_decodes_legacy_and_modern_headers() {
        for (header_version, offset) in
            [(0u32, BOOT_HEADER_LEGACY_OS_VERSION_OFFSET), (4u32, BOOT_HEADER_V3_OS_VERSION_OFFSET)]
        {
            let mut header = [0u8; BOOT_HEADER_PREFIX_SIZE];
            header[..8].copy_from_slice(b"ANDROID!");
            header[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4]
                .copy_from_slice(&header_version.to_le_bytes());
            let os_version = (25u32 << 4) | 9;
            header[offset..offset + 4].copy_from_slice(&os_version.to_le_bytes());
            assert_eq!(boot_header_patchlevel(&header).unwrap(), 20250900);

            header[offset..offset + 4].fill(0);
            assert_eq!(boot_header_patchlevel(&header).unwrap(), 20000000);
        }
    }

    #[test]
    fn boot_patchlevel_property_uses_aosp_date_parser() {
        for (value, expected) in [
            (b"2025-09-05".as_slice(), Some(20250905)),
            (b"2025-9-5".as_slice(), None),
            (b"  +2025-02-31".as_slice(), None),
            (b"2025-13-01".as_slice(), None),
            (b"2025-12-01x".as_slice(), None),
        ] {
            assert_eq!(parse_boot_patchlevel_property(value), expected, "{value:?}");
        }

        let mut oversized = vec![0u8; AVB_HEADER_SIZE];
        oversized[..4].copy_from_slice(b"AVB0");
        oversized[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        oversized[20..28].copy_from_slice(&(AVB_MAX_VBMETA_SIZE as u64).to_be_bytes());
        assert!(validated_vbmeta_size(&oversized).is_err());

        let mut avb_1_4 = vec![0u8; AVB_HEADER_SIZE];
        avb_1_4[..4].copy_from_slice(b"AVB0");
        avb_1_4[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        avb_1_4[8..12].copy_from_slice(&AVB_VERSION_MINOR.to_be_bytes());
        assert_eq!(validated_vbmeta_size(&avb_1_4).unwrap(), AVB_HEADER_SIZE);
    }

    #[test]
    fn patchlevel_auto_uses_each_aosp_property() {
        let resolved = resolve_patch_levels_from(
            &RawTrustConfig::default(),
            Some("2025-12-01"),
            Some("2025-11-05"),
            Some("2025-10-05"),
            Some("2025-12-01"),
            None,
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "2025-12-01");
        assert_eq!(resolved.os_patchlevel, "2025-12-01");
        assert_eq!(resolved.vendor_patchlevel, "2025-11-05");
        assert_eq!(resolved.boot_patchlevel, "2025-10-05");
        assert!(!resolved.write_security_patch);
    }

    #[test]
    fn patchlevel_sources_are_not_date_filtered_before_wire_conversion() {
        let resolved = resolve_patch_levels_from(
            &RawTrustConfig::default(),
            Some("raw-security"),
            Some("raw-vendor"),
            Some("raw-boot"),
            Some("raw-security"),
            None,
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "raw-security");
        assert_eq!(resolved.os_patchlevel, "raw-security");
        assert_eq!(resolved.vendor_patchlevel, "raw-vendor");
        assert_eq!(resolved.boot_patchlevel, "raw-boot");
    }

    #[test]
    fn patchlevel_fallbacks_and_overrides_are_independent() {
        let trust = RawTrustConfig {
            security_patch: "2026-04-05".to_string(),
            os_patchlevel: "2026-03-05".to_string(),
            vendor_patchlevel: "auto".to_string(),
            boot_patchlevel: "latest".to_string(),
            ..Default::default()
        };
        let resolved = resolve_patch_levels_from(
            &trust,
            Some("2025-12-01"),
            None,
            None,
            Some("2025-12-01"),
            Some("2026-07-05"),
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "2026-04-05");
        assert_eq!(resolved.os_patchlevel, "2026-03-05");
        assert_eq!(resolved.vendor_patchlevel, "2026-03-05");
        assert_eq!(resolved.boot_patchlevel, "2026-07-05");
        assert_eq!(resolved.observed_security_patch.as_deref(), Some("2025-12-01"));
        assert!(resolved.write_security_patch);
    }

    #[test]
    fn build_prop_security_value_is_not_treated_as_a_runtime_property() {
        let trust =
            RawTrustConfig { security_patch: "2026-04-05".to_string(), ..Default::default() };
        let resolved =
            resolve_patch_levels_from(&trust, Some("2025-12-01"), None, None, None, None).unwrap();
        assert_eq!(resolved.security_patch, "2026-04-05");
        assert!(resolved.observed_security_patch.is_none());
        assert!(!resolved.write_security_patch);
    }

    #[test]
    fn build_prop_parser_uses_an_exact_nonempty_key() {
        let contents = r#"
# comment
ro.vendor.boot_security_patch = 2025-10-05
ro.vendor.boot_security_patch.extra = ignored
"#;
        assert_eq!(
            parse_build_prop_value(contents, BOOT_PATCH_PROP).as_deref(),
            Some("2025-10-05")
        );
    }

    #[test]
    fn security_patch_write_accepts_a_verified_lost_ack() {
        let state = std::cell::RefCell::new(Some("2025-12-01".to_string()));
        let result = write_security_patch_with_rollback(
            |_, desired| {
                *state.borrow_mut() = Some(desired.to_string());
                Err(anyhow!("lost acknowledgment"))
            },
            |_| state.borrow().clone(),
            "2026-07-05",
            Some("2025-12-01"),
        );
        assert!(result.is_ok());
        assert_eq!(state.borrow().as_deref(), Some("2026-07-05"));
    }

    #[test]
    fn security_patch_write_refuses_to_create_a_missing_property() {
        let writes = std::cell::Cell::new(0);
        let result = write_security_patch_with_rollback(
            |_, _| {
                writes.set(writes.get() + 1);
                Ok(())
            },
            |_| None,
            "2026-07-05",
            Some("2025-12-01"),
        );
        assert!(result.is_err());
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn pinned_values_resync_an_empty_runtime_property() {
        // Second boot on a device whose bootloader passes no androidboot.vbmeta.digest
        // (for example MuMu): init rebuilt the property area, the config carries the
        // value pinned on the first boot, and the runtime property is empty again.
        let field = ResolvedField { value: [0x22; 32], source: TrustValueSource::ExplicitHex };
        let writes = std::cell::Cell::new(0);
        sync_sysprop_with_runtime_property(
            VBMETA_HASH_PROP,
            &field,
            |_| None,
            |name, value| {
                assert_eq!(name, VBMETA_HASH_PROP);
                assert_eq!(value, hex::encode([0x22; 32]));
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn matching_runtime_property_is_left_alone() {
        // Resolution tier one: the value came from the live property itself, so the
        // runtime property already matches (case-insensitively) and is not rewritten.
        let field = ResolvedField { value: [0x33; 32], source: TrustValueSource::Property };
        let writes = std::cell::Cell::new(0);
        let observed = hex::encode([0x33; 32]).to_uppercase();
        sync_sysprop_with_runtime_property(
            VBMETA_HASH_PROP,
            &field,
            move |_| Some(observed.clone()),
            |_, _| {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn stale_runtime_property_is_rewritten() {
        // A live property that carries a different (here: truncated) digest must be
        // rewritten so the runtime value matches the value used for attestation.
        let field = ResolvedField { value: [0x44; 32], source: TrustValueSource::ExplicitHex };
        let writes = std::cell::Cell::new(0);
        sync_sysprop_with_runtime_property(
            VBMETA_KEY_PROP,
            &field,
            |_| Some("00112233445566778899aabbccddeeff".to_string()),
            |_, _| {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn sysprop_rewrite_failure_surfaces_from_the_sync_helper() {
        let field = ResolvedField { value: [0x55; 32], source: TrustValueSource::RandomFallback };
        let result = sync_sysprop_with_runtime_property(
            VBMETA_HASH_PROP,
            &field,
            |_| None,
            |_, _| Err(anyhow!("resetprop unavailable")),
        );
        assert!(result.is_err());
    }

    #[test]
    fn runtime_property_match_requires_the_full_value() {
        let value = hex::encode([0x66; 32]);
        assert!(runtime_property_matches(Some(value.as_str()), &value));
        assert!(runtime_property_matches(Some(&value.to_uppercase()), &value));
        assert!(!runtime_property_matches(Some(&value[..63]), &value));
        assert!(!runtime_property_matches(Some("deadbeef"), &value));
        assert!(!runtime_property_matches(Some(""), &value));
        assert!(!runtime_property_matches(Some("  "), &value));
        assert!(!runtime_property_matches(None, &value));
    }

    #[test]
    fn random_fallback_values_are_pinned_in_config() {
        let mut config_file = ConfigFile::default();
        let vb_key = ResolvedField { value: [0x11; 32], source: TrustValueSource::RandomFallback };
        let vb_hash = ResolvedField { value: [0x22; 32], source: TrustValueSource::RandomFallback };

        assert!(pin_random_fallback_values(&mut config_file, &vb_key, &vb_hash));
        assert_eq!(config_file.trust.vb_key, TrustValueSpec::Hex([0x11; 32]));
        assert_eq!(config_file.trust.vb_hash, TrustValueSpec::Hex([0x22; 32]));
    }

    fn build_test_vbmeta(
        public_key: &[u8],
        auth_block_size: usize,
        aux_block_size: usize,
    ) -> Vec<u8> {
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

    fn build_test_vbmeta_with_descriptors(flags: u32, descriptors: &[u8]) -> Vec<u8> {
        let aux_block_size = (descriptors.len() + 63) & !63;
        let mut blob = vec![0u8; AVB_HEADER_SIZE + aux_block_size];
        blob[..4].copy_from_slice(b"AVB0");
        blob[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        blob[20..28].copy_from_slice(&(aux_block_size as u64).to_be_bytes());
        blob[104..112].copy_from_slice(&(descriptors.len() as u64).to_be_bytes());
        blob[120..124].copy_from_slice(&flags.to_be_bytes());
        blob[AVB_HEADER_SIZE..AVB_HEADER_SIZE + descriptors.len()].copy_from_slice(descriptors);
        blob
    }

    fn build_test_property_descriptor(key: &[u8], value: &[u8]) -> Vec<u8> {
        let unpadded_size = AVB_PROPERTY_DESCRIPTOR_SIZE + key.len() + 1 + value.len() + 1;
        let total_size = (unpadded_size + 7) & !7;
        let mut descriptor = vec![0u8; total_size];
        descriptor[..8].copy_from_slice(&AVB_PROPERTY_TAG.to_be_bytes());
        descriptor[8..16]
            .copy_from_slice(&((total_size - AVB_DESCRIPTOR_SIZE) as u64).to_be_bytes());
        descriptor[16..24].copy_from_slice(&(key.len() as u64).to_be_bytes());
        descriptor[24..32].copy_from_slice(&(value.len() as u64).to_be_bytes());
        descriptor[32..32 + key.len()].copy_from_slice(key);
        let value_start = 32 + key.len() + 1;
        descriptor[value_start..value_start + value.len()].copy_from_slice(value);
        descriptor
    }

    fn build_test_boot_image(embedded_vbmeta: Option<&[u8]>) -> Vec<u8> {
        let mut image = vec![0u8; BOOT_HEADER_PREFIX_SIZE];
        image[..8].copy_from_slice(b"ANDROID!");
        image[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        image[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4]
            .copy_from_slice(&((25u32 << 4) | 9).to_le_bytes());

        if let Some(vbmeta) = embedded_vbmeta {
            let vbmeta_offset = image.len();
            image.extend_from_slice(vbmeta);
            let mut footer = [0u8; AVB_FOOTER_SIZE];
            footer[..4].copy_from_slice(b"AVBf");
            footer[4..8].copy_from_slice(&1u32.to_be_bytes());
            footer[20..28].copy_from_slice(&(vbmeta_offset as u64).to_be_bytes());
            footer[28..36].copy_from_slice(&(vbmeta.len() as u64).to_be_bytes());
            image.extend_from_slice(&footer);
        }
        image
    }
}
