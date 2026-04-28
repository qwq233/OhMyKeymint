use crate::config::{ConfigFile, DeviceProperty};

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, Status};
use std::fs;
use std::process::Command;

const PHONE_SUB_INFO_SERVICE: &str = "iphonesubinfo";
const GET_DEVICE_ID_FOR_PHONE_TRANSACTION: u32 = 4;
// AOSP ITelephony.aidl currently places these methods at 148 and 151.
const GET_IMEI_FOR_SLOT_TRANSACTION: u32 = 148;
const GET_MEID_FOR_SLOT_TRANSACTION: u32 = 151;
const CALLING_PACKAGE: &str = "android";
const SHELL_CALLING_PACKAGE: &str = "com.android.shell";
const CALLING_FEATURE: &str = "omk";
const PHONE_SERVICE: &str = "phone";
const SU_BINARY: &str = "/system/bin/su";
const TELEPHONY_PROBE_ARG: &str = "--omk-telephony-probe";
const SHELL_TELEPHONY_HELPER_PATH: &str = "/data/local/tmp/omk_telephony_probe";

const IMEI_PROPERTIES: &[&str] = &[
    "ro.ril.oem.imei",
    "persist.radio.imei",
    "persist.vendor.radio.imei",
    "persist.vendor.radio.imei1",
];

const IMEI2_PROPERTIES: &[&str] = &[
    "ro.ril.oem.imei2",
    "persist.radio.imei2",
    "persist.vendor.radio.imei2",
];

const MEID_PROPERTIES: &[&str] = &[
    "ro.ril.oem.meid",
    "persist.radio.meid",
    "persist.vendor.radio.meid",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentifierKind {
    Imei,
    Meid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentifierCandidate {
    kind: IdentifierKind,
    value: String,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackfillEvent {
    field: &'static str,
    source: String,
    value: String,
}

pub fn maybe_run_telephony_probe_command() -> Result<bool> {
    let Some(arg) = std::env::args().nth(1) else {
        return Ok(false);
    };
    if arg != TELEPHONY_PROBE_ARG {
        return Ok(false);
    }

    rsbinder::ProcessState::init_default();

    for slot in [0_i32, 1_i32] {
        if let Some(value) = probe_phone_identifier_via_binder(
            slot,
            GET_IMEI_FOR_SLOT_TRANSACTION,
            SHELL_CALLING_PACKAGE,
        )? {
            println!("imei\t{slot}\t{}", value.trim());
        }
    }

    for slot in [0_i32, 1_i32] {
        if let Some(value) = probe_phone_identifier_via_binder(
            slot,
            GET_MEID_FOR_SLOT_TRANSACTION,
            SHELL_CALLING_PACKAGE,
        )? {
            println!("meid\t{slot}\t{}", value.trim());
        }
    }

    Ok(true)
}

pub fn bootstrap_device_ids(config_file: &mut ConfigFile) {
    let device = &mut config_file.device;
    let respect_user_telephony_override = device.override_telephony_properties;
    let imei_needs_backfill =
        telephony_field_needs_backfill(&device.imei, respect_user_telephony_override);
    let imei2_needs_backfill = needs_backfill(&device.imei2);
    let meid_needs_backfill =
        telephony_field_needs_backfill(&device.meid, respect_user_telephony_override);

    if !imei_needs_backfill && !imei2_needs_backfill && !meid_needs_backfill {
        log::debug!("Device identifiers already configured; skipping startup auto-fill");
        return;
    }

    if !respect_user_telephony_override {
        clear_unpinned_telephony_fields(device);
    }

    let telephony_api_candidates = probe_telephony_api_candidates();
    let mut events = apply_telephony_candidates(device, &telephony_api_candidates);
    events.extend(apply_property_fallbacks(device));
    let device_id_candidates = probe_device_id_candidates();
    events.extend(apply_telephony_candidates(device, &device_id_candidates));

    if events.is_empty() {
        log_device_id_state(device, "startup auto-fill left field empty");
        return;
    }

    for event in events {
        log::info!(
            "Auto-filled {} from {} as {}",
            event.field,
            event.source,
            mask_identifier(&event.value)
        );
    }

    log_device_id_state(device, "startup auto-fill result");
}

fn apply_telephony_candidates(
    device: &mut DeviceProperty,
    candidates: &[IdentifierCandidate],
) -> Vec<BackfillEvent> {
    let mut events = Vec::new();
    let mut used_imeis = configured_imei_values(device);

    let mut imei_empty = needs_backfill(&device.imei);
    let mut imei2_empty = needs_backfill(&device.imei2);
    let mut meid_empty = needs_backfill(&device.meid);

    for candidate in candidates {
        match candidate.kind {
            IdentifierKind::Imei => {
                if used_imeis
                    .iter()
                    .any(|existing| existing == &candidate.value)
                {
                    continue;
                }

                if imei_empty {
                    device.imei = candidate.value.clone();
                    events.push(BackfillEvent {
                        field: "device.imei",
                        source: candidate.source.clone(),
                        value: candidate.value.clone(),
                    });
                    used_imeis.push(candidate.value.clone());
                    imei_empty = false;
                    continue;
                }

                if imei2_empty {
                    device.imei2 = candidate.value.clone();
                    events.push(BackfillEvent {
                        field: "device.imei2",
                        source: candidate.source.clone(),
                        value: candidate.value.clone(),
                    });
                    used_imeis.push(candidate.value.clone());
                    imei2_empty = false;
                }
            }
            IdentifierKind::Meid => {
                if meid_empty {
                    device.meid = candidate.value.clone();
                    events.push(BackfillEvent {
                        field: "device.meid",
                        source: candidate.source.clone(),
                        value: candidate.value.clone(),
                    });
                    meid_empty = false;
                }
            }
        }

        if !imei_empty && !imei2_empty && !meid_empty {
            break;
        }
    }

    events
}

fn apply_property_fallbacks(device: &mut DeviceProperty) -> Vec<BackfillEvent> {
    let mut events = Vec::new();

    if needs_backfill(&device.imei) {
        let excluded = configured_imei_values(device);
        if let Some(candidate) =
            find_property_candidate(IMEI_PROPERTIES, IdentifierKind::Imei, &excluded)
        {
            device.imei = candidate.value.clone();
            events.push(BackfillEvent {
                field: "device.imei",
                source: candidate.source,
                value: candidate.value,
            });
        }
    }

    if needs_backfill(&device.imei2) {
        let excluded = configured_imei_values(device);
        if let Some(candidate) =
            find_property_candidate(IMEI2_PROPERTIES, IdentifierKind::Imei, &excluded)
        {
            device.imei2 = candidate.value.clone();
            events.push(BackfillEvent {
                field: "device.imei2",
                source: candidate.source,
                value: candidate.value,
            });
        }
    }

    if needs_backfill(&device.meid) {
        if let Some(candidate) = find_property_candidate(MEID_PROPERTIES, IdentifierKind::Meid, &[])
        {
            device.meid = candidate.value.clone();
            events.push(BackfillEvent {
                field: "device.meid",
                source: candidate.source,
                value: candidate.value,
            });
        }
    }

    events
}

fn configured_imei_values(device: &DeviceProperty) -> Vec<String> {
    [device.imei.trim(), device.imei2.trim()]
        .into_iter()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn find_property_candidate(
    properties: &[&str],
    expected_kind: IdentifierKind,
    excluded_values: &[String],
) -> Option<IdentifierCandidate> {
    select_property_candidate(
        properties
            .iter()
            .filter_map(|property| read_string_property(property).map(|value| (*property, value))),
        expected_kind,
        excluded_values,
    )
}

fn classify_identifier(raw: &str, source: String) -> Option<IdentifierCandidate> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }

    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        let kind = match value.len() {
            15 | 16 => IdentifierKind::Imei,
            18 => IdentifierKind::Meid,
            _ => return None,
        };
        return Some(IdentifierCandidate {
            kind,
            value: value.to_string(),
            source,
        });
    }

    if value.len() == 14 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(IdentifierCandidate {
            kind: IdentifierKind::Meid,
            value: value.to_ascii_uppercase(),
            source,
        });
    }

    None
}

fn select_property_candidate<'a, I>(
    candidates: I,
    expected_kind: IdentifierKind,
    excluded_values: &[String],
) -> Option<IdentifierCandidate>
where
    I: IntoIterator<Item = (&'a str, String)>,
{
    for (property, raw) in candidates {
        let Some(candidate) = classify_identifier(&raw, property.to_string()) else {
            continue;
        };
        if candidate.kind != expected_kind {
            continue;
        }
        if excluded_values
            .iter()
            .any(|existing| existing == &candidate.value)
        {
            continue;
        }
        return Some(candidate);
    }

    None
}

fn needs_backfill(value: &str) -> bool {
    value.trim().is_empty()
}

fn telephony_field_needs_backfill(value: &str, respect_user_override: bool) -> bool {
    !respect_user_override || needs_backfill(value)
}

fn clear_unpinned_telephony_fields(device: &mut DeviceProperty) {
    if !device.imei.trim().is_empty() || !device.meid.trim().is_empty() {
        log::debug!(
            "Ignoring user-configured imei/meid because overrideTelephonyProperties is not true"
        );
    }
    device.imei.clear();
    device.meid.clear();
}

fn mask_identifier(value: &str) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }

    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }

    let prefix: String = chars.iter().take(2).copied().collect();
    let suffix: String = chars[chars.len() - 2..].iter().copied().collect();
    format!("{prefix}{}{suffix}", "*".repeat(chars.len() - 4))
}

fn log_device_id_state(device: &DeviceProperty, label: &str) {
    log::info!(
        "{}: imei={}, imei2={}, meid={}",
        label,
        mask_identifier(device.imei.trim()),
        mask_identifier(device.imei2.trim()),
        mask_identifier(device.meid.trim())
    );
}

fn probe_telephony_api_candidates() -> Vec<IdentifierCandidate> {
    match invoke_shell_telephony_probe() {
        Ok(output) => parse_shell_telephony_probe_output(&output),
        Err(error) => {
            log::warn!("Telephony API probe helper failed: {error:#}");
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "android"))]
fn probe_telephony_api_candidates() -> Vec<IdentifierCandidate> {
    Vec::new()
}

fn probe_device_id_candidates() -> Vec<IdentifierCandidate> {
    let mut candidates = Vec::new();

    for slot in [0_i32, 1_i32] {
        match probe_device_id_slot(slot) {
            Ok(Some(value)) => {
                let source = format!("device id slot {slot}");
                match classify_identifier(&value, source.clone()) {
                    Some(candidate) => candidates.push(candidate),
                    None => log::warn!(
                        "Ignoring unrecognized device identifier from {source}: {}",
                        mask_identifier(value.trim())
                    ),
                }
            }
            Ok(None) => log::debug!("Device ID slot {slot} returned no identifier"),
            Err(error) => log::warn!("Device ID slot {slot} probe failed: {error:#}"),
        }
    }

    candidates
}

#[cfg(not(target_os = "android"))]
fn probe_device_id_candidates() -> Vec<IdentifierCandidate> {
    Vec::new()
}

fn probe_device_id_slot(slot: i32) -> Result<Option<String>> {
    let binder = hub::get_service(PHONE_SUB_INFO_SERVICE)
        .ok_or_else(|| anyhow!("service {PHONE_SUB_INFO_SERVICE} unavailable"))?;
    let proxy = binder
        .as_proxy()
        .context("iphonesubinfo binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare iphonesubinfo transaction")?;
    data.write(&slot)
        .context("failed to write phoneId for iphonesubinfo")?;
    data.write(&CALLING_PACKAGE.to_string())
        .context("failed to write calling package for iphonesubinfo")?;
    data.write(&CALLING_FEATURE.to_string())
        .context("failed to write calling feature for iphonesubinfo")?;

    let mut reply = proxy
        .submit_transact(GET_DEVICE_ID_FOR_PHONE_TRANSACTION, &data, 0)
        .context("iphonesubinfo transact failed")?
        .context("iphonesubinfo returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode iphonesubinfo reply status")?;
    if !status.is_ok() {
        bail!("iphonesubinfo returned non-ok status: {status}");
    }

    let value: Option<String> = reply
        .read()
        .context("failed to decode iphonesubinfo device id string")?;
    Ok(value)
}

fn probe_phone_identifier_via_binder(
    slot: i32,
    transaction: u32,
    calling_package: &str,
) -> Result<Option<String>> {
    let binder =
        hub::get_service(PHONE_SERVICE).ok_or_else(|| anyhow!("service {PHONE_SERVICE} unavailable"))?;
    let proxy = binder
        .as_proxy()
        .context("phone binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare phone transaction")?;
    data.write(&slot)
        .context("failed to write slot for phone transaction")?;
    data.write(&calling_package.to_string())
        .context("failed to write calling package for phone transaction")?;
    data.write(&CALLING_FEATURE.to_string())
        .context("failed to write calling feature for phone transaction")?;

    let mut reply = proxy
        .submit_transact(transaction, &data, 0)
        .context("phone transact failed")?
        .context("phone returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode phone reply status")?;
    if !status.is_ok() {
        bail!("phone returned non-ok status: {status}");
    }

    let value: Option<String> = reply
        .read()
        .context("failed to decode phone identifier string")?;
    Ok(value)
}

fn invoke_shell_telephony_probe() -> Result<String> {
    let helper_path = prepare_shell_accessible_helper()?;
    let helper_command = format!("{} {}", helper_path.display(), TELEPHONY_PROBE_ARG);
    let output = Command::new(SU_BINARY)
        .arg("2000")
        .arg("-c")
        .arg(&helper_command)
        .output()
        .with_context(|| format!("failed to invoke telephony probe helper via {SU_BINARY}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{SU_BINARY} exited with {} while running telephony probe helper: {}",
            output.status,
            stderr.trim()
        );
    }

    if !output.stderr.is_empty() {
        log::debug!(
            "Telephony probe helper stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn prepare_shell_accessible_helper() -> Result<std::path::PathBuf> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let helper_path = std::path::PathBuf::from(SHELL_TELEPHONY_HELPER_PATH);

    fs::copy(&current_exe, &helper_path).with_context(|| {
        format!(
            "failed to copy telephony helper from {} to {}",
            current_exe.display(),
            helper_path.display()
        )
    })?;

    #[cfg(target_os = "android")]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&helper_path, permissions).with_context(|| {
            format!(
                "failed to chmod telephony helper {}",
                helper_path.display()
            )
        })?;
    }

    Ok(helper_path)
}

fn parse_shell_telephony_probe_output(output: &str) -> Vec<IdentifierCandidate> {
    let mut candidates = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(3, '\t');
        let Some(kind) = parts.next() else {
            continue;
        };
        let Some(slot_raw) = parts.next() else {
            log::warn!("Ignoring malformed telephony probe line: {trimmed}");
            continue;
        };
        let Some(value) = parts.next() else {
            log::warn!("Ignoring malformed telephony probe line: {trimmed}");
            continue;
        };

        let slot: i32 = match slot_raw.parse() {
            Ok(slot) => slot,
            Err(error) => {
                log::warn!("Ignoring telephony probe line with invalid slot {slot_raw}: {error}");
                continue;
            }
        };

        let source = format!("telephony api {kind} slot {slot}");
        let candidate = match kind {
            "imei" => normalize_imei_candidate(value, source.clone()),
            "meid" => normalize_meid_candidate(value, source.clone()),
            _ => {
                log::warn!("Ignoring telephony probe line with unknown kind {kind}");
                continue;
            }
        };

        match candidate {
            Some(candidate) => candidates.push(candidate),
            None => log::warn!(
                "Ignoring invalid telephony probe value from {source}: {}",
                mask_identifier(value.trim())
            ),
        }
    }

    candidates
}

fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_imei_candidate(raw: &str, source: String) -> Option<IdentifierCandidate> {
    let value = raw.trim();
    if matches!(value.len(), 15 | 16) && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(IdentifierCandidate {
            kind: IdentifierKind::Imei,
            value: value.to_string(),
            source,
        });
    }

    None
}

fn normalize_meid_candidate(raw: &str, source: String) -> Option<IdentifierCandidate> {
    let value = raw.trim();
    if value.len() == 18 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(IdentifierCandidate {
            kind: IdentifierKind::Meid,
            value: value.to_string(),
            source,
        });
    }

    if value.len() == 14 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(IdentifierCandidate {
            kind: IdentifierKind::Meid,
            value: value.to_ascii_uppercase(),
            source,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_device() -> DeviceProperty {
        DeviceProperty {
            brand: "Google".to_string(),
            device: "caiman".to_string(),
            product: "caiman".to_string(),
            manufacturer: "Google".to_string(),
            model: "Pixel".to_string(),
            serial: "serial".to_string(),
            override_telephony_properties: false,
            meid: String::new(),
            imei: String::new(),
            imei2: String::new(),
        }
    }

    #[test]
    fn classify_identifier_accepts_imei_and_meid_shapes() {
        let imei = classify_identifier("355231937352445", "binder".to_string()).unwrap();
        assert_eq!(imei.kind, IdentifierKind::Imei);
        assert_eq!(imei.value, "355231937352445");

        let meid_hex = classify_identifier("a100000927f62b", "binder".to_string()).unwrap();
        assert_eq!(meid_hex.kind, IdentifierKind::Meid);
        assert_eq!(meid_hex.value, "A100000927F62B");

        let meid_dec = classify_identifier("990012345678901234", "binder".to_string()).unwrap();
        assert_eq!(meid_dec.kind, IdentifierKind::Meid);
        assert_eq!(meid_dec.value, "990012345678901234");
    }

    #[test]
    fn classify_identifier_rejects_invalid_shapes() {
        assert!(classify_identifier("12345678901234", "binder".to_string()).is_none());
        assert!(classify_identifier("3552-3193-7352-445", "binder".to_string()).is_none());
        assert!(classify_identifier("not-an-id", "binder".to_string()).is_none());
    }

    #[test]
    fn normalize_telephony_api_candidates_accept_expected_shapes() {
        let imei = normalize_imei_candidate("355231937352445", "phone".to_string()).unwrap();
        assert_eq!(imei.kind, IdentifierKind::Imei);
        assert_eq!(imei.value, "355231937352445");

        let meid = normalize_meid_candidate("a100000927f62b", "phone".to_string()).unwrap();
        assert_eq!(meid.kind, IdentifierKind::Meid);
        assert_eq!(meid.value, "A100000927F62B");

        assert!(normalize_imei_candidate("A100000927F62B", "phone".to_string()).is_none());
        assert!(normalize_meid_candidate("355231937352445", "phone".to_string()).is_none());
    }

    #[test]
    fn telephony_candidates_fill_distinct_imeis_and_meid() {
        let mut device = empty_device();
        let candidates = vec![
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "355231937352445".to_string(),
                source: "slot0".to_string(),
            },
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "355231937352445".to_string(),
                source: "slot1".to_string(),
            },
            IdentifierCandidate {
                kind: IdentifierKind::Meid,
                value: "A100000927F62B".to_string(),
                source: "slot1".to_string(),
            },
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "355231937352446".to_string(),
                source: "prop".to_string(),
            },
        ];

        let events = apply_telephony_candidates(&mut device, &candidates);
        assert_eq!(device.imei, "355231937352445");
        assert_eq!(device.imei2, "355231937352446");
        assert_eq!(device.meid, "A100000927F62B");
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn telephony_candidates_preserve_existing_values() {
        let mut device = empty_device();
        device.imei = "111111111111111".to_string();
        device.meid = "A1000000000001".to_string();

        let candidates = vec![
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "222222222222222".to_string(),
                source: "slot0".to_string(),
            },
            IdentifierCandidate {
                kind: IdentifierKind::Meid,
                value: "A100000927F62B".to_string(),
                source: "slot1".to_string(),
            },
        ];

        let events = apply_telephony_candidates(&mut device, &candidates);
        assert_eq!(device.imei, "111111111111111");
        assert_eq!(device.imei2, "222222222222222");
        assert_eq!(device.meid, "A1000000000001");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].field, "device.imei2");
    }

    #[test]
    fn property_fallback_only_fills_empty_fields() {
        let excluded = vec!["355231937352445".to_string(), "355231937352446".to_string()];
        let imei = select_property_candidate(
            vec![
                ("persist.vendor.radio.imei1", "355231937352445".to_string()),
                ("persist.vendor.radio.imei2", "355231937352446".to_string()),
            ],
            IdentifierKind::Imei,
            &excluded,
        );
        assert!(imei.is_none());

        let meid = select_property_candidate(
            vec![("persist.vendor.radio.meid", "a100000927f62b".to_string())],
            IdentifierKind::Meid,
            &[],
        );
        assert_eq!(meid.unwrap().value, "A100000927F62B");
    }

    #[test]
    fn parse_shell_probe_output_accepts_expected_lines() {
        let candidates = parse_shell_telephony_probe_output(
            "imei\t0\t355231937352445\nmeid\t1\ta100000927f62b\n",
        );
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].source, "telephony api imei slot 0");
        assert_eq!(candidates[0].value, "355231937352445");
        assert_eq!(candidates[1].source, "telephony api meid slot 1");
        assert_eq!(candidates[1].value, "A100000927F62B");
    }

    #[test]
    fn parse_shell_probe_output_ignores_malformed_lines() {
        let candidates = parse_shell_telephony_probe_output(
            "imei\tzero\t355231937352445\nbadline\nunknown\t0\t123\n",
        );
        assert!(candidates.is_empty());
    }

    #[test]
    fn duplicate_imei_does_not_fill_second_slot() {
        let mut device = empty_device();
        let candidates = vec![
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "355231937352445".to_string(),
                source: "slot0".to_string(),
            },
            IdentifierCandidate {
                kind: IdentifierKind::Imei,
                value: "355231937352445".to_string(),
                source: "slot1".to_string(),
            },
        ];

        apply_telephony_candidates(&mut device, &candidates);
        assert_eq!(device.imei, "355231937352445");
        assert!(device.imei2.is_empty());
    }

    #[test]
    fn default_mode_ignores_user_pinned_imei_and_meid() {
        let mut config = ConfigFile::default();
        config.device.imei = "111111111111111".to_string();
        config.device.meid = "A1000000000001".to_string();
        config.device.imei2 = "222222222222222".to_string();

        bootstrap_device_ids(&mut config);

        assert!(config.device.imei.is_empty());
        assert!(config.device.meid.is_empty());
        assert_eq!(config.device.imei2, "222222222222222");
    }

    #[test]
    fn override_mode_preserves_user_pinned_imei_and_meid() {
        let mut config = ConfigFile::default();
        config.device.override_telephony_properties = true;
        config.device.imei = "111111111111111".to_string();
        config.device.meid = "A1000000000001".to_string();

        bootstrap_device_ids(&mut config);

        assert_eq!(config.device.imei, "111111111111111");
        assert_eq!(config.device.meid, "A1000000000001");
    }

    #[test]
    fn mask_identifier_redacts_middle_digits() {
        assert_eq!(mask_identifier("355231937352445"), "35***********45");
        assert_eq!(mask_identifier("A100"), "****");
    }

}
