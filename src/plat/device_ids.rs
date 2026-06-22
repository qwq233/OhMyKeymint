use crate::{
    config::{ConfigFile, DeviceProperty},
    plat::resetprop::read_string_property,
};

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, Status};

const PHONE_SUB_INFO_SERVICE: &str = "iphonesubinfo";
const GET_DEVICE_ID_FOR_PHONE_TRANSACTION: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 3;
const CALLING_PACKAGE: &str = "android";
const CALLING_FEATURE: &str = "android";
const PHONE_SERVICE: &str = "phone";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TelephonyTransactions {
    get_imei_for_slot: rsbinder::TransactionCode,
    get_meid_for_slot: Option<rsbinder::TransactionCode>,
}

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
    let mut candidates = Vec::new();

    for slot in [0_i32, 1_i32] {
        match probe_imei_slot(slot) {
            Ok(Some(value)) => {
                let source = format!("telephony api imei slot {slot}");
                match normalize_imei_candidate(&value, source.clone()) {
                    Some(candidate) => candidates.push(candidate),
                    None => log::warn!(
                        "Ignoring invalid telephony IMEI from {source}: {}",
                        mask_identifier(value.trim())
                    ),
                }
            }
            Ok(None) => log::debug!("Telephony API IMEI slot {slot} returned no identifier"),
            Err(error) => log::warn!("Telephony API IMEI slot {slot} probe failed: {error:#}"),
        }
    }

    for slot in [0_i32, 1_i32] {
        match probe_meid_slot(slot) {
            Ok(Some(value)) => {
                let source = format!("telephony api meid slot {slot}");
                match normalize_meid_candidate(&value, source.clone()) {
                    Some(candidate) => candidates.push(candidate),
                    None => log::warn!(
                        "Ignoring invalid telephony MEID from {source}: {}",
                        mask_identifier(value.trim())
                    ),
                }
            }
            Ok(None) => log::debug!("Telephony API MEID slot {slot} returned no identifier"),
            Err(error) => log::warn!("Telephony API MEID slot {slot} probe failed: {error:#}"),
        }
    }

    candidates
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

fn probe_device_id_slot(slot: i32) -> Result<Option<String>> {
    probe_phone_string_via_binder(
        PHONE_SUB_INFO_SERVICE,
        GET_DEVICE_ID_FOR_PHONE_TRANSACTION,
        slot,
        "iphonesubinfo",
        "phoneId",
        "device id",
    )
}

fn probe_imei_slot(slot: i32) -> Result<Option<String>> {
    probe_phone_string_via_binder(
        PHONE_SERVICE,
        telephony_transactions().get_imei_for_slot,
        slot,
        "phone",
        "slot",
        "identifier",
    )
}

fn probe_meid_slot(slot: i32) -> Result<Option<String>> {
    let Some(transaction) = telephony_transactions().get_meid_for_slot else {
        log::debug!("phone getMeidForSlot is not present on Android 17");
        return Ok(None);
    };

    probe_phone_string_via_binder(
        PHONE_SERVICE,
        transaction,
        slot,
        "phone",
        "slot",
        "identifier",
    )
}

fn probe_phone_string_via_binder(
    service: &str,
    transaction: rsbinder::TransactionCode,
    slot: i32,
    label: &str,
    slot_label: &str,
    value_label: &str,
) -> Result<Option<String>> {
    let binder =
        hub::get_service(service).ok_or_else(|| anyhow!("service {service} unavailable"))?;
    let proxy = binder
        .as_proxy()
        .with_context(|| format!("{label} binder was unexpectedly local"))?;
    let mut data = proxy
        .prepare_transact(true)
        .with_context(|| format!("failed to prepare {label} transaction"))?;
    data.write(&slot)
        .with_context(|| format!("failed to write {slot_label} for {label}"))?;
    data.write(&CALLING_PACKAGE.to_string())
        .with_context(|| format!("failed to write calling package for {label}"))?;
    data.write(&CALLING_FEATURE.to_string())
        .with_context(|| format!("failed to write calling feature for {label}"))?;

    let mut reply = proxy
        .submit_transact(transaction, &data, 0)
        .with_context(|| format!("{label} transact failed"))?
        .with_context(|| format!("{label} returned no reply"))?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .with_context(|| format!("failed to decode {label} reply status"))?;
    if !status.is_ok() {
        bail!("{label} returned non-ok status: {status}");
    }

    let value: Option<String> = reply
        .read()
        .with_context(|| format!("failed to decode {label} {value_label} string"))?;
    Ok(value.filter(|value| !value.trim().is_empty()))
}

fn telephony_transactions() -> TelephonyTransactions {
    telephony_transactions_for(kmr_common::android_version::android_major_version())
}

fn telephony_transactions_for(android_major: Option<i32>) -> TelephonyTransactions {
    let (imei_offset, meid_offset) = match android_major {
        Some(version) if version <= 12 => (149, Some(151)),
        Some(13) => (145, Some(147)),
        Some(14) => (148, Some(151)),
        Some(15 | 16) | None => (147, Some(150)),
        Some(version) if version >= 17 => (132, None),
        _ => (147, Some(150)),
    };

    TelephonyTransactions {
        get_imei_for_slot: rsbinder::FIRST_CALL_TRANSACTION + imei_offset,
        get_meid_for_slot: meid_offset.map(|offset| rsbinder::FIRST_CALL_TRANSACTION + offset),
    }
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

    fn ensure_binder_process_state() {
        let _ = rsbinder::ProcessState::init_default();
    }

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
    fn telephony_api_uses_android_request_metadata() {
        assert_eq!(CALLING_PACKAGE, "android");
        assert_eq!(CALLING_FEATURE, "android");
    }

    #[test]
    fn telephony_transaction_table_matches_supported_android_versions() {
        use rsbinder::FIRST_CALL_TRANSACTION;

        let android_12 = telephony_transactions_for(Some(12));
        assert_eq!(android_12.get_imei_for_slot, FIRST_CALL_TRANSACTION + 149);
        assert_eq!(
            android_12.get_meid_for_slot,
            Some(FIRST_CALL_TRANSACTION + 151)
        );

        let android_13 = telephony_transactions_for(Some(13));
        assert_eq!(android_13.get_imei_for_slot, FIRST_CALL_TRANSACTION + 145);
        assert_eq!(
            android_13.get_meid_for_slot,
            Some(FIRST_CALL_TRANSACTION + 147)
        );

        let android_14 = telephony_transactions_for(Some(14));
        assert_eq!(android_14.get_imei_for_slot, FIRST_CALL_TRANSACTION + 148);
        assert_eq!(
            android_14.get_meid_for_slot,
            Some(FIRST_CALL_TRANSACTION + 151)
        );

        let android_15 = telephony_transactions_for(Some(15));
        assert_eq!(android_15.get_imei_for_slot, FIRST_CALL_TRANSACTION + 147);
        assert_eq!(
            android_15.get_meid_for_slot,
            Some(FIRST_CALL_TRANSACTION + 150)
        );

        let android_16 = telephony_transactions_for(Some(16));
        assert_eq!(android_16.get_imei_for_slot, FIRST_CALL_TRANSACTION + 147);
        assert_eq!(
            android_16.get_meid_for_slot,
            Some(FIRST_CALL_TRANSACTION + 150)
        );

        let android_17 = telephony_transactions_for(Some(17));
        assert_eq!(android_17.get_imei_for_slot, FIRST_CALL_TRANSACTION + 132);
        assert_eq!(android_17.get_meid_for_slot, None);
        assert_eq!(
            GET_DEVICE_ID_FOR_PHONE_TRANSACTION,
            FIRST_CALL_TRANSACTION + 3
        );
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
    fn empty_telephony_result_still_falls_through_to_property_candidate() {
        let mut device = empty_device();
        let telephony_candidates = Vec::new();
        let property_candidates = vec![IdentifierCandidate {
            kind: IdentifierKind::Imei,
            value: "355231937352445".to_string(),
            source: "persist.vendor.radio.imei1".to_string(),
        }];

        let telephony_events = apply_telephony_candidates(&mut device, &telephony_candidates);
        let property_events = apply_telephony_candidates(&mut device, &property_candidates);

        assert!(telephony_events.is_empty());
        assert_eq!(property_events.len(), 1);
        assert_eq!(device.imei, "355231937352445");
        assert_eq!(property_events[0].source, "persist.vendor.radio.imei1");
    }

    #[test]
    fn property_failure_still_falls_through_to_generic_device_id_candidate() {
        let mut device = empty_device();
        let telephony_candidates = Vec::new();
        let property_candidates = Vec::new();
        let device_id_candidates = vec![IdentifierCandidate {
            kind: IdentifierKind::Meid,
            value: "A100000927F62B".to_string(),
            source: "device id slot 0".to_string(),
        }];

        apply_telephony_candidates(&mut device, &telephony_candidates);
        let property_events = apply_telephony_candidates(&mut device, &property_candidates);
        let device_id_events = apply_telephony_candidates(&mut device, &device_id_candidates);

        assert!(property_events.is_empty());
        assert_eq!(device_id_events.len(), 1);
        assert_eq!(device.meid, "A100000927F62B");
        assert_eq!(device_id_events[0].source, "device id slot 0");
    }

    #[test]
    fn field_stays_empty_only_after_all_three_sources_fail() {
        let mut device = empty_device();

        let telephony_events = apply_telephony_candidates(&mut device, &[]);
        let property_events = apply_telephony_candidates(&mut device, &[]);
        let device_id_events = apply_telephony_candidates(&mut device, &[]);

        assert!(telephony_events.is_empty());
        assert!(property_events.is_empty());
        assert!(device_id_events.is_empty());
        assert!(device.imei.is_empty());
        assert!(device.imei2.is_empty());
        assert!(device.meid.is_empty());
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
    fn default_mode_clears_user_pinned_imei_and_meid_before_backfill() {
        let mut config = ConfigFile::default();
        config.device.imei = "111111111111111".to_string();
        config.device.meid = "A1000000000001".to_string();
        config.device.imei2 = "222222222222222".to_string();

        clear_unpinned_telephony_fields(&mut config.device);

        assert!(config.device.imei.is_empty());
        assert!(config.device.meid.is_empty());
        assert_eq!(config.device.imei2, "222222222222222");
    }

    #[test]
    fn override_mode_preserves_user_pinned_imei_and_meid() {
        ensure_binder_process_state();
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
