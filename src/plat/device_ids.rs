use crate::{
    config::{self, ConfigFile, DeviceProperty},
    plat::resetprop::{
        is_binder_service_unavailable, read_string_property, runtime_get_device_id_for_phone,
        runtime_get_imei_for_slot, runtime_get_meid_for_slot, runtime_telephony_features,
        TelephonyFeatures,
    },
};

use anyhow::Result;

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

fn bootstrap_device_ids(config_file: &mut ConfigFile) -> Option<bool> {
    let device = &mut config_file.device;
    if device.override_telephony_properties {
        log::debug!("device identifiers pinned by config; skipping telephony auto-fill");
        return Some(false);
    }

    if !needs_backfill(&device.imei)
        && !needs_backfill(&device.imei2)
        && !needs_backfill(&device.meid)
    {
        log::debug!("device identifiers already configured; skipping telephony auto-fill");
        return Some(false);
    }

    let mut service_unavailable = false;
    let features = match runtime_telephony_features() {
        Ok(features) => features,
        Err(error) => {
            service_unavailable = is_binder_service_unavailable(&error);
            log::warn!("device ID feature probe failed; probing all ID APIs once: {error:#}");
            TelephonyFeatures {
                any: true,
                gsm: true,
                cdma: true,
            }
        }
    };
    let (candidates, probe_service_unavailable) = probe_device_id_candidates(features);
    service_unavailable |= probe_service_unavailable;
    let mut events = apply_telephony_candidates(device, &candidates);
    events.extend(apply_property_fallbacks(device));

    if events.is_empty() {
        log_device_id_state(device, "telephony auto-fill left fields empty");
    } else {
        for event in &events {
            log::info!(
                "Auto-filled {} from {} as {}",
                event.field,
                event.source,
                mask_identifier(&event.value)
            );
        }
        log_device_id_state(device, "telephony auto-fill result");
    }

    (!service_unavailable).then_some(!events.is_empty())
}

pub fn resolve_runtime_device_ids() -> Result<Option<DeviceProperty>> {
    let mut config_file = config::bootstrap_config_file()?;
    let Some(changed) = bootstrap_device_ids(&mut config_file) else {
        log::debug!("telephony Binder services are not ready; deferring attestation ID snapshot");
        return Ok(None);
    };
    let device = config_file.device.clone();
    match config::config().write() {
        Ok(mut runtime) => runtime.device = device.clone(),
        Err(_) => log::warn!("config lock poisoned while updating device identifiers"),
    }
    if changed {
        if let Err(error) = config::persist_config_file(&config_file) {
            log::warn!("failed to persist resolved device identifiers: {error:#}");
        }
    }
    Ok(Some(device))
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

    if value.len() == 14 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(IdentifierCandidate {
            kind: IdentifierKind::Meid,
            value: value.to_ascii_uppercase(),
            source,
        });
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
    candidates
        .into_iter()
        .filter_map(|(property, raw)| classify_identifier(&raw, property.to_string()))
        .find(|candidate| {
            candidate.kind == expected_kind
                && !excluded_values
                    .iter()
                    .any(|existing| existing == &candidate.value)
        })
}

fn needs_backfill(value: &str) -> bool {
    value.trim().is_empty()
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

fn probe_device_id_candidates(features: TelephonyFeatures) -> (Vec<IdentifierCandidate>, bool) {
    let mut candidates = Vec::new();
    let mut service_unavailable = false;
    if features.gsm {
        service_unavailable |= collect_slot_candidates(
            &mut candidates,
            "telephony API IMEI",
            Some(IdentifierKind::Imei),
            runtime_get_imei_for_slot,
        );
    }
    if features.cdma {
        service_unavailable |= collect_slot_candidates(
            &mut candidates,
            "telephony API MEID",
            Some(IdentifierKind::Meid),
            runtime_get_meid_for_slot,
        );
    }
    if features.any {
        service_unavailable |= collect_slot_candidates(
            &mut candidates,
            "device ID",
            None,
            runtime_get_device_id_for_phone,
        );
    }

    if candidates.is_empty() {
        log::debug!("telephony device IDs are unavailable");
    }
    (candidates, service_unavailable)
}

fn collect_slot_candidates(
    candidates: &mut Vec<IdentifierCandidate>,
    label: &str,
    expected_kind: Option<IdentifierKind>,
    mut probe: impl FnMut(i32) -> Result<Option<String>>,
) -> bool {
    let mut service_unavailable = false;
    for slot in [0_i32, 1_i32] {
        let source = format!("{} slot {slot}", label.to_ascii_lowercase());
        match probe(slot) {
            Ok(Some(value)) => {
                match classify_identifier(&value, source.clone()).filter(|candidate| {
                    expected_kind.is_none_or(|expected| candidate.kind == expected)
                }) {
                    Some(candidate) => candidates.push(candidate),
                    None => log::warn!(
                        "Ignoring invalid {label} from {source}: {}",
                        mask_identifier(value.trim())
                    ),
                }
            }
            Ok(None) => log::debug!("{label} slot {slot} returned no identifier"),
            Err(error) => {
                service_unavailable |= is_binder_service_unavailable(&error);
                log::warn!("{label} slot {slot} probe failed: {error:#}");
            }
        }
    }
    service_unavailable
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

        let meid_numeric_hex = classify_identifier("12345678901234", "binder".to_string()).unwrap();
        assert_eq!(meid_numeric_hex.kind, IdentifierKind::Meid);
        assert_eq!(meid_numeric_hex.value, "12345678901234");

        let meid_dec = classify_identifier("990012345678901234", "binder".to_string()).unwrap();
        assert_eq!(meid_dec.kind, IdentifierKind::Meid);
        assert_eq!(meid_dec.value, "990012345678901234");
    }

    #[test]
    fn classify_identifier_rejects_invalid_shapes() {
        assert!(classify_identifier("1234567890123", "binder".to_string()).is_none());
        assert!(classify_identifier("3552-3193-7352-445", "binder".to_string()).is_none());
        assert!(classify_identifier("not-an-id", "binder".to_string()).is_none());
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
    fn slot_probe_keeps_valid_candidates_after_errors() {
        let mut candidates = Vec::new();
        let mut imeis = vec![
            Ok(Some("355231937352445".to_string())),
            Err(anyhow::anyhow!("slot unavailable")),
        ]
        .into_iter();
        let service_unavailable = collect_slot_candidates(
            &mut candidates,
            "telephony API IMEI",
            Some(IdentifierKind::Imei),
            |_| imeis.next().unwrap(),
        );
        assert!(!service_unavailable);

        let mut device_ids = vec![Ok(None), Ok(Some("A100000927F62B".to_string()))].into_iter();
        let service_unavailable =
            collect_slot_candidates(&mut candidates, "device ID", None, |_| {
                device_ids.next().unwrap()
            });
        assert!(!service_unavailable);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].kind, IdentifierKind::Imei);
        assert_eq!(candidates[1].kind, IdentifierKind::Meid);
    }

    #[test]
    fn slot_probe_keeps_candidates_but_retries_after_service_unavailable() {
        use crate::plat::resetprop::BinderServiceUnavailable;

        let mut candidates = Vec::new();
        let mut imeis = vec![
            Ok(Some("355231937352445".to_string())),
            Err(BinderServiceUnavailable("phone".to_string()).into()),
        ]
        .into_iter();
        let service_unavailable = collect_slot_candidates(
            &mut candidates,
            "telephony API IMEI",
            Some(IdentifierKind::Imei),
            |_| imeis.next().unwrap(),
        );

        assert!(service_unavailable);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].value, "355231937352445");
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
    fn single_imei_does_not_require_imei2_or_meid() {
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
        assert!(device.meid.is_empty());
    }

    #[test]
    fn override_mode_preserves_user_pinned_imei_and_meid() {
        let mut config = ConfigFile::default();
        config.device.override_telephony_properties = true;
        config.device.imei = "111111111111111".to_string();
        config.device.meid = "A1000000000001".to_string();

        assert_eq!(bootstrap_device_ids(&mut config), Some(false));

        assert_eq!(config.device.imei, "111111111111111");
        assert_eq!(config.device.meid, "A1000000000001");
    }

    #[test]
    fn mask_identifier_redacts_middle_digits() {
        assert_eq!(mask_identifier("355231937352445"), "35***********45");
        assert_eq!(mask_identifier("A100"), "****");
    }
}
