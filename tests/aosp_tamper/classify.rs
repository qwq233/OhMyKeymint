#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataKeyView {
    pub domain_is_key_id: bool,
    pub alias_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataShapeView {
    pub modification_time_ms: i64,
    pub has_origin_authorization: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PureCertLevelView {
    pub top_level_security_level_present: bool,
    pub metadata_security_level_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListEntriesBatchedView {
    pub cursor_echoed: bool,
    pub expected_next_missing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinderChainView {
    pub generate_matches_get: bool,
    pub repeated_consistent: bool,
    pub delete_removed_alias: bool,
    pub suspicious_leaf_issuer_spki: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NativeTraceFlags {
    pub got_mismatch: bool,
    pub text_mismatch: bool,
    pub honeypot_anomaly: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilteredPairSeries {
    pub attested_samples: Vec<f64>,
    pub non_attested_samples: Vec<f64>,
}

pub const TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS: f64 = 0.2;

pub fn metadata_key_is_normalized(view: MetadataKeyView) -> bool {
    view.domain_is_key_id && !view.alias_present
}

pub fn metadata_shape_is_valid(view: MetadataShapeView) -> bool {
    view.modification_time_ms > 0 && view.has_origin_authorization
}

pub fn pure_cert_top_level_security_level_exposed(view: PureCertLevelView) -> bool {
    view.top_level_security_level_present
}

pub fn list_entries_batched_cursor_echoed(view: ListEntriesBatchedView) -> bool {
    view.cursor_echoed
}

pub fn list_entries_batched_expected_next_missing(view: ListEntriesBatchedView) -> bool {
    view.expected_next_missing
}

#[cfg(test)]
pub fn sorted_aliases<I, S>(aliases: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut aliases = aliases
        .into_iter()
        .map(|alias| alias.as_ref().to_string())
        .collect::<Vec<_>>();
    aliases.sort();
    aliases
}

pub fn aliases_contain_all(aliases: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .all(|expected_alias| aliases.iter().any(|alias| alias == expected_alias))
}

pub fn alias_is_strictly_after_cursor(alias: &str, cursor: &str) -> bool {
    alias > cursor
}

pub fn list_entries_batched_view(
    aliases: &[String],
    cursor: &str,
    expected_next: &str,
) -> ListEntriesBatchedView {
    ListEntriesBatchedView {
        cursor_echoed: aliases.iter().any(|alias| alias == cursor),
        expected_next_missing: !aliases.iter().any(|alias| alias == expected_next),
    }
}

pub fn binder_chain_has_issue(view: BinderChainView) -> bool {
    !view.generate_matches_get
        || !view.repeated_consistent
        || !view.delete_removed_alias
        || view.suspicious_leaf_issuer_spki
}

pub fn native_flags_have_issue(flags: NativeTraceFlags) -> bool {
    flags.got_mismatch || flags.text_mismatch || flags.honeypot_anomaly
}

pub fn paired_diff_series(attested_samples: &[f64], non_attested_samples: &[f64]) -> Vec<f64> {
    let paired_count = attested_samples.len().min(non_attested_samples.len());
    (0..paired_count)
        .map(|index| attested_samples[index] - non_attested_samples[index])
        .collect()
}

pub fn filter_outlier_pairs(
    attested_samples: &[f64],
    non_attested_samples: &[f64],
) -> FilteredPairSeries {
    let paired_count = attested_samples.len().min(non_attested_samples.len());
    if paired_count < 8 {
        return FilteredPairSeries {
            attested_samples: attested_samples[..paired_count].to_vec(),
            non_attested_samples: non_attested_samples[..paired_count].to_vec(),
        };
    }

    let paired_diffs = paired_diff_series(attested_samples, non_attested_samples);
    let mut sorted_diffs = paired_diffs.clone();
    sorted_diffs.sort_by(|left, right| left.partial_cmp(right).unwrap());
    let median = sorted_diffs[sorted_diffs.len() / 2];
    let mut absolute_deviation = paired_diffs
        .iter()
        .map(|diff| (diff - median).abs())
        .collect::<Vec<_>>();
    absolute_deviation.sort_by(|left, right| left.partial_cmp(right).unwrap());
    let mad = absolute_deviation[absolute_deviation.len() / 2];
    if mad == 0.0 {
        return FilteredPairSeries {
            attested_samples: attested_samples[..paired_count].to_vec(),
            non_attested_samples: non_attested_samples[..paired_count].to_vec(),
        };
    }

    let keep_indices = paired_diffs
        .iter()
        .enumerate()
        .filter_map(|(index, diff)| ((diff - median).abs() <= mad * 6.0).then_some(index))
        .collect::<Vec<_>>();
    if keep_indices.is_empty() || keep_indices.len() == paired_diffs.len() {
        return FilteredPairSeries {
            attested_samples: attested_samples[..paired_count].to_vec(),
            non_attested_samples: non_attested_samples[..paired_count].to_vec(),
        };
    }

    FilteredPairSeries {
        attested_samples: keep_indices
            .iter()
            .map(|index| attested_samples[*index])
            .collect(),
        non_attested_samples: keep_indices
            .iter()
            .map(|index| non_attested_samples[*index])
            .collect(),
    }
}

pub fn timing_side_channel_suspicious(diff_ms: f64) -> bool {
    diff_ms.abs() > TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_key_normalization_matches_expected_shape() {
        assert!(metadata_key_is_normalized(MetadataKeyView {
            domain_is_key_id: true,
            alias_present: false,
        }));
        assert!(!metadata_key_is_normalized(MetadataKeyView {
            domain_is_key_id: false,
            alias_present: false,
        }));
        assert!(!metadata_key_is_normalized(MetadataKeyView {
            domain_is_key_id: true,
            alias_present: true,
        }));
    }

    #[test]
    fn metadata_shape_requires_modification_time_and_origin() {
        assert!(metadata_shape_is_valid(MetadataShapeView {
            modification_time_ms: 1,
            has_origin_authorization: true,
        }));
        assert!(!metadata_shape_is_valid(MetadataShapeView {
            modification_time_ms: 0,
            has_origin_authorization: true,
        }));
        assert!(!metadata_shape_is_valid(MetadataShapeView {
            modification_time_ms: 1,
            has_origin_authorization: false,
        }));
    }

    #[test]
    fn pure_cert_top_level_security_level_detection_is_strict() {
        assert!(pure_cert_top_level_security_level_exposed(
            PureCertLevelView {
                top_level_security_level_present: true,
                metadata_security_level_present: true,
            }
        ));
        assert!(!pure_cert_top_level_security_level_exposed(
            PureCertLevelView {
                top_level_security_level_present: false,
                metadata_security_level_present: true,
            }
        ));
    }

    #[test]
    fn list_entries_batched_helpers_preserve_cursor_semantics() {
        let view = ListEntriesBatchedView {
            cursor_echoed: true,
            expected_next_missing: false,
        };
        assert!(list_entries_batched_cursor_echoed(view));
        assert!(!list_entries_batched_expected_next_missing(view));
    }

    #[test]
    fn alias_helpers_extract_containment_and_lexicographic_cursor_order() {
        let aliases = sorted_aliases(["probe_01", "probe_00", "other"]);
        assert_eq!(aliases, ["other", "probe_00", "probe_01"]);
        assert!(aliases_contain_all(&aliases, &["probe_00", "probe_01"]));
        assert!(!aliases_contain_all(&aliases, &["probe_00", "probe_02"]));
        assert!(alias_is_strictly_after_cursor("probe_01", "probe_00"));
        assert!(!alias_is_strictly_after_cursor("probe_00", "probe_00"));
        assert!(!alias_is_strictly_after_cursor("probe_00", "probe_01"));
    }

    #[test]
    fn list_entries_batched_view_reports_pass_and_fail_cases() {
        let pass_aliases = vec!["probe_01".to_string(), "probe_02".to_string()];
        let pass = list_entries_batched_view(&pass_aliases, "probe_00", "probe_01");
        assert!(!list_entries_batched_cursor_echoed(pass));
        assert!(!list_entries_batched_expected_next_missing(pass));

        let echoed_aliases = vec!["probe_00".to_string(), "probe_01".to_string()];
        let echoed = list_entries_batched_view(&echoed_aliases, "probe_00", "probe_01");
        assert!(list_entries_batched_cursor_echoed(echoed));
        assert!(!list_entries_batched_expected_next_missing(echoed));

        let missing_aliases = vec!["probe_02".to_string()];
        let missing = list_entries_batched_view(&missing_aliases, "probe_00", "probe_01");
        assert!(!list_entries_batched_cursor_echoed(missing));
        assert!(list_entries_batched_expected_next_missing(missing));
    }

    #[test]
    fn binder_chain_flags_catch_mismatch_and_spki_reuse() {
        assert!(binder_chain_has_issue(BinderChainView {
            generate_matches_get: false,
            repeated_consistent: true,
            delete_removed_alias: true,
            suspicious_leaf_issuer_spki: false,
        }));
        assert!(binder_chain_has_issue(BinderChainView {
            generate_matches_get: true,
            repeated_consistent: true,
            delete_removed_alias: true,
            suspicious_leaf_issuer_spki: true,
        }));
        assert!(!binder_chain_has_issue(BinderChainView {
            generate_matches_get: true,
            repeated_consistent: true,
            delete_removed_alias: true,
            suspicious_leaf_issuer_spki: false,
        }));
    }

    #[test]
    fn mad_filter_and_timing_threshold_match_duck_thresholds() {
        let filtered = filter_outlier_pairs(
            &[1.0, 1.1, 1.2, 1.1, 1.0, 20.0, 1.1, 1.2],
            &[0.8, 0.9, 1.0, 0.9, 0.8, 0.5, 0.9, 1.0],
        );
        assert!(filtered.attested_samples.len() < 8);
        assert!(timing_side_channel_suspicious(0.21));
        assert!(timing_side_channel_suspicious(-0.21));
        assert!(!timing_side_channel_suspicious(0.19));
    }

    #[test]
    fn native_detector_logic_only_needs_any_single_signal() {
        assert!(native_flags_have_issue(NativeTraceFlags {
            got_mismatch: true,
            text_mismatch: false,
            honeypot_anomaly: false,
        }));
        assert!(!native_flags_have_issue(NativeTraceFlags {
            got_mismatch: false,
            text_mismatch: false,
            honeypot_anomaly: false,
        }));
    }
}
