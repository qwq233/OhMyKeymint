use crate::aosp_tamper::model::{ProbeOutput, ProbeRow, ScoredCategory, SignalLevel, Verdict};

pub fn evaluate(rows: Vec<ProbeRow>, advisory_rows: Vec<ProbeRow>) -> ProbeOutput {
    let policy_hard_count = count_rows(&rows, ScoredCategory::PolicyHard, SignalLevel::Fail);
    let policy_soft_count = count_rows(&rows, ScoredCategory::PolicySoft, SignalLevel::Warn);
    let supplementary_fail_count =
        count_rows(&rows, ScoredCategory::Supplementary, SignalLevel::Fail);
    let supplementary_warn_count =
        count_rows(&rows, ScoredCategory::Supplementary, SignalLevel::Warn);
    let supplementary_count = supplementary_fail_count + supplementary_warn_count;
    let broken_count = rows
        .iter()
        .filter(|row| row.level == SignalLevel::Broken)
        .count();

    let tamper_score = ((policy_hard_count * 28)
        + (policy_soft_count * 8)
        + (supplementary_fail_count * 10)
        + (supplementary_warn_count * 4))
        .min(100);

    let verdict = if policy_hard_count > 0 {
        Verdict::Tampered
    } else if broken_count > 0 {
        Verdict::Broken
    } else if policy_soft_count > 0 {
        Verdict::Suspicious
    } else {
        Verdict::Consistent
    };

    let headline = match verdict {
        Verdict::Consistent if supplementary_count > 0 => {
            "Attestation aligned; local probes need review".to_string()
        }
        Verdict::Consistent => "Local TEE attestation checks aligned".to_string(),
        Verdict::Suspicious => "Policy-backed attestation evidence needs review".to_string(),
        Verdict::Tampered => "Policy-backed attestation anomalies were detected".to_string(),
        Verdict::Broken => "Hardware-backed local verification was not established".to_string(),
    };

    let summary = match verdict {
        Verdict::Consistent if supplementary_count > 0 => {
            "Local blind probes raised review items while attestation stayed aligned.".to_string()
        }
        Verdict::Consistent => {
            "Attestation, keystore surface, and local native checks aligned.".to_string()
        }
        Verdict::Suspicious => {
            first_row_value(&rows, ScoredCategory::PolicySoft, SignalLevel::Warn)
                .unwrap_or_else(|| "Policy-backed review signals suggest closer inspection.".into())
        }
        Verdict::Tampered => first_row_value(&rows, ScoredCategory::PolicyHard, SignalLevel::Fail)
            .unwrap_or_else(|| "Policy-backed anomalies were detected.".into()),
        Verdict::Broken => rows
            .iter()
            .find(|row| row.level == SignalLevel::Broken)
            .map(|row| row.value.clone())
            .unwrap_or_else(|| {
                "Hardware-backed local verification could not be established.".into()
            }),
    };

    ProbeOutput {
        headline,
        summary,
        verdict,
        tamper_score,
        policy_hard_count,
        policy_soft_count,
        supplementary_count,
        rows,
        advisory_rows,
    }
}

fn count_rows(rows: &[ProbeRow], category: ScoredCategory, level: SignalLevel) -> usize {
    rows.iter()
        .filter(|row| row.scored_category == Some(category) && row.level == level)
        .count()
}

fn first_row_value(
    rows: &[ProbeRow],
    category: ScoredCategory,
    level: SignalLevel,
) -> Option<String> {
    rows.iter()
        .find(|row| row.scored_category == Some(category) && row.level == level)
        .map(|row| row.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aosp_tamper::model::{ProbeRow, ScoredCategory, SignalLevel, Verdict};

    #[test]
    fn duck_weights_and_cap_stay_aligned() {
        let output = evaluate(
            vec![
                ProbeRow::new(
                    "Challenge",
                    "challenge mismatch",
                    SignalLevel::Fail,
                    Some(ScoredCategory::PolicyHard),
                ),
                ProbeRow::new(
                    "Oversized challenge",
                    "accepted 4096B",
                    SignalLevel::Warn,
                    Some(ScoredCategory::PolicySoft),
                ),
                ProbeRow::new(
                    "Keystore2",
                    "java hook style reply",
                    SignalLevel::Fail,
                    Some(ScoredCategory::Supplementary),
                ),
                ProbeRow::new(
                    "Timing side-channel",
                    "diff=0.25ms",
                    SignalLevel::Warn,
                    Some(ScoredCategory::Supplementary),
                ),
                ProbeRow::new(
                    "Native",
                    "ioctl text mismatch",
                    SignalLevel::Fail,
                    Some(ScoredCategory::Supplementary),
                ),
            ],
            Vec::new(),
        );

        assert_eq!(output.tamper_score, 60);

        let capped = evaluate(
            (0..8)
                .map(|index| {
                    ProbeRow::new(
                        format!("Hard {index}"),
                        "fail",
                        SignalLevel::Fail,
                        Some(ScoredCategory::PolicyHard),
                    )
                })
                .collect(),
            Vec::new(),
        );
        assert_eq!(capped.tamper_score, 100);
    }

    #[test]
    fn verdict_precedence_is_hard_then_soft_then_supplementary() {
        let hard = evaluate(
            vec![
                ProbeRow::new(
                    "Challenge",
                    "challenge mismatch",
                    SignalLevel::Fail,
                    Some(ScoredCategory::PolicyHard),
                ),
                ProbeRow::new(
                    "Oversized challenge",
                    "accepted 256B",
                    SignalLevel::Warn,
                    Some(ScoredCategory::PolicySoft),
                ),
                ProbeRow::new(
                    "Keystore2",
                    "java hook style reply",
                    SignalLevel::Fail,
                    Some(ScoredCategory::Supplementary),
                ),
            ],
            Vec::new(),
        );
        assert_eq!(hard.verdict, Verdict::Tampered);

        let soft = evaluate(
            vec![
                ProbeRow::new(
                    "Oversized challenge",
                    "accepted 256B",
                    SignalLevel::Warn,
                    Some(ScoredCategory::PolicySoft),
                ),
                ProbeRow::new(
                    "Keystore2",
                    "java hook style reply",
                    SignalLevel::Fail,
                    Some(ScoredCategory::Supplementary),
                ),
            ],
            Vec::new(),
        );
        assert_eq!(soft.verdict, Verdict::Suspicious);

        let supplementary = evaluate(
            vec![ProbeRow::new(
                "Keystore2",
                "java hook style reply",
                SignalLevel::Fail,
                Some(ScoredCategory::Supplementary),
            )],
            Vec::new(),
        );
        assert_eq!(supplementary.verdict, Verdict::Consistent);
    }

    #[test]
    fn supplementary_only_keeps_aligned_headline_and_review_summary() {
        let output = evaluate(
            vec![ProbeRow::new(
                "Keystore2",
                "native surface looks patched",
                SignalLevel::Warn,
                Some(ScoredCategory::Supplementary),
            )],
            Vec::new(),
        );

        assert_eq!(output.verdict, Verdict::Consistent);
        assert_eq!(
            output.headline,
            "Attestation aligned; local probes need review"
        );
        assert_eq!(
            output.summary,
            "Local blind probes raised review items while attestation stayed aligned."
        );
    }
}
