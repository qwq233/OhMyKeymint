use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Consistent,
    Suspicious,
    Tampered,
    Broken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalLevel {
    Pass,
    Info,
    Warn,
    Fail,
    Unavailable,
    Broken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoredCategory {
    PolicyHard,
    PolicySoft,
    Supplementary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeRow {
    pub label: String,
    pub value: String,
    pub level: SignalLevel,
    pub scored_category: Option<ScoredCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicion_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fatal_on_fail: Option<bool>,
}

impl ProbeRow {
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        level: SignalLevel,
        scored_category: Option<ScoredCategory>,
    ) -> Self {
        let label = label.into();
        let (suspicion_score, fatal_on_fail) = default_suspicion_metadata(&label)
            .map(|(score, fatal)| (Some(score), Some(fatal && scored_category.is_some())))
            .unwrap_or((None, None));
        Self {
            label,
            value: value.into(),
            level,
            scored_category,
            suspicion_score,
            fatal_on_fail,
        }
    }

    #[allow(dead_code)]
    pub fn with_suspicion(mut self, suspicion_score: u8, fatal_on_fail: bool) -> Self {
        self.suspicion_score = Some(suspicion_score);
        self.fatal_on_fail = Some(fatal_on_fail);
        self
    }
}

fn default_suspicion_metadata(label: &str) -> Option<(u8, bool)> {
    match label {
        "Boot consistency" => Some((95, true)),
        "Key pair consistency" => Some((98, true)),
        "Certificate chain" => Some((96, true)),
        "Pure cert follow-up" => Some((92, true)),
        "Alias lifecycle" => Some((42, false)),
        "Alias isolation" => Some((44, false)),
        "Attestation route marker" => Some((99, true)),
        "Native" => Some((48, false)),
        "Native binder parity" => Some((18, false)),
        "Native maps" => Some((24, false)),
        "Native fd" => Some((28, false)),
        "Native linker" => Some((26, false)),
        "Native smaps" => Some((22, false)),
        "Native binder timing" => Some((16, false)),
        "Native targeted residue" => Some((30, false)),
        "DER attestation sanity" => Some((20, false)),
        "AES-GCM operation" => Some((14, false)),
        "Key lifecycle" => Some((12, false)),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeOutput {
    pub headline: String,
    pub summary: String,
    pub verdict: Verdict,
    pub tamper_score: usize,
    pub policy_hard_count: usize,
    pub policy_soft_count: usize,
    pub supplementary_count: usize,
    pub rows: Vec<ProbeRow>,
    pub advisory_rows: Vec<ProbeRow>,
}

impl Verdict {
    pub fn as_text(self) -> &'static str {
        match self {
            Verdict::Consistent => "consistent",
            Verdict::Suspicious => "suspicious",
            Verdict::Tampered => "tampered",
            Verdict::Broken => "broken",
        }
    }
}

impl SignalLevel {
    pub fn as_text(self) -> &'static str {
        match self {
            SignalLevel::Pass => "PASS",
            SignalLevel::Info => "INFO",
            SignalLevel::Warn => "WARN",
            SignalLevel::Fail => "FAIL",
            SignalLevel::Unavailable => "UNAVAILABLE",
            SignalLevel::Broken => "BROKEN",
        }
    }
}

impl ScoredCategory {
    pub fn as_text(self) -> &'static str {
        match self {
            ScoredCategory::PolicyHard => "policy hard",
            ScoredCategory::PolicySoft => "policy soft",
            ScoredCategory::Supplementary => "supplementary",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn new_rows_attach_suspicion_metadata_for_new_probe_labels() {
        let row = ProbeRow::new(
            "Boot consistency",
            "matched",
            SignalLevel::Pass,
            Some(ScoredCategory::PolicyHard),
        );
        assert_eq!(row.suspicion_score, Some(95));
        assert_eq!(row.fatal_on_fail, Some(true));
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            json.get("suspicion_score").and_then(Value::as_u64),
            Some(95)
        );
        assert_eq!(
            json.get("fatal_on_fail").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn legacy_rows_keep_suspicion_metadata_absent() {
        let row = ProbeRow::new(
            "Challenge",
            "matched",
            SignalLevel::Pass,
            Some(ScoredCategory::PolicyHard),
        );
        assert_eq!(row.suspicion_score, None);
        assert_eq!(row.fatal_on_fail, None);
    }

    #[test]
    fn advisory_rows_never_carry_fatal_metadata() {
        let row = ProbeRow::new("Boot consistency", "unavailable", SignalLevel::Info, None);
        assert_eq!(row.suspicion_score, Some(95));
        assert_eq!(row.fatal_on_fail, Some(false));
    }
}
