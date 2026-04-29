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
}

impl ProbeRow {
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        level: SignalLevel,
        scored_category: Option<ScoredCategory>,
    ) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            level,
            scored_category,
        }
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
