use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Severity of a finding. Declaration order matters: `Critical` is the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Severity::Info => "提示",
            Severity::Low => "低",
            Severity::Medium => "中",
            Severity::High => "高",
            Severity::Critical => "严重",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" | "提示" | "信息" => Ok(Severity::Info),
            "low" | "低" | "低危" => Ok(Severity::Low),
            "medium" | "mid" | "中" | "中危" => Ok(Severity::Medium),
            "high" | "高" | "高危" => Ok(Severity::High),
            "critical" | "严重" | "紧急" => Ok(Severity::Critical),
            other => Err(format!("未知的严重级别: {other}")),
        }
    }
}

impl Serialize for Severity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// A single sensitive-data hit inside a file.
///
/// `raw` is only populated when `storage.store_raw_match = true`; it is skipped
/// in every serialized report by default. The persisted model is [`StoredFinding`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: Severity,
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    /// Masked value, safe to display and persist.
    pub masked: String,
    /// A short piece of the surrounding line, with the match replaced by `masked`.
    pub snippet: String,
    /// SHA-256 of the raw match, used for de-duplication.
    pub match_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip)]
    pub start: usize,
    #[serde(skip)]
    pub end: usize,
}

/// A finding as stored in SQLite and rendered in reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: i64,
    pub path: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: Severity,
    pub masked: String,
    pub line: usize,
    pub snippet: String,
    pub detected_at: i64,
    pub acknowledged: bool,
}

/// Aggregated result of one scan batch.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanSummary {
    pub files_seen: u64,
    pub files_scanned: u64,
    pub files_unchanged: u64,
    pub files_excluded: u64,
    pub files_skipped: u64,
    pub files_failed: u64,
    pub findings: u64,
    pub new_findings: u64,
    /// Findings still shown as unacknowledged; acknowledged ones are ignored by
    /// the "file modified again" reminder.
    pub unacknowledged: u64,
    pub by_severity: BTreeMap<Severity, u64>,
    pub new_by_severity: BTreeMap<Severity, u64>,
    pub examples: Vec<FindingExample>,
    #[serde(skip)]
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingExample {
    pub path: String,
    pub rule_name: String,
    pub severity: Severity,
    pub masked: String,
    pub line: usize,
}

impl ScanSummary {
    pub fn highest_new_severity(&self) -> Option<Severity> {
        self.new_by_severity
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(severity, _)| *severity)
            .max()
    }
}

/// Category display labels used by reports and notifications.
pub fn category_label(category: &str) -> &'static str {
    match category {
        "identity" => "身份信息",
        "contact" => "联系方式",
        "financial" => "金融账户",
        "credential" => "账号凭据",
        "crypto" => "密钥材料",
        "internal" => "内部数据",
        _ => "其他",
    }
}
