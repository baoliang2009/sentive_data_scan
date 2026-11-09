pub mod builtin;
pub mod validator;

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use regex::{Regex, RegexSet};

use crate::config::{CustomRuleConfig, RulesConfig};
use crate::model::{Finding, Severity};
use crate::util::{
    build_snippet, ceil_char_boundary, floor_char_boundary, mask_value, sha256_hex_str,
};
use validator::{parse_validators, validate_all, Validator};

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: Severity,
    pub regex: Regex,
    pub keywords: Vec<String>,
    pub validators: Vec<Validator>,
    pub description: String,
    pub context_chars: usize,
}

pub struct RuleSet {
    rules: Vec<CompiledRule>,
    set: Option<RegexSet>,
    min_severity: Severity,
}

impl RuleSet {
    pub fn build(config: &RulesConfig) -> Result<Self> {
        let disabled: HashSet<&str> = config.disabled.iter().map(String::as_str).collect();
        let mut rules = Vec::new();
        let mut ids = HashSet::new();

        for spec in builtin::BUILTIN_RULES {
            if disabled.contains(spec.id) {
                continue;
            }
            let validators = parse_validators(spec.validators)
                .with_context(|| format!("内置规则 {} 的校验器配置无效", spec.id))?;
            let regex = Regex::new(spec.pattern)
                .with_context(|| format!("内置规则 {} 的正则编译失败", spec.id))?;
            rules.push(CompiledRule {
                id: spec.id.to_string(),
                name: spec.name.to_string(),
                category: spec.category.to_string(),
                severity: spec.severity,
                regex,
                keywords: spec.keywords.iter().map(|kw| kw.to_lowercase()).collect(),
                validators,
                description: spec.description.to_string(),
                context_chars: 160,
            });
            ids.insert(spec.id.to_string());
        }

        for custom in &config.custom {
            if !ids.insert(custom.id.clone()) {
                bail!("自定义规则 id 与已有规则重复: {}", custom.id);
            }
            rules.push(compile_custom(custom)?);
        }

        let patterns: Vec<&str> = rules.iter().map(|rule| rule.regex.as_str()).collect();
        let set = if patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(patterns.iter().copied()).context("规则集编译失败")?)
        };

        Ok(Self {
            rules,
            set,
            min_severity: config.min_severity,
        })
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Stable fingerprint of the active rule set. Stored in SQLite so that a
    /// rule/config change automatically triggers a full re-scan of unchanged
    /// files on the next run.
    pub fn fingerprint(&self) -> String {
        let mut material = String::new();
        material.push_str(self.min_severity.as_str());
        for rule in &self.rules {
            material.push('|');
            material.push_str(&rule.id);
            material.push(':');
            material.push_str(&rule.name);
            material.push(':');
            material.push_str(&rule.category);
            material.push(':');
            material.push_str(rule.severity.as_str());
            material.push(':');
            material.push_str(rule.regex.as_str());
            material.push(':');
            material.push_str(&rule.keywords.join(","));
            material.push(':');
            material.push_str(&rule.context_chars.to_string());
            material.push(':');
            let validators = rule
                .validators
                .iter()
                .map(Validator::describe)
                .collect::<Vec<_>>()
                .join(",");
            material.push_str(&validators);
        }
        sha256_hex_str(&material)
    }

    /// Scan a decoded text document. `chunk_bytes` controls the streaming block
    /// size; matches crossing block boundaries are covered by a 4 KiB overlap.
    pub fn scan(
        &self,
        text: &str,
        path: &Path,
        chunk_bytes: usize,
        context_chars: usize,
        store_raw: bool,
    ) -> Vec<Finding> {
        let Some(set) = &self.set else {
            return Vec::new();
        };
        if text.is_empty() {
            return Vec::new();
        }

        let line_index = LineIndex::new(text);
        let chunk_bytes = chunk_bytes.max(64 * 1024);
        let overlap = (chunk_bytes / 256).clamp(256, 4096);
        let mut collected: Vec<Finding> = Vec::new();
        let mut start = 0usize;

        while start < text.len() {
            let mut end = (start + chunk_bytes).min(text.len());
            if end < text.len() {
                end = ceil_char_boundary(text, (end + overlap).min(text.len()));
            }
            let slice = &text[start..end];

            for index in set.matches(slice).iter() {
                let rule = &self.rules[index];
                if rule.severity < self.min_severity {
                    continue;
                }
                if !rule.keywords.is_empty() && !self.keyword_hit(rule, text, start, end) {
                    continue;
                }
                for captures in rule.regex.captures_iter(slice) {
                    let Some(capture) = captures.get(1).or_else(|| captures.get(0)) else {
                        continue;
                    };
                    if capture.start() == capture.end() {
                        continue;
                    }
                    let absolute_start = start + capture.start();
                    let absolute_end = start + capture.end();
                    let value = capture.as_str();
                    if !validate_all(&rule.validators, value) {
                        continue;
                    }
                    let rule_context = context_chars.max(rule.context_chars);
                    if !rule.keywords.is_empty()
                        && !self.keyword_hit_value(
                            rule,
                            text,
                            absolute_start,
                            absolute_end,
                            rule_context,
                        )
                    {
                        continue;
                    }

                    let masked = mask_value(&rule.id, value);
                    let (line, column) = line_index.line_column(text, absolute_start);
                    let snippet =
                        build_snippet(text, absolute_start, absolute_end, &masked, rule_context);
                    collected.push(Finding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        category: rule.category.clone(),
                        severity: rule.severity,
                        path: path.to_path_buf(),
                        line,
                        column,
                        masked,
                        snippet,
                        match_hash: sha256_hex_str(value),
                        raw: if store_raw {
                            Some(value.to_string())
                        } else {
                            None
                        },
                        start: absolute_start,
                        end: absolute_end,
                    });
                    if collected.len() >= 20_000 {
                        tracing::warn!(
                            path = %path.display(),
                            "单个文件命中过多，已截断到 20000 条"
                        );
                        break;
                    }
                }
            }

            if end >= text.len() {
                break;
            }
            start = floor_char_boundary(text, end.saturating_sub(overlap));
        }

        dedupe(collected)
    }

    fn keyword_hit(&self, rule: &CompiledRule, text: &str, start: usize, end: usize) -> bool {
        let window_start = floor_char_boundary(text, start.saturating_sub(512));
        let window_end = ceil_char_boundary(text, (end + 512).min(text.len()));
        let window = text[window_start..window_end].to_lowercase();
        rule.keywords.iter().any(|keyword| window.contains(keyword))
    }

    fn keyword_hit_value(
        &self,
        rule: &CompiledRule,
        text: &str,
        start: usize,
        end: usize,
        context_chars: usize,
    ) -> bool {
        let reach = context_chars.max(80);
        let window_start = floor_char_boundary(text, start.saturating_sub(reach));
        let window_end = ceil_char_boundary(text, (end + reach).min(text.len()));
        let window = text[window_start..window_end].to_lowercase();
        rule.keywords.iter().any(|keyword| window.contains(keyword))
    }
}

fn compile_custom(custom: &CustomRuleConfig) -> Result<CompiledRule> {
    let regex = Regex::new(&custom.pattern)
        .with_context(|| format!("自定义规则 {} 的正则编译失败", custom.id))?;
    let validators = parse_validators(&custom.validator)
        .with_context(|| format!("自定义规则 {} 的校验器配置无效", custom.id))?;
    Ok(CompiledRule {
        id: custom.id.clone(),
        name: if custom.name.trim().is_empty() {
            custom.id.clone()
        } else {
            custom.name.clone()
        },
        category: if custom.category.trim().is_empty() {
            "internal".to_string()
        } else {
            custom.category.clone()
        },
        severity: custom.severity,
        regex,
        keywords: custom
            .keywords
            .iter()
            .map(|keyword| keyword.to_lowercase())
            .collect(),
        validators,
        description: custom.description.clone(),
        context_chars: custom.context_chars.max(80),
    })
}

fn dedupe(mut findings: Vec<Finding>) -> Vec<Finding> {
    // Prefer the highest severity at the same span, and only keep one hit per
    // (rule, value) pair per file to match the SQLite unique constraint.
    findings.sort_by_key(|finding| (std::cmp::Reverse(finding.severity), finding.start));
    let mut seen_values = HashSet::new();
    let mut seen_spans = HashSet::new();
    let mut kept = Vec::new();
    for finding in findings {
        let value_key = (finding.rule_id.clone(), finding.match_hash.clone());
        let span_key = (finding.start, finding.end);
        if seen_values.contains(&value_key) || seen_spans.contains(&span_key) {
            continue;
        }
        seen_values.insert(value_key);
        seen_spans.insert(span_key);
        kept.push(finding);
    }
    kept.sort_by_key(|finding| finding.start);
    kept
}

struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = Vec::with_capacity(text.len() / 48 + 1);
        starts.push(0);
        for (index, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(index + 1);
            }
        }
        Self { starts }
    }

    fn line_column(&self, text: &str, offset: usize) -> (usize, usize) {
        let line_index = match self.starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let line_start = self.starts[line_index];
        let column = text[line_start..offset].chars().count() + 1;
        (line_index + 1, column)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RuleSet {
        RuleSet::build(&RulesConfig::default()).unwrap()
    }

    #[test]
    fn detects_id_phone_and_password() {
        let text = "联系人 13812345678\n身份证 11010519491231002X\npassword = \"a8F#k2Lm9Qz!\"\n";
        let findings = rules().scan(text, Path::new("test.txt"), 1 << 20, 160, false);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"cn_mobile"));
        assert!(ids.contains(&"cn_id_card"));
        assert!(ids.contains(&"password_assignment"));
        assert!(findings.iter().all(|finding| finding.raw.is_none()));
        assert!(findings
            .iter()
            .all(|finding| !finding.snippet.contains("13812345678")));

        let formatted = rules().scan(
            "电话 +86 138-1234-5678",
            Path::new("test.txt"),
            1 << 20,
            160,
            false,
        );
        assert!(formatted
            .iter()
            .any(|finding| finding.rule_id == "cn_mobile"));
    }

    #[test]
    fn rejects_invalid_checksums() {
        let text = "110105194912310021\n4111111111111112\n";
        let findings = rules().scan(text, Path::new("test.txt"), 1 << 20, 160, false);
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "cn_id_card"));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "bank_card"));
    }

    #[test]
    fn detects_chunk_boundary() {
        let text = format!("{}{}", "a".repeat(70_000), " 13812345678 ");
        let findings = rules().scan(&text, Path::new("big.txt"), 64 * 1024, 160, false);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "cn_mobile"));
    }

    #[test]
    fn custom_rule_with_keyword() {
        let config = RulesConfig {
            custom: vec![CustomRuleConfig {
                id: "employee".to_string(),
                name: "员工编号".to_string(),
                category: "internal".to_string(),
                severity: Severity::High,
                pattern: r"EMP-\d{6}".to_string(),
                keywords: vec!["员工".to_string()],
                validator: "none".to_string(),
                description: String::new(),
                context_chars: 160,
            }],
            ..RulesConfig::default()
        };
        let rules = RuleSet::build(&config).unwrap();
        let hit = rules.scan("员工 EMP-123456", Path::new("a.txt"), 1 << 20, 160, false);
        assert_eq!(hit.len(), 1);
        let miss = rules.scan("EMP-123456", Path::new("a.txt"), 1 << 20, 160, false);
        assert!(miss.is_empty());
    }

    #[test]
    fn fingerprint_changes_with_rules() {
        let base = RuleSet::build(&RulesConfig::default()).unwrap();
        let same = RuleSet::build(&RulesConfig::default()).unwrap();
        assert_eq!(base.fingerprint(), same.fingerprint());

        let mut disabled = RulesConfig::default();
        disabled.disabled.push("cn_mobile".to_string());
        let changed = RuleSet::build(&disabled).unwrap();
        assert_ne!(base.fingerprint(), changed.fingerprint());
    }
}
