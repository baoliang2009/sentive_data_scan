use std::collections::HashMap;

use anyhow::{bail, Result};
use chrono::{Datelike, NaiveDate, Utc};

/// Post-match validators. They turn broad regexes into high-precision findings.
#[derive(Debug, Clone, PartialEq)]
pub enum Validator {
    Luhn,
    CnIdCard,
    CnIdCard15,
    Phone,
    Placeholder,
    Entropy(f64),
}

impl Validator {
    pub fn validate(&self, value: &str) -> bool {
        match self {
            Validator::Luhn => is_luhn_valid(value),
            Validator::CnIdCard => is_cn_id_card_valid(value),
            Validator::CnIdCard15 => is_cn_id_card_15_valid(value),
            Validator::Phone => is_cn_phone_valid(value),
            Validator::Placeholder => !is_placeholder(value),
            Validator::Entropy(min) => shannon_entropy(value) >= *min,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Validator::Luhn => "luhn".to_string(),
            Validator::CnIdCard => "cn_id".to_string(),
            Validator::CnIdCard15 => "cn_id_15".to_string(),
            Validator::Phone => "phone".to_string(),
            Validator::Placeholder => "placeholder".to_string(),
            Validator::Entropy(min) => format!("entropy:{min}"),
        }
    }
}

/// Parse a comma separated validator specification, e.g.
/// `"entropy:3.2,placeholder"`.
pub fn parse_validators(spec: &str) -> Result<Vec<Validator>> {
    let mut validators = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() || token.eq_ignore_ascii_case("none") {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        let validator = if lower == "luhn" {
            Validator::Luhn
        } else if lower == "cn_id" {
            Validator::CnIdCard
        } else if lower == "cn_id_15" {
            Validator::CnIdCard15
        } else if lower == "phone" {
            Validator::Phone
        } else if lower == "placeholder" {
            Validator::Placeholder
        } else if let Some(threshold) = lower.strip_prefix("entropy:") {
            let threshold: f64 = threshold
                .parse()
                .map_err(|_| anyhow::anyhow!("无效的熵阈值: {token}"))?;
            Validator::Entropy(threshold)
        } else {
            bail!("未知的校验器: {token}");
        };
        validators.push(validator);
    }
    Ok(validators)
}

pub fn validate_all(validators: &[Validator], value: &str) -> bool {
    validators.iter().all(|validator| validator.validate(value))
}

pub fn is_cn_id_card_valid(value: &str) -> bool {
    let value = value.trim();
    if value.chars().count() != 18 {
        return false;
    }
    let upper = value.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    if !bytes[..17].iter().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if !validate_date(&upper[6..10], &upper[10..12], &upper[12..14]) {
        return false;
    }

    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: &[u8] = b"10X98765432";
    let sum: u32 = upper[..17]
        .chars()
        .zip(WEIGHTS.iter())
        .map(|(ch, weight)| ch.to_digit(10).unwrap_or(0) * weight)
        .sum();
    let expected = CHECK[(sum % 11) as usize] as char;
    upper.chars().nth(17) == Some(expected)
}

pub fn is_cn_id_card_15_valid(value: &str) -> bool {
    let value = value.trim();
    if value.len() != 15 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let year = format!("19{}", &value[6..8]);
    validate_date(&year, &value[8..10], &value[10..12])
}

fn validate_date(year: &str, month: &str, day: &str) -> bool {
    let (Ok(year), Ok(month), Ok(day)) = (
        year.parse::<i32>(),
        month.parse::<u32>(),
        day.parse::<u32>(),
    ) else {
        return false;
    };
    let current_year = Utc::now().year();
    if !(1900..=current_year + 1).contains(&year) {
        return false;
    }
    NaiveDate::from_ymd_opt(year, month, day).is_some()
}

pub fn is_cn_phone_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    let digits = if digits.len() == 13 && digits.starts_with("86") {
        &digits[2..]
    } else {
        digits.as_str()
    };
    if digits.len() != 11 {
        return false;
    }
    let bytes = digits.as_bytes();
    if bytes[0] != b'1' || !(b'3'..=b'9').contains(&bytes[1]) {
        return false;
    }
    if digits.bytes().all(|byte| byte == bytes[0]) {
        return false;
    }
    !matches!(digits, "13800138000" | "10086000000" | "12345678901")
}

pub fn is_luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if digits.iter().all(|digit| *digit == digits[0]) {
        return false;
    }

    let mut sum = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        if index % 2 == 1 {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
    }
    sum % 10 == 0
}

pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    let mut len = 0usize;
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
        len += 1;
    }
    let len = len as f64;
    counts.values().fold(0.0, |entropy, count| {
        let probability = *count as f64 / len;
        entropy - probability * probability.log2()
    })
}

pub fn is_placeholder(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "xxxx",
        "****",
        "example",
        "sample",
        "dummy",
        "changeme",
        "change_me",
        "placeholder",
        "your_",
        "your-",
        "test123",
        "123456",
        "abcdef",
        "null",
        "none",
        "todo",
        "fixme",
        "redacted",
        "hidden",
        "undefined",
    ];
    if PLACEHOLDERS.iter().any(|item| lower.contains(item)) {
        return true;
    }
    if lower.contains("${")
        || lower.contains("{{")
        || lower.contains("%{")
        || lower.contains("os.environ")
        || lower.contains("process.env")
        || lower.contains("getenv")
        || lower.contains("<%")
        || lower.contains("vault://")
    {
        return true;
    }
    if value.starts_with('<') && value.ends_with('>') {
        return true;
    }

    let chars: Vec<char> = value.chars().collect();
    if chars.len() >= 4 && chars.windows(2).all(|pair| pair[0] == pair[1]) {
        return true;
    }

    // Repeated blocks such as "abcabcabc".
    let mut unique = std::collections::HashSet::new();
    for ch in &chars {
        unique.insert(*ch);
    }
    if unique.len() <= 2 && chars.len() >= 8 {
        return true;
    }
    for block in 2..=chars.len() / 2 {
        if chars.len() % block == 0 && chars.chunks(block).all(|chunk| chunk == &chars[..block]) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cn_id_checksum() {
        assert!(is_cn_id_card_valid("11010519491231002X"));
        assert!(!is_cn_id_card_valid("110105194912310021"));
        assert!(!is_cn_id_card_valid("11010520991231002X"));
    }

    #[test]
    fn cn_id_15() {
        assert!(is_cn_id_card_15_valid("110105491231002"));
        assert!(!is_cn_id_card_15_valid("110105991331002"));
    }

    #[test]
    fn phone() {
        assert!(is_cn_phone_valid("13812345678"));
        assert!(is_cn_phone_valid("+86 138-1234-5678"));
        assert!(!is_cn_phone_valid("12812345678"));
        assert!(!is_cn_phone_valid("1381234567"));
    }

    #[test]
    fn luhn() {
        assert!(is_luhn_valid("4111111111111111"));
        assert!(!is_luhn_valid("4111111111111112"));
    }

    #[test]
    fn placeholders() {
        assert!(is_placeholder("your_password_here"));
        assert!(is_placeholder("${DB_PASSWORD}"));
        assert!(!is_placeholder("a8F#k2Lm9Qz!"));
    }

    #[test]
    fn parse() {
        let validators = parse_validators("entropy:3.2, placeholder").unwrap();
        assert_eq!(validators.len(), 2);
        assert!(parse_validators("bogus").is_err());
    }
}
