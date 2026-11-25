use std::collections::HashMap;

use anyhow::{bail, Result};
use chrono::{Datelike, NaiveDate, Utc};

use super::tables::{BANK_BIN_RANGES, ID_PREFECTURE_PREFIXES, LANDLINE_AREA_CODES};

/// Post-match validators. They turn broad regexes into high-precision findings.
#[derive(Debug, Clone, PartialEq)]
pub enum Validator {
    /// Pure Luhn check, kept for custom rules.
    Luhn,
    /// Luhn + BIN 号段 + 卡号长度，用于国内银行卡。
    BankCard,
    CnIdCard,
    CnIdCard15,
    Phone,
    Landline,
    SocialSecurity,
    Passport,
    Placeholder,
    Entropy(f64),
}

impl Validator {
    pub fn validate(&self, value: &str) -> bool {
        match self {
            Validator::Luhn => is_luhn_valid(value),
            Validator::BankCard => is_bank_card_valid(value),
            Validator::CnIdCard => is_cn_id_card_valid(value),
            Validator::CnIdCard15 => is_cn_id_card_15_valid(value),
            Validator::Phone => is_cn_phone_valid(value),
            Validator::Landline => is_cn_landline_valid(value),
            Validator::SocialSecurity => is_cn_social_security_valid(value),
            Validator::Passport => is_cn_passport_valid(value),
            Validator::Placeholder => !is_placeholder(value),
            Validator::Entropy(min) => shannon_entropy(value) >= *min,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Validator::Luhn => "luhn".to_string(),
            Validator::BankCard => "bank_card".to_string(),
            Validator::CnIdCard => "cn_id".to_string(),
            Validator::CnIdCard15 => "cn_id_15".to_string(),
            Validator::Phone => "phone".to_string(),
            Validator::Landline => "landline".to_string(),
            Validator::SocialSecurity => "social_security".to_string(),
            Validator::Passport => "passport".to_string(),
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
        } else if matches!(lower.as_str(), "bank_card" | "cn_bank_card" | "pan") {
            Validator::BankCard
        } else if lower == "cn_id" {
            Validator::CnIdCard
        } else if lower == "cn_id_15" {
            Validator::CnIdCard15
        } else if lower == "phone" {
            Validator::Phone
        } else if lower == "landline" {
            Validator::Landline
        } else if matches!(lower.as_str(), "social_security" | "cn_social_security") {
            Validator::SocialSecurity
        } else if lower == "passport" {
            Validator::Passport
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

/// 18-digit resident ID: 行政区划 + 出生日期 + GB 11643 校验位。
///
/// 地区码只校验到地级市，避免新区县被误杀；这一步能挡掉绝大多数
/// 订单号、流水号、雪花 ID 等纯数字串。
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
    if !is_plausible_id_area(&upper[..6]) {
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

/// 15-digit legacy ID: 行政区划 + 出生日期（无校验位，靠地区码收敛）。
pub fn is_cn_id_card_15_valid(value: &str) -> bool {
    let value = value.trim();
    if value.len() != 15 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if !is_plausible_id_area(&value[..6]) {
        return false;
    }
    let year = format!("19{}", &value[6..8]);
    validate_date(&year, &value[8..10], &value[10..12])
}

/// 身份证前 6 位地区码是否落在真实行政区划内（只比对前 4 位）。
fn is_plausible_id_area(code: &str) -> bool {
    let prefix = match code.get(..4).and_then(|item| item.parse::<u32>().ok()) {
        Some(prefix) => prefix,
        None => return false,
    };
    ID_PREFECTURE_PREFIXES.binary_search(&prefix).is_ok()
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
    // 140-144、154 至今未分配给公众移动通信，命中基本是流水号。
    let prefix3: u32 = digits[..3].parse().unwrap_or(0);
    if (140..=144).contains(&prefix3) || prefix3 == 154 {
        return false;
    }
    if all_same(digits) || is_sequential(digits) || max_run(digits) >= 7 {
        return false;
    }
    !matches!(digits, "13800138000" | "10086000000" | "12345678901")
}

/// 固定电话：区号必须在真实区号表内，本地号码 7/8 位。
///
/// 这一步把 `01234567890`、`02023112412` 之类的长数字串挡在区号表外，
/// 并且只有书写了分隔符（`010-85612345`）时才接受 7 位本地号码；紧凑写法
/// 只认大城市常见的 8 位本地号码，避免把 `0202311241` 这类流水号当成座机。
pub fn is_cn_landline_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !digits.starts_with('0') || !(10..=12).contains(&digits.len()) {
        return false;
    }
    let separated = value.chars().any(|ch| ch == '-' || ch == ' ');
    // 去掉前导 0 后，区号长度为 2（010/02x）或 3（0xxx）。
    for area_len in [2usize, 3usize] {
        let split = 1 + area_len;
        if split >= digits.len() {
            continue;
        }
        let Ok(area) = digits[1..split].parse::<u32>() else {
            continue;
        };
        if LANDLINE_AREA_CODES.binary_search(&area).is_err() {
            continue;
        }
        let local = &digits[split..];
        if !(7..=8).contains(&local.len()) || local.starts_with('0') {
            continue;
        }
        if local.len() == 7 && !separated {
            continue;
        }
        if all_same(local) || is_sequential(local) || max_run(local) >= 7 {
            continue;
        }
        return true;
    }
    false
}

/// 社保卡卡号：各地规则不一，常见 9 位，也有 8/10/12/14 位。
///
/// 因为没有统一校验位，规则层强制要求“社保卡号/医保卡号”等标签，
/// 这里只排除明显的占位数字与顺序号。
pub fn is_cn_social_security_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !(8..=14).contains(&digits.len()) {
        return false;
    }
    if all_same(&digits) || is_sequential(&digits) {
        return false;
    }
    !matches!(digits.as_str(), "123456789" | "12345678" | "87654321")
}

/// 中国护照：G/E + 8 位、E + 字母（I/O 除外）+ 7 位、D/S/P + E + 7 位。
pub fn is_cn_passport_valid(value: &str) -> bool {
    let value = value.trim().to_ascii_uppercase();
    let bytes = value.as_bytes();
    if bytes.len() != 9 || !bytes[..1].iter().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let tail_digits = |start: usize| bytes[start..].iter().all(|b| b.is_ascii_digit());
    match bytes[0] {
        b'E' => match bytes[1] {
            b'I' | b'O' => false,
            b'0'..=b'9' => tail_digits(2) && &bytes[2..] != b"0000000",
            b'A'..=b'Z' => tail_digits(2) && &bytes[2..] != b"0000000",
            _ => false,
        },
        b'G' => tail_digits(1) && &bytes[1..] != b"00000000",
        b'D' | b'S' | b'P' => bytes[1] == b'E' && tail_digits(2) && &bytes[2..] != b"0000000",
        _ => false,
    }
}

/// 银行卡号：Luhn + BIN 号段 + 长度三者同时成立。
///
/// 另外把“本身就是合法身份证号”的数字排除掉，避免 15 位老身份证被
/// 误判成 Amex、18 位身份证被误判成银联卡。
pub fn is_bank_card_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
    let len = digits.len();
    if !(12..=19).contains(&len) {
        return false;
    }
    if all_same(&digits) || is_sequential(&digits) || max_run(&digits) >= 9 {
        return false;
    }
    if len == 18 && is_cn_id_card_valid(&digits) {
        return false;
    }
    if len == 15 && is_cn_id_card_15_valid(&digits) {
        return false;
    }
    if !is_known_card_bin(&digits) {
        return false;
    }
    is_luhn_valid(&digits)
}

/// 5 位 BIN 前缀 + 卡号长度是否命中公开号段表；未收录时回落到国际卡组织 IIN。
fn is_known_card_bin(digits: &str) -> bool {
    let len = digits.len();
    if let Ok(prefix) = digits[..5].parse::<u32>() {
        let index = BANK_BIN_RANGES.partition_point(|(low, _, _)| *low <= prefix);
        if index > 0 {
            let (low, high, mask) = BANK_BIN_RANGES[index - 1];
            if prefix >= low && prefix <= high {
                return mask & (1 << (len - 12)) != 0;
            }
        }
    }
    is_international_iin(digits, len)
}

fn is_international_iin(digits: &str, len: usize) -> bool {
    let bytes = digits.as_bytes();
    let number = |start: usize, end: usize| digits[start..end].parse::<u32>().ok();
    match bytes[0] {
        // Visa：13 / 16 / 19 位
        b'4' => matches!(len, 13 | 16 | 19),
        // Mastercard：51-55（16 位）、2221-2720（16 位）
        b'5' => len == 16 && (b'1'..=b'5').contains(&bytes[1]),
        b'2' => len == 16 && number(0, 4).is_some_and(|value| (2221..=2720).contains(&value)),
        b'3' => match number(0, 2) {
            Some(34 | 37) => len == 15,                          // Amex
            Some(30 | 36 | 38 | 39) => (14..=19).contains(&len), // Diners
            Some(35) => {
                number(0, 4).is_some_and(|v| (3528..=3589).contains(&v)) && (16..=19).contains(&len)
            } // JCB
            _ => false,
        },
        // Discover：6011 / 65 / 644-649（16-19 位）
        b'6' => {
            (16..=19).contains(&len)
                && (number(0, 4) == Some(6011)
                    || number(0, 2) == Some(65)
                    || number(0, 3).is_some_and(|value| (644..=649).contains(&value)))
        }
        _ => false,
    }
}

pub fn is_luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect();
    if !(12..=19).contains(&digits.len()) {
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

fn all_same(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => chars.all(|ch| ch == first),
        None => true,
    }
}

/// 123456、987654 之类的连续数字（按 10 取模，兼容 789012）。
fn is_sequential(value: &str) -> bool {
    let digits: Vec<i32> = value
        .chars()
        .filter_map(|ch| ch.to_digit(10).map(|digit| digit as i32))
        .collect();
    if digits.len() < 4 {
        return false;
    }
    let forward = digits.windows(2).all(|pair| (pair[0] + 1) % 10 == pair[1]);
    let backward = digits.windows(2).all(|pair| (pair[0] + 9) % 10 == pair[1]);
    forward || backward
}

fn max_run(value: &str) -> usize {
    let mut best = 0usize;
    let mut current = 0usize;
    let mut last = None;
    for ch in value.chars() {
        if Some(ch) == last {
            current += 1;
        } else {
            last = Some(ch);
            current = 1;
        }
        best = best.max(current);
    }
    best
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
        assert!(is_cn_id_card_valid("320102198001010016"));
        assert!(is_cn_id_card_valid("620102198001010017"));
        assert!(!is_cn_id_card_valid("110105194912310021"));
        assert!(!is_cn_id_card_valid("11010520991231002X"));
    }

    #[test]
    fn cn_id_rejects_numeric_noise() {
        // 合法校验位但地区码不存在（99 开头 / 0000 开头 / 时间戳开头）
        assert!(!is_cn_id_card_valid("990105194912310023"));
        assert!(!is_cn_id_card_valid("00010519491231002X"));
        assert!(!is_cn_id_card_valid("202311241530451234"));
        // 20 位雪花 ID / 订单号
        assert!(!is_cn_id_card_valid("1699999999999999999"));
    }

    #[test]
    fn cn_id_15() {
        assert!(is_cn_id_card_15_valid("110105491231002"));
        assert!(!is_cn_id_card_15_valid("110105991331002"));
        assert!(!is_cn_id_card_15_valid("990105491231002"));
    }

    #[test]
    fn bank_card_requires_bin_and_length() {
        // 622251（交通银行）16 位；622202（工行）只有 19 位版本
        assert!(is_bank_card_valid("6222511234567894"));
        assert!(is_bank_card_valid("6222021234567890128"));
        assert!(is_bank_card_valid("6217001234567890122"));
        assert!(is_bank_card_valid("4242 4242 4242 4242"));
        assert!(is_bank_card_valid("4242-4242-4242-4242"));
        // 银联 BIN 622202 在号段表里只有 19 位版本，16 位即使 Luhn 通过也不算
        assert!(!is_bank_card_valid("6222000000000009"));
        // 未收录的 BIN（777777 不在公开号段表，也不是国际卡组织号段）
        assert!(!is_bank_card_valid("7777771234567891"));
        assert!(!is_bank_card_valid("2023112415304500"));
        // Luhn 不通过
        assert!(!is_bank_card_valid("6222511234567895"));
    }

    #[test]
    fn bank_card_does_not_swallow_id_numbers() {
        assert!(!is_bank_card_valid("11010519491231002X"));
        assert!(!is_bank_card_valid("110105491231002"));
    }

    #[test]
    fn phone() {
        assert!(is_cn_phone_valid("13812345678"));
        assert!(is_cn_phone_valid("+86 138-1234-5678"));
        assert!(!is_cn_phone_valid("12812345678"));
        assert!(!is_cn_phone_valid("1381234567"));
        assert!(!is_cn_phone_valid("13800000000"));
        assert!(!is_cn_phone_valid("12345678901"));
    }

    #[test]
    fn landline_requires_real_area_code() {
        assert!(is_cn_landline_valid("010-85612345"));
        assert!(is_cn_landline_valid("0311-8561234"));
        assert!(is_cn_landline_valid("0755 82345678"));
        assert!(!is_cn_landline_valid("01234567890"));
        assert!(!is_cn_landline_valid("00000000000"));
        assert!(!is_cn_landline_valid("010-00000000"));
        // 连号多半是测试数据
        assert!(!is_cn_landline_valid("010-12345678"));
    }

    #[test]
    fn social_security() {
        assert!(is_cn_social_security_valid("220102198"));
        assert!(!is_cn_social_security_valid("111111111"));
        assert!(!is_cn_social_security_valid("123456789"));
        assert!(!is_cn_social_security_valid("12345678"));
    }

    #[test]
    fn passport() {
        assert!(is_cn_passport_valid("E12345678"));
        assert!(is_cn_passport_valid("EA1234567"));
        assert!(is_cn_passport_valid("G12345678"));
        assert!(is_cn_passport_valid("PE1234567"));
        assert!(!is_cn_passport_valid("EI1234567"));
        assert!(!is_cn_passport_valid("E00000000"));
        assert!(!is_cn_passport_valid("E1234567"));
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
        assert_eq!(
            parse_validators("bank_card,cn_social_security").unwrap(),
            vec![Validator::BankCard, Validator::SocialSecurity]
        );
    }
}
