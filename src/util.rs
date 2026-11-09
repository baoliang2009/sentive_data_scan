use std::path::Path;

use chrono::{Local, TimeZone};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn sha256_hex_str(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn format_ts(ts: i64) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

pub fn path_to_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Mask a sensitive value so it can be safely stored, logged and displayed.
pub fn mask_value(rule_id: &str, value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    let keep = |head: usize, tail: usize| -> String {
        let head = head.min(len);
        let tail = tail.min(len.saturating_sub(head));
        let mut out = String::new();
        out.extend(chars.iter().take(head));
        out.push_str("********");
        out.extend(chars.iter().skip(len - tail));
        out
    };

    if rule_id.contains("private_key") {
        return "PRIVATE KEY [已隐藏]".to_string();
    }
    if len < 8 {
        return "****".to_string();
    }
    if rule_id.contains("password")
        || rule_id.contains("secret")
        || rule_id.contains("token")
        || rule_id.contains("key")
    {
        if len < 12 {
            return "****".to_string();
        }
        return keep(4, 4);
    }
    if rule_id.contains("email") {
        if let Some((local, domain)) = value.split_once('@') {
            let local: Vec<char> = local.chars().collect();
            let head: String = local.iter().take(2).collect();
            return format!("{head}***@{domain}");
        }
        return keep(2, 2);
    }
    if rule_id.contains("id_card") {
        return keep(6, 4);
    }
    if rule_id.contains("mobile") || rule_id.contains("landline") || rule_id.contains("phone") {
        return keep(3, 4);
    }
    if rule_id.contains("bank_card") {
        return keep(4, 4);
    }
    keep(2, 2)
}

pub fn build_snippet(text: &str, start: usize, end: usize, masked: &str, context: usize) -> String {
    let start = start.min(text.len());
    let end = end.min(text.len()).max(start);
    let raw = &text[start..end];

    let line_start = text[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = text[end..]
        .find('\n')
        .map(|index| end + index)
        .unwrap_or(text.len());
    let line = &text[line_start..line_end];
    let max_len = context.saturating_mul(2).max(120);

    let (window_start, window_end) = if line.chars().count() <= max_len {
        (line_start, line_end)
    } else {
        let reach = context.max(60) / 2;
        (
            floor_char_boundary(text, start.saturating_sub(reach)).max(line_start),
            ceil_char_boundary(text, (end + reach).min(line_end)).min(line_end),
        )
    };

    let mut out = text[window_start..window_end]
        .replace('\r', "")
        .replace('\t', " ");
    out = out.replace(raw, masked);
    if window_start > line_start {
        out.insert(0, '…');
    }
    if window_end < line_end {
        out.push('…');
    }
    truncate_chars(out.trim(), 320)
}

pub fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub fn ceil_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

pub fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max).collect();
    out.push('…');
    out
}

pub fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn is_temp_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("~$") || lower.ends_with('~') || lower == ".ds_store" {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "tmp" | "temp" | "part" | "partial" | "crdownload" | "download" | "swp" | "swx" | "lock"
    )
}

pub fn effective_threads(configured: usize) -> usize {
    if configured > 0 {
        return configured.clamp(1, 64);
    }
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .clamp(1, 8)
}

pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 1.0 {
        format!("{} ms", duration.as_millis())
    } else if secs < 60.0 {
        format!("{secs:.1} s")
    } else {
        let minutes = (secs / 60.0).floor();
        let rest = secs - minutes * 60.0;
        format!("{minutes:.0} min {rest:.0} s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_values() {
        assert_eq!(
            mask_value("cn_id_card", "11010519491231002X"),
            "110105********002X"
        );
        assert_eq!(mask_value("cn_mobile", "13812345678"), "138********5678");
        assert_eq!(
            mask_value("email", "alice@example.com"),
            "al***@example.com"
        );
        assert!(!mask_value("password_assignment", "hunter2secret").contains("hunter2"));
        assert_eq!(mask_value("password_assignment", "abc123"), "****");
    }

    #[test]
    fn snippet_replaces_raw() {
        let text = "user=alice password=SuperSecret! host=localhost\n";
        let start = text.find("SuperSecret!").unwrap();
        let end = start + "SuperSecret!".len();
        let snippet = build_snippet(text, start, end, "Supe********cret!", 80);
        assert!(!snippet.contains("SuperSecret!"));
    }
}
