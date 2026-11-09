//! Comment-preserving edits of `config.toml`.
//!
//! Re-serializing the deserialized `Config` would drop every explanatory
//! comment in the shipped default file, so the console patches individual keys
//! in place and leaves the rest of the document untouched.

/// Replace `key` inside `[section]`, inserting it when missing.
pub fn set_key(text: &str, section: &str, key: &str, literal: &str) -> String {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let header = format!("[{section}]");

    let Some(start) = lines.iter().position(|line| line.trim() == header) else {
        while lines
            .last()
            .map(|line| line.trim().is_empty())
            .unwrap_or(false)
        {
            lines.pop();
        }
        lines.push(String::new());
        lines.push(header);
        lines.push(format!("{key} = {literal}"));
        lines.push(String::new());
        return lines.join("\n");
    };

    let mut end = lines.len();
    let mut existing = None;
    for (index, line) in lines.iter().enumerate().skip(start + 1) {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            end = index;
            break;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            if name.trim() == key {
                existing = Some(index);
            }
        }
    }

    match existing {
        Some(index) => {
            let indent: String = lines[index]
                .chars()
                .take_while(|ch| *ch == ' ' || *ch == '\t')
                .collect();
            lines[index] = format!("{indent}{key} = {literal}");
        }
        None => {
            let mut insert_at = start + 1;
            for (index, line) in lines.iter().enumerate().take(end).skip(start + 1) {
                if !line.trim().is_empty() {
                    insert_at = index + 1;
                }
            }
            lines.insert(insert_at, format!("{key} = {literal}"));
        }
    }
    lines.join("\n")
}

/// Encode a JSON value as a TOML literal.
pub fn toml_literal(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Array(items) => {
            let encoded: Vec<String> = items
                .iter()
                .map(|item| match item {
                    serde_json::Value::String(text) => {
                        serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string())
                    }
                    other => other.to_string(),
                })
                .collect();
            format!("[{}]", encoded.join(", "))
        }
        serde_json::Value::String(text) => {
            serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string())
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# 头部注释\n[scan]\n# 扫描目录\nroots = []\nmax_file_size_mb = 64\n\n[notify]\nenabled = true\n";

    #[test]
    fn replaces_value_and_keeps_comments() {
        let updated = set_key(SAMPLE, "scan", "max_file_size_mb", "128");
        assert!(updated.contains("# 扫描目录"));
        assert!(updated.contains("max_file_size_mb = 128"));
        let parsed: toml::Value = toml::from_str(&updated).unwrap();
        assert_eq!(parsed["scan"]["max_file_size_mb"].as_integer(), Some(128));
    }

    #[test]
    fn inserts_missing_key_into_section() {
        let updated = set_key(SAMPLE, "notify", "mode", "\"summary\"");
        let parsed: toml::Value = toml::from_str(&updated).unwrap();
        assert_eq!(parsed["notify"]["mode"].as_str(), Some("summary"));
        assert!(updated.contains("enabled = true"));
    }

    #[test]
    fn creates_missing_section() {
        let updated = set_key(SAMPLE, "storage", "retention_days", "30");
        let parsed: toml::Value = toml::from_str(&updated).unwrap();
        assert_eq!(parsed["storage"]["retention_days"].as_integer(), Some(30));
        assert!(updated.contains("[storage]"));
    }

    #[test]
    fn encodes_arrays() {
        let value = serde_json::json!(["/tmp/a", "/tmp/b"]);
        assert_eq!(toml_literal(&value), "[\"/tmp/a\", \"/tmp/b\"]");
    }
}
