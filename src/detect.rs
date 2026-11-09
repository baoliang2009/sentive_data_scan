use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::config::Config;
use crate::model::Finding;
use crate::rules::RuleSet;
use crate::util::sha256_hex;

const MAX_OFFICE_UNCOMPRESSED: u64 = 256 * 1024 * 1024;

pub struct Detector {
    rules: RuleSet,
    max_file_size: u64,
    office_documents: bool,
    chunk_bytes: usize,
    context_chars: usize,
    store_raw: bool,
}

pub struct Extracted {
    pub text: String,
    pub content_hash: String,
    pub kind: &'static str,
}

pub enum ExtractOutcome {
    Content(Extracted),
    Skip(&'static str),
}

impl Detector {
    pub fn new(rules: RuleSet, config: &Config) -> Self {
        Self {
            rules,
            max_file_size: config.max_file_size_bytes(),
            office_documents: config.scan.office_documents,
            chunk_bytes: config.scan.chunk_kb.saturating_mul(1024),
            context_chars: config.scan.context_chars,
            store_raw: config.storage.store_raw_match,
        }
    }

    pub fn extract_file(&self, path: &Path) -> Result<ExtractOutcome> {
        let metadata =
            fs::metadata(path).with_context(|| format!("无法读取文件信息 {}", path.display()))?;
        if !metadata.is_file() {
            return Ok(ExtractOutcome::Skip("不是普通文件"));
        }
        if metadata.len() > self.max_file_size {
            return Ok(ExtractOutcome::Skip("超过大小上限"));
        }

        let extension = file_extension(path);
        if is_office_extension(&extension) {
            if !self.office_documents {
                return Ok(ExtractOutcome::Skip("Office 抽取已关闭"));
            }
            return self.extract_office(path, &extension);
        }
        if extension == "pdf" {
            return Ok(ExtractOutcome::Skip("PDF 暂不支持"));
        }
        if matches!(extension.as_str(), "doc" | "xls" | "ppt") {
            return Ok(ExtractOutcome::Skip("旧版 Office 格式暂不支持"));
        }

        let bytes = fs::read(path).with_context(|| format!("无法读取文件 {}", path.display()))?;
        if bytes.is_empty() {
            return Ok(ExtractOutcome::Skip("空文件"));
        }
        if looks_binary(&bytes) {
            return Ok(ExtractOutcome::Skip("二进制文件"));
        }
        let Some(text) = decode_text(&bytes) else {
            return Ok(ExtractOutcome::Skip("无法识别文本编码"));
        };
        if looks_like_garbage(&text) {
            return Ok(ExtractOutcome::Skip("疑似二进制内容"));
        }
        Ok(ExtractOutcome::Content(Extracted {
            text,
            content_hash: sha256_hex(&bytes),
            kind: "text",
        }))
    }

    pub fn detect(&self, text: &str, path: &Path) -> Vec<Finding> {
        self.rules.scan(
            text,
            path,
            self.chunk_bytes,
            self.context_chars,
            self.store_raw,
        )
    }

    fn extract_office(&self, path: &Path, extension: &str) -> Result<ExtractOutcome> {
        let bytes =
            fs::read(path).with_context(|| format!("无法读取 Office 文件 {}", path.display()))?;
        let content_hash = sha256_hex(&bytes);
        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor)
            .with_context(|| format!("无法解析 Office 容器 {}", path.display()))?;
        let mut text = String::new();
        let mut total = 0u64;

        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .with_context(|| format!("无法读取 Office 内部条目 {}", path.display()))?;
            if !entry.is_file() {
                continue;
            }
            let name = entry.name().to_string();
            if !is_office_content(&name, extension) {
                continue;
            }
            let size = entry.size();
            if total.saturating_add(size) > MAX_OFFICE_UNCOMPRESSED {
                return Ok(ExtractOutcome::Skip("Office 解压体积超过上限"));
            }
            let remaining = MAX_OFFICE_UNCOMPRESSED.saturating_sub(total);
            let mut data = Vec::with_capacity(size.min(8 * 1024 * 1024) as usize);
            entry
                .by_ref()
                .take(remaining)
                .read_to_end(&mut data)
                .with_context(|| format!("读取 Office 条目失败 {}", name))?;
            total += data.len() as u64;
            let xml = String::from_utf8_lossy(&data);
            strip_xml(&xml, &mut text);
            if !text.ends_with('\n') {
                text.push('\n');
            }
            if text.len() > 128 * 1024 * 1024 {
                break;
            }
        }

        if text.trim().is_empty() {
            return Ok(ExtractOutcome::Skip("Office 文档中没有可提取文本"));
        }
        Ok(ExtractOutcome::Content(Extracted {
            text,
            content_hash,
            kind: "office",
        }))
    }
}

pub fn file_extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub fn is_office_extension(extension: &str) -> bool {
    matches!(extension, "docx" | "xlsx" | "pptx")
}

fn is_office_content(name: &str, extension: &str) -> bool {
    match extension {
        "docx" => {
            name == "word/document.xml"
                || name.starts_with("word/header")
                || name.starts_with("word/footer")
                || name.starts_with("word/footnotes")
                || name.starts_with("word/endnotes")
        }
        "xlsx" => name == "xl/sharedStrings.xml" || name.starts_with("xl/worksheets/sheet"),
        "pptx" => name.starts_with("ppt/slides/slide"),
        _ => false,
    }
}

pub fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return false;
    }
    let sample = &bytes[..bytes.len().min(8192)];
    if sample.is_empty() {
        return false;
    }
    if sample.contains(&0) {
        return true;
    }
    let control = sample
        .iter()
        .filter(|byte| **byte < 0x09 || (**byte > 0x0d && **byte < 0x20))
        .count();
    control * 100 / sample.len() > 10
}

pub fn looks_like_garbage(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let sample: String = text.chars().take(4096).collect();
    let control = sample
        .chars()
        .filter(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
        .count();
    control * 100 / sample.chars().count().max(1) > 10
}

pub fn decode_text(bytes: &[u8]) -> Option<String> {
    if let Some((encoding, bom_length)) = encoding_rs::Encoding::for_bom(bytes) {
        let (decoded, _, _) = encoding.decode(&bytes[bom_length..]);
        return Some(decoded.into_owned());
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Some(text.to_string());
    }

    let mut detector = chardetng::EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        let replacement = decoded.chars().filter(|ch| *ch == '\u{FFFD}').count();
        if replacement > decoded.chars().count() / 20 {
            return None;
        }
    }
    Some(decoded.into_owned())
}

/// Strip XML tags while keeping human-visible text and paragraph breaks.
fn strip_xml(xml: &str, out: &mut String) {
    let bytes = xml.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => {
                let Some(relative_end) = xml[index..].find('>') else {
                    break;
                };
                let end = index + relative_end;
                let tag = &xml[index + 1..end];
                let tag_lower = tag.to_ascii_lowercase();
                if tag_lower.starts_with("/w:p")
                    || tag_lower.starts_with("/a:p")
                    || tag_lower.starts_with("/text:p")
                    || tag_lower.starts_with("/w:tr")
                {
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                } else if tag_lower.starts_with("w:tab")
                    || tag_lower.starts_with("w:br")
                    || tag_lower.starts_with("a:br")
                    || !(out.ends_with(' ') || out.ends_with('\n') || out.ends_with('\t'))
                {
                    out.push(' ');
                }
                index = end + 1;
            }
            b'&' => {
                if let Some(relative_end) = xml[index..].find(';') {
                    if relative_end <= 12 {
                        let entity = &xml[index..index + relative_end + 1];
                        if let Some(ch) = decode_entity(entity) {
                            out.push(ch);
                            index += relative_end + 1;
                            continue;
                        }
                    }
                }
                out.push('&');
                index += 1;
            }
            byte if byte.is_ascii() => {
                out.push(byte as char);
                index += 1;
            }
            _ => {
                if let Some(ch) = xml[index..].chars().next() {
                    out.push(ch);
                    index += ch.len_utf8();
                } else {
                    break;
                }
            }
        }
    }
    if out.len() > 256 * 1024 * 1024 {
        let cut = crate::util::floor_char_boundary(out, 256 * 1024 * 1024);
        out.truncate(cut);
    }
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "&amp;" => Some('&'),
        "&lt;" => Some('<'),
        "&gt;" => Some('>'),
        "&quot;" => Some('"'),
        "&apos;" => Some('\''),
        "&nbsp;" => Some(' '),
        _ if entity.starts_with("&#x") || entity.starts_with("&#X") => {
            u32::from_str_radix(&entity[3..entity.len() - 1], 16)
                .ok()
                .and_then(char::from_u32)
        }
        _ if entity.starts_with("&#") => entity[2..entity.len() - 1]
            .parse::<u32>()
            .ok()
            .and_then(char::from_u32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_sniff() {
        assert!(looks_binary(&[0, 1, 2, 3, 4]));
        assert!(!looks_binary("普通文本\n第二行".as_bytes()));
        assert!(!looks_binary(&[0xFF, 0xFE, b'h', 0, b'i', 0]));
    }

    #[test]
    fn decode_utf8_and_bom() {
        assert_eq!(decode_text("密码abc".as_bytes()).unwrap(), "密码abc");
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in "身份证".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_text(&utf16).unwrap(), "身份证");
    }

    #[test]
    fn xml_text_extraction() {
        let xml = r#"<w:document><w:body><w:p><w:r><w:t>身份证：</w:t></w:r><w:r><w:t>11010519491231002X</w:t></w:r></w:p></w:body></w:document>"#;
        let mut out = String::new();
        strip_xml(xml, &mut out);
        assert!(out.contains("身份证："));
        assert!(out.contains("11010519491231002X"));
    }

    #[test]
    fn office_extension_check() {
        assert!(is_office_extension("docx"));
        assert!(!is_office_extension("doc"));
        assert!(is_office_content("word/document.xml", "docx"));
        assert!(!is_office_content("word/styles.xml", "docx"));
    }
}
