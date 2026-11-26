use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::config::Config;
use crate::model::Finding;
use crate::rules::RuleSet;
use crate::util::sha256_hex;

/// Office 压缩包解压后的总字节上限。
///
/// 原来是 256 MiB，配合“大文件锁只看压缩后大小”会让一个 8 MiB 的 docx
/// 膨胀到数百 MiB；多个扫描线程同时处理即可 OOM。这里压到 64 MiB，
/// 同时 `scan.rs` 会把 Office 文件也纳入大文件串行路径。
const MAX_OFFICE_UNCOMPRESSED: u64 = 64 * 1024 * 1024;

/// 抽取出的纯文本上限（字节）。超过后停止追加，避免 `text` 无界增长。
const MAX_OFFICE_TEXT_BYTES: usize = 32 * 1024 * 1024;

/// 单个 zip 条目一次性读取的上限；超过部分直接丢弃。
const MAX_OFFICE_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

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
            store_raw: config.storage.store_raw_match
                || (config.syslog.enabled && config.syslog.send_raw),
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
            if !self.office_documents {
                return Ok(ExtractOutcome::Skip("文档抽取已关闭"));
            }
            return self.extract_pdf(path);
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

    fn extract_pdf(&self, path: &Path) -> Result<ExtractOutcome> {
        let bytes =
            fs::read(path).with_context(|| format!("无法读取 PDF 文件 {}", path.display()))?;
        let content_hash = sha256_hex(&bytes);
        let mut text = match std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(&bytes)) {
            Ok(Ok(text)) => text,
            Ok(Err(error)) => {
                tracing::debug!(path = %path.display(), error = %error, "PDF 文本抽取失败");
                return Ok(ExtractOutcome::Skip("PDF 无法解析或已加密"));
            }
            Err(_) => {
                tracing::warn!(path = %path.display(), "PDF 解析触发异常，已跳过");
                return Ok(ExtractOutcome::Skip("PDF 解析异常"));
            }
        };
        if text.len() > MAX_OFFICE_TEXT_BYTES {
            let cut = crate::util::floor_char_boundary(&text, MAX_OFFICE_TEXT_BYTES);
            text.truncate(cut);
        }
        if text.trim().is_empty() {
            return Ok(ExtractOutcome::Skip("PDF 无可提取文本（可能是扫描图片）"));
        }
        Ok(ExtractOutcome::Content(Extracted {
            text,
            content_hash,
            kind: "pdf",
        }))
    }

    fn extract_office(&self, path: &Path, extension: &str) -> Result<ExtractOutcome> {
        let bytes =
            fs::read(path).with_context(|| format!("无法读取 Office 文件 {}", path.display()))?;
        let content_hash = sha256_hex(&bytes);
        if !bytes.starts_with(b"PK\x03\x04") {
            if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
                let text = extract_ole2_text(&bytes);
                if text.trim().is_empty() {
                    return Ok(ExtractOutcome::Skip("旧版 WPS 文档没有可提取文本"));
                }
                return Ok(ExtractOutcome::Content(Extracted {
                    text,
                    content_hash,
                    kind: "wps-ole2",
                }));
            }
            return Ok(ExtractOutcome::Skip("不支持的 Office/WPS 容器格式"));
        }
        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor)
            .with_context(|| format!("无法解析 Office 容器 {}", path.display()))?;
        let mut text = String::new();
        let mut total = 0u64;

        for index in 0..archive.len() {
            if text.len() >= MAX_OFFICE_TEXT_BYTES {
                break;
            }
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
            // `entry.size()` 来自压缩包头，完全由文件内容控制，只能当“上限提示”
            // 用；真正的读取量必须被 remaining 夹住。
            let size = entry.size();
            if total.saturating_add(size) > MAX_OFFICE_UNCOMPRESSED {
                return Ok(ExtractOutcome::Skip("Office 解压体积超过上限"));
            }
            let remaining = MAX_OFFICE_UNCOMPRESSED
                .saturating_sub(total)
                .min(MAX_OFFICE_ENTRY_BYTES);
            // 预分配用“实际将被读取的量”，而不是压缩包头声明的大小。
            let mut data = Vec::with_capacity(size.min(remaining).min(8 * 1024 * 1024) as usize);
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
        }
        if text.len() > MAX_OFFICE_TEXT_BYTES {
            let cut = crate::util::floor_char_boundary(&text, MAX_OFFICE_TEXT_BYTES);
            text.truncate(cut);
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
    matches!(extension, "docx" | "xlsx" | "pptx" | "wps" | "et" | "dps")
}

fn is_office_content(name: &str, extension: &str) -> bool {
    match extension {
        "docx" | "wps" => {
            name == "word/document.xml"
                || name.starts_with("word/header")
                || name.starts_with("word/footer")
                || name.starts_with("word/footnotes")
                || name.starts_with("word/endnotes")
        }
        "xlsx" | "et" => name == "xl/sharedStrings.xml" || name.starts_with("xl/worksheets/sheet"),
        "pptx" | "dps" => name.starts_with("ppt/slides/slide"),
        _ => false,
    }
}

/// 从旧版 WPS（OLE2 复合文档）中抽取连续可读文本（UTF-16LE 与 ASCII/UTF-8）。
fn extract_ole2_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    // 1. 提取 UTF-16LE 可读段（至少 4 个连续字符，覆盖中文与英文正文）
    let mut utf16_run: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let ch = char::from_u32(unit as u32);
        let readable = matches!(
            ch,
            Some(c) if (c.is_ascii_graphic() || c == ' ' || ('\u{4E00}'..='\u{9FFF}').contains(&c) || ('\u{3000}'..='\u{303F}').contains(&c) || ('\u{FF00}'..='\u{FFEF}').contains(&c))
        );
        if readable {
            utf16_run.push(unit);
            i += 2;
        } else {
            if utf16_run.len() >= 4 {
                out.push_str(&String::from_utf16_lossy(&utf16_run));
                out.push('\n');
            }
            utf16_run.clear();
            i += 2;
        }
    }
    if utf16_run.len() >= 4 {
        out.push_str(&String::from_utf16_lossy(&utf16_run));
        out.push('\n');
    }

    // 2. 提取单字节 ASCII 可读段（至少 6 个连续字符，兜底数字/邮箱/密钥）
    let mut ascii_run: Vec<u8> = Vec::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            ascii_run.push(b);
        } else {
            if ascii_run.len() >= 6 {
                out.push_str(&String::from_utf8_lossy(&ascii_run));
                out.push('\n');
            }
            ascii_run.clear();
        }
    }
    if ascii_run.len() >= 6 {
        out.push_str(&String::from_utf8_lossy(&ascii_run));
        out.push('\n');
    }

    if out.len() > MAX_OFFICE_TEXT_BYTES {
        let cut = crate::util::floor_char_boundary(&out, MAX_OFFICE_TEXT_BYTES);
        out.truncate(cut);
    }
    out
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
        assert!(is_office_extension("wps"));
        assert!(is_office_extension("et"));
        assert!(is_office_extension("dps"));
        assert!(!is_office_extension("doc"));
        assert!(is_office_content("word/document.xml", "docx"));
        assert!(is_office_content("word/document.xml", "wps"));
        assert!(!is_office_content("word/styles.xml", "docx"));
    }

    #[test]
    fn ole2_text_extraction_finds_utf16_and_ascii() {
        let mut raw = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00];
        for unit in "身份证 11010519491231002X".encode_utf16() {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
        raw.extend_from_slice(&[0x00, 0x00]);
        let extracted = extract_ole2_text(&raw);
        assert!(extracted.contains("11010519491231002X"));
    }
}
