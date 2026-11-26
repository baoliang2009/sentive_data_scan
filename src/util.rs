use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{Local, TimeZone};
use sha2::{Digest, Sha256};

/// 简单的并发连接上限。
///
/// 服务端每来一个连接就 `thread::spawn` 且没有上限时，连接风暴会耗尽线程
/// 栈与文件描述符；更糟的是 `thread::spawn` 失败会直接 panic。用这个守卫
/// 把“同时处理的连接数”钉死，超限时由调用方直接拒绝（drop 连接或回 503）。
#[derive(Debug)]
pub struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConnectionLimiter {
    pub const fn new(max: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max: if max == 0 { 1 } else { max },
        }
    }

    /// 尝试占用一个并发名额；返回的守卫 drop 时自动归还。
    pub fn try_acquire(&self) -> Option<ConnectionGuard<'_>> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnectionGuard { limiter: self }),
                Err(actual) => current = actual,
            }
        }
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max
    }
}

/// 并发名额守卫：drop 时归还名额。
#[derive(Debug)]
pub struct ConnectionGuard<'a> {
    limiter: &'a ConnectionLimiter,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// accept / recv 持续失败时的退避，避免 FD 耗尽（EMFILE）后进入 100% CPU 忙等。
///
/// `Interrupted`（信号打断）可以立即重试；其余错误通常是持续性的，
/// 立刻重试只会把 CPU 跑满、同时继续刷日志。
pub fn backoff_after_accept_error(error: &std::io::Error) {
    if error.kind() != std::io::ErrorKind::Interrupted {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// 读取一行（含末尾 `\n`），但**限制最大字节数**。
///
/// 这是避免「对端永不发换行导致无限缓冲」的关键：`BufRead::read_line` / `lines()`
/// 会一直读到换行或 EOF 才返回，对端若持续发送不含 `\n` 的数据，缓冲区就会无上限增长，
/// 最终把进程内存吃光（表现为内存/交换暴涨）。本函数一旦超过 `max` 立即返回错误。
///
/// 返回读取到的字节数；0 表示 EOF。`buf` 只包含本次读到的内容（已清空）。
pub fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<usize> {
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(buf.len());
        }
        // 本段里如果出现换行，只取到换行为止。
        if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
            let take = position + 1;
            if buf.len() + take > max {
                return Err(too_long());
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(buf.len());
        }
        // 整段都没有换行；若加上它会超限，立即报错而不是继续缓冲。
        if buf.len() + available.len() > max {
            return Err(too_long());
        }
        buf.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn too_long() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "单行长度超过上限（对端可能未发送换行符，已断开以防内存耗尽）",
    )
}

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

/// 解码 URL 百分号编码。
///
/// 必须在**字节**层面判断 `%XX`，不能按 `&str` 切片：URL 里出现
/// `%` + 多字节字符（`/%中文`）时，`[index + 1..index + 3]` 会切在 UTF-8
/// 字符中间并 panic。这里只在后两个字节都是 ASCII 十六进制数字时才解码，
/// 其余情况原样保留 `%`。
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit() =>
            {
                let hi = hex_value(bytes[index + 1]);
                let lo = hex_value(bytes[index + 2]);
                out.push((hi << 4) | lo);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// Mask a sensitive value so it can be safely stored, logged and displayed.
pub fn mask_value(rule_id: &str, value: &str) -> String {
    // 卡号/证件号常写成 "6222 0212 3456 7890" 或 "010-85612345"，
    // 掩码前先去掉分隔符，避免露出 "**** 128" 这种带空格的尾巴。
    let normalized;
    let value = if rule_id.contains("bank_card")
        || rule_id.contains("id_card")
        || rule_id.contains("mobile")
        || rule_id.contains("landline")
        || rule_id.contains("phone")
        || rule_id.contains("social_security")
        || rule_id.contains("passport")
    {
        normalized = value
            .chars()
            .filter(|ch| !matches!(ch, ' ' | '-' | '\u{3000}'))
            .collect::<String>();
        normalized.as_str()
    } else {
        value
    };
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
    if rule_id.contains("social_security") {
        return keep(2, 2);
    }
    if rule_id.contains("passport") {
        return keep(2, 2);
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

    #[test]
    fn bounded_read_stops_at_limit() {
        use std::io::BufReader;
        // 无换行的无限流：必须在上限处报错，而不是无限缓冲。
        let data = vec![b'A'; 100_000];
        let mut reader = BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let result = read_line_bounded(&mut reader, &mut buf, 1024);
        assert!(result.is_err(), "超过上限应报错");
        assert!(buf.len() <= 1024, "缓冲区不得超过上限");

        // 正常多行：逐行读取正确。
        let text = b"line one\nline two\n";
        let mut reader = BufReader::new(&text[..]);
        let mut buf = Vec::new();
        assert_eq!(read_line_bounded(&mut reader, &mut buf, 1024).unwrap(), 9);
        assert_eq!(buf, b"line one\n");
        assert_eq!(read_line_bounded(&mut reader, &mut buf, 1024).unwrap(), 9);
        assert_eq!(buf, b"line two\n");
        assert_eq!(read_line_bounded(&mut reader, &mut buf, 1024).unwrap(), 0);
    }

    #[test]
    fn bounded_read_handles_exact_limit() {
        use std::io::BufReader;
        let text = b"abcde\n";
        let mut reader = BufReader::new(&text[..]);
        let mut buf = Vec::new();
        // 恰好等于上限应成功。
        assert_eq!(read_line_bounded(&mut reader, &mut buf, 6).unwrap(), 6);
        // 上限小 1 应失败。
        let mut reader = BufReader::new(&text[..]);
        assert!(read_line_bounded(&mut reader, &mut buf, 5).is_err());
    }

    #[test]
    fn percent_decode_handles_multibyte_after_percent() {
        // 回归：`/%中` 曾按 &str 切片 panic（切在 UTF-8 字符中间）。
        // 现在必须原样返回而不是崩溃。
        assert_eq!(percent_decode("/%中"), "/%中");
        assert_eq!(percent_decode("%2Ftmp"), "/tmp");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%E6%A1%8C%E9%9D%A2"), "桌面");
        assert_eq!(percent_decode("/%"), "/%");
    }

    #[test]
    fn connection_limiter_caps_and_returns_slots() {
        let limiter = ConnectionLimiter::new(2);
        let first = limiter.try_acquire().expect("第一个名额");
        let second = limiter.try_acquire().expect("第二个名额");
        assert!(limiter.try_acquire().is_none(), "超限必须拒绝");
        assert_eq!(limiter.active(), 2);

        drop(first);
        assert_eq!(limiter.active(), 1);
        // 名额释放后可以再次获取。
        let third = limiter.try_acquire().expect("释放后应可再获取");
        assert!(limiter.try_acquire().is_none());
        drop(second);
        drop(third);
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn connection_limiter_zero_is_treated_as_one() {
        let limiter = ConnectionLimiter::new(0);
        assert_eq!(limiter.max(), 1);
        let _only = limiter.try_acquire().expect("至少允许一个连接");
        assert!(limiter.try_acquire().is_none());
    }
}
