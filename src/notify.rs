#[allow(unused_imports)]
use anyhow::{bail, Context, Result};

use crate::config::NotifyConfig;
use crate::model::{ScanSummary, Severity};
use crate::util::{format_duration, truncate_chars};

pub struct Notifier {
    enabled: bool,
    min_severity: Severity,
    mode: String,
    sound: bool,
    max_per_batch: usize,
    macos_mode: String,
}

impl Notifier {
    pub fn new(config: &NotifyConfig) -> Self {
        Self {
            enabled: config.enabled && config.mode != "off",
            min_severity: config.min_severity,
            mode: config.mode.clone(),
            sound: config.sound,
            max_per_batch: config.max_per_batch.max(1),
            macos_mode: config.macos_mode.clone(),
        }
    }

    pub fn notify_scan(&self, summary: &ScanSummary) {
        if !self.enabled {
            return;
        }
        let qualifying: u64 = summary
            .new_by_severity
            .iter()
            .filter(|(severity, _)| **severity >= self.min_severity)
            .map(|(_, count)| *count)
            .sum();
        if qualifying == 0 {
            return;
        }
        let highest = summary.highest_new_severity().unwrap_or(self.min_severity);

        if self.mode == "per_file" && !summary.examples.is_empty() {
            let mut sent = 0usize;
            for example in summary.examples.iter() {
                if sent >= self.max_per_batch {
                    break;
                }
                if example.severity < self.min_severity {
                    continue;
                }
                let file_name = std::path::Path::new(&example.path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| example.path.clone());
                let body = format!(
                    "{} · 第 {} 行 · {}\n严重级别：{}",
                    file_name,
                    example.line,
                    example.rule_name,
                    highest.label_zh()
                );
                let title = format!("数据哨兵：发现{}风险", highest.label_zh());
                if let Err(error) =
                    send_desktop(&title, &body, highest, self.sound, &self.macos_mode)
                {
                    tracing::warn!(error = %error, "桌面通知发送失败");
                }
                sent += 1;
            }
            if qualifying > sent as u64 {
                notify_summary(self, summary, qualifying, highest);
            }
            return;
        }

        notify_summary(self, summary, qualifying, highest);
    }

    pub fn test(&self) -> Result<()> {
        send_desktop(
            "数据哨兵 · 通知测试",
            "桌面通知链路正常。发现敏感数据时将在此提醒。",
            Severity::Medium,
            self.sound,
            &self.macos_mode,
        )
    }
}

fn notify_summary(notifier: &Notifier, summary: &ScanSummary, qualifying: u64, highest: Severity) {
    let title = format!("数据哨兵：发现 {} 处敏感数据", qualifying);
    let mut body = format!("新增 {} 处，最高级别：{}。", qualifying, highest.label_zh());
    for example in summary.examples.iter().take(3) {
        let file_name = std::path::Path::new(&example.path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| example.path.clone());
        body.push_str(&format!(
            "\n{file_name} · {}（{}）",
            example.rule_name,
            example.severity.label_zh()
        ));
    }
    if notifier.mode == "summary" {
        tracing::info!(
            count = qualifying,
            elapsed = %format_duration(summary.duration),
            "已发送桌面通知"
        );
    }
    if let Err(error) = send_desktop(&title, &body, highest, notifier.sound, &notifier.macos_mode) {
        tracing::warn!(error = %error, "桌面通知发送失败");
    }
}

fn send_desktop(
    title: &str,
    body: &str,
    severity: Severity,
    sound: bool,
    macos_mode: &str,
) -> Result<()> {
    let title = truncate_chars(title, 80);
    let body = truncate_chars(body, 400);
    #[cfg(target_os = "macos")]
    {
        send_macos(&title, &body, severity, sound, macos_mode)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = sound;
        let _ = macos_mode;
        send_windows(&title, &body, severity)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = sound;
        let _ = macos_mode;
        send_linux(&title, &body, severity)
    }
}

#[cfg(target_os = "macos")]
fn send_macos(title: &str, body: &str, severity: Severity, sound: bool, mode: &str) -> Result<()> {
    let use_alert = match mode {
        "alert" => true,
        "notification" => false,
        // macOS Focus/Do Not Disturb can silently suppress Notification Center
        // banners; a real dialog is the only reliable popup. Use it for
        // medium/high/critical by default, and reserve notifications for low.
        _ => severity >= Severity::Medium,
    };

    if use_alert {
        return send_macos_alert(title, body, severity, sound);
    }
    send_macos_notification(title, body, sound)
}

#[cfg(target_os = "macos")]
fn send_macos_alert(title: &str, body: &str, severity: Severity, sound: bool) -> Result<()> {
    let icon = if severity >= Severity::Critical {
        "critical"
    } else {
        "warning"
    };
    let mut script = String::new();
    if sound {
        script.push_str("beep\n");
    }
    script.push_str(&format!(
        "display alert \"{}\" message \"{}\" as {} giving up after 20",
        escape_applescript(title),
        escape_applescript(body),
        icon
    ));
    let mut child = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .spawn()
        .context("无法调用 osascript 弹出对话框")?;
    let pid = child.id();
    // Reap the child in the background so the daemon is not blocked by a modal
    // dialog and no zombies accumulate.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    tracing::info!(pid, "已弹出 macOS 系统对话框");
    Ok(())
}

#[cfg(target_os = "macos")]
fn send_macos_notification(title: &str, body: &str, sound: bool) -> Result<()> {
    let sound_clause = if sound { " sound name \"Basso\"" } else { "" };
    let script = format!(
        "display notification \"{}\" with title \"{}\"{}",
        escape_applescript(body),
        escape_applescript(title),
        sound_clause
    );
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .context("无法调用 osascript")?;
    if !status.success() {
        bail!("osascript 返回失败状态");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn escape_applescript(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn send_linux(title: &str, body: &str, severity: Severity) -> Result<()> {
    let urgency = match severity {
        Severity::Critical | Severity::High => "critical",
        Severity::Medium => "normal",
        _ => "low",
    };
    let urgency_arg = format!("--urgency={urgency}");

    let attempts: Vec<(&str, Vec<&str>)> = vec![
        (
            "notify-send",
            vec![
                "--app-name=DataSentinel",
                "--icon=dialog-warning",
                urgency_arg.as_str(),
                "--expire-time=10000",
                title,
                body,
            ],
        ),
        (
            "kdialog",
            vec!["--title", title, "--passivepopup", body, "10"],
        ),
        (
            "zenity",
            vec![
                "--warning",
                "--no-wrap",
                "--timeout=10",
                "--title",
                title,
                "--text",
                body,
            ],
        ),
        ("xmessage", vec!["-timeout", "10", "-center", body]),
    ];

    let mut last_error = None;
    for (program, args) in attempts {
        match std::process::Command::new(program).args(args).status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_error = Some(format!("{program} 退出状态 {status}"));
            }
            Err(error) => {
                last_error = Some(format!("{program}: {error}"));
            }
        }
    }
    Err(anyhow::anyhow!(
        "所有 Linux 通知通道均失败: {}",
        last_error.unwrap_or_else(|| "未知错误".to_string())
    ))
}

#[cfg(target_os = "windows")]
fn send_windows(title: &str, body: &str, severity: Severity) -> Result<()> {
    let xml_title = xml_escape(title);
    let xml_body = xml_escape(body);
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$AppId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\WindowsPowerShell\v1.0\powershell.exe'
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>')
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)
"#,
        xml_title.replace('\'', "''"),
        xml_body.replace('\'', "''")
    );

    // Use -EncodedCommand instead of writing a temporary .ps1 and calling
    // -File: enterprise Group Policy can forbid script files even with
    // -ExecutionPolicy Bypass, and Windows PowerShell 5.1 would also decode a
    // BOM-less script with the ANSI code page (mojibake / invalid toast XML).
    // An encoded UTF-16LE command avoids both problems and leaves no temp file
    // for antivirus software to flag.
    let encoded = encode_powershell_command(&script);
    let output = {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: the toast is rendered by the shell, so the helper
        // PowerShell process must never flash a console window (or print its
        // errors into the parent console) on screen.
        std::process::Command::new(powershell_path())
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand"])
            .arg(&encoded)
            .creation_flags(0x0800_0000)
            .output()
    };

    match output {
        Ok(output) if output.status.success() => Ok(()),
        other => {
            match &other {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        status = %output.status,
                        stderr = %stderr.trim(),
                        "PowerShell Toast 发送失败，尝试 msg 降级"
                    );
                }
                Err(error) => {
                    tracing::warn!(error = %error, "无法启动 PowerShell，尝试 msg 降级");
                }
            }
            // Fallback for Windows editions where WinRT toast is unavailable.
            let _ = severity;
            use std::os::windows::process::CommandExt;
            let status = std::process::Command::new("msg")
                .arg("*")
                .arg(format!("{title}\n{body}"))
                .creation_flags(0x0800_0000)
                .status();
            match status {
                Ok(status) if status.success() => Ok(()),
                _ => bail!("Windows Toast 与 msg 通知均失败"),
            }
        }
    }
}

/// Prefer the absolute path of Windows PowerShell: a trimmed `PATH` (for
/// example when launched from a service or a restricted shell) would otherwise
/// make `Command::new("powershell.exe")` fail with "program not found".
#[cfg(target_os = "windows")]
fn powershell_path() -> std::path::PathBuf {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let candidate = std::path::PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if candidate.is_file() {
            return candidate;
        }
    }
    std::path::PathBuf::from("powershell.exe")
}

/// Encode a PowerShell script the way `powershell.exe -EncodedCommand` expects:
/// UTF-16LE bytes, base64 encoded without line breaks.
///
/// Kept platform-independent so the encoder itself can be unit tested.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn encode_powershell_command(script: &str) -> String {
    let mut utf16 = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    base64_encode(&utf16)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(value & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, encode_powershell_command};

    #[test]
    fn base64_matches_reference_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn powershell_command_is_utf16le_then_base64() {
        // "A" is 0x41 0x00 in UTF-16LE, which is "QQA=" in base64
        // ("QQ==" would be the UTF-8 byte 0x41).
        assert_eq!(encode_powershell_command("A"), "QQA=");
        // "AB" is 0x41 0x00 0x42 0x00 => "QQBCAA==".
        assert_eq!(encode_powershell_command("AB"), "QQBCAA==");
        // Non-ASCII must be encoded as UTF-16 code units, not UTF-8 bytes.
        // "数" is U+6570 => 0x70 0x65 little endian => "cGU=".
        assert_eq!(encode_powershell_command("数"), "cGU=");
        assert!(encode_powershell_command("Write-Host '数据'").is_ascii());
    }
}
