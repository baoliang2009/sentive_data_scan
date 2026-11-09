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

    let path = std::env::temp_dir().join(format!(
        "datasentinel-notify-{}-{}.ps1",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::write(&path, script).context("写入 Windows 通知脚本失败")?;
    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&path)
        .status();
    let _ = std::fs::remove_file(&path);

    match result {
        Ok(status) if status.success() => Ok(()),
        _ => {
            // Fallback for Windows editions where WinRT toast is unavailable.
            let _ = severity;
            let status = std::process::Command::new("msg")
                .arg("*")
                .arg(format!("{title}\n{body}"))
                .status();
            match status {
                Ok(status) if status.success() => Ok(()),
                _ => bail!("Windows Toast 与 msg 通知均失败"),
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
