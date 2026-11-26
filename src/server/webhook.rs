//! 服务端主动告警推送（Webhook）：支持通用 JSON、企业微信、钉钉、飞书。
//!
//! 通过有界队列 + 单后台线程异步发送，避免外部网络抖动阻塞 syslog 接收。

use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::model::Severity;
use crate::server::config::WebhookConfig;
use crate::server::store::{IncomingBatch, IncomingFinding};

pub struct WebhookDispatcher {
    tx: SyncSender<Job>,
    config: WebhookConfig,
}

enum Job {
    Alert {
        hostname: String,
        username: String,
        finding: IncomingFinding,
    },
}

impl WebhookDispatcher {
    pub fn spawn(config: &WebhookConfig) -> Option<Arc<Self>> {
        if !config.enabled || config.url.trim().is_empty() {
            return None;
        }
        let (tx, rx) = sync_channel::<Job>(1024);
        let cfg = config.clone();
        std::thread::Builder::new()
            .name("sentinel-webhook".into())
            .spawn(move || {
                tracing::info!(
                    format = %cfg.format,
                    min_severity = cfg.min_severity.as_str(),
                    "服务端 Webhook 主动告警推送已启用"
                );
                while let Ok(job) = rx.recv() {
                    match job {
                        Job::Alert {
                            hostname,
                            username,
                            finding,
                        } => {
                            let body = format_payload(&cfg.format, &hostname, &username, &finding);
                            if let Err(error) = send_webhook(&cfg, &body) {
                                tracing::warn!(error = %error, "Webhook 告警推送失败");
                            }
                        }
                    }
                }
            })
            .ok()?;
        Some(Arc::new(Self {
            tx,
            config: config.clone(),
        }))
    }

    pub fn notify_batch(&self, batch: &IncomingBatch) {
        for finding in &batch.findings {
            let severity: Severity = finding.severity.trim().parse().unwrap_or(Severity::Medium);
            if severity < self.config.min_severity {
                continue;
            }
            let job = Job::Alert {
                hostname: batch.hostname.clone(),
                username: batch.username.clone(),
                finding: finding.clone(),
            };
            if let Err(TrySendError::Full(_)) = self.tx.try_send(job) {
                tracing::debug!("Webhook 推送队列已满，已丢弃一条告警");
            }
        }
    }

    pub fn send_test(&self) -> Result<()> {
        let sample = IncomingFinding {
            rule_id: "webhook_test".to_string(),
            rule_name: "连通性测试".to_string(),
            category: "internal".to_string(),
            severity: Severity::High.as_str().to_string(),
            masked: "138********5678".to_string(),
            matched: "138********5678".to_string(),
            file_name: "test.txt".to_string(),
            path: "/tmp/test.txt".to_string(),
            line: 1,
            column: 1,
            snippet: "DataSentinel 服务端告警推送测试".to_string(),
            match_hash: "test".to_string(),
            time: chrono::Utc::now().to_rfc3339(),
        };
        let body = format_payload(&self.config.format, "sentinel-server", "admin", &sample);
        send_webhook(&self.config, &body)
    }
}

fn send_webhook(config: &WebhookConfig, payload: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(payload)?;
    let status = crate::sync::post_json(config.url.trim(), &bytes, config.insecure_tls)?;
    if !(200..300).contains(&status) {
        bail!("Webhook 返回异常状态码：HTTP {status}");
    }
    Ok(())
}

fn format_payload(
    format: &str,
    hostname: &str,
    username: &str,
    finding: &IncomingFinding,
) -> Value {
    let user = if username.trim().is_empty() {
        hostname
    } else {
        username
    };
    let file_name = if finding.file_name.trim().is_empty() {
        finding
            .path
            .rsplit(['/', '\\'])
            .find(|s| !s.is_empty())
            .unwrap_or("未知文件")
    } else {
        finding.file_name.trim()
    };
    let matched = if finding.matched.trim().is_empty() {
        finding.masked.trim()
    } else {
        finding.matched.trim()
    };
    let text = format!(
        "【数据哨兵敏感数据告警】\n级别：{}\n用户/主机：{} ({})\n规则：{}\n文件：{} ({})\n命中内容：{}",
        finding.severity, user, hostname, finding.rule_name, file_name, finding.path, matched
    );

    match format.to_ascii_lowercase().as_str() {
        "wecom" => json!({
            "msgtype": "markdown",
            "markdown": { "content": text }
        }),
        "dingtalk" => json!({
            "msgtype": "markdown",
            "markdown": {
                "title": "数据哨兵敏感数据告警",
                "text": text
            }
        }),
        "feishu" => json!({
            "msg_type": "text",
            "content": { "text": text }
        }),
        _ => json!({
            "event": "sensitive_alert",
            "hostname": hostname,
            "username": username,
            "severity": finding.severity,
            "category": finding.category,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "file_name": file_name,
            "path": finding.path,
            "line": finding.line,
            "matched": matched,
            "masked": finding.masked,
            "snippet": finding.snippet,
            "time": finding.time,
        }),
    }
}
