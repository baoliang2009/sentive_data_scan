//! 服务端 syslog 接收器：解析 RFC 5424 报文，把 JSON 载荷落库。
//!
//! 同时接受两种上报形态，方便不同客户端接入：
//! 1. **RFC 5424 报文**（`sentinel` 客户端默认形态）：从 PRI/HEADER 之后
//!    取 MSG，MSG 是一行 JSON。
//! 2. **裸 JSON 行**（脚本、其他语言客户端）：直接丢弃前导 `<PRI>` 后解析。
//!
//! 解析失败的报文只记日志并计数，绝不让一个坏包拖垮接收循环。

use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::config::ServerConfig;
use super::store::{IncomingBatch, IncomingFinding, ServerStore};

/// 接收统计，供控制台展示。
#[derive(Debug, Default)]
pub struct IngestStats {
    pub packets: AtomicU64,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub events: AtomicU64,
    /// 收到并处理成功的终端心跳数。
    pub heartbeats: AtomicU64,
}

impl IngestStats {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "packets": self.packets.load(Ordering::Relaxed),
            "accepted": self.accepted.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "events": self.events.load(Ordering::Relaxed),
            "heartbeats": self.heartbeats.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Deserialize)]
struct SinglePayload {
    #[serde(default)]
    event: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    rule_name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    masked: String,
    #[serde(default)]
    file_name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    line: i64,
    #[serde(default)]
    column: i64,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    match_hash: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    time: String,
}

impl SinglePayload {
    fn into_batch(self) -> Option<IncomingBatch> {
        // 连通性测试报文没有敏感数据，只用于确认链路。
        if self.event == "test" {
            return None;
        }
        if self.rule_id.trim().is_empty() {
            return None;
        }
        Some(IncomingBatch {
            agent_id: self.agent_id,
            hostname: self.hostname,
            username: self.username,
            platform: self.platform,
            version: self.version,
            rule_revision: 0,
            findings: vec![IncomingFinding {
                rule_id: self.rule_id,
                rule_name: self.rule_name,
                category: self.category,
                severity: self.severity,
                masked: if self.masked.trim().is_empty() {
                    self.value.clone()
                } else {
                    self.masked.clone()
                },
                matched: if self.value.trim().is_empty() {
                    self.masked
                } else {
                    self.value
                },
                file_name: self.file_name,
                path: self.path,
                line: self.line,
                column: self.column,
                snippet: self.snippet,
                match_hash: self.match_hash,
                time: self.time,
            }],
        })
    }
}

/// 从一行报文里提取 JSON。
///
/// RFC 5424 形如：`<35>1 2026-11-26T... host app proc - [sd] {json}`，
/// JSON 一定在最后一段（structured-data 内部不含花括号）。
pub fn extract_json(message: &str) -> Option<&str> {
    let message = message.trim();
    let start = message.find('{')?;
    let end = message.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(&message[start..=end])
}

/// 一条「终端在线」心跳。
///
/// 与命中报文分开建模：心跳没有任何 `findings`，只用来刷新
/// `agents.last_seen`，让控制台能看到「没有告警但在线」的机器。
#[derive(Debug, Clone, Deserialize)]
pub struct Heartbeat {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub version: String,
}

/// 解析结果：只有这三种形态，避免调用方再判断「空批量」。
#[derive(Debug, Clone)]
pub enum Payload {
    /// 含命中的上报批次。
    Findings(Box<IncomingBatch>),
    /// 终端心跳（不含任何命中）。
    Heartbeat(Heartbeat),
    /// 明确忽略（例如连通性测试报文）。
    Ignored,
}

/// 解析一行报文为可入库的载荷。
///
/// 不用 `#[serde(untagged)]`：`IncomingBatch` 的字段全部可选，
/// serde 会先把单条报文成功匹配成「空批量」，导致数据静默丢失。
/// 这里显式按 `findings` / `event` 字段判别形态。
pub fn parse_message(message: &str) -> Result<Payload> {
    let Some(json) = extract_json(message) else {
        anyhow::bail!("报文里没有 JSON 载荷");
    };
    let value: serde_json::Value = serde_json::from_str(json).context("JSON 载荷无法解析")?;
    if value.get("findings").is_some() {
        let batch: IncomingBatch = serde_json::from_value(value).context("批量上报结构不合法")?;
        return Ok(Payload::Findings(Box::new(batch)));
    }
    // 心跳必须在单条告警之前判断：它同样没有 findings，但带 event=heartbeat。
    if value.get("event").and_then(serde_json::Value::as_str) == Some("heartbeat") {
        let heartbeat: Heartbeat = serde_json::from_value(value).context("心跳结构不合法")?;
        return Ok(Payload::Heartbeat(heartbeat));
    }
    let single: SinglePayload = serde_json::from_value(value).context("告警结构不合法")?;
    Ok(match single.into_batch() {
        Some(batch) => Payload::Findings(Box::new(batch)),
        None => Payload::Ignored,
    })
}

/// 启动接收器（非阻塞：在后台线程里跑，返回统计句柄）。
pub fn spawn(config: &ServerConfig, store: Arc<ServerStore>) -> Result<Arc<IngestStats>> {
    let stats = Arc::new(IngestStats::default());
    let protocols = config.listen_protocols();
    let bind = config.ingest.bind.clone();
    let max_bytes = config.ingest.max_message_bytes.clamp(512, 1024 * 1024);
    let allow = Arc::new(config.ingest.allow_cidrs.clone());

    for protocol in protocols {
        let store = Arc::clone(&store);
        let stats = Arc::clone(&stats);
        let bind = bind.clone();
        let allow = Arc::clone(&allow);
        let name = format!("sentinel-ingest-{protocol}");
        std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                let result = match protocol {
                    "udp" => run_udp(&bind, max_bytes, &allow, &store, &stats),
                    _ => run_tcp(&bind, max_bytes, &allow, &store, &stats),
                };
                if let Err(error) = result {
                    tracing::error!(protocol, error = %format!("{error:#}"), "syslog 接收器退出");
                }
            })
            .context("无法启动 syslog 接收线程")?;
    }
    Ok(stats)
}

/// 接收器并发连接上限：每个 TCP 连接一个线程，不设上限会被连接风暴打穿。
static CONNECTION_LIMITER: crate::util::ConnectionLimiter =
    crate::util::ConnectionLimiter::new(256);

fn run_udp(
    bind: &str,
    max_bytes: usize,
    allow: &[String],
    store: &Arc<ServerStore>,
    stats: &Arc<IngestStats>,
) -> Result<()> {
    let socket = UdpSocket::bind(bind)
        .with_context(|| format!("无法监听 UDP {bind}（514 端口需要 root）"))?;
    tracing::info!(bind, "syslog UDP 接收器已启动");
    let mut buffer = vec![0u8; max_bytes];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, peer)) => {
                stats.packets.fetch_add(1, Ordering::Relaxed);
                if !allowed(peer.ip(), allow) {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%peer, "来源不在白名单，已丢弃");
                    continue;
                }
                let message = String::from_utf8_lossy(&buffer[..len]);
                handle_line(&message, peer, store, stats);
            }
            Err(error) => {
                tracing::debug!(error = %error, "UDP 接收失败");
                // 持续错误（例如 FD 耗尽）时不能忙等自旋。
                crate::util::backoff_after_accept_error(&error);
            }
        }
    }
}

fn run_tcp(
    bind: &str,
    max_bytes: usize,
    allow: &[String],
    store: &Arc<ServerStore>,
    stats: &Arc<IngestStats>,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .with_context(|| format!("无法监听 TCP {bind}（514 端口需要 root）"))?;
    tracing::info!(bind, "syslog TCP 接收器已启动");
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(error = %error, "TCP accept 失败");
                crate::util::backoff_after_accept_error(&error);
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        if !allowed(peer.ip(), allow) {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "来源不在白名单，已断开");
            continue;
        }
        let Some(slot) = CONNECTION_LIMITER.try_acquire() else {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %peer,
                max = CONNECTION_LIMITER.max(),
                "syslog 并发连接已达上限，已断开"
            );
            drop(stream);
            continue;
        };
        let store = Arc::clone(store);
        let stats = Arc::clone(stats);
        let spawned = std::thread::Builder::new()
            .name("sentinel-ingest-conn".into())
            .spawn(move || {
                let _slot = slot;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                let mut reader = std::io::BufReader::new(stream);
                let mut line_bytes = Vec::new();
                loop {
                    // 关键：用带长度上限的读行，防止对端只发数据不发换行时无限缓冲。
                    match crate::util::read_line_bounded(&mut reader, &mut line_bytes, max_bytes) {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            stats.packets.fetch_add(1, Ordering::Relaxed);
                            let line = String::from_utf8_lossy(&line_bytes);
                            handle_line(line.trim_end_matches(['\r', '\n']), peer, &store, &stats);
                        }
                        Err(error) => {
                            tracing::debug!(error = %error, "TCP 读取失败，关闭连接");
                            break;
                        }
                    }
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(error = %error, "无法为 syslog 连接创建处理线程");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    Ok(())
}

fn handle_line(
    message: &str,
    peer: SocketAddr,
    store: &Arc<ServerStore>,
    stats: &Arc<IngestStats>,
) {
    match parse_message(message) {
        Ok(Payload::Findings(batch)) => {
            let batch = *batch;
            if batch.findings.is_empty() {
                return;
            }
            match store.ingest(&batch, &peer.ip().to_string()) {
                Ok(inserted) => {
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    stats.events.fetch_add(inserted as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %format!("{error:#}"), "写入告警失败");
                }
            }
        }
        Ok(Payload::Heartbeat(heartbeat)) => {
            // 心跳只刷新在线状态，不产生告警；失败也单独计数，
            // 免得把「终端登记失败」和「报文格式错误」混为一谈。
            match store.touch_agent(
                &heartbeat.agent_id,
                &heartbeat.hostname,
                &heartbeat.username,
                &heartbeat.platform,
                &heartbeat.version,
                &peer.ip().to_string(),
            ) {
                Ok(()) => {
                    stats.heartbeats.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %format!("{error:#}"), "写入终端心跳失败");
                }
            }
        }
        Ok(Payload::Ignored) => {
            // 测试报文：链路正常，不计数为失败。
            tracing::debug!(%peer, "收到连通性测试报文");
        }
        Err(error) => {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, error = %format!("{error:#}"), "报文解析失败");
        }
    }
}

/// CIDR 白名单匹配；空列表表示全部放行。
fn allowed(ip: IpAddr, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return true;
    }
    cidrs.iter().any(|cidr| match_cidr(ip, cidr.trim()))
}

pub fn match_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => (network, prefix.parse::<u8>().ok()),
        None => (cidr, None),
    };
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let prefix = prefix.unwrap_or(32).min(32);
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let prefix = prefix.unwrap_or(128).min(128);
            if prefix == 0 {
                return true;
            }
            let ip = u128::from(ip);
            let net = u128::from(net);
            let mask = u128::MAX << (128 - prefix);
            (ip & mask) == (net & mask)
        }
        _ => false,
    }
}

/// 让接收器可被优雅停止（当前用于测试与控制台重启）。
pub struct IngestHandle {
    pub stats: Arc<IngestStats>,
    pub stopped: Arc<AtomicBool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_json_from_rfc5424() {
        let line = r#"<35>1 2026-11-26T10:00:00.123Z host DataSentinel 123 - [datasentinel@32473 event="x"] {"rule_id":"a"}"#;
        assert_eq!(extract_json(line), Some(r#"{"rule_id":"a"}"#));
        assert_eq!(extract_json("no json here"), None);
        assert_eq!(extract_json("}{"), None);
    }

    #[test]
    fn parses_single_finding() {
        let line = r#"<35>1 2026-11-26T10:00:00Z host DataSentinel 1 - [x] {"event":"finding","rule_id":"cn_id_card","rule_name":"身份证","category":"identity","severity":"high","value":"11010519491231002X","masked":"110105********002X","file_name":"a.txt","path":"/home/u/a.txt","line":3,"match_hash":"h1","hostname":"pc01","username":"alice"}"#;
        let Payload::Findings(batch) = parse_message(line).unwrap() else {
            panic!("应解析成命中批次");
        };
        assert_eq!(batch.hostname, "pc01");
        assert_eq!(batch.username, "alice");
        assert_eq!(batch.findings.len(), 1);
        let finding = &batch.findings[0];
        assert_eq!(finding.rule_id, "cn_id_card");
        assert_eq!(finding.file_name, "a.txt");
        assert_eq!(finding.masked, "110105********002X");
        assert_eq!(finding.matched, "11010519491231002X");
    }

    #[test]
    fn parses_batch_payload() {
        let line =
            r#"{"agent_id":"a1","hostname":"pc01","findings":[{"rule_id":"x","severity":"low"}]}"#;
        let Payload::Findings(batch) = parse_message(line).unwrap() else {
            panic!("应解析成命中批次");
        };
        assert_eq!(batch.agent_id, "a1");
        assert_eq!(batch.findings.len(), 1);
    }

    /// 心跳报文必须与命中报文区分开：它没有 findings，但带 event=heartbeat。
    #[test]
    fn parses_heartbeat() {
        let line = r#"<30>1 2026-11-26T10:00:00Z host DataSentinel 1 - [x] {"event":"heartbeat","agent_id":"abc","hostname":"pc01","username":"alice","platform":"macos-aarch64","version":"0.3.0"}"#;
        let Payload::Heartbeat(heartbeat) = parse_message(line).unwrap() else {
            panic!("应解析成心跳");
        };
        assert_eq!(heartbeat.agent_id, "abc");
        assert_eq!(heartbeat.username, "alice");
        assert_eq!(heartbeat.platform, "macos-aarch64");
        assert_eq!(heartbeat.version, "0.3.0");
    }

    #[test]
    fn ignores_test_event() {
        let line = r#"<36>1 2026-11-26T10:00:00Z host DataSentinel 1 - [x] {"event":"test","message":"ping"}"#;
        assert!(matches!(parse_message(line).unwrap(), Payload::Ignored));
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_message("garbage").is_err());
        assert!(parse_message(r#"<35>1 x {"unclosed":1"#).is_err());
    }

    #[test]
    fn cidr_matching() {
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        assert!(match_cidr(ip, "192.168.1.0/24"));
        assert!(match_cidr(ip, "192.168.0.0/16"));
        assert!(!match_cidr(ip, "10.0.0.0/8"));
        assert!(match_cidr(ip, "0.0.0.0/0"));

        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(match_cidr(v6, "fe80::/10"));
        assert!(!match_cidr(v6, "2001:db8::/32"));

        // 版本不匹配
        assert!(!match_cidr(ip, "fe80::/10"));
    }

    #[test]
    fn whitelist_allows_when_empty() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(allowed(ip, &[]));
        assert!(allowed(ip, &["10.0.0.0/8".to_string()]));
        assert!(!allowed(ip, &["192.168.0.0/16".to_string()]));
    }
}
