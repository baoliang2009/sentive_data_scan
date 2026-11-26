//! Syslog 外发（RFC 5424）与服务端接收。
//!
//! 设计取舍：
//! - **默认只发脱敏值**。外发通道一旦开启就是数据的“出口”，因此 `send_raw`
//!   默认 false；即使打开，也要求 `storage.store_raw_match` 或本开关显式启用，
//!   否则回落到脱敏值。
//! - **发送失败不影响扫描**。外发是旁路，网络异常只记日志与计数，绝不阻塞或
//!   中断扫描主流程。
//! - **MSG 字段是单行 JSON**，方便服务端做结构化解析；同时用 RFC 5424 的
//!   structured-data 携带事件类型等关键字段，兼容标准 syslog 采集器（rsyslog /
//!   syslog-ng / journald）。

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde_json::json;

use crate::config::{SyslogConfig, SyslogServerConfig};
use crate::model::{Finding, Severity};

/// 单条报文上限。RFC 5424 要求至少支持 2048 字节；这里放宽到 8 KiB，
/// 超出后截断 MSG 而不是静默丢弃整条记录。
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// RFC 5424 里 DataSentinel 使用的私有 enterprise ID（示例区间）。
const SD_ID: &str = "datasentinel@32473";

pub struct SyslogSender {
    config: SyslogConfig,
    hostname: String,
    transport: Mutex<Transport>,
    /// 当前生效的目标（地址 + 协议）。mDNS 模式下会随发现结果更新。
    target: Mutex<Option<Target>>,
}

/// 实际发送目标：把「配置」和「发现结果」解耦。
#[derive(Debug, Clone, PartialEq)]
struct Target {
    server: String,
    protocol: String,
}

enum Transport {
    /// 尚未建立连接，首次发送时按 protocol 惰性初始化。
    Uninitialized,
    Udp(UdpSocket),
    Tcp(Option<TcpStream>),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixDatagram),
}

impl SyslogSender {
    /// 根据配置构造发送端；未启用或没有可用地址时返回 `None`。
    ///
    /// `mdns` 模式下允许 `server` 为空：首次发送时通过 mDNS 解析。
    pub fn from_config(config: &SyslogConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        if !config.uses_mdns() && config.endpoint().is_none() {
            return None;
        }
        let hostname = if config.hostname.trim().is_empty() {
            local_hostname()
        } else {
            config.hostname.trim().to_string()
        };
        Some(Self {
            config: config.clone(),
            hostname,
            transport: Mutex::new(Transport::Uninitialized),
            target: Mutex::new(None),
        })
    }

    /// 解析当前应发送到的目标。
    ///
    /// `mdns` 模式优先用发现结果；发现失败时回落到静态 `server`。
    fn resolve_target(&self) -> Option<Target> {
        if let Ok(guard) = self.target.lock() {
            if let Some(target) = guard.as_ref() {
                return Some(target.clone());
            }
        }
        let mut protocol = self.config.protocol.to_ascii_lowercase();
        let server = if self.config.uses_mdns() {
            let resolver = crate::mdns::global_resolver(
                &self.config.mdns_service,
                Duration::from_millis(self.config.mdns_timeout_ms.clamp(500, 30_000)),
            );
            match resolver.resolve() {
                Some(found) => {
                    if let Some(found_protocol) = found.protocol {
                        protocol = found_protocol;
                    }
                    found.endpoint
                }
                None => match self.config.endpoint() {
                    Some(fallback) => {
                        tracing::debug!(
                            server = %fallback,
                            "mDNS 未发现服务端，使用静态 syslog.server"
                        );
                        fallback
                    }
                    None => {
                        tracing::warn!(
                            service = %self.config.mdns_service,
                            "mDNS 未发现 syslog 服务端且未配置静态地址，本次跳过外发"
                        );
                        return None;
                    }
                },
            }
        } else {
            self.config.endpoint()?
        };
        let target = Target { server, protocol };
        if let Ok(mut guard) = self.target.lock() {
            *guard = Some(target.clone());
        }
        Some(target)
    }

    /// 发现结果变化（例如服务端换机）后重置目标，下次发送重新解析。
    fn invalidate_target(&self) {
        if let Ok(mut guard) = self.target.lock() {
            *guard = None;
        }
        if let Ok(mut transport) = self.transport.lock() {
            *transport = Transport::Uninitialized;
        }
        if self.config.uses_mdns() {
            crate::mdns::global_resolver(
                &self.config.mdns_service,
                Duration::from_millis(self.config.mdns_timeout_ms.clamp(500, 30_000)),
            )
            .invalidate();
        }
    }

    /// 当前生效的服务端地址（用于日志/控制台展示）。
    pub fn effective_server(&self) -> String {
        self.resolve_target()
            .map(|target| target.server)
            .unwrap_or_else(|| self.config.server.clone())
    }

    /// 发送一批命中。返回 `(成功条数, 失败条数)`。
    ///
    /// 只在 `new_hashes` 里的命中才外发，避免每次全量对账把旧记录重复推一遍。
    pub fn send_findings(&self, path: &Path, findings: &[Finding]) -> (usize, usize) {
        let Some(target) = self.resolve_target() else {
            return (0, findings.len());
        };
        let mut sent = 0usize;
        let mut failed = 0usize;
        let timeout = Duration::from_millis(self.config.timeout_ms.max(200));
        let mut transport = match self.transport.lock() {
            Ok(transport) => transport,
            Err(poisoned) => poisoned.into_inner(),
        };
        for finding in findings {
            let message = self.format_message(path, finding);
            match self.send_one(&mut transport, &target, message.as_bytes(), timeout) {
                Ok(()) => sent += 1,
                Err(error) => {
                    failed += 1;
                    // 同一批里只需要提示一次，避免刷屏。
                    if failed == 1 {
                        tracing::warn!(
                            server = %target.server,
                            protocol = %target.protocol,
                            error = %error,
                            "syslog 外发失败"
                        );
                    }
                }
            }
        }
        if sent == 0 && failed > 0 && self.config.uses_mdns() {
            // 地址可能已过期（服务端换机/换 IP），下次重新发现。
            self.invalidate_target();
        }
        (sent, failed)
    }

    /// 发送一条连通性测试报文。
    pub fn send_test(&self) -> Result<()> {
        let target = self
            .resolve_target()
            .context("没有可用的 syslog 服务端地址")?;
        let payload = json!({
            "event": "test",
            "app": self.config.app_name,
            "hostname": self.hostname,
            "time": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "message": "DataSentinel syslog 连通性测试",
        });
        let message = self.wrap(Severity::Medium, "test", &payload.to_string());
        let timeout = Duration::from_millis(self.config.timeout_ms.max(200));
        let mut transport = match self.transport.lock() {
            Ok(transport) => transport,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.send_one(&mut transport, &target, message.as_bytes(), timeout)
    }

    fn send_one(
        &self,
        transport: &mut Transport,
        target: &Target,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<()> {
        let mut payload = truncate_bytes(payload, MAX_MESSAGE_BYTES);
        let protocol = target.protocol.to_ascii_lowercase();
        // TCP 采用 RFC 6587 的 non-transparent framing（换行分隔），
        // 这样 `nc` / rsyslog / 我们的接收端都能按行切分。
        if protocol == "tcp" && !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }
        if matches!(transport, Transport::Uninitialized) {
            *transport = match protocol.as_str() {
                "udp" => {
                    let bind = if target.server.starts_with('[') {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    };
                    let socket = UdpSocket::bind(bind).context("无法创建 syslog UDP 套接字")?;
                    socket.set_write_timeout(Some(timeout)).ok();
                    Transport::Udp(socket)
                }
                "tcp" => Transport::Tcp(Some(connect_tcp(&target.server, timeout)?)),
                #[cfg(unix)]
                "unix" => Transport::Unix(
                    std::os::unix::net::UnixDatagram::unbound()
                        .context("无法创建 syslog Unix 套接字")?,
                ),
                other => bail!("不支持的 syslog 协议: {other}"),
            };
        }

        match transport {
            Transport::Udp(socket) => {
                socket
                    .send_to(&payload, target.server.as_str())
                    .with_context(|| format!("UDP 发送到 {} 失败", target.server))?;
                Ok(())
            }
            Transport::Tcp(slot) => {
                if slot.is_none() {
                    *slot = Some(connect_tcp(&target.server, timeout)?);
                }
                let stream = slot.as_mut().expect("TCP 流已初始化");
                if let Err(error) = stream.write_all(&payload) {
                    // 对端可能因空闲超时断开，重连一次再试。
                    tracing::debug!(error = %error, "syslog TCP 写入失败，尝试重连");
                    let mut stream = connect_tcp(&target.server, timeout)?;
                    stream
                        .write_all(&payload)
                        .with_context(|| format!("TCP 重连后发送到 {} 失败", target.server))?;
                    *slot = Some(stream);
                }
                Ok(())
            }
            #[cfg(unix)]
            Transport::Unix(socket) => {
                socket
                    .send_to(&payload, target.server.trim())
                    .with_context(|| format!("Unix 套接字发送到 {} 失败", target.server))?;
                Ok(())
            }
            Transport::Uninitialized => bail!("syslog 传输层未初始化"),
        }
    }

    fn format_message(&self, path: &Path, finding: &Finding) -> String {
        // 默认脱敏；只有显式要求且检测层确实保留了原文时才发原文。
        let value = if self.config.send_raw {
            finding.raw.as_deref().unwrap_or(&finding.masked)
        } else {
            &finding.masked
        };
        let mut payload = json!({
            "event": "finding",
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "category": finding.category,
            "severity": finding.severity.as_str(),
            "path": path.to_string_lossy(),
            "line": finding.line,
            "column": finding.column,
            "value": value,
            "masked": finding.masked,
            "match_hash": finding.match_hash,
            "hostname": self.hostname,
            "time": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        if self.config.include_snippet {
            payload["snippet"] = json!(finding.snippet);
        }
        self.wrap(finding.severity, &finding.rule_id, &payload.to_string())
    }

    /// 组装 RFC 5424 报文。
    fn wrap(&self, severity: Severity, event: &str, message: &str) -> String {
        let facility = facility_code(&self.config.facility);
        let pri = facility * 8 + severity_code(severity);
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let hostname = sanitize_field(&self.hostname, 255);
        let app_name = sanitize_field(&self.config.app_name, 48);
        let procid = std::process::id().to_string();
        let sd = format!(
            "[{SD_ID} event=\"{}\" severity=\"{}\" host=\"{}\"]",
            escape_sd(event),
            severity.as_str(),
            escape_sd(&self.hostname)
        );
        format!("<{pri}>1 {timestamp} {hostname} {app_name} {procid} - {sd} {message}")
    }
}

fn connect_tcp(server: &str, timeout: Duration) -> Result<TcpStream> {
    let mut last_error = None;
    for address in server
        .to_socket_addrs()
        .with_context(|| format!("无法解析 syslog 服务端地址 {server}"))?
    {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_write_timeout(Some(timeout)).ok();
                stream.set_nodelay(true).ok();
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(anyhow::anyhow!(
        "连接 syslog 服务端 {server} 失败: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "没有可用地址".to_string())
    ))
}

/// 按字节安全截断（避免切断 UTF-8 序列）。
fn truncate_bytes(payload: &[u8], limit: usize) -> Vec<u8> {
    if payload.len() <= limit {
        return payload.to_vec();
    }
    let mut end = limit;
    while end > 0 && (payload[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    payload[..end].to_vec()
}

/// RFC 5424 HEADER 字段不允许空格/控制字符。
fn sanitize_field(value: &str, limit: usize) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, ' ' | '"' | ']' | '[' | '=') {
                '_'
            } else {
                ch
            }
        })
        .collect();
    cleaned.chars().take(limit).collect()
}

fn escape_sd(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

fn severity_code(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 2, // crit
        Severity::High => 3,     // err
        Severity::Medium => 4,   // warning
        Severity::Low => 5,      // notice
        Severity::Info => 6,     // info
    }
}

fn facility_code(name: &str) -> u8 {
    match name.trim().to_ascii_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "ntp" => 12,
        "audit" => 13,
        "alert" => 14,
        "clock" => 15,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        other => other
            .parse::<u8>()
            .ok()
            .filter(|code| *code < 24)
            .unwrap_or(4),
    }
}

fn local_hostname() -> String {
    // 与 mDNS 复用同一套平台探测逻辑，保证 RFC 5424 的 HOSTNAME 字段在
    // Windows / Linux / macOS 上都能拿到真实主机名，而不是恒为 localhost。
    crate::mdns::local_hostname()
}

// --------------------------------------------------------------- forwarder --

/// 非阻塞外发队列。
///
/// 扫描是 rayon 并行 + 磁盘 IO 的密集路径，网络抖动绝不能拖慢它；因此扫描线程
/// 只做一次 `try_send`，真正的套接字读写交给单个后台线程串行完成。
pub struct Forwarder {
    tx: std::sync::mpsc::SyncSender<Job>,
    sent: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
}

enum Job {
    Batch {
        path: PathBuf,
        findings: Vec<Finding>,
    },
    /// 测试/退出时的同步屏障：外发线程处理到它时回传信号。
    Barrier(std::sync::mpsc::SyncSender<()>),
}

impl Forwarder {
    /// 未启用或完全没有可用地址时返回 `None`，调用方据此跳过外发分支。
    ///
    /// `mdns` 模式下允许 `server` 为空——地址在首次发送时才解析。
    pub fn spawn(config: &SyslogConfig) -> Option<Arc<Self>> {
        let sender = SyslogSender::from_config(config)?;
        let min_severity = config.min_severity;
        let mdns = config.uses_mdns();
        let server = config.endpoint().unwrap_or_default();
        let protocol = config.protocol.clone();
        let service = config.mdns_service.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel::<Job>(4096);
        let forwarder = Arc::new(Self {
            tx,
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        let counters = Arc::downgrade(&forwarder);
        std::thread::Builder::new()
            .name("sentinel-syslog".into())
            .spawn(move || {
                if mdns {
                    tracing::info!(
                        service = %service,
                        fallback = %server,
                        "syslog 外发已启用（mDNS 自动发现）"
                    );
                } else {
                    tracing::info!(server = %server, protocol = %protocol, "syslog 外发已启用");
                }
                while let Ok(job) = rx.recv() {
                    match job {
                        Job::Barrier(ack) => {
                            let _ = ack.try_send(());
                        }
                        Job::Batch { path, findings } => {
                            let qualifying: Vec<Finding> = findings
                                .iter()
                                .filter(|finding| finding.severity >= min_severity)
                                .cloned()
                                .collect();
                            if qualifying.is_empty() {
                                continue;
                            }
                            let (sent, failed) = sender.send_findings(&path, &qualifying);
                            if let Some(forwarder) = counters.upgrade() {
                                forwarder.sent.fetch_add(sent as u64, Ordering::Relaxed);
                                forwarder.failed.fetch_add(failed as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
                tracing::debug!("syslog 外发线程退出");
            })
            .ok()?;
        Some(forwarder)
    }

    /// 只投递新增命中；队列满时丢弃并计数，避免内存被网络问题拖垮。
    pub fn submit(&self, path: &Path, findings: Vec<Finding>) {
        if findings.is_empty() {
            return;
        }
        let job = Job::Batch {
            path: path.to_path_buf(),
            findings,
        };
        if let Err(std::sync::mpsc::TrySendError::Full(_)) = self.tx.try_send(job) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("syslog 外发队列已满，丢弃一批命中");
        }
    }

    /// 等待已入队的命中发完（`sentinel scan` 这类短命进程退出前调用）。
    pub fn flush(&self, timeout: Duration) {
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<()>(1);
        if self.tx.try_send(Job::Barrier(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(timeout);
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }
}

// ------------------------------------------------------------------ server --

/// 服务端接收器：把收到的报文写入本地日志文件并打印到 stdout。
///
/// 只做“最小可用”的落盘与展示——真正的集中存储应交给 rsyslog / syslog-ng /
/// SIEM；这里是为了让“配置了服务端地址就真的能收到”可被自证。
pub struct SyslogServer {
    config: SyslogServerConfig,
}

impl SyslogServer {
    pub fn new(config: SyslogServerConfig) -> Self {
        Self { config }
    }

    /// 阻塞运行，直到收到 SIGINT。
    ///
    /// 若 `advertise` 为 true，会同时通过 mDNS 广播自己，客户端即可自动发现。
    pub fn run_with_advertise(&self, advertise: bool) -> Result<()> {
        let output = self.output_path();
        if let Some(parent) = output.parent() {
            crate::config::ensure_private_dir(parent)?;
        }
        tracing::info!(
            bind = %self.config.bind,
            protocol = %self.config.protocol,
            output = %output.display(),
            advertise,
            "syslog 服务端已启动"
        );
        println!(
            "syslog 服务端已启动：{} ({})，输出：{}",
            self.config.bind,
            self.config.protocol,
            output.display()
        );

        // 先绑定端口，成功后再广播——否则客户端会拿到一个连不上的地址。
        let advertiser = if advertise {
            let result = crate::mdns::Advertiser::start(
                &self.config.mdns_service,
                &self.config.instance,
                &self.config.bind,
                &self.config.protocol,
            );
            match result {
                Ok(advertiser) => {
                    println!(
                        "  mDNS 广播：{}（客户端 discovery = \"mdns\" 即可自动发现）",
                        advertiser.fullname()
                    );
                    Some(advertiser)
                }
                Err(error) => {
                    eprintln!("  mDNS 广播失败（不影响接收）：{error:#}");
                    tracing::warn!(error = %format!("{error:#}"), "mDNS 广播失败");
                    None
                }
            }
        } else {
            None
        };
        let _advertiser = advertiser;

        match self.config.protocol.to_ascii_lowercase().as_str() {
            "udp" => self.run_udp(&output),
            "tcp" => self.run_tcp(&output),
            other => bail!("服务端不支持协议 {other}（仅 udp / tcp）"),
        }
    }

    /// 兼容旧调用：默认不广播。
    pub fn run(&self) -> Result<()> {
        self.run_with_advertise(false)
    }

    fn output_path(&self) -> PathBuf {
        if self.config.output.as_os_str().is_empty() {
            crate::config::data_dir()
                .join("syslog")
                .join("received.log")
        } else {
            crate::config::expand_path(&self.config.output)
        }
    }

    fn run_udp(&self, output: &Path) -> Result<()> {
        let socket = UdpSocket::bind(self.config.bind.as_str())
            .with_context(|| format!("无法监听 UDP {}", self.config.bind))?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, peer)) => {
                    self.store(output, &buffer[..len], peer.to_string());
                }
                Err(error) => tracing::warn!(error = %error, "接收 UDP 报文失败"),
            }
        }
    }

    fn run_tcp(&self, output: &Path) -> Result<()> {
        let listener = std::net::TcpListener::bind(self.config.bind.as_str())
            .with_context(|| format!("无法监听 TCP {}", self.config.bind))?;
        for incoming in listener.incoming() {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(error = %error, "接受 TCP 连接失败");
                    continue;
                }
            };
            let peer = stream
                .peer_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let output = output.to_path_buf();
            std::thread::spawn(move || {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(stream);
                for line in reader.lines() {
                    match line {
                        Ok(line) => store_line(&output, &line, &peer),
                        Err(error) => {
                            tracing::debug!(error = %error, "读取 TCP 报文失败");
                            break;
                        }
                    }
                }
            });
        }
        Ok(())
    }

    fn store(&self, output: &Path, raw: &[u8], peer: String) {
        let message = String::from_utf8_lossy(raw);
        store_line(output, message.trim_end(), &peer);
    }
}

fn store_line(output: &Path, message: &str, peer: &str) {
    println!("[{peer}] {message}");
    let line = format!(
        "{} {peer} {message}\n",
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    );
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
    {
        Ok(mut file) => {
            crate::config::secure_file(output).ok();
            if let Err(error) = file.write_all(line.as_bytes()) {
                tracing::warn!(error = %error, "写入 syslog 接收日志失败");
            }
        }
        Err(error) => tracing::warn!(error = %error, path = %output.display(), "打开接收日志失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn config() -> SyslogConfig {
        SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1:5514".to_string(),
            ..SyslogConfig::default()
        }
    }

    fn finding() -> Finding {
        Finding {
            rule_id: "cn_id_card".to_string(),
            rule_name: "中国大陆居民身份证号".to_string(),
            category: "identity".to_string(),
            severity: Severity::High,
            path: PathBuf::from("/tmp/a.txt"),
            line: 3,
            column: 5,
            masked: "110105********002X".to_string(),
            snippet: "身份证 110105********002X".to_string(),
            match_hash: "abc".to_string(),
            raw: None,
            start: 0,
            end: 1,
        }
    }

    #[test]
    fn rfc5424_header_is_well_formed() {
        let sender = SyslogSender::from_config(&config()).unwrap();
        let message = sender.format_message(Path::new("/tmp/a.txt"), &finding());
        // <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
        assert!(message.starts_with("<35>1 "), "{message}");
        assert!(message.contains("[datasentinel@32473 event=\"cn_id_card\""));
        assert!(message.contains("severity=\"high\""));
        assert!(message.contains("\"value\":\"110105********002X\""));
        // 报文必须单行，否则 TCP 读取端会按行拆错。
        assert!(!message.contains('\n'));
    }

    #[test]
    fn raw_is_never_sent_unless_requested() {
        let sender = SyslogSender::from_config(&config()).unwrap();
        let mut item = finding();
        item.raw = Some("11010519491231002X".to_string());
        let message = sender.format_message(Path::new("/tmp/a.txt"), &item);
        assert!(!message.contains("11010519491231002X"));

        let mut raw_config = config();
        raw_config.send_raw = true;
        let raw_sender = SyslogSender::from_config(&raw_config).unwrap();
        let message = raw_sender.format_message(Path::new("/tmp/a.txt"), &item);
        assert!(message.contains("11010519491231002X"));
    }

    #[test]
    fn facility_and_severity_mapping() {
        assert_eq!(facility_code("auth"), 4);
        assert_eq!(facility_code("local0"), 16);
        assert_eq!(facility_code("10"), 10);
        assert_eq!(severity_code(Severity::Critical), 2);
        assert_eq!(severity_code(Severity::Info), 6);
    }

    #[test]
    fn udp_roundtrip() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let mut cfg = config();
        cfg.server = address;
        let sender = SyslogSender::from_config(&cfg).unwrap();
        sender.send_test().unwrap();

        let mut buffer = [0u8; 4096];
        let (len, _) = socket.recv_from(&mut buffer).unwrap();
        let text = String::from_utf8_lossy(&buffer[..len]);
        assert!(text.contains("event=\"test\""), "{text}");
    }

    #[test]
    fn tcp_roundtrip() {
        use std::io::BufRead;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = std::io::BufReader::new(stream);
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
            }
        });
        let mut cfg = config();
        cfg.protocol = "tcp".to_string();
        cfg.server = address;
        let sender = SyslogSender::from_config(&cfg).unwrap();
        sender.send_test().unwrap();
    }

    #[test]
    fn truncates_without_splitting_utf8() {
        let text = "身".repeat(4000); // 3 bytes each
        let truncated = truncate_bytes(text.as_bytes(), 100);
        assert_eq!(truncated.len(), 99);
        assert!(String::from_utf8(truncated).is_ok());
    }

    #[test]
    fn disabled_or_empty_server_yields_none() {
        let mut cfg = config();
        cfg.enabled = false;
        assert!(SyslogSender::from_config(&cfg).is_none());
        let mut cfg = config();
        cfg.server = "   ".to_string();
        assert!(SyslogSender::from_config(&cfg).is_none());
    }
}
