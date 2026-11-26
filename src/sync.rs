//! 客户端策略同步：从服务端拉取统一规则、扫描目录、定时策略与白名单，并回传已应用版本。
//!
//! 仅使用标准库 `TcpStream` + `rustls`，保持客户端单文件零重依赖。

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde::{Deserialize, Serialize};

use crate::config::{AgentPolicy, Config, RulesConfig};
use crate::identity::Identity;
use crate::store::Store;

const META_SYNCED_BUNDLE: &str = "synced_bundle";

/// 服务端下发给客户端的完整策略文档。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncedBundle {
    pub revision: i64,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub policy: AgentPolicy,
}

/// 从本地台账读取上次同步的服务端策略（供离线重启兜底）。
pub fn load_cached(store: &Store) -> Option<SyncedBundle> {
    let raw = store.get_meta(META_SYNCED_BUNDLE).ok()??;
    serde_json::from_str(&raw).ok()
}

/// 将最新同步到的服务端策略缓存到本地台账。
pub fn save_cached(store: &Store, bundle: &SyncedBundle) -> Result<()> {
    let json = serde_json::to_string(bundle).context("序列化服务端策略失败")?;
    store.set_meta(META_SYNCED_BUNDLE, &json)
}

/// 将服务端策略合并到运行时配置副本中（不改写本地配置文件）。
pub fn apply_bundle(base: &Config, bundle: &SyncedBundle) -> Config {
    let mut merged = base.clone();
    // 规则：合并服务端下发的 disabled、min_severity、custom 与 allow_values。
    for id in &bundle.rules.disabled {
        if !merged.rules.disabled.iter().any(|item| item == id) {
            merged.rules.disabled.push(id.clone());
        }
    }
    if bundle.revision > 0 {
        merged.rules.min_severity = bundle.rules.min_severity;
    }
    for rule in &bundle.rules.custom {
        if let Some(pos) = merged.rules.custom.iter().position(|r| r.id == rule.id) {
            merged.rules.custom[pos] = rule.clone();
        } else {
            merged.rules.custom.push(rule.clone());
        }
    }
    for val in &bundle.rules.allow_values {
        let trimmed = val.trim();
        if !trimmed.is_empty() && !merged.rules.allow_values.iter().any(|v| v == trimmed) {
            merged.rules.allow_values.push(trimmed.to_string());
        }
    }
    merged.apply_agent_policy(&bundle.policy)
}

/// 解析服务端控制台基址（优先 `server.url`，为空且启用 mDNS 时尝试自动发现）。
pub fn resolve_server_url(config: &Config) -> Option<String> {
    if !config.server.enabled {
        return None;
    }
    let trimmed = config.server.url.trim().trim_end_matches('/');
    if !trimmed.is_empty() {
        return Some(trimmed.to_string());
    }
    if config.syslog.uses_mdns() {
        let timeout = Duration::from_millis(config.syslog.mdns_timeout_ms.clamp(500, 30_000));
        if let Some(found) =
            crate::mdns::global_resolver(&config.syslog.mdns_service, timeout).resolve()
        {
            if let Some(console) = found.console {
                return Some(console.trim_end_matches('/').to_string());
            }
        }
    }
    None
}

/// 若配置了服务端地址则拉取最新策略；未配置地址时返回 `Ok(None)`。
pub fn fetch_policy(config: &Config) -> Result<Option<SyncedBundle>> {
    let Some(base_url) = resolve_server_url(config) else {
        return Ok(None);
    };
    let token = config.server.agent_token.trim();
    let (status, body) = http_request(
        "GET",
        &base_url,
        "/api/agent/rules",
        token,
        None,
        config.server.insecure_tls,
    )?;
    if status == 401 {
        bail!("拉取服务端策略鉴权失败（401），请检查 [server] agent_token");
    }
    if !(200..300).contains(&status) {
        bail!("拉取服务端策略失败：HTTP {status}");
    }
    let bundle: SyncedBundle = serde_json::from_slice(&body).context("解析服务端策略 JSON 失败")?;
    Ok(Some(bundle))
}

/// 服务端下发的远端指令。
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteCommand {
    pub id: i64,
    pub action: String,
    pub target_path: String,
}

#[derive(Debug, Deserialize)]
struct CommandsResp {
    #[serde(default)]
    items: Vec<RemoteCommand>,
}

/// 从服务端拉取待执行的远程指令。
pub fn fetch_commands(config: &Config, identity: &Identity) -> Result<Vec<RemoteCommand>> {
    let Some(base_url) = resolve_server_url(config) else {
        return Ok(Vec::new());
    };
    let token = config.server.agent_token.trim();
    if token.is_empty() {
        return Ok(Vec::new());
    }
    let path = format!(
        "/api/agent/commands?agent_id={}",
        percent_encode(&identity.agent_id)
    );
    let (status, body) = http_request(
        "GET",
        &base_url,
        &path,
        token,
        None,
        config.server.insecure_tls,
    )?;
    if !(200..300).contains(&status) {
        bail!("拉取远程指令失败：HTTP {status}");
    }
    let resp: CommandsResp = serde_json::from_slice(&body).context("解析远程指令 JSON 失败")?;
    Ok(resp.items)
}

/// 回传远程指令执行结果。
pub fn ack_command(
    config: &Config,
    identity: &Identity,
    command_id: i64,
    status_str: &str,
    message: &str,
) -> Result<()> {
    let Some(base_url) = resolve_server_url(config) else {
        return Ok(());
    };
    let token = config.server.agent_token.trim();
    if token.is_empty() {
        return Ok(());
    }
    let payload = serde_json::json!({
        "agent_id": identity.agent_id,
        "command_id": command_id,
        "status": status_str,
        "message": message,
    });
    let body = serde_json::to_vec(&payload)?;
    let (status, _) = http_request(
        "POST",
        &base_url,
        "/api/agent/commands/ack",
        token,
        Some(&body),
        config.server.insecure_tls,
    )?;
    if !(200..300).contains(&status) {
        bail!("回传指令状态失败：HTTP {status}");
    }
    Ok(())
}

/// 拉取并安全执行服务端下发的远程删除文件指令。
pub fn process_remote_commands(base_config: &Config, active_config: &Config, store: &Store) {
    let Ok(identity) = Identity::load_or_create(store, active_config) else {
        return;
    };
    let commands = match fetch_commands(base_config, &identity) {
        Ok(items) => items,
        Err(error) => {
            tracing::debug!(error = %error, "拉取远程指令失败");
            return;
        }
    };
    for cmd in commands {
        if cmd.action != "delete_file" {
            let _ = ack_command(
                base_config,
                &identity,
                cmd.id,
                "failed",
                &format!("不支持的指令: {}", cmd.action),
            );
            continue;
        }
        match safe_delete_file(active_config, store, &cmd.target_path) {
            Ok(msg) => {
                tracing::info!(path = %cmd.target_path, "已根据服务端指令删除敏感文件");
                let _ = ack_command(base_config, &identity, cmd.id, "done", &msg);
            }
            Err(error) => {
                tracing::warn!(path = %cmd.target_path, error = %error, "执行服务端删除文件指令失败");
                let _ = ack_command(
                    base_config,
                    &identity,
                    cmd.id,
                    "failed",
                    &format!("{error:#}"),
                );
            }
        }
    }
}

fn safe_delete_file(config: &Config, store: &Store, raw_path: &str) -> Result<String> {
    let target = std::path::PathBuf::from(raw_path);
    if !target.is_absolute() {
        bail!("拒绝非绝对路径");
    }
    let canonical = dunce::canonicalize(&target).unwrap_or_else(|_| target.clone());
    let in_roots = config.effective_roots().iter().any(|root| {
        let root_canon = dunce::canonicalize(root).unwrap_or_else(|_| root.clone());
        canonical.starts_with(&root_canon)
    });
    let in_store = store.has_file_or_finding(&target) || store.has_file_or_finding(&canonical);
    if !in_roots && !in_store {
        bail!("目标文件不在受管目录或扫描台账中，已拒绝删除");
    }
    if !target.exists() {
        let _ = store.remove_file(&target);
        return Ok("文件已不存在，已清理本地台账".to_string());
    }
    if !target.is_file() {
        bail!("目标不是普通文件，拒绝删除");
    }
    std::fs::remove_file(&target).with_context(|| format!("删除文件失败: {}", target.display()))?;
    let _ = store.remove_file(&target);
    Ok("已删除文件".to_string())
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 向服务端上报当前客户端已应用的策略版本。
pub fn report_revision(config: &Config, identity: &Identity, revision: i64) -> Result<()> {
    let Some(base_url) = resolve_server_url(config) else {
        return Ok(());
    };
    let token = config.server.agent_token.trim();
    if token.is_empty() {
        return Ok(());
    }
    let payload = serde_json::json!({
        "agent_id": identity.agent_id,
        "revision": revision,
    });
    let body = serde_json::to_vec(&payload)?;
    let (status, _) = http_request(
        "POST",
        &base_url,
        "/api/agent/revision",
        token,
        Some(&body),
        config.server.insecure_tls,
    )?;
    if !(200..300).contains(&status) {
        bail!("上报策略版本失败：HTTP {status}");
    }
    Ok(())
}

struct ParsedUrl<'a> {
    https: bool,
    host: &'a str,
    port: u16,
    base_path: &'a str,
}

fn parse_url(url: &str) -> Result<ParsedUrl<'_>> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("服务端地址需以 http:// 或 https:// 开头：{url}");
    };
    let (authority, base_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        if let Some((h, tail)) = stripped.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(if https { 443 } else { 80 });
            (h, port)
        } else {
            bail!("无效的 IPv6 地址：{authority}");
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .with_context(|| format!("无效端口号：{authority}"))?;
        (h, port)
    } else {
        (authority, if https { 443 } else { 80 })
    };
    if host.is_empty() {
        bail!("服务端主机名为空：{url}");
    }
    Ok(ParsedUrl {
        https,
        host,
        port,
        base_path,
    })
}

fn http_request(
    method: &str,
    base_url: &str,
    path: &str,
    bearer: &str,
    body: Option<&[u8]>,
    insecure_tls: bool,
) -> Result<(u16, Vec<u8>)> {
    let parsed = parse_url(base_url)?;
    let full_path = format!("{}{}", parsed.base_path, path);
    http_request_parts(&parsed, method, &full_path, bearer, body, insecure_tls)
}

/// 供服务端 Webhook 等组件使用的轻量 JSON POST。
pub fn post_json(url: &str, body: &[u8], insecure_tls: bool) -> Result<u16> {
    let parsed = parse_url(url)?;
    let path = if parsed.base_path.is_empty() {
        "/"
    } else {
        parsed.base_path
    };
    let (status, _) = http_request_parts(&parsed, "POST", path, "", Some(body), insecure_tls)?;
    Ok(status)
}

fn http_request_parts(
    parsed: &ParsedUrl<'_>,
    method: &str,
    full_path: &str,
    bearer: &str,
    body: Option<&[u8]>,
    insecure_tls: bool,
) -> Result<(u16, Vec<u8>)> {
    let addr = (parsed.host, parsed.port)
        .to_socket_addrs()
        .with_context(|| format!("解析服务端地址失败：{}:{}", parsed.host, parsed.port))?
        .next()
        .context("未解析到服务端 IP")?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .with_context(|| format!("连接服务端失败：{addr}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let host_header =
        if (parsed.https && parsed.port == 443) || (!parsed.https && parsed.port == 80) {
            parsed.host.to_string()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };

    let mut req = format!(
        "{method} {full_path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if !bearer.is_empty() {
        req.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
    }
    if let Some(bytes) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    req.push_str("\r\n");

    let raw_response = if parsed.https {
        let tls_config = build_tls_config(insecure_tls)?;
        let server_name = ServerName::try_from(parsed.host.to_string())
            .map_err(|_| anyhow::anyhow!("无效的 TLS 主机名：{}", parsed.host))?;
        let conn = ClientConnection::new(Arc::new(tls_config), server_name)
            .context("初始化 TLS 客户端失败")?;
        let mut tls = StreamOwned::new(conn, stream);
        tls.write_all(req.as_bytes())?;
        if let Some(bytes) = body {
            tls.write_all(bytes)?;
        }
        tls.flush()?;
        read_http_bytes(&mut tls)?
    } else {
        let mut tcp = stream;
        tcp.write_all(req.as_bytes())?;
        if let Some(bytes) = body {
            tcp.write_all(bytes)?;
        }
        tcp.flush()?;
        read_http_bytes(&mut tcp)?
    };

    parse_http_response(&raw_response)
}

fn read_http_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 8 * 1024 * 1024 {
                    bail!("服务端响应过大");
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(out)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("服务端响应缺少 HTTP 头结束标记")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("无法解析 HTTP 状态码")?;
    Ok((status, raw[split + 4..].to_vec()))
}

fn build_tls_config(insecure: bool) -> Result<ClientConfig> {
    if insecure {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        return Ok(config);
    }
    let roots = rustls::RootCertStore::empty();
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
