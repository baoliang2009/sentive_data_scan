//! 服务端配置（`server.toml`）。
//!
//! 与客户端 `config.toml` 分开：服务端通常部署在中心节点，职责与权限完全不同，
//! 混在一起会让「客户端配置」意外影响服务端。

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{ensure_private_dir, expand_path, secure_file};

pub const DEFAULT_SERVER_CONFIG: &str = include_str!("../../config/default-server.toml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub server: HttpConfig,
    pub ingest: IngestConfig,
    pub storage: ServerStorageConfig,
    pub auth: AuthConfig,
    pub retention: RetentionConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Web 控制台 / HTTP API 监听地址。
    pub bind: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8443".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestConfig {
    /// syslog 接收是否启用。
    pub enabled: bool,
    /// `udp` / `tcp`（也接受 `both`）。
    pub protocol: String,
    /// syslog 监听地址。
    pub bind: String,
    /// 允许上报的客户端 CIDR 白名单；空表示不限制。
    pub allow_cidrs: Vec<String>,
    /// 单条报文最大字节数。
    pub max_message_bytes: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: "both".to_string(),
            bind: "0.0.0.0:5514".to_string(),
            allow_cidrs: Vec::new(),
            max_message_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerStorageConfig {
    /// SQLite 路径；空则使用数据目录下 `server.db`。
    pub database: PathBuf,
}

impl Default for ServerStorageConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// 允许上报/拉取规则的共享 Token。空表示首次启动自动生成。
    pub agent_token: String,
    /// Web 控制台管理口令的 PBKDF2 记录。空则首次启动生成随机口令并打印。
    pub admin_password_hash: String,
    /// 会话有效期（分钟）。
    pub session_ttl_minutes: u64,
    /// 是否允许 Agent 匿名读取规则（默认关闭）。
    pub allow_anonymous_rules: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            agent_token: String::new(),
            admin_password_hash: String::new(),
            session_ttl_minutes: 480,
            allow_anonymous_rules: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionConfig {
    /// 告警保留天数；0 表示永久保留。
    pub event_days: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            event_days: 180,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// 证书链路径（PEM）。留空表示使用明文 HTTP。
    pub cert: PathBuf,
    /// 私钥路径（PEM）。
    pub key: PathBuf,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: PathBuf::new(),
            key: PathBuf::new(),
        }
    }
}

impl ServerConfig {
    pub fn load(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
        let path = resolve_server_config_path(explicit);
        if !path.exists() {
            write_default_server_config(&path, false)?;
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("无法读取服务端配置 {}", path.display()))?;
        let mut config: Self = toml::from_str(&text)
            .with_context(|| format!("服务端配置格式错误: {}", path.display()))?;
        config.normalize_relative_paths(path.parent().unwrap_or(Path::new(".")));
        config.validate()?;
        Ok((config, path))
    }

    pub fn validate(&self) -> Result<()> {
        if !has_host_port(&self.server.bind) {
            bail!(
                "server.bind 需为 host:port 形式，例如 0.0.0.0:8443（当前：{}）",
                self.server.bind
            );
        }
        if self.ingest.enabled {
            if !has_host_port(&self.ingest.bind) {
                bail!(
                    "ingest.bind 需为 host:port 形式，例如 0.0.0.0:5514（当前：{}）",
                    self.ingest.bind
                );
            }
            if !matches!(
                self.ingest.protocol.to_ascii_lowercase().as_str(),
                "udp" | "tcp" | "both"
            ) {
                bail!("ingest.protocol 只支持 udp / tcp / both");
            }
        }
        if !matches!(
            self.ingest.protocol.to_ascii_lowercase().as_str(),
            "udp" | "tcp" | "both"
        ) {
            bail!("ingest.protocol 只支持 udp / tcp / both");
        }
        for cidr in &self.ingest.allow_cidrs {
            parse_cidr(cidr).with_context(|| format!("ingest.allow_cidrs 中的 {cidr} 无效"))?;
        }
        if !self.tls.cert.as_os_str().is_empty() != !self.tls.key.as_os_str().is_empty() {
            bail!("tls.cert 与 tls.key 必须同时配置或同时留空");
        }
        if self.auth.session_ttl_minutes == 0 {
            bail!("auth.session_ttl_minutes 必须大于 0");
        }
        Ok(())
    }

    pub fn database_path(&self) -> PathBuf {
        if self.storage.database.as_os_str().is_empty() {
            crate::config::data_dir().join("server.db")
        } else {
            expand_path(&self.storage.database)
        }
    }

    /// syslog 需要监听的协议列表。
    pub fn listen_protocols(&self) -> Vec<&'static str> {
        match self.ingest.protocol.to_ascii_lowercase().as_str() {
            "udp" => vec!["udp"],
            "tcp" => vec!["tcp"],
            _ => vec!["udp", "tcp"],
        }
    }

    pub fn session_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.auth.session_ttl_minutes.saturating_mul(60))
    }

    fn normalize_relative_paths(&mut self, base: &Path) {
        for path in [
            &mut self.storage.database,
            &mut self.tls.cert,
            &mut self.tls.key,
        ] {
            if path.as_os_str().is_empty() {
                continue;
            }
            let expanded = expand_path(path);
            *path = if expanded.is_absolute() {
                expanded
            } else {
                base.join(expanded)
            };
        }
    }
}

pub fn resolve_server_config_path(explicit: Option<&Path>) -> PathBuf {
    let resolve = |path: PathBuf| {
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(&path))
                .unwrap_or(path)
        }
    };
    if let Some(path) = explicit {
        return resolve(expand_path(path));
    }
    if let Ok(path) = std::env::var("DATASENTINEL_SERVER_CONFIG") {
        if !path.trim().is_empty() {
            return resolve(expand_path(Path::new(&path)));
        }
    }
    crate::config::config_dir().join("server.toml")
}

pub fn write_default_server_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    fs::write(path, DEFAULT_SERVER_CONFIG)
        .with_context(|| format!("无法写入默认服务端配置 {}", path.display()))?;
    secure_file(path)?;
    Ok(())
}

fn has_host_port(value: &str) -> bool {
    let value = value.trim();
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }
    port.parse::<u16>().map(|port| port > 0).unwrap_or(false)
}

/// 极简 CIDR 校验，支持 IPv4 与 IPv6 的单地址或 `x/y` 形式。
pub fn parse_cidr(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        bail!("CIDR 不能为空");
    }
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (value, None),
    };
    let ip: std::net::IpAddr = addr
        .parse()
        .with_context(|| format!("IP 地址无效: {addr}"))?;
    if let Some(prefix) = prefix {
        let prefix: u8 = prefix.parse().with_context(|| format!("前缀长度无效: {prefix}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("前缀长度 {prefix} 超过 {max}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ports_and_protocols() {
        let mut config = ServerConfig::default();
        assert!(config.validate().is_ok());

        config.server.bind = "0.0.0.0".to_string();
        assert!(config.validate().is_err());

        let mut config = ServerConfig::default();
        config.ingest.protocol = "sctp".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_cidrs() {
        assert!(parse_cidr("10.0.0.0/8").is_ok());
        assert!(parse_cidr("192.168.1.5").is_ok());
        assert!(parse_cidr("::1/128").is_ok());
        assert!(parse_cidr("10.0.0.0/99").is_err());
        assert!(parse_cidr("not-an-ip").is_err());
    }

    #[test]
    fn requires_paired_tls_files() {
        let mut config = ServerConfig::default();
        config.tls.cert = PathBuf::from("/tmp/cert.pem");
        assert!(config.validate().is_err());
        config.tls.key = PathBuf::from("/tmp/key.pem");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_config_parses() {
        let config: ServerConfig = toml::from_str(DEFAULT_SERVER_CONFIG).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn listen_protocols_expand_both() {
        let mut config = ServerConfig::default();
        assert_eq!(config.listen_protocols(), vec!["udp", "tcp"]);
        config.ingest.protocol = "tcp".to_string();
        assert_eq!(config.listen_protocols(), vec!["tcp"]);
    }
}
