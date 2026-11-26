use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::Severity;

pub const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

/// DHCP/DNS-SD 约定：服务类型名（`_xxx`）最长 15 字节，实例名才可长。
pub const DEFAULT_MDNS_SERVICE: &str = "_datasentinel._udp.local.";

/// 测试专用服务类型：避免与真实部署的 `_datasentinel` 广播互相干扰。
pub const MDNS_TEST_SERVICE: &str = "_dstest._udp.local.";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub scan: ScanConfig,
    pub watch: WatchConfig,
    pub notify: NotifyConfig,
    pub storage: StorageConfig,
    pub rules: RulesConfig,
    pub syslog: SyslogConfig,
    pub syslog_server: SyslogServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub language: String,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            language: "zh-CN".to_string(),
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Empty means auto-detect Desktop / Documents / Downloads (incl. localized names).
    pub roots: Vec<PathBuf>,
    /// Trusted paths that should never be scanned (in addition to built-in excludes).
    pub allow_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
    /// Apply the built-in cache/VCS/binary excludes in addition to config.
    pub use_default_excludes: bool,
    pub include_extensions: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub max_file_size_mb: u64,
    pub threads: usize,
    pub scan_on_startup: bool,
    pub full_scan_interval_hours: u64,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    pub office_documents: bool,
    pub chunk_kb: usize,
    pub context_chars: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            allow_globs: Vec::new(),
            exclude_globs: default_exclude_globs(),
            use_default_excludes: true,
            include_extensions: Vec::new(),
            exclude_extensions: default_exclude_extensions(),
            max_file_size_mb: 64,
            threads: 0,
            scan_on_startup: true,
            full_scan_interval_hours: 24,
            follow_symlinks: false,
            skip_hidden: false,
            office_documents: true,
            chunk_kb: 1024,
            context_chars: 160,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    pub enabled: bool,
    pub roots: Vec<PathBuf>,
    pub debounce_ms: u64,
    pub ignore_temp_files: bool,
    pub max_pending: usize,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            roots: Vec::new(),
            debounce_ms: 2000,
            ignore_temp_files: true,
            max_pending: 20_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub enabled: bool,
    pub min_severity: Severity,
    /// `summary` (default), `per_file` or `off`.
    pub mode: String,
    pub sound: bool,
    pub max_per_batch: usize,
    /// macOS only: `auto` (dialog for medium+, notification for low),
    /// `alert` (always dialog) or `notification` (notification center only).
    pub macos_mode: String,
    /// Re-alert when a watched file is saved again and still contains
    /// qualifying sensitive data, even if no new value appeared.
    pub renotify_modified: bool,
    /// Minimum gap between two alerts for the same file, in seconds.
    pub renotify_cooldown_secs: u64,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_severity: Severity::Medium,
            mode: "summary".to_string(),
            sound: true,
            max_per_batch: 5,
            macos_mode: "auto".to_string(),
            renotify_modified: true,
            renotify_cooldown_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Empty means platform data dir (e.g. `~/.local/share/DataSentinel/sentinel.db`).
    pub database: PathBuf,
    pub reports_dir: PathBuf,
    pub store_raw_match: bool,
    pub retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::new(),
            reports_dir: PathBuf::new(),
            store_raw_match: false,
            retention_days: 180,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
    pub min_severity: Severity,
    pub custom: Vec<CustomRuleConfig>,
}

/// 服务端接收配置（用于 `sentinel syslog-server`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogServerConfig {
    pub enabled: bool,
    /// `udp` / `tcp`。
    pub protocol: String,
    /// 监听地址，例如 `0.0.0.0:514`。
    pub bind: String,
    /// 接收日志落盘路径；空则写入数据目录下 `syslog/received.log`。
    pub output: PathBuf,
    /// 是否通过 mDNS 广播自己，供客户端自动发现。
    pub advertise: bool,
    /// 广播的服务类型；需与客户端 `syslog.mdns_service` 一致。
    pub mdns_service: String,
    /// 广播的实例名；空则用 `DataSentinel-<hostname>`。
    pub instance: String,
}

impl Default for SyslogServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: "udp".to_string(),
            bind: "0.0.0.0:5514".to_string(),
            output: PathBuf::new(),
            advertise: true,
            mdns_service: DEFAULT_MDNS_SERVICE.to_string(),
            instance: String::new(),
        }
    }
}

impl SyslogServerConfig {
    pub fn transport_supported(&self) -> bool {
        matches!(self.protocol.to_ascii_lowercase().as_str(), "udp" | "tcp")
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            disabled: Vec::new(),
            min_severity: Severity::Low,
            custom: Vec::new(),
        }
    }
}

/// Syslog 外发：把命中的敏感数据以 RFC 5424 报文推送到服务端。
///
/// 默认关闭。开启后只发送脱敏值（`store_raw_match = false` 时的默认行为），
/// 除非显式打开 `send_raw`；这样“外发”不会变成一次数据泄漏。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    pub enabled: bool,
    /// `udp` / `tcp` / `unix`。
    pub protocol: String,
    /// 服务端地址：UDP/TCP 为 `host:port`，unix 为套接字路径。
    pub server: String,
    /// RFC 5424 facility，常见 `auth`(4) / `user`(1) / `local0`-`local7`。
    pub facility: String,
    /// 发送的最低命中级别。
    pub min_severity: Severity,
    /// 报文 HOSTNAME 字段；空则使用本机主机名。
    pub hostname: String,
    /// 报文 APP-NAME 字段。
    pub app_name: String,
    /// 是否附带脱敏上下文片段。
    pub include_snippet: bool,
    /// 是否外发命中原文（默认关闭，仅脱敏值）。
    pub send_raw: bool,
    /// 单次发送超时（毫秒），UDP 也用于避免阻塞扫描线程。
    pub timeout_ms: u64,
    /// 服务端地址的解析方式：`static`（只用 `server`）或 `mdns`（局域网自动发现）。
    pub discovery: String,
    /// 自动发现的服务类型（DNS-SD），默认 `_datasentinel._udp.local.`。
    pub mdns_service: String,
    /// 自动发现超时（毫秒）。超时后回落到静态 `server`。
    pub mdns_timeout_ms: u64,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: "udp".to_string(),
            server: String::new(),
            facility: "auth".to_string(),
            min_severity: Severity::Medium,
            hostname: String::new(),
            app_name: "DataSentinel".to_string(),
            include_snippet: true,
            send_raw: false,
            timeout_ms: 2000,
            discovery: "static".to_string(),
            mdns_service: DEFAULT_MDNS_SERVICE.to_string(),
            mdns_timeout_ms: 4000,
        }
    }
}

impl SyslogConfig {
    /// 解析后的服务端地址；未配置时返回 `None`。
    pub fn endpoint(&self) -> Option<String> {
        let server = self.server.trim();
        if server.is_empty() {
            None
        } else {
            Some(server.to_string())
        }
    }

    /// 是否启用 mDNS 自动发现。
    pub fn uses_mdns(&self) -> bool {
        self.discovery.eq_ignore_ascii_case("mdns")
    }

    /// 传输层是否能识别。`unix` 仅 Unix 平台可用。
    pub fn transport_supported(&self) -> bool {
        let protocol = self.protocol.to_ascii_lowercase();
        if protocol == "unix" {
            cfg!(unix)
        } else {
            matches!(protocol.as_str(), "udp" | "tcp")
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleConfig {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: Severity,
    /// Rust `regex` syntax. The first capture group is treated as the secret.
    pub pattern: String,
    pub keywords: Vec<String>,
    /// Comma separated: none, luhn, bank_card, cn_id, cn_id_15, phone, landline,
    /// social_security, passport, placeholder, entropy:3.2
    pub validator: String,
    pub description: String,
    pub context_chars: usize,
}

impl Default for CustomRuleConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            category: "internal".to_string(),
            severity: Severity::Medium,
            pattern: String::new(),
            keywords: Vec::new(),
            validator: "none".to_string(),
            description: String::new(),
            context_chars: 160,
        }
    }
}

pub fn default_exclude_globs() -> Vec<String> {
    [
        "**/node_modules/**",
        "**/.git/**",
        "**/.svn/**",
        "**/__pycache__/**",
        "**/target/**",
        "**/.venv/**",
        "**/venv/**",
        "**/.cache/**",
        "**/.npm/**",
        "**/.gradle/**",
        "**/.idea/**",
        "**/.vscode/**",
        "**/Library/Caches/**",
        "**/AppData/Local/Temp/**",
        "**/AppData/Local/Cache/**",
        "**/$RECYCLE.BIN/**",
        "**/System Volume Information/**",
        "**/.Trash/**",
        "**/.Trashes/**",
        "**/lost+found/**",
    ]
    .iter()
    .map(|item| item.to_string())
    .collect()
}

pub fn default_exclude_extensions() -> Vec<String> {
    [
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "svg", "tif", "tiff", "heic", "raw",
        "mp3", "wav", "flac", "aac", "ogg", "m4a", "mp4", "mkv", "avi", "mov", "wmv", "flv", "zip",
        "rar", "7z", "tar", "gz", "bz2", "xz", "zst", "iso", "dmg", "pkg", "deb", "rpm", "exe",
        "dll", "so", "dylib", "bin", "class", "o", "a", "obj", "lib", "pdb", "sys", "ttf", "otf",
        "woff", "woff2", "eot", "db", "sqlite", "sqlite3", "mdb", "lock",
    ]
    .iter()
    .map(|item| item.to_string())
    .collect()
}

impl Config {
    pub fn load(explicit_path: Option<&Path>) -> Result<(Self, PathBuf)> {
        let path = resolve_config_path(explicit_path);
        if !path.exists() {
            write_default_config(&path, false)?;
            tracing::info!(path = %path.display(), "已生成默认配置文件");
        }

        let text = fs::read_to_string(&path)
            .with_context(|| format!("无法读取配置文件 {}", path.display()))?;
        let mut config: Config = toml::from_str(&text)
            .with_context(|| format!("配置文件格式错误: {}", path.display()))?;
        config.validate()?;
        config.normalize_relative_paths(path.parent().unwrap_or(Path::new(".")));

        Ok((config, path))
    }

    pub fn validate(&self) -> Result<()> {
        if self.scan.max_file_size_mb == 0 {
            bail!("scan.max_file_size_mb 必须大于 0");
        }
        if self.scan.chunk_kb < 16 {
            bail!("scan.chunk_kb 不能小于 16");
        }
        if !matches!(self.notify.mode.as_str(), "summary" | "per_file" | "off") {
            bail!("notify.mode 只支持 summary / per_file / off");
        }
        if !matches!(
            self.notify.macos_mode.as_str(),
            "auto" | "alert" | "notification"
        ) {
            bail!("notify.macos_mode 只支持 auto / alert / notification");
        }
        if !matches!(self.syslog.protocol.as_str(), "udp" | "tcp" | "unix") {
            bail!("syslog.protocol 只支持 udp / tcp / unix");
        }
        if !matches!(self.syslog.discovery.as_str(), "static" | "mdns") {
            bail!("syslog.discovery 只支持 static / mdns");
        }
        if self.syslog.uses_mdns() && !is_valid_mdns_service(&self.syslog.mdns_service) {
            bail!(
                "syslog.mdns_service 需形如 _datasentinel._udp.local.（服务名 ≤15 字节），当前：{}",
                self.syslog.mdns_service
            );
        }
        if self.syslog.enabled {
            if self.syslog.protocol == "unix" && !cfg!(unix) {
                bail!("syslog.protocol = \"unix\" 仅在 Unix 平台可用");
            }
            if !self.syslog.uses_mdns() && self.syslog.server.trim().is_empty() {
                bail!("已启用 syslog 外发，但 syslog.server 为空（也可设 discovery = \"mdns\" 自动发现）");
            }
            if !self.syslog.uses_mdns()
                && self.syslog.protocol != "unix"
                && !has_host_port(&self.syslog.server)
            {
                bail!(
                    "syslog.server 需为 host:port 形式，例如 10.0.0.5:514（当前：{}）",
                    self.syslog.server
                );
            }
        }
        if self.syslog_server.enabled {
            if !self.syslog_server.transport_supported() {
                bail!("syslog_server.protocol 只支持 udp / tcp");
            }
            if !has_host_port(&self.syslog_server.bind) {
                bail!(
                    "syslog_server.bind 需为 host:port 形式，例如 0.0.0.0:5514（当前：{}）",
                    self.syslog_server.bind
                );
            }
            if self.syslog_server.advertise
                && !is_valid_mdns_service(&self.syslog_server.mdns_service)
            {
                bail!(
                    "syslog_server.mdns_service 需形如 _datasentinel._udp.local.，当前：{}",
                    self.syslog_server.mdns_service
                );
            }
        }
        let mut ids = HashSet::new();
        for rule in &self.rules.custom {
            if rule.id.trim().is_empty() {
                bail!("自定义规则缺少 id");
            }
            if rule.pattern.trim().is_empty() {
                bail!("自定义规则 {} 缺少 pattern", rule.id);
            }
            if !ids.insert(rule.id.clone()) {
                bail!("自定义规则 id 重复: {}", rule.id);
            }
        }
        Ok(())
    }

    pub fn effective_roots(&self) -> Vec<PathBuf> {
        let roots = if self.scan.roots.is_empty() {
            auto_roots()
        } else {
            self.scan.roots.iter().map(|p| expand_path(p)).collect()
        };
        dedup_paths(roots)
    }

    pub fn watch_roots(&self) -> Vec<PathBuf> {
        if self.watch.roots.is_empty() {
            self.effective_roots()
        } else {
            dedup_paths(self.watch.roots.iter().map(|p| expand_path(p)).collect())
        }
    }

    pub fn data_dir(&self) -> PathBuf {
        data_dir()
    }

    pub fn database_path(&self) -> PathBuf {
        if self.storage.database.as_os_str().is_empty() {
            data_dir().join("sentinel.db")
        } else {
            expand_path(&self.storage.database)
        }
    }

    pub fn reports_dir(&self) -> PathBuf {
        if self.storage.reports_dir.as_os_str().is_empty() {
            data_dir().join("reports")
        } else {
            expand_path(&self.storage.reports_dir)
        }
    }

    pub fn logs_dir(&self) -> PathBuf {
        data_dir().join("logs")
    }

    pub fn max_file_size_bytes(&self) -> u64 {
        self.scan.max_file_size_mb.saturating_mul(1024 * 1024)
    }

    fn normalize_relative_paths(&mut self, base: &Path) {
        fn normalize(path: &mut PathBuf, base: &Path) {
            if path.as_os_str().is_empty() {
                return;
            }
            let expanded = expand_path(path);
            *path = if expanded.is_absolute() {
                expanded
            } else {
                base.join(expanded)
            };
        }

        for root in &mut self.scan.roots {
            normalize(root, base);
        }
        for root in &mut self.watch.roots {
            normalize(root, base);
        }
        normalize(&mut self.storage.database, base);
        normalize(&mut self.storage.reports_dir, base);
    }
}

/// 校验 mDNS 服务类型：`_name._udp.local.` / `_name._tcp.local.`。
///
/// RFC 6763 规定服务名（`_name` 去掉下划线）不超过 15 字节，超过会被
/// Avahi / Bonjour 拒绝发布，因此这里提前拦截而不是运行期静默失败。
pub fn is_valid_mdns_service(value: &str) -> bool {
    let value = value.trim().trim_end_matches('.');
    let Some((service, rest)) = value.split_once('.') else {
        return false;
    };
    let Some(name) = service.strip_prefix('_') else {
        return false;
    };
    if name.is_empty() || name.len() > 15 {
        return false;
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return false;
    }
    matches!(rest, "_udp.local" | "_tcp.local")
}

/// 校验 `host:port`（支持 IPv6 的 `[::1]:514`），端口必须非 0。
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

pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
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
    if let Ok(path) = std::env::var("DATASENTINEL_CONFIG") {
        if !path.trim().is_empty() {
            return resolve(expand_path(Path::new(&path)));
        }
    }
    config_dir().join("config.toml")
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("DataSentinel")
}

pub fn data_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("DataSentinel")
}

pub fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    fs::write(path, DEFAULT_CONFIG)
        .with_context(|| format!("无法写入默认配置 {}", path.display()))?;
    secure_file(path)?;
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(path).with_context(|| format!("无法创建目录 {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub fn secure_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("无法设置文件权限 {}", path.display()))?;
    }
    Ok(())
}

/// 日志保留天数（滚动日志按天切分，旧文件需要主动删除）。
pub const LOG_RETENTION_DAYS: u64 = 14;

/// 清理超过保留天数的滚动日志。
///
/// `tracing_appender::rolling::daily` 只负责按天切分，**不会删除旧文件**；
/// 常驻守护进程跑上几个月，`logs/` 会一直变大。启动时清一次，守护进程
/// 每天再清一次，足够把日志量收敛住。
pub fn prune_old_logs(dir: &Path, keep_days: u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let max_age = std::time::Duration::from_secs(keep_days.saturating_mul(86_400));
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !name.starts_with("sentinel.log") {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let expired = now
            .duration_since(modified)
            .map(|age| age > max_age)
            .unwrap_or(false);
        if expired {
            let _ = fs::remove_file(&path);
        }
    }
}

pub fn expand_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        return dirs::home_dir().unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = text
            .strip_prefix("$HOME/")
            .or_else(|| text.strip_prefix("${HOME}/"))
        {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        let normalized = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.insert(normalized.clone()) {
            out.push(path);
        }
    }
    out
}

/// Common user directories, including localized XDG names on Kylin/Linux.
pub fn auto_roots() -> Vec<PathBuf> {
    let home = match dirs::home_dir() {
        Some(home) => home,
        None => return Vec::new(),
    };
    let mut roots = Vec::new();

    // XDG user dirs (Kylin / most Linux desktops, localized names like 桌面/文档/下载).
    for key in ["XDG_DESKTOP_DIR", "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR"] {
        if let Some(path) = xdg_user_dir(key) {
            roots.push(path);
        }
    }

    // Platform-standard locations (macOS/Windows, and fallback for Linux).
    for path in [
        dirs::desktop_dir(),
        dirs::document_dir(),
        dirs::download_dir(),
    ]
    .into_iter()
    .flatten()
    {
        roots.push(path);
    }

    // English + Chinese fallbacks, covers desktops where XDG files are missing.
    for name in [
        "Desktop",
        "Documents",
        "Downloads",
        "桌面",
        "文档",
        "下载",
        "WPS Cloud Files",
        "WeChat Files",
    ] {
        let candidate = home.join(name);
        if candidate.is_dir() {
            roots.push(candidate);
        }
    }

    dedup_paths(roots.into_iter().filter(|p| p.is_dir()).collect())
}

fn xdg_user_dir(key: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let file = home.join(".config/user-dirs.dirs");
    let text = fs::read_to_string(&file).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(key) {
            continue;
        }
        let (_, raw) = line.split_once('=')?;
        let raw = raw.trim().trim_matches('"');
        if raw.is_empty() {
            return None;
        }
        let expanded = raw
            .replace("${HOME}", &home.to_string_lossy())
            .replace("$HOME", &home.to_string_lossy());
        let path = PathBuf::from(expanded);
        if path.is_absolute() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let config: Config = toml::from_str(DEFAULT_CONFIG).expect("default config must parse");
        config.validate().expect("default config must be valid");
        assert!(config.scan.max_file_size_mb > 0);
    }

    #[test]
    fn expands_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_path(Path::new("~/abc")), home.join("abc"));
    }
}
