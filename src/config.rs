use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::Severity;

pub const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub scan: ScanConfig,
    pub watch: WatchConfig,
    pub notify: NotifyConfig,
    pub storage: StorageConfig,
    pub rules: RulesConfig,
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

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            disabled: Vec::new(),
            min_severity: Severity::Low,
            custom: Vec::new(),
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
    /// Comma separated: none, luhn, cn_id, cn_id_15, phone, placeholder, entropy:3.2
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
