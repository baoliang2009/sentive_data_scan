//! Local web console for DataSentinel.
//!
//! `sentinel ui` binds a single-user HTTP server on the loopback interface and
//! opens the system default browser. Keeping the UI in the browser means the
//! console works identically on Windows, Kylin/Linux and macOS without shipping
//! a WebView runtime, and the whole product stays a single executable.

pub mod api;
pub mod server;
mod tomlpatch;

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::config::Config;
use crate::scan::ScanProgress;
use crate::util::{now_ts, sha256_hex_str};

pub const DEFAULT_PORT: u16 = 7419;

pub struct AppContext {
    pub config_path: PathBuf,
    pub token: String,
    pub scan: Arc<ScanSession>,
    pub started_at: i64,
    /// Autostart status shells out to `launchctl` / `schtasks` / `systemctl`,
    /// so the result is cached for a few seconds.
    pub autostart_cache: Mutex<Option<(std::time::Instant, String)>>,
    /// One shared read connection for every request: opening a fresh handle on
    /// each API call competes with the scanner for the WAL lock.
    store_cache: Mutex<Option<(PathBuf, Arc<crate::store::Store>)>>,
}

impl AppContext {
    pub fn load_config(&self) -> Result<Config> {
        Config::load(Some(&self.config_path)).map(|(config, _path)| config)
    }

    pub fn store(&self) -> Result<Arc<crate::store::Store>> {
        let path = self.load_config()?.database_path();
        if let Ok(cache) = self.store_cache.lock() {
            if let Some((cached, store)) = cache.as_ref() {
                if cached == &path {
                    return Ok(store.clone());
                }
            }
        }
        let store = Arc::new(crate::store::Store::open(&path)?);
        if let Ok(mut cache) = self.store_cache.lock() {
            *cache = Some((path, store.clone()));
        }
        Ok(store)
    }

    pub fn autostart_status(&self) -> String {
        if let Ok(cache) = self.autostart_cache.lock() {
            if let Some((at, text)) = cache.as_ref() {
                if at.elapsed().as_secs() < 15 {
                    return text.clone();
                }
            }
        }
        self.autostart_status_fresh()
    }

    pub fn autostart_status_fresh(&self) -> String {
        let text = crate::autostart::status()
            .unwrap_or_else(|error| format!("无法读取自启动状态：{error}"));
        if let Ok(mut cache) = self.autostart_cache.lock() {
            *cache = Some((std::time::Instant::now(), text.clone()));
        }
        text
    }
}

/// One scan batch driven by the console.
pub struct ScanSession {
    pub running: AtomicBool,
    pub started_at: AtomicI64,
    pub force: AtomicBool,
    pub progress: Arc<ScanProgress>,
    pub roots: Mutex<Vec<String>>,
    pub last: Mutex<Option<ScanResult>>,
    pub error: Mutex<Option<String>>,
}

impl ScanSession {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            started_at: AtomicI64::new(0),
            force: AtomicBool::new(false),
            progress: Arc::new(ScanProgress::new()),
            roots: Mutex::new(Vec::new()),
            last: Mutex::new(None),
            error: Mutex::new(None),
        }
    }
}

impl Default for ScanSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ScanResult {
    pub started_at: i64,
    pub finished_at: i64,
    pub duration_ms: u64,
    pub roots: Vec<String>,
    pub summary: serde_json::Value,
}

pub fn run(config_path: Option<PathBuf>, port: u16, open_browser: bool) -> Result<()> {
    let (_config, path) = Config::load(config_path.as_deref())?;
    let listener = bind(port)?;
    let address = listener.local_addr().context("无法获取监听地址")?;
    let context = Arc::new(AppContext {
        config_path: path,
        token: random_token(),
        scan: Arc::new(ScanSession::new()),
        started_at: now_ts(),
        autostart_cache: Mutex::new(None),
        store_cache: Mutex::new(None),
    });

    let url = format!("http://127.0.0.1:{}/", address.port());
    println!("数据哨兵控制台已启动：{url}");
    println!("  配置文件：{}", context.config_path.display());
    println!("  仅监听本机回环地址；按 Ctrl+C 结束。");

    if open_browser {
        if let Err(error) = open_url(&url) {
            eprintln!("无法自动打开浏览器（{error}），请手动访问上面的地址。");
        }
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let context = context.clone();
                std::thread::spawn(move || server::handle_connection(stream, context));
            }
            Err(error) => tracing::debug!(error = %error, "接受连接失败"),
        }
    }
    Ok(())
}

fn bind(preferred: u16) -> Result<TcpListener> {
    if preferred != 0 {
        for offset in 0..10u16 {
            let port = preferred.saturating_add(offset);
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                return Ok(listener);
            }
        }
        eprintln!("端口 {preferred} 已被占用，改用系统分配的随机端口。");
    }
    TcpListener::bind(("127.0.0.1", 0)).context("无法在 127.0.0.1 上启动控制台端口")
}

fn random_token() -> String {
    let mut seed = String::new();
    seed.push_str(&now_ts().to_string());
    seed.push_str(&std::process::id().to_string());
    if let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        seed.push_str(&elapsed.as_nanos().to_string());
    }
    let local = 0u8;
    seed.push_str(&format!("{:p}", &local));
    sha256_hex_str(&seed)
}

pub fn platform_label() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "windows" => format!("Windows · {arch}"),
        "macos" => format!("macOS · {arch}"),
        "linux" => format!(
            "{} · {arch}",
            linux_pretty_name().unwrap_or_else(|| "Linux".into())
        ),
        other => format!("{other} · {arch}"),
    }
}

fn linux_pretty_name() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
            let name = rest.trim().trim_matches('"').to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
pub fn open_url(url: &str) -> Result<()> {
    Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()
        .context("无法调用系统浏览器")?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn open_url(url: &str) -> Result<()> {
    Command::new("open")
        .arg(url)
        .spawn()
        .context("无法调用 open")?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn open_url(url: &str) -> Result<()> {
    if Command::new("xdg-open").arg(url).spawn().is_ok() {
        return Ok(());
    }
    Command::new("gio")
        .args(["open", url])
        .spawn()
        .context("无法调用 xdg-open / gio，请手动在浏览器中打开上面的地址")?;
    Ok(())
}

/// Open the folder that contains `path`.
pub fn reveal(path: &str) -> Result<()> {
    let target = PathBuf::from(path);
    let folder = if target.is_dir() {
        target
    } else {
        target
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    };
    if !folder.exists() {
        anyhow::bail!("路径不存在：{}", folder.display());
    }
    open_path(&folder)
}

#[cfg(target_os = "windows")]
pub fn open_path(path: &PathBuf) -> Result<()> {
    Command::new("explorer")
        .arg(path)
        .spawn()
        .context("无法调用资源管理器")?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn open_path(path: &PathBuf) -> Result<()> {
    Command::new("open")
        .arg(path)
        .spawn()
        .context("无法调用 open")?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn open_path(path: &PathBuf) -> Result<()> {
    if Command::new("xdg-open").arg(path).spawn().is_ok() {
        return Ok(());
    }
    Command::new("gio")
        .arg("open")
        .arg(path)
        .spawn()
        .context("无法打开文件管理器")?;
    Ok(())
}
