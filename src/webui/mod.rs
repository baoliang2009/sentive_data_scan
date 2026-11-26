//! Local web console for DataSentinel.
//!
//! `sentinel ui` binds a single-user HTTP server on the loopback interface and
//! opens the system default browser. Keeping the UI in the browser means the
//! console works identically on Windows, Kylin/Linux and macOS without shipping
//! a WebView runtime, and the whole product stays a single executable.

pub mod api;
pub mod server;
// tomlpatch 已提升到 crate 根（服务端也用它改写配置）
pub use crate::tomlpatch;

/// 兼容旧调用：`crate::webui::tomlpatch_set_key`。
pub fn tomlpatch_set_key(text: &str, section: &str, key: &str, value: &str) -> String {
    crate::tomlpatch::set_key(text, section, key, &crate::tomlpatch::toml_quote(value))
}

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::config::Config;
use crate::scan::ScanProgress;
use crate::util::{now_ts, sha256_hex_str, ConnectionLimiter};

pub const DEFAULT_PORT: u16 = 7419;

/// 本地控制台同时处理的连接数上限。
///
/// 单用户控制台不需要高并发；但每连接一线程且没有上限时，浏览器里一个死循环
/// 的脚本（或本机的恶意进程）就能把线程栈/FD 打满。超限直接回 503。
static CONNECTION_LIMITER: ConnectionLimiter = ConnectionLimiter::new(64);

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
    /// Whether this process is running the filesystem watcher. The config only
    /// says it is allowed to; the console must not claim "监控中" otherwise.
    watch_active: bool,
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

pub fn run(
    config_path: Option<PathBuf>,
    port: u16,
    open_browser: bool,
    watch_active: bool,
) -> Result<()> {
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
        watch_active,
    });

    let url = format!("http://127.0.0.1:{}/", address.port());
    println!("数据哨兵控制台已启动：{url}");
    println!("  配置文件：{}", context.config_path.display());
    if watch_active {
        println!("  落盘监控：已启用（文件落到扫描目录会立即检测并提醒）");
    } else {
        println!("  落盘监控：未启用（只能手动扫描，或运行 sentinel daemon）");
    }
    println!("  仅监听本机回环地址；按 Ctrl+C 结束。");

    if open_browser {
        if let Err(error) = open_url(&url) {
            eprintln!("无法自动打开浏览器（{error}），请手动访问上面的地址。");
        }
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let Some(slot) = CONNECTION_LIMITER.try_acquire() else {
                    crate::server::http::reject_overloaded(stream);
                    continue;
                };
                let context = context.clone();
                let spawned = std::thread::Builder::new()
                    .name("sentinel-ui-conn".into())
                    .spawn(move || {
                        let _slot = slot;
                        server::handle_connection(stream, context);
                    });
                if let Err(error) = spawned {
                    tracing::warn!(error = %error, "无法创建控制台连接线程");
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
            Err(error) => {
                tracing::debug!(error = %error, "接受连接失败");
                crate::util::backoff_after_accept_error(&error);
            }
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
    spawn_and_reap(Command::new("cmd").args(["/C", "start", "", url])).context("无法调用系统浏览器")
}

#[cfg(target_os = "macos")]
pub fn open_url(url: &str) -> Result<()> {
    spawn_and_reap(Command::new("open").arg(url)).context("无法调用 open")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn open_url(url: &str) -> Result<()> {
    if spawn_and_reap(Command::new("xdg-open").arg(url)).is_ok() {
        return Ok(());
    }
    spawn_and_reap(Command::new("gio").args(["open", url]))
        .context("无法调用 xdg-open / gio，请手动在浏览器中打开上面的地址")
}

/// 启动一个辅助进程并在后台回收。
///
/// 只用 `spawn()` 而丢弃 `Child` 不会回收子进程：`open` / `xdg-open` /
/// `explorer` 很快退出，于是一次点击就留下一个僵尸，直到本进程退出为止。
fn spawn_and_reap(command: &mut Command) -> Result<()> {
    let mut child = command.spawn().context("无法启动辅助进程")?;
    std::thread::Builder::new()
        .name("sentinel-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        })
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("{error}"))
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
    spawn_and_reap(Command::new("explorer").arg(path)).context("无法调用资源管理器")
}

#[cfg(target_os = "macos")]
pub fn open_path(path: &PathBuf) -> Result<()> {
    spawn_and_reap(Command::new("open").arg(path)).context("无法调用 open")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn open_path(path: &PathBuf) -> Result<()> {
    if spawn_and_reap(Command::new("xdg-open").arg(path)).is_ok() {
        return Ok(());
    }
    spawn_and_reap(Command::new("gio").arg("open").arg(path)).context("无法打开文件管理器")
}
