//! `sentinel-server`：敏感数据告警汇总服务端。
//!
//! 职责：
//! 1. 接收各终端通过 syslog 上报的告警（UDP/TCP，RFC 5424）。
//! 2. 统一维护并下发检测规则，客户端按版本自动应用。
//! 3. 提供 Web 控制台：按用户/类型/级别/内容筛选查看。

pub mod api;
pub mod auth;
pub mod config;
pub mod http;
pub mod ingest;
pub mod report;
pub mod rules;
pub mod store;
pub mod tls;
pub mod webhook;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::server::auth::Sessions;
use crate::server::config::ServerConfig;
use crate::server::store::ServerStore;

pub struct AuthState {
    pub sessions: Sessions,
    pub session_ttl: std::time::Duration,
    pub agent_token: String,
    pub allow_anonymous_rules: bool,
    password_hash: String,
    throttle: api::LoginThrottle,
}

impl AuthState {
    pub fn new(config: &ServerConfig, password_hash: String, agent_token: String) -> Self {
        Self {
            sessions: Sessions::new(config.session_ttl()),
            session_ttl: config.session_ttl(),
            agent_token,
            allow_anonymous_rules: config.auth.allow_anonymous_rules,
            password_hash,
            throttle: api::LoginThrottle::new(),
        }
    }

    pub fn verify(&self, password: &str) -> bool {
        auth::verify_password(password, &self.password_hash)
    }

    fn record_failure(&self, remote: &str) {
        self.throttle.record_failure(remote);
    }

    fn clear_failures(&self, remote: &str) {
        self.throttle.clear(remote);
    }

    /// 登录前先判断是否已被限流。
    pub fn locked(&self, remote: &str) -> bool {
        self.throttle.is_locked(remote)
    }
}

pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub store: Arc<ServerStore>,
    pub auth: Arc<AuthState>,
    pub ingest_stats: Arc<ingest::IngestStats>,
    pub webhook: Option<Arc<webhook::WebhookDispatcher>>,
    pub started_at: Instant,
    pub stopped: Arc<AtomicBool>,
    pub config_path: PathBuf,
}

/// 启动服务端：加载配置、初始化凭据、拉起监听。
pub fn run(config_path: Option<PathBuf>) -> Result<()> {
    let (mut config, path) = ServerConfig::load(config_path.as_deref())?;
    let (password_hash, password, agent_token, token_generated) =
        ensure_credentials(&mut config, &path)?;

    let store = Arc::new(ServerStore::open(&config.database_path())?);
    let auth = Arc::new(AuthState::new(&config, password_hash, agent_token.clone()));

    println!("数据哨兵服务端已启动");
    println!("  配置文件：{}", path.display());
    println!("  数据库：{}", config.database_path().display());
    let scheme = if config.tls.cert.as_os_str().is_empty() {
        "http"
    } else {
        "https"
    };
    println!("  控制台：{scheme}://{}/", config.server.bind);
    if config.ingest.enabled {
        println!(
            "  syslog 接收：{} ({})",
            config.ingest.bind, config.ingest.protocol
        );
    }

    if let Some(password) = password {
        println!();
        println!("  已生成初始管理口令（仅显示一次，请立即保存）：");
        println!("    {password}");
        println!("  已写入配置 auth.admin_password_hash");
        println!();
    }
    println!("  Agent Token：{agent_token}");
    if token_generated {
        println!("    （已生成并写入配置 auth.agent_token）");
    }
    println!();

    // 保留期清理：启动时清一次，之后每小时一次。
    if config.retention.event_days > 0 {
        let cutoff =
            crate::util::now_ts() - (config.retention.event_days as i64).saturating_mul(86_400);
        match store.purge_old_data(cutoff, RETAIN_RULE_REVISIONS) {
            Ok(report) if report.total() > 0 => {
                tracing::info!(
                    events = report.events,
                    audit = report.audit,
                    rule_sets = report.rule_sets,
                    agents = report.agents,
                    "已按保留期清理过期数据"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "按保留期清理失败"),
        }
    }

    let config = Arc::new(config);

    // 先加载 TLS、绑定控制台端口、再起 syslog 与 mDNS 广播。
    // 顺序很重要：证书有问题或端口被占用时应当直接失败退出，
    // 而不是先在后台拉起接收器与广播，留下一个“半启动”状态。
    let tls = if config.tls.cert.as_os_str().is_empty() {
        None
    } else {
        Some(tls::load(&config.tls.cert, &config.tls.key)?)
    };
    let listener = TcpListener::bind(&config.server.bind)
        .with_context(|| format!("无法监听 {}", config.server.bind))?;
    if tls.is_some() {
        println!(
            "  控制台已启用 HTTPS（证书：{}）",
            config.tls.cert.display()
        );
    }

    let webhook = webhook::WebhookDispatcher::spawn(&config.webhook);
    let stats = if config.ingest.enabled {
        ingest::spawn_with_webhook(&config, Arc::clone(&store), webhook.clone())?
    } else {
        Arc::new(ingest::IngestStats::default())
    };

    // mDNS 广播：让客户端 discovery = "mdns" 直接找到本机。
    // 放在 syslog 接收器启动之后，客户端拿到的地址就一定是可连的。
    let _advertiser = start_advertiser(&config);

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        store,
        auth,
        ingest_stats: stats,
        webhook,
        started_at: Instant::now(),
        stopped: Arc::new(AtomicBool::new(false)),
        config_path: path,
    });

    start_retention_worker(Arc::clone(&state));

    // 优雅退出：Ctrl-C / SIGTERM 时置位 stopped，让保留期线程退出，
    // 并让 mDNS 广播在进程结束前发出 goodbye 包。
    {
        let stopped = Arc::clone(&state.stopped);
        if let Err(error) = ctrlc::set_handler(move || {
            stopped.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("收到退出信号，服务端正在停止");
        }) {
            tracing::warn!(error = %error, "注册退出信号处理器失败");
        }
    }

    // 非阻塞 accept + 短轮询，才能在每个循环里看到 stopped 标志。
    // 直接 `for incoming in listener.incoming()` 会一直阻塞在 accept 上，
    // 装了信号处理器之后 Ctrl-C 会“看起来没反应”。
    if let Err(error) = listener.set_nonblocking(true) {
        tracing::warn!(error = %error, "无法将监听套接字设为非阻塞，退出信号可能延迟生效");
    }

    while !state.stopped.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_nonblocking(false);
                let Some(slot) = CONNECTION_LIMITER.try_acquire() else {
                    // 已建立的控制台连接：回 503 比直接 RST 更友好。
                    crate::server::http::reject_overloaded(stream);
                    continue;
                };
                let state = Arc::clone(&state);
                let tls = tls.clone();
                let spawned = std::thread::Builder::new()
                    .name("sentinel-server-conn".into())
                    .spawn(move || {
                        let _slot = slot;
                        match tls {
                            Some(tls) => http::handle_tls_connection(stream, state, tls),
                            None => http::handle_connection(stream, state),
                        }
                    });
                if let Err(error) = spawned {
                    tracing::warn!(error = %error, "无法创建控制台连接线程");
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => {
                tracing::debug!(error = %error, "接受连接失败");
                crate::util::backoff_after_accept_error(&error);
            }
        }
    }
    tracing::info!("服务端已停止");
    Ok(())
}

/// 保留的规则版本数量：足够覆盖回滚窗口，又不会让 `rule_sets` 无限增长。
const RETAIN_RULE_REVISIONS: usize = 50;

/// 控制台并发连接上限：每连接一个线程，不设上限会被连接风暴打穿。
static CONNECTION_LIMITER: crate::util::ConnectionLimiter =
    crate::util::ConnectionLimiter::new(256);

/// 按配置注册 mDNS 广播，失败只告警——发现是便利功能，不能阻断服务启动。
fn start_advertiser(config: &ServerConfig) -> Option<crate::mdns::Advertiser> {
    if !config.discover.enabled {
        tracing::info!("discover.enabled = false，客户端需手动填写服务端地址");
        return None;
    }
    if !config.ingest.enabled {
        // 广播的核心是 syslog 接收地址；没开接收就没有可广播的端口，
        // 播出去只会让客户端连到一个空端口。
        tracing::info!("ingest.enabled = false，跳过 mDNS 广播");
        return None;
    }
    let instance = if config.discover.instance.trim().is_empty() {
        crate::mdns::default_instance_name()
    } else {
        config.discover.instance.trim().to_string()
    };

    // 广播 syslog 监听地址，并附带控制台端口，便于 `syslog discover` 一并展示。
    let console_port = config
        .server
        .bind
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());
    let mut extra = std::collections::HashMap::new();
    if let Some(port) = console_port {
        extra.insert("console".to_string(), port.to_string());
        if !config.tls.cert.as_os_str().is_empty() {
            extra.insert("console_tls".to_string(), "1".to_string());
        }
    }

    match crate::mdns::Advertiser::start_with(
        &config.discover.service,
        &instance,
        &config.ingest.bind,
        &config.ingest.protocol,
        &extra,
    ) {
        Ok(advertiser) => {
            println!(
                "  mDNS 广播：{}（客户端 discovery = \"mdns\" 即可自动发现）",
                advertiser.fullname()
            );
            Some(advertiser)
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "mDNS 广播失败，客户端需手动配置地址");
            println!("  mDNS 广播失败（不影响服务端运行）：{error:#}");
            None
        }
    }
}

/// 确定三种凭据：管理口令哈希、明文口令（仅首次）、Agent Token。
fn ensure_credentials(
    config: &mut ServerConfig,
    path: &std::path::Path,
) -> Result<(String, Option<String>, String, bool)> {
    let mut dirty = false;

    // 管理口令：已配置则沿用；否则生成随机口令并写回配置。
    let (password_hash, plain) = if config.auth.admin_password_hash.trim().is_empty() {
        let password = auth::generate_passphrase();
        let hash = auth::hash_password(&password);
        config.auth.admin_password_hash = hash.clone();
        dirty = true;
        (hash, Some(password))
    } else {
        (config.auth.admin_password_hash.trim().to_string(), None)
    };

    // Agent Token：已配置则沿用；否则生成。
    let (agent_token, token_generated) = if config.auth.agent_token.trim().is_empty() {
        let token = auth::random_token();
        config.auth.agent_token = token.clone();
        dirty = true;
        (token, true)
    } else {
        (config.auth.agent_token.trim().to_string(), false)
    };

    if dirty {
        write_back_credentials(
            path,
            &config.auth.admin_password_hash,
            &config.auth.agent_token,
        )?;
    }
    Ok((password_hash, plain, agent_token, token_generated))
}

/// 只改写凭据两行，保留用户写在配置里的注释。
fn write_back_credentials(path: &std::path::Path, hash: &str, token: &str) -> Result<()> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut updated = crate::webui::tomlpatch_set_key(&text, "auth", "admin_password_hash", hash);
    updated = crate::webui::tomlpatch_set_key(&updated, "auth", "agent_token", token);
    std::fs::write(path, updated).with_context(|| format!("无法回写凭据到 {}", path.display()))?;
    let _ = crate::config::secure_file(path);
    Ok(())
}

fn start_retention_worker(state: Arc<AppState>) {
    std::thread::Builder::new()
        .name("sentinel-retention".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            if state.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if state.config.retention.event_days == 0 {
                continue;
            }
            let cutoff = crate::util::now_ts()
                - (state.config.retention.event_days as i64).saturating_mul(86_400);
            match state.store.purge_old_data(cutoff, RETAIN_RULE_REVISIONS) {
                Ok(report) if report.total() > 0 => {
                    tracing::info!(
                        events = report.events,
                        audit = report.audit,
                        rule_sets = report.rule_sets,
                        agents = report.agents,
                        "已按保留期清理过期数据"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(error = %error, "按保留期清理失败"),
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_missing_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        std::fs::write(&path, crate::server::config::DEFAULT_SERVER_CONFIG).unwrap();

        let mut config = ServerConfig::load(Some(&path)).unwrap().0;
        let (hash, plain, token, generated) = ensure_credentials(&mut config, &path).unwrap();
        assert!(plain.is_some(), "首次应返回明文口令供打印");
        assert!(generated);
        assert!(!token.is_empty());
        assert!(auth::verify_password(plain.as_ref().unwrap(), &hash));

        // 回写后再次加载：不应再生成新口令
        let reloaded = ServerConfig::load(Some(&path)).unwrap().0;
        assert_eq!(reloaded.auth.admin_password_hash, hash);
        assert_eq!(reloaded.auth.agent_token, token);
        let (_, plain_again, _, generated_again) =
            ensure_credentials(&mut reloaded.clone(), &path).unwrap();
        assert!(plain_again.is_none());
        assert!(!generated_again);
    }

    #[test]
    fn rewrite_preserves_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");
        std::fs::write(&path, crate::server::config::DEFAULT_SERVER_CONFIG).unwrap();
        write_back_credentials(&path, "pbkdf2$1$aa$bb", "token-abc").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# Agent 上报与拉取规则使用的共享 Token。"));
        assert!(text.contains("agent_token = \"token-abc\""));
    }
}
