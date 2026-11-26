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
pub mod rules;
pub mod store;

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
    println!("  控制台：http://{}/", config.server.bind);
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
        if let Ok(removed) = store.purge_events_before(cutoff) {
            if removed > 0 {
                tracing::info!(removed, "已按保留期清理过期告警");
            }
        }
    }

    let config = Arc::new(config);
    let stats = if config.ingest.enabled {
        ingest::spawn(&config, Arc::clone(&store))?
    } else {
        Arc::new(ingest::IngestStats::default())
    };

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        store,
        auth,
        ingest_stats: stats,
        started_at: Instant::now(),
        stopped: Arc::new(AtomicBool::new(false)),
        config_path: path,
    });

    start_retention_worker(Arc::clone(&state));

    let listener = TcpListener::bind(&config.server.bind)
        .with_context(|| format!("无法监听 {}", config.server.bind))?;
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || http::handle_connection(stream, state));
            }
            Err(error) => tracing::debug!(error = %error, "接受连接失败"),
        }
    }
    Ok(())
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
            if let Ok(removed) = state.store.purge_events_before(cutoff) {
                if removed > 0 {
                    tracing::info!(removed, "已清理过期告警");
                }
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
