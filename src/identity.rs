//! 终端身份：`agent_id`、用户名、主机名、平台与版本。
//!
//! 服务端控制台的「终端 / 按用户」两页都依赖这些字段：
//! - `agent_id` 必须**跨重启稳定**，否则每次启动都会在服务端留下一条新终端；
//! - `username` 让「按用户」维度有意义，而不是全部回落到主机名。
//!
//! 因此 `agent_id` 首次生成后写进本地库的 `meta` 表，之后一直复用。

use anyhow::Result;

use crate::config::Config;
use crate::store::Store;

/// `meta` 表里保存 `agent_id` 的键名。
const AGENT_ID_KEY: &str = "agent_id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub version: String,
}

impl Identity {
    /// 读取（必要时生成）本机身份。
    pub fn load_or_create(store: &Store, config: &Config) -> Result<Self> {
        let agent_id = match store.get_meta(AGENT_ID_KEY)? {
            Some(existing) if !existing.trim().is_empty() => existing.trim().to_string(),
            _ => {
                let generated = generate_agent_id();
                store.set_meta(AGENT_ID_KEY, &generated)?;
                generated
            }
        };
        let hostname = if config.syslog.hostname.trim().is_empty() {
            crate::mdns::local_hostname()
        } else {
            config.syslog.hostname.trim().to_string()
        };
        Ok(Self {
            agent_id,
            hostname,
            username: current_username(),
            platform: platform_name(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    /// 仅按当前环境推断（不落库），用于 `sentinel syslog test` 这类一次性命令。
    pub fn ephemeral(config: &Config) -> Self {
        let hostname = if config.syslog.hostname.trim().is_empty() {
            crate::mdns::local_hostname()
        } else {
            config.syslog.hostname.trim().to_string()
        };
        Self {
            agent_id: String::new(),
            hostname,
            username: current_username(),
            platform: platform_name(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// 完全不依赖配置的临时身份（用于只发一条测试报文、不需要归属的场景）。
    pub fn ephemeral_default() -> Self {
        Self {
            agent_id: String::new(),
            hostname: crate::mdns::local_hostname(),
            username: current_username(),
            platform: platform_name(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// 生成 32 字节随机 ID（hex）。
///
/// 客户端不引入 `uuid` 依赖：这里只需要「不可预测且不重复」，用系统熵源
/// （Unix 上 `/dev/urandom`）加时间与进程信息混合即可；生成一次后长期复用，
/// 不参与任何安全判定。
fn generate_agent_id() -> String {
    let mut seed = Vec::new();
    if let Ok(bytes) = read_random(32) {
        seed.extend_from_slice(&bytes);
    }
    seed.extend_from_slice(std::process::id().to_string().as_bytes());
    seed.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos().to_be_bytes())
            .unwrap_or_default(),
    );
    let local = 0u8;
    seed.extend_from_slice(&(&local as *const u8 as usize).to_be_bytes());
    crate::util::sha256_hex(&seed)
}

fn read_random(len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buffer = vec![0u8; len];
    // 只读需要的字节：`fs::read` 会一直读到 EOF，而 /dev/urandom 永不 EOF。
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// 当前登录用户名。
///
/// 优先环境变量（SSH/终端里最准），其次 `whoami`；GUI 进程启动时环境可能
/// 很干净，所以命令行兜底是必要的。都拿不到时返回空串，服务端会回落到主机名。
pub fn current_username() -> String {
    #[cfg(windows)]
    const ENV_KEYS: &[&str] = &["USERNAME", "USER"];
    #[cfg(not(windows))]
    const ENV_KEYS: &[&str] = &["USER", "LOGNAME"];

    for key in ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    whoami().unwrap_or_default()
}

#[cfg(unix)]
fn whoami() -> Option<String> {
    let output = std::process::Command::new("whoami").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(windows)]
fn whoami() -> Option<String> {
    // Windows 的 `whoami` 输出形如 `domain\user`，只保留用户名部分。
    let output = std::process::Command::new("whoami").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let name = raw.rsplit('\\').next().unwrap_or(&raw).to_string();
    (!name.is_empty()).then_some(name)
}

/// 平台标识，例如 `macos-aarch64` / `windows-x86_64` / `linux-x86_64`。
pub fn platform_name() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_is_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("sentinel.db")).unwrap();
        let config = Config::default();

        let first = Identity::load_or_create(&store, &config).unwrap();
        assert_eq!(first.agent_id.len(), 64, "agent_id 应为 32 字节 hex");
        assert!(!first.agent_id.is_empty());

        // 第二次（模拟重启）必须复用同一个 ID，否则服务端会不断产生新终端。
        let second = Identity::load_or_create(&store, &config).unwrap();
        assert_eq!(first.agent_id, second.agent_id);
    }

    #[test]
    fn platform_name_is_not_empty() {
        let platform = platform_name();
        assert!(platform.contains('-'), "{platform}");
        assert!(platform.contains(std::env::consts::OS), "{platform}");
    }

    #[test]
    fn username_falls_back_without_panicking() {
        // 不保证一定有用户名，但必须能返回字符串而不是 panic。
        let name = current_username();
        assert!(!name.contains('\n'), "{name}");
    }
}
