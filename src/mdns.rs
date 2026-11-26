//! 通过 mDNS / DNS-SD 自动发现局域网内的 syslog 服务端。
//!
//! 目标：客户端**不再需要手工填写服务端 IP**——服务端在启动时用同一个 mDNS
//! 服务类型（默认 `_datasentinel._udp.local.`）把自己广播出去，客户端 browses
//! 到实例后，从 SRV 记录拿端口、从 A/AAAA 记录拿 IP，直接拼出 `ip:port`。
//!
//! 设计要点：
//! - **一次解析、缓存结果**：`resolve()` 是阻塞调用（带超时），只在需要时执行；
//!   结果由 [`Resolver`] 缓存，扫描热路径不会反复 browse。
//! - **失败可回落**：发现失败只记日志，调用方继续用静态 `server`。
//! - **TXT 可覆盖协议**：服务端可以在 TXT 里声明 `protocol=tcp`，客户端按服务端
//!   实际监听的协议发送，避免“发现到了却用错协议”。
//! - **无外部依赖**：只用 `mdns-sd`，无需 Avahi/Bonjour 守护进程（Windows 上这点
//!   尤其重要，企业环境通常没有装 Bonjour）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// 发现到的服务端。
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredServer {
    /// `ip:port`，可直接用于 syslog 发送。
    pub endpoint: String,
    /// 服务端在 TXT 中声明的协议；为空表示沿用本地配置。
    pub protocol: Option<String>,
    /// 实例名，便于日志排查。
    pub instance: String,
    /// 解析到的所有地址，IPv4 优先。
    pub addresses: Vec<IpAddr>,
    /// 控制台地址（服务端在 TXT 里声明 `console=<端口>` 时才有），
    /// 例如 `https://10.0.0.5:8443`。仅用于提示运维人员，客户端不依赖它。
    pub console: Option<String>,
}

impl DiscoveredServer {
    /// 给用户看的地址（不含实例名）。
    pub fn display(&self) -> String {
        self.endpoint.clone()
    }
}

/// 带缓存的发现器：同一进程内复用结果，避免每次扫描都发 mDNS 查询。
pub struct Resolver {
    service: String,
    timeout: Duration,
    cached: Mutex<Option<(Instant, Option<DiscoveredServer>)>>,
    /// 缓存有效期：服务端下线/换 IP 后最多这么久会发现不到旧值。
    ttl: Duration,
}

impl Resolver {
    pub fn new(service: &str, timeout: Duration) -> Self {
        Self {
            service: normalize_service(service),
            timeout,
            cached: Mutex::new(None),
            ttl: Duration::from_secs(30),
        }
    }

    /// 解析服务端；使用缓存，命中时不产生网络流量。
    pub fn resolve(&self) -> Option<DiscoveredServer> {
        if let Ok(cache) = self.cached.lock() {
            if let Some((at, value)) = cache.as_ref() {
                if at.elapsed() < self.ttl {
                    return value.clone();
                }
            }
        }
        let resolved = discover(&self.service, self.timeout).ok().flatten();
        if let Ok(mut cache) = self.cached.lock() {
            *cache = Some((Instant::now(), resolved.clone()));
        }
        if let Some(server) = &resolved {
            tracing::info!(
                instance = %server.instance,
                endpoint = %server.endpoint,
                "mDNS 发现 syslog 服务端"
            );
        } else {
            tracing::debug!(service = %self.service, "mDNS 未发现 syslog 服务端");
        }
        resolved
    }

    /// 丢弃缓存，强制下一次重新查询。
    pub fn invalidate(&self) {
        if let Ok(mut cache) = self.cached.lock() {
            *cache = None;
        }
    }
}

/// 阻塞式发现：启动一个短生命周期的 daemon，browse 到第一个实例后即返回。
///
/// 每次调用都新建 daemon 是刻意的：syslog 外发频率低，复用常驻 daemon 会长期
/// 占用 5353 端口，反而和企业里已有的 Avahi/Bonjour 抢端口。
pub fn discover(service: &str, timeout: Duration) -> Result<Option<DiscoveredServer>> {
    let service = normalize_service(service);
    let deadline = Instant::now() + timeout;

    let daemon = ServiceDaemon::new().context("无法启动 mDNS 客户端")?;
    let guard = DaemonGuard(daemon.clone());
    let receiver = daemon
        .browse(&service)
        .with_context(|| format!("mDNS browse {service} 失败"))?;

    let mut best: Option<DiscoveredServer> = None;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let wait = remaining.min(Duration::from_millis(250));
        match receiver.recv_timeout(wait) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(server) = from_service_info(&info) {
                    // IPv4 优先；若已有 IPv4 结果就不再等 IPv6。
                    let has_v4 = server.addresses.iter().any(IpAddr::is_ipv4);
                    best = Some(server);
                    if has_v4 {
                        break;
                    }
                }
            }
            Ok(_) => {}
            // 通道关闭/超时：结束等待。
            Err(_) => {}
        }
    }
    drop(guard);
    Ok(best)
}

/// 服务端侧：把自己注册到 mDNS。
///
/// 返回的 guard 析构时会优雅注销（发 goodbye 包），避免客户端读到陈旧记录。
pub struct Advertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertiser {
    /// `bind` 为监听地址（`0.0.0.0:5514`），port 从其中解析。
    ///
    /// 广播的地址会自动取本机所有非回环 IPv4/IPv6；`0.0.0.0` 会被展开成真实地址，
    /// 否则客户端拿到 `0.0.0.0` 无法连接。
    pub fn start(service: &str, instance: &str, bind: &str, protocol: &str) -> Result<Self> {
        Self::start_with(service, instance, bind, protocol, &HashMap::new())
    }

    /// 同 [`start`](Self::start)，但可以附加自定义 TXT 键值。
    ///
    /// `sentinel-server` 用它额外广播 `console=<端口>` / `console_tls=1`，
    /// 这样运维在 `sentinel syslog discover` 里就能直接看到控制台地址。
    pub fn start_with(
        service: &str,
        instance: &str,
        bind: &str,
        protocol: &str,
        extra: &HashMap<String, String>,
    ) -> Result<Self> {
        let service = normalize_service(service);
        let port = bind
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .with_context(|| format!("无法从监听地址解析端口：{bind}"))?;
        let host = local_hostname();
        let host_name = format!("{host}.local.");

        let daemon = ServiceDaemon::new().context("无法启动 mDNS 服务端")?;
        let mut props = HashMap::from([
            ("protocol".to_string(), protocol.to_string()),
            ("ver".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("app".to_string(), "DataSentinel".to_string()),
        ]);
        // 调用方的键覆盖内置键，避免顺序依赖。
        for (key, value) in extra {
            if !key.trim().is_empty() {
                props.insert(key.trim().to_string(), value.clone());
            }
        }
        let properties = props;
        let mut info = ServiceInfo::new(
            &service, instance, &host_name,
            // 空地址 + addr_auto：由库在注册时填入本机所有可用地址。
            "", port, properties,
        )
        .with_context(|| format!("构造 mDNS 服务信息失败（service={service}）"))?
        .enable_addr_auto();
        // 实例名已带主机名，重名风险低；关闭探测可以更快上线。
        info.set_requires_probe(false);

        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .with_context(|| format!("注册 mDNS 服务 {fullname} 失败"))?;
        Ok(Self { daemon, fullname })
    }

    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        // 尽力发 goodbye；失败无所谓，TTL 到期后记录自然消失。
        if let Ok(receiver) = self.daemon.unregister(&self.fullname) {
            let _ = receiver.recv_timeout(Duration::from_millis(300));
        }
        let _ = self.daemon.shutdown();
    }
}

struct DaemonGuard(ServiceDaemon);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

fn from_service_info(info: &mdns_sd::ResolvedService) -> Option<DiscoveredServer> {
    let port = info.get_port();
    let mut candidates: Vec<IpAddr> = Vec::new();
    for addr in info.get_addresses_v4() {
        candidates.push(IpAddr::V4(addr));
    }
    for scoped in info.get_addresses() {
        if scoped.is_ipv6() {
            candidates.push(scoped.to_ip_addr());
        }
    }
    candidates.retain(|addr| !addr.is_unspecified());
    candidates.sort_by_key(|addr| address_rank(*addr));
    candidates.dedup();
    // 优先取跨机可用地址；若整张网卡只有链路本地/回环（例如纯离线实验室），
    // 再退回任意可用地址，避免“发现到了却报没有地址”。
    let chosen = candidates
        .iter()
        .copied()
        .find(is_usable_address)
        .or_else(|| candidates.first().copied())?;
    let endpoint = match chosen {
        IpAddr::V4(addr) => format!("{addr}:{port}"),
        IpAddr::V6(addr) => format!("[{addr}]:{port}"),
    };
    let protocol = info
        .get_property_val_str("protocol")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| matches!(value.as_str(), "udp" | "tcp"));
    // 控制台端口由服务端在 TXT 中声明；缺省表示该实例不提供控制台。
    let console = info
        .get_property_val_str("console")
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .map(|port| {
            let tls = info
                .get_property_val_str("console_tls")
                .map(|value| value.trim() == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let scheme = if tls { "https" } else { "http" };
            match chosen {
                IpAddr::V4(addr) => format!("{scheme}://{addr}:{port}/"),
                IpAddr::V6(addr) => format!("{scheme}://[{addr}]:{port}/"),
            }
        });
    Some(DiscoveredServer {
        endpoint,
        protocol,
        instance: info.get_fullname().to_string(),
        addresses: candidates,
        console,
    })
}

/// 跨机器可用的地址：排除回环、IPv6 链路本地（需 scope id，客户端无法直接
/// connect）、以及 IPv4 自动私有地址（169.254/16，通常是没拿到 DHCP 的兜底）。
fn is_usable_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() && !v6.is_unicast_link_local(),
    }
}

/// 排序权重：局域网 IPv4 最优先，其次其他 IPv4，再到 IPv6。
fn address_rank(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let private = octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168);
            if private {
                0
            } else {
                1
            }
        }
        IpAddr::V6(_) => 2,
    }
}

/// 统一成 `_name._udp.local.` / `_name._tcp.local.` 形式。
fn normalize_service(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return crate::config::DEFAULT_MDNS_SERVICE.to_string();
    }
    format!("{trimmed}.")
}

/// 本机主机名（不含域名后缀）。
///
/// 平台差异：
/// - Windows 只有 `COMPUTERNAME`；
/// - Linux/macOS 的 `HOSTNAME` 常常没导出到服务进程环境里，因此回落到
///   `/etc/hostname` 与 `hostname` 命令；
/// - 结果必须是合法 DNS 标签，否则 mDNS 会拒绝广播。
pub(crate) fn local_hostname() -> String {
    #[cfg(windows)]
    let candidates = { vec![std::env::var("COMPUTERNAME").ok()] };
    #[cfg(not(windows))]
    let candidates = {
        vec![
            std::env::var("HOSTNAME").ok(),
            std::fs::read_to_string("/etc/hostname").ok(),
            command_hostname(),
        ]
    };

    let raw = candidates
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string());
    sanitize_dns_label(&raw)
}

#[cfg(not(windows))]
fn command_hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 把主机名收敛成合法 DNS 标签：去掉域名后缀、替换非法字符。
fn sanitize_dns_label(value: &str) -> String {
    let label = value
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let trimmed = label.trim_matches('-');
    if trimmed.is_empty() {
        "localhost".to_string()
    } else {
        trimmed.to_string()
    }
}

/// 生成一个稳定且可读的实例名，便于在同一网段多台服务端时区分。
pub fn default_instance_name() -> String {
    format!("DataSentinel-{}", local_hostname())
}

/// 进程级单例：扫描路径上只能有一个缓存，否则每个 Scanner 都会各自发查询。
static GLOBAL: OnceLock<Resolver> = OnceLock::new();

/// 取得全局 Resolver；首次调用时按配置初始化。
pub fn global_resolver(service: &str, timeout: Duration) -> &'static Resolver {
    GLOBAL.get_or_init(|| Resolver::new(service, timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_service_names() {
        assert_eq!(normalize_service("_ds._udp"), "_ds._udp.");
        assert_eq!(normalize_service("_ds._udp."), "_ds._udp.");
        assert_eq!(normalize_service("  "), crate::config::DEFAULT_MDNS_SERVICE);
    }

    #[test]
    fn rejects_bad_service_names() {
        // 服务名超过 15 字节会被 Avahi/Bonjour 拒绝
        assert!(!crate::config::is_valid_mdns_service(
            "_a-very-long-service-name._udp.local."
        ));
        assert!(crate::config::is_valid_mdns_service(
            "_datasentinel._udp.local."
        ));
        assert!(!crate::config::is_valid_mdns_service("_ds._sctp.local."));
    }

    #[test]
    fn instance_name_is_stable() {
        let name = default_instance_name();
        assert!(name.starts_with("DataSentinel-"));
        assert_eq!(name, default_instance_name());
    }

    #[test]
    fn hostname_is_a_valid_dns_label() {
        let host = local_hostname();
        assert!(!host.is_empty());
        // DNS 标签：仅字母数字与连字符，且不以连字符开头/结尾
        assert!(
            host.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
            "非法字符: {host}"
        );
        assert!(!host.starts_with('-') && !host.ends_with('-'), "{host}");
        // 不能带域名后缀，否则 mDNS 的 host_name 会变成 a.b.local.
        assert!(!host.contains('.'), "{host}");
    }

    #[test]
    fn sanitizes_weird_hostnames() {
        assert_eq!(sanitize_dns_label("My-PC.local"), "My-PC");
        assert_eq!(sanitize_dns_label("desktop_01"), "desktop-01");
        // 纯非 ASCII 主机名会被替换成连字符，最终回落为 localhost
        assert_eq!(sanitize_dns_label("张三的电脑"), "localhost");
        assert_eq!(sanitize_dns_label("-边缘-"), "localhost");
        assert_eq!(sanitize_dns_label("  "), "localhost");
    }

    #[test]
    fn resolver_caches_misses_too() {
        // 不存在的服务：第一次查询会超时，第二次应直接命中缓存（很快返回）。
        let resolver = Resolver::new("_nonexistent-ds._udp.local.", Duration::from_millis(400));
        let start = Instant::now();
        assert!(resolver.resolve().is_none());
        let first = start.elapsed();
        let start = Instant::now();
        assert!(resolver.resolve().is_none());
        let second = start.elapsed();
        assert!(second < first, "第二次应命中缓存: {second:?} vs {first:?}");
    }
}
