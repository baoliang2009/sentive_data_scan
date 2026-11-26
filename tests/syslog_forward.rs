use std::net::UdpSocket;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use data_sentinel::config::{Config, SyslogConfig};
use data_sentinel::model::Severity;
use data_sentinel::rules::RuleSet;
use data_sentinel::scan::Scanner;
use data_sentinel::store::Store;

/// 端到端：扫描落盘 → 命中 → 通过 UDP syslog 外发，且外发内容是脱敏值。
#[test]
fn scan_forwards_masked_findings_over_syslog() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let docs = dir.path().join("docs");
    std::fs::create_dir_all(&docs)?;
    std::fs::write(
        docs.join("secret.txt"),
        "身份证 320102198001010016\n手机 19912345678\n订单 202311241530451234\n",
    )?;

    // 先占一个本地 UDP 端口当“服务端”。
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server_addr = server.local_addr()?.to_string();

    let mut config = Config::default();
    config.scan.roots = vec![docs.clone()];
    config.scan.threads = 1;
    config.scan.full_scan_interval_hours = 0;
    config.scan.use_default_excludes = false;
    config.scan.exclude_globs.clear();
    config.scan.exclude_extensions.clear();
    config.storage.database = dir.path().join("sentinel.db");
    config.notify.enabled = false;
    config.syslog = SyslogConfig {
        enabled: true,
        protocol: "udp".to_string(),
        server: server_addr,
        min_severity: Severity::Medium,
        ..SyslogConfig::default()
    };

    let store = Arc::new(Store::open(&config.storage.database)?);
    let rules = RuleSet::build(&config.rules)?;
    let scanner = Scanner::new(Arc::new(config.clone()), store, rules)?;
    let summary = scanner.scan_roots(std::slice::from_ref(&docs), false);
    assert_eq!(summary.findings, 2, "只应有身份证与手机命中");
    scanner.flush_syslog();

    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    while received.len() < 2 {
        match server.recv_from(&mut buffer) {
            Ok((len, _)) => received.push(String::from_utf8_lossy(&buffer[..len]).into_owned()),
            Err(error) => panic!("没有收到 syslog 报文: {error}"),
        }
    }

    let joined = received.join("\n");
    // RFC 5424 头 + structured-data
    assert!(joined.contains("DataSentinel"), "{joined}");
    assert!(joined.contains("event=\"cn_id_card\""), "{joined}");
    assert!(joined.contains("event=\"cn_mobile\""), "{joined}");
    // 默认只发脱敏值：原文绝不能出现在报文里
    assert!(!joined.contains("320102198001010016"), "{joined}");
    assert!(!joined.contains("19912345678"), "{joined}");
    assert!(joined.contains("320102********0016"), "{joined}");
    // 噪声数字不应产生任何报文
    assert!(!joined.contains("202311241530451234"), "{joined}");
    Ok(())
}

/// 第二次扫描没有任何新增命中时，不应重复外发。
#[test]
fn rescan_does_not_forward_again() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let docs = dir.path().join("docs");
    std::fs::create_dir_all(&docs)?;
    std::fs::write(docs.join("a.txt"), "身份证 320102198001010016\n")?;

    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_millis(700)))?;
    let server_addr = server.local_addr()?.to_string();

    let mut config = Config::default();
    config.scan.roots = vec![docs.clone()];
    config.scan.threads = 1;
    config.scan.full_scan_interval_hours = 0;
    config.scan.use_default_excludes = false;
    config.scan.exclude_globs.clear();
    config.scan.exclude_extensions.clear();
    config.storage.database = dir.path().join("sentinel.db");
    config.notify.enabled = false;
    config.syslog = SyslogConfig {
        enabled: true,
        protocol: "udp".to_string(),
        server: server_addr,
        ..SyslogConfig::default()
    };

    let store = Arc::new(Store::open(&config.storage.database)?);
    let rules = RuleSet::build(&config.rules)?;
    let scanner = Scanner::new(Arc::new(config), store, rules)?;

    scanner.scan_roots(std::slice::from_ref(&docs), false);
    scanner.flush_syslog();
    let mut buffer = [0u8; 8192];
    assert!(server.recv_from(&mut buffer).is_ok(), "第一次应外发");

    // 再跑一次，文件未变化 → 走台账，不会有新命中。
    let second = scanner.scan_roots(std::slice::from_ref(&docs), false);
    assert_eq!(second.new_findings, 0);
    scanner.flush_syslog();
    assert!(
        server.recv_from(&mut buffer).is_err(),
        "未变化文件不应重复外发"
    );
    Ok(())
}

/// TCP 模式下报文以换行分隔，便于 rsyslog / 接收脚本按行解析。
#[test]
fn syslog_server_accepts_tcp_lines() -> anyhow::Result<()> {
    use std::io::{BufRead, BufReader};

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?.to_string();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read line");
        line
    });

    let sender = data_sentinel::syslog::SyslogSender::from_config(&SyslogConfig {
        enabled: true,
        protocol: "tcp".to_string(),
        server: address,
        ..SyslogConfig::default()
    })
    .expect("sender");
    sender.send_test()?;

    let line = handle.join().expect("join");
    assert!(line.starts_with('<'), "{line}");
    assert!(line.contains("event=\"test\""), "{line}");
    Ok(())
}

#[test]
fn invalid_syslog_config_is_rejected() {
    let mut config = Config::default();
    config.syslog.enabled = true;
    config.syslog.server = String::new();
    assert!(config.validate().is_err());

    config.syslog.server = "10.0.0.5".to_string();
    assert!(config.validate().is_err(), "缺少端口应被拒绝");

    config.syslog.server = "10.0.0.5:514".to_string();
    assert!(config.validate().is_ok());

    config.syslog.protocol = "carrier-pigeon".to_string();
    assert!(config.validate().is_err());
}

/// 外发关闭时不产生任何网络流量。
#[test]
fn disabled_syslog_never_sends() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let address = socket.local_addr()?.to_string();

    let sender = data_sentinel::syslog::SyslogSender::from_config(&SyslogConfig {
        enabled: false,
        server: address,
        ..SyslogConfig::default()
    });
    assert!(sender.is_none(), "关闭时不应创建发送端");

    // 也验证一下配置里 write default 是关闭的
    assert!(!Config::default().syslog.enabled);
    let _ = Path::new(".");
    Ok(())
}

/// mDNS 模式：未配置任何 IP 时，仍能通过自动发现发送成功。
///
/// 用同一个进程内的 Advertiser（服务端）+ Sender（客户端）验证；
/// 若运行环境不允许 mDNS（例如 macOS 上 5353 被占用），测试会跳过而不是失败。
#[test]
fn mdns_mode_sends_without_static_address() -> anyhow::Result<()> {
    use data_sentinel::config::MDNS_TEST_SERVICE;

    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(8)))?;
    let port = server.local_addr()?.port();

    let instance = format!("ds-test-{}", std::process::id());
    let advertiser = match data_sentinel::mdns::Advertiser::start(
        MDNS_TEST_SERVICE,
        &instance,
        &format!("0.0.0.0:{port}"),
        "udp",
    ) {
        Ok(advertiser) => advertiser,
        Err(error) => {
            eprintln!("跳过：当前环境无法启动 mDNS 广播（{error:#}）");
            return Ok(());
        }
    };

    // 给广播一点时间生效
    std::thread::sleep(Duration::from_millis(800));
    let found = data_sentinel::mdns::discover(MDNS_TEST_SERVICE, Duration::from_secs(6))?;
    let Some(found) = found else {
        eprintln!("跳过：当前环境未发现 mDNS 服务（可能是 5353 端口争用）");
        drop(advertiser);
        return Ok(());
    };
    assert!(found.endpoint.ends_with(&format!(":{port}")), "{found:?}");
    assert!(!found.addresses.is_empty());
    drop(advertiser);
    Ok(())
}

/// mDNS 未发现时回落到静态 server，保证单机/隔离网络依然可用。
#[test]
fn mdns_falls_back_to_static_server() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let address = socket.local_addr()?.to_string();

    let sender = data_sentinel::syslog::SyslogSender::from_config(&SyslogConfig {
        enabled: true,
        discovery: "mdns".to_string(),
        // 故意用一个不存在的服务类型，强制走回落
        mdns_service: "_no-such-service-ds._udp.local.".to_string(),
        mdns_timeout_ms: 600,
        server: address.clone(),
        ..SyslogConfig::default()
    })
    .expect("sender should exist in mdns mode even without server");

    sender.send_test()?;
    let mut buffer = [0u8; 4096];
    let (len, _) = socket.recv_from(&mut buffer)?;
    assert!(String::from_utf8_lossy(&buffer[..len]).contains("event=\"test\""));
    Ok(())
}

/// mdns 模式下 server 为空也是合法的（地址纯靠发现）。
#[test]
fn mdns_mode_allows_empty_server() {
    let mut config = Config::default();
    config.syslog.enabled = true;
    config.syslog.discovery = "mdns".to_string();
    config.syslog.server = String::new();
    assert!(config.validate().is_ok(), "mdns 模式不应要求 server");

    // static 模式仍然必须填 server
    config.syslog.discovery = "static".to_string();
    assert!(config.validate().is_err());
}

/// 服务类型名超过 15 字节会被 Avahi/Bonjour 拒绝，必须提前拦住。
#[test]
fn rejects_overlong_mdns_service_name() {
    let mut config = Config::default();
    config.syslog.enabled = true;
    config.syslog.discovery = "mdns".to_string();
    config.syslog.mdns_service = "_a-very-long-service-name._udp.local.".to_string();
    assert!(config.validate().is_err());

    config.syslog.mdns_service = "_datasentinel._udp.local.".to_string();
    assert!(config.validate().is_ok());
}

/// 回归：命中报文必须带上终端身份（agent_id / 用户名 / 平台 / 版本）。
///
/// 缺这些字段时服务端只能退化成 `legacy-<主机名哈希>`，「终端」页的
/// 用户名/平台全是空——这正是「服务端看不到客户端」的表象之一。
#[test]
fn finding_payload_carries_agent_identity() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let address = socket.local_addr()?.to_string();

    let sender = data_sentinel::syslog::SyslogSender::from_config_with_identity(
        &SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: address,
            ..SyslogConfig::default()
        },
        data_sentinel::identity::Identity {
            agent_id: "agent-under-test".to_string(),
            hostname: "pc01".to_string(),
            username: "alice".to_string(),
            platform: "macos-aarch64".to_string(),
            version: "9.9.9".to_string(),
        },
    )
    .expect("sender");

    let finding = data_sentinel::model::Finding {
        rule_id: "cn_mobile".to_string(),
        rule_name: "手机".to_string(),
        category: "contact".to_string(),
        severity: Severity::High,
        path: Path::new("/tmp/a.txt").to_path_buf(),
        line: 1,
        column: 1,
        masked: "138********5678".to_string(),
        snippet: String::new(),
        match_hash: "h1".to_string(),
        raw: None,
        start: 0,
        end: 0,
    };
    let (sent, failed) = sender.send_findings(Path::new("/tmp/a.txt"), &[finding]);
    assert_eq!((sent, failed), (1, 0));

    let mut buffer = [0u8; 8192];
    let (len, _) = socket.recv_from(&mut buffer)?;
    let text = String::from_utf8_lossy(&buffer[..len]);
    for expected in [
        "\"agent_id\":\"agent-under-test\"",
        "\"username\":\"alice\"",
        "\"platform\":\"macos-aarch64\"",
        "\"version\":\"9.9.9\"",
    ] {
        assert!(text.contains(expected), "缺少 {expected}：{text}");
    }
    Ok(())
}

/// 回归：机器没有新命中时也必须能被服务端看见。
///
/// 服务端原来只在收到「含 findings 的报文」时才写 `agents`，于是一台
/// 没有新敏感数据的客户端永远不出现在控制台「终端」页。心跳报文让
/// 「在线」与「有告警」解耦。
#[test]
fn heartbeat_registers_agent_without_any_finding() -> anyhow::Result<()> {
    use data_sentinel::server::ingest::{parse_message, Payload};
    use data_sentinel::server::store::ServerStore;

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let address = socket.local_addr()?.to_string();

    let sender = data_sentinel::syslog::SyslogSender::from_config_with_identity(
        &SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: address,
            ..SyslogConfig::default()
        },
        data_sentinel::identity::Identity {
            agent_id: "heartbeat-agent".to_string(),
            hostname: "pc-online".to_string(),
            username: "bob".to_string(),
            platform: "linux-x86_64".to_string(),
            version: "0.3.0".to_string(),
        },
    )
    .expect("sender");

    assert!(sender.send_heartbeat(), "心跳应发送成功");

    let mut buffer = [0u8; 8192];
    let (len, peer) = socket.recv_from(&mut buffer)?;
    let text = String::from_utf8_lossy(&buffer[..len]);
    assert!(text.contains("event=\"heartbeat\""), "{text}");
    // 心跳绝不能带任何文件路径或命中内容。
    assert!(!text.contains("path"), "心跳不应包含路径：{text}");

    // 用真实解析 + 入库，确认服务端会登记这台终端。
    let Payload::Heartbeat(heartbeat) = parse_message(&text)? else {
        panic!("应解析成心跳：{text}");
    };
    let dir = tempfile::tempdir()?;
    let store = ServerStore::open(&dir.path().join("srv.db"))?;
    store.touch_agent(
        &heartbeat.agent_id,
        &heartbeat.hostname,
        &heartbeat.username,
        &heartbeat.platform,
        &heartbeat.version,
        &peer.ip().to_string(),
    )?;

    let agents = store.agents()?;
    assert_eq!(agents.len(), 1, "心跳应登记一台终端");
    let agent = &agents[0];
    assert_eq!(agent.id, "heartbeat-agent");
    assert_eq!(agent.hostname, "pc-online");
    assert_eq!(agent.username, "bob");
    assert_eq!(agent.platform, "linux-x86_64");
    // 心跳不产生告警。
    assert!(store
        .events(&data_sentinel::server::store::EventFilter::default())?
        .0
        .is_empty());
    Ok(())
}
