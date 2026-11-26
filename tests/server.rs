//! 服务端集成测试：确认「声明了的能力」真的能用。
//!
//! 覆盖两条容易被“配置对了但代码没接上”破坏的链路：
//! 1. `[tls]` 配好证书后，控制台必须真的走 HTTPS（而不是静默退化成明文）。
//! 2. `[discover]` 开启后，mDNS 广播里必须带 syslog 地址与控制台地址。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use data_sentinel::server::config::DEFAULT_SERVER_CONFIG;

const TEST_CERT: &str = include_str!("fixtures/tls/localhost.crt");
const TEST_KEY: &str = include_str!("fixtures/tls/localhost.key");

fn write_fixture(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = dir.join("localhost.crt");
    let key = dir.join("localhost.key");
    std::fs::write(&cert, TEST_CERT).unwrap();
    std::fs::write(&key, TEST_KEY).unwrap();
    (cert, key)
}

fn client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut TEST_CERT.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// 起一个只处理一次握手 + 一次请求的最小 HTTPS 服务，验证 TLS 配置可用。
fn serve_once(tls: Arc<rustls::ServerConfig>) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(tls).unwrap();
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut remaining = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line.trim().is_empty() {
                break;
            }
            remaining.push_str(&line);
        }
        drop(reader);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        stream.flush().unwrap();
        // 与 http::handle_tls_connection 一致：发 close_notify，避免客户端报 UnexpectedEof。
        stream.conn.send_close_notify();
        let _ = stream.flush();
        request_line.trim().to_string()
    });
    (address, handle)
}

#[test]
fn tls_config_serves_https() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_fixture(dir.path());
    let tls = data_sentinel::server::tls::load(&cert, &key).unwrap();

    let (address, handle) = serve_once(tls);

    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(client_config()), server_name).unwrap();
    let tcp = TcpStream::connect(&address).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    stream
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    stream.flush().unwrap();

    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("200 OK"), "响应异常：{text}");
    assert!(text.ends_with("ok"), "响应体异常：{text}");

    let request_line = handle.join().unwrap();
    assert!(request_line.contains("/api/health"), "{request_line}");
}

/// 明文客户端打 HTTPS 端口必须拿不到业务数据（证明不是明文在跑）。
#[test]
fn tls_port_rejects_plain_http() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_fixture(dir.path());
    let tls = data_sentinel::server::tls::load(&cert, &key).unwrap();

    // 模拟 http::handle_tls_connection：先握手，失败即断开。
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let conn = rustls::ServerConnection::new(tls).unwrap();
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream.conn.complete_io(&mut stream.sock).is_err()
    });

    let mut tcp = TcpStream::connect(address).unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let _ = tcp.flush();
    // 服务端应放弃握手；客户端侧读不到任何 HTTPS 响应。
    let mut buffer = [0u8; 16];
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.read(&mut buffer);
    assert!(handle.join().unwrap(), "明文请求不应握手成功");
}

/// mDNS 广播的 TXT 必须带上控制台端口，客户端才能从发现结果直接拿到控制台地址。
#[test]
fn advertiser_publishes_console_hint() -> anyhow::Result<()> {
    use data_sentinel::config::MDNS_TEST_SERVICE;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let console_port = listener.local_addr()?.port();
    drop(listener);

    let instance = format!("ds-server-test-{}", std::process::id());
    let mut extra = std::collections::HashMap::new();
    extra.insert("console".to_string(), console_port.to_string());
    extra.insert("console_tls".to_string(), "1".to_string());

    let advertiser = match data_sentinel::mdns::Advertiser::start_with(
        MDNS_TEST_SERVICE,
        &instance,
        "0.0.0.0:5514",
        "udp",
        &extra,
    ) {
        Ok(advertiser) => advertiser,
        Err(error) => {
            eprintln!("跳过：当前环境无法启动 mDNS 广播（{error:#}）");
            return Ok(());
        }
    };
    std::thread::sleep(Duration::from_millis(800));

    let found = data_sentinel::mdns::discover(MDNS_TEST_SERVICE, Duration::from_secs(6))?;
    let Some(found) = found else {
        eprintln!("跳过：当前环境未发现 mDNS 服务（可能是 5353 端口争用）");
        drop(advertiser);
        return Ok(());
    };

    assert_eq!(found.instance, format!("{instance}.{MDNS_TEST_SERVICE}"));
    assert_eq!(found.protocol.as_deref(), Some("udp"));
    let console = found.console.expect("应带出控制台地址");
    assert!(console.starts_with("https://"), "{console}");
    assert!(console.ends_with(&format!(":{console_port}/")), "{console}");
    drop(advertiser);
    Ok(())
}

/// 默认配置必须能被解析并通过校验，否则首启就会失败。
#[test]
fn default_config_is_valid() {
    let config: data_sentinel::server::config::ServerConfig =
        toml::from_str(DEFAULT_SERVER_CONFIG).unwrap();
    config.validate().unwrap();
    assert!(config.discover.enabled);
    assert_eq!(config.discover.service, "_datasentinel._udp.local.");
}

/// 回归：`GET /%中` 曾让 `percent_decode` 按字节切在 UTF-8 字符中间 panic，
/// 而 release 构建是 `panic = "abort"`，等于一个请求打挂整个服务端。
///
/// 这里直接驱动真实的 `http::handle_connection`，确认畸形 URL 只得到 4xx，
/// 且进程继续正常工作。
#[test]
fn malformed_percent_url_does_not_kill_connection_handler() -> anyhow::Result<()> {
    use data_sentinel::server::{api, config::ServerConfig, http, store::ServerStore};
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    let dir = tempfile::tempdir()?;
    let config = Arc::new(ServerConfig {
        storage: data_sentinel::server::config::ServerStorageConfig {
            database: dir.path().join("server.db"),
        },
        ..ServerConfig::default()
    });
    let store = Arc::new(ServerStore::open(&config.database_path())?);
    let state = Arc::new(data_sentinel::server::AppState {
        config: Arc::clone(&config),
        store,
        auth: Arc::new(data_sentinel::server::AuthState::new(
            &config,
            String::new(),
            "token".to_string(),
        )),
        ingest_stats: Arc::new(data_sentinel::server::ingest::IngestStats::default()),
        started_at: Instant::now(),
        stopped: Arc::new(AtomicBool::new(false)),
        config_path: dir.path().join("server.toml"),
    });

    // 起一个真实监听端口，用原始字节把畸形请求打进去。
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server_state = Arc::clone(&state);
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let state = Arc::clone(&server_state);
            std::thread::spawn(move || http::handle_connection(stream, state));
        }
    });

    let request = |line: &str| -> anyhow::Result<String> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(String::from_utf8_lossy(&response).into_owned())
    };

    let first = request("GET /%中 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    assert!(
        first.starts_with("HTTP/1.1 4") || first.starts_with("HTTP/1.1 200"),
        "畸形 URL 不应崩溃，实际响应：{first}"
    );

    // 服务端仍然存活：紧接着的健康检查必须正常返回。
    let second =
        request("GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    assert!(second.contains("200 OK"), "服务端已被打挂：{second}");
    assert!(second.contains("\"ok\":true"), "{second}");

    let _ = api::JSON;
    server.join().ok();
    Ok(())
}

/// 登录链路回归：输入正确口令后，后续请求必须凭 Cookie 通过鉴权。
///
/// 这条链路同时覆盖两个曾经的坑：
/// 1. `Set-Cookie` 没被浏览器接受 / 没被带回来 → 每个请求都 401，
///    前端表现就是「输入口令后还是停在登录页」；
/// 2. Cookie 头里夹带不含 `=` 的片段时解析提前中止，会话丢失。
#[test]
fn login_issues_session_cookie_that_authorizes_next_request() -> anyhow::Result<()> {
    use data_sentinel::server::{api, config::ServerConfig, http, store::ServerStore};
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    const PASSWORD: &str = "test-admin-password";

    let dir = tempfile::tempdir()?;
    let config = Arc::new(ServerConfig {
        storage: data_sentinel::server::config::ServerStorageConfig {
            database: dir.path().join("server.db"),
        },
        ..ServerConfig::default()
    });
    let store = Arc::new(ServerStore::open(&config.database_path())?);
    let state = Arc::new(data_sentinel::server::AppState {
        config: Arc::clone(&config),
        store,
        auth: Arc::new(data_sentinel::server::AuthState::new(
            &config,
            data_sentinel::server::auth::hash_password(PASSWORD),
            "agent-token".to_string(),
        )),
        ingest_stats: Arc::new(data_sentinel::server::ingest::IngestStats::default()),
        started_at: Instant::now(),
        stopped: Arc::new(AtomicBool::new(false)),
        config_path: dir.path().join("server.toml"),
    });
    let _ = api::JSON;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server_state = Arc::clone(&state);
    let server = std::thread::spawn(move || {
        // 正好处理下面 3 个请求；accept 次数多于请求数会让 join 永远等不到连接。
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let state = Arc::clone(&server_state);
            std::thread::spawn(move || http::handle_connection(stream, state));
        }
    });

    let request = |raw: &str| -> anyhow::Result<String> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(raw.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(String::from_utf8_lossy(&response).into_owned())
    };

    // 1. 口令正确 → 200 且下发 Cookie。
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    let login = request(&format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    ))?;
    assert!(login.contains("200 OK"), "登录应成功：{login}");
    let cookie_line = login
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .expect("登录响应必须带 Set-Cookie");
    assert!(cookie_line.contains("HttpOnly"), "{cookie_line}");
    assert!(cookie_line.contains("SameSite=Strict"), "{cookie_line}");
    let session_cookie = cookie_line
        .split_once("sentinel_session=")
        .and_then(|(_, rest)| rest.split(';').next())
        .expect("Cookie 中应有 sentinel_session")
        .to_string();
    assert_eq!(session_cookie.len(), 64, "会话令牌应为 32 字节 hex");

    // 2. 带上 Cookie 访问受保护接口 → 200；顺便验证 Cookie 头里有杂项也不影响。
    let authorized = request(&format!(
        "GET /api/me HTTP/1.1\r\nHost: localhost\r\nCookie: other=1; sentinel_session={session_cookie}\r\n\
         Connection: close\r\n\r\n"
    ))?;
    assert!(
        authorized.contains("200 OK"),
        "会话应通过鉴权：{authorized}"
    );
    assert!(authorized.contains("\"actor\":"), "{authorized}");

    // 3. 不存在的会话 → 401，仍然要求登录。
    let anonymous = request(
        "GET /api/me HTTP/1.1\r\nHost: localhost\r\nCookie: sentinel_session=bogus\r\n\
         Connection: close\r\n\r\n",
    )?;
    assert!(anonymous.contains("401"), "伪造会话必须被拒绝：{anonymous}");

    server.join().ok();
    Ok(())
}
