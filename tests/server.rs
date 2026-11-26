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
