//! 控制台 HTTPS：基于 `rustls` 的同步 TLS 终止。
//!
//! 只用 `rustls` + `ring`（纯 Rust/汇编实现，无 OpenSSL 依赖），
//! 保证 Windows / 麒麟 / macOS 三平台产物依旧是单文件可执行，
//! 不需要额外安装 OpenSSL 运行库——这正是本项目一贯的取舍。
//!
//! 证书由运维自行准备（PEM）：`server.toml` 的 `[tls] cert/key`。
//! 配置了就走 HTTPS，未配置就保持明文 HTTP；两者共用同一个监听端口，
//! 不存在“配了但没生效”的中间状态。

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// 读取证书链与私钥，构造 TLS 配置。
///
/// 任何一步失败都直接返回错误：监听器宁可起不来，也不要静默退化成明文，
/// 否则运维会误以为链路已加密。
pub fn load(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("初始化 TLS 协议版本失败")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "证书与私钥不匹配或算法不受支持（cert={}，key={}）",
                cert_path.display(),
                key_path.display()
            )
        })?;
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("无法读取证书 {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("证书 {} 不是合法的 PEM", path.display()))?;
    if certs.is_empty() {
        bail!("证书 {} 里没有找到 CERTIFICATE 块", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("无法读取私钥 {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("私钥 {} 不是合法的 PEM", path.display()))?;
    match key {
        Some(key) => Ok(key),
        None => bail!(
            "私钥 {} 里没有找到 PRIVATE KEY 块（支持 PKCS#8 / PKCS#1 / SEC1）",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// 测试用自签证书（CN=localhost，SAN 含 DNS:localhost / IP:127.0.0.1）。
    /// 只在单元测试里使用，绝不用于任何真实部署。
    const TEST_CERT: &str = include_str!("../../tests/fixtures/tls/localhost.crt");
    const TEST_KEY: &str = include_str!("../../tests/fixtures/tls/localhost.key");

    fn write_fixture(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = dir.join("localhost.crt");
        let key = dir.join("localhost.key");
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::fs::write(&key, TEST_KEY).unwrap();
        (cert, key)
    }

    #[test]
    fn loads_valid_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_fixture(dir.path());
        assert!(load(&cert, &key).is_ok());
    }

    #[test]
    fn rejects_missing_or_broken_files() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_fixture(dir.path());
        assert!(load(&dir.path().join("nope.crt"), &key).is_err());
        assert!(load(&cert, &dir.path().join("nope.key")).is_err());

        let broken = dir.path().join("broken.crt");
        std::fs::write(&broken, "not a pem").unwrap();
        assert!(load(&broken, &key).is_err());
    }

    /// 端到端握手：服务端写一行，客户端读一行，证明 TLS 配置真能用。
    #[test]
    fn tls_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_fixture(dir.path());
        let server_config = load(&cert, &key).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, tcp);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut TEST_CERT.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let tcp = std::net::TcpStream::connect(address).unwrap();
        let mut stream = rustls::StreamOwned::new(conn, tcp);

        let mut buffer = [0u8; 64];
        let len = stream.read(&mut buffer).unwrap();
        assert!(String::from_utf8_lossy(&buffer[..len]).contains("204"));
        handle.join().unwrap();
    }
}
