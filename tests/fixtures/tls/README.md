# 测试用自签证书（仅供单元/集成测试）

本目录下的 `localhost.crt` / `localhost.key` 是仓库自带的**测试夹具**，
只在 `cargo test` 里用于验证 TLS 加载与握手链路：

- 证书 `CN=localhost`，SAN 含 `DNS:localhost`、`IP:127.0.0.1`；
- 10 年有效期，仅为避免测试因过期而失败；
- 私钥是公开的，**任何人都能拿到**，绝不能用于真实部署。

生产环境请按 `config/default-server.toml` 里 `[tls]` 段的注释自行生成证书，
并把证书导入需要访问控制台的机器的受信任根证书，否则浏览器会提示不安全。
