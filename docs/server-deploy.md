# 服务端部署（`sentinel-server`）

面向运维：把 `sentinel-server` 跑成常驻服务，接收各终端上报的敏感数据告警。

## 1. 准备

```bash
# 单文件可执行，无运行时依赖
install -m 0755 sentinel-server /usr/local/bin/sentinel-server

# 生成默认配置（Linux: ~/.config/DataSentinel/server.toml）
sentinel-server config-init
sentinel-server config-path
```

编辑 `server.toml`：

```toml
[server]
bind = "0.0.0.0:8443"

[ingest]
enabled = true
protocol = "both"
# 514 需要 root 或 CAP_NET_BIND_SERVICE；先跑 5514 更省事
bind = "0.0.0.0:5514"
# 强烈建议按网段限制来源
allow_cidrs = ["10.0.0.0/8", "192.168.0.0/16"]

[auth]
# 两者留空时首次启动自动生成，并写回本文件
agent_token = ""
admin_password_hash = ""

[discover]
enabled = true

[tls]
cert = "/etc/datasentinel/server.crt"
key = "/etc/datasentinel/server.key"
```

首次启动会把管理口令**只打印一次**：

```bash
sentinel-server doctor     # 先自检：规则、数据库、证书、mDNS
sentinel-server run
```

## 2. systemd（推荐，非 root 运行）

用 `setcap` 绑低端口，避免整个进程跑成 root：

```bash
sudo useradd --system --home /var/lib/datasentinel --shell /usr/sbin/nologin datasentinel
sudo install -d -o datasentinel -g datasentinel -m 0700 /var/lib/datasentinel
sudo install -d -o root -g datasentinel -m 0750 /etc/datasentinel
# 证书私钥只让服务账号可读
sudo chown root:datasentinel /etc/datasentinel/server.key
sudo chmod 0640 /etc/datasentinel/server.key

sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sentinel-server
```

`/etc/systemd/system/sentinel-server.service`：

```ini
[Unit]
Description=DataSentinel 集中服务端
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=datasentinel
Group=datasentinel
Environment=DATASENTINEL_SERVER_CONFIG=/etc/datasentinel/server.toml
ExecStart=/usr/local/bin/sentinel-server run
Restart=on-failure
RestartSec=5

# 数据库与日志写在 /var/lib/datasentinel
StateDirectory=datasentinel
WorkingDirectory=/var/lib/datasentinel

# 加固：只读系统、禁止提权
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/datasentinel

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-server
sudo journalctl -u sentinel-server -f
```

## 3. 防火墙

| 端口 | 用途 | 建议 |
|---|---|---|
| 8443/tcp | Web 控制台 + API | 只对内网管理网段开放 |
| 5514/udp+tcp | syslog 接收 | 只对被监控终端网段开放 |
| 5353/udp | mDNS 广播 | 同广播域；跨网段部署可关掉 `[discover]` |

```bash
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=5514/udp --add-port=5514/tcp
sudo firewall-cmd --permanent --add-service=mdns
sudo firewall-cmd --reload
```

## 4. 客户端接入

终端上配置（推荐 mDNS，零 IP）：

```toml
[syslog]
enabled = true
discovery = "mdns"
mdns_service = "_datasentinel._udp.local."
min_severity = "medium"
```

跨网段或禁组播时用静态地址：

```toml
[syslog]
enabled = true
discovery = "static"
server = "10.0.0.5:5514"
protocol = "udp"
```

验证：

```bash
sentinel syslog discover     # 应看到地址、协议与控制台 URL
sentinel syslog test         # 发一条测试报文
```

## 5. 运维要点

- **凭据轮换**：改管理口令用 `sentinel-server password-hash '新口令'`，把输出粘到
  `auth.admin_password_hash` 后重启（重启会使现有会话全部失效）。换 Agent Token 直接改
  `auth.agent_token`，然后同步更新客户端配置。
- **规则发布**：控制台「规则下发」页面改动后必须点「发布」，客户端下次拉取才生效；
  每条规则都会在服务端编译校验，坏正则会被拒绝保存。
- **磁盘**：告警量 = 终端数 × 命中数。按 `retention.event_days` 自动清理（默认 180 天），
  也可在「服务设置」手动清理。
- **备份**：只需备份 `server.db`（SQLite，先停服务或用 `sqlite3 .backup` 保证一致性）。
- **HTTPS 证书**：自签证书需要导入客户端受信任根证书，否则浏览器会提示不安全；
  正式环境建议用内部 CA 签发，域名/IP 必须写进 SAN。
