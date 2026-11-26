# DataSentinel 数据哨兵

跨平台（Windows / 银河麒麟及主流 Linux / macOS）的**本地敏感数据扫描器**。开机自动巡检常用目录，常驻监听文件落盘变更，发现身份证、手机号、银行卡、密码、私钥、云密钥等敏感信息后弹出桌面通知，并把脱敏结果保存在本地 SQLite。

> 数据不出本机；默认不保存命中原文。

## 功能

- **全量巡检**：扫描桌面、文档、下载（含麒麟/Linux 的中文 XDG 目录名），也可配置任意目录。
- **增量扫描**：`notify` 监听创建/修改/重命名，去抖后只扫描变化文件，不必反复全量遍历。
- **规则变更补偿**：修改规则、阈值或自定义规则后，下次扫描会自动重扫未变化文件，避免新规则漏检旧文件。
- **对账补偿**：启动、定时对账按 `size + mtime` 跳过未变化文件，关机期间漏掉的事件也能补齐。
- **内置规则**：身份证（18/15 位）、社保卡号、手机号、座机、邮箱、银行卡（Luhn + BIN）、密码、通用密钥、PEM 私钥、AWS/GitHub/Google/Slack/Stripe/OpenAI Token、JWT、Bearer、护照等。
- **高精度**：身份证校验位/出生日期/行政区划、银行卡 Luhn + 银联 BIN 号段 + 卡号长度、座机区号表、熵值、占位符过滤、关键词上下文、跨块去重。
- **Office 抽取**：直接扫描 `.docx/.xlsx/.pptx` 内部文本。
- **脱敏存储**：只保存 `110105********002X` 这类脱敏值、行号、上下文和哈希；支持 HTML/JSON 报告。
- **本地控制台**：`sentinel ui` 启动图形界面（概览 / 命中记录 / 检测规则 / 设置），带实时扫描进度、筛选搜索、批量确认与报告导出；仅监听 `127.0.0.1`，三平台统一用系统浏览器打开。控制台进程默认自带落盘监控，文件落到扫描目录会立即检测并提醒（`--no-watch` 可关闭）。
- **集中服务端**（可选）：`sentinel-server` 接收各终端上报的告警，按用户/类型/级别汇总，提供 Web 控制台统一维护下发检测规则；支持 HTTPS 与 mDNS 零配置发现。
- **桌面通知**：Windows Toast、macOS 通知中心、Linux/Kylin `notify-send`，并有降级通道。
- **开机自启**：Windows 任务计划/注册表、macOS LaunchAgent、Linux systemd 用户服务/XDG autostart。
- **单文件可执行**：Rust 编译，无运行时依赖（SQLite 已内置）。

## 自动编译（GitHub Actions）

仓库内置两套工作流：

- `.github/workflows/ci.yml`：每次 push / PR 在三平台执行测试和 release 构建，并上传构建产物。
- `.github/workflows/release.yml`：手动运行或推送 `v*` 标签时构建三平台二进制；打标签时自动创建 GitHub Release 并附加安装包。

推送到 GitHub 后，在 **Actions → 对应 workflow → Artifacts** 下载：

- `sentinel-windows-x86_64`：Windows `sentinel.exe`
- `sentinel-macos-*`：macOS 可执行文件
- `sentinel-linux-x86_64`：Linux 可执行文件

发布正式版本（自动构建三平台二进制并生成 GitHub Release）：

```bash
git tag v0.2.0
git push origin v0.2.0
```

Windows 用户下载 `sentinel.exe` 后无需安装 Rust，直接运行即可。

## 快速开始

```bash
# 编译（需要较新的稳定版 Rust，建议 1.85+）
cargo build --release

# 首次运行会生成默认配置
./target/release/sentinel config path

# 打开图形控制台（自动用系统默认浏览器）
./target/release/sentinel ui

# 手动扫描默认目录
./target/release/sentinel scan

# 强制全量扫描指定目录
./target/release/sentinel scan --force --path ~/Desktop --path ~/work

# 前台运行守护进程（落盘监控 + 定时对账）
./target/release/sentinel daemon

# 查看最近命中
./target/release/sentinel findings --limit 30

# 导出 HTML 报告
./target/release/sentinel report --format html --days 30

# 安装开机自启（以当前用户身份运行，不需要 sudo/管理员）
./target/release/sentinel autostart install

# 验证桌面通知
./target/release/sentinel notify-test
```

首次扫描后，后续 `scan` 默认只处理新增/变化文件；`--force` 才会忽略扫描台账。

## 命令

| 命令 | 说明 |
|---|---|
| `sentinel ui [--port 7419] [--no-open] [--no-watch]` | 启动本地图形控制台（浏览器界面），默认同时运行落盘监控 |
| `sentinel scan [--path ...] [--force] [--no-notify] [--json]` | 扫描目录，输出统计 |
| `sentinel watch` / `sentinel daemon` | 落盘监控 + 启动对账 + 定时对账 |
| `sentinel findings [--severity high] [--all] [--json]` | 查看命中记录 |
| `sentinel report --format html\|json [--days 30] [--out FILE]` | 导出报告 |
| `sentinel ack --all` / `--id 12 --id 15` | 确认命中，避免重复提醒 |
| `sentinel rules list` | 列出内置与自定义规则 |
| `sentinel rules test --text "..."` | 直接测试文本 |
| `sentinel rules test ~/file.docx` | 测试文本或 Office 文件 |
| `sentinel config path\|show\|init [--force]` | 配置操作 |
| `sentinel autostart install\|uninstall\|status` | 开机自启管理 |
| `sentinel notify-test` | 桌面通知链路测试 |
| `sentinel syslog test [--server host:port]` | 向 syslog 服务端发送一条测试报文 |
| `sentinel syslog serve [--bind 0.0.0.0:5514] [--output FILE]` | 在本机启动 syslog 接收端（自测或轻量采集） |
| `sentinel syslog discover [--service _ds._udp.local.]` | 通过 mDNS 自动发现局域网内的服务端 |

## 图形控制台

```bash
sentinel ui                 # 打开 http://127.0.0.1:7419/，同时启用落盘监控
sentinel ui --port 8080     # 指定端口（被占用时自动顺延）
sentinel ui --no-open       # 只启动服务，不打开浏览器
sentinel ui --no-watch      # 只提供控制台，不监听落盘（需要手动扫描或另跑 daemon）
```

> 控制台启动时会在后台线程里运行与 `sentinel watch` 相同的监控逻辑（启动对账 + 落盘监听 + 定时对账），所以不必再单独开一个 `daemon`；顶部「落盘监控运行中」指示灯反映的是真实运行状态。

| 页面 | 内容 |
|---|---|
| 概览 | 未确认 / 严重高危计数、级别与分类分布、最近命中、扫描历史、上次扫描结果 |
| 命中记录 | 按级别、状态、类型筛选，关键词搜索，批量确认，右侧详情含脱敏值、上下文与文件定位 |
| 检测规则 | 内置规则逐条开关，在线测试文本（结果同样只显示脱敏值） |
| 设置 | 扫描目录、大小上限、线程数、通知策略、syslog 外发、保留天数、开机自启、直接编辑 `config.toml` |

设计取舍：

- **不引入 WebView / Tauri**：界面由同一个二进制内置提供，三平台都用系统自带浏览器打开。麒麟上无需安装 WebKitGTK，产物仍是单文件可执行，CI 三平台构建流程不变。
- **只监听回环地址**：绑定 `127.0.0.1`，并用随机会话令牌校验 `X-Sentinel-Token`，其他网页无法驱动本机接口。
- **改配置保留注释**：开关规则、修改设置只就地改写对应键值，不会冲掉 `config.toml` 里的注释；写入前备份为 `config.toml.bak`。
- **控制台自带监控**：`sentinel ui` 默认在后台运行落盘监听与定时对账，不必再单独开 `daemon`；顶部「落盘监控运行中」是真实状态。只想查看历史时可加 `--no-watch`，长期无人值守仍建议 `autostart install`。

## 配置

默认位置：

| 平台 | 路径 |
|---|---|
| Windows | `%APPDATA%\DataSentinel\config.toml` |
| macOS | `~/Library/Application Support/DataSentinel/config.toml` |
| 麒麟/Linux | `~/.config/DataSentinel/config.toml` |

也可用 `--config FILE` 或环境变量 `DATASENTINEL_CONFIG` 指定。完整带注释的默认配置见 [`config/default.toml`](config/default.toml)。

最小示例：

```toml
[scan]
roots = ["~/Desktop", "~/Documents", "~/Downloads", "~/work"]
allow_globs = ["**/test-fixtures/**"]  # 可信路径，永不扫描
use_default_excludes = true      # 内置缓存/VCS/二进制排除
max_file_size_mb = 64
threads = 0                     # 0 = 自动
scan_on_startup = true
full_scan_interval_hours = 24

[watch]
enabled = true
debounce_ms = 2000

[notify]
enabled = true
min_severity = "medium"
mode = "summary"                # summary | per_file | off
macos_mode = "auto"             # auto | alert | notification（macOS）
renotify_modified = true        # 文件被修改后仍含敏感数据时再次提醒
renotify_cooldown_secs = 600    # 同一文件重复提醒冷却时间

[storage]
store_raw_match = false         # 默认只存脱敏值

[syslog]                        # 命中后外发到日志服务端（默认关闭）
enabled = false
protocol = "udp"                # udp | tcp | unix
server = "10.0.0.5:514"         # host:port；mdns 模式下可留空
discovery = "static"            # static | mdns（局域网自动发现）
mdns_service = "_datasentinel._udp.local."
facility = "auth"
min_severity = "medium"
include_snippet = true
send_raw = false                # 默认只发脱敏值

[rules]
disabled = ["cn_landline"]
min_severity = "low"

[[rules.custom]]
id = "employee_id"
name = "员工工号"
category = "internal"
severity = "medium"
pattern = 'EMP-\d{6}'
keywords = ["员工", "工号"]
validator = "none"
```

自定义规则说明：

- `pattern` 使用 Rust `regex` 语法，不支持 lookaround。匹配紧贴中文标签的号码时请用
  `(?-u:\b)`（ASCII 单词边界），普通 `\b` 在中文旁会失效。
- 第一个捕获组视为敏感值；没有捕获组时使用整段匹配。
- `validator` 支持 `none`、`luhn`、`bank_card`、`cn_id`、`cn_id_15`、`phone`、
  `landline`、`social_security`、`passport`、`placeholder`、`entropy:3.2`，可逗号组合。
- `keywords` 要求命中附近出现任一关键词，用于降低误报。

## Syslog 外发

把命中结果以 RFC 5424 报文推送到日志服务端（rsyslog / syslog-ng / SIEM / 自建采集器）。

```toml
[syslog]
enabled = true
protocol = "udp"                # udp 开销最小；tcp 可靠、自动重连；unix 仅本机
server = "10.0.0.5:514"         # 必须是 host:port
facility = "auth"               # auth / daemon / local0-local7 ...
min_severity = "medium"         # 只外发该级别及以上
hostname = ""                   # 空 = 本机主机名
app_name = "DataSentinel"
include_snippet = true          # 附带脱敏后的上下文行
send_raw = false                # 默认只发脱敏值
timeout_ms = 2000
```

报文形如：

```
<35>1 2026-11-25T12:02:38.317Z host01 DataSentinel 59635 - [datasentinel@32473 event="cn_id_card" severity="high" host="host01"] {"event":"finding","rule_id":"cn_id_card","rule_name":"中国大陆居民身份证号","severity":"high","path":"/home/u/a.txt","line":2,"value":"320102********0016","masked":"320102********0016",...}
```

行为约定：

- **只推送新增命中**：未变化文件不会重复外发；`value` 字段默认是脱敏值，`send_raw = true` 才会变成原文，控制台会二次确认。
- **外发不阻塞扫描**：发送走独立线程与有界队列，网络异常只记 `WARN` 与统计，扫描照常完成。
- **服务端可配置**：`server` 支持 `host:port` 与 IPv6 `[::1]:514`；`protocol = "unix"` 时填套接字路径。
- **连通性自测**：`sentinel syslog test` 发一条测试报文；本机没有采集器时可用 `sentinel syslog serve` 起一个最小接收端，它会打印报文并落到数据目录 `syslog/received.log`。

### 零配置：mDNS 自动发现服务端

不想在每台客户端上填 IP 时，用 mDNS/DNS-SD 让客户端自动找到服务端。

**服务端**（`sentinel syslog serve` 默认就会广播）：

```toml
[syslog_server]
enabled = true
protocol = "udp"
bind = "0.0.0.0:5514"
advertise = true                                   # 通过 mDNS 广播自己
mdns_service = "_datasentinel._udp.local."          # 客户端必须用同一个
instance = ""                                      # 空 = DataSentinel-<主机名>
```

**客户端**（完全不写 IP）：

```toml
[syslog]
enabled = true
discovery = "mdns"                                 # 自动发现
mdns_service = "_datasentinel._udp.local."
mdns_timeout_ms = 4000
server = ""                                        # 留空；也可填回落地址
```

行为说明：

| 场景 | 行为 |
|---|---|
| 发现成功 | 从 SRV 记录取端口、从 A/AAAA 记录取 IP，自动拼出 `ip:port` |
| 服务端声明协议 | 读 TXT 的 `protocol=udp\|tcp`，客户端按服务端实际监听的协议发送 |
| 发现失败 | 回落到 `server`；`server` 也为空则本批跳过外发并记日志，不影响扫描 |
| 地址选择 | 局域网 IPv4 优先 → 其他 IPv4 → IPv6；过滤回环、`169.254/16`、IPv6 链路本地 |
| 缓存 | 结果缓存 30 秒，热路径不反复发查询；发送全部失败时自动失效并重新发现 |
| 端口占用 | 发现器用短生命周期 daemon，用完即关，避免长期占用 5353 与 Avahi/Bonjour 争用 |

排查命令：

```bash
sentinel syslog discover            # 打印发现的实例、地址、协议
sentinel syslog discover --service _datasentinel._udp.local. --timeout-ms 8000
```

支持矩阵（三平台均已适配，差异只在端口复用语义）：

| 平台 | mDNS 收发 | 是否需装 Avahi/Bonjour | 同机自测 | 备注 |
|---|---|---|---|---|
| Windows 10/11 | 内置 | 不需要 | ✅ 稳定 | `SO_REUSEADDR` 允许多进程同时收包 |
| 银河麒麟 / Linux | 内置 | 不需要 | ⚠️ 可能与 Avahi 抢包 | 跨机器正常；单机自测建议填静态地址 |
| macOS | 内置 | 不需要 | ⚠️ 与 mDNSResponder 分包子 | 跨机器正常 |

> 注意：mDNS 只在一个广播域（同一 VLAN/子网）内有效，无法跨路由。跨网段部署仍需 `discovery = "static"` 配合 DNS 或固定 IP。企业网络若禁用了组播，也会自动回落到静态地址。
>
> 防火墙放行：Windows 首次运行勾选「专用网络」；Linux `firewall-cmd --add-service=mdns` 或 `ufw allow 5353/udp`。

`sentinel-server` 启动时会广播，并在 TXT 里额外带 `console=<端口>` / `console_tls=1`，
所以 `sentinel syslog discover` 能一次把 syslog 地址和**控制台地址**都列出来：

```text
发现 syslog 服务端：
  实例：DataSentinel-srv01._datasentinel._udp.local.
  地址：10.0.0.5:5514
  协议：udp（由服务端 TXT 声明）
  控制台：https://10.0.0.5:8443/
```

对接 rsyslog 的示例（服务端 `/etc/rsyslog.conf`）：

```
module(load="imudp")
input(type="imudp" port="514")
template(name="dsJson" type="string" string="%msg%\n")
local4.* /var/log/datasentinel.log;dsJson
```

## 服务端：集中接收与规则下发（`sentinel-server`）

客户端上报的告警默认只留在本机。需要**集中视角**（谁、在哪台机器、命中了哪类敏感数据）时，
部署 `sentinel-server`：它接收 syslog、按用户/类型/级别汇总，并提供 Web 控制台统一维护下发检测规则。

```bash
cargo build --release
./target/release/sentinel-server run            # 首次启动自动生成配置、口令与 Agent Token
./target/release/sentinel-server doctor         # 自检：数据库、规则、TLS 证书、mDNS
./target/release/sentinel-server config-path     # 配置文件位置
./target/release/sentinel-server agent-token    # 打印 Agent Token（配置客户端用）
./target/release/sentinel-server password-hash '你的新口令'
```

首次启动会把生成的初始化口令**只打印一次**，并写入 `server.toml` 的 `auth.admin_password_hash`；
`auth.agent_token` 留空时同样自动生成并写回。两者都是就地改写对应行，不会覆盖你写的注释。

| 关注点 | 做法 |
|---|---|
| 采集 | syslog RFC 5424（UDP/TCP/两者），也接受裸 JSON 行；来源可用 `allow_cidrs` 限制 |
| 存储 | 独立 SQLite（`server.db`），表结构含 agents / events / rule_sets / audit_log |
| 隐私 | 服务端只存**脱敏值**；客户端即使误发原文也会被丢弃，避免服务端变成明文仓库 |
| 鉴权 | 控制台走管理口令 + 会话 Cookie（HttpOnly/SameSite）；Agent 走共享 Bearer Token |
| 规则 | 整份规则文档按版本保存，支持回滚（回滚生成新版本，历史不删）；发布前强制编译校验 |
| 审计 | 规则发布/回滚、删除终端、清理告警等都写 `audit_log` |
| 保留期 | 启动时与每小时按 `retention.event_days` 清理过期告警 |
| 零配置 | `[discover]` 通过 mDNS 广播地址，客户端 `discovery = "mdns"` 即可上报 |
| 传输安全 | `[tls]` 配好证书即启用 HTTPS，与明文共用同一端口，**不会**静默退化成明文 |

### HTTPS

`[tls]` 的 `cert` / `key` 必须同时配置，任一缺失或证书私钥不匹配都会让启动失败——
安全配置“配了但没生效”比不配更危险，所以这里选择直接报错而不是降级。

```bash
# 生成自签证书（把 IP 换成服务端实际地址，客户端访问才不会报域名不匹配）
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout server.key -out server.crt \
  -subj "/CN=sentinel.local" \
  -addext "subjectAltName=DNS:sentinel.local,IP=10.0.0.5" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth"
```

TLS 实现用 `rustls` + `ring`（纯 Rust，**不依赖 OpenSSL 运行库**），因此 Windows / 麒麟 / macOS
的产物依旧是单文件可执行。

启动后用 `doctor` 或控制台「服务设置 → 接入地址」确认当前是 `http://` 还是 `https://`。

### mDNS 广播

```toml
[discover]
enabled = true
service = "_datasentinel._udp.local."   # 必须与客户端 [syslog] mdns_service 一致
instance = ""                           # 空 = DataSentinel-<主机名>
```

广播内容只有服务名、IP、端口、协议、版本与控制台端口，**不含任何告警数据**。
高保密环境应设 `enabled = false`，改用静态地址。

客户端侧无需任何 IP：

```toml
[syslog]
enabled = true
discovery = "mdns"
mdns_service = "_datasentinel._udp.local."
```

部署细节（systemd、最低权限、防火墙、证书）见 [`docs/server-deploy.md`](docs/server-deploy.md)。

## 平台说明

三种平台的控制台都用系统默认浏览器打开（Windows 默认浏览器 / macOS Safari / 麒麟自带浏览器），不需要额外安装运行时。

### Windows

Windows 不能直接运行 macOS/Linux 产物，需要重新编译 `sentinel.exe`。详细步骤、交叉编译和常见问题见 [`docs/build-windows.md`](docs/build-windows.md)。

最省事的方式：在项目根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

前提是已安装 Rust 和 Visual Studio Build Tools（“使用 C++ 的桌面开发”）。

- 使用 MSVC 工具链：安装 Visual Studio Build Tools 后 `rustup target add x86_64-pc-windows-msvc`。
- VC 运行库已静态链接（`.cargo/config.toml` 开启 `+crt-static`），目标机器无需安装 Visual C++ Redistributable。
- Toast 通过 PowerShell + WinRT 发送（`-EncodedCommand`，不落地临时脚本，不受脚本执行策略影响）；极端情况下回退 `msg`。
- 自启优先写入任务计划（登录后延迟 30 秒），失败回退 `HKCU\...\Run`。
- 任务计划以控制台程序启动时可能闪现一次窗口；后续可替换为托盘程序或 `windows_subsystem` 包装器。
- **mDNS 自动发现无需安装 Bonjour**：内置纯 Rust 实现，直接收发 5353 组播。Windows 的 `SO_REUSEADDR` 允许多个进程同时收到同一个组播包，所以和系统自带的 mDNS 服务共存比 Unix 更稳。防火墙首次运行时可能弹出「允许网络访问」，请勾选**专用网络**；若被策略拦截，会自动回落到静态地址。
- 若企业策略禁用组播（域控防火墙常见），`sentinel syslog discover` 会返回未发现，此时改用 `discovery = "static"` 填固定 IP。

### macOS

- Intel / Apple Silicon 均可编译。
- **macOS 通知**：默认 `notify.macos_mode = "auto"`：中危及以上的命中使用 `osascript display alert` 系统对话框，**不会被“专注模式/勿扰”静默拦截**；低危走通知中心。
- 如需只用横幅通知，设置 `macos_mode = "notification"`，并在“系统设置 → 通知 → Script Editor”中允许通知；同时关闭专注模式。
- 自启写入 `~/Library/LaunchAgents/com.datasentinel.scanner.plist`。
- **mDNS 自动发现**：系统自带 mDNSResponder 会常驻占用 5353。macOS 的 `SO_REUSEPORT` 采用负载均衡语义（不是复制），本机自测时可能出现「自己发现不到自己」，跨机器正常。需要本机验证时建议用 `discovery = "static"` 或换一台机器测试。

### 银河麒麟 / Linux

- 依赖桌面通知服务；UKUI/GNOME/KDE 通常已自带 `notify-send`。无 `notify-send` 时自动尝试 `kdialog/zenity/xmessage`。
- 自启优先 systemd 用户服务（`~/.config/systemd/user/data-sentinel.service`），无 systemd 用户实例时回退 XDG autostart。
- 常见 x86_64 / aarch64 环境可直接在本机 `cargo build --release`；LoongArch 需确认 Rust 工具链对该 target 的支持。
- 建议在目标发行版或较老的 glibc 环境中编译（或使用 musl 静态构建），避免跨发行版 glibc 不兼容。
- 中文目录通过读取 `~/.config/user-dirs.dirs` 自动识别（桌面/文档/下载）。
- 大规模目录可能触及 `inotify` 的 `max_user_watches` 上限；监听失败会记录日志，并由启动/定时对账兜底。
- **mDNS 自动发现**：不依赖 Avahi 守护进程，直接收发 5353 组播；与 Avahi 共存靠 `SO_REUSEPORT`。
  - 若系统已启用 Avahi 且占用了 5353，内核会把组播包分发给其中一个监听者，可能出现「本机自己发现不到自己」。跨机器发现不受影响；单机自测建议直接填 `server` 或用 `discovery = "static"`。
  - firewalld 默认放行 mDNS：`firewall-cmd --add-service=mdns --permanent`；ufw 需要 `ufw allow 5353/udp`。
  - 容器/虚拟机环境若做了组播隔离，同样会回落到静态地址。

## 架构与性能

详细设计见 [`docs/architecture.md`](docs/architecture.md)。核心思路：

1. **路径漏斗**：排除缓存、源码构建目录、回收站、图片/视频/压缩包等。
2. **台账漏斗**：SQLite 保存 `path → size/mtime`，全量对账只 stat 不读内容。
3. **内容漏斗**：二进制嗅探 → 编码识别（UTF-8/UTF-16/GBK/GB18030）→ 1 MiB 分块 + 4 KiB 重叠 → `RegexSet` 多模式预筛。
4. **精度漏斗**：校验位、Luhn、熵值、占位符、关键词上下文。
5. **结果漏斗**：同文件同值去重、跨扫描哈希去重、确认状态保留。

文件级并行使用 `rayon`；Office 解压和单文件读取设上限，避免内存与 zip bomb 风险。

### 实测参考

在一台 Apple Silicon 机器、release 构建、8 线程下：

- 1000 个文本文件（约 19 MB，含 60 处命中）：首次全量扫描约 **1.0 s**（含 SQLite 写入）。
- 同一批文件二次对账：约 **0.02 s**（只 stat，不读内容）。
- 修改单个文件后 watcher 增量扫描：约 **20 ms** 完成检测并写入。

实际耗时会受磁盘、文件数量、加密盘、杀毒软件实时防护影响。

## 隐私与安全

- 默认只保存脱敏值；`storage.store_raw_match = true` 才会保存原文（不建议）。
- 数据库、报告、配置在 Unix 上以 `0600` 写入，目录 `0700`。
- 自动排除自身数据库/日志/报告目录。
- 默认全程离线：不扫描、不存储、不外发都只在本机完成。**只有显式开启 `[syslog] enabled = true` 才会产生网络流量**，且默认只发送脱敏值；`send_raw = true` 需要用户二次确认。
- syslog 走明文 UDP/TCP，不含加密；跨不可信网络时请在服务端用 rsyslog `imtcp + gtls` 或隧道（WireGuard / stunnel）保护链路。
- 接收端日志同样以 `0600` 落盘。
- mDNS 自动发现只广播「服务名 + IP + 端口 + 协议」，不携带任何命中数据；但它会把本机在局域网内暴露为可发现节点，保密环境可设 `advertise = false` 并改用静态地址。

## 测试

```bash
cargo test
```

覆盖：身份证校验位/行政区划、银行卡 BIN + Luhn、手机号号段、座机区号、社保卡号标签联动、占位符、编码识别、分块边界、规则引擎、SQLite 去重/确认状态、syslog 外发（脱敏、去重、UDP/TCP、mDNS 自动发现与回落）、服务端 HTTPS 握手与证书校验、mDNS 广播带出控制台地址，以及时间戳/订单号/雪花 ID 等常见数字噪声的误报回归。

## 目录结构

```
src/
  main.rs        CLI 分发、日志
  bin/
    sentinel-server.rs  服务端入口
  cli.rs         clap 定义
  config.rs      配置与常用目录探测
  model.rs       Finding / 统计模型
  rules/         规则集、内置规则、本地区划/卡 BIN 常量表、校验器
  syslog.rs      RFC 5424 外发、异步队列、接收端
  mdns.rs        mDNS/DNS-SD 自动发现与广播
  server/        集中服务端：HTTP/TLS、接收、存储、规则下发、控制台
  detect.rs      编码、二进制嗅探、Office 抽取
  scan.rs        遍历、并行、增量台账
  watch.rs       notify 监听与去抖
  store.rs       SQLite
  notify.rs      三平台桌面通知
  autostart.rs   三平台自启
  report.rs      HTML/JSON 报告
  tomlpatch.rs   保留注释的 TOML 就地改写
  util.rs        脱敏、哈希、片段、有界读行、转义
tests/           集成测试（含 TLS 测试证书）
config/          客户端与服务端默认配置
docs/            架构设计
```

## 已知限制

- 用户态 watcher 在网络盘或部分 FUSE 文件系统上可能丢事件，依赖启动/定时对账兜底。
- PDF、旧版 `.doc/.xls/.ppt`、图片 OCR、压缩包内文件暂不支持（架构已预留扩展点）。
- 不是内核级 DLP，不能阻断写盘；只做本地发现与提醒。
- 恶意程序可以绕过用户态扫描，本工具用于个人隐私自查与日常卫生，不替代企业级 DLP。

## License

MIT
