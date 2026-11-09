# 数据哨兵 DataSentinel — 产品架构设计

> 一个纯本地运行的跨平台敏感数据扫描器：Windows / 银河麒麟（及主流 Linux）/ macOS。
> 开机登录后自动巡检常用目录，也可通过配置扩展目录；常驻进程监听文件落盘事件做增量扫描；命中敏感数据后弹出桌面通知，并把脱敏结果保存在本地。

---

## 1. 目标与边界

### 1.1 产品目标

| 目标 | 说明 |
|---|---|
| 全量巡检 | 开机/登录后自动扫描桌面、文档、下载等常用目录，也能手动触发全盘或指定目录扫描 |
| 增量发现 | 文件创建/修改/重命名时自动扫描，不必反复全量遍历 |
| 内置规则 | 身份证、手机号、银行卡、邮箱、密码、私钥、云厂商密钥、JWT 等常见个人隐私/凭据 |
| 可扩展 | TOML 配置扫描目录、排除规则、自定义正则规则、动作与性能参数 |
| 本地闭环 | 数据不出本机；结果落 SQLite，支持 JSON / HTML 报告 |
| 及时提醒 | 命中后通过系统通知中心弹窗，聚合提醒，避免通知轰炸 |
| 跨平台 | 同一套 Rust 代码，三平台原生运行；麒麟走 Linux 分支并提供 systemd/XDG 自启 |

### 1.2 明确的非目标（v1）

- 不做云端上报、不做账号体系、不做远程管理。
- 不做数据防泄漏（DLP）阻断；v1 只发现和提醒，不自动删除/加密/阻断写盘。
- 不做 OCR 与图片内文字识别（路线图）。
- 不做 PDF 深度解析（路线图，v1 可通过扩展点接入）。
- 不做内核级文件过滤驱动；落盘监控采用用户态文件系统事件，兼顾可维护性与三平台一致性。

### 1.3 威胁模型与隐私原则

1. **本地优先**：检测、存储、通知全部在本机完成，默认不联网。
2. **最小留存**：默认只保存脱敏值（如 `110101********1234`）、规则 ID、文件路径、行号与上下文片段；不保存原始命中内容。
3. **最小权限**：以当前用户身份运行，不要求管理员/root；只读扫描用户有权限的文件。
4. **可审计**：每次扫描写运行记录；发现项可确认（ack），数据库与报告文件在 Unix 上以 `0600` 创建。
5. **防误报优先**：身份证校验位、银行卡 Luhn、上下文关键词、熵值、占位符过滤共同降低噪音。

---

## 2. 总体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                          sentinel CLI                            │
│  ui / scan / watch(daemon) / findings / report / ack / rules /   │
│  config / autostart / notify-test                                │
└───────────────┬──────────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────────┐
│                         Orchestrator                             │
│  Scanner：目录遍历、任务调度、批量聚合、扫描统计                  │
│  Watcher：文件系统事件、去抖、增量任务、定时对账                  │
└───────┬───────────────────┬───────────────────┬──────────────────┘
        │                   │                   │
┌───────▼────────┐  ┌───────▼────────┐  ┌───────▼───────────────┐
│  Discovery     │  │  Detection     │  │  Persistence          │
│  walkdir       │  │  decoding      │  │  SQLite (rusqlite)    │
│  globset       │  │  extract       │  │  files / findings     │
│  rayon pool    │  │  RegexSet      │  │  scan_runs / meta     │
│  file journal  │  │  validators    │  │  JSON / HTML report   │
└───────┬────────┘  └───────┬────────┘  └───────┬───────────────┘
        │                   │                   │
        └───────────────────┴─────────┬─────────┘
                                      │
                        ┌─────────────▼─────────────┐
                        │  Platform Adapters        │
                        │  Notifier / Autostart     │
                        │  Win: Toast + schtasks    │
                        │  macOS: osascript + plist │
                        │  Linux: notify-send +     │
                        │         systemd/XDG       │
                        └───────────────────────────┘
```

### 2.1 代码分层

```
data-sentinel/
├── Cargo.toml
├── config/default.toml          # 首次运行写入用户配置目录
├── docs/architecture.md
├── src/
│   ├── main.rs                  # CLI 入口、日志初始化、命令分发
│   ├── cli.rs                   # clap 定义
│   ├── config.rs                # 配置模型、路径解析、默认目录
│   ├── model.rs                 # Severity / Finding / ScanSummary
│   ├── rules/
│   │   ├── mod.rs               # RuleSet、编译、扫描、去重
│   │   ├── builtin.rs           # 内置规则表
│   │   └── validator.rs         # 校验位、Luhn、熵、占位符
│   ├── detect.rs                # 解码、分块、文本/Office 提取、检测引擎
│   ├── scan.rs                  # 目录遍历 + rayon 并行 + 增量台账
│   ├── watch.rs                 # notify 监听、去抖、定时对账
│   ├── store.rs                 # SQLite 持久化
│   ├── notify.rs                # 三平台桌面通知
│   ├── autostart.rs             # 三平台开机自启
│   ├── report.rs                # HTML / JSON 报告
│   ├── webui/                   # 本地图形控制台（sentinel ui）
│   │   ├── mod.rs               # 回环监听、会话令牌、浏览器/文件管理器调用
│   │   ├── server.rs            # 极简 HTTP/1.1 + 静态资源内嵌
│   │   ├── api.rs               # JSON 接口：概览/命中/规则/扫描/设置
│   │   ├── tomlpatch.rs         # 保留注释的 config.toml 就地改写
│   │   └── assets/              # index.html + app.css + app.js（无构建步骤）
│   └── util.rs                  # 路径、脱敏、哈希、HTML 转义
└── tests/detection.rs
```

模块之间只通过 `Config`、`Finding`、`Store` 等少量类型耦合，后续可替换检测引擎或再套一层原生壳而不影响核心。

### 2.2 本地控制台

`sentinel ui` 在 `127.0.0.1` 上起一个单用户 HTTP 服务，并用系统默认浏览器打开。
界面资源在编译期内嵌（`include_str!`），不需要 Node 构建链，也不需要 WebView 运行时，
因此 Windows / 麒麟 / macOS 三平台产物仍是单文件可执行。

| 关注点 | 做法 |
|---|---|
| 攻击面 | 仅绑定回环地址；所有 `/api/*` 校验 `X-Sentinel-Token`，令牌随机生成后注入首页 |
| 并发 | 请求线程池 + 共享只读 `Store` 连接；扫描线程使用独立连接，WAL 下一写多读 |
| 实时进度 | `ScanProgress` 原子计数，前端轮询 `/api/scan/status`，避免长连接与 SSE |
| 配置写入 | 只就地改写目标键值，保留 `config.toml` 注释；校验通过后落盘并备份 `.bak` |
| 隐私 | 界面与接口只暴露脱敏值；不新增任何外发通道 |

---

## 3. 核心流程

### 3.1 全量/对账扫描

```
启动/定时/手动
   │
   ▼
列出扫描根目录（配置 > 系统常用目录自动探测）
   │
   ▼
WalkDir 遍历（排除目录/隐藏/符号链接策略/大小/扩展名）
   │
   ▼
与 SQLite files 台账比对 (size, mtime)
   ├─ 未变化 → 跳过（全量扫描的绝大部分）
   └─ 新增/变化 → 投递到 rayon 工作池
                         │
                         ▼
              读取 → 二进制嗅探 → 编码识别 → 解码
                         │              └─ Office 走 zip+XML 抽取
                         ▼
              RegexSet 多模式预筛 → 单规则捕获 → 校验器/上下文
                         │
                         ▼
              脱敏 + 行号 + 上下文 + 哈希去重
                         │
                         ▼
              SQLite 事务保存（保留 ack 状态）
                         │
                         ▼
              汇总新增命中 → 桌面通知（聚合）
```

### 3.2 落盘增量扫描

```
notify::RecommendedWatcher（每平台原生后端）
   │ Create / Modify / Rename / Remove
   ▼
路径过滤（排除自身数据库、日志、临时文件；文件存在性检查）
   │
   ▼
去抖缓冲 HashMap<PathBuf, (Instant, kind)>，默认 2s
   │
   ▼
到期批次 → 强制扫描这些文件（不再全量遍历）
   │
   ▼
保存结果 → 只对“新增命中”弹窗
```

- **重启补偿**：守护进程启动时先做一次对账扫描，按 `size + mtime` 跳过未变化文件，因此即使关机期间错过事件也能补齐。
- **事件丢失兜底**：可配置定时全量对账（默认 24h），同样只处理变化文件。
- **写入中文件**：去抖 + 跳过 `.tmp/.part/.swp/~$` + 读取失败重试，避免扫描到半个文件。
- **重命名**：`RenameMode::Both` 会同时处理旧路径与新路径；旧路径删除台账，新路径重新扫描。

### 3.3 通知策略

- 默认 **summary**：一个扫描批次只弹一次，例如「发现 3 个文件共 5 处敏感数据，最高级别：高危」。
- 可按文件聚合（`mode = "per_file"`），并限制每批最多弹窗数量。
- 只对 **新命中** 弹窗：相同文件、相同规则、相同内容的哈希已存在时不重复提醒；用户确认（ack）后也不再重复。
- 低于 `notify.min_severity` 的结果只入库不弹窗。
- 通知失败自动降级：Linux `notify-send → zenity → kdialog → xmessage`；Windows Toast → `msg`；macOS 通知中心 → 日志。

---

## 4. 高性能敏感数据发现

性能目标（普通办公本，SSD）：

| 场景 | 目标 |
|---|---|
| 10 万文件、20 GB 常用目录首次全量 | 10–30 分钟（受磁盘 IO 限制） |
| 第二次全量对账（无变化） | 秒级到分钟级（只 stat，不读内容） |
| 单文件增量扫描 | 毫秒级到百毫秒级 |
| 纯文本检测吞吐 | ≥ 100 MB/s/核（RegexSet + 字面量预筛） |
| 常驻内存 | 空载 < 80 MB；扫描峰值与线程数、单文件上限相关 |

### 4.1 五级漏斗

1. **路径级过滤（最便宜）**
   - 目录排除：`node_modules`、`.git`、`target`、缓存、回收站、虚拟环境等；支持 glob。
   - 文件过滤：扩展名白/黑名单、大小上限、符号链接策略、自身数据目录排除。
2. **台账级过滤（一次 SQLite 预加载）**
   - 扫描前一次性加载 `path → (size, mtime)` 到内存；未变化文件只做 stat，不读内容。
   - 这是“第二次全量扫描秒级完成”的关键。
3. **内容级预筛**
   - 先做二进制嗅探（NUL/控制字符比例），避免对图片、压缩包、可执行文件跑正则。
   - 文本文件识别编码（BOM / UTF-8 / chardetng + encoding_rs，兼容 GBK/GB18030、UTF-16）。
   - `RegexSet` 一次性匹配所有规则，得到候选规则下标，再对候选规则做捕获提取。
   - 可选 Aho-Corasick 字面量锚点（如 `AKIA`、`BEGIN PRIVATE KEY`、`密码`）作为更廉价的预筛。
4. **规则级校验（降误报）**
   - 身份证校验位 + 出生日期合法性；银行卡 Luhn；手机号号段；密码/密钥熵值；占位符与变量引用过滤。
   - 关键词上下文窗口（如“密码/口令/password”附近才认定密码字段）。
5. **结果级去重**
   - 同一文件内按 `(起始偏移, 结束偏移)` 去重，重叠规则保留最高严重级别。
   - 跨扫描按 `(path, rule_id, match_hash)` 唯一约束，保留确认状态。

### 4.2 并行模型

- **文件级并行**：`rayon` 线程池，默认 `min(CPU 核数, 8)`，避免机械硬盘随机读放大；SSD 可调高。
- **流式遍历**：`WalkDir → par_bridge()`，边遍历边扫描，不把百万路径收集进内存。
- **大文件分块**：1 MiB 块 + 4 KiB 重叠，按 UTF-8 字符边界切分，避免跨块漏匹配；块间重复命中由偏移去重。
- **IO 友好**：单文件只读一次；Office 先读 zip 再抽取；读取失败/被占用计入 failed 并继续，不阻塞整批。
- **内存上限**：单文件默认 64 MB 上限，超出跳过并记录；Office 解压总量上限 256 MB，防 zip bomb。

### 4.3 增量与缓存

- SQLite `files` 表是“扫描台账”：`path, size, mtime, content_hash, last_scanned, status`。
- **规则变更自动重扫**：SQLite `meta` 保存规则指纹（规则 ID、模式、校验器、级别、关键词）；检测规则或阈值变化后，下一次全量扫描会自动忽略台账，对未变化文件重扫，避免旧文件漏检新规则。
- **启动对账、定时对账、手动 `scan` 都复用同一套台账**；`--force` 可忽略台账。
- **删除清理**：对账结束时检查台账中位于扫描根目录下、但已不存在的文件，清理其台账与命中记录（watcher 删除事件也会即时清理）。
- `findings` 表按路径事务替换；重扫时读取旧 `match_hash`，保留用户已确认状态，并只把真正新增的哈希计入“新发现”。
- 数据库开启 WAL，读写不互相阻塞；写操作串行化在一个 `Mutex<Connection>` 后，扫描线程只做短事务。

### 4.4 编码与文档抽取

- 纯文本：UTF-8 直接使用；BOM UTF-16 使用 encoding_rs；非法 UTF-8 用 chardetng 猜测（覆盖 GBK/GB18030）。
- Office Open XML（`.docx/.xlsx/.pptx`）：zip 解包后提取 `word/document.xml`、`xl/sharedStrings.xml`、`xl/worksheets/*.xml`、`ppt/slides/*.xml`，剥离 XML 标签、解码实体。
- 旧版 `.doc/.xls/.ppt`、PDF、图片 OCR：v1 跳过，架构中预留 `Extractor` 扩展点。
- 压缩包默认跳过，避免解压炸弹与“压缩包内敏感文件”的合规争议；可在路线图中加白名单解压策略。

### 4.5 规则匹配细节

- 每条规则包含：`id / name / category / severity / regex / keywords / validators / description`。
- **第一个捕获组即敏感值**；无捕获组时使用整段匹配。这样密码规则可以只把 `secret=` 后面的值作为命中，而不是整行。
- Rust `regex` 不支持 lookaround，规则统一用 `\b` 与校验器替代零宽断言。
- 自定义规则直接写正则，支持 `keywords`（上下文必须出现其一）和 `validator`（`none/luhn/cn_id/phone/entropy:3.2/placeholder`）。
- 规则编译失败在启动时报错并指出规则 ID，避免静默失效。

---

## 5. 内置规则清单（v1）

| 规则 ID | 名称 | 严重级别 | 校验 |
|---|---|---|---|
| `cn_id_card` | 中国大陆居民身份证号（18 位） | 高 | 校验位 + 出生日期 |
| `cn_id_card_15` | 一代身份证号（15 位） | 中 | 出生日期 |
| `cn_mobile` | 中国大陆手机号 | 中 | 号段 + 无效号过滤 |
| `cn_landline` | 固定电话 | 低 | 格式 |
| `email` | 电子邮箱 | 中 | 格式 + 占位符过滤 |
| `bank_card` | 银行卡号（紧凑格式） | 高 | Luhn + BIN 前缀 |
| `bank_card_formatted` | 银行卡号（4 位分组） | 高 | Luhn |
| `password_assignment` | 密码赋值/配置项 | 高 | 熵 + 占位符 |
| `generic_secret` | 通用密钥/令牌赋值 | 高 | 熵 + 关键词 + 占位符 |
| `private_key` | PEM/OpenSSH 私钥头 | 严重 | 字面量 |
| `aws_access_key` | AWS Access Key ID | 严重 | `AKIA` 前缀 |
| `aws_secret_key` | AWS Secret Access Key | 严重 | 上下文 + 长度 |
| `github_token` | GitHub Token | 严重 | 前缀 |
| `google_api_key` | Google API Key | 高 | 前缀 |
| `slack_token` | Slack Token | 高 | 前缀 |
| `stripe_key` | Stripe Live Key | 严重 | 前缀 |
| `openai_key` | OpenAI API Key | 高 | 前缀 |
| `jwt` | JSON Web Token | 中 | 三段式结构 |
| `bearer_token` | Authorization Bearer | 高 | 上下文 |
| `cn_passport` | 中国护照号 | 中 | 格式 |

> 规则表是可数据化的清单，新增规则通常只需要在 `builtin.rs` 添加一行，或在 TOML 中写自定义规则，无需改检测引擎。

---

## 6. 配置模型

配置文件默认位置：

| 平台 | 路径 |
|---|---|
| Windows | `%APPDATA%\DataSentinel\config.toml` |
| macOS | `~/Library/Application Support/DataSentinel/config.toml` |
| 麒麟/Linux | `~/.config/DataSentinel/config.toml` |

关键配置段：

```toml
[scan]
roots = []                    # 空 = 自动探测桌面/文档/下载（含中文目录名）
allow_globs = []              # 可信路径，永不扫描
exclude_globs = []            # 追加排除
use_default_excludes = true   # 内置缓存/VCS/二进制排除
include_extensions = []       # 空 = 内置文本/Office 扩展名 + 内容嗅探
max_file_size_mb = 64
threads = 0                   # 0 = 自动
scan_on_startup = true
full_scan_interval_hours = 24 # 0 = 关闭定时对账

[watch]
enabled = true
debounce_ms = 2000
ignore_temp_files = true

[notify]
enabled = true
min_severity = "medium"
mode = "summary"              # summary | per_file | off

[storage]
database = ""                 # 空 = 平台数据目录
reports_dir = ""
store_raw_match = false       # 默认只存脱敏值

[rules]
disabled = []
min_severity = "low"
# [[rules.custom]] ...
```

配置解析使用 serde 默认值，旧配置缺字段可平滑升级；`sentinel config show` 输出最终生效配置。

---

## 7. 存储与报告

### 7.1 SQLite 表

```sql
files(path PK, size, mtime, content_hash, last_scanned, status)
findings(id PK, path, rule_id, rule_name, category, severity,
         masked, match_hash, line, snippet, detected_at,
         acknowledged, UNIQUE(path, rule_id, match_hash))
scan_runs(id PK, started_at, finished_at, roots, files_scanned,
          findings, new_findings, status)
meta(key PK, value)
```

- `masked` 与 `snippet` 均不包含完整敏感值；`match_hash` 用于去重与确认。
- 可选 `store_raw_match = true` 才保存原始值（不推荐，文档中明确风险）。
- `retention_days` 控制历史发现清理。

### 7.2 报告

- `sentinel report --format html`：自包含单文件 HTML，含严重级别筛选、时间、路径、规则、脱敏片段；适合发给安全管理员。
- `sentinel report --format json`：供 SIEM/资产平台二次消费。
- 报告默认写入数据目录 `reports/`，也可 `--out` 指定。

---

## 8. 桌面通知

| 平台 | 主通道 | 降级 |
|---|---|---|
| Windows 10/11 | PowerShell + WinRT `Windows.UI.Notifications` Toast | `msg *` |
| macOS | 中危+：`osascript display alert` 系统对话框（不受专注模式影响）；低危：通知中心横幅 | 日志 |
| 麒麟 / Linux | `notify-send`（D-Bus `org.freedesktop.Notifications`） | `zenity` → `kdialog` → `xmessage` |

- macOS 默认 `notify.macos_mode = "auto"`：中危及以上的命中直接弹系统对话框，避免通知中心被专注模式/勿扰静默抑制；`alert` / `notification` 可切换。
- 通知内容只包含“文件数 / 命中数 / 最高级别 / 示例文件名与规则名”，不包含敏感明文。
- 所有平台通过 `Command` 直接传参，不经过 shell，避免命令注入。
- `sentinel notify-test` 用于验证桌面通知链路。

---

## 9. 开机自启

| 平台 | 机制 | 说明 |
|---|---|---|
| Windows | 任务计划程序 `schtasks /SC ONLOGON` | 登录后延迟 30s 启动，失败回退 `HKCU\...\Run` 注册表 |
| macOS | `~/Library/LaunchAgents/com.datasentinel.scanner.plist` | `RunAtLoad=true`，`launchctl bootstrap gui/$UID`，失败回退 `load -w` |
| 麒麟/Linux | `~/.config/systemd/user/data-sentinel.service` | `WantedBy=default.target`，`systemctl --user enable --now`；无 systemd 时写 XDG autostart `.desktop` |

守护进程启动后先做一次“对账扫描”，再进入 watcher 循环；即使自启项只负责拉起进程，也不会漏掉关机期间的变化。

`sentinel autostart install|uninstall|status` 幂等操作，路径使用当前可执行文件绝对路径与配置绝对路径。

---

## 10. 安全、合规与运维

- **不联网**：无遥测、无云端；未来若加上报必须显式配置并二次确认。
- **最小数据**：默认不存原文；报告与数据库 Unix 权限 `0600`，目录 `0700`。
- **排除自身**：数据库、日志、报告目录自动加入排除，避免扫描结果再次触发通知。
- **性能保护**：文件大小上限、解压上限、线程上限、临时文件过滤、失败重试上限。
- **可观测性**：日志按天滚动；`scan_runs` 记录每次扫描统计；`sentinel findings` 查看最近命中。
- **升级兼容**：配置 serde 默认值；数据库 `meta.schema_version` 预留迁移。
- **已知限制**：用户态 watcher 在网络盘/部分 FUSE 文件系统上可能丢事件，依赖定时对账兜底；恶意软件可绕过；不替代专业 DLP。

---

## 11. 路线图

1. **v1（本仓库）**：三平台 CLI + 全量/增量扫描 + 内置规则 + 脱敏存储 + 通知 + 自启。
2. **v1.1**：PDF 文本抽取、更多 Office 旧格式、规则热加载、配置变更自动 reload。
3. **v1.2**：系统托盘/轻量 GUI（Tauri 或原生 tray），发现列表与一键确认。
4. **v2**：图片 OCR、压缩包策略、企业策略下发（可选、显式开启）、SIEM 导出。
5. **性能增强**：Aho-Corasick 多锚点、SIMD 字面量预筛、按扩展名分派专用扫描器、增量索引。

---

## 12. 验收标准

- 三平台 `cargo build --release` 通过，产物为单文件可执行程序。
- 首次运行自动生成配置；`sentinel scan` 能扫描默认目录并输出统计。
- 样例文本中的身份证、手机号、银行卡、密码、私钥、云密钥均能命中；无效身份证校验位、无效 Luhn 卡号不命中。
- 修改文件后 2–5 秒内 watcher 触发增量扫描；未修改文件在全量对账中被跳过。
- 命中后桌面出现通知，通知中无敏感明文。
- `sentinel report --format html` 生成可离线打开的报告。
- `sentinel autostart install` 后重启/重新登录，守护进程自动运行并完成一次对账扫描。
