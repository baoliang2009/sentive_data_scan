# DataSentinel 数据哨兵

跨平台（Windows / 银河麒麟及主流 Linux / macOS）的**本地敏感数据扫描器**。开机自动巡检常用目录，常驻监听文件落盘变更，发现身份证、手机号、银行卡、密码、私钥、云密钥等敏感信息后弹出桌面通知，并把脱敏结果保存在本地 SQLite。

> 数据不出本机；默认不保存命中原文。

## 功能

- **全量巡检**：扫描桌面、文档、下载（含麒麟/Linux 的中文 XDG 目录名），也可配置任意目录。
- **增量扫描**：`notify` 监听创建/修改/重命名，去抖后只扫描变化文件，不必反复全量遍历。
- **规则变更补偿**：修改规则、阈值或自定义规则后，下次扫描会自动重扫未变化文件，避免新规则漏检旧文件。
- **对账补偿**：启动、定时对账按 `size + mtime` 跳过未变化文件，关机期间漏掉的事件也能补齐。
- **内置规则**：身份证（18/15 位）、手机号、座机、邮箱、银行卡（Luhn）、密码、通用密钥、PEM 私钥、AWS/GitHub/Google/Slack/Stripe/OpenAI Token、JWT、Bearer、护照等。
- **高精度**：身份证校验位/出生日期、银行卡 Luhn、熵值、占位符过滤、关键词上下文、跨块去重。
- **Office 抽取**：直接扫描 `.docx/.xlsx/.pptx` 内部文本。
- **脱敏存储**：只保存 `110105********002X` 这类脱敏值、行号、上下文和哈希；支持 HTML/JSON 报告。
- **本地控制台**：`sentinel ui` 启动图形界面（概览 / 命中记录 / 检测规则 / 设置），带实时扫描进度、筛选搜索、批量确认与报告导出；仅监听 `127.0.0.1`，三平台统一用系统浏览器打开。
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
| `sentinel ui [--port 7419] [--no-open]` | 启动本地图形控制台（浏览器界面） |
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

## 图形控制台

```bash
sentinel ui                 # 打开 http://127.0.0.1:7419/
sentinel ui --port 8080     # 指定端口（被占用时自动顺延）
sentinel ui --no-open       # 只启动服务，不打开浏览器
```

| 页面 | 内容 |
|---|---|
| 概览 | 未确认 / 严重高危计数、级别与分类分布、最近命中、扫描历史、上次扫描结果 |
| 命中记录 | 按级别、状态、类型筛选，关键词搜索，批量确认，右侧详情含脱敏值、上下文与文件定位 |
| 检测规则 | 内置规则逐条开关，在线测试文本（结果同样只显示脱敏值） |
| 设置 | 扫描目录、大小上限、线程数、通知策略、保留天数、开机自启、直接编辑 `config.toml` |

设计取舍：

- **不引入 WebView / Tauri**：界面由同一个二进制内置提供，三平台都用系统自带浏览器打开。麒麟上无需安装 WebKitGTK，产物仍是单文件可执行，CI 三平台构建流程不变。
- **只监听回环地址**：绑定 `127.0.0.1`，并用随机会话令牌校验 `X-Sentinel-Token`，其他网页无法驱动本机接口。
- **改配置保留注释**：开关规则、修改设置只就地改写对应键值，不会冲掉 `config.toml` 里的注释；写入前备份为 `config.toml.bak`。
- **控制台不替代守护进程**：它是查看与操作入口；需要落盘实时监控仍用 `sentinel daemon`，或在设置页安装开机自启。

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

[storage]
store_raw_match = false         # 默认只存脱敏值

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

- `pattern` 使用 Rust `regex` 语法，不支持 lookaround。
- 第一个捕获组视为敏感值；没有捕获组时使用整段匹配。
- `validator` 支持 `none`、`luhn`、`cn_id`、`cn_id_15`、`phone`、`placeholder`、`entropy:3.2`，可逗号组合。
- `keywords` 要求命中附近出现任一关键词，用于降低误报。

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
- Toast 通过 PowerShell + WinRT 发送；极端情况下回退 `msg`。
- 自启优先写入任务计划（登录后延迟 30 秒），失败回退 `HKCU\...\Run`。
- 任务计划以控制台程序启动时可能闪现一次窗口；后续可替换为托盘程序或 `windows_subsystem` 包装器。

### macOS

- Intel / Apple Silicon 均可编译。
- 默认 `notify.macos_mode = "auto"`：中危及以上的命中使用 `osascript display alert` 系统对话框，**不会被“专注模式/勿扰”静默拦截**；低危走通知中心。
- 如需只用横幅通知，设置 `macos_mode = "notification"`，并在“系统设置 → 通知 → Script Editor”中允许通知；同时关闭专注模式。
- 自启写入 `~/Library/LaunchAgents/com.datasentinel.scanner.plist`。

### 银河麒麟 / Linux

- 依赖桌面通知服务；UKUI/GNOME/KDE 通常已自带 `notify-send`。无 `notify-send` 时自动尝试 `kdialog/zenity/xmessage`。
- 自启优先 systemd 用户服务（`~/.config/systemd/user/data-sentinel.service`），无 systemd 用户实例时回退 XDG autostart。
- 常见 x86_64 / aarch64 环境可直接在本机 `cargo build --release`；LoongArch 需确认 Rust 工具链对该 target 的支持。
- 建议在目标发行版或较老的 glibc 环境中编译（或使用 musl 静态构建），避免跨发行版 glibc 不兼容。
- 中文目录通过读取 `~/.config/user-dirs.dirs` 自动识别（桌面/文档/下载）。
- 大规模目录可能触及 `inotify` 的 `max_user_watches` 上限；监听失败会记录日志，并由启动/定时对账兜底。

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
- 全部检测、存储、通知在本地完成，无网络请求。

## 测试

```bash
cargo test
```

覆盖：身份证校验位、Luhn、手机号、占位符、编码识别、分块边界、规则引擎、SQLite 去重/确认状态。

## 目录结构

```
src/
  main.rs        CLI 分发、日志
  cli.rs         clap 定义
  config.rs      配置与常用目录探测
  model.rs       Finding / 统计模型
  rules/         规则集、内置规则、校验器
  detect.rs      编码、二进制嗅探、Office 抽取
  scan.rs        遍历、并行、增量台账
  watch.rs       notify 监听与去抖
  store.rs       SQLite
  notify.rs      三平台桌面通知
  autostart.rs   三平台自启
  report.rs      HTML/JSON 报告
  util.rs        脱敏、哈希、片段、转义
tests/           集成测试
docs/            架构设计
```

## 已知限制

- 用户态 watcher 在网络盘或部分 FUSE 文件系统上可能丢事件，依赖启动/定时对账兜底。
- PDF、旧版 `.doc/.xls/.ppt`、图片 OCR、压缩包内文件暂不支持（架构已预留扩展点）。
- 不是内核级 DLP，不能阻断写盘；只做本地发现与提醒。
- 恶意程序可以绕过用户态扫描，本工具用于个人隐私自查与日常卫生，不替代企业级 DLP。

## License

MIT
