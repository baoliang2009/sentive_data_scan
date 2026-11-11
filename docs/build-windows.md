# Windows 构建与使用

## 结论：必须使用 Windows 版本的二进制

Rust 编译产物是**原生平台二进制**，不是跨平台字节码：

- 当前仓库里的 `target/release/sentinel` 是 macOS ARM64 的 Mach-O 文件，**不能**在 Windows 上运行。
- Windows 需要重新编译出 `sentinel.exe`（x86_64 PE 文件），或直接使用 GitHub Actions 构建的 Windows 产物。
- 源码、配置格式、检测规则、数据库结构完全一致，只是需要对应平台的编译产物。

## 方式一：在 Windows 上原生编译（推荐）

### 1. 安装 Rust

安装 [rustup](https://rustup.rs/)，选择默认工具链：

```powershell
rustup default stable-x86_64-pc-windows-msvc
rustc --version
cargo --version
```

### 2. 安装 C 编译环境

项目使用 `rusqlite` 的 `bundled` 特性，会编译内置 SQLite C 代码，因此需要 MSVC：

- 安装 **Visual Studio 2022 Build Tools**；
- 勾选 **“使用 C++ 的桌面开发”**（Desktop development with C++）；
- 确保其中包含 Windows 10/11 SDK 和 MSVC v143 编译器。

如果 `cargo build` 报 `link.exe not found`，基本就是缺少这个组件。

### 3. 编译

```powershell
cd path\to\sentive_data

cargo build --release --locked

# 产物
.\target\release\sentinel.exe version
```

### 4. 运行

```powershell
# 首次运行会生成配置：
# %APPDATA%\DataSentinel\config.toml
.\target\release\sentinel.exe config path

# 扫描默认目录（桌面/文档/下载）
.\target\release\sentinel.exe scan

# 指定目录、强制全量
.\target\release\sentinel.exe scan --force --path "$env:USERPROFILE\Desktop"

# 前台运行落盘监控 + 定时对账
.\target\release\sentinel.exe daemon

# 查看命中、导出报告
.\target\release\sentinel.exe findings --limit 30
.\target\release\sentinel.exe report --format html --days 30

# 测试桌面 Toast
.\target\release\sentinel.exe notify-test

# 安装登录自启（不需要管理员权限）
.\target\release\sentinel.exe autostart install
```

Windows 下：

- 配置：`%APPDATA%\DataSentinel\config.toml`
- 数据库/日志/报告：`%LOCALAPPDATA%\DataSentinel\`
- 桌面提醒：PowerShell + WinRT Toast；Toast 不可用时回退 `msg`
- 自启：任务计划程序（登录后延迟 30 秒），失败回退 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### 5. 可选：打包成单文件分发

MSVC release 产物已经是单个 `sentinel.exe`，SQLite 与 VC 运行库都已静态内置（仓库里的 `.cargo/config.toml` 为 Windows MSVC 目标开启了 `+crt-static`）。直接复制这个 exe 到其他 Windows 机器即可，无需安装 Rust，也无需安装 Visual C++ Redistributable。

如果希望双击启动或隐藏控制台窗口，可以使用任务计划程序启动 `sentinel.exe daemon`；当前版本由控制台程序启动时可能闪现一次窗口。

## 方式二：在 macOS/Linux 上交叉编译（可选）

需要 `mingw-w64` 和 GNU Windows target：

```bash
# macOS
brew install mingw-w64

rustup target add x86_64-pc-windows-gnu

export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

cargo build --release --target x86_64-pc-windows-gnu --locked

# 产物
ls target/x86_64-pc-windows-gnu/release/sentinel.exe
```

检查依赖 DLL：

```bash
x86_64-w64-mingw32-objdump -p target/x86_64-pc-windows-gnu/release/sentinel.exe \
  | grep "DLL Name"
```

如果出现 `libgcc_s_seh-1.dll` 或 `libwinpthread-1.dll`，需要一并分发这些 DLL，或改用 Windows 原生 MSVC 编译。生产分发优先推荐方式一。

## 方式三：使用 GitHub Actions 产物

仓库已包含 `.github/workflows/ci.yml`，在 GitHub 上运行后会产出：

- `sentinel-windows-x86_64`（Windows exe）
- `sentinel-macos-*`
- `sentinel-linux-x86_64`

在 Actions 运行详情页的 **Artifacts** 区域下载对应平台产物即可。

## 常见问题

### `link.exe not found`

安装 Visual Studio Build Tools 的“使用 C++ 的桌面开发”工作负载，或改用 `x86_64-pc-windows-gnu` 工具链。

### 编译 `sqlite3.c` 失败

缺少 C 编译器或 Windows SDK。确认 MSVC Build Tools 安装完整，然后在 **“x64 Native Tools Command Prompt for VS”** 中执行 `cargo build --release`。

### 运行时报缺少 DLL

如果双击 `sentinel.exe` 时弹出“无法启动此程序，因为计算机中丢失 VCRUNTIME140.dll”，说明拿到的是旧版本二进制。仓库已通过 `.cargo/config.toml` 为 Windows MSVC 目标开启 `+crt-static`，重新执行 `cargo build --release`（或下载最新 GitHub Release 产物）即可，运行库会一并打包进 exe。

可以用下面的命令确认新产物不再依赖 `VCRUNTIME140.dll`：

```powershell
dumpbin /dependents .\target\release\sentinel.exe
```

如果使用 GNU 交叉编译，按上面的 DLL 检查结果补充分发 `libgcc_s_seh-1.dll` 等文件，生产分发仍优先推荐方式一。

### SmartScreen / 杀毒软件提示

这是未签名的新二进制，可能出现“Windows 已保护你的电脑”。点击“更多信息 → 仍要运行”。正式分发建议做代码签名。

### 没有弹出 Toast / 通知时报错

- 确认 `config.toml` 中 `[notify] enabled = true`；
- 运行 `sentinel.exe notify-test`；
- 当前实现通过 `powershell.exe -EncodedCommand` 发送 WinRT Toast（不落地临时 `.ps1`，也不依赖脚本执行策略），并用 `CREATE_NO_WINDOW` 隐藏控制台窗口；
- PowerShell 失败时日志里会有一条 `PowerShell Toast 发送失败，尝试 msg 降级`，其中 `stderr` 字段是 PowerShell 的原始报错，按它排查即可；
- Windows 家庭版或通知服务异常时会回退 `msg` 弹窗；
- 检查“设置 → 系统 → 通知”是否允许 Windows PowerShell 通知；
- 如果日志显示 `Windows Toast 与 msg 通知均失败`，优先检查通知服务（`Get-Service WpnService`）以及是否处于“专注助手/勿扰”模式。

### 想扫描其他盘符

在 `config.toml` 中配置：

```toml
[scan]
roots = ["C:\\Users\\你的用户名\\Desktop", "D:\\work", "E:\\资料"]
```

Windows 路径在 TOML 中建议使用双反斜杠或正斜杠：

```toml
roots = ["C:/Users/me/Desktop", "D:/work"]
```
