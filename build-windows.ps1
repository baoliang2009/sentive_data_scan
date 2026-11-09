# 在 Windows PowerShell 中执行：
#   powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "未找到 cargo。请先安装 Rust：https://rustup.rs/ ，然后重新打开 PowerShell。"
}

Write-Host "==> 检查工具链"
rustc --version
cargo --version

Write-Host "==> 编译 release 版本（首次编译会编译内置 SQLite，耗时较长）"
cargo build --release --locked

$exe = Join-Path $PSScriptRoot "target\release\sentinel.exe"
if (-not (Test-Path $exe)) {
    throw "编译失败：未找到 $exe"
}

Write-Host ""
Write-Host "编译完成：$exe"
& $exe version

Write-Host ""
Write-Host "常用命令："
Write-Host "  $exe config path"
Write-Host "  $exe scan"
Write-Host "  $exe daemon"
Write-Host "  $exe findings --limit 30"
Write-Host "  $exe notify-test"
Write-Host "  $exe autostart install"
