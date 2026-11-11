use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    version,
    about = "数据哨兵：本地敏感数据扫描与落盘监控",
    long_about = "DataSentinel 在本地扫描常用目录与文件落盘变更，识别身份证、手机号、银行卡、密码、私钥等敏感数据，并通过桌面通知提醒。所有数据默认只保存在本机。"
)]
pub struct Cli {
    /// 配置文件路径（默认使用平台配置目录）
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 输出调试日志
    #[arg(long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 打开本地图形控制台（浏览器界面）
    Ui(UiArgs),
    /// 扫描目录（默认扫描配置中的常用目录）
    Scan(ScanArgs),
    /// 前台运行落盘监控 + 定时对账
    Watch(WatchArgs),
    /// 同 watch，供开机自启使用
    Daemon(WatchArgs),
    /// 查看最近的敏感数据命中
    Findings(FindingsArgs),
    /// 导出 HTML / JSON 报告
    Report(ReportArgs),
    /// 确认（忽略）历史命中
    Ack(AckArgs),
    /// 查看或测试检测规则
    Rules(RulesArgs),
    /// 配置文件操作
    Config(ConfigArgs),
    /// 安装/卸载/查看开机自启
    Autostart(AutostartArgs),
    /// 发送一条测试桌面通知
    #[command(name = "notify-test")]
    NotifyTest,
    /// 显示版本信息
    Version,
}

#[derive(Debug, Args)]
pub struct UiArgs {
    /// 监听端口；0 表示由系统分配，端口被占用时自动顺延
    #[arg(long, default_value_t = 7419)]
    pub port: u16,

    /// 启动后不自动打开浏览器
    #[arg(long)]
    pub no_open: bool,

    /// 不启动后台落盘监控（默认随控制台一起运行，落盘即提醒）
    #[arg(long)]
    pub no_watch: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// 指定扫描目录或文件，可重复：--path ~/Desktop --path ~/work
    #[arg(long = "path", value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// 忽略增量台账，强制重新扫描
    #[arg(long)]
    pub force: bool,

    /// 扫描完成不弹桌面通知
    #[arg(long)]
    pub no_notify: bool,

    /// 以 JSON 输出扫描统计
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args, Default)]
pub struct WatchArgs {
    /// 覆盖配置，启动时不执行对账扫描
    #[arg(long)]
    pub no_startup_scan: bool,
}

#[derive(Debug, Args)]
pub struct FindingsArgs {
    /// 最多显示多少条
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// 只看某个级别及以上：info/low/medium/high/critical
    #[arg(long)]
    pub severity: Option<String>,

    /// 包含已确认的记录
    #[arg(long)]
    pub all: bool,

    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// html 或 json
    #[arg(long, default_value = "html")]
    pub format: String,

    /// 输出文件路径；默认写入平台数据目录 reports/
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// 导出最近多少天；0 表示全部
    #[arg(long, default_value_t = 30)]
    pub days: u64,
}

#[derive(Debug, Args)]
pub struct AckArgs {
    /// 确认全部未确认命中
    #[arg(long)]
    pub all: bool,

    /// 确认指定 ID，可重复：--id 12 --id 15
    #[arg(long = "id", value_name = "ID")]
    pub ids: Vec<i64>,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// 列出所有规则
    List,
    /// 对文本或文件执行规则测试
    Test(TestArgs),
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// 直接测试一段文本
    #[arg(long)]
    pub text: Option<String>,

    /// 测试一个文件（支持文本与 docx/xlsx/pptx）
    #[arg(value_name = "FILE")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// 显示当前配置文件路径
    Path,
    /// 显示最终生效配置（TOML）
    Show,
    /// 重新写入默认配置
    Init {
        /// 覆盖已有配置文件
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
pub struct AutostartArgs {
    #[command(subcommand)]
    pub command: AutostartCommand,
}

#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    /// 安装当前用户的开机/登录自启
    Install,
    /// 移除自启
    Uninstall,
    /// 查看自启状态
    Status,
}
