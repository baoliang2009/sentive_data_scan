//! `sentinel-server` 入口：集中接收告警、下发规则、提供管理控制台。

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use data_sentinel::server::{self, auth, config::ServerConfig};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sentinel-server",
    version,
    about = "数据哨兵服务端：集中接收敏感数据告警、统一下发检测规则",
    long_about = "sentinel-server 汇总各终端通过 syslog 上报的敏感数据命中，\
                  提供按用户/类型/级别的筛选视图，并统一维护下发检测规则。\
                  数据全部保存在本地 SQLite，不依赖外部服务。"
)]
struct Cli {
    /// 服务端配置文件路径（默认使用平台配置目录下的 server.toml）
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// 输出调试日志
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// 启动服务端（默认命令）
    Run,
    /// 显示配置文件路径
    ConfigPath,
    /// 显示最终生效配置
    ConfigShow,
    /// 重新写入默认配置
    ConfigInit {
        /// 覆盖已有配置文件
        #[arg(long)]
        force: bool,
    },
    /// 生成管理口令的 PBKDF2 记录，可粘贴到 server.toml
    PasswordHash {
        /// 明文口令；省略则从标准输入读取
        password: Option<String>,
    },
    /// 打印当前 Agent Token（用于配置客户端）
    AgentToken,
    /// 服务端自检：数据库可读写、规则可编译
    Doctor,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("错误: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let command = cli.command.unwrap_or(Command::Run);
    init_logging(cli.verbose);

    match command {
        Command::Run => server::run(cli.config),
        Command::ConfigPath => {
            println!(
                "{}",
                server::config::resolve_server_config_path(cli.config.as_deref()).display()
            );
            Ok(())
        }
        Command::ConfigShow => {
            let (config, _path) = ServerConfig::load(cli.config.as_deref())?;
            // 打印前脱敏凭据，避免口令哈希/token 出现在终端历史或截图里。
            let mut safe = config.clone();
            if !safe.auth.admin_password_hash.is_empty() {
                safe.auth.admin_password_hash = "<已配置>".to_string();
            }
            if !safe.auth.agent_token.is_empty() {
                safe.auth.agent_token = "<已配置>".to_string();
            }
            println!("{}", toml::to_string_pretty(&safe)?);
            Ok(())
        }
        Command::ConfigInit { force } => {
            let path = server::config::resolve_server_config_path(cli.config.as_deref());
            server::config::write_default_server_config(&path, force)?;
            println!("已写入默认服务端配置：{}", path.display());
            Ok(())
        }
        Command::PasswordHash { password } => {
            let password = match password {
                Some(password) => password,
                None => read_password()?,
            };
            auth::validate_password_strength(&password)?;
            println!("{}", auth::hash_password(&password));
            Ok(())
        }
        Command::AgentToken => {
            let (config, _path) = ServerConfig::load(cli.config.as_deref())?;
            if config.auth.agent_token.trim().is_empty() {
                println!("尚未生成 Agent Token，启动一次服务端即可自动生成");
            } else {
                println!("{}", config.auth.agent_token);
            }
            Ok(())
        }
        Command::Doctor => doctor(cli.config),
    }
}

fn doctor(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let (config, path) = ServerConfig::load(config_path.as_deref())?;
    println!("配置文件：{}", path.display());
    println!("数据库：{}", config.database_path().display());

    let store = server::store::ServerStore::open(&config.database_path())?;
    let rules = store.current_rules()?;
    match &rules {
        Some(doc) => println!(
            "规则：v{}，{} 条自定义规则",
            doc.revision,
            doc.rules.custom.len()
        ),
        None => println!("规则：尚未发布（客户端将使用内置默认规则）"),
    }
    println!(
        "syslog：{}（{}）",
        if config.ingest.enabled {
            "启用"
        } else {
            "关闭"
        },
        config.ingest.bind
    );
    println!("控制台：http://{}", config.server.bind);
    println!("自检通过");
    Ok(())
}

fn read_password() -> anyhow::Result<String> {
    use std::io::{BufRead, Write};
    if std::io::stdin().is_terminal() {
        eprint!("请输入口令：");
        std::io::stderr().flush().ok();
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        anyhow::bail!("口令不能为空");
    }
    Ok(password)
}

fn init_logging(verbose: bool) {
    let level = if verbose {
        "debug".to_string()
    } else {
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
    };
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
