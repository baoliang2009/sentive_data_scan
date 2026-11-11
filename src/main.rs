use std::io;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Parser;
use data_sentinel::cli::{
    AckArgs, AutostartCommand, Cli, Command, ConfigCommand, FindingsArgs, RulesCommand, ScanArgs,
    TestArgs,
};
use data_sentinel::config::{self, expand_path, write_default_config, Config};
use data_sentinel::detect::{Detector, ExtractOutcome};
use data_sentinel::model::{category_label, ScanSummary, Severity, StoredFinding};
use data_sentinel::notify::Notifier;
use data_sentinel::rules::RuleSet;
use data_sentinel::scan::Scanner;
use data_sentinel::store::Store;
use data_sentinel::util::{format_duration, format_ts, truncate_chars};
use data_sentinel::{autostart, report, watch};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("错误: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    if let Command::Version = &cli.command {
        println!(
            "DataSentinel {} ({})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        );
        return Ok(());
    }

    let (mut config, config_path) = Config::load(cli.config.as_deref())?;
    let _log_guard = init_logging(&config, cli.verbose);

    match cli.command {
        Command::Version => {
            println!(
                "DataSentinel {} ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            );
            Ok(())
        }
        Command::Ui(args) => {
            let watch_active = if args.no_watch {
                tracing::info!("已通过 --no-watch 关闭后台落盘监控");
                false
            } else if !config.watch.enabled {
                tracing::info!("配置 watch.enabled = false，控制台不会监听落盘变更");
                false
            } else {
                match start_background_watch(&config) {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::warn!(error = %error, "后台落盘监控启动失败，控制台仍可手动扫描");
                        eprintln!("落盘监控启动失败：{error:#}");
                        false
                    }
                }
            };
            data_sentinel::webui::run(cli.config.clone(), args.port, !args.no_open, watch_active)
        }
        Command::Config(args) => handle_config(&config, &config_path, args.command),
        Command::Autostart(args) => handle_autostart(&config_path, args.command),
        Command::NotifyTest => Notifier::new(&config.notify).test(),
        Command::Scan(args) => {
            let store = open_store(&config)?;
            let rules = RuleSet::build(&config.rules)?;
            let scanner = Scanner::new(Arc::new(config.clone()), store, rules)?;
            let roots = resolve_scan_roots(&config, &args);
            let summary = scanner.scan_roots(&roots, args.force);
            print_summary(&summary, args.json)?;
            if !args.no_notify {
                Notifier::new(&config.notify).notify_scan(&summary);
            }
            Ok(())
        }
        Command::Watch(args) | Command::Daemon(args) => {
            if args.no_startup_scan {
                config.scan.scan_on_startup = false;
            }
            let store = open_store(&config)?;
            let rules = RuleSet::build(&config.rules)?;
            let scanner = Arc::new(Scanner::new(Arc::new(config.clone()), store, rules)?);
            let notifier = Notifier::new(&config.notify);
            watch::run(Arc::new(config), scanner, notifier)
        }
        Command::Findings(args) => {
            let store = open_store(&config)?;
            let findings = load_findings(&store, &args)?;
            print_findings(&findings, args.json)?;
            Ok(())
        }
        Command::Report(args) => {
            let store = open_store(&config)?;
            let path = report::export(
                &store,
                &config,
                &args.format,
                args.out.as_deref(),
                args.days,
            )?;
            println!("报告已生成: {}", path.display());
            Ok(())
        }
        Command::Ack(args) => {
            let store = open_store(&config)?;
            let updated = acknowledge(&store, &args)?;
            println!("已确认 {updated} 条命中记录");
            Ok(())
        }
        Command::Rules(args) => {
            let rules = RuleSet::build(&config.rules)?;
            match args.command {
                RulesCommand::List => {
                    print_rules(&rules);
                    Ok(())
                }
                RulesCommand::Test(test) => run_rule_test(&config, rules, test),
            }
        }
    }
}

fn resolve_scan_roots(config: &Config, args: &ScanArgs) -> Vec<PathBuf> {
    if args.paths.is_empty() {
        config.effective_roots()
    } else {
        args.paths
            .iter()
            .map(|path| {
                let expanded = expand_path(path);
                if expanded.is_absolute() {
                    expanded
                } else {
                    std::env::current_dir()
                        .map(|cwd| cwd.join(&expanded))
                        .unwrap_or(expanded)
                }
            })
            .collect()
    }
}

fn open_store(config: &Config) -> Result<Arc<Store>> {
    let store = Arc::new(Store::open(&config.database_path())?);
    if let Err(error) = store.prune(config.storage.retention_days) {
        tracing::warn!(error = %error, "清理过期发现记录失败");
    }
    if !config.storage.store_raw_match {
        if let Err(error) = store.clear_raw_matches() {
            tracing::warn!(error = %error, "清理历史原文失败");
        }
    }
    Ok(store)
}

/// Spawn the filesystem watcher in a background thread so `sentinel ui` doubles
/// as a resident monitor: files that land in the scanned directories are
/// detected (and notified) without a separate `sentinel daemon` process.
fn start_background_watch(config: &Config) -> Result<()> {
    let config = Arc::new(config.clone());
    let store = open_store(&config)?;
    let rules = RuleSet::build(&config.rules)?;
    let scanner = Arc::new(Scanner::new(Arc::clone(&config), store, rules)?);
    let notifier = Notifier::new(&config.notify);

    std::thread::Builder::new()
        .name("sentinel-watch".into())
        .spawn(move || {
            if let Err(error) = watch::run_detached(config, scanner, notifier) {
                tracing::error!(error = %error, "后台落盘监控退出");
            }
        })
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn load_findings(store: &Store, args: &FindingsArgs) -> Result<Vec<StoredFinding>> {
    let severity = match args.severity.as_deref() {
        Some(value) => Some(
            value
                .parse::<Severity>()
                .map_err(|error| anyhow::anyhow!(error))?,
        ),
        None => None,
    };
    store.recent_findings(severity, args.limit.max(1), args.all)
}

fn acknowledge(store: &Store, args: &AckArgs) -> Result<usize> {
    if !args.all && args.ids.is_empty() {
        bail!("请指定 --all 或至少一个 --id");
    }
    if args.all {
        store.ack_all()
    } else {
        store.ack_ids(&args.ids)
    }
}

fn print_summary(summary: &ScanSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
        return Ok(());
    }
    println!("扫描完成，用时 {}", format_duration(summary.duration));
    println!(
        "  文件：发现 {}，扫描 {}，未变化 {}，排除 {}，跳过 {}，失败 {}",
        summary.files_seen,
        summary.files_scanned,
        summary.files_unchanged,
        summary.files_excluded,
        summary.files_skipped,
        summary.files_failed
    );
    println!(
        "  命中：{} 处（新增 {}）",
        summary.findings, summary.new_findings
    );
    if !summary.by_severity.is_empty() {
        let mut parts = Vec::new();
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            if let Some(count) = summary.by_severity.get(&severity) {
                parts.push(format!("{} {}", severity.label_zh(), count));
            }
        }
        println!("  级别：{}", parts.join(" / "));
    }
    if !summary.examples.is_empty() {
        println!("  示例：");
        for example in &summary.examples {
            println!(
                "    [{}] {} · {} 第 {} 行",
                example.severity.label_zh(),
                example.rule_name,
                truncate_chars(&example.path, 72),
                example.line
            );
        }
    }
    Ok(())
}

fn print_findings(findings: &[StoredFinding], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(findings)?);
        return Ok(());
    }
    if findings.is_empty() {
        println!("没有找到符合条件的结果。");
        return Ok(());
    }
    println!(
        "{:<19} {:<6} {:<26} {:<60} 行",
        "时间", "级别", "规则", "文件"
    );
    for finding in findings {
        println!(
            "{:<19} {:<6} {:<26} {:<60} {}",
            format_ts(finding.detected_at),
            finding.severity.label_zh(),
            truncate_chars(&finding.rule_name, 24),
            truncate_chars(&finding.path, 58),
            finding.line
        );
        println!("  脱敏值: {}", finding.masked);
        if !finding.snippet.is_empty() {
            println!("  上下文: {}", truncate_chars(&finding.snippet, 140));
        }
        if finding.acknowledged {
            println!("  状态: 已确认");
        }
    }
    Ok(())
}

fn print_rules(rules: &RuleSet) {
    println!(
        "{:<24} {:<6} {:<10} {:<28} 校验器",
        "ID", "级别", "分类", "名称"
    );
    for rule in rules.rules() {
        let validators = rule
            .validators
            .iter()
            .map(|validator| validator.describe())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{:<24} {:<6} {:<10} {:<28} {}",
            rule.id,
            rule.severity.label_zh(),
            category_label(&rule.category),
            rule.name,
            if validators.is_empty() {
                "-".to_string()
            } else {
                validators
            }
        );
        if !rule.description.is_empty() {
            println!("   {}", rule.description);
        }
    }
    println!(
        "\n共 {} 条规则。可在配置文件的 [rules] 段关闭规则或添加自定义规则。",
        rules.rules().len()
    );
}

fn run_rule_test(config: &Config, rules: RuleSet, args: TestArgs) -> Result<()> {
    let detector = Detector::new(rules, config);
    let (text, path) = match (args.text, args.path) {
        (Some(text), _) => (text, PathBuf::from("<inline>")),
        (None, Some(path)) => match detector.extract_file(&path)? {
            ExtractOutcome::Content(content) => (content.text, path),
            ExtractOutcome::Skip(reason) => {
                println!("文件未扫描：{reason}");
                return Ok(());
            }
        },
        (None, None) => bail!("请提供 --text 或文件路径"),
    };

    let findings = detector.detect(&text, &path);
    if findings.is_empty() {
        println!("未发现敏感数据。");
        return Ok(());
    }
    println!("发现 {} 处敏感数据（值已脱敏）：", findings.len());
    for finding in findings {
        println!(
            "  [{}] {} · 第 {} 行\n    值: {}\n    上下文: {}",
            finding.severity.label_zh(),
            finding.rule_name,
            finding.line,
            finding.masked,
            truncate_chars(&finding.snippet, 160)
        );
    }
    Ok(())
}

fn handle_config(config: &Config, config_path: &Path, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Path => {
            println!("{}", config_path.display());
            Ok(())
        }
        ConfigCommand::Show => {
            print!("{}", toml::to_string_pretty(config)?);
            Ok(())
        }
        ConfigCommand::Init { force } => {
            write_default_config(config_path, force)?;
            println!("已写入默认配置: {}", config_path.display());
            Ok(())
        }
    }
}

fn handle_autostart(config_path: &Path, command: AutostartCommand) -> Result<()> {
    match command {
        AutostartCommand::Install => autostart::install(config_path),
        AutostartCommand::Uninstall => autostart::uninstall(),
        AutostartCommand::Status => {
            println!("{}", autostart::status()?);
            Ok(())
        }
    }
}

fn init_logging(config: &Config, verbose: bool) -> Option<WorkerGuard> {
    let level = if verbose {
        "debug".to_string()
    } else {
        config.general.log_level.clone()
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .with_target(false);

    match config::ensure_private_dir(&config.logs_dir()) {
        Ok(()) => {
            let appender = tracing_appender::rolling::daily(config.logs_dir(), "sentinel.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::registry()
                .with(filter)
                .with(stderr_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(writer)
                        .with_ansi(false)
                        .with_target(false),
                )
                .init();
            Some(guard)
        }
        Err(error) => {
            eprintln!("警告: 无法创建日志目录，仅输出到终端: {error}");
            tracing_subscriber::registry()
                .with(filter)
                .with(stderr_layer)
                .init();
            None
        }
    }
}
