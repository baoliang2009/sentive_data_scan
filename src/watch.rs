use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use notify::event::{EventKind, ModifyKind};
use notify::{Event, RecursiveMode, Watcher};

use crate::config::Config;
use crate::notify::Notifier;
use crate::scan::Scanner;
use crate::util::format_duration;

/// 文件系统事件队列上限。
///
/// `notify` 的回调在独立线程里被高频调用；如果主线程正在执行一次长扫描，
/// 无界 channel 会让事件无限堆积（内存持续上涨，扫完还要消化海量积压）。
/// 这里给队列一个硬上限，满了就丢弃并计数——落盘监控本来就是“尽力而为”，
/// 丢事件后还有定时全量对账兜底。
const EVENT_QUEUE_CAPACITY: usize = 8192;

/// 「终端在线」心跳间隔。
///
/// 服务端只用 `agents.last_seen` 表示在线状态，5 分钟一次既能让控制台在
/// 一个刷新周期内看到机器上线/离线，又不会给 syslog 链路带来明显流量。
const HEARTBEAT_INTERVAL_SECS: u64 = 300;

pub fn run(config: Arc<Config>, scanner: Arc<Scanner>, notifier: Notifier) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let running_flag = running.clone();
    if let Err(error) = ctrlc::set_handler(move || {
        running_flag.store(false, Ordering::SeqCst);
    }) {
        tracing::warn!(error = %error, "注册 Ctrl-C 处理器失败");
    }
    run_loop(config, scanner, notifier, running)
}

/// Run the watcher loop without installing a Ctrl-C handler.
///
/// Used when the watcher is embedded in a longer-lived foreground process such
/// as `sentinel ui`: the console keeps the default SIGINT behaviour, so Ctrl-C
/// still terminates the whole process instead of only stopping the watcher.
pub fn run_detached(config: Arc<Config>, scanner: Arc<Scanner>, notifier: Notifier) -> Result<()> {
    run_loop(config, scanner, notifier, Arc::new(AtomicBool::new(true)))
}

fn build_watcher(
    watch_roots: &[PathBuf],
) -> Result<(
    notify::RecommendedWatcher,
    std::sync::mpsc::Receiver<notify::Result<Event>>,
    Arc<AtomicU64>,
)> {
    let (tx, rx) = std::sync::mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));
    let dropped_in_callback = Arc::clone(&dropped);
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        match tx.try_send(result) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped_in_callback.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    })?;

    let mut watched = 0usize;
    for root in watch_roots {
        if !root.exists() {
            tracing::warn!(path = %root.display(), "监听目录不存在，已跳过");
            continue;
        }
        match watcher.watch(root, RecursiveMode::Recursive) {
            Ok(()) => {
                watched += 1;
                tracing::info!(path = %root.display(), "开始监听目录");
            }
            Err(error) => {
                tracing::warn!(path = %root.display(), error = %error, "监听目录失败");
            }
        }
    }
    if watched == 0 && !watch_roots.is_empty() {
        tracing::warn!("没有成功监听任何目录，将只依赖定时对账");
    }
    Ok((watcher, rx, dropped))
}

fn canonical_watch_roots(config: &Config) -> Vec<PathBuf> {
    config
        .watch_roots()
        .into_iter()
        .map(|path| dunce::canonicalize(&path).unwrap_or(path))
        .collect()
}

fn scan_interval(config: &Config) -> Option<Duration> {
    if config.scan.full_scan_interval_hours == 0 {
        None
    } else {
        Some(Duration::from_secs(
            config.scan.full_scan_interval_hours.saturating_mul(3600),
        ))
    }
}

fn run_loop(
    base_config: Arc<Config>,
    mut scanner: Arc<Scanner>,
    notifier: Notifier,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let store = Arc::clone(&scanner.store);
    let mut current_bundle = crate::sync::load_cached(&store);
    match crate::sync::fetch_policy(&base_config) {
        Ok(Some(bundle)) => {
            if current_bundle.as_ref() != Some(&bundle) {
                if let Err(error) = crate::sync::save_cached(&store, &bundle) {
                    tracing::warn!(error = %error, "缓存服务端策略失败");
                }
            }
            current_bundle = Some(bundle);
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(error = %error, "启动拉取服务端策略失败，将使用本地缓存/配置");
        }
    }

    let mut active_config = if let Some(bundle) = &current_bundle {
        let merged = Arc::new(crate::sync::apply_bundle(&base_config, bundle));
        if let Ok(rules) = crate::rules::RuleSet::build(&merged.rules) {
            if let Ok(next_scanner) = Scanner::new(Arc::clone(&merged), Arc::clone(&store), rules) {
                scanner = Arc::new(next_scanner);
            }
        }
        if let Ok(identity) = crate::identity::Identity::load_or_create(&store, &merged) {
            let _ = crate::sync::report_revision(&base_config, &identity, bundle.revision);
        }
        merged
    } else {
        Arc::clone(&base_config)
    };

    let mut scan_roots = active_config.effective_roots();
    let mut watch_roots = canonical_watch_roots(&active_config);
    tracing::info!(
        scan_roots = ?scan_roots,
        watch_roots = ?watch_roots,
        "数据哨兵守护进程启动"
    );

    let (mut _watcher, mut receiver) = if active_config.watch.enabled {
        let (w, rx, dropped) = build_watcher(&watch_roots)?;
        (Some(w), Some((rx, dropped)))
    } else {
        (None, None)
    };

    if (active_config.scan.scan_on_startup || scanner.rules_changed()) && !scan_roots.is_empty() {
        if scanner.rules_changed() {
            tracing::info!("检测规则已变化，强制执行一次全量对账");
        }
        tracing::info!("开始启动对账扫描");
        let summary = scanner.scan_roots(&scan_roots, false);
        log_summary(&summary, "启动扫描");
        scanner.flush_syslog();
    } else if scan_roots.is_empty() {
        tracing::info!("当前未配置扫描目录，等待服务端下发策略");
    }

    // 启动即报到：否则一台没有新命中的机器要等到下次落盘命中才会
    // 出现在服务端「终端」页。
    scanner.heartbeat();

    let debounce = Duration::from_millis(active_config.watch.debounce_ms.max(200));
    let max_pending = active_config.watch.max_pending.max(100);
    let mut interval = scan_interval(&active_config);
    let sync_interval = Duration::from_secs(base_config.server.sync_interval_secs.max(10));

    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut last_full_scan = Instant::now();
    let mut last_drop_log = Instant::now();
    let mut last_log_prune = Instant::now();
    // 心跳：构造 Scanner 时已发过一次，这里负责长期保活。
    let mut last_heartbeat = Instant::now();
    let mut last_sync = Instant::now();
    let heartbeat_interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);

    while running.load(Ordering::SeqCst) {
        if let Some((receiver, dropped)) = receiver.as_ref() {
            match receiver.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(event)) => {
                    handle_event(event, &scanner, &mut pending);
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "文件系统监听出错");
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let dropped_count = dropped.swap(0, Ordering::Relaxed);
            if dropped_count > 0 && last_drop_log.elapsed() >= Duration::from_secs(10) {
                tracing::warn!(
                    dropped = dropped_count,
                    capacity = EVENT_QUEUE_CAPACITY,
                    "文件系统事件队列已满，部分事件被丢弃"
                );
                last_drop_log = Instant::now();
            }
        } else {
            std::thread::sleep(Duration::from_millis(500));
        }

        // 尽量把已经到达的事件一次性消费掉，避免队列积压（有上限，不会失控）。
        if let Some((receiver, _)) = receiver.as_ref() {
            for _ in 0..EVENT_QUEUE_CAPACITY {
                match receiver.try_recv() {
                    Ok(Ok(event)) => handle_event(event, &scanner, &mut pending),
                    Ok(Err(error)) => {
                        tracing::warn!(error = %error, "文件系统监听出错");
                    }
                    Err(_) => break,
                }
            }
        }

        // 守护进程通常长期不重启，日志需要主动清理。这里不绑定“定时对账”
        // （`full_scan_interval_hours = 0` 时那条分支永不执行），而是每天清一次。
        if last_log_prune.elapsed() >= Duration::from_secs(86_400) {
            crate::config::prune_old_logs(&active_config.logs_dir(), crate::config::LOG_RETENTION_DAYS);
            last_log_prune = Instant::now();
        }

        // 「终端在线」心跳：没有新命中的机器也要让服务端看见。
        if last_heartbeat.elapsed() >= heartbeat_interval {
            scanner.heartbeat();
            last_heartbeat = Instant::now();
        }

        // 定期向服务端拉取统一策略（扫描路径、定时周期、白名单与规则），变化时热更新。
        if last_sync.elapsed() >= sync_interval {
            last_sync = Instant::now();
            match crate::sync::fetch_policy(&base_config) {
                Ok(Some(bundle)) if current_bundle.as_ref() != Some(&bundle) => {
                    tracing::info!(revision = bundle.revision, "收到服务端新策略，正在热更新");
                    let merged = Arc::new(crate::sync::apply_bundle(&base_config, &bundle));
                    match crate::rules::RuleSet::build(&merged.rules)
                        .and_then(|rules| Scanner::new(Arc::clone(&merged), Arc::clone(&store), rules))
                    {
                        Ok(next_scanner) => {
                            scanner = Arc::new(next_scanner);
                            active_config = merged;
                            scan_roots = active_config.effective_roots();
                            interval = scan_interval(&active_config);
                            let next_watch_roots = canonical_watch_roots(&active_config);
                            if next_watch_roots != watch_roots {
                                watch_roots = next_watch_roots;
                                if active_config.watch.enabled {
                                    match build_watcher(&watch_roots) {
                                        Ok((w, rx, dropped)) => {
                                            _watcher = Some(w);
                                            receiver = Some((rx, dropped));
                                        }
                                        Err(error) => {
                                            tracing::warn!(error = %error, "更新监听目录失败");
                                        }
                                    }
                                }
                            }
                            let _ = crate::sync::save_cached(&store, &bundle);
                            if let Ok(identity) =
                                crate::identity::Identity::load_or_create(&store, &active_config)
                            {
                                let _ = crate::sync::report_revision(
                                    &base_config,
                                    &identity,
                                    bundle.revision,
                                );
                            }
                            current_bundle = Some(bundle);
                            if !scan_roots.is_empty() {
                                let summary = scanner.scan_roots(&scan_roots, false);
                                log_summary(&summary, "策略更新扫描");
                                scanner.flush_syslog();
                                last_full_scan = Instant::now();
                            }
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "应用服务端新策略失败，保留当前配置");
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(error = %error, "拉取服务端策略失败");
                }
            }
        }

        if let Some(interval) = interval {
            if !scan_roots.is_empty() && last_full_scan.elapsed() >= interval {
                tracing::info!("开始定时对账扫描");
                let summary = scanner.scan_roots(&scan_roots, false);
                log_summary(&summary, "定时扫描");
                scanner.flush_syslog();
                last_full_scan = Instant::now();
            }
        }

        let now = Instant::now();
        let overflow = pending.len() >= max_pending;
        let mut due: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, at)| overflow || now.duration_since(**at) >= debounce)
            .map(|(path, _)| path.clone())
            .collect();
        // 即使积压，也只取一批：一次扫全部会长时间阻塞事件消费，形成正反馈。
        if due.len() > max_pending {
            due.truncate(max_pending);
        }
        if !due.is_empty() {
            for path in &due {
                pending.remove(path);
            }
            // 积压严重时 pending 自身也要收敛：虽然 due 会分批消费，但高
            // churn 目录可能持续灌入。只有超过 2 倍上限才压缩一次，避免
            // 每次都排序 2 万条记录；被丢弃的事件由定时全量对账兜底。
            let hard_limit = max_pending.saturating_mul(2);
            if pending.len() > hard_limit {
                let mut entries: Vec<(PathBuf, Instant)> = pending.drain().collect();
                entries.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
                entries.truncate(max_pending);
                pending.extend(entries);
                tracing::warn!(
                    kept = max_pending,
                    "待扫描队列超过上限，较早的落盘事件已丢弃（将由定时对账补齐）"
                );
            }
            due.sort();
            due.dedup();
            tracing::debug!(count = due.len(), "扫描落盘变更");
            let summary = scanner.scan_paths(&due, true);
            if summary.new_findings > 0 {
                log_summary(&summary, "增量扫描");
            }
            notifier.notify_scan(&summary);
            scanner.flush_syslog();
            // "编辑并保存"通常不会产生新的敏感值，但仍值得提醒一次。
            notifier.notify_rescan(&due, &summary);
        }
    }

    tracing::info!("数据哨兵守护进程退出");
    Ok(())
}

fn handle_event(event: Event, scanner: &Scanner, pending: &mut HashMap<PathBuf, Instant>) {
    match event.kind {
        EventKind::Remove(_) => {
            for path in event.paths {
                pending.remove(&path);
                if scanner.is_internal_path(&path) {
                    continue;
                }
                if let Err(error) = scanner.store.remove_file(&path) {
                    tracing::debug!(path = %path.display(), error = %error, "清理已删除文件记录失败");
                }
            }
        }
        EventKind::Create(_)
        | EventKind::Modify(ModifyKind::Data(_))
        | EventKind::Modify(ModifyKind::Name(_))
        | EventKind::Modify(ModifyKind::Any) => {
            for path in event.paths {
                if path.is_dir() || !scanner.is_watched_path(&path) {
                    continue;
                }
                pending.insert(path, Instant::now());
            }
        }
        _ => {}
    }
}

fn log_summary(summary: &crate::model::ScanSummary, label: &str) {
    tracing::info!(
        label,
        files_scanned = summary.files_scanned,
        files_unchanged = summary.files_unchanged,
        findings = summary.findings,
        new_findings = summary.new_findings,
        elapsed = %format_duration(summary.duration),
        "扫描完成"
    );
}
