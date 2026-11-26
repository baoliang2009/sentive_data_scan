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

fn run_loop(
    config: Arc<Config>,
    scanner: Arc<Scanner>,
    notifier: Notifier,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let scan_roots = config.effective_roots();
    let watch_roots: Vec<PathBuf> = config
        .watch_roots()
        .into_iter()
        .map(|path| dunce::canonicalize(&path).unwrap_or(path))
        .collect();
    tracing::info!(
        scan_roots = ?scan_roots,
        watch_roots = ?watch_roots,
        "数据哨兵守护进程启动"
    );

    let (mut watcher, receiver) = if config.watch.enabled {
        let (tx, rx) = std::sync::mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_in_callback = Arc::clone(&dropped);
        let watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
            match tx.try_send(result) {
                Ok(()) => {}
                // 队列满：丢弃事件但保留计数，避免内存被拖垮。
                Err(TrySendError::Full(_)) => {
                    dropped_in_callback.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        })?;
        (Some(watcher), Some((rx, dropped)))
    } else {
        (None, None)
    };

    if let Some(watcher) = watcher.as_mut() {
        let mut watched = 0usize;
        for root in &watch_roots {
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
        if watched == 0 {
            tracing::warn!("没有成功监听任何目录，将只依赖定时对账");
        }
    }

    if config.scan.scan_on_startup || scanner.rules_changed() {
        if scanner.rules_changed() {
            tracing::info!("检测规则已变化，强制执行一次全量对账");
        }
        tracing::info!("开始启动对账扫描");
        let summary = scanner.scan_roots(&scan_roots, false);
        log_summary(&summary, "启动扫描");
        scanner.flush_syslog();
    }

    let debounce = Duration::from_millis(config.watch.debounce_ms.max(200));
    let max_pending = config.watch.max_pending.max(100);
    let interval = if config.scan.full_scan_interval_hours == 0 {
        None
    } else {
        Some(Duration::from_secs(
            config.scan.full_scan_interval_hours.saturating_mul(3600),
        ))
    };

    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut last_full_scan = Instant::now();
    let mut last_drop_log = Instant::now();
    let mut last_log_prune = Instant::now();

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
            crate::config::prune_old_logs(&config.logs_dir(), crate::config::LOG_RETENTION_DAYS);
            last_log_prune = Instant::now();
        }

        if let Some(interval) = interval {
            if last_full_scan.elapsed() >= interval {
                tracing::info!("开始定时对账扫描");
                let summary = scanner.scan_roots(&scan_roots, false);
                log_summary(&summary, "定时扫描");
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
