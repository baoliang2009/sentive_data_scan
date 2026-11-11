use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use notify::event::{EventKind, ModifyKind};
use notify::{Event, RecursiveMode, Watcher};

use crate::config::Config;
use crate::notify::Notifier;
use crate::scan::Scanner;
use crate::util::format_duration;

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
        let (tx, rx) = std::sync::mpsc::channel();
        let watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
            let _ = tx.send(result);
        })?;
        (Some(watcher), Some(rx))
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
        notifier.notify_scan(&summary);
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

    while running.load(Ordering::SeqCst) {
        if let Some(receiver) = receiver.as_ref() {
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
        } else {
            std::thread::sleep(Duration::from_millis(500));
        }

        if let Some(interval) = interval {
            if last_full_scan.elapsed() >= interval {
                tracing::info!("开始定时对账扫描");
                let summary = scanner.scan_roots(&scan_roots, false);
                log_summary(&summary, "定时扫描");
                notifier.notify_scan(&summary);
                last_full_scan = Instant::now();
            }
        }

        let now = Instant::now();
        let mut due: Vec<PathBuf> = if pending.len() >= max_pending {
            pending.keys().cloned().collect()
        } else {
            pending
                .iter()
                .filter(|(_, at)| now.duration_since(**at) >= debounce)
                .map(|(path, _)| path.clone())
                .collect()
        };
        if !due.is_empty() {
            for path in &due {
                pending.remove(path);
            }
            due.sort();
            due.dedup();
            tracing::debug!(count = due.len(), "扫描落盘变更");
            let summary = scanner.scan_paths(&due, true);
            if summary.new_findings > 0 {
                log_summary(&summary, "增量扫描");
            }
            notifier.notify_scan(&summary);
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
