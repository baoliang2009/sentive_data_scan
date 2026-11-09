use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use rayon::ThreadPool;
use walkdir::{DirEntry, WalkDir};

use crate::config::{default_exclude_extensions, default_exclude_globs, Config};
use crate::detect::{file_extension, Detector, ExtractOutcome};
use crate::model::{Finding, FindingExample, ScanSummary, Severity};
use crate::rules::RuleSet;
use crate::store::{FileState, Store};
use crate::util::{effective_threads, path_to_key};

pub struct Scanner {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    detector: Detector,
    filter: PathFilter,
    pool: ThreadPool,
    rules_fingerprint: String,
    rules_dirty: AtomicBool,
    large_file_lock: Mutex<()>,
}

impl Scanner {
    pub fn new(config: Arc<Config>, store: Arc<Store>, rules: RuleSet) -> Result<Self> {
        let filter = PathFilter::build(&config)?;
        let threads = effective_threads(config.scan.threads);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|index| format!("sentinel-scan-{index}"))
            .build()
            .context("无法创建扫描线程池")?;
        let rules_fingerprint = rules.fingerprint();
        let previous = match store.get_meta("rules_fingerprint") {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, "读取规则指纹失败");
                None
            }
        };
        let rules_dirty = previous.as_deref() != Some(rules_fingerprint.as_str());
        if rules_dirty {
            tracing::info!("检测规则已变化，下次扫描将对未变化文件执行全量重扫");
        }
        let detector = Detector::new(rules, &config);
        Ok(Self {
            config,
            store,
            detector,
            filter,
            pool,
            rules_fingerprint,
            rules_dirty: AtomicBool::new(rules_dirty),
            large_file_lock: Mutex::new(()),
        })
    }

    pub fn rules_changed(&self) -> bool {
        self.rules_dirty.load(Ordering::Relaxed)
    }

    pub fn scan_roots(&self, roots: &[PathBuf], force: bool) -> ScanSummary {
        let started_at = Instant::now();
        let started_ts = chrono::Utc::now().timestamp();
        let stats = ScanStats::default();
        let force = force || self.rules_changed();

        let states: Arc<HashMap<String, FileState>> =
            Arc::new(self.store.file_states().unwrap_or_else(|error| {
                tracing::warn!(error = %error, "读取扫描台账失败，将退化为全量扫描");
                HashMap::new()
            }));

        let existing_roots: Vec<PathBuf> = roots
            .iter()
            .filter_map(|root| {
                if !root.exists() {
                    tracing::warn!(path = %root.display(), "扫描目录不存在，已跳过");
                    return None;
                }
                Some(dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()))
            })
            .collect();
        if existing_roots.is_empty() {
            tracing::warn!("没有可扫描的目录，请检查 scan.roots 配置");
            return stats.finish(started_at);
        }

        self.pool.install(|| {
            let iterator = existing_roots.iter().flat_map(|root| self.walk(root));
            iterator.par_bridge().for_each(|entry| {
                self.process_entry(&entry, Some(&states), force, &stats);
            });
        });

        let removed = self.prune_missing(&existing_roots, &states);
        if removed > 0 {
            tracing::info!(removed, "清理已删除文件的台账与命中记录");
        }

        let summary = stats.finish(started_at);
        if let Err(error) = self.store.record_scan(started_ts, &summary, roots) {
            tracing::warn!(error = %error, "写入扫描记录失败");
        }
        if self.covers_configured_roots(roots) {
            match self
                .store
                .set_meta("rules_fingerprint", &self.rules_fingerprint)
            {
                Ok(()) => self.rules_dirty.store(false, Ordering::Relaxed),
                Err(error) => tracing::warn!(error = %error, "写入规则指纹失败"),
            }
        }
        tracing::debug!(
            files_scanned = summary.files_scanned,
            files_unchanged = summary.files_unchanged,
            findings = summary.findings,
            new_findings = summary.new_findings,
            elapsed = ?summary.duration,
            "扫描完成"
        );
        summary
    }

    pub fn scan_paths(&self, paths: &[PathBuf], force: bool) -> ScanSummary {
        let started_at = Instant::now();
        let stats = ScanStats::default();

        self.pool.install(|| {
            paths.par_iter().for_each(|path| {
                if !path.exists() {
                    stats.skipped.fetch_add(1, Ordering::Relaxed);
                    let _ = self.store.remove_file(path);
                    return;
                }
                self.process_path(path, None, force, &stats);
            });
        });

        stats.finish(started_at)
    }

    pub fn is_watched_path(&self, path: &Path) -> bool {
        self.filter.is_watched_path(path)
    }

    pub fn is_internal_path(&self, path: &Path) -> bool {
        self.filter.is_internal(path)
    }

    fn covers_configured_roots(&self, roots: &[PathBuf]) -> bool {
        let configured = self.config.effective_roots();
        if configured.is_empty() {
            return true;
        }
        let scanned: HashSet<PathBuf> = roots
            .iter()
            .map(|path| dunce::canonicalize(path).unwrap_or_else(|_| path.clone()))
            .collect();
        configured.iter().filter(|path| path.exists()).all(|path| {
            let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.clone());
            scanned.contains(&canonical)
        })
    }

    fn prune_missing(&self, roots: &[PathBuf], states: &HashMap<String, FileState>) -> usize {
        states
            .keys()
            .filter(|key| {
                !key.contains('\u{FFFD}') && {
                    let path = Path::new(key);
                    roots.iter().any(|root| path.starts_with(root)) && !path.exists()
                }
            })
            .filter_map(|key| self.store.remove_file(Path::new(key)).ok())
            .count()
    }

    fn walk<'a>(&'a self, root: &'a Path) -> impl Iterator<Item = DirEntry> + 'a {
        WalkDir::new(root)
            .follow_links(self.config.scan.follow_symlinks)
            .into_iter()
            .filter_entry(move |entry| self.filter.accept_entry(entry))
            .filter_map(move |entry| match entry {
                Ok(entry) => Some(entry),
                Err(error) => {
                    tracing::debug!(error = %error, "遍历目录时出错，已跳过");
                    None
                }
            })
            .filter(|entry| entry.file_type().is_file())
    }

    fn process_entry(
        &self,
        entry: &DirEntry,
        states: Option<&HashMap<String, FileState>>,
        force: bool,
        stats: &ScanStats,
    ) {
        if !entry.file_type().is_file() {
            return;
        }
        self.process_path(entry.path(), states, force, stats);
    }

    fn process_path(
        &self,
        path: &Path,
        states: Option<&HashMap<String, FileState>>,
        force: bool,
        stats: &ScanStats,
    ) {
        stats.files_seen.fetch_add(1, Ordering::Relaxed);

        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::debug!(path = %path.display(), error = %error, "读取文件信息失败");
                stats.failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if !metadata.is_file() {
            stats.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.filter.is_watched_path(path) {
            stats.excluded.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let size = metadata.len();
        if size > self.config.max_file_size_bytes() {
            stats.skipped.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(path = %path.display(), size, "文件超过大小上限，已跳过");
            return;
        }
        let mtime = mtime_nanos(&metadata);

        if !force {
            let unchanged = if let Some(states) = states {
                states
                    .get(&path_to_key(path))
                    .map(|state| state.size == size && state.mtime == mtime)
                    .unwrap_or(false)
            } else {
                !self.store.needs_scan(path, size, mtime).unwrap_or(true)
            };
            if unchanged {
                stats.unchanged.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // Large files are read and decoded entirely; serialize them so the
        // peak memory stays bounded even with many scan threads.
        let _large_file_guard = if size > 8 * 1024 * 1024 {
            self.large_file_lock.lock().ok()
        } else {
            None
        };

        match self.detector.extract_file(path) {
            Ok(ExtractOutcome::Skip(reason)) => {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(path = %path.display(), reason, "跳过文件");
            }
            Ok(ExtractOutcome::Content(content)) => {
                tracing::debug!(
                    path = %path.display(),
                    kind = content.kind,
                    chars = content.text.chars().count(),
                    "开始检测文件内容"
                );
                let findings = self.detector.detect(&content.text, path);
                match self
                    .store
                    .save_file(path, size, mtime, &content.content_hash, &findings)
                {
                    Ok(outcome) => {
                        stats.scanned.fetch_add(1, Ordering::Relaxed);
                        stats
                            .findings
                            .fetch_add(outcome.findings, Ordering::Relaxed);
                        stats
                            .new_findings
                            .fetch_add(outcome.new_findings, Ordering::Relaxed);
                        for (severity, count) in &outcome.new_by_severity {
                            stats.new_severity[*severity as usize]
                                .fetch_add(*count, Ordering::Relaxed);
                        }
                        for (severity, count) in severity_counts(&findings) {
                            stats.severity[severity as usize].fetch_add(count, Ordering::Relaxed);
                        }
                        stats.add_examples(&findings, &outcome.new_hashes);
                        let done = stats.scanned.load(Ordering::Relaxed);
                        if done % 2000 == 0 {
                            tracing::info!(files_scanned = done, "扫描进行中…");
                        }
                    }
                    Err(error) => {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(path = %path.display(), error = %error, "保存扫描结果失败");
                    }
                }
            }
            Err(error) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(path = %path.display(), error = %error, "扫描文件失败");
            }
        }
    }
}

fn mtime_nanos(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos() as i64)
                .unwrap_or(0)
        })
}

fn severity_counts(findings: &[Finding]) -> Vec<(Severity, u64)> {
    let mut counts = [0u64; 5];
    for finding in findings {
        counts[finding.severity as usize] += 1;
    }
    [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .enumerate()
    .filter(|(index, _)| counts[*index] > 0)
    .map(|(index, severity)| (severity, counts[index]))
    .collect()
}

#[derive(Default)]
struct ScanStats {
    files_seen: AtomicU64,
    scanned: AtomicU64,
    unchanged: AtomicU64,
    excluded: AtomicU64,
    skipped: AtomicU64,
    failed: AtomicU64,
    findings: AtomicU64,
    new_findings: AtomicU64,
    severity: [AtomicU64; 5],
    new_severity: [AtomicU64; 5],
    examples: Mutex<Vec<FindingExample>>,
}

impl ScanStats {
    fn add_examples(&self, findings: &[Finding], new_hashes: &HashSet<String>) {
        if findings.is_empty() {
            return;
        }
        let Ok(mut examples) = self.examples.lock() else {
            return;
        };
        let mut selected: Vec<&Finding> = if new_hashes.is_empty() {
            findings.iter().collect()
        } else {
            findings
                .iter()
                .filter(|finding| new_hashes.contains(&finding.match_hash))
                .collect()
        };
        selected.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
        for finding in selected {
            if examples.len() >= 8 {
                break;
            }
            if examples.iter().any(|existing| {
                existing.path == finding.path.to_string_lossy().as_ref()
                    && existing.rule_name == finding.rule_name
            }) {
                continue;
            }
            examples.push(FindingExample {
                path: finding.path.to_string_lossy().into_owned(),
                rule_name: finding.rule_name.clone(),
                severity: finding.severity,
                masked: finding.masked.clone(),
                line: finding.line,
            });
        }
    }

    fn finish(&self, started: Instant) -> ScanSummary {
        let severities = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let mut by_severity = std::collections::BTreeMap::new();
        let mut new_by_severity = std::collections::BTreeMap::new();
        for (index, severity) in severities.iter().enumerate() {
            let count = self.severity[index].load(Ordering::Relaxed);
            if count > 0 {
                by_severity.insert(*severity, count);
            }
            let new_count = self.new_severity[index].load(Ordering::Relaxed);
            if new_count > 0 {
                new_by_severity.insert(*severity, new_count);
            }
        }
        let mut examples = self
            .examples
            .lock()
            .map(|examples| examples.clone())
            .unwrap_or_default();
        examples.sort_by_key(|example| std::cmp::Reverse(example.severity));
        examples.truncate(5);

        ScanSummary {
            files_seen: self.files_seen.load(Ordering::Relaxed),
            files_scanned: self.scanned.load(Ordering::Relaxed),
            files_unchanged: self.unchanged.load(Ordering::Relaxed),
            files_excluded: self.excluded.load(Ordering::Relaxed),
            files_skipped: self.skipped.load(Ordering::Relaxed),
            files_failed: self.failed.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
            new_findings: self.new_findings.load(Ordering::Relaxed),
            by_severity,
            new_by_severity,
            examples,
            duration: started.elapsed(),
        }
    }
}

struct PathFilter {
    allow: GlobSet,
    exclude: GlobSet,
    exclude_names: HashSet<String>,
    include_ext: Option<HashSet<String>>,
    exclude_ext: HashSet<String>,
    internal: Vec<PathBuf>,
    skip_hidden: bool,
    ignore_temp: bool,
}

impl PathFilter {
    fn build(config: &Config) -> Result<Self> {
        let mut patterns = if config.scan.use_default_excludes {
            default_exclude_globs()
        } else {
            Vec::new()
        };
        patterns.extend(config.scan.exclude_globs.iter().cloned());
        let exclude = build_globset(&patterns)?;
        let allow = build_globset(&config.scan.allow_globs)?;

        let exclude_names: HashSet<String> = if config.scan.use_default_excludes {
            [
                "node_modules",
                ".git",
                ".svn",
                "__pycache__",
                "target",
                ".cache",
                ".npm",
                ".gradle",
                ".venv",
                "venv",
                "$RECYCLE.BIN",
                "System Volume Information",
                ".Trash",
                ".Trashes",
                "lost+found",
            ]
            .iter()
            .map(|name| name.to_string())
            .collect()
        } else {
            HashSet::new()
        };

        let include_ext = if config.scan.include_extensions.is_empty() {
            None
        } else {
            Some(
                config
                    .scan
                    .include_extensions
                    .iter()
                    .map(|extension| extension.trim_start_matches('.').to_ascii_lowercase())
                    .collect(),
            )
        };

        let mut exclude_ext: HashSet<String> = if config.scan.use_default_excludes {
            default_exclude_extensions().into_iter().collect()
        } else {
            HashSet::new()
        };
        exclude_ext.extend(
            config
                .scan
                .exclude_extensions
                .iter()
                .map(|extension| extension.trim_start_matches('.').to_ascii_lowercase()),
        );

        let mut internal = vec![
            config.data_dir(),
            config.reports_dir(),
            config.logs_dir(),
            crate::config::config_dir(),
        ];
        let db_path = config.database_path();
        for suffix in ["-wal", "-shm"] {
            let mut companion = db_path.as_os_str().to_os_string();
            companion.push(suffix);
            internal.push(PathBuf::from(companion));
        }
        internal.push(db_path);
        let internal: Vec<PathBuf> = internal
            .into_iter()
            .map(|path| dunce::canonicalize(&path).unwrap_or(path))
            .collect();

        Ok(Self {
            allow,
            exclude,
            exclude_names,
            include_ext,
            exclude_ext,
            internal,
            skip_hidden: config.scan.skip_hidden,
            ignore_temp: config.watch.ignore_temp_files,
        })
    }

    fn is_internal(&self, path: &Path) -> bool {
        self.internal.iter().any(|prefix| path.starts_with(prefix))
    }

    fn is_watched_path(&self, path: &Path) -> bool {
        if self.is_internal(path) {
            return false;
        }
        if self.ignore_temp && crate::util::is_temp_file(path) {
            return false;
        }
        if self.skip_hidden {
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                if name.starts_with('.') {
                    return false;
                }
            }
        }
        let match_path = normalized(path);
        if self.allow.is_match(&match_path) {
            return false;
        }
        if self.exclude.is_match(&match_path) {
            return false;
        }
        let extension = file_extension(path);
        if !extension.is_empty() && self.exclude_ext.contains(&extension) {
            return false;
        }
        if let Some(include_ext) = &self.include_ext {
            if !extension.is_empty() && !include_ext.contains(&extension) {
                return false;
            }
        }
        true
    }

    fn accept_entry(&self, entry: &DirEntry) -> bool {
        if entry.depth() == 0 {
            return true;
        }
        let path = entry.path();
        if self.is_internal(path) {
            return false;
        }
        if entry.file_type().is_dir() {
            if self.skip_hidden {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    if name.starts_with('.') {
                        return false;
                    }
                }
            }
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                if self.exclude_names.contains(name) {
                    return false;
                }
            }
            !self.exclude.is_match(normalized(path))
        } else {
            true
        }
    }
}

fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        builder.add(Glob::new(pattern).with_context(|| format!("无效的 glob 规则: {pattern}"))?);
    }
    builder.build().context("编译 glob 规则失败")
}

fn normalized(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
