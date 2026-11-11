use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};

use crate::config::{ensure_private_dir, secure_file};
use crate::model::{Finding, ScanSummary, Severity, StoredFinding};
use crate::util::{now_ts, path_to_key};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS files (
    path          TEXT PRIMARY KEY,
    size          INTEGER NOT NULL,
    mtime         INTEGER NOT NULL,
    content_hash  TEXT,
    last_scanned  INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'scanned'
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    masked        TEXT NOT NULL,
    match_hash    TEXT NOT NULL,
    line          INTEGER NOT NULL,
    snippet       TEXT NOT NULL,
    raw_match     TEXT,
    detected_at   INTEGER NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(path, rule_id, match_hash)
);

CREATE INDEX IF NOT EXISTS idx_findings_time ON findings(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
CREATE INDEX IF NOT EXISTS idx_findings_ack ON findings(acknowledged);

CREATE TABLE IF NOT EXISTS scan_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER NOT NULL,
    roots         TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    files_skipped INTEGER NOT NULL,
    findings      INTEGER NOT NULL,
    new_findings  INTEGER NOT NULL,
    status        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

#[derive(Debug, Clone, Copy)]
pub struct FileState {
    pub size: u64,
    pub mtime: i64,
}

#[derive(Debug, Default, Clone)]
pub struct SaveOutcome {
    pub findings: u64,
    pub new_findings: u64,
    pub new_by_severity: BTreeMap<Severity, u64>,
    pub new_hashes: HashSet<String>,
}

#[derive(Debug, Default, Clone)]
pub struct StoreStats {
    pub files: u64,
    pub findings: u64,
    pub unacknowledged: u64,
    pub by_severity: BTreeMap<Severity, u64>,
    pub last_scan: Option<i64>,
}

/// One row of `scan_runs`, used by the local console history list.
#[derive(Debug, Clone, Copy)]
pub struct ScanRun {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: i64,
    pub files_scanned: u64,
    pub findings: u64,
    pub new_findings: u64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let conn = open_connection(path)?;
        Self::initialize(conn, path)
    }

    fn initialize(conn: Connection, path: &Path) -> Result<Self> {
        conn.execute_batch(SCHEMA)
            .with_context(|| format!("初始化数据库失败 {}", path.display()))?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '1')
             ON CONFLICT(key) DO NOTHING",
            [],
        )?;
        let _ = secure_file(path);
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库连接锁已中毒"))
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn()?;
        Ok(conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn file_states(&self) -> Result<HashMap<String, FileState>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT path, size, mtime FROM files")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                FileState {
                    size: row.get::<_, i64>(1)?.max(0) as u64,
                    mtime: row.get::<_, i64>(2)?,
                },
            ))
        })?;
        let mut states = HashMap::new();
        for row in rows {
            let (path, state) = row?;
            states.insert(path, state);
        }
        Ok(states)
    }

    pub fn needs_scan(&self, path: &Path, size: u64, mtime: i64) -> Result<bool> {
        let key = path_to_key(path);
        let conn = self.conn()?;
        let existing = conn
            .query_row(
                "SELECT size, mtime FROM files WHERE path = ?1",
                params![key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(match existing {
            Some((stored_size, stored_mtime)) => {
                stored_size.max(0) as u64 != size || stored_mtime != mtime
            }
            None => true,
        })
    }

    pub fn save_file(
        &self,
        path: &Path,
        size: u64,
        mtime: i64,
        content_hash: &str,
        findings: &[Finding],
    ) -> Result<SaveOutcome> {
        let key = path_to_key(path);
        let now = now_ts();
        let mut conn = self.conn()?;
        // BEGIN IMMEDIATE: the console (`sentinel ui`) and a standalone daemon
        // may scan the same file at the same time. A deferred transaction would
        // take a read snapshot first and then fail to upgrade when the other
        // process commits ("database is locked"), silently losing the scan
        // result. Taking the write lock up front lets busy_timeout serialize us.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut existing: HashMap<String, bool> = HashMap::new();
        {
            let mut stmt =
                tx.prepare("SELECT match_hash, acknowledged FROM findings WHERE path = ?1")?;
            let rows = stmt.query_map(params![key], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
            })?;
            for row in rows {
                let (hash, acknowledged) = row?;
                existing.insert(hash, acknowledged);
            }
        }

        tx.execute("DELETE FROM findings WHERE path = ?1", params![key])?;
        tx.execute("DELETE FROM files WHERE path = ?1", params![key])?;
        tx.execute(
            "INSERT INTO files(path, size, mtime, content_hash, last_scanned, status)
             VALUES(?1, ?2, ?3, ?4, ?5, 'scanned')",
            params![key, size as i64, mtime, content_hash, now],
        )?;

        let mut outcome = SaveOutcome {
            findings: findings.len() as u64,
            ..SaveOutcome::default()
        };
        let mut insert = tx.prepare(
            "INSERT OR IGNORE INTO findings(
                path, rule_id, rule_name, category, severity, masked, match_hash,
                line, snippet, raw_match, detected_at, acknowledged
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        for finding in findings {
            let is_new = !existing.contains_key(&finding.match_hash);
            let acknowledged = existing.get(&finding.match_hash).copied().unwrap_or(false);
            insert.execute(params![
                key,
                finding.rule_id,
                finding.rule_name,
                finding.category,
                finding.severity.as_str(),
                finding.masked,
                finding.match_hash,
                finding.line as i64,
                finding.snippet,
                finding.raw,
                now,
                if acknowledged { 1 } else { 0 },
            ])?;
            if is_new {
                outcome.new_findings += 1;
                outcome.new_hashes.insert(finding.match_hash.clone());
                *outcome.new_by_severity.entry(finding.severity).or_insert(0) += 1;
            }
        }
        drop(insert);
        tx.commit()?;
        Ok(outcome)
    }

    pub fn remove_file(&self, path: &Path) -> Result<()> {
        let key = path_to_key(path);
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM files WHERE path = ?1", params![key])?;
        tx.execute("DELETE FROM findings WHERE path = ?1", params![key])?;
        tx.commit()?;
        Ok(())
    }

    pub fn recent_findings(
        &self,
        min_severity: Option<Severity>,
        limit: usize,
        include_acknowledged: bool,
    ) -> Result<Vec<StoredFinding>> {
        let conn = self.conn()?;
        let sql = if include_acknowledged {
            "SELECT id, path, rule_id, rule_name, category, severity, masked, line, snippet, detected_at, acknowledged
             FROM findings ORDER BY detected_at DESC, id DESC LIMIT 5000"
        } else {
            "SELECT id, path, rule_id, rule_name, category, severity, masked, line, snippet, detected_at, acknowledged
             FROM findings WHERE acknowledged = 0 ORDER BY detected_at DESC, id DESC LIMIT 5000"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], map_finding)?;
        let mut findings = Vec::new();
        for row in rows {
            let finding = row?;
            if let Some(minimum) = min_severity {
                if finding.severity < minimum {
                    continue;
                }
            }
            findings.push(finding);
            if findings.len() >= limit {
                break;
            }
        }
        Ok(findings)
    }

    pub fn findings_since(&self, since_ts: i64) -> Result<Vec<StoredFinding>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, path, rule_id, rule_name, category, severity, masked, line, snippet, detected_at, acknowledged
             FROM findings WHERE detected_at >= ?1 ORDER BY detected_at DESC, id DESC",
        )?;
        let rows = stmt.query_map(params![since_ts], map_finding)?;
        let mut findings = Vec::new();
        for row in rows {
            findings.push(row?);
        }
        Ok(findings)
    }

    pub fn clear_raw_matches(&self) -> Result<usize> {
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE findings SET raw_match = NULL WHERE raw_match IS NOT NULL",
            [],
        )?;
        Ok(updated)
    }

    pub fn ack_all(&self) -> Result<usize> {
        let conn = self.conn()?;
        let updated = conn.execute(
            "UPDATE findings SET acknowledged = 1 WHERE acknowledged = 0",
            [],
        )?;
        Ok(updated)
    }

    pub fn ack_ids(&self, ids: &[i64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut updated = 0usize;
        {
            let mut stmt = tx.prepare("UPDATE findings SET acknowledged = 1 WHERE id = ?1")?;
            for id in ids {
                updated += stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(updated)
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let conn = self.conn()?;
        let files = conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0))?;
        let findings = conn.query_row("SELECT COUNT(*) FROM findings", [], |row| {
            row.get::<_, i64>(0)
        })?;
        let unacknowledged = conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE acknowledged = 0",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let last_scan = conn.query_row("SELECT MAX(last_scanned) FROM files", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;

        let mut by_severity = BTreeMap::new();
        {
            let mut stmt =
                conn.prepare("SELECT severity, COUNT(*) FROM findings GROUP BY severity")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (severity, count) = row?;
                if let Ok(severity) = severity.parse::<Severity>() {
                    by_severity.insert(severity, count.max(0) as u64);
                }
            }
        }

        Ok(StoreStats {
            files: files.max(0) as u64,
            findings: findings.max(0) as u64,
            unacknowledged: unacknowledged.max(0) as u64,
            by_severity,
            last_scan,
        })
    }

    pub fn record_scan(
        &self,
        started_at: i64,
        summary: &ScanSummary,
        roots: &[std::path::PathBuf],
    ) -> Result<()> {
        let conn = self.conn()?;
        let roots = serde_json::to_string(roots).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO scan_runs(
                started_at, finished_at, roots, files_scanned, files_skipped,
                findings, new_findings, status
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ok')",
            params![
                started_at,
                now_ts(),
                roots,
                summary.files_scanned as i64,
                (summary.files_unchanged + summary.files_excluded + summary.files_skipped) as i64,
                summary.findings as i64,
                summary.new_findings as i64,
            ],
        )?;
        Ok(())
    }

    /// Most recent scan batches, newest first.
    pub fn recent_runs(&self, limit: usize) -> Result<Vec<ScanRun>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, started_at, finished_at, files_scanned, findings, new_findings
             FROM scan_runs ORDER BY finished_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.max(1) as i64], |row| {
            Ok(ScanRun {
                id: row.get(0)?,
                started_at: row.get(1)?,
                finished_at: row.get(2)?,
                files_scanned: row.get::<_, i64>(3)?.max(0) as u64,
                findings: row.get::<_, i64>(4)?.max(0) as u64,
                new_findings: row.get::<_, i64>(5)?.max(0) as u64,
            })
        })?;
        let mut runs = Vec::new();
        for row in rows {
            runs.push(row?);
        }
        Ok(runs)
    }

    /// Finding counts grouped by rule category.
    pub fn category_counts(&self) -> Result<BTreeMap<String, u64>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT category, COUNT(*) FROM findings GROUP BY category")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut counts = BTreeMap::new();
        for row in rows {
            let (category, count) = row?;
            counts.insert(category, count.max(0) as u64);
        }
        Ok(counts)
    }

    pub fn prune(&self, retention_days: u64) -> Result<usize> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = now_ts() - (retention_days as i64) * 86_400;
        let conn = self.conn()?;
        let removed = conn.execute(
            "DELETE FROM findings WHERE detected_at < ?1",
            params![cutoff],
        )?;
        let _ = conn.execute(
            "DELETE FROM scan_runs WHERE finished_at < ?1",
            params![cutoff],
        )?;
        Ok(removed)
    }
}

/// Open a connection and apply pragmas.
///
/// Several processes (the CLI, the daemon and the local console) may hold the
/// same database open. Switching `journal_mode` needs a brief exclusive lock,
/// so a concurrent writer makes it fail with `SQLITE_BUSY` even though the file
/// is already in WAL mode. We therefore only touch the mode when it differs and
/// retry a few times before giving up.
fn open_connection(path: &Path) -> Result<Connection> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let result = Connection::open(path)
            .with_context(|| format!("无法打开数据库 {}", path.display()))
            .and_then(|conn| {
                conn.busy_timeout(Duration::from_secs(10))?;
                configure(&conn).map(|()| conn)
            });
        match result {
            Ok(conn) => return Ok(conn),
            Err(error) if attempt < 4 => {
                tracing::debug!(attempt, error = %error, "数据库暂时被占用，稍后重试");
                std::thread::sleep(Duration::from_millis(120 * u64::from(attempt)));
            }
            Err(error) => return Err(error),
        }
    }
}

fn configure(conn: &Connection) -> Result<()> {
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap_or_default();
    if !mode.eq_ignore_ascii_case("wal") {
        conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0))?;
    }
    conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;")?;
    Ok(())
}

fn map_finding(row: &Row<'_>) -> rusqlite::Result<StoredFinding> {
    let severity_text: String = row.get(5)?;
    Ok(StoredFinding {
        id: row.get(0)?,
        path: row.get(1)?,
        rule_id: row.get(2)?,
        rule_name: row.get(3)?,
        category: row.get(4)?,
        severity: severity_text.parse().unwrap_or(Severity::Low),
        masked: row.get(6)?,
        line: row.get::<_, i64>(7)?.max(0) as usize,
        snippet: row.get(8)?,
        detected_at: row.get(9)?,
        acknowledged: row.get::<_, i64>(10)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn memory_store() -> Store {
        let conn = Connection::open_in_memory().unwrap();
        Store::initialize(conn, Path::new(":memory:")).unwrap()
    }

    fn finding(rule: &str, hash: &str) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            rule_name: rule.to_string(),
            category: "credential".to_string(),
            severity: Severity::High,
            path: "a.txt".into(),
            line: 1,
            column: 1,
            masked: "****".to_string(),
            snippet: "****".to_string(),
            match_hash: hash.to_string(),
            raw: None,
            start: 0,
            end: 4,
        }
    }

    #[test]
    fn save_preserves_ack_and_counts_new() {
        let store = memory_store();
        let path = Path::new("a.txt");
        let first = store
            .save_file(path, 10, 100, "hash", &[finding("password", "h1")])
            .unwrap();
        assert_eq!(first.new_findings, 1);
        store.ack_all().unwrap();

        let second = store
            .save_file(
                path,
                10,
                101,
                "hash",
                &[finding("password", "h1"), finding("token", "h2")],
            )
            .unwrap();
        assert_eq!(second.new_findings, 1);
        let stored = store.recent_findings(None, 10, true).unwrap();
        assert_eq!(stored.len(), 2);
        let acked = stored
            .iter()
            .find(|item| item.rule_id == "password")
            .unwrap();
        assert!(acked.acknowledged);
    }

    #[test]
    fn needs_scan_compares_size_and_mtime() {
        let store = memory_store();
        let path = Path::new("a.txt");
        assert!(store.needs_scan(path, 10, 100).unwrap());
        store.save_file(path, 10, 100, "hash", &[]).unwrap();
        assert!(!store.needs_scan(path, 10, 100).unwrap());
        assert!(store.needs_scan(path, 11, 100).unwrap());
    }

    /// `sentinel ui` now embeds the watcher, so two processes can scan the same
    /// file at the same time. Deferred transactions used to fail with
    /// "database is locked" when the second writer upgraded its snapshot,
    /// dropping the result (and the notification) silently.
    #[test]
    fn concurrent_writers_on_separate_connections_do_not_lose_data() {
        use std::sync::{Arc, Barrier};

        let dir = std::env::temp_dir().join(format!(
            "datasentinel-store-concurrency-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("sentinel.db");

        let workers = 6usize;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();
        for _ in 0..workers {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let store = Store::open(&db).unwrap();
                barrier.wait();
                store
                    .save_file(
                        Path::new("a.txt"),
                        10,
                        100,
                        "hash",
                        &[finding("password", "h1")],
                    )
                    .map(|outcome| outcome.new_findings)
            }));
        }

        let mut new_total = 0;
        for handle in handles {
            new_total += handle.join().unwrap().expect("并发写入不应失败");
        }
        assert_eq!(new_total, 1, "同一个命中只应计一次新增");

        let store = Store::open(&db).unwrap();
        assert_eq!(store.stats().unwrap().findings, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
