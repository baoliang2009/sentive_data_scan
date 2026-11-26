//! 服务端持久化：告警事件、Agent 注册、规则集、审计。
//!
//! 与客户端 `store.rs` 完全独立：服务端保存的是**跨机器汇总**的告警，
//! 客户端保存的是本机台账，两者 schema 不共享，避免升级互相牵连。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::config::ensure_private_dir;
use crate::model::{category_label, Severity};

const SCHEMA: &str = r#"
-- 一台被监控终端（客户端）。
CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,          -- 客户端上报的 agent_id（uuid）
    hostname      TEXT NOT NULL,
    username      TEXT NOT NULL DEFAULT '',  -- 终端使用者，可空
    platform      TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    rule_revision INTEGER NOT NULL DEFAULT 0, -- 客户端当前应用的规则版本
    remote_addr   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agents_host ON agents(hostname);
CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(username);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);

-- 一条告警（来自某个 agent 的一次命中）。
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    username      TEXT NOT NULL DEFAULT '',
    rule_id       TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL,
    masked        TEXT NOT NULL DEFAULT '',
    matched       TEXT NOT NULL DEFAULT '',
    file_name     TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    line          INTEGER NOT NULL DEFAULT 0,
    column_no     INTEGER NOT NULL DEFAULT 0,
    snippet       TEXT NOT NULL DEFAULT '',
    match_hash    TEXT NOT NULL DEFAULT '',
    event_time    TEXT NOT NULL DEFAULT '',   -- 客户端本地时间（RFC 3339）
    received_at   INTEGER NOT NULL,
    UNIQUE(agent_id, rule_id, match_hash, received_at)
);

CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

-- 全局规则集：整份文档按版本保存，便于回滚与审计。
CREATE TABLE IF NOT EXISTS rule_sets (
    revision      INTEGER PRIMARY KEY AUTOINCREMENT,
    payload       TEXT NOT NULL,            -- 完整规则 JSON
    note          TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    created_by    TEXT NOT NULL DEFAULT ''
);

-- 每个 agent 已经拉取到的规则版本（用于展示「谁还没跟上」）。
CREATE TABLE IF NOT EXISTS agent_rule_state (
    agent_id      TEXT PRIMARY KEY,
    revision      INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- 管理操作审计。
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
"#;

/// 服务端保存的一条告警。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEvent {
    pub id: i64,
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: Severity,
    pub masked: String,
    pub matched: String,
    pub file_name: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub event_time: String,
    pub received_at: i64,
}

impl ServerEvent {
    pub fn category_label(&self) -> &'static str {
        category_label(&self.category)
    }

    /// 展示用的「用户」：优先终端用户名，其次主机名。
    pub fn user_label(&self) -> &str {
        if self.username.is_empty() {
            &self.hostname
        } else {
            &self.username
        }
    }
}

/// 一台终端。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub version: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub rule_revision: i64,
    pub remote_addr: String,
}

/// 客户端上报的告警载荷（syslog MSG 的 JSON，或 HTTP 批量上报）。
#[derive(Debug, Clone, Deserialize)]
pub struct IncomingFinding {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub masked: String,
    #[serde(default, alias = "value")]
    pub matched: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: i64,
    #[serde(default)]
    pub column: i64,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub match_hash: String,
    #[serde(default)]
    pub time: String,
}

/// 客户端上报的批次。
#[derive(Debug, Clone, Deserialize)]
pub struct IncomingBatch {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub rule_revision: i64,
    #[serde(default)]
    pub findings: Vec<IncomingFinding>,
}

/// 按用户聚合的统计行。
#[derive(Debug, Clone, Serialize)]
pub struct UserSummary {
    pub user: String,
    pub hostname: String,
    pub agents: u64,
    pub events: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub last_seen: i64,
    /// 各敏感数据类型（category）的命中分布。
    pub categories: BTreeMap<String, u64>,
}

/// 查询过滤条件。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventFilter {
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub rule_id: String,
    /// 全文关键词，匹配脱敏值/路径/上下文/规则名。
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub since: Option<i64>,
    #[serde(default)]
    pub until: Option<i64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

pub struct ServerStore {
    conn: Mutex<Connection>,
}

impl ServerStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("无法打开服务端数据库 {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)
            .with_context(|| format!("初始化服务端数据库失败 {}", path.display()))?;
        for sql in [
            "ALTER TABLE events ADD COLUMN matched TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE events ADD COLUMN file_name TEXT NOT NULL DEFAULT ''",
        ] {
            if let Err(error) = conn.execute(sql, []) {
                let message = error.to_string();
                if !message.contains("duplicate column name") {
                    return Err(error).with_context(|| format!("迁移服务端数据库失败 {}", path.display()));
                }
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("服务端数据库连接锁已中毒"))
    }

    /// 记录/更新一台终端，并写入其告警。
    ///
    /// 整体在一个 `IMMEDIATE` 事务里完成：多个客户端并发上报时，
    /// 先拿写锁可以让 busy_timeout 串行化，而不是读到旧快照后升级失败。
    pub fn ingest(&self, batch: &IncomingBatch, remote_addr: &str) -> Result<usize> {
        let now = crate::util::now_ts();
        let agent_id = if batch.agent_id.trim().is_empty() {
            // 老版本客户端可能只填 hostname；用主机名兜底成稳定 ID。
            format!(
                "legacy-{}",
                crate::util::sha256_hex_str(batch.hostname.trim())
            )
        } else {
            batch.agent_id.trim().to_string()
        };
        let hostname = if batch.hostname.trim().is_empty() {
            "unknown".to_string()
        } else {
            batch.hostname.trim().to_string()
        };
        let username = batch.username.trim().to_string();

        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        tx.execute(
            "INSERT INTO agents(id, hostname, username, platform, version, first_seen, last_seen, rule_revision, remote_addr)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                -- 空值不覆盖已有信息：老版本客户端不带这些字段，
                -- 不能让它们把心跳登记好的用户名/平台/版本清空。
                username = CASE WHEN excluded.username = '' THEN agents.username ELSE excluded.username END,
                platform = CASE WHEN excluded.platform = '' THEN agents.platform ELSE excluded.platform END,
                version = CASE WHEN excluded.version = '' THEN agents.version ELSE excluded.version END,
                last_seen = excluded.last_seen,
                rule_revision = MAX(agents.rule_revision, excluded.rule_revision),
                remote_addr = excluded.remote_addr",
            params![
                agent_id,
                hostname,
                username,
                batch.platform.trim(),
                batch.version.trim(),
                now,
                batch.rule_revision.max(0),
                remote_addr,
            ],
        )?;

        let mut inserted = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO events(
                    agent_id, hostname, username, rule_id, rule_name, category, severity,
                    masked, matched, file_name, path, line, column_no, snippet, match_hash, event_time, received_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            )?;
            for finding in &batch.findings {
                let severity = finding
                    .severity
                    .trim()
                    .parse::<Severity>()
                    .unwrap_or(Severity::Medium);
                let masked = finding.masked.trim();
                let matched = if finding.matched.trim().is_empty() {
                    masked
                } else {
                    finding.matched.trim()
                };
                let path = finding.path.trim();
                let file_name = extract_file_name(&finding.file_name, path);
                // match_hash 缺失时用内容摘要兜底，保证去重仍然有效。
                let match_hash = if finding.match_hash.trim().is_empty() {
                    crate::util::sha256_hex_str(&format!(
                        "{}|{}|{}",
                        finding.rule_id, masked, path
                    ))
                } else {
                    finding.match_hash.trim().to_string()
                };
                let changed = stmt.execute(params![
                    agent_id,
                    hostname,
                    username,
                    finding.rule_id.trim(),
                    finding.rule_name.trim(),
                    finding.category.trim(),
                    severity.as_str(),
                    masked,
                    matched,
                    file_name,
                    path,
                    finding.line.max(0),
                    finding.column.max(0),
                    finding.snippet.trim(),
                    match_hash,
                    finding.time.trim(),
                    now,
                ])?;
                inserted += changed;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    // ------------------------------------------------------------- agents --

    /// 登记或刷新一台终端（心跳路径）。
    ///
    /// 与 `ingest` 的区别：这里**不写任何告警**，只维护 `agents` 行。
    /// 这样一台没有新命中的机器也能出现在控制台「终端」页；否则服务端
    /// 只能看到「曾经告警过的机器」，运维会误判为离线。
    pub fn touch_agent(
        &self,
        agent_id: &str,
        hostname: &str,
        username: &str,
        platform: &str,
        version: &str,
        remote_addr: &str,
    ) -> Result<()> {
        let now = crate::util::now_ts();
        // 与 ingest 保持同一套兜底规则，避免同一台机器出现两条记录。
        let agent_id = if agent_id.trim().is_empty() {
            format!("legacy-{}", crate::util::sha256_hex_str(hostname.trim()))
        } else {
            agent_id.trim().to_string()
        };
        let hostname = if hostname.trim().is_empty() {
            "unknown".to_string()
        } else {
            hostname.trim().to_string()
        };
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO agents(id, hostname, username, platform, version, first_seen, last_seen, rule_revision, remote_addr)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6, 0, ?7)
             ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                username = CASE WHEN excluded.username = '' THEN agents.username ELSE excluded.username END,
                platform = CASE WHEN excluded.platform = '' THEN agents.platform ELSE excluded.platform END,
                version = CASE WHEN excluded.version = '' THEN agents.version ELSE excluded.version END,
                last_seen = excluded.last_seen,
                remote_addr = excluded.remote_addr",
            params![
                agent_id,
                hostname,
                username.trim(),
                platform.trim(),
                version.trim(),
                now,
                remote_addr,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn agents(&self) -> Result<Vec<Agent>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, hostname, username, platform, version, first_seen, last_seen, rule_revision, remote_addr
             FROM agents ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Agent {
                id: row.get(0)?,
                hostname: row.get(1)?,
                username: row.get(2)?,
                platform: row.get(3)?,
                version: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                rule_revision: row.get(7)?,
                remote_addr: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn delete_agent(&self, agent_id: &str) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM events WHERE agent_id = ?1", params![agent_id])?;
        tx.execute(
            "DELETE FROM agent_rule_state WHERE agent_id = ?1",
            params![agent_id],
        )?;
        tx.execute("DELETE FROM agents WHERE id = ?1", params![agent_id])?;
        tx.commit()?;
        Ok(())
    }

    // ------------------------------------------------------------- events --

    pub fn events(&self, filter: &EventFilter) -> Result<(Vec<ServerEvent>, u64)> {
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if !filter.user.trim().is_empty() {
            clauses.push("(username = ? OR hostname = ?)".to_string());
            args.push(Box::new(filter.user.trim().to_string()));
            args.push(Box::new(filter.user.trim().to_string()));
        }
        if !filter.hostname.trim().is_empty() {
            clauses.push("hostname = ?".to_string());
            args.push(Box::new(filter.hostname.trim().to_string()));
        }
        if !filter.category.trim().is_empty() {
            clauses.push("category = ?".to_string());
            args.push(Box::new(filter.category.trim().to_string()));
        }
        if !filter.severity.trim().is_empty() {
            // 支持 "high" 单值，也支持 "high,critical" 多选。
            let values: Vec<String> = filter
                .severity
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect();
            if !values.is_empty() {
                let placeholders = values.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                clauses.push(format!("severity IN ({placeholders})"));
                for value in values {
                    args.push(Box::new(value));
                }
            }
        }
        if !filter.rule_id.trim().is_empty() {
            clauses.push("rule_id = ?".to_string());
            args.push(Box::new(filter.rule_id.trim().to_string()));
        }
        if !filter.q.trim().is_empty() {
            clauses.push(
                "(masked LIKE ? OR matched LIKE ? OR file_name LIKE ? OR path LIKE ? OR snippet LIKE ? OR rule_name LIKE ? OR hostname LIKE ? OR username LIKE ?)"
                    .to_string(),
            );
            let pattern = format!("%{}%", filter.q.trim());
            for _ in 0..8 {
                args.push(Box::new(pattern.clone()));
            }
        }
        if let Some(since) = filter.since {
            clauses.push("received_at >= ?".to_string());
            args.push(Box::new(since));
        }
        if let Some(until) = filter.until {
            clauses.push("received_at <= ?".to_string());
            args.push(Box::new(until));
        }

        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };

        let limit = filter.limit.unwrap_or(100).clamp(1, 1000);
        let offset = filter.offset.unwrap_or(0);

        let conn = self.conn()?;
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM events{where_sql}"),
            rusqlite::params_from_iter(args.iter().map(|value| value.as_ref())),
            |row| row.get(0),
        )?;

        let mut stmt = conn.prepare(&format!(
            "SELECT id, agent_id, hostname, username, rule_id, rule_name, category, severity,
                    masked, matched, file_name, path, line, column_no, snippet, event_time, received_at
             FROM events{where_sql}
             ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?"
        ))?;
        let mut all_args: Vec<Box<dyn rusqlite::ToSql>> = args;
        all_args.push(Box::new(limit as i64));
        all_args.push(Box::new(offset as i64));
        let rows = stmt.query_map(
            rusqlite::params_from_iter(all_args.iter().map(|value| value.as_ref())),
            map_event,
        )?;
        let events = rows.collect::<Result<Vec<_>, _>>()?;
        Ok((events, total.max(0) as u64))
    }

    /// 总体概览：事件数、按级别分布、按类型分布、Agent 数。
    pub fn overview(&self) -> Result<serde_json::Value> {
        let conn = self.conn()?;
        let events: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        let agents: i64 = conn.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let today_start = crate::util::now_ts() - 86_400;
        let today: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE received_at >= ?1",
            params![today_start],
            |row| row.get(0),
        )?;

        let mut by_severity = serde_json::Map::new();
        {
            let mut stmt =
                conn.prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (severity, count) = row?;
                by_severity.insert(severity, serde_json::json!(count));
            }
        }

        let mut by_category = serde_json::Map::new();
        {
            let mut stmt = conn.prepare(
                "SELECT category, COUNT(*) FROM events GROUP BY category ORDER BY 2 DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (category, count) = row?;
                by_category.insert(category, serde_json::json!(count));
            }
        }

        let mut top_rules: Vec<serde_json::Value> = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT rule_id, rule_name, COUNT(*) AS c FROM events GROUP BY rule_id ORDER BY c DESC LIMIT 10",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (rule_id, rule_name, count) = row?;
                top_rules.push(serde_json::json!({
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "count": count,
                }));
            }
        }

        Ok(serde_json::json!({
            "events": events,
            "agents": agents,
            "events_24h": today,
            "by_severity": by_severity,
            "by_category": by_category,
            "top_rules": top_rules,
        }))
    }

    /// 按用户聚合：一个用户（终端使用者）一行的总览。
    pub fn user_summaries(&self) -> Result<Vec<UserSummary>> {
        let conn = self.conn()?;
        // 用户维度 = username 非空则按 username，否则回落到 hostname。
        let mut stmt = conn.prepare(
            "SELECT
                CASE WHEN username = '' THEN hostname ELSE username END AS user_key,
                hostname,
                COUNT(*) AS events,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END),
                MAX(received_at)
             FROM events
             GROUP BY user_key
             ORDER BY events DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(UserSummary {
                user: row.get(0)?,
                hostname: row.get(1)?,
                events: row.get::<_, i64>(2)?.max(0) as u64,
                critical: row.get::<_, i64>(3)?.max(0) as u64,
                high: row.get::<_, i64>(4)?.max(0) as u64,
                medium: row.get::<_, i64>(5)?.max(0) as u64,
                low: row.get::<_, i64>(6)?.max(0) as u64,
                last_seen: row.get(7)?,
                agents: 0,
                categories: BTreeMap::new(),
            })
        })?;
        let mut summaries = rows.collect::<Result<Vec<_>, _>>()?;

        // 补上每个用户的类型分布与 Agent 数。
        let mut by_user_category: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT CASE WHEN username = '' THEN hostname ELSE username END AS user_key,
                        category, COUNT(*)
                 FROM events GROUP BY user_key, category",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (user, category, count) = row?;
                by_user_category
                    .entry(user)
                    .or_default()
                    .insert(category, count.max(0) as u64);
            }
        }
        let mut agents_by_user: BTreeMap<String, u64> = BTreeMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT CASE WHEN username = '' THEN hostname ELSE username END AS user_key, COUNT(*)
                 FROM agents GROUP BY user_key",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (user, count) = row?;
                agents_by_user.insert(user, count.max(0) as u64);
            }
        }
        for summary in &mut summaries {
            summary.categories = by_user_category.remove(&summary.user).unwrap_or_default();
            summary.agents = agents_by_user.get(&summary.user).copied().unwrap_or(0);
        }
        Ok(summaries)
    }

    /// 供筛选下拉框使用：出现过的类型、级别、主机、用户。
    pub fn facets(&self) -> Result<serde_json::Value> {
        let conn = self.conn()?;
        let collect = |sql: &str| -> Result<Vec<String>> {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.filter_map(Result::ok).collect())
        };
        let users = collect(
            "SELECT DISTINCT CASE WHEN username = '' THEN hostname ELSE username END FROM events ORDER BY 1",
        )?;
        let hosts = collect("SELECT DISTINCT hostname FROM events ORDER BY 1")?;
        let categories =
            collect("SELECT DISTINCT category FROM events WHERE category <> '' ORDER BY 1")?;
        let severities = collect("SELECT DISTINCT severity FROM events ORDER BY 1")?;
        Ok(serde_json::json!({
            "users": users,
            "hostnames": hosts,
            "categories": categories,
            "severities": severities,
        }))
    }

    pub fn purge_events_before(&self, ts: i64) -> Result<usize> {
        let conn = self.conn()?;
        Ok(conn.execute("DELETE FROM events WHERE received_at < ?1", params![ts])?)
    }

    /// 按保留期清理所有会持续增长的表。
    ///
    /// 原来只删 `events`，但 `audit_log`、`rule_sets` 与长期离线的 `agents`
    /// 会一直累积 —— 服务端跑一年后数据库体积几乎只增不减。这里统一清理：
    /// - `events` / `audit_log`：按时间保留；
    /// - `rule_sets`：保留最近 `keep_rule_revisions` 个版本（回滚窗口）；
    /// - `agents`：超过保留期仍未上报的终端（连同其规则状态）。
    pub fn purge_old_data(
        &self,
        cutoff_ts: i64,
        keep_rule_revisions: usize,
    ) -> Result<PurgeReport> {
        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let events = tx.execute(
            "DELETE FROM events WHERE received_at < ?1",
            params![cutoff_ts],
        )?;
        let audit = tx.execute("DELETE FROM audit_log WHERE at < ?1", params![cutoff_ts])?;

        // 保留最近 N 个规则版本：找出“最老的保留版本”，删除更旧的。
        // OFFSET 取 keep-1（第 N 新），否则会少删一个、实际多保留一版。
        let keep = keep_rule_revisions.max(1) as i64;
        let boundary: Option<i64> = tx
            .query_row(
                "SELECT revision FROM rule_sets ORDER BY revision DESC LIMIT 1 OFFSET ?1",
                params![keep - 1],
                |row| row.get(0),
            )
            .optional()?;
        let rule_sets = match boundary {
            Some(boundary) => tx.execute(
                "DELETE FROM rule_sets WHERE revision < ?1",
                params![boundary],
            )?,
            None => 0,
        };

        let agents = tx.execute(
            "DELETE FROM agents WHERE last_seen < ?1",
            params![cutoff_ts],
        )?;
        if agents > 0 {
            tx.execute(
                "DELETE FROM agent_rule_state WHERE agent_id NOT IN (SELECT id FROM agents)",
                [],
            )?;
        }
        tx.commit()?;

        Ok(PurgeReport {
            events,
            audit,
            rule_sets,
            agents,
        })
    }
}

/// 一次保留期清理的结果。
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeReport {
    pub events: usize,
    pub audit: usize,
    pub rule_sets: usize,
    pub agents: usize,
}

impl PurgeReport {
    pub fn total(&self) -> usize {
        self.events + self.audit + self.rule_sets + self.agents
    }
}

fn extract_file_name(file_name: &str, path: &str) -> String {
    let trimmed = file_name.trim();
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    path.trim()
        .rsplit(['/', '\\'])
        .find(|segment| !segment.is_empty())
        .unwrap_or("")
        .to_string()
}

fn map_event(row: &Row<'_>) -> rusqlite::Result<ServerEvent> {
    let severity: String = row.get(7)?;
    let masked: String = row.get(8)?;
    let matched: String = row.get(9)?;
    let file_name: String = row.get(10)?;
    let path: String = row.get(11)?;
    Ok(ServerEvent {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        hostname: row.get(2)?,
        username: row.get(3)?,
        rule_id: row.get(4)?,
        rule_name: row.get(5)?,
        category: row.get(6)?,
        severity: severity.parse().unwrap_or(Severity::Medium),
        matched: if matched.is_empty() {
            masked.clone()
        } else {
            matched
        },
        masked,
        file_name: extract_file_name(&file_name, &path),
        path,
        line: row.get::<_, i64>(12)?.max(0) as usize,
        column: row.get::<_, i64>(13)?.max(0) as usize,
        snippet: row.get(14)?,
        event_time: row.get(15)?,
        received_at: row.get(16)?,
    })
}
