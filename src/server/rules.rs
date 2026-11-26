//! 统一规则下发：服务端保存整份规则文档，客户端按版本拉取并在本地应用。
//!
//! 文档结构与客户端 `RulesConfig` 保持一致（同一份 serde 定义），
//! 但额外带 `revision` / `updated_at` / `note`，便于客户端判断是否需要更新。

use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::config::{AgentPolicy, CustomRuleConfig, RulesConfig};
use crate::model::Severity;
use crate::rules::validator::parse_validators;
use crate::rules::RuleSet;
use crate::util::now_ts;

use super::store::ServerStore;

/// 下发给客户端的规则与统一策略文档。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesDocument {
    /// 规则版本号，单调递增；客户端据此判断是否更新。
    pub revision: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub note: String,
    /// 与客户端 `config.rules` 完全同构。
    pub rules: RulesConfig,
    /// 服务端统一下发的客户端扫描路径、定时策略与白名单。
    #[serde(default)]
    pub policy: AgentPolicy,
    /// 该版本编译后的规则个数，方便前端展示。
    #[serde(default)]
    pub rule_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBundlePayload {
    rules: RulesConfig,
    #[serde(default)]
    policy: AgentPolicy,
}

fn decode_bundle_payload(payload: &str) -> Result<(RulesConfig, AgentPolicy)> {
    let value: serde_json::Value = serde_json::from_str(payload)?;
    if value.get("rules").is_some() {
        let bundle: StoredBundlePayload = serde_json::from_value(value)?;
        Ok((bundle.rules, bundle.policy))
    } else {
        let rules: RulesConfig = serde_json::from_value(value)?;
        Ok((rules, AgentPolicy::default()))
    }
}

impl RulesDocument {
    /// 校验文档是否可用：正则能编译、id 不重复、校验器合法。
    ///
    /// 下发前必须过这一关——一条坏规则会让所有客户端后续扫描全部失败。
    pub fn validate(&self) -> Result<()> {
        if self.rules.min_severity < Severity::Info {
            bail!("min_severity 非法");
        }
        for rule in &self.rules.custom {
            if rule.id.trim().is_empty() {
                bail!("自定义规则缺少 id");
            }
            if rule.pattern.trim().is_empty() {
                bail!("自定义规则 {} 缺少 pattern", rule.id);
            }
            regex::Regex::new(&rule.pattern)
                .with_context(|| format!("规则 {} 的正则无法编译", rule.id))?;
            parse_validators(&rule.validator)
                .with_context(|| format!("规则 {} 的校验器配置无效", rule.id))?;
        }
        RuleSet::build(&self.rules).context("规则集整体编译失败")?;
        Ok(())
    }
}

impl ServerStore {
    /// 当前生效的规则版本；从未发布过时返回 `None`。
    pub fn current_rules(&self) -> Result<Option<RulesDocument>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT revision, payload, created_at, note FROM rule_sets ORDER BY revision DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((revision, payload, created_at, note)) = row else {
            return Ok(None);
        };
        let (rules, policy) = decode_bundle_payload(&payload)
            .with_context(|| format!("规则版本 {revision} 的 JSON 无法解析"))?;
        let rule_count = RuleSet::build(&rules)
            .map(|set| set.rules().len())
            .unwrap_or(0);
        Ok(Some(RulesDocument {
            revision,
            updated_at: created_at,
            note,
            rules,
            policy,
            rule_count,
        }))
    }

    pub fn rules_history(&self, limit: usize) -> Result<Vec<RulesDocument>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT revision, payload, created_at, note FROM rule_sets ORDER BY revision DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 200) as i64], |row| {
            Ok::<(i64, String, i64, String), rusqlite::Error>((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (revision, payload, created_at, note) = row?;
            let (rules, policy) = match decode_bundle_payload(&payload) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            let rule_count = RuleSet::build(&rules)
                .map(|set| set.rules().len())
                .unwrap_or(0);
            out.push(RulesDocument {
                revision,
                updated_at: created_at,
                note,
                rules,
                policy,
                rule_count,
            });
        }
        Ok(out)
    }

    /// 发布新规则版本（保留接口兼容，默认复用默认策略）。
    pub fn publish_rules(
        &self,
        rules: RulesConfig,
        note: &str,
        actor: &str,
        dedupe: bool,
    ) -> Result<RulesDocument> {
        self.publish_bundle(rules, AgentPolicy::default(), note, actor, dedupe)
    }

    /// 发布新策略版本（含规则 + 客户端扫描目录/定时策略/白名单）。
    pub fn publish_bundle(
        &self,
        rules: RulesConfig,
        policy: AgentPolicy,
        note: &str,
        actor: &str,
        dedupe: bool,
    ) -> Result<RulesDocument> {
        let bundle = StoredBundlePayload {
            rules: rules.clone(),
            policy: policy.clone(),
        };
        let payload = serde_json::to_string(&bundle).context("序列化策略失败")?;
        let mut doc = RulesDocument {
            revision: 0,
            updated_at: now_ts(),
            note: note.to_string(),
            rules,
            policy,
            rule_count: 0,
        };
        doc.validate()?;
        doc.rule_count = RuleSet::build(&doc.rules)
            .map(|set| set.rules().len())
            .unwrap_or(0);

        let mut conn = self.conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if dedupe {
            let current: Option<(i64, String)> = tx
                .query_row(
                    "SELECT revision, payload FROM rule_sets ORDER BY revision DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((revision, existing)) = current {
                if existing == payload {
                    drop(tx);
                    let mut same = doc;
                    same.revision = revision;
                    return Ok(same);
                }
            }
        }

        tx.execute(
            "INSERT INTO rule_sets(payload, note, created_at, created_by) VALUES(?1, ?2, ?3, ?4)",
            params![payload, doc.note, doc.updated_at, actor],
        )?;
        let revision = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO audit_log(at, actor, action, detail) VALUES(?1, ?2, 'publish_rules', ?3)",
            params![
                now_ts(),
                actor,
                format!("revision={revision} rules={}", doc.rule_count)
            ],
        )?;
        tx.commit()?;

        doc.revision = revision;
        Ok(doc)
    }

    /// 客户端上报「我已应用版本 X」。
    pub fn record_agent_revision(&self, agent_id: &str, revision: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO agent_rule_state(agent_id, revision, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(agent_id) DO UPDATE SET revision = excluded.revision, updated_at = excluded.updated_at",
            params![agent_id, revision, now_ts()],
        )?;
        Ok(())
    }

    /// 规则同步状态：哪些终端还没跟上最新版本。
    pub fn rule_sync_status(&self) -> Result<serde_json::Value> {
        let conn = self.conn()?;
        let latest: Option<i64> = conn
            .query_row("SELECT MAX(revision) FROM rule_sets", [], |row| row.get(0))
            .optional()?
            .flatten();
        let latest = latest.unwrap_or(0);

        let mut agents = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT a.id, a.hostname, a.username, a.last_seen,
                        COALESCE(s.revision, 0) AS applied
                 FROM agents a
                 LEFT JOIN agent_rule_state s ON s.agent_id = a.id
                 ORDER BY a.last_seen DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "agent_id": row.get::<_, String>(0)?,
                    "hostname": row.get::<_, String>(1)?,
                    "username": row.get::<_, String>(2)?,
                    "last_seen": row.get::<_, i64>(3)?,
                    "applied_revision": row.get::<_, i64>(4)?,
                }))
            })?;
            for row in rows {
                agents.push(row?);
            }
        }
        let up_to_date = agents
            .iter()
            .filter(|item| item["applied_revision"].as_i64().unwrap_or(0) >= latest)
            .count();
        Ok(serde_json::json!({
            "latest_revision": latest,
            "agents": agents,
            "up_to_date": up_to_date,
        }))
    }

    /// 回滚到历史版本：把旧版本内容作为新版本重新发布，保留完整链路。
    pub fn rollback_rules(&self, revision: i64, actor: &str) -> Result<RulesDocument> {
        let conn = self.conn()?;
        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM rule_sets WHERE revision = ?1",
                params![revision],
                |row| row.get(0),
            )
            .optional()?;
        drop(conn);
        let Some(payload) = payload else {
            bail!("规则版本 {revision} 不存在");
        };
        let (rules, policy) = decode_bundle_payload(&payload)
            .with_context(|| format!("规则版本 {revision} 的 JSON 无法解析"))?;
        self.publish_bundle(
            rules,
            policy,
            &format!("回滚自版本 {revision}"),
            actor,
            false,
        )
    }

    pub fn audit_log(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT at, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit.clamp(1, 500) as i64], |row| {
            Ok(serde_json::json!({
                "at": row.get::<_, i64>(0)?,
                "actor": row.get::<_, String>(1)?,
                "action": row.get::<_, String>(2)?,
                "detail": row.get::<_, String>(3)?,
            }))
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn record_audit(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO audit_log(at, actor, action, detail) VALUES(?1, ?2, ?3, ?4)",
            params![now_ts(), actor, action, detail],
        )?;
        Ok(())
    }
}

/// 客户端默认的规则文档（首次部署、服务端未发布任何规则时使用）。
pub fn default_rules_document() -> RulesDocument {
    RulesDocument {
        revision: 0,
        updated_at: now_ts(),
        note: "内置默认规则".to_string(),
        rules: RulesConfig::default(),
        policy: AgentPolicy::default(),
        rule_count: RuleSet::build(&RulesConfig::default())
            .map(|set| set.rules().len())
            .unwrap_or(0),
    }
}

/// 供服务端首启时预置一份「当前内置规则」。
pub fn builtin_rules_snapshot() -> Vec<serde_json::Value> {
    crate::rules::builtin::BUILTIN_RULES
        .iter()
        .map(|spec| {
            serde_json::json!({
                "id": spec.id,
                "name": spec.name,
                "category": spec.category,
                "severity": spec.severity.as_str(),
                "severity_label": spec.severity.label_zh(),
                "description": spec.description,
                "validators": spec.validators,
                "pattern": spec.pattern,
                "keywords": spec.keywords,
                "builtin": true,
            })
        })
        .collect()
}

/// 把单个自定义规则转换成前端可编辑的结构。
pub fn custom_rule_view(rule: &CustomRuleConfig) -> serde_json::Value {
    serde_json::json!({
        "id": rule.id,
        "name": rule.name,
        "category": rule.category,
        "severity": rule.severity.as_str(),
        "pattern": rule.pattern,
        "keywords": rule.keywords,
        "validator": rule.validator,
        "description": rule.description,
        "context_chars": rule.context_chars,
        "builtin": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, ServerStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ServerStore::open(&dir.path().join("srv.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn publish_and_dedupe() {
        let (_dir, store) = temp_store();
        let doc = store
            .publish_rules(RulesConfig::default(), "初始", "admin", true)
            .unwrap();
        assert!(doc.revision > 0);
        assert!(doc.rule_count > 0);

        // 内容相同：版本号不变
        let same = store
            .publish_rules(RulesConfig::default(), "再点一次", "admin", true)
            .unwrap();
        assert_eq!(same.revision, doc.revision);

        // 关闭去重后会新增版本
        let bumped = store
            .publish_rules(RulesConfig::default(), "强制", "admin", false)
            .unwrap();
        assert!(bumped.revision > doc.revision);
    }

    #[test]
    fn rejects_broken_regex() {
        let (_dir, store) = temp_store();
        let mut rules = RulesConfig::default();
        rules.custom.push(CustomRuleConfig {
            id: "broken".to_string(),
            name: "坏规则".to_string(),
            pattern: "([unclosed".to_string(),
            ..CustomRuleConfig::default()
        });
        assert!(store.publish_rules(rules, "", "admin", true).is_err());
    }

    #[test]
    fn rollback_creates_new_revision() {
        let (_dir, store) = temp_store();
        let first = store
            .publish_rules(RulesConfig::default(), "v1", "admin", false)
            .unwrap();

        let mut changed = RulesConfig::default();
        changed.disabled.push("email".to_string());
        let second = store.publish_rules(changed, "v2", "admin", false).unwrap();
        assert!(second.revision > first.revision);

        let rolled = store.rollback_rules(first.revision, "admin").unwrap();
        assert!(rolled.revision > second.revision);
        // 回滚后应恢复成 v1 的内容（email 重新启用）
        assert!(!rolled.rules.disabled.contains(&"email".to_string()));
        assert_eq!(
            store.current_rules().unwrap().unwrap().revision,
            rolled.revision
        );
    }

    #[test]
    fn tracks_agent_revisions() {
        let (_dir, store) = temp_store();
        let doc = store
            .publish_rules(RulesConfig::default(), "v1", "admin", false)
            .unwrap();
        store
            .record_agent_revision("agent-1", doc.revision)
            .unwrap();
        let status = store.rule_sync_status().unwrap();
        assert_eq!(status["latest_revision"], doc.revision);
    }

    /// 保留期清理必须同时收敛 events / audit / rule_sets / agents，
    /// 否则服务端长期运行后数据库只增不减。
    #[test]
    fn purge_old_data_prunes_every_growing_table() {
        use super::super::store::{IncomingBatch, IncomingFinding};
        let dir = tempfile::tempdir().unwrap();
        let store = ServerStore::open(&dir.path().join("srv.db")).unwrap();

        // 生成 5 个规则版本。
        for index in 0..5 {
            let mut rules = RulesConfig::default();
            rules.custom.push(CustomRuleConfig {
                id: format!("r{index}"),
                pattern: r"EMP-\d{6}".to_string(),
                ..CustomRuleConfig::default()
            });
            store.publish_rules(rules, "v", "admin", false).unwrap();
        }

        // 一条告警 + 一台终端。
        let batch = IncomingBatch {
            agent_id: "agent-1".to_string(),
            hostname: "pc01".to_string(),
            username: "alice".to_string(),
            platform: "linux".to_string(),
            version: "0.2.2".to_string(),
            rule_revision: 1,
            findings: vec![IncomingFinding {
                rule_id: "cn_mobile".to_string(),
                rule_name: "手机".to_string(),
                category: "contact".to_string(),
                severity: "high".to_string(),
                masked: "138********5678".to_string(),
                matched: "138********5678".to_string(),
                file_name: "a.txt".to_string(),
                path: "/tmp/a.txt".to_string(),
                line: 1,
                column: 1,
                snippet: String::new(),
                match_hash: "h".to_string(),
                time: String::new(),
            }],
        };
        store.ingest(&batch, "127.0.0.1").unwrap();

        // 用一个“未来”的截止时间把全部数据都判为过期。
        let cutoff = crate::util::now_ts() + 86_400;
        let report = store.purge_old_data(cutoff, 2).unwrap();
        assert_eq!(report.events, 1);
        assert_eq!(report.agents, 1);
        // 5 个版本只保留 2 个。
        assert_eq!(report.rule_sets, 3);
        assert!(report.audit >= 1);

        assert!(store
            .events(&crate::server::store::EventFilter::default())
            .unwrap()
            .0
            .is_empty());
        assert!(store.agents().unwrap().is_empty());
        assert_eq!(store.rules_history(100).unwrap().len(), 2);
    }

    #[test]
    fn delete_file_command_lifecycle() {
        use crate::server::store::{EventFilter, IncomingBatch, IncomingFinding};
        let dir = tempfile::tempdir().unwrap();
        let store = ServerStore::open(&dir.path().join("server.db")).unwrap();
        let batch = IncomingBatch {
            agent_id: "agent-del".to_string(),
            hostname: "pc-del".to_string(),
            username: "bob".to_string(),
            platform: "macos".to_string(),
            version: "0.3.0".to_string(),
            rule_revision: 1,
            findings: vec![IncomingFinding {
                rule_id: "cn_mobile".to_string(),
                rule_name: "手机".to_string(),
                category: "contact".to_string(),
                severity: "high".to_string(),
                masked: "138********5678".to_string(),
                matched: "13812345678".to_string(),
                file_name: "leak.txt".to_string(),
                path: "/tmp/leak.txt".to_string(),
                line: 1,
                column: 1,
                snippet: String::new(),
                match_hash: "h-del".to_string(),
                time: String::new(),
            }],
        };
        store.ingest(&batch, "127.0.0.1").unwrap();
        let (events, _) = store.events(&EventFilter::default()).unwrap();
        let cmd = store.enqueue_delete_file(events[0].id, "admin").unwrap();
        assert_eq!(cmd.status, "pending");

        let pending = store.pending_commands_for_agent("agent-del").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].target_path, "/tmp/leak.txt");

        store
            .ack_command("agent-del", cmd.id, "done", "已删除文件")
            .unwrap();
        assert!(store
            .pending_commands_for_agent("agent-del")
            .unwrap()
            .is_empty());
        let (events_after, _) = store.events(&EventFilter::default()).unwrap();
        assert!(events_after[0].file_deleted);
    }
}
