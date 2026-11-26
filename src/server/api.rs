//! 服务端 JSON API。
//!
//! 分两类：
//! - `/api/agent/*`：客户端专用，只认共享 Agent Token。
//!   客户端用它拉取规则、上报「已应用版本」。
//! - 其余 `/api/*`：控制台专用，需要管理员会话。

use std::time::Instant;

use serde_json::{json, Value};

use super::store::EventFilter;
use super::{AppState, AuthState};
use crate::server::auth::constant_time_eq;
use crate::server::http::Request;

pub const JSON: &str = "application/json; charset=utf-8";

pub fn ok(value: Value) -> (u16, &'static str, Vec<u8>) {
    (200, JSON, serde_json::to_vec(&value).unwrap_or_default())
}

pub fn created(value: Value) -> (u16, &'static str, Vec<u8>) {
    (201, JSON, serde_json::to_vec(&value).unwrap_or_default())
}

pub fn error_response(status: u16, message: impl Into<String>) -> (u16, &'static str, Vec<u8>) {
    let body = json!({ "error": message.into() });
    (status, JSON, serde_json::to_vec(&body).unwrap_or_default())
}

fn fail(error: anyhow::Error) -> (u16, &'static str, Vec<u8>) {
    tracing::warn!(error = %format!("{error:#}"), "服务端接口调用失败");
    error_response(500, format!("{error:#}"))
}

// ------------------------------------------------------------------ 鉴权 --

/// 登录：校验口令并下发会话 Cookie。
///
/// 返回 `(响应, Set-Cookie)`。Cookie 设为 `HttpOnly` + `SameSite=Strict`，
/// 避免被前端脚本读取或被跨站请求携带。
///
/// 连续失败会按来源 IP 限流：`LoginThrottle` 记录了失败次数，但必须在这里
/// 真正读取它，否则“锁定”形同虚设，口令仍可被无限爆破。
pub fn login(
    auth: &AuthState,
    request: &Request,
) -> ((u16, &'static str, Vec<u8>), Option<String>) {
    if auth.locked(&request.remote) {
        tracing::warn!(remote = %request.remote, "登录失败次数过多，已临时锁定");
        return (error_response(429, "失败次数过多，请稍后再试"), None);
    }
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return (error_response(400, error), None),
    };
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return (error_response(400, "缺少 password"), None);
    };

    if !auth.verify(password) {
        auth.record_failure(&request.remote);
        tracing::warn!(remote = %request.remote, "控制台登录失败");
        return (error_response(401, "口令错误"), None);
    }
    auth.clear_failures(&request.remote);

    let token = auth.sessions.issue();
    let cookie = format!(
        "sentinel_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        auth.session_ttl.as_secs()
    );
    tracing::info!(remote = %request.remote, "控制台登录成功");
    (ok(json!({ "ok": true })), Some(cookie))
}

pub fn logout(
    auth: &AuthState,
    request: &Request,
) -> ((u16, &'static str, Vec<u8>), Option<String>) {
    if let Some(token) = request.cookie("sentinel_session") {
        auth.sessions.revoke(&token);
    }
    let cookie = "sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string();
    (ok(json!({ "ok": true })), Some(cookie))
}

/// 校验控制台会话；成功返回操作者标识（用于审计）。
pub fn authorize(
    auth: &AuthState,
    request: &Request,
) -> Result<String, (u16, &'static str, Vec<u8>)> {
    let Some(token) = request.cookie("sentinel_session") else {
        return Err(error_response(401, "未登录"));
    };
    if !auth.sessions.valid(&token) {
        return Err(error_response(401, "会话已过期，请重新登录"));
    }
    Ok(format!("admin@{}", request.remote))
}

/// 校验 Agent 共享 Token。
fn authorize_agent(auth: &AuthState, request: &Request) -> bool {
    let Some(token) = request.bearer() else {
        return false;
    };
    constant_time_eq(token, &auth.agent_token)
}

// -------------------------------------------------------------- Agent API --

pub fn handle_agent(request: &Request, state: &AppState) -> (u16, &'static str, Vec<u8>) {
    match (request.method.as_str(), request.path.as_str()) {
        // 拉取当前生效规则。允许匿名仅在显式配置时放开。
        ("GET", "/api/agent/rules") => {
            if !state.auth.allow_anonymous_rules && !authorize_agent(&state.auth, request) {
                return error_response(401, "Agent Token 无效");
            }
            match state.store.current_rules() {
                Ok(Some(document)) => ok(json!({
                    "revision": document.revision,
                    "updated_at": document.updated_at,
                    "note": document.note,
                    "rule_count": document.rule_count,
                    "rules": document.rules,
                    "policy": document.policy,
                })),
                Ok(None) => {
                    // 尚未发布：返回内置默认规则，客户端可直接使用。
                    let fallback = crate::server::rules::default_rules_document();
                    ok(json!({
                        "revision": 0,
                        "updated_at": fallback.updated_at,
                        "note": fallback.note,
                        "rule_count": fallback.rule_count,
                        "rules": fallback.rules,
                        "policy": fallback.policy,
                    }))
                }
                Err(error) => fail(error),
            }
        }
        // 客户端上报「已应用版本」。
        ("POST", "/api/agent/revision") => {
            if !authorize_agent(&state.auth, request) {
                return error_response(401, "Agent Token 无效");
            }
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let agent_id = body
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let revision = body.get("revision").and_then(Value::as_i64).unwrap_or(0);
            if agent_id.trim().is_empty() {
                return error_response(400, "缺少 agent_id");
            }
            match state.store.record_agent_revision(agent_id, revision) {
                Ok(()) => ok(json!({ "ok": true })),
                Err(error) => fail(error),
            }
        }
        // 客户端拉取待执行的远程指令（如删除敏感文件）。
        ("GET", "/api/agent/commands") => {
            if !authorize_agent(&state.auth, request) {
                return error_response(401, "Agent Token 无效");
            }
            let params = request.query_params();
            let agent_id = params.get("agent_id").map(String::as_str).unwrap_or("");
            if agent_id.trim().is_empty() {
                return error_response(400, "缺少 agent_id");
            }
            match state.store.pending_commands_for_agent(agent_id) {
                Ok(commands) => ok(json!({ "items": commands })),
                Err(error) => fail(error),
            }
        }
        // 客户端回传指令执行结果。
        ("POST", "/api/agent/commands/ack") => {
            if !authorize_agent(&state.auth, request) {
                return error_response(401, "Agent Token 无效");
            }
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let agent_id = body.get("agent_id").and_then(Value::as_str).unwrap_or("");
            let command_id = body.get("command_id").and_then(Value::as_i64).unwrap_or(0);
            let status = body
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("failed");
            let message = body.get("message").and_then(Value::as_str).unwrap_or("");
            if agent_id.trim().is_empty() || command_id <= 0 {
                return error_response(400, "缺少 agent_id 或 command_id");
            }
            match state
                .store
                .ack_command(agent_id, command_id, status, message)
            {
                Ok(()) => ok(json!({ "ok": true })),
                Err(error) => fail(error),
            }
        }
        _ => error_response(404, "Agent 接口不存在"),
    }
}

// ---------------------------------------------------------- 控制台 API --

pub fn handle(request: &Request, state: &AppState, actor: &str) -> (u16, &'static str, Vec<u8>) {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/me") => ok(json!({ "actor": actor, "version": env!("CARGO_PKG_VERSION") })),

        ("GET", "/api/overview") => match state.store.overview() {
            Ok(mut value) => {
                value["ingest"] = state.ingest_stats.snapshot();
                value["uptime_secs"] = json!(state.started_at.elapsed().as_secs());
                ok(value)
            }
            Err(error) => fail(error),
        },

        ("GET", "/api/users") => match state.store.user_summaries() {
            Ok(rows) => ok(json!({ "items": rows })),
            Err(error) => fail(error),
        },

        ("GET", "/api/events") => {
            let filter = filter_from_query(&request.query_params());
            match state.store.events(&filter) {
                Ok((events, total)) => ok(json!({
                    "items": events,
                    "total": total,
                    "limit": filter.limit.unwrap_or(100),
                    "offset": filter.offset.unwrap_or(0),
                })),
                Err(error) => fail(error),
            }
        }

        ("GET", "/api/facets") => match state.store.facets() {
            Ok(value) => ok(value),
            Err(error) => fail(error),
        },

        ("POST", "/api/events/delete-file") => {
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let Some(event_id) = body.get("event_id").and_then(Value::as_i64) else {
                return error_response(400, "缺少 event_id");
            };
            match state.store.enqueue_delete_file(event_id, actor) {
                Ok(cmd) => ok(json!({ "ok": true, "command": cmd })),
                Err(error) => error_response(400, format!("{error:#}")),
            }
        }

        ("GET", "/api/agents") => match state.store.agents() {
            Ok(agents) => ok(json!({ "items": agents })),
            Err(error) => fail(error),
        },

        ("DELETE", "/api/agents") => {
            let Some(agent_id) = request.query_params().get("id").cloned() else {
                return error_response(400, "缺少 id");
            };
            match state.store.delete_agent(&agent_id) {
                Ok(()) => {
                    let _ = state.store.record_audit(actor, "delete_agent", &agent_id);
                    ok(json!({ "ok": true }))
                }
                Err(error) => fail(error),
            }
        }

        ("GET", "/api/rules") => match state.store.current_rules() {
            Ok(document) => {
                let doc = document.unwrap_or_else(crate::server::rules::default_rules_document);
                // 内置规则清单供前端展示「哪些是内置、不可删除」。
                ok(json!({
                    "current": doc,
                    "builtin": crate::server::rules::builtin_rules_snapshot(),
                }))
            }
            Err(error) => fail(error),
        },

        ("GET", "/api/rules/history") => match state.store.rules_history(50) {
            Ok(items) => ok(json!({ "items": items })),
            Err(error) => fail(error),
        },

        ("POST", "/api/rules") => {
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let Some(rules_value) = body.get("rules") else {
                return error_response(400, "缺少 rules");
            };
            let rules: crate::config::RulesConfig =
                match serde_json::from_value(rules_value.clone()) {
                    Ok(rules) => rules,
                    Err(error) => return error_response(400, format!("rules 结构不合法：{error}")),
                };
            let note = body.get("note").and_then(Value::as_str).unwrap_or("");
            let policy = if let Some(policy_val) = body.get("policy") {
                match serde_json::from_value::<crate::config::AgentPolicy>(policy_val.clone()) {
                    Ok(policy) => policy,
                    Err(error) => {
                        return error_response(400, format!("policy 结构不合法：{error}"));
                    }
                }
            } else {
                state
                    .store
                    .current_rules()
                    .ok()
                    .flatten()
                    .map(|doc| doc.policy)
                    .unwrap_or_default()
            };
            match state.store.publish_bundle(rules, policy, note, actor, true) {
                Ok(doc) => created(json!({
                    "revision": doc.revision,
                    "rule_count": doc.rule_count,
                })),
                Err(error) => error_response(400, format!("{error:#}")),
            }
        }

        ("POST", "/api/whitelist") => {
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let kind = body.get("kind").and_then(Value::as_str).unwrap_or("");
            let entry = body
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if entry.is_empty() {
                return error_response(400, "白名单内容不能为空");
            }
            let current = match state.store.current_rules() {
                Ok(Some(doc)) => doc,
                Ok(None) => crate::server::rules::default_rules_document(),
                Err(error) => return fail(error),
            };
            let mut policy = current.policy;
            match kind {
                "glob" => {
                    if !policy.allow_globs.iter().any(|item| item == entry) {
                        policy.allow_globs.push(entry.to_string());
                    }
                }
                "value" => {
                    if !policy.allow_values.iter().any(|item| item == entry) {
                        policy.allow_values.push(entry.to_string());
                    }
                }
                _ => return error_response(400, "kind 必须为 glob 或 value"),
            }
            match state.store.publish_bundle(
                current.rules,
                policy,
                &format!("添加白名单：{entry}"),
                actor,
                true,
            ) {
                Ok(doc) => ok(json!({
                    "revision": doc.revision,
                    "policy": doc.policy,
                })),
                Err(error) => error_response(400, format!("{error:#}")),
            }
        }

        ("POST", "/api/rules/rollback") => {
            let body = match request.json() {
                Ok(body) => body,
                Err(error) => return error_response(400, error),
            };
            let Some(revision) = body.get("revision").and_then(Value::as_i64) else {
                return error_response(400, "缺少 revision");
            };
            match state.store.rollback_rules(revision, actor) {
                Ok(doc) => ok(json!({ "revision": doc.revision, "rule_count": doc.rule_count })),
                Err(error) => error_response(400, format!("{error:#}")),
            }
        }

        ("GET", "/api/rules/sync") => match state.store.rule_sync_status() {
            Ok(value) => ok(value),
            Err(error) => fail(error),
        },

        ("GET", "/api/audit") => match state.store.audit_log(200) {
            Ok(items) => ok(json!({ "items": items })),
            Err(error) => fail(error),
        },

        ("GET", "/api/config") => ok(json!({
            "ingest": {
                "enabled": state.config.ingest.enabled,
                "protocol": state.config.ingest.protocol,
                "bind": state.config.ingest.bind,
                "allow_cidrs": state.config.ingest.allow_cidrs,
            },
            "retention_days": state.config.retention.event_days,
            "tls": !state.config.tls.cert.as_os_str().is_empty(),
            "discover": {
                "enabled": state.config.discover.enabled,
                "service": state.config.discover.service,
                "instance": if state.config.discover.instance.trim().is_empty() {
                    crate::mdns::default_instance_name()
                } else {
                    state.config.discover.instance.clone()
                },
            },
            "webhook": {
                "enabled": state.config.webhook.enabled,
                "format": state.config.webhook.format,
                "min_severity": state.config.webhook.min_severity.as_str(),
                "has_url": !state.config.webhook.url.trim().is_empty(),
            },
            "console_bind": state.config.server.bind,
            "version": env!("CARGO_PKG_VERSION"),
        })),

        ("POST", "/api/webhook/test") => match &state.webhook {
            Some(dispatcher) => match dispatcher.send_test() {
                Ok(()) => ok(json!({ "ok": true })),
                Err(error) => error_response(502, format!("Webhook 推送失败：{error:#}")),
            },
            None => error_response(
                400,
                "Webhook 未启用或 url 为空，请在 server.toml [webhook] 中配置",
            ),
        },

        ("POST", "/api/purge") => {
            let body = request.json().unwrap_or(Value::Null);
            let days = body
                .get("days")
                .and_then(Value::as_i64)
                .unwrap_or(state.config.retention.event_days as i64);
            if days <= 0 {
                return error_response(400, "days 必须大于 0");
            }
            let cutoff = crate::util::now_ts() - days.saturating_mul(86_400);
            match state
                .store
                .purge_old_data(cutoff, super::RETAIN_RULE_REVISIONS)
            {
                Ok(report) => {
                    let _ = state.store.record_audit(
                        actor,
                        "purge_events",
                        &format!(
                            "days={days} events={} audit={} agents={} rule_sets={}",
                            report.events, report.audit, report.agents, report.rule_sets
                        ),
                    );
                    ok(json!({
                        "ok": true,
                        "removed": report.total(),
                        "events": report.events,
                        "audit": report.audit,
                        "agents": report.agents,
                        "rule_sets": report.rule_sets,
                    }))
                }
                Err(error) => fail(error),
            }
        }

        _ => error_response(404, "接口不存在"),
    }
}

/// 从查询参数构造过滤条件。
fn filter_from_query(params: &std::collections::HashMap<String, String>) -> EventFilter {
    let get = |key: &str| {
        params
            .get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    EventFilter {
        user: get("user").unwrap_or_default(),
        hostname: get("hostname").unwrap_or_default(),
        category: get("category").unwrap_or_default(),
        severity: get("severity").unwrap_or_default(),
        rule_id: get("rule_id").unwrap_or_default(),
        q: get("q").unwrap_or_default(),
        since: params
            .get("since")
            .and_then(|value| value.parse::<i64>().ok()),
        until: params
            .get("until")
            .and_then(|value| value.parse::<i64>().ok()),
        limit: params
            .get("limit")
            .and_then(|value| value.parse::<usize>().ok()),
        offset: params
            .get("offset")
            .and_then(|value| value.parse::<usize>().ok()),
    }
}

/// 登录失败限流表的上限，按来源 IP 计。
///
/// 5 分钟窗口内最多保留这么多来源；不设上限时，攻击者伪造大量来源
/// （或 IPv6 地址轮换）就能让这张内存表无限增长。
const MAX_THROTTLE_ENTRIES: usize = 4096;

/// 导出告警报表（CSV 或 HTML）。
pub fn export_events(
    request: &Request,
    state: &AppState,
) -> (u16, &'static str, Vec<u8>, Option<String>) {
    let params = request.query_params();
    let format = params
        .get("format")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "csv".to_string());
    let mut filter = filter_from_query(&params);
    filter.limit = Some(10_000);
    filter.offset = Some(0);
    let (events, total) = match state.store.events(&filter) {
        Ok(res) => res,
        Err(error) => {
            let (status, ctype, body) = fail(error);
            return (status, ctype, body, None);
        }
    };
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    match format.as_str() {
        "html" => {
            let body = crate::server::report::render_html(&events, total);
            let disp = format!("attachment; filename=\"sentinel-report-{ts}.html\"");
            (200, "text/html; charset=utf-8", body, Some(disp))
        }
        _ => {
            let body = crate::server::report::render_csv(&events);
            let disp = format!("attachment; filename=\"sentinel-report-{ts}.csv\"");
            (200, "text/csv; charset=utf-8", body, Some(disp))
        }
    }
}

/// 登录失败限流状态（简单的内存计数，够防暴力破解）。
pub struct LoginThrottle {
    entries: std::sync::Mutex<std::collections::HashMap<String, (u32, Instant)>>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 记录一次失败；同一来源 1 分钟内超过 5 次就锁 5 分钟。
    ///
    /// 表大小有硬上限：攻击者用大量不同来源刷登录时，不能让它无界增长。
    pub fn record_failure(&self, remote: &str) {
        if let Ok(mut map) = self.entries.lock() {
            let now = Instant::now();
            map.retain(|_, (_, at)| now.duration_since(*at) < std::time::Duration::from_secs(300));
            if map.len() >= MAX_THROTTLE_ENTRIES {
                // 已经满了：优先淘汰最早的记录，保证新来源仍能被限流。
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(key, _)| key.clone())
                {
                    map.remove(&oldest);
                }
            }
            let entry = map.entry(remote.to_string()).or_insert((0, now));
            entry.0 += 1;
            entry.1 = now;
        }
    }

    pub fn is_locked(&self, remote: &str) -> bool {
        let Ok(mut map) = self.entries.lock() else {
            return false;
        };
        let now = Instant::now();
        map.retain(|_, (_, at)| now.duration_since(*at) < std::time::Duration::from_secs(300));
        match map.get(remote) {
            Some((count, _)) => *count >= 5,
            None => false,
        }
    }

    pub fn clear(&self, remote: &str) {
        if let Ok(mut map) = self.entries.lock() {
            map.remove(remote);
        }
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_filter_from_query() {
        let mut params = std::collections::HashMap::new();
        params.insert("user".to_string(), "alice".to_string());
        params.insert("severity".to_string(), "high,critical".to_string());
        params.insert("limit".to_string(), "20".to_string());
        params.insert("empty".to_string(), "  ".to_string());
        let filter = filter_from_query(&params);
        assert_eq!(filter.user, "alice");
        assert_eq!(filter.severity, "high,critical");
        assert_eq!(filter.limit, Some(20));
        assert_eq!(filter.category, "");
    }

    #[test]
    fn throttle_locks_after_repeated_failures() {
        let throttle = LoginThrottle::new();
        assert!(!throttle.is_locked("1.2.3.4"));
        for _ in 0..5 {
            throttle.record_failure("1.2.3.4");
        }
        assert!(throttle.is_locked("1.2.3.4"));
        assert!(!throttle.is_locked("5.6.7.8"));
        throttle.clear("1.2.3.4");
        assert!(!throttle.is_locked("1.2.3.4"));
    }

    /// 大量不同来源刷登录时，限流表必须有界，不能被撑爆内存。
    #[test]
    fn throttle_table_is_bounded() {
        let throttle = LoginThrottle::new();
        for index in 0..(MAX_THROTTLE_ENTRIES + 500) {
            throttle.record_failure(&format!("10.0.{}.{}", index / 256, index % 256));
        }
        let entries = throttle.entries.lock().unwrap().len();
        assert!(
            entries <= MAX_THROTTLE_ENTRIES,
            "限流表应保持有界，实际 {entries}"
        );
        // 最新的来源仍然会被正常记录/限流。
        for _ in 0..5 {
            throttle.record_failure("192.168.1.9");
        }
        assert!(throttle.is_locked("192.168.1.9"));
    }

    /// 限流必须真的作用在登录入口上：锁定后即使口令正确也应被拒绝。
    #[test]
    fn login_is_blocked_after_too_many_failures() {
        use crate::server::config::ServerConfig;
        use crate::server::http::Request;

        let dir = tempfile::tempdir().unwrap();
        let config = ServerConfig {
            storage: crate::server::config::ServerStorageConfig {
                database: dir.path().join("srv.db"),
            },
            ..ServerConfig::default()
        };
        let hash = crate::server::auth::hash_password("correct-password");
        let auth = AuthState::new(&config, hash, "token".to_string());

        let bad = Request {
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body: br#"{"password":"wrong"}"#.to_vec(),
            remote: "203.0.113.7".to_string(),
        };
        for _ in 0..5 {
            let (response, cookie) = login(&auth, &bad);
            assert_eq!(response.0, 401, "前 5 次应是口令错误");
            assert!(cookie.is_none());
        }

        let good = Request {
            body: br#"{"password":"correct-password"}"#.to_vec(),
            ..bad
        };
        let (response, cookie) = login(&auth, &good);
        assert_eq!(response.0, 429, "锁定后即使口令正确也应被限流");
        assert!(cookie.is_none());
    }
}
