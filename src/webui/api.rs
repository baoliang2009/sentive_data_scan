//! JSON API behind the local console.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::autostart;
use crate::config::{expand_path, secure_file, Config};
use crate::detect::Detector;
use crate::model::{category_label, Severity, StoredFinding};
use crate::notify::Notifier;
use crate::report;
use crate::rules::RuleSet;
use crate::scan::Scanner;
use crate::store::Store;
use crate::util::{format_ts, now_ts};
use crate::webui::server::{Request, Response};
use crate::webui::tomlpatch::{set_key, toml_literal};
use crate::webui::{AppContext, ScanResult};

pub const JSON: &str = "application/json; charset=utf-8";

pub fn ok(value: Value) -> Response {
    (200, JSON, serde_json::to_vec(&value).unwrap_or_default())
}

pub fn error_response(status: u16, message: impl Into<String>) -> Response {
    let body = json!({ "error": message.into() });
    (status, JSON, serde_json::to_vec(&body).unwrap_or_default())
}

fn fail(error: anyhow::Error) -> Response {
    tracing::warn!(error = %format!("{error:#}"), "控制台接口调用失败");
    error_response(500, format!("{error:#}"))
}

pub fn handle(request: &Request, ctx: &AppContext) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/overview") => overview(ctx),
        ("GET", "/api/findings") => findings(ctx, request),
        ("POST", "/api/findings/ack") => acknowledge(ctx, request),
        ("GET", "/api/rules") => rules(ctx),
        ("POST", "/api/rules/toggle") => toggle_rule(ctx, request),
        ("POST", "/api/rules/test") => test_rules(ctx, request),
        ("GET", "/api/scan/status") => scan_status(ctx),
        ("POST", "/api/scan/start") => start_scan(ctx, request),
        ("GET", "/api/fs/list") => list_directory(ctx, request),
        ("POST", "/api/report") => export_report(ctx, request),
        ("POST", "/api/autostart") => autostart_action(ctx, request),
        ("POST", "/api/notify/test") => notify_test(ctx),
        ("GET", "/api/settings") => get_settings(ctx),
        ("POST", "/api/settings") => save_settings(ctx, request),
        ("GET", "/api/config") => get_config(ctx),
        ("POST", "/api/config") => save_config(ctx, request),
        ("POST", "/api/reveal") => reveal(ctx, request),
        ("POST", "/api/open") => open_target(ctx, request),
        _ => error_response(404, "接口不存在"),
    }
}

// ---------------------------------------------------------------- overview --

fn overview(ctx: &AppContext) -> Response {
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let store = match ctx.store() {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    let stats = match store.stats() {
        Ok(stats) => stats,
        Err(error) => return fail(error),
    };
    let runs = store.recent_runs(6).unwrap_or_default();
    let categories = store.category_counts().unwrap_or_default();
    // Prefer the last scan run: files.last_scanned only moves when a file is
    // actually re-analysed, so an all-unchanged incremental scan would leave
    // the dashboard showing a stale timestamp.
    let last_scan = runs.first().map(|run| run.finished_at).or(stats.last_scan);

    let by_severity = severity_map(&stats.by_severity);
    let mut category_items: Vec<Value> = categories
        .iter()
        .map(|(category, count)| {
            json!({
                "category": category,
                "label": category_label(category),
                "count": count,
            })
        })
        .collect();
    category_items.sort_by_key(|item| std::cmp::Reverse(item["count"].as_u64().unwrap_or(0)));

    let runs_json: Vec<Value> = runs
        .iter()
        .map(|run| {
            json!({
                "id": run.id,
                "started_at": run.started_at,
                "started_at_text": format_ts(run.started_at),
                "finished_at": run.finished_at,
                "duration_seconds": (run.finished_at - run.started_at).max(0),
                "files_scanned": run.files_scanned,
                "findings": run.findings,
                "new_findings": run.new_findings,
            })
        })
        .collect();

    let autostart_text = ctx.autostart_status();

    ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": crate::webui::platform_label(),
        "os": std::env::consts::OS,
        "config_path": config_path_text(&ctx.config_path),
        "data_dir": config.data_dir().to_string_lossy(),
        "database_path": config.database_path().to_string_lossy(),
        "reports_dir": config.reports_dir().to_string_lossy(),
        "logs_dir": config.logs_dir().to_string_lossy(),
        "roots": config.effective_roots().iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "roots_auto": config.scan.roots.is_empty(),
        "stats": {
            "files": stats.files,
            "findings": stats.findings,
            "unacknowledged": stats.unacknowledged,
            "by_severity": by_severity,
            "last_scan": last_scan,
            "last_scan_text": last_scan.map(format_ts),
        },
        "categories": category_items,
        "runs": runs_json,
        "autostart": {
            "installed": autostart_text.contains("已安装"),
            "detail": autostart_text,
        },
        "watch": {
            "enabled": config.watch.enabled,
            "interval_hours": config.scan.full_scan_interval_hours,
            "debounce_ms": config.watch.debounce_ms,
        },
        "scan": status_json(ctx),
        "privacy": {
            "store_raw_match": config.storage.store_raw_match,
            "retention_days": config.storage.retention_days,
        },
    }))
}

fn config_path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn severity_map(map: &std::collections::BTreeMap<Severity, u64>) -> Map<String, Value> {
    let mut out = Map::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out.insert(
            severity.as_str().to_string(),
            json!(map.get(&severity).copied().unwrap_or(0)),
        );
    }
    out
}

// ---------------------------------------------------------------- findings --

fn finding_json(finding: &StoredFinding) -> Value {
    json!({
        "id": finding.id,
        "path": finding.path,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "category": finding.category,
        "category_label": category_label(&finding.category),
        "severity": finding.severity.as_str(),
        "severity_label": finding.severity.label_zh(),
        "masked": finding.masked,
        "line": finding.line,
        "snippet": finding.snippet,
        "detected_at": finding.detected_at,
        "detected_at_text": format_ts(finding.detected_at),
        "acknowledged": finding.acknowledged,
    })
}

fn findings(ctx: &AppContext, request: &Request) -> Response {
    let params = request.query_params();
    let severity = params
        .get("severity")
        .cloned()
        .unwrap_or_else(|| "all".into());
    let category = params
        .get("category")
        .cloned()
        .unwrap_or_else(|| "all".into());
    let ack = params.get("ack").cloned().unwrap_or_else(|| "open".into());
    let query = params
        .get("q")
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_default();
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let store = match ctx.store() {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    let include_acknowledged = ack != "open";
    let all = match store.recent_findings(None, 5000, include_acknowledged) {
        Ok(all) => all,
        Err(error) => return fail(error),
    };

    let filtered: Vec<&StoredFinding> = all
        .iter()
        .filter(|item| match ack.as_str() {
            "acked" => item.acknowledged,
            "open" => !item.acknowledged,
            _ => true,
        })
        .filter(|item| category == "all" || category.is_empty() || item.category == category)
        .filter(|item| {
            if query.is_empty() {
                return true;
            }
            let label = category_label(&item.category).to_lowercase();
            item.path.to_lowercase().contains(&query)
                || item.rule_name.to_lowercase().contains(&query)
                || item.masked.to_lowercase().contains(&query)
                || label.contains(&query)
        })
        .collect();

    let mut counts = Map::new();
    for level in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = filtered
            .iter()
            .filter(|item| item.severity == level)
            .count();
        counts.insert(level.as_str().to_string(), json!(count));
    }

    let selected: Vec<&StoredFinding> = if severity == "all" || severity.is_empty() {
        filtered.clone()
    } else {
        match severity.parse::<Severity>() {
            Ok(level) => filtered
                .iter()
                .copied()
                .filter(|item| item.severity == level)
                .collect(),
            Err(_) => filtered.clone(),
        }
    };

    let total = selected.len();
    let items: Vec<Value> = selected
        .iter()
        .skip(offset)
        .take(limit)
        .map(|item| finding_json(item))
        .collect();

    ok(json!({
        "items": items,
        "total": total,
        "counts": counts,
        "offset": offset,
        "limit": limit,
        "has_more": offset + items.len() < total,
    }))
}

fn acknowledge(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let store = match ctx.store() {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    let all = body.get("all").and_then(Value::as_bool).unwrap_or(false);
    let ids: Vec<i64> = body
        .get("ids")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default();

    if !all && ids.is_empty() {
        return error_response(400, "请选择要确认的记录");
    }
    let result = if all {
        store.ack_all()
    } else {
        store.ack_ids(&ids)
    };
    match result {
        Ok(updated) => ok(json!({ "updated": updated })),
        Err(error) => fail(error),
    }
}

// ------------------------------------------------------------------- rules --

fn rules(ctx: &AppContext) -> Response {
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let ruleset = match RuleSet::build(&config.rules) {
        Ok(ruleset) => ruleset,
        Err(error) => return fail(error),
    };
    let all = RuleSet::build(&Default::default());
    let disabled: std::collections::HashSet<String> =
        config.rules.disabled.iter().cloned().collect();
    let builtin_ids: std::collections::HashSet<String> = all
        .map(|set| set.rules().iter().map(|rule| rule.id.clone()).collect())
        .unwrap_or_default();

    let mut items: Vec<Value> = Vec::new();
    // Disabled rules are not part of the compiled set, so rebuild the full list.
    if let Ok(full) = RuleSet::build(&crate::config::RulesConfig {
        disabled: Vec::new(),
        ..config.rules.clone()
    }) {
        for rule in full.rules() {
            items.push(json!({
                "id": rule.id,
                "name": rule.name,
                "category": rule.category,
                "category_label": category_label(&rule.category),
                "severity": rule.severity.as_str(),
                "severity_label": rule.severity.label_zh(),
                "description": rule.description,
                "validators": rule.validators.iter().map(|v| v.describe()).collect::<Vec<_>>(),
                "builtin": builtin_ids.contains(&rule.id),
                "enabled": !disabled.contains(&rule.id),
            }));
        }
    }

    ok(json!({
        "items": items,
        "total": items.len(),
        "active": ruleset.rules().len(),
        "min_severity": config.rules.min_severity.as_str(),
        "disabled": disabled.into_iter().collect::<Vec<_>>(),
        "custom_count": config.rules.custom.len(),
        "config_path": config_path_text(&ctx.config_path),
    }))
}

fn toggle_rule(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let Some(id) = body.get("id").and_then(Value::as_str) else {
        return error_response(400, "缺少规则 id");
    };
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);

    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let mut disabled = config.rules.disabled.clone();
    if enabled {
        disabled.retain(|item| item != id);
    } else if !disabled.iter().any(|item| item == id) {
        disabled.push(id.to_string());
    }
    let literal = toml_literal(&json!(disabled));
    match patch_config(ctx, &[("rules", "disabled", literal.as_str())]) {
        Ok(config) => ok(json!({
            "ok": true,
            "enabled": enabled,
            "disabled": config.rules.disabled,
        })),
        Err(response) => response,
    }
}

fn test_rules(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let Some(text) = body.get("text").and_then(Value::as_str) else {
        return error_response(400, "缺少待检测文本");
    };
    if text.trim().is_empty() {
        return ok(json!({ "items": [], "total": 0 }));
    }
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let ruleset = match RuleSet::build(&config.rules) {
        Ok(ruleset) => ruleset,
        Err(error) => return fail(error),
    };
    let detector = Detector::new(ruleset, &config);
    let hits = detector.detect(text, Path::new("<控制台测试>"));
    let items: Vec<Value> = hits
        .iter()
        .map(|hit| {
            json!({
                "rule_id": hit.rule_id,
                "rule_name": hit.rule_name,
                "category": hit.category,
                "category_label": category_label(&hit.category),
                "severity": hit.severity.as_str(),
                "severity_label": hit.severity.label_zh(),
                "masked": hit.masked,
                "line": hit.line,
                "column": hit.column,
                "snippet": hit.snippet,
            })
        })
        .collect();
    ok(json!({ "items": items, "total": items.len() }))
}

// -------------------------------------------------------------------- scan --

fn status_json(ctx: &AppContext) -> Value {
    let session = &ctx.scan;
    let running = session.running.load(Ordering::SeqCst);
    let started_at = session.started_at.load(Ordering::SeqCst);
    let elapsed_ms = if running && started_at > 0 {
        ((now_ts() - started_at).max(0) * 1000) as u64
    } else {
        0
    };
    let roots = session
        .roots
        .lock()
        .map(|roots| roots.clone())
        .unwrap_or_default();
    let error = session.error.lock().ok().and_then(|slot| slot.clone());
    let last = session
        .last
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().cloned())
        .map(|result| scan_result_json(&result));

    json!({
        "running": running,
        "started_at": started_at,
        "elapsed_ms": elapsed_ms,
        "files_seen": session.progress.files_seen(),
        "files_scanned": session.progress.files_scanned(),
        "findings": session.progress.findings(),
        "roots": roots,
        "force": session.force.load(Ordering::SeqCst),
        "error": error,
        "last": last,
    })
}

fn scan_result_json(result: &ScanResult) -> Value {
    json!({
        "started_at": result.started_at,
        "started_at_text": format_ts(result.started_at),
        "finished_at": result.finished_at,
        "duration_ms": result.duration_ms,
        "roots": result.roots,
        "summary": result.summary,
    })
}

fn scan_status(ctx: &AppContext) -> Response {
    ok(status_json(ctx))
}

fn start_scan(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    if ctx.scan.running.swap(true, Ordering::SeqCst) {
        return error_response(409, "已有扫描任务正在执行，请稍候再试");
    }

    let requested: Vec<String> = body
        .get("paths")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
    let notify = body.get("notify").and_then(Value::as_bool).unwrap_or(true);

    ctx.scan.progress.reset();
    ctx.scan.started_at.store(now_ts(), Ordering::SeqCst);
    ctx.scan.force.store(force, Ordering::SeqCst);
    if let Ok(mut roots) = ctx.scan.roots.lock() {
        *roots = requested.clone();
    }
    if let Ok(mut error) = ctx.scan.error.lock() {
        *error = None;
    }

    let session = Arc::clone(&ctx.scan);
    let config_path = ctx.config_path.clone();
    std::thread::spawn(move || {
        let started = Instant::now();
        let started_at = now_ts();
        let outcome = run_scan_batch(
            &config_path,
            &requested,
            force,
            notify,
            Arc::clone(&session),
        );
        let finished_at = now_ts();
        match outcome {
            Ok((roots, summary)) => {
                let result = ScanResult {
                    started_at,
                    finished_at,
                    duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    roots: roots.clone(),
                    summary,
                };
                if let Ok(mut slot) = session.last.lock() {
                    *slot = Some(result);
                }
                if let Ok(mut slot) = session.roots.lock() {
                    *slot = roots;
                }
            }
            Err(error) => {
                if let Ok(mut slot) = session.error.lock() {
                    *slot = Some(format!("{error:#}"));
                }
            }
        }
        session.progress.mark_finished();
        session.running.store(false, Ordering::SeqCst);
    });

    ok(json!({ "ok": true }))
}

fn run_scan_batch(
    config_path: &Path,
    requested: &[String],
    force: bool,
    notify: bool,
    session: Arc<crate::webui::ScanSession>,
) -> Result<(Vec<String>, Value)> {
    let (config, _path) = Config::load(Some(config_path))?;
    let store = Arc::new(Store::open(&config.database_path())?);
    if let Err(error) = store.prune(config.storage.retention_days) {
        tracing::warn!(error = %error, "清理过期发现记录失败");
    }
    if !config.storage.store_raw_match {
        let _ = store.clear_raw_matches();
    }
    let rules = RuleSet::build(&config.rules)?;
    let mut scanner = Scanner::new(Arc::new(config.clone()), store, rules)?;
    scanner.set_progress(Arc::clone(&session.progress));

    let roots: Vec<PathBuf> = if requested.is_empty() {
        config.effective_roots()
    } else {
        requested
            .iter()
            .map(|item| expand_path(Path::new(item)))
            .collect()
    };
    if roots.is_empty() {
        anyhow::bail!("没有可扫描的目录，请先在设置中添加扫描目录");
    }

    let summary = scanner.scan_roots(&roots, force);
    if notify {
        Notifier::new(&config.notify).notify_scan(&summary);
    }
    let value = serde_json::to_value(&summary).context("序列化扫描结果失败")?;
    let labels: Vec<String> = roots
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    Ok((labels, value))
}

// ---------------------------------------------------------------- filesystem --

fn list_directory(_ctx: &AppContext, request: &Request) -> Response {
    let params = request.query_params();
    let raw = params.get("path").cloned().unwrap_or_default();
    let target = if raw.trim().is_empty() {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
    } else {
        expand_path(Path::new(raw.trim()))
    };
    if !target.is_dir() {
        return error_response(400, format!("目录不存在：{}", target.display()));
    }

    let mut directories: Vec<(String, String, bool)> = Vec::new();
    let entries = match std::fs::read_dir(&target) {
        Ok(entries) => entries,
        Err(error) => {
            return error_response(400, format!("无法读取目录 {}：{error}", target.display()))
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
            || (path.is_symlink() && path.is_dir());
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let hidden = name.starts_with('.');
        directories.push((name, path.to_string_lossy().into_owned(), hidden));
        if directories.len() >= 800 {
            break;
        }
    }
    directories.sort_by(|a, b| {
        a.2.cmp(&b.2)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });

    let shortcuts: Vec<Value> = [
        ("主目录", dirs::home_dir()),
        ("桌面", dirs::desktop_dir()),
        ("文档", dirs::document_dir()),
        ("下载", dirs::download_dir()),
    ]
    .into_iter()
    .filter_map(|(label, path)| path.map(|path| (label, path)))
    .filter(|(_, path)| path.is_dir())
    .map(|(label, path)| json!({ "label": label, "path": path.to_string_lossy() }))
    .collect();

    ok(json!({
        "path": target.to_string_lossy(),
        "parent": target.parent().map(|path| path.to_string_lossy().into_owned()),
        "dirs": directories.into_iter().map(|(name, path, hidden)| json!({
            "name": name,
            "path": path,
            "hidden": hidden,
        })).collect::<Vec<_>>(),
        "shortcuts": shortcuts,
    }))
}

// ----------------------------------------------------------------- reports --

fn export_report(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let format = body
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("html")
        .to_string();
    let days = body.get("days").and_then(Value::as_u64).unwrap_or(30);
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let store = match ctx.store() {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    match report::export(&store, &config, &format, None, days) {
        Ok(path) => ok(json!({ "path": path.to_string_lossy() })),
        Err(error) => fail(error),
    }
}

// ------------------------------------------------------------------ system --

fn autostart_action(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("status");
    let result = match action {
        "install" => autostart::install(&ctx.config_path),
        "uninstall" => autostart::uninstall(),
        _ => Ok(()),
    };
    if let Err(error) = result {
        return fail(error);
    }
    let text = ctx.autostart_status_fresh();
    ok(json!({
        "ok": true,
        "status": text,
        "installed": text.contains("已安装"),
    }))
}

fn notify_test(ctx: &AppContext) -> Response {
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    match Notifier::new(&config.notify).test() {
        Ok(()) => ok(json!({ "ok": true })),
        Err(error) => fail(error),
    }
}

fn reveal(_ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let Some(path) = body.get("path").and_then(Value::as_str) else {
        return error_response(400, "缺少路径");
    };
    match crate::webui::reveal(path) {
        Ok(()) => ok(json!({ "ok": true })),
        Err(error) => fail(error),
    }
}

fn open_target(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let target = body.get("target").and_then(Value::as_str).unwrap_or("data");
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    let path = match target {
        "config" => ctx.config_path.clone(),
        "reports" => config.reports_dir(),
        "logs" => config.logs_dir(),
        "database" => config.database_path(),
        _ => config.data_dir(),
    };
    let parent = if path.is_dir() {
        path.clone()
    } else {
        path.parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or(path)
    };
    let _ = crate::config::ensure_private_dir(&parent);
    match crate::webui::open_path(&parent) {
        Ok(()) => ok(json!({ "ok": true })),
        Err(error) => fail(error),
    }
}

// ---------------------------------------------------------------- settings --

fn get_settings(ctx: &AppContext) -> Response {
    let config = match ctx.load_config() {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    ok(json!({
        "scan": {
            "roots": config.scan.roots.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
            "roots_auto": config.scan.roots.is_empty(),
            "effective_roots": config.effective_roots().iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
            "max_file_size_mb": config.scan.max_file_size_mb,
            "threads": config.scan.threads,
            "office_documents": config.scan.office_documents,
            "skip_hidden": config.scan.skip_hidden,
            "follow_symlinks": config.scan.follow_symlinks,
            "use_default_excludes": config.scan.use_default_excludes,
            "full_scan_interval_hours": config.scan.full_scan_interval_hours,
            "scan_on_startup": config.scan.scan_on_startup,
            "context_chars": config.scan.context_chars,
            "exclude_globs": config.scan.exclude_globs,
            "allow_globs": config.scan.allow_globs,
        },
        "watch": {
            "enabled": config.watch.enabled,
            "debounce_ms": config.watch.debounce_ms,
        },
        "notify": {
            "enabled": config.notify.enabled,
            "min_severity": config.notify.min_severity.as_str(),
            "mode": config.notify.mode,
            "macos_mode": config.notify.macos_mode,
        },
        "storage": {
            "retention_days": config.storage.retention_days,
            "store_raw_match": config.storage.store_raw_match,
        },
        "rules": {
            "min_severity": config.rules.min_severity.as_str(),
            "disabled": config.rules.disabled,
            "custom_count": config.rules.custom.len(),
        },
        "paths": {
            "config": config_path_text(&ctx.config_path),
            "database": config.database_path().to_string_lossy(),
            "reports": config.reports_dir().to_string_lossy(),
            "logs": config.logs_dir().to_string_lossy(),
            "data": config.data_dir().to_string_lossy(),
        },
        "autostart": {
            "installed": ctx.autostart_status().contains("已安装"),
            "detail": ctx.autostart_status(),
        },
    }))
}

fn save_settings(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };

    let mut patches: Vec<(String, String, String)> = Vec::new();
    let mut push = |section: &str, key: &str, value: &Value| {
        patches.push((section.to_string(), key.to_string(), toml_literal(value)));
    };

    if let Some(scan) = body.get("scan") {
        for (key, value) in scan_object(scan) {
            push("scan", &key, &value);
        }
    }
    if let Some(watch) = body.get("watch") {
        for (key, value) in watch_object(watch) {
            push("watch", &key, &value);
        }
    }
    if let Some(notify) = body.get("notify") {
        for (key, value) in notify_object(notify) {
            push("notify", &key, &value);
        }
    }
    if let Some(storage) = body.get("storage") {
        for (key, value) in storage_object(storage) {
            push("storage", &key, &value);
        }
    }
    if let Some(rules) = body.get("rules") {
        for (key, value) in rules_object(rules) {
            push("rules", &key, &value);
        }
    }

    if patches.is_empty() {
        return error_response(400, "没有需要保存的设置");
    }

    let owned: Vec<(&str, &str, &str)> = patches
        .iter()
        .map(|(section, key, literal)| (section.as_str(), key.as_str(), literal.as_str()))
        .collect();
    match patch_config(ctx, &owned) {
        Ok(_) => ok(json!({ "ok": true })),
        Err(response) => response,
    }
}

fn scan_object(value: &Value) -> Vec<(String, Value)> {
    let map = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in [
        "roots",
        "max_file_size_mb",
        "threads",
        "office_documents",
        "skip_hidden",
        "follow_symlinks",
        "use_default_excludes",
        "full_scan_interval_hours",
        "scan_on_startup",
        "context_chars",
    ] {
        if let Some(value) = map.get(key) {
            out.push((key.to_string(), value.clone()));
        }
    }
    out
}

fn watch_object(value: &Value) -> Vec<(String, Value)> {
    let map = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in ["enabled", "debounce_ms"] {
        if let Some(value) = map.get(key) {
            out.push((key.to_string(), value.clone()));
        }
    }
    out
}

fn notify_object(value: &Value) -> Vec<(String, Value)> {
    let map = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in ["enabled", "min_severity", "mode", "macos_mode"] {
        if let Some(value) = map.get(key) {
            out.push((key.to_string(), value.clone()));
        }
    }
    out
}

fn storage_object(value: &Value) -> Vec<(String, Value)> {
    let map = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in ["retention_days", "store_raw_match"] {
        if let Some(value) = map.get(key) {
            out.push((key.to_string(), value.clone()));
        }
    }
    out
}

fn rules_object(value: &Value) -> Vec<(String, Value)> {
    let map = match value.as_object() {
        Some(map) => map,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in ["min_severity", "disabled"] {
        if let Some(value) = map.get(key) {
            out.push((key.to_string(), value.clone()));
        }
    }
    out
}

/// Apply key patches, validate the whole document, then write it back.
fn patch_config(ctx: &AppContext, patches: &[(&str, &str, &str)]) -> Result<Config, Response> {
    let original = std::fs::read_to_string(&ctx.config_path).unwrap_or_default();
    let mut text = original.clone();
    for (section, key, literal) in patches {
        text = set_key(&text, section, key, literal);
    }
    let config: Config = match toml::from_str(&text) {
        Ok(config) => config,
        Err(error) => {
            return Err(error_response(400, format!("配置格式错误：{error}")));
        }
    };
    if let Err(error) = config.validate() {
        return Err(error_response(400, format!("{error:#}")));
    }
    if let Some(parent) = ctx.config_path.parent() {
        if let Err(error) = crate::config::ensure_private_dir(parent) {
            return Err(fail(error));
        }
    }
    let backup = ctx.config_path.with_extension("toml.bak");
    let _ = std::fs::write(&backup, &original);
    if let Err(error) = std::fs::write(&ctx.config_path, &text) {
        return Err(fail(anyhow::anyhow!(error).context("无法写入配置文件")));
    }
    let _ = secure_file(&ctx.config_path);
    Ok(config)
}

// ------------------------------------------------------------------ config --

fn get_config(ctx: &AppContext) -> Response {
    let text = std::fs::read_to_string(&ctx.config_path).unwrap_or_default();
    ok(json!({
        "path": config_path_text(&ctx.config_path),
        "toml": text,
        "version": env!("CARGO_PKG_VERSION"),
        "platform": crate::webui::platform_label(),
    }))
}

fn save_config(ctx: &AppContext, request: &Request) -> Response {
    let body = match request.json() {
        Ok(body) => body,
        Err(error) => return error_response(400, error),
    };
    let Some(text) = body.get("toml").and_then(Value::as_str) else {
        return error_response(400, "缺少配置内容");
    };
    let config: Config = match toml::from_str(text) {
        Ok(config) => config,
        Err(error) => return error_response(400, format!("配置格式错误：{error}")),
    };
    if let Err(error) = config.validate() {
        return error_response(400, format!("{error:#}"));
    }
    let original = std::fs::read_to_string(&ctx.config_path).unwrap_or_default();
    let _ = std::fs::write(ctx.config_path.with_extension("toml.bak"), &original);
    if let Err(error) = std::fs::write(&ctx.config_path, text) {
        return fail(anyhow::anyhow!(error).context("无法写入配置文件"));
    }
    let _ = secure_file(&ctx.config_path);
    ok(json!({ "ok": true }))
}
