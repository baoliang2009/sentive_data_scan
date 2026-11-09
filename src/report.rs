use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Local;

use crate::config::{ensure_private_dir, secure_file, Config};
use crate::model::{category_label, StoredFinding};
use crate::store::Store;
use crate::util::{format_ts, html_escape, now_ts};

pub fn export(
    store: &Store,
    config: &Config,
    format: &str,
    out: Option<&Path>,
    days: u64,
) -> Result<PathBuf> {
    let format = format.to_ascii_lowercase();
    if !matches!(format.as_str(), "html" | "json") {
        bail!("报告格式只支持 html 或 json");
    }
    let since = if days == 0 {
        0
    } else {
        now_ts() - (days as i64) * 86_400
    };
    let findings = store.findings_since(since)?;
    let stats = store.stats()?;

    let path = match out {
        Some(path) => path.to_path_buf(),
        None => {
            let dir = config.reports_dir();
            ensure_private_dir(&dir)?;
            dir.join(format!(
                "sentinel-report-{}.{}",
                Local::now().format("%Y%m%d-%H%M%S"),
                format
            ))
        }
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir(parent)?;
        }
    }

    match format.as_str() {
        "json" => write_json(&path, days, &stats, &findings)?,
        _ => write_html(&path, days, &stats, &findings)?,
    }
    let _ = secure_file(&path);
    Ok(path)
}

fn write_json(
    path: &Path,
    days: u64,
    stats: &crate::store::StoreStats,
    findings: &[StoredFinding],
) -> Result<()> {
    let generated_at = now_ts();
    let by_severity: std::collections::BTreeMap<String, u64> = stats
        .by_severity
        .iter()
        .map(|(severity, count)| (severity.as_str().to_string(), *count))
        .collect();
    let value = serde_json::json!({
        "product": "DataSentinel",
        "generated_at": generated_at,
        "generated_at_text": format_ts(generated_at),
        "days": days,
        "stats": {
            "files": stats.files,
            "findings": stats.findings,
            "unacknowledged": stats.unacknowledged,
            "by_severity": by_severity,
            "last_scan": stats.last_scan,
            "last_scan_text": stats.last_scan.map(format_ts),
        },
        "findings": findings,
    });
    let file = File::create(path).with_context(|| format!("无法创建报告 {}", path.display()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &value).context("写入 JSON 报告失败")?;
    Ok(())
}

fn write_html(
    path: &Path,
    days: u64,
    stats: &crate::store::StoreStats,
    findings: &[StoredFinding],
) -> Result<()> {
    let mut html = String::with_capacity(64 * 1024 + findings.len() * 512);
    let generated_at = format_ts(now_ts());
    let last_scan = stats
        .last_scan
        .map(format_ts)
        .unwrap_or_else(|| "尚无".to_string());

    html.push_str(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DataSentinel 敏感数据报告</title>
<style>
:root{--bg:#f6f7fb;--card:#fff;--text:#172033;--muted:#667085;--line:#e6e8ef;
--critical:#b42318;--high:#d92d20;--medium:#b54708;--low:#175cd3;--info:#475467}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1320px;margin:0 auto;padding:32px 24px 64px}
header{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;flex-wrap:wrap;margin-bottom:24px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}.sub{color:var(--muted)}
.badge{background:#fff;border:1px solid var(--line);border-radius:999px;padding:6px 12px;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.card .label{color:var(--muted);font-size:12px}.card .num{font-size:26px;font-weight:700;margin-top:4px}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 16px}
button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:7px 14px;cursor:pointer;color:var(--text)}
button:hover{border-color:#98a2b3}button.active{background:#172033;color:#fff;border-color:#172033}
.tablewrap{background:var(--card);border:1px solid var(--line);border-radius:16px;overflow:auto}
table{border-collapse:collapse;width:100%;min-width:980px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#fbfcfe;font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}tr:hover td{background:#fafbff}
.sev{display:inline-block;border-radius:999px;padding:2px 9px;font-size:12px;font-weight:600}
.sev-critical{background:#fee4e2;color:var(--critical)}.sev-high{background:#fee4e2;color:var(--high)}
.sev-medium{background:#fef0c7;color:var(--medium)}.sev-low{background:#d1e9ff;color:var(--low)}
.sev-info{background:#eaecf0;color:var(--info)}
.path{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.masked{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#344054}
.snippet{color:var(--muted);max-width:420px;word-break:break-word}
.ack{color:#027a48;font-size:12px}.unack{color:#b54708;font-size:12px}
.empty{padding:56px;text-align:center;color:var(--muted)}
footer{margin-top:18px;color:var(--muted);font-size:12px}
@media (max-width:720px){.wrap{padding:20px 14px}h1{font-size:21px}}
</style>
</head>
<body><div class="wrap">
"#,
    );
    let _ = writeln!(
        html,
        r#"<header>
  <div><h1>DataSentinel 敏感数据报告</h1>
  <div class="sub">本地扫描 · 默认仅保存脱敏结果 · 数据不出本机</div></div>
  <div class="badge">生成时间：{generated_at}</div>
</header>"#,
        generated_at = generated_at
    );
    let range_label = if days == 0 {
        "全部".to_string()
    } else {
        format!("{days} 天")
    };
    let _ = writeln!(
        html,
        r#"<section class="cards">
<div class="card"><div class="label">扫描文件台账</div><div class="num">{}</div></div>
<div class="card"><div class="label">发现总数</div><div class="num">{}</div></div>
<div class="card"><div class="label">未确认</div><div class="num">{}</div></div>
<div class="card"><div class="label">时间范围</div><div class="num">{}</div></div>
<div class="card"><div class="label">最近扫描</div><div class="num" style="font-size:15px;font-weight:600">{}</div></div>
</section>"#,
        stats.files,
        stats.findings,
        stats.unacknowledged,
        range_label,
        html_escape(&last_scan),
    );

    html.push_str(
        r#"<div class="bar">
<button class="active" data-sev="all" onclick="filterSev('all',this)">全部</button>
<button data-sev="critical" onclick="filterSev('critical',this)">严重</button>
<button data-sev="high" onclick="filterSev('high',this)">高危</button>
<button data-sev="medium" onclick="filterSev('medium',this)">中危</button>
<button data-sev="low" onclick="filterSev('low',this)">低危</button>
<button data-sev="info" onclick="filterSev('info',this)">提示</button>
<span style="flex:1"></span>
<button onclick="filterAck(this)">仅未确认</button>
</div>
<div class="tablewrap"><table><thead><tr>
<th>时间</th><th>级别</th><th>规则</th><th>文件</th><th>脱敏值</th><th>上下文</th><th>状态</th>
</tr></thead><tbody id="rows">
"#,
    );

    if findings.is_empty() {
        html.push_str(
            r#"<tr><td colspan="7" class="empty">当前时间范围内没有发现敏感数据。</td></tr>"#,
        );
    } else {
        for finding in findings {
            let severity = finding.severity;
            let severity_class = format!("sev sev-{}", severity.as_str());
            let location = format!("{}:{}", finding.path, finding.line);
            let ack = if finding.acknowledged {
                r#"<span class="ack">已确认</span>"#
            } else {
                r#"<span class="unack">未确认</span>"#
            };
            let _ = writeln!(
                html,
                "<tr data-sev=\"{sev}\" data-ack=\"{ack}\"><td>{time}</td>\
<td><span class=\"{cls}\">{label}</span></td>\
<td>{rule_name}<div class=\"sub\">{category}</div></td>\
<td class=\"path\">{path}</td>\
<td class=\"masked\">{masked}</td>\
<td class=\"snippet\">{snippet}</td>\
<td>{ack_html}</td></tr>",
                sev = severity.as_str(),
                ack = if finding.acknowledged { "1" } else { "0" },
                time = format_ts(finding.detected_at),
                cls = severity_class,
                label = severity.label_zh(),
                rule_name = html_escape(&finding.rule_name),
                category = html_escape(category_label(&finding.category)),
                path = html_escape(&location),
                masked = html_escape(&finding.masked),
                snippet = html_escape(&finding.snippet),
                ack_html = ack,
            );
        }
    }

    html.push_str(
        r#"</tbody></table></div>
<footer>本报告由 DataSentinel 生成；默认不包含敏感数据原文。请妥善保管报告文件。</footer>
</div>
<script>
let ackOnly = false;
let currentSev = 'all';
function filterSev(sev, btn) {
  document.querySelectorAll('.bar button[data-sev]').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentSev = sev;
  apply();
}
function filterAck(btn) {
  ackOnly = !ackOnly;
  btn.classList.toggle('active', ackOnly);
  apply();
}
function apply() {
  document.querySelectorAll('#rows tr[data-sev]').forEach(row => {
    const sevOk = currentSev === 'all' || row.dataset.sev === currentSev;
    const ackOk = !ackOnly || row.dataset.ack === '0';
    row.style.display = sevOk && ackOk ? '' : 'none';
  });
}
</script>
</body></html>"#,
    );

    fs::write(path, html).with_context(|| format!("写入 HTML 报告失败 {}", path.display()))?;
    Ok(())
}
