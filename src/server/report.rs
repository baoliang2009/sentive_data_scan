//! 服务端报表导出：支持 CSV（带 UTF-8 BOM）与独立单文件 HTML。

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use crate::model::{category_label, Severity};
use crate::server::store::ServerEvent;
use crate::util::{format_ts, html_escape, now_ts};

pub fn render_csv(events: &[ServerEvent]) -> Vec<u8> {
    let mut out = String::from("\u{FEFF}");
    out.push_str("时间,用户,主机,级别,类型,规则ID,规则名称,文件名,文件路径,行号,命中内容,脱敏值,上下文,文件状态\n");
    for ev in events {
        let user = if ev.username.trim().is_empty() {
            ev.hostname.as_str()
        } else {
            ev.username.as_str()
        };
        let status = if ev.file_deleted { "已删除" } else { "存在" };
        let cols = [
            format_ts(ev.received_at),
            user.to_string(),
            ev.hostname.clone(),
            ev.severity.label_zh().to_string(),
            category_label(&ev.category).to_string(),
            ev.rule_id.clone(),
            ev.rule_name.clone(),
            ev.file_name.clone(),
            ev.path.clone(),
            ev.line.to_string(),
            ev.matched.clone(),
            ev.masked.clone(),
            ev.snippet.clone(),
            status.to_string(),
        ];
        for (i, col) in cols.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&csv_escape(col));
        }
        out.push('\n');
    }
    out.into_bytes()
}

fn csv_escape(val: &str) -> String {
    let clean = val.replace(['\r', '\n'], " ");
    if clean.contains([',', '"']) {
        format!("\"{}\"", clean.replace('"', "\"\""))
    } else {
        clean
    }
}

pub fn render_html(events: &[ServerEvent], total: u64) -> Vec<u8> {
    let generated = format_ts(now_ts());
    let mut high_or_crit = 0usize;
    let mut hosts = HashSet::new();
    let mut by_cat: BTreeMap<&'static str, usize> = BTreeMap::new();
    for ev in events {
        if ev.severity >= Severity::High {
            high_or_crit += 1;
        }
        if !ev.hostname.is_empty() {
            hosts.insert(ev.hostname.as_str());
        }
        *by_cat.entry(category_label(&ev.category)).or_insert(0) += 1;
    }

    let mut rows = String::new();
    for ev in events {
        let user = if ev.username.trim().is_empty() {
            ev.hostname.as_str()
        } else {
            ev.username.as_str()
        };
        let _ = writeln!(
            rows,
            "<tr><td>{}</td><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td><td>{}</td><td><b>{}</b><br><small>{}:{}</small></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            html_escape(&format_ts(ev.received_at)),
            html_escape(user),
            html_escape(&ev.hostname),
            html_escape(ev.severity.label_zh()),
            html_escape(category_label(&ev.category)),
            html_escape(&ev.rule_name),
            html_escape(&ev.file_name),
            html_escape(&ev.path),
            ev.line,
            html_escape(&ev.matched),
            html_escape(&ev.snippet),
            if ev.file_deleted { "已删除" } else { "存在" },
        );
    }

    let mut cat_summary = String::new();
    for (cat, count) in by_cat {
        let _ = write!(cat_summary, "<span class=\"pill\">{}：{}</span> ", html_escape(cat), count);
    }

    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>数据哨兵服务端告警报表</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:24px;color:#1f2937;background:#f8fafc}}
h1{{margin:0 0 6px;font-size:22px}} .meta{{color:#64748b;font-size:13px;margin-bottom:18px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px}}
.card .label{{font-size:12px;color:#64748b}} .card .val{{font-size:22px;font-weight:700;margin-top:4px}}
.pill{{display:inline-block;background:#e2e8f0;border-radius:99px;padding:2px 10px;font-size:12px;margin:2px 4px 2px 0}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;font-size:13px}}
th,td{{padding:8px 10px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top;word-break:break-all}}
th{{background:#f1f5f9;font-weight:600}} small{{color:#64748b}} code{{background:#f1f5f9;padding:1px 4px;border-radius:4px}}
</style></head><body>
<h1>数据哨兵 · 敏感数据告警报表</h1>
<div class="meta">生成时间：{generated} · 导出条数：{}（匹配总计：{total}）</div>
<div class="cards">
<div class="card"><div class="label">导出告警数</div><div class="val">{}</div></div>
<div class="card"><div class="label">高危 / 严重</div><div class="val">{}</div></div>
<div class="card"><div class="label">涉及主机数</div><div class="val">{}</div></div>
</div>
<div style="margin-bottom:14px">{}</div>
<table><thead><tr><th>时间</th><th>用户 / 主机</th><th>级别</th><th>类型</th><th>规则</th><th>文件 / 路径</th><th>命中内容</th><th>上下文</th><th>状态</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"#,
        events.len(),
        events.len(),
        high_or_crit,
        hosts.len(),
        cat_summary
    );
    html.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn sample_event() -> ServerEvent {
        ServerEvent {
            id: 1,
            agent_id: "a1".to_string(),
            hostname: "pc-01".to_string(),
            username: "alice".to_string(),
            rule_id: "cn_mobile".to_string(),
            rule_name: "中国大陆手机号".to_string(),
            category: "contact".to_string(),
            severity: Severity::High,
            masked: "138********5678".to_string(),
            matched: "13812345678".to_string(),
            file_name: "客户,名单.xlsx".to_string(),
            path: "/Users/alice/客户,名单.xlsx".to_string(),
            line: 2,
            column: 4,
            snippet: "联系 138********5678".to_string(),
            event_time: "2026-11-26T10:00:00Z".to_string(),
            received_at: 1700000000,
            file_deleted: false,
        }
    }

    #[test]
    fn csv_has_bom_and_escapes_commas() {
        let csv = render_csv(&[sample_event()]);
        assert!(csv.starts_with(&[0xEF, 0xBB, 0xBF]));
        let text = String::from_utf8(csv).unwrap();
        assert!(text.contains("\"客户,名单.xlsx\""));
        assert!(text.contains("13812345678"));
    }

    #[test]
    fn html_contains_summary_and_row() {
        let html = String::from_utf8(render_html(&[sample_event()], 1)).unwrap();
        assert!(html.contains("数据哨兵 · 敏感数据告警报表"));
        assert!(html.contains("客户,名单.xlsx"));
        assert!(html.contains("13812345678"));
    }
}
