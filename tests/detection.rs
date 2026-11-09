use std::io::Write;
use std::sync::Arc;

use data_sentinel::config::Config;
use data_sentinel::detect::{Detector, ExtractOutcome};
use data_sentinel::report;
use data_sentinel::rules::RuleSet;
use data_sentinel::scan::Scanner;
use data_sentinel::store::Store;

#[test]
fn end_to_end_scan_dedupe_and_report() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let docs = dir.path().join("docs");
    std::fs::create_dir_all(&docs)?;
    let sample = docs.join("secret.txt");
    std::fs::write(
        &sample,
        "姓名: 张三\n\
         身份证: 11010519491231002X\n\
         手机号: 13812345678\n\
         邮箱: alice@corp.cn\n\
         银行卡: 4111 1111 1111 1111\n\
         密码: a8F#k2Lm9Qz!\n\
         无效身份证: 110105194912310021\n\
         -----BEGIN RSA PRIVATE KEY-----\n\
         MIIEowIBAAKCAQEA...\n\
         -----END RSA PRIVATE KEY-----\n",
    )?;
    std::fs::write(
        docs.join("notes.txt"),
        "今天没有敏感信息，只有普通会议记录。\n",
    )?;

    let mut config = Config::default();
    config.scan.roots = vec![docs.clone()];
    config.scan.threads = 2;
    config.scan.full_scan_interval_hours = 0;
    // tempfile uses %TEMP% on Windows, which is in the built-in exclude list;
    // disable built-ins so this test can scan its own temporary fixture.
    config.scan.use_default_excludes = false;
    config.scan.exclude_globs.clear();
    config.scan.exclude_extensions.clear();
    config.storage.database = dir.path().join("sentinel.db");
    config.storage.reports_dir = dir.path().join("reports");
    config.notify.enabled = false;

    let store = Arc::new(Store::open(&config.storage.database)?);
    let rules = RuleSet::build(&config.rules)?;
    let scanner = Scanner::new(Arc::new(config.clone()), store.clone(), rules)?;

    let first = scanner.scan_roots(std::slice::from_ref(&docs), false);
    assert_eq!(first.files_scanned, 2);
    assert_eq!(first.new_findings, first.findings);
    assert!(first.findings >= 6, "expected at least 6 findings");

    let findings = store.recent_findings(None, 100, true)?;
    let ids: Vec<&str> = findings.iter().map(|item| item.rule_id.as_str()).collect();
    assert!(ids.contains(&"cn_id_card"));
    assert!(ids.contains(&"cn_mobile"));
    assert!(ids.contains(&"email"));
    assert!(ids.contains(&"bank_card_formatted"));
    assert!(ids.contains(&"password_assignment"));
    assert!(ids.contains(&"private_key"));
    assert!(
        !ids.contains(&"bank_card"),
        "formatted card should win span dedupe"
    );

    // The raw sensitive values must never be persisted.
    for finding in &findings {
        assert!(!finding.snippet.contains("11010519491231002X"));
        assert!(!finding.snippet.contains("13812345678"));
        assert!(!finding.snippet.contains("a8F#k2Lm9Qz!"));
    }

    let second = scanner.scan_roots(std::slice::from_ref(&docs), false);
    assert_eq!(second.files_scanned, 0);
    assert_eq!(second.files_unchanged, 2);
    assert_eq!(second.new_findings, 0);

    // Changing detection rules must invalidate the ledger and re-scan files
    // whose size/mtime did not change.
    let mut changed_config = config.clone();
    changed_config.rules.disabled.push("cn_mobile".to_string());
    let changed_rules = RuleSet::build(&changed_config.rules)?;
    let changed_scanner = Scanner::new(Arc::new(changed_config), store.clone(), changed_rules)?;
    let third = changed_scanner.scan_roots(std::slice::from_ref(&docs), false);
    assert_eq!(third.files_scanned, 2);
    let remaining = store.recent_findings(None, 100, true)?;
    assert!(!remaining.iter().any(|item| item.rule_id == "cn_mobile"));

    let report_path = dir.path().join("report.html");
    report::export(&store, &config, "html", Some(&report_path), 30)?;
    let html = std::fs::read_to_string(&report_path)?;
    assert!(html.contains("DataSentinel 敏感数据报告"));
    assert!(html.contains("110105********002X"));
    assert!(!html.contains("11010519491231002X"));
    assert!(!html.contains("a8F#k2Lm9Qz!"));

    Ok(())
}

#[test]
fn extracts_sensitive_text_from_docx() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret.docx");
    let file = std::fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("word/document.xml", options)?;
    zip.write_all(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>员工身份证：11010519491231002X</w:t></w:r></w:p>
  <w:p><w:r><w:t>联系电话：13812345678</w:t></w:r></w:p></w:body>
</w:document>"#
            .as_bytes(),
    )?;
    zip.finish()?;

    let config = Config::default();
    let rules = RuleSet::build(&config.rules)?;
    let detector = Detector::new(rules, &config);
    let content = match detector.extract_file(&path)? {
        ExtractOutcome::Content(content) => content,
        ExtractOutcome::Skip(reason) => panic!("docx should be extracted, got: {reason}"),
    };
    let findings = detector.detect(&content.text, &path);
    let ids: Vec<&str> = findings.iter().map(|item| item.rule_id.as_str()).collect();
    assert!(ids.contains(&"cn_id_card"));
    assert!(ids.contains(&"cn_mobile"));
    Ok(())
}
