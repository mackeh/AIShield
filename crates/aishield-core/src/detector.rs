use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::rules::{Rule, RuleSet};
use crate::scanner::collect_source_files;
use crate::scoring::compute_risk_score;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub ai_confidence: f32,
    pub risk_score: f32,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub ai_tendency: Option<String>,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub total: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub scanned_files: usize,
    pub matched_rules: usize,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub ai_only: bool,
    pub min_ai_confidence: Option<f32>,
    pub categories: Vec<String>,
}

pub struct Analyzer {
    rules: RuleSet,
}

impl Analyzer {
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn analyze_path(
        &self,
        target: &Path,
        options: &AnalysisOptions,
    ) -> Result<ScanResult, String> {
        let rules = self.rules.with_categories(&options.categories);
        let files = collect_source_files(target);

        let mut findings = Vec::new();
        let mut dedup = HashSet::new();

        for file in &files {
            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            let full_lower = content.to_ascii_lowercase();

            for rule in rules.for_language(&file.language) {
                if !should_include_rule(rule, options) {
                    continue;
                }

                for (line_no, line) in content.lines().enumerate() {
                    let line_lower = line.to_ascii_lowercase();
                    let Some(column) = rule.matches_line(&line_lower) else {
                        continue;
                    };

                    if has_negative_match(&line_lower, &full_lower, &rule.negative_patterns) {
                        continue;
                    }

                    let relative = relative_path(target, &file.path);
                    let dedup_key = format!("{}:{}:{}", rule.id, relative, line_no + 1);
                    if !dedup.insert(dedup_key) {
                        continue;
                    }

                    findings.push(Finding {
                        id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: rule.severity,
                        file: relative,
                        line: line_no + 1,
                        column,
                        snippet: line.trim().to_string(),
                        ai_confidence: ((rule.confidence_that_ai_generated * 100.0) * 10.0).round()
                            / 10.0,
                        risk_score: compute_risk_score(rule, rule.severity, &file.path),
                        category: rule.category.clone(),
                        tags: rule.tags.clone(),
                        ai_tendency: rule.ai_tendency.clone(),
                        fix_suggestion: rule.fix_suggestion.clone(),
                    });
                }
            }
        }

        findings.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        let summary = build_summary(&findings, files.len(), rules.rules.len());
        Ok(ScanResult { findings, summary })
    }
}

fn should_include_rule(rule: &Rule, options: &AnalysisOptions) -> bool {
    if !options.ai_only {
        return true;
    }

    let threshold = options.min_ai_confidence.unwrap_or(0.70).clamp(0.0, 1.0);
    rule.confidence_that_ai_generated >= threshold
}

fn has_negative_match(line_lower: &str, full_lower: &str, negative_patterns: &[String]) -> bool {
    for pattern in negative_patterns {
        if line_lower.contains(pattern) || full_lower.contains(pattern) {
            return true;
        }
    }
    false
}

fn relative_path(root: &Path, path: &Path) -> String {
    if root.is_file() {
        if let Some(name) = path.file_name() {
            return name.to_string_lossy().to_string();
        }
        return path.display().to_string();
    }

    match path.strip_prefix(root) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn build_summary(findings: &[Finding], scanned_files: usize, matched_rules: usize) -> ScanSummary {
    let mut by_severity = BTreeMap::new();
    by_severity.insert("critical".to_string(), 0);
    by_severity.insert("high".to_string(), 0);
    by_severity.insert("medium".to_string(), 0);
    by_severity.insert("low".to_string(), 0);
    by_severity.insert("info".to_string(), 0);

    for finding in findings {
        let key = finding.severity.as_str().to_string();
        *by_severity.entry(key).or_insert(0) += 1;
    }

    ScanSummary {
        total: findings.len(),
        by_severity,
        scanned_files,
        matched_rules,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::rules::RuleSet;

    use super::{AnalysisOptions, Analyzer};

    #[test]
    fn detects_python_token_compare_pattern() {
        let root = temp_path("aishield-core-test");
        let rules_dir = root.join("rules/python/auth");
        let src_dir = root.join("src");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&src_dir).expect("create src dir");

        fs::write(
            rules_dir.join("token-compare.yaml"),
            r#"id: AISHIELD-PY-AUTH-001
title: Timing-Unsafe Secret Comparison
severity: high
confidence_that_ai_generated: 0.88
languages: [python]
category: auth
pattern:
  all:
    - "token"
    - "=="
  not:
    - "compare_digest("
fix:
  suggestion: use compare_digest
tags: [auth]
"#,
        )
        .expect("write rule");

        fs::write(
            src_dir.join("login.py"),
            r#"def check(token, provided):
    return token == provided
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(src_dir.as_path(), &AnalysisOptions::default())
            .expect("scan");

        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].id, "AISHIELD-PY-AUTH-001");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn any_and_not_patterns_work_together() {
        let root = temp_path("aishield-core-test-any-not");
        let rules_dir = root.join("rules/javascript/auth");
        let src_dir = root.join("src");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&src_dir).expect("create src dir");

        fs::write(
            rules_dir.join("token-compare.yaml"),
            r#"id: AISHIELD-JS-AUTH-001
title: Timing-Unsafe Token Comparison
severity: high
confidence_that_ai_generated: 0.84
languages: [javascript]
category: auth
pattern:
  any:
    - "token === "
    - "apikey === "
  not:
    - "timingsafeequal("
fix:
  suggestion: use timingSafeEqual
tags: [auth]
"#,
        )
        .expect("write rule");

        fs::write(
            src_dir.join("auth.js"),
            r#"function bad(token, expected) {
  if (token === expected) return true;
}

function good(token, expected) {
  return crypto.timingSafeEqual(token, expected);
}
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(src_dir.as_path(), &AnalysisOptions::default())
            .expect("scan");

        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].line, 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fixture_suite_triggers_broad_rule_coverage() {
        let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        let rules = RuleSet::load_from_dir(&rules_dir).expect("load repository rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(fixture_dir.as_path(), &AnalysisOptions::default())
            .expect("scan fixture suite");

        assert!(
            result.summary.total >= 20,
            "expected at least 20 findings in fixture suite, got {}",
            result.summary.total
        );
    }

    #[test]
    fn single_file_scan_keeps_filename_location() {
        let root = temp_path("aishield-core-test-file-target");
        let rules_dir = root.join("rules/python/auth");
        let src_dir = root.join("src");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&src_dir).expect("create src dir");

        fs::write(
            rules_dir.join("token-compare.yaml"),
            r#"id: AISHIELD-PY-AUTH-001
title: Timing-Unsafe Secret Comparison
severity: high
confidence_that_ai_generated: 0.88
languages: [python]
category: auth
pattern:
  any:
    - "token == "
fix:
  suggestion: use compare_digest
tags: [auth]
"#,
        )
        .expect("write rule");

        let file = src_dir.join("single.py");
        fs::write(&file, "if token == provided:\n    pass\n").expect("write source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(file.as_path(), &AnalysisOptions::default())
            .expect("scan");

        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].file, "single.py");

        let _ = fs::remove_dir_all(root);
    }

    fn temp_path(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{stamp}"))
    }
}
