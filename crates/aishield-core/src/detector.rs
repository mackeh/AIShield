use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::classifier::{AiClassifierOptions, AiLikelihoodScorer};
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
    pub exclude_paths: Vec<String>,
    pub cross_file: bool,
    pub ai_classifier: AiClassifierOptions,
}

#[derive(Debug, Clone)]
struct SourceSlice {
    file: String,
    language: String,
    lines: Vec<String>,
    line_lowers: Vec<String>,
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
        let mut source_slices = Vec::<SourceSlice>::new();
        let ai_scorer = AiLikelihoodScorer::from_options(&options.ai_classifier);

        for file in &files {
            if is_excluded_path(target, &file.path, &options.exclude_paths) {
                continue;
            }

            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            let full_lower = content.to_ascii_lowercase();
            let lines = content
                .lines()
                .map(|line| line.to_string())
                .collect::<Vec<_>>();
            let line_lowers = lines
                .iter()
                .map(|line| line.to_ascii_lowercase())
                .collect::<Vec<_>>();
            let relative = relative_path(target, &file.path);

            source_slices.push(SourceSlice {
                file: relative.clone(),
                language: file.language.clone(),
                lines: lines.clone(),
                line_lowers: line_lowers.clone(),
            });

            for rule in rules.for_language(&file.language) {
                if !should_include_rule(rule, options) {
                    continue;
                }

                if is_file_suppressed(&line_lowers, &rule.id) {
                    continue;
                }

                for (line_no, line) in lines.iter().enumerate() {
                    let line_lower = &line_lowers[line_no];

                    if is_line_suppressed(line_lower, &rule.id) {
                        continue;
                    }
                    if line_no > 0 && is_line_suppressed(&line_lowers[line_no - 1], &rule.id) {
                        continue;
                    }

                    let Some(column) = rule.matches_line(line_lower) else {
                        continue;
                    };

                    if has_negative_match(&line_lower, &full_lower, &rule.negative_patterns) {
                        continue;
                    }

                    let dedup_key = format!("{}:{}:{}", rule.id, relative, line_no + 1);
                    if !dedup.insert(dedup_key) {
                        continue;
                    }

                    let ai_confidence = ai_scorer.score(rule, &file.path, line.trim());
                    findings.push(Finding {
                        id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: rule.severity,
                        file: relative.clone(),
                        line: line_no + 1,
                        column,
                        snippet: line.trim().to_string(),
                        ai_confidence,
                        risk_score: compute_risk_score(
                            rule,
                            rule.severity,
                            &file.path,
                            line.trim(),
                            ai_confidence,
                        ),
                        category: rule.category.clone(),
                        tags: rule.tags.clone(),
                        ai_tendency: rule.ai_tendency.clone(),
                        fix_suggestion: rule.fix_suggestion.clone(),
                    });
                }
            }
        }

        if options.cross_file {
            for finding in detect_cross_file_auth_gaps(&source_slices) {
                let dedup_key = format!("{}:{}:{}", finding.id, finding.file, finding.line);
                if dedup.insert(dedup_key) {
                    findings.push(finding);
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

fn is_excluded_path(target: &Path, file_path: &Path, exclude_paths: &[String]) -> bool {
    if exclude_paths.is_empty() {
        return false;
    }

    let full = file_path.to_string_lossy().to_ascii_lowercase();
    let relative = relative_path(target, file_path).to_ascii_lowercase();

    exclude_paths.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        !pattern.is_empty() && (full.contains(&pattern) || relative.contains(&pattern))
    })
}

fn has_negative_match(line_lower: &str, full_lower: &str, negative_patterns: &[String]) -> bool {
    for pattern in negative_patterns {
        if line_lower.contains(pattern) || full_lower.contains(pattern) {
            return true;
        }
    }
    false
}

fn is_file_suppressed(lines_lower: &[String], rule_id: &str) -> bool {
    let rule_id_lower = rule_id.to_ascii_lowercase();
    lines_lower
        .iter()
        .any(|line| marker_applies(line, "aishield:ignore-file", &rule_id_lower))
}

fn is_line_suppressed(line_lower: &str, rule_id: &str) -> bool {
    if line_lower.contains("aishield:ignore-file") {
        return false;
    }
    marker_applies(line_lower, "aishield:ignore", &rule_id.to_ascii_lowercase())
}

fn marker_applies(line_lower: &str, marker: &str, rule_id_lower: &str) -> bool {
    let Some(idx) = line_lower.find(marker) else {
        return false;
    };

    let tail = line_lower[idx + marker.len()..]
        .trim()
        .trim_start_matches(':')
        .trim();

    if tail.is_empty() {
        return true;
    }

    tail.contains(rule_id_lower)
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

fn detect_cross_file_auth_gaps(sources: &[SourceSlice]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in sources {
        match source.language.as_str() {
            "javascript" => findings.extend(detect_js_sensitive_routes_without_auth(source)),
            "python" => findings.extend(detect_python_sensitive_routes_without_auth(source)),
            "java" => findings.extend(detect_java_sensitive_routes_without_auth(source)),
            _ => {}
        }
    }
    findings
}

fn detect_js_sensitive_routes_without_auth(source: &SourceSlice) -> Vec<Finding> {
    let mut findings = Vec::new();
    let route_markers = [
        "app.get(",
        "app.post(",
        "app.put(",
        "app.delete(",
        "router.get(",
        "router.post(",
        "router.put(",
        "router.delete(",
    ];

    for (idx, line_lower) in source.line_lowers.iter().enumerate() {
        if !route_markers
            .iter()
            .any(|marker| line_lower.contains(marker))
        {
            continue;
        }
        let route = extract_quoted_segment(&source.lines[idx]).unwrap_or_default();
        if !route_is_sensitive(&route) {
            continue;
        }
        if line_has_auth_hint(line_lower) {
            continue;
        }
        if has_prior_js_guard(source, idx) {
            continue;
        }

        findings.push(Finding {
            id: "AISHIELD-JS-AUTH-XF-001".to_string(),
            title: "Potential Unprotected Sensitive Route".to_string(),
            severity: Severity::High,
            file: source.file.clone(),
            line: idx + 1,
            column: 1,
            snippet: source.lines[idx].trim().to_string(),
            ai_confidence: 58.0,
            risk_score: 70.0,
            category: Some("auth".to_string()),
            tags: vec![
                "auth".to_string(),
                "cross-file".to_string(),
                "heuristic".to_string(),
            ],
            ai_tendency: Some(
                "AI route handlers often expose sensitive endpoints before auth middleware is applied."
                    .to_string(),
            ),
            fix_suggestion: Some(
                "Attach authentication/authorization middleware to this route or apply guarded router groups.".to_string(),
            ),
        });
    }

    findings
}

fn detect_python_sensitive_routes_without_auth(source: &SourceSlice) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line_lower) in source.line_lowers.iter().enumerate() {
        let is_route = line_lower.contains("@app.route(")
            || line_lower.contains("@bp.route(")
            || line_lower.contains("@api.route(")
            || line_lower.contains("@app.get(")
            || line_lower.contains("@app.post(")
            || line_lower.contains("@router.get(")
            || line_lower.contains("@router.post(");
        if !is_route {
            continue;
        }

        let route = extract_quoted_segment(&source.lines[idx]).unwrap_or_default();
        if !route_is_sensitive(&route) {
            continue;
        }
        if has_nearby_python_auth_decorator(source, idx) {
            continue;
        }

        findings.push(Finding {
            id: "AISHIELD-PY-AUTH-XF-001".to_string(),
            title: "Potential Unprotected Sensitive Route".to_string(),
            severity: Severity::High,
            file: source.file.clone(),
            line: idx + 1,
            column: 1,
            snippet: source.lines[idx].trim().to_string(),
            ai_confidence: 57.0,
            risk_score: 69.0,
            category: Some("auth".to_string()),
            tags: vec![
                "auth".to_string(),
                "cross-file".to_string(),
                "heuristic".to_string(),
            ],
            ai_tendency: Some(
                "Generated backend routes frequently omit login/authorization decorators on admin-like endpoints."
                    .to_string(),
            ),
            fix_suggestion: Some(
                "Add login/authorization decorators (for example @login_required or @jwt_required())."
                    .to_string(),
            ),
        });
    }

    findings
}

fn detect_java_sensitive_routes_without_auth(source: &SourceSlice) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line_lower) in source.line_lowers.iter().enumerate() {
        let is_route = line_lower.contains("@getmapping(")
            || line_lower.contains("@postmapping(")
            || line_lower.contains("@putmapping(")
            || line_lower.contains("@deletemapping(")
            || line_lower.contains("@requestmapping(");
        if !is_route {
            continue;
        }

        let route = extract_quoted_segment(&source.lines[idx]).unwrap_or_default();
        if !route_is_sensitive(&route) {
            continue;
        }
        if has_nearby_java_auth_annotation(source, idx) {
            continue;
        }

        findings.push(Finding {
            id: "AISHIELD-JAVA-AUTH-XF-001".to_string(),
            title: "Potential Unprotected Sensitive Route".to_string(),
            severity: Severity::High,
            file: source.file.clone(),
            line: idx + 1,
            column: 1,
            snippet: source.lines[idx].trim().to_string(),
            ai_confidence: 56.0,
            risk_score: 68.5,
            category: Some("auth".to_string()),
            tags: vec![
                "auth".to_string(),
                "cross-file".to_string(),
                "heuristic".to_string(),
            ],
            ai_tendency: Some(
                "AI-generated Spring controller snippets may define admin-like routes without authorization annotations."
                    .to_string(),
            ),
            fix_suggestion: Some(
                "Add method-level authorization (for example @PreAuthorize or @Secured) for sensitive routes."
                    .to_string(),
            ),
        });
    }

    findings
}

fn has_prior_js_guard(source: &SourceSlice, route_line: usize) -> bool {
    source.line_lowers[..=route_line].iter().any(|line| {
        (line.contains("app.use(") || line.contains("router.use(")) && line_has_auth_hint(line)
    })
}

fn has_nearby_python_auth_decorator(source: &SourceSlice, route_line: usize) -> bool {
    let auth_markers = [
        "@login_required",
        "@jwt_required",
        "@auth_required",
        "@roles_required",
        "@permission_required",
        "@requires_auth",
    ];

    let start = route_line.saturating_sub(4);
    let end = (route_line + 3).min(source.line_lowers.len().saturating_sub(1));
    source.line_lowers[start..=end]
        .iter()
        .any(|line| auth_markers.iter().any(|marker| line.contains(marker)))
}

fn has_nearby_java_auth_annotation(source: &SourceSlice, route_line: usize) -> bool {
    let auth_markers = [
        "@preauthorize",
        "@secured",
        "@rolesallowed",
        "@authenticationprincipal",
    ];
    let start = route_line.saturating_sub(4);
    source.line_lowers[start..=route_line]
        .iter()
        .any(|line| auth_markers.iter().any(|marker| line.contains(marker)))
}

fn line_has_auth_hint(line_lower: &str) -> bool {
    let hints = [
        "auth",
        "jwt",
        "passport",
        "requireauth",
        "verifytoken",
        "loginrequired",
        "authenticated",
    ];
    hints.iter().any(|hint| line_lower.contains(hint))
}

fn route_is_sensitive(route: &str) -> bool {
    if route.is_empty() {
        return false;
    }
    let route = route.to_ascii_lowercase();
    let hints = [
        "admin", "account", "billing", "payment", "profile", "internal", "private", "manage",
        "settings", "user",
    ];
    hints.iter().any(|hint| route.contains(hint))
}

fn extract_quoted_segment(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let start = line.find(quote)?;
        let remainder = &line[start + 1..];
        let end = remainder.find(quote)?;
        let value = remainder[..end].trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
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
            result.summary.total >= 110,
            "expected at least 110 findings in expanded fixture suite, got {}",
            result.summary.total
        );

        let go_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-GO-"))
            .count();
        let rust_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-RS-"))
            .count();
        let java_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-JAVA-"))
            .count();
        let csharp_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-CS-"))
            .count();
        let ruby_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-RB-"))
            .count();
        let php_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-PHP-"))
            .count();
        let kotlin_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-KT-"))
            .count();
        let swift_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-SW-"))
            .count();
        let terraform_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-TF-"))
            .count();
        let kubernetes_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-K8S-"))
            .count();
        let docker_findings = result
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("AISHIELD-DOCKER-"))
            .count();

        assert!(
            go_findings >= 15,
            "expected at least 15 go findings in fixture suite, got {}",
            go_findings
        );
        assert!(
            rust_findings >= 15,
            "expected at least 15 rust findings in fixture suite, got {}",
            rust_findings
        );
        assert!(
            java_findings >= 15,
            "expected at least 15 java findings in fixture suite, got {}",
            java_findings
        );
        assert!(
            csharp_findings >= 5,
            "expected at least 5 csharp findings in fixture suite, got {}",
            csharp_findings
        );
        assert!(
            ruby_findings >= 5,
            "expected at least 5 ruby findings in fixture suite, got {}",
            ruby_findings
        );
        assert!(
            php_findings >= 5,
            "expected at least 5 php findings in fixture suite, got {}",
            php_findings
        );
        assert!(
            kotlin_findings >= 10,
            "expected at least 10 kotlin findings in fixture suite, got {}",
            kotlin_findings
        );
        assert!(
            swift_findings >= 10,
            "expected at least 10 swift findings in fixture suite, got {}",
            swift_findings
        );
        assert!(
            terraform_findings >= 5,
            "expected at least 5 terraform findings in fixture suite, got {}",
            terraform_findings
        );
        assert!(
            kubernetes_findings >= 5,
            "expected at least 5 kubernetes findings in fixture suite, got {}",
            kubernetes_findings
        );
        assert!(
            docker_findings >= 5,
            "expected at least 5 dockerfile findings in fixture suite, got {}",
            docker_findings
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

    #[test]
    fn suppression_markers_ignore_expected_findings() {
        let root = temp_path("aishield-core-test-suppressions");
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

        fs::write(
            src_dir.join("suppress.py"),
            r#"# aishield:ignore AISHIELD-PY-AUTH-001
if token == expected:
    pass

# aishield:ignore
if token == another:
    pass

if token == live:
    pass
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(src_dir.as_path(), &AnalysisOptions::default())
            .expect("scan");

        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].line, 9);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_level_suppression_works_for_rule() {
        let root = temp_path("aishield-core-test-file-suppress");
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
fix:
  suggestion: use timingSafeEqual
tags: [auth]
"#,
        )
        .expect("write rule");

        fs::write(
            src_dir.join("suppressed.js"),
            r#"// aishield:ignore-file AISHIELD-JS-AUTH-001
if (token === expected) {
  return true;
}
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(src_dir.as_path(), &AnalysisOptions::default())
            .expect("scan");

        assert_eq!(result.summary.total, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exclude_paths_skip_matching_files() {
        let root = temp_path("aishield-core-test-exclude");
        let rules_dir = root.join("rules/python/auth");
        let src_dir = root.join("src");
        let vendor_dir = src_dir.join("vendor");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&vendor_dir).expect("create vendor dir");

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

        fs::write(src_dir.join("main.py"), "if token == expected:\n    pass\n")
            .expect("write source");
        fs::write(
            vendor_dir.join("lib.py"),
            "if token == expected:\n    pass\n",
        )
        .expect("write vendor source");

        let rules = RuleSet::load_from_dir(root.join("rules").as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let options = AnalysisOptions {
            exclude_paths: vec!["vendor/".to_string()],
            ..AnalysisOptions::default()
        };
        let result = analyzer
            .analyze_path(src_dir.as_path(), &options)
            .expect("scan");

        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].file, "main.py");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cross_file_mode_detects_sensitive_routes_only_when_enabled() {
        let root = temp_path("aishield-core-test-cross-file-enabled");
        let rules_dir = root.join("rules");
        let src_dir = root.join("src");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&src_dir).expect("create src dir");
        fs::write(
            src_dir.join("routes.js"),
            r#"const app = require("express")();
app.get("/admin/users", listUsers);
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(rules_dir.as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);

        let no_cross_file = analyzer
            .analyze_path(src_dir.as_path(), &AnalysisOptions::default())
            .expect("scan default");
        assert_eq!(no_cross_file.summary.total, 0);

        let result = analyzer
            .analyze_path(
                src_dir.as_path(),
                &AnalysisOptions {
                    cross_file: true,
                    ..AnalysisOptions::default()
                },
            )
            .expect("scan cross-file");
        assert_eq!(result.summary.total, 1);
        assert_eq!(result.findings[0].id, "AISHIELD-JS-AUTH-XF-001");
        assert_eq!(result.findings[0].file, "routes.js");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cross_file_mode_skips_js_route_with_auth_hint() {
        let root = temp_path("aishield-core-test-cross-file-auth-hint");
        let rules_dir = root.join("rules");
        let src_dir = root.join("src");

        fs::create_dir_all(&rules_dir).expect("create rules dir");
        fs::create_dir_all(&src_dir).expect("create src dir");
        fs::write(
            src_dir.join("routes.js"),
            r#"const app = require("express")();
app.get("/admin/users", requireAuth, listUsers);
"#,
        )
        .expect("write source");

        let rules = RuleSet::load_from_dir(rules_dir.as_path()).expect("load rules");
        let analyzer = Analyzer::new(rules);
        let result = analyzer
            .analyze_path(
                src_dir.as_path(),
                &AnalysisOptions {
                    cross_file: true,
                    ..AnalysisOptions::default()
                },
            )
            .expect("scan cross-file");

        assert_eq!(result.summary.total, 0);

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
