use std::path::Path;

use crate::rules::Rule;
use crate::Severity;

pub fn compute_risk_score(rule: &Rule, severity: Severity, path: &Path, snippet: &str) -> f32 {
    let sast_severity = severity_weight(severity) * 100.0;
    let ai_likelihood = (rule.confidence_that_ai_generated.clamp(0.0, 1.0)) * 100.0;
    let context_risk = context_risk(path, rule, snippet);
    let exploitability = exploitability(rule, path, snippet);

    let score = (sast_severity * 0.3)
        + (ai_likelihood * 0.3)
        + (context_risk * 0.2)
        + (exploitability * 0.2);

    normalize_score(score)
}

fn severity_weight(severity: Severity) -> f32 {
    match severity {
        Severity::Critical => 1.0,
        Severity::High => 0.8,
        Severity::Medium => 0.5,
        Severity::Low => 0.2,
        Severity::Info => 0.1,
    }
}

fn context_risk(path: &Path, rule: &Rule, snippet: &str) -> f32 {
    let path_text = path.to_string_lossy().to_ascii_lowercase();
    let snippet_text = snippet.to_ascii_lowercase();
    let mut score: f32 = 50.0;

    let critical_path_signal = [
        "auth",
        "login",
        "token",
        "session",
        "secret",
        "password",
        "admin",
        "payment",
        "billing",
        "checkout",
        "wallet",
        "invoice",
        "payout",
        "transfer",
        "credential",
        "oauth",
    ];
    let elevated_path_signal = ["api", "gateway", "handler", "controller", "middleware"];
    let low_signal = [
        "test", "tests", "fixture", "fixtures", "example", "examples", "docs",
    ];

    if contains_any(&path_text, &critical_path_signal) {
        score += 30.0;
    } else if contains_any(&path_text, &elevated_path_signal) {
        score += 12.0;
    }

    if contains_any(
        &snippet_text,
        &["password", "token", "secret", "authorization", "bearer"],
    ) {
        score += 10.0;
    }

    if let Some(category) = &rule.category {
        match category.to_ascii_lowercase().as_str() {
            "auth" => score += 8.0,
            "crypto" => score += 6.0,
            "injection" => score += 9.0,
            _ => {}
        }
    }

    if contains_any(&path_text, &low_signal) {
        score -= 18.0;
    }

    score.clamp(15.0, 98.0)
}

fn exploitability(rule: &Rule, path: &Path, snippet: &str) -> f32 {
    let mut tags = String::new();
    for tag in &rule.tags {
        tags.push_str(&tag.to_ascii_lowercase());
        tags.push(' ');
    }
    if let Some(category) = &rule.category {
        tags.push_str(&category.to_ascii_lowercase());
        tags.push(' ');
    }
    tags.push_str(&rule.id.to_ascii_lowercase());

    let path_text = path.to_string_lossy().to_ascii_lowercase();
    let snippet_text = snippet.to_ascii_lowercase();

    let mut score: f32 = if tags.contains("injection") {
        86.0
    } else if tags.contains("auth") {
        80.0
    } else if tags.contains("crypto") {
        74.0
    } else if tags.contains("misconfig") {
        64.0
    } else {
        58.0
    };

    let high_sink = [
        "eval(",
        "exec(",
        "runtime.getruntime().exec",
        "os.system(",
        "shell=true",
        "shell = true",
        "innerhtml",
        "document.write(",
        "$where",
        "verify=false",
        "verify = false",
    ];
    let medium_sink = [
        "select *",
        "insert into",
        "update ",
        "delete from",
        "md5(",
        "sha1(",
        "math.random(",
    ];

    if contains_any(&snippet_text, &high_sink) {
        score += 12.0;
    } else if contains_any(&snippet_text, &medium_sink) {
        score += 7.0;
    }

    if contains_any(
        &path_text,
        &[
            "internet", "public", "external", "api", "gateway", "handler",
        ],
    ) {
        score += 5.0;
    }

    if contains_any(
        &path_text,
        &[
            "test", "tests", "fixture", "fixtures", "example", "examples",
        ],
    ) {
        score -= 10.0;
    }

    score.clamp(20.0, 98.0)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn normalize_score(score: f32) -> f32 {
    let clamped = score.clamp(0.0, 100.0);
    (clamped * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::rules::Rule;
    use crate::Severity;

    use super::compute_risk_score;

    fn rule(category: &str, confidence: f32, tags: &[&str]) -> Rule {
        Rule {
            id: format!("AISHIELD-TEST-{}", category.to_ascii_uppercase()),
            title: "test".to_string(),
            severity: Severity::Medium,
            confidence_that_ai_generated: confidence,
            languages: vec!["python".to_string()],
            ai_tendency: None,
            category: Some(category.to_string()),
            tags: tags.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            fix_suggestion: None,
            pattern_any: vec!["x".to_string()],
            pattern_all: Vec::new(),
            pattern_not: Vec::new(),
            negative_patterns: Vec::new(),
        }
    }

    #[test]
    fn risk_score_boosts_for_sensitive_context_and_sinks() {
        let r = rule("injection", 0.82, &["injection"]);
        let high = compute_risk_score(
            &r,
            Severity::High,
            Path::new("src/auth/payment_handler.py"),
            "os.system(user_input)",
        );
        let low = compute_risk_score(
            &r,
            Severity::High,
            Path::new("tests/fixtures/demo.py"),
            "print('demo')",
        );
        assert!(high > low);
    }

    #[test]
    fn risk_score_respects_severity_weighting() {
        let r = rule("auth", 0.75, &["auth"]);
        let critical = compute_risk_score(
            &r,
            Severity::Critical,
            Path::new("src/auth/login.py"),
            "if token == provided:",
        );
        let medium = compute_risk_score(
            &r,
            Severity::Medium,
            Path::new("src/auth/login.py"),
            "if token == provided:",
        );
        assert!(critical > medium);
    }

    #[test]
    fn risk_score_is_bounded_to_percentage_range() {
        let r = rule("injection", 1.2, &["injection"]);
        let score = compute_risk_score(
            &r,
            Severity::Critical,
            Path::new("src/api/public_gateway.py"),
            "eval(untrusted)",
        );
        assert!((0.0..=100.0).contains(&score));
    }
}
