use std::path::Path;

use crate::rules::Rule;
use crate::Severity;

pub fn compute_risk_score(rule: &Rule, severity: Severity, path: &Path) -> f32 {
    let sast_severity = severity_weight(severity) * 100.0;
    let ai_likelihood = (rule.confidence_that_ai_generated.clamp(0.0, 1.0)) * 100.0;
    let context_risk = context_risk(path);
    let exploitability = exploitability(rule);

    let score = (sast_severity * 0.3)
        + (ai_likelihood * 0.3)
        + (context_risk * 0.2)
        + (exploitability * 0.2);

    (score * 10.0).round() / 10.0
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

fn context_risk(path: &Path) -> f32 {
    let path_text = path.to_string_lossy().to_ascii_lowercase();
    let high_signal = [
        "auth", "login", "token", "payment", "billing", "admin", "secret",
    ];
    if high_signal.iter().any(|needle| path_text.contains(needle)) {
        90.0
    } else {
        55.0
    }
}

fn exploitability(rule: &Rule) -> f32 {
    let mut tags = String::new();
    for tag in &rule.tags {
        tags.push_str(&tag.to_ascii_lowercase());
        tags.push(' ');
    }
    if let Some(category) = &rule.category {
        tags.push_str(&category.to_ascii_lowercase());
    }

    if tags.contains("injection") {
        return 90.0;
    }
    if tags.contains("auth") {
        return 85.0;
    }
    if tags.contains("crypto") {
        return 80.0;
    }

    60.0
}
