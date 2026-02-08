use std::path::Path;

use crate::rules::Rule;

pub fn estimate_ai_likelihood(rule: &Rule, path: &Path, snippet: &str) -> f32 {
    let mut score = (rule.confidence_that_ai_generated.clamp(0.0, 1.0)) * 100.0;
    let path_text = path.to_string_lossy().to_ascii_lowercase();
    let snippet_text = snippet.to_ascii_lowercase();

    if contains_any(
        &path_text,
        &[
            "generated",
            "autogen",
            "assistant",
            "copilot",
            "ai",
            "llm",
            "tmp",
            "draft",
        ],
    ) {
        score += 8.0;
    }

    if contains_any(
        &path_text,
        &[
            "test", "tests", "fixture", "fixtures", "example", "examples",
        ],
    ) {
        score -= 14.0;
    }

    if contains_any(
        &snippet_text,
        &[
            "todo",
            "quick fix",
            "temporary",
            "disable security",
            "verify=false",
            "shell=true",
            "debug=true",
            "ignoreexpiration: true",
            "runtime.getruntime().exec",
            "eval(",
        ],
    ) {
        score += 7.0;
    }

    if contains_any(
        &snippet_text,
        &[
            "compare_digest(",
            "timingsafeequal(",
            "constanttimecompare(",
            "preparedstatement",
            "parameterized",
            "securerandom",
            "cryptographically secure",
        ],
    ) {
        score -= 8.0;
    }

    if snippet_text.len() > 120 {
        score += 2.0;
    }
    if snippet_text.len() < 20 {
        score -= 2.0;
    }

    // Naive identifiers are common in AI-proposed examples.
    if contains_any(
        &snippet_text,
        &[
            "user_input",
            "apikey",
            "token",
            "provided",
            "incoming",
            "password",
        ],
    ) {
        score += 3.0;
    }

    // Penalize snippets that contain clear domain-specific custom identifiers.
    if looks_domain_specific(&snippet_text) {
        score -= 4.0;
    }

    (score.clamp(0.0, 100.0) * 10.0).round() / 10.0
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn looks_domain_specific(snippet: &str) -> bool {
    let tokens = snippet
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map(|token| token.trim())
        .filter(|token| token.len() >= 10)
        .filter(|token| !token.chars().all(|c| c.is_ascii_digit()))
        .collect::<Vec<_>>();
    tokens.len() >= 2
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::rules::Rule;
    use crate::Severity;

    use super::estimate_ai_likelihood;

    fn rule(confidence: f32) -> Rule {
        Rule {
            id: "AISHIELD-TEST-001".to_string(),
            title: "test".to_string(),
            severity: Severity::High,
            confidence_that_ai_generated: confidence,
            languages: vec!["python".to_string()],
            ai_tendency: None,
            category: Some("auth".to_string()),
            tags: vec!["auth".to_string()],
            fix_suggestion: None,
            pattern_any: vec!["token == ".to_string()],
            pattern_all: Vec::new(),
            pattern_not: Vec::new(),
            negative_patterns: Vec::new(),
        }
    }

    #[test]
    fn likelihood_decreases_on_fixture_paths() {
        let r = rule(0.85);
        let fixture_score = estimate_ai_likelihood(
            &r,
            Path::new("tests/fixtures/auth_example.py"),
            "if token == provided:",
        );
        let prod_score =
            estimate_ai_likelihood(&r, Path::new("src/auth/login.py"), "if token == provided:");
        assert!(prod_score > fixture_score);
    }

    #[test]
    fn likelihood_penalizes_secure_primitives() {
        let r = rule(0.90);
        let insecure =
            estimate_ai_likelihood(&r, Path::new("src/auth/login.py"), "if token == provided:");
        let secure = estimate_ai_likelihood(
            &r,
            Path::new("src/auth/login.py"),
            "hmac.compare_digest(token, provided)",
        );
        assert!(secure < insecure);
    }

    #[test]
    fn likelihood_is_bounded_to_percentage_range() {
        let r = rule(1.5);
        let score = estimate_ai_likelihood(
            &r,
            Path::new("generated/assistant/auth.py"),
            "TODO quick fix eval(user_input) verify=False shell=True",
        );
        assert!((0.0..=100.0).contains(&score));
    }
}
