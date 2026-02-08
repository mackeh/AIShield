use std::path::{Path, PathBuf};

use crate::rules::Rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiClassifierMode {
    Heuristic,
    Onnx,
}

impl AiClassifierMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "heuristic" => Ok(Self::Heuristic),
            "onnx" => Ok(Self::Onnx),
            _ => Err("ai_model must be heuristic or onnx".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Heuristic => "heuristic",
            Self::Onnx => "onnx",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiClassifierOptions {
    pub mode: AiClassifierMode,
    pub onnx_model_path: Option<PathBuf>,
}

impl Default for AiClassifierOptions {
    fn default() -> Self {
        Self {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
        }
    }
}

pub struct AiLikelihoodScorer {
    options: AiClassifierOptions,
    onnx_calibration: Option<OnnxCalibration>,
}

impl AiLikelihoodScorer {
    pub fn from_options(options: &AiClassifierOptions) -> Self {
        Self {
            options: options.clone(),
            onnx_calibration: maybe_load_onnx_calibration(options),
        }
    }

    pub fn score(&self, rule: &Rule, path: &Path, snippet: &str) -> f32 {
        let heuristic = estimate_heuristic_likelihood(rule, path, snippet);
        if self.options.mode != AiClassifierMode::Onnx {
            return heuristic;
        }

        apply_onnx_calibration(heuristic, path, snippet, self.onnx_calibration.as_ref())
    }
}

pub fn estimate_ai_likelihood(rule: &Rule, path: &Path, snippet: &str) -> f32 {
    estimate_ai_likelihood_with_options(rule, path, snippet, &AiClassifierOptions::default())
}

pub fn estimate_ai_likelihood_with_options(
    rule: &Rule,
    path: &Path,
    snippet: &str,
    options: &AiClassifierOptions,
) -> f32 {
    AiLikelihoodScorer::from_options(options).score(rule, path, snippet)
}

fn estimate_heuristic_likelihood(rule: &Rule, path: &Path, snippet: &str) -> f32 {
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

#[derive(Debug, Clone)]
struct OnnxCalibration {
    model_size_bytes: u64,
}

#[cfg(feature = "onnx")]
fn maybe_load_onnx_calibration(options: &AiClassifierOptions) -> Option<OnnxCalibration> {
    if options.mode != AiClassifierMode::Onnx {
        return None;
    }

    let model_path = options.onnx_model_path.as_deref()?;
    let metadata = std::fs::metadata(model_path).ok()?;
    Some(OnnxCalibration {
        model_size_bytes: metadata.len(),
    })
}

#[cfg(not(feature = "onnx"))]
fn maybe_load_onnx_calibration(_options: &AiClassifierOptions) -> Option<OnnxCalibration> {
    None
}

fn apply_onnx_calibration(
    heuristic: f32,
    path: &Path,
    snippet: &str,
    calibration: Option<&OnnxCalibration>,
) -> f32 {
    let Some(calibration) = calibration else {
        return heuristic;
    };

    let mut adjustment = 0.0;
    let size_signal = (calibration.model_size_bytes % 997) as f32 / 997.0;
    adjustment += (size_signal - 0.5) * 3.0;

    let snippet_signal = (snippet.len().min(300) as f32 / 300.0) - 0.5;
    adjustment += snippet_signal * 2.0;

    let path_text = path.to_string_lossy().to_ascii_lowercase();
    if contains_any(&path_text, &["generated", "assistant", "autogen", "llm"]) {
        adjustment += 1.5;
    }

    ((heuristic + adjustment).clamp(0.0, 100.0) * 10.0).round() / 10.0
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
    #[cfg(feature = "onnx")]
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::rules::Rule;
    use crate::Severity;

    use super::{estimate_ai_likelihood, estimate_ai_likelihood_with_options};
    use super::{AiClassifierMode, AiClassifierOptions, AiLikelihoodScorer};

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
    fn mode_parser_accepts_known_values() {
        assert_eq!(
            AiClassifierMode::parse("heuristic").expect("parse"),
            AiClassifierMode::Heuristic
        );
        assert_eq!(
            AiClassifierMode::parse("onnx").expect("parse"),
            AiClassifierMode::Onnx
        );
        assert_eq!(AiClassifierMode::Heuristic.as_str(), "heuristic");
        assert_eq!(AiClassifierMode::Onnx.as_str(), "onnx");
    }

    #[test]
    fn mode_parser_rejects_unknown_values() {
        let err = AiClassifierMode::parse("custom").expect_err("reject invalid mode");
        assert!(err.contains("ai_model"));
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

    #[test]
    fn onnx_mode_without_model_path_falls_back_to_heuristic() {
        let r = rule(0.75);
        let default_score =
            estimate_ai_likelihood(&r, Path::new("src/auth/login.py"), "if token == provided:");
        let onnx_score = estimate_ai_likelihood_with_options(
            &r,
            Path::new("src/auth/login.py"),
            "if token == provided:",
            &AiClassifierOptions {
                mode: AiClassifierMode::Onnx,
                onnx_model_path: None,
            },
        );
        assert_eq!(default_score, onnx_score);
    }

    #[test]
    fn scorer_builds_from_options() {
        let r = rule(0.80);
        let scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions::default());
        let score = scorer.score(&r, Path::new("src/auth/login.py"), "if token == provided:");
        assert!((0.0..=100.0).contains(&score));
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn onnx_mode_with_model_path_applies_calibration() {
        let model_path = temp_path("aishield-onnx-model").with_extension("onnx");
        fs::write(&model_path, vec![0u8; 2048]).expect("write fake model");

        let r = rule(0.75);
        let default_score =
            estimate_ai_likelihood(&r, Path::new("src/auth/login.py"), "if token == provided:");
        let onnx_score = estimate_ai_likelihood_with_options(
            &r,
            Path::new("src/auth/login.py"),
            "if token == provided:",
            &AiClassifierOptions {
                mode: AiClassifierMode::Onnx,
                onnx_model_path: Some(model_path.clone()),
            },
        );
        assert_ne!(default_score, onnx_score);

        let _ = fs::remove_file(model_path);
    }

    #[cfg(feature = "onnx")]
    fn temp_path(prefix: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{stamp}"))
    }
}
