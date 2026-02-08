use std::path::{Path, PathBuf};
#[cfg(feature = "onnx")]
use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    process::Command,
};

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
    onnx_backend: Option<OnnxBackend>,
}

impl AiLikelihoodScorer {
    pub fn from_options(options: &AiClassifierOptions) -> Self {
        Self {
            options: options.clone(),
            onnx_backend: maybe_load_onnx_backend(options),
        }
    }

    pub fn score(&self, rule: &Rule, path: &Path, snippet: &str) -> f32 {
        let heuristic = estimate_heuristic_likelihood(rule, path, snippet);
        if self.options.mode != AiClassifierMode::Onnx {
            return heuristic;
        }

        let Some(probability) =
            predict_with_onnx_backend(self.onnx_backend.as_ref(), rule, path, snippet, heuristic)
        else {
            return heuristic;
        };

        blend_onnx_with_heuristic(probability, heuristic)
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

#[cfg(feature = "onnx")]
#[derive(Debug)]
struct OnnxBackend {
    model_path: PathBuf,
    runner_path: PathBuf,
    python_bin: String,
    cache: RefCell<HashMap<u64, f32>>,
}

#[cfg(feature = "onnx")]
fn maybe_load_onnx_backend(options: &AiClassifierOptions) -> Option<OnnxBackend> {
    if options.mode != AiClassifierMode::Onnx {
        return None;
    }

    let model_path = options.onnx_model_path.as_ref()?.to_path_buf();
    if std::fs::metadata(&model_path).is_err() {
        return None;
    }

    let runner_path = discover_onnx_runner_path(&model_path)?;
    let python_bin = discover_python_bin()?;

    Some(OnnxBackend {
        model_path,
        runner_path,
        python_bin,
        cache: RefCell::new(HashMap::new()),
    })
}

#[cfg(not(feature = "onnx"))]
struct OnnxBackend;

#[cfg(not(feature = "onnx"))]
fn maybe_load_onnx_backend(_options: &AiClassifierOptions) -> Option<OnnxBackend> {
    None
}

#[cfg(feature = "onnx")]
fn discover_onnx_runner_path(model_path: &Path) -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("AISHIELD_ONNX_RUNNER") {
        let candidate = PathBuf::from(raw.trim());
        if !candidate.as_os_str().is_empty() && candidate.exists() {
            return Some(candidate);
        }
    }

    let sibling = model_path.parent()?.join("onnx_runner.py");
    if sibling.exists() {
        return Some(sibling);
    }

    let repo_default = PathBuf::from("models/ai-classifier/onnx_runner.py");
    if repo_default.exists() {
        return Some(repo_default);
    }

    None
}

#[cfg(feature = "onnx")]
fn discover_python_bin() -> Option<String> {
    let candidates = if let Ok(raw) = std::env::var("AISHIELD_ONNX_PYTHON") {
        vec![raw]
    } else {
        vec!["python3".to_string(), "python".to_string()]
    };

    for candidate in candidates {
        if let Ok(output) = Command::new(&candidate).arg("--version").output() {
            if output.status.success() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(feature = "onnx")]
fn predict_with_onnx_backend(
    backend: Option<&OnnxBackend>,
    rule: &Rule,
    path: &Path,
    snippet: &str,
    heuristic: f32,
) -> Option<f32> {
    let backend = backend?;

    let features = build_onnx_features(rule, path, snippet, heuristic);
    let key = feature_cache_key(&features);
    if let Some(score) = backend.cache.borrow().get(&key).copied() {
        return Some(score);
    }

    let feature_payload = features
        .iter()
        .map(|value| format!("{value:.6}"))
        .collect::<Vec<_>>()
        .join(",");
    let output = Command::new(&backend.python_bin)
        .arg(&backend.runner_path)
        .arg("--model")
        .arg(&backend.model_path)
        .arg("--features")
        .arg(feature_payload)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parsed = raw.parse::<f32>().ok()?;
    let probability = if (0.0..=1.0).contains(&parsed) {
        parsed
    } else if (1.0..=100.0).contains(&parsed) {
        parsed / 100.0
    } else {
        return None;
    };

    backend.cache.borrow_mut().insert(key, probability);
    Some(probability)
}

#[cfg(not(feature = "onnx"))]
fn predict_with_onnx_backend(
    _backend: Option<&OnnxBackend>,
    _rule: &Rule,
    _path: &Path,
    _snippet: &str,
    _heuristic: f32,
) -> Option<f32> {
    None
}

fn blend_onnx_with_heuristic(probability: f32, heuristic_score: f32) -> f32 {
    let onnx_score = probability.clamp(0.0, 1.0) * 100.0;
    ((onnx_score * 0.70 + heuristic_score * 0.30).clamp(0.0, 100.0) * 10.0).round() / 10.0
}

#[cfg(feature = "onnx")]
fn build_onnx_features(rule: &Rule, path: &Path, snippet: &str, heuristic_score: f32) -> Vec<f32> {
    let snippet_lower = snippet.to_ascii_lowercase();
    let path_lower = path.to_string_lossy().to_ascii_lowercase();
    let snippet_chars = snippet.chars().collect::<Vec<_>>();
    let alnum_chars = snippet_chars
        .iter()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .count() as f32;
    let digit_chars = snippet_chars
        .iter()
        .filter(|ch| ch.is_ascii_digit())
        .count() as f32;
    let upper_chars = snippet_chars
        .iter()
        .filter(|ch| ch.is_ascii_uppercase())
        .count() as f32;
    let punctuation_chars = snippet_chars
        .iter()
        .filter(|ch| !ch.is_ascii_alphanumeric() && !ch.is_ascii_whitespace())
        .count() as f32;
    let total_chars = snippet_chars.len().max(1) as f32;
    let token_count = snippet
        .split_whitespace()
        .filter(|token| !token.trim().is_empty())
        .count() as f32;

    vec![
        rule.confidence_that_ai_generated.clamp(0.0, 1.0),
        heuristic_score.clamp(0.0, 100.0) / 100.0,
        (snippet.len().min(600) as f32) / 600.0,
        (token_count.min(160.0)) / 160.0,
        contains_any(&path_lower, &["generated", "autogen", "assistant", "llm"]) as u8 as f32,
        contains_any(
            &path_lower,
            &[
                "test", "tests", "fixture", "fixtures", "example", "examples",
            ],
        ) as u8 as f32,
        contains_any(
            &snippet_lower,
            &[
                "todo",
                "quick fix",
                "verify=false",
                "shell=true",
                "eval(",
                "runtime.getruntime().exec",
            ],
        ) as u8 as f32,
        contains_any(
            &snippet_lower,
            &[
                "compare_digest(",
                "timingsafeequal(",
                "constanttimecompare(",
                "preparedstatement",
            ],
        ) as u8 as f32,
        contains_any(
            &snippet_lower,
            &["token", "apikey", "password", "user_input", "incoming"],
        ) as u8 as f32,
        if alnum_chars > 0.0 {
            digit_chars / alnum_chars
        } else {
            0.0
        },
        upper_chars / total_chars,
        punctuation_chars / total_chars,
    ]
}

#[cfg(feature = "onnx")]
fn feature_cache_key(features: &[f32]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for value in features {
        value.to_bits().hash(&mut hasher);
    }
    hasher.finish()
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
        process::Command,
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
    fn onnx_mode_with_runner_uses_runtime_prediction() {
        if !python_available() {
            return;
        }

        let temp_dir = temp_path("aishield-onnx-model-dir");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let model_path = temp_dir.join("model.onnx");
        let runner_path = temp_dir.join("onnx_runner.py");
        fs::write(&model_path, vec![0u8; 2048]).expect("write fake model");
        fs::write(
            &runner_path,
            r#"#!/usr/bin/env python3
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--model", required=True)
parser.add_argument("--features", required=True)
parser.parse_args()
print("0.95")
"#,
        )
        .expect("write fake runner");

        let r = rule(0.75);
        let heuristic_score =
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
        assert!(onnx_score > heuristic_score);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn onnx_mode_falls_back_when_runner_is_missing() {
        let temp_dir = temp_path("aishield-onnx-no-runner");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let model_path = temp_dir.join("model.onnx");
        fs::write(&model_path, vec![0u8; 512]).expect("write fake model");

        let r = rule(0.80);
        let heuristic_score =
            estimate_ai_likelihood(&r, Path::new("src/auth/login.py"), "if token == provided:");
        let onnx_score = estimate_ai_likelihood_with_options(
            &r,
            Path::new("src/auth/login.py"),
            "if token == provided:",
            &AiClassifierOptions {
                mode: AiClassifierMode::Onnx,
                onnx_model_path: Some(model_path),
            },
        );
        assert_eq!(onnx_score, heuristic_score);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[cfg(feature = "onnx")]
    fn python_available() -> bool {
        ["python3", "python"].iter().any(|bin| {
            Command::new(bin)
                .arg("--version")
                .output()
                .map(|result| result.status.success())
                .unwrap_or(false)
        })
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
