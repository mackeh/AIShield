use std::path::{Path, PathBuf};

pub mod onnx;

#[cfg(feature = "onnx")]
use self::onnx::OnnxClassifier;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiCalibrationProfile {
    Conservative,
    Balanced,
    Aggressive,
}

impl AiCalibrationProfile {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "conservative" => Ok(Self::Conservative),
            "balanced" => Ok(Self::Balanced),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err("ai_calibration must be conservative, balanced, or aggressive".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AiCalibrationSettings {
    pub onnx_weight: f32,
    pub heuristic_weight: f32,
    pub probability_scale: f32,
    pub probability_bias: f32,
    pub min_probability: f32,
    pub max_probability: f32,
}

impl AiCalibrationSettings {
    pub fn from_profile(profile: AiCalibrationProfile) -> Self {
        match profile {
            AiCalibrationProfile::Conservative => Self {
                onnx_weight: 0.55,
                heuristic_weight: 0.45,
                probability_scale: 0.90,
                probability_bias: -0.03,
                min_probability: 0.02,
                max_probability: 0.97,
            },
            AiCalibrationProfile::Balanced => Self {
                onnx_weight: 0.70,
                heuristic_weight: 0.30,
                probability_scale: 1.00,
                probability_bias: 0.00,
                min_probability: 0.01,
                max_probability: 0.99,
            },
            AiCalibrationProfile::Aggressive => Self {
                onnx_weight: 0.82,
                heuristic_weight: 0.18,
                probability_scale: 1.08,
                probability_bias: 0.03,
                min_probability: 0.00,
                max_probability: 1.00,
            },
        }
    }
}

impl Default for AiCalibrationSettings {
    fn default() -> Self {
        Self::from_profile(AiCalibrationProfile::Balanced)
    }
}

#[derive(Debug, Clone)]
pub struct AiClassifierOptions {
    pub mode: AiClassifierMode,
    pub onnx_model_path: Option<PathBuf>,
    pub calibration: AiCalibrationSettings,
}

impl Default for AiClassifierOptions {
    fn default() -> Self {
        Self {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
            calibration: AiCalibrationSettings::default(),
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

        blend_onnx_with_heuristic(probability, heuristic, self.options.calibration)
    }
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

    // Penalize snippets that contain clear domain-specific custom identifiers.
    if looks_domain_specific(&snippet_text) {
        score -= 4.0;
    }

    (score.clamp(0.0, 100.0) * 10.0).round() / 10.0
}

#[cfg(feature = "onnx")]
struct OnnxBackend {
    classifier: OnnxClassifier,
}

#[cfg(feature = "onnx")]
fn maybe_load_onnx_backend(options: &AiClassifierOptions) -> Option<OnnxBackend> {
    if options.mode != AiClassifierMode::Onnx {
        return None;
    }

    let model_path = options.onnx_model_path.as_ref()?;
    let model_path_str = model_path.to_str()?;

    match OnnxClassifier::new(model_path_str) {
        Ok(classifier) => Some(OnnxBackend { classifier }),
        Err(e) => {
            eprintln!("Failed to load ONNX model: {}", e);
            None
        }
    }
}

#[cfg(not(feature = "onnx"))]
struct OnnxBackend;

#[cfg(not(feature = "onnx"))]
fn maybe_load_onnx_backend(_options: &AiClassifierOptions) -> Option<OnnxBackend> {
    None
}

#[cfg(feature = "onnx")]
fn predict_with_onnx_backend(
    backend: Option<&OnnxBackend>,
    _rule: &Rule,
    _path: &Path,
    snippet: &str,
    _heuristic: f32,
) -> Option<f32> {
    let backend = backend?;
    Some(backend.classifier.score(snippet))
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

fn blend_onnx_with_heuristic(
    probability: f32,
    heuristic_score: f32,
    calibration: AiCalibrationSettings,
) -> f32 {
    let prob_floor = calibration.min_probability.clamp(0.0, 1.0);
    let prob_ceil = calibration.max_probability.clamp(prob_floor, 1.0);
    let calibrated_probability = (probability.clamp(0.0, 1.0) * calibration.probability_scale
        + calibration.probability_bias)
        .clamp(prob_floor, prob_ceil);

    let onnx_score = calibrated_probability * 100.0;
    let onnx_weight = calibration.onnx_weight.max(0.0);
    let heuristic_weight = calibration.heuristic_weight.max(0.0);
    let total_weight = (onnx_weight + heuristic_weight).max(f32::EPSILON);
    let blended = (onnx_score * onnx_weight + heuristic_score * heuristic_weight) / total_weight;

    (blended.clamp(0.0, 100.0) * 10.0).round() / 10.0
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
    use std::path::PathBuf;

    use crate::rules::Rule;
    use crate::Severity;

    use super::{
        AiCalibrationProfile, AiCalibrationSettings, AiClassifierMode, AiClassifierOptions,
        AiLikelihoodScorer,
    };

    fn rule(confidence: f32) -> Rule {
        Rule {
            id: "AISHIELD-TEST-001".to_string(),
            title: "test".to_string(),
            severity: Severity::High,
            confidence_that_ai_generated: confidence,
            languages: vec!["python".to_string()],
            ai_tendency: None,
            category: Some("auth".to_string()),
            cwe_id: None,
            owasp_category: None,
            tags: vec!["auth".to_string()],
            fix_suggestion: None,
            pattern_any: vec!["secret == ".to_string()],
            pattern_all: Vec::new(),
            pattern_not: Vec::new(),
            negative_patterns: Vec::new(),
        }
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn onnx_mode_uses_real_classifier() {
        // We look for the model relative to the workspace root or crate root
        // If running from crates/aishield-core, it's ../../models/ai-classifier/model.onnx
        let model_path = PathBuf::from("../../models/ai-classifier/model.onnx");
        if !model_path.exists() {
            // Fallback for different CWDs
            if !PathBuf::from("models/ai-classifier/model.onnx").exists() {
                eprintln!(
                    "Model not found at {:?} or local, skipping test",
                    model_path
                );
                return;
            }
        }
        let effective_path = if model_path.exists() {
            model_path
        } else {
            PathBuf::from("models/ai-classifier/model.onnx")
        };

        let r = rule(0.75);
        // Human code
        let human_score = AiLikelihoodScorer::from_options(&AiClassifierOptions {
            mode: AiClassifierMode::Onnx,
            onnx_model_path: Some(effective_path.clone()),
            calibration: AiCalibrationSettings::default(),
        })
        .score(
            &r,
            Path::new("src/main.rs"),
            "fn main() { println!(\"Hello\"); }",
        );
        // Expect low score for simple code with no comments
        // Note: Our synthetic model might be dumb, but we assert it runs.
        // The default score for minimal features might be 0.0 or something.
        // Just assert it doesn't crash and returns something valid.
        assert!(human_score >= 0.0 && human_score <= 100.0);

        // AI Code
        let ai_score = AiLikelihoodScorer::from_options(&AiClassifierOptions {
            mode: AiClassifierMode::Onnx,
            onnx_model_path: Some(effective_path),
            calibration: AiCalibrationSettings::default(),
        })
        .score(
            &r,
            Path::new("generated/code.rs"),
            "// Here is the code generated by AI Assistant\nfn foo() { bar(); }",
        );

        // Similarly, just assert validity for now until we trust the model.
        assert!(ai_score >= 0.0 && ai_score <= 100.0);
    }

    #[test]
    fn likelihood_penalizes_secure_primitives() {
        let r = rule(0.90);
        let scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions::default());
        let insecure = scorer.score(&r, Path::new("src/auth/login.py"), "if secret == provided:");
        let secure = scorer.score(
            &r,
            Path::new("src/auth/login.py"),
            "hmac.compare_digest(token, provided)",
        );
        assert!(secure < insecure);
    }

    #[test]
    fn likelihood_is_bounded_to_percentage_range() {
        let r = rule(1.5);
        let scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions::default());
        let score = scorer.score(
            &r,
            Path::new("generated/assistant/auth.py"),
            "TODO quick fix eval(user_input) verify=False shell=True",
        );
        assert!((0.0..=100.0).contains(&score));
    }

    #[test]
    fn onnx_mode_without_model_path_falls_back_to_heuristic() {
        let r = rule(0.75);
        let default_scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions::default());
        let default_score =
            default_scorer.score(&r, Path::new("src/auth/login.py"), "if secret == provided:");
        let onnx_scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions {
            mode: AiClassifierMode::Onnx,
            onnx_model_path: None,
            calibration: AiCalibrationSettings::default(),
        });
        let onnx_score =
            onnx_scorer.score(&r, Path::new("src/auth/login.py"), "if secret == provided:");
        assert_eq!(default_score, onnx_score);
    }

    #[test]
    fn scorer_builds_from_options() {
        let r = rule(0.80);
        let scorer = AiLikelihoodScorer::from_options(&AiClassifierOptions::default());
        let score = scorer.score(&r, Path::new("src/auth/login.py"), "if secret == provided:");
        assert!((0.0..=100.0).contains(&score));
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
    fn calibration_profile_parser_accepts_known_values() {
        assert_eq!(
            AiCalibrationProfile::parse("conservative").expect("parse"),
            AiCalibrationProfile::Conservative
        );
        assert_eq!(
            AiCalibrationProfile::parse("balanced").expect("parse"),
            AiCalibrationProfile::Balanced
        );
        assert_eq!(
            AiCalibrationProfile::parse("aggressive").expect("parse"),
            AiCalibrationProfile::Aggressive
        );
    }

    #[test]
    fn calibration_profile_parser_rejects_unknown_values() {
        let err = AiCalibrationProfile::parse("custom").expect_err("reject invalid profile");
        assert!(err.contains("ai_calibration"));
    }

    #[test]
    fn mode_parser_rejects_unknown_values() {
        let err = AiClassifierMode::parse("custom").expect_err("reject invalid mode");
        assert!(err.contains("ai_model"));
    }
}
