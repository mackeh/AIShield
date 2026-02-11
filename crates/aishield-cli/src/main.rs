use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

mod analytics_client;
mod config;
mod git_utils;

use aishield_core::{
    AiCalibrationProfile, AiCalibrationSettings, AiClassifierMode, AiClassifierOptions,
    AnalysisOptions, Analyzer, Finding, RuleSet, ScanResult, ScanSummary, Severity,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use dialoguer::{Confirm, MultiSelect, Select};
use reqwest::blocking::Client;
use serde_json::Value;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "scan" => run_scan(&args[1..]),
        "fix" => run_fix(&args[1..]),
        "bench" => run_bench(&args[1..]),
        "init" => run_init(&args[1..]),
        "create-rule" => run_create_rule(&args[1..]),
        "rules" => run_rules(&args[1..]),
        "stats" => run_stats(&args[1..]),
        "hook" => run_hook(&args[1..]),
        "config" => run_config(&args[1..]),
        "analytics" => run_analytics(&args[1..]),
        "watch" => run_watch(&args[1..]),
        "deps" => run_deps(&args[1..]),
        "sbom" => run_sbom(&args[1..]),
        "keys" => run_keys(&args[1..]),
        "verify" => run_verify(&args[1..]),
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        cmd => Err(format!("unknown command `{cmd}`")),
    }
}

fn run_scan(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("scan requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);

    let mut rules_dir_override = None;
    let mut format_override = None;
    let mut dedup_mode_override = None;
    let mut bridge_engines_override = None::<Vec<BridgeEngine>>;
    let mut categories_override = None;
    let mut exclude_paths_override = None;
    let mut ai_only_flag = false;
    let mut cross_file_flag = false;
    let mut ai_model_override = None::<AiClassifierMode>;
    let mut onnx_model_override = None::<PathBuf>;
    let mut onnx_manifest_override = None::<PathBuf>;
    let mut ai_calibration_override = None::<AiCalibrationProfile>;
    let mut min_ai_confidence_override = None;
    let mut severity_override = None;
    let mut fail_on_findings_flag = false;
    let mut output_path = None;
    let mut baseline_path = None::<PathBuf>;
    let mut notify_webhook_override = None::<String>;
    let mut notify_severity_override = None::<SeverityThreshold>;
    let mut history_file_override = None;
    let mut no_history_flag = false;
    let mut analytics_push_flag = false;
    let mut org_id_override = None::<String>;
    let mut team_id_override = None::<String>;
    let mut repo_id_override = None::<String>;
    let mut staged_only = false;
    let mut changed_from = None::<String>;
    let mut config_path = PathBuf::from(".aishield.yml");
    let mut use_config = true;
    let mut profile_override = None::<ScanProfile>;
    let mut badge_flag = false;
    let mut vibe_flag = false;
    let mut sign_flag = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir_override = Some(PathBuf::from(
                    args.get(i).ok_or("--rules-dir requires a value")?,
                ));
            }
            "--org-id" => {
                i += 1;
                org_id_override = Some(args.get(i).ok_or("--org-id requires a value")?.to_string());
            }
            "--team-id" => {
                i += 1;
                team_id_override =
                    Some(args.get(i).ok_or("--team-id requires a value")?.to_string());
            }
            "--repo-id" => {
                i += 1;
                repo_id_override =
                    Some(args.get(i).ok_or("--repo-id requires a value")?.to_string());
            }
            "--format" => {
                i += 1;
                format_override = Some(OutputFormat::parse(
                    args.get(i).ok_or("--format requires a value")?,
                )?);
            }
            "--dedup" => {
                i += 1;
                dedup_mode_override = Some(DedupMode::parse(
                    args.get(i).ok_or("--dedup requires a value")?,
                )?);
            }
            "--bridge" => {
                i += 1;
                bridge_engines_override = Some(parse_bridge_engines(
                    args.get(i).ok_or("--bridge requires a value")?,
                )?);
            }
            "--rules" => {
                i += 1;
                let raw = args.get(i).ok_or("--rules requires a value")?;
                categories_override = Some(parse_list_like(raw));
            }
            "--exclude" => {
                i += 1;
                let raw = args.get(i).ok_or("--exclude requires a value")?;
                exclude_paths_override = Some(parse_list_like(raw));
            }
            "--ai-only" => ai_only_flag = true,
            "--cross-file" => cross_file_flag = true,
            "--ai-model" => {
                i += 1;
                ai_model_override = Some(AiClassifierMode::parse(
                    args.get(i).ok_or("--ai-model requires a value")?,
                )?);
            }
            "--onnx-model" => {
                i += 1;
                onnx_model_override = Some(PathBuf::from(
                    args.get(i).ok_or("--onnx-model requires a value")?,
                ));
            }
            "--onnx-manifest" => {
                i += 1;
                onnx_manifest_override = Some(PathBuf::from(
                    args.get(i).ok_or("--onnx-manifest requires a value")?,
                ));
            }
            "--ai-calibration" => {
                i += 1;
                ai_calibration_override = Some(AiCalibrationProfile::parse(
                    args.get(i).ok_or("--ai-calibration requires a value")?,
                )?);
            }
            "--min-ai-confidence" => {
                i += 1;
                let raw = args.get(i).ok_or("--min-ai-confidence requires a value")?;
                min_ai_confidence_override = Some(
                    raw.parse::<f32>()
                        .map_err(|_| "invalid --min-ai-confidence value".to_string())?,
                );
            }
            "--severity" => {
                i += 1;
                severity_override = Some(SeverityThreshold::parse(
                    args.get(i).ok_or("--severity requires a value")?,
                )?);
            }
            "--fail-on-findings" => fail_on_findings_flag = true,
            "--output" => {
                i += 1;
                output_path = Some(PathBuf::from(
                    args.get(i).ok_or("--output requires a value")?,
                ));
            }
            "--baseline" => {
                i += 1;
                baseline_path = Some(PathBuf::from(
                    args.get(i).ok_or("--baseline requires a value")?,
                ));
            }
            "--notify-webhook" => {
                i += 1;
                notify_webhook_override = Some(
                    args.get(i)
                        .ok_or("--notify-webhook requires a value")?
                        .to_string(),
                );
            }
            "--notify-min-severity" => {
                i += 1;
                notify_severity_override = Some(SeverityThreshold::parse(
                    args.get(i)
                        .ok_or("--notify-min-severity requires a value")?,
                )?);
            }
            "--history-file" => {
                i += 1;
                history_file_override = Some(PathBuf::from(
                    args.get(i).ok_or("--history-file requires a value")?,
                ));
            }
            "--no-history" => no_history_flag = true,
            "--analytics-push" => analytics_push_flag = true,
            "--staged" => staged_only = true,
            "--changed-from" => {
                i += 1;
                changed_from = Some(
                    args.get(i)
                        .ok_or("--changed-from requires a value")?
                        .to_string(),
                );
            }
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or("--config requires a value")?);
            }
            "--no-config" => use_config = false,
            "--profile" => {
                i += 1;
                profile_override = Some(ScanProfile::parse(
                    args.get(i).ok_or("--profile requires a value")?,
                )?);
            }
            "--badge" => badge_flag = true,
            "--vibe" => vibe_flag = true,
            "--sign" => sign_flag = true,
            other => return Err(format!("unknown scan option `{other}`")),
        }
        i += 1;
    }

    let config = if use_config {
        AppConfig::load_if_exists(&config_path)?
    } else {
        AppConfig::default()
    };

    let rules_dir = rules_dir_override.unwrap_or_else(|| config.rules_dir.clone());
    let format = format_override.unwrap_or(config.format);
    let dedup_mode = dedup_mode_override
        .or(config.dedup_mode)
        .unwrap_or_else(|| DedupMode::default_for_format(format));
    let bridge_engines = bridge_engines_override.unwrap_or_else(|| config.bridge_engines.clone());
    let categories = categories_override.unwrap_or_else(|| config.rules.clone());
    let mut exclude_paths = config.exclude_paths.clone();
    if let Some(extra) = exclude_paths_override {
        exclude_paths.extend(extra);
    }
    let cross_file = cross_file_flag || config.cross_file;
    let ai_model = ai_model_override
        .or_else(|| onnx_model_override.as_ref().map(|_| AiClassifierMode::Onnx))
        .or_else(|| {
            onnx_manifest_override
                .as_ref()
                .map(|_| AiClassifierMode::Onnx)
        })
        .unwrap_or(config.ai_model);
    let onnx_model_path = onnx_model_override.or_else(|| config.onnx_model_path.clone());
    let onnx_manifest_path = onnx_manifest_override.or_else(|| config.onnx_manifest_path.clone());
    let ai_calibration = ai_calibration_override.unwrap_or(config.ai_calibration);
    // Apply profile overrides (profile sets defaults, explicit flags still take precedence)
    let (profile_min_severity, profile_min_ai, profile_ai_only) = match profile_override {
        Some(ScanProfile::Strict) => (None, None, false),
        Some(ScanProfile::Pragmatic) => (
            Some(SeverityThreshold::High),
            Some(0.50_f32),
            true,
        ),
        Some(ScanProfile::AiFocus) => (None, Some(0.75_f32), true),
        None => (None, None, false),
    };
    let ai_only = ai_only_flag || config.ai_only || profile_ai_only;
    let severity_threshold = severity_override
        .or(config.severity_threshold)
        .or(profile_min_severity);
    let min_ai_confidence = min_ai_confidence_override
        .or(config.min_ai_confidence)
        .or(profile_min_ai);
    let fail_on_findings = fail_on_findings_flag || config.fail_on_findings;
    let history_file = history_file_override.unwrap_or_else(|| config.history_file.clone());
    let record_history = if no_history_flag {
        false
    } else {
        config.record_history
    };
    let notify_webhook_url = notify_webhook_override
        .or_else(|| {
            env::var("AISHIELD_NOTIFY_WEBHOOK")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| config.notify_webhook_url.clone());
    let notify_min_severity = notify_severity_override
        .or(config.notify_min_severity)
        .unwrap_or(SeverityThreshold::High);

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;

    if ruleset.rules.is_empty() {
        return Err(format!("no rules found in {}", rules_dir.display()));
    }

    let rules_count = ruleset.rules.len();
    let analyzer = Analyzer::new(ruleset);
    let ai_classifier = resolve_ai_classifier(
        ai_model,
        onnx_model_path,
        onnx_manifest_path.as_deref(),
        ai_calibration,
    );
    let options = AnalysisOptions {
        ai_only,
        cross_file,
        ai_classifier,
        min_ai_confidence,
        categories,
        exclude_paths,
    };
    if staged_only && changed_from.is_some() {
        return Err("use either --staged or --changed-from, not both".to_string());
    }

    let mut result = if staged_only {
        let staged_targets = collect_staged_targets(&target)?;
        analyze_targets(&analyzer, &options, &staged_targets, rules_count)?
    } else if let Some(from_ref) = changed_from.as_deref() {
        let changed_targets = collect_changed_targets(&target, from_ref)?;
        analyze_targets(&analyzer, &options, &changed_targets, rules_count)?
    } else {
        analyzer
            .analyze_path(&target, &options)
            .map_err(|err| format!("failed to scan {}: {err}", target.display()))?
    };

    if !bridge_engines.is_empty() {
        let bridge_result = collect_bridge_findings(&target, &bridge_engines);
        for warning in bridge_result.warnings {
            eprintln!("warning: {warning}");
        }

        if !bridge_result.findings.is_empty() {
            result.findings.extend(bridge_result.findings);
            result = dedup_machine_output(&result, DedupMode::Normalized);
            result.summary = recompute_summary(&result);
        }
    }

    if let Some(threshold) = severity_threshold {
        result.findings = result
            .findings
            .into_iter()
            .filter(|f| threshold.includes(f.severity))
            .collect::<Vec<_>>();
        result.summary = recompute_summary(&result);
    }

    if let Some(path) = baseline_path.as_deref() {
        let baseline_keys = load_baseline_keys(path)?;
        let (filtered, suppressed) = filter_findings_against_baseline(&result, &baseline_keys);
        result = filtered;
        if suppressed > 0 {
            eprintln!(
                "info: baseline filtered {} finding(s) from {}",
                suppressed,
                path.display()
            );
        }
    }

    if record_history {
        if let Err(err) = append_history(&history_file, &target, &result) {
            eprintln!("warning: failed to append scan history: {err}");
        }
    }

    // Push to analytics API if enabled
    if analytics_push_flag {
        if let Err(err) = push_to_analytics(
            &target,
            &result,
            org_id_override,
            team_id_override,
            repo_id_override,
        ) {
            eprintln!("warning: analytics push failed: {err}");
        }
    }

    if let Some(webhook_url) = notify_webhook_url {
        if let Err(err) =
            maybe_send_webhook_notification(&webhook_url, notify_min_severity, &target, &result)
        {
            eprintln!("warning: failed to send webhook notification: {err}");
        }
    }

    let rendered = if vibe_flag {
        render_vibe(&result)
    } else {
        match format {
            OutputFormat::Table => render_table(&result),
            OutputFormat::Json => {
                let deduped = dedup_machine_output(&result, dedup_mode);
                let summary = build_output_summary(&result, &deduped, dedup_mode);
                render_json(&deduped, &summary)
            }
            OutputFormat::Sarif => {
                let deduped = dedup_machine_output(&result, dedup_mode);
                let summary = build_output_summary(&result, &deduped, dedup_mode);
                render_sarif(&deduped, &summary)
            }
            OutputFormat::Github => {
                let deduped = dedup_machine_output(&result, dedup_mode);
                let summary = build_output_summary(&result, &deduped, dedup_mode);
                render_github_annotations(&deduped, &summary)
            }
        }
    };

    let badge_output = if badge_flag {
        Some(render_badge(&result))
    } else {
        None
    };

    let rendered = if sign_flag && matches!(format, OutputFormat::Json) {
        match sign_scan_output(&rendered) {
            Ok(signed) => signed,
            Err(e) => {
                eprintln!("warning: signing failed: {e}");
                rendered
            }
        }
    } else {
        rendered
    };

    if let Some(path) = output_path {
        fs::write(&path, rendered)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        println!("Wrote report to {}", path.display());
    } else {
        write_stdout(&rendered)?;
    }

    if let Some(badge) = badge_output {
        println!("{badge}");
    }

    if fail_on_findings && !result.findings.is_empty() {
        std::process::exit(2);
    }

    Ok(())
}

fn collect_staged_targets(target: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .map_err(|err| format!("failed to query staged files via git: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            "unknown git error".to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(format!("git diff --cached failed: {}", message));
    }

    let mut targets = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let path = PathBuf::from(line.trim());
        if path.as_os_str().is_empty() {
            continue;
        }
        if !path_matches_target(&path, target) {
            continue;
        }
        if path.exists() {
            targets.push(path);
        }
    }

    Ok(targets)
}

fn collect_changed_targets(target: &Path, from_ref: &str) -> Result<Vec<PathBuf>, String> {
    let range = format!("{from_ref}...HEAD");
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", &range])
        .output()
        .map_err(|err| format!("failed to query changed files via git: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            "unknown git error".to_string()
        } else {
            stderr.trim().to_string()
        };
        return Err(format!("git diff {range} failed: {}", message));
    }

    let mut targets = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let path = PathBuf::from(line.trim());
        if path.as_os_str().is_empty() {
            continue;
        }
        if !path_matches_target(&path, target) {
            continue;
        }
        if path.exists() {
            targets.push(path);
        }
    }

    Ok(targets)
}

struct BridgeScanResult {
    findings: Vec<Finding>,
    warnings: Vec<String>,
}

fn parse_bridge_engines(raw: &str) -> Result<Vec<BridgeEngine>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let items = parse_list_like(raw);
    if items.is_empty() {
        return Ok(Vec::new());
    }

    for item in items {
        let mut engines = match item.as_str() {
            "all" => vec![
                BridgeEngine::Semgrep,
                BridgeEngine::Bandit,
                BridgeEngine::Eslint,
            ],
            _ => vec![BridgeEngine::parse(&item)?],
        };
        for engine in engines.drain(..) {
            if seen.insert(engine.as_str()) {
                out.push(engine);
            }
        }
    }

    Ok(out)
}

fn collect_bridge_findings(target: &Path, engines: &[BridgeEngine]) -> BridgeScanResult {
    let mut handles = Vec::new();
    for engine in engines {
        let target = target.to_path_buf();
        let engine = *engine;
        handles.push(thread::spawn(move || {
            match run_bridge_engine(engine, &target) {
                Ok(findings) => (engine, findings, None),
                Err(err) => (
                    engine,
                    Vec::new(),
                    Some(format!("{} bridge unavailable: {}", engine.as_str(), err)),
                ),
            }
        }));
    }

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok((_engine, engine_findings, warning)) => {
                findings.extend(engine_findings);
                if let Some(warning) = warning {
                    warnings.push(warning);
                }
            }
            Err(_) => warnings.push("bridge worker thread panicked".to_string()),
        }
    }

    BridgeScanResult { findings, warnings }
}

fn run_bridge_engine(engine: BridgeEngine, target: &Path) -> Result<Vec<Finding>, String> {
    match engine {
        BridgeEngine::Semgrep => run_semgrep_bridge(target),
        BridgeEngine::Bandit => run_bandit_bridge(target),
        BridgeEngine::Eslint => run_eslint_bridge(target),
    }
}

fn run_semgrep_bridge(target: &Path) -> Result<Vec<Finding>, String> {
    let output = Command::new("semgrep")
        .args([
            "scan",
            "--json",
            "--quiet",
            "--disable-version-check",
            &target.display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute semgrep: {err}"))?;

    if !(output.status.success() || output.status.code() == Some(1)) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            format!("semgrep exited with status {}", output.status)
        } else {
            stderr.trim().to_string()
        });
    }

    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid semgrep JSON output: {err}"))?;
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();
    for result in results {
        let check_id = result
            .get("check_id")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        let path = result
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let line = result
            .get("start")
            .and_then(|v| v.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let column = result
            .get("start")
            .and_then(|v| v.get("col"))
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;

        let message = result
            .get("extra")
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str)
            .unwrap_or(check_id)
            .to_string();
        let snippet = result
            .get("extra")
            .and_then(|v| v.get("lines"))
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| message.clone());
        let severity = semgrep_severity_to_internal(
            result
                .get("extra")
                .and_then(|v| v.get("severity"))
                .and_then(Value::as_str)
                .unwrap_or("warning"),
        );

        findings.push(Finding {
            id: format!("SAST-SEMGRP-{}", sanitize_bridge_id(check_id)),
            title: message,
            severity,
            file: display_path_for_finding(target, path),
            line,
            column,
            snippet,
            ai_confidence: 30.0,
            risk_score: bridge_risk_score(severity),
            category: Some("sast-bridge".to_string()),
            cwe_id: None,
            owasp_category: None,
            tags: vec!["sast-bridge".to_string(), "semgrep".to_string()],
            ai_tendency: None,
            fix_suggestion: None,
        });
    }

    Ok(findings)
}

fn run_bandit_bridge(target: &Path) -> Result<Vec<Finding>, String> {
    let output = Command::new("bandit")
        .args(["-r", "-f", "json", &target.display().to_string()])
        .output()
        .map_err(|err| format!("failed to execute bandit: {err}"))?;

    if !(output.status.success() || output.status.code() == Some(1)) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            format!("bandit exited with status {}", output.status)
        } else {
            stderr.trim().to_string()
        });
    }

    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid bandit JSON output: {err}"))?;
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();
    for result in results {
        let test_id = result
            .get("test_id")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        let message = result
            .get("issue_text")
            .and_then(Value::as_str)
            .unwrap_or(test_id)
            .to_string();
        let file = result
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let line = result
            .get("line_number")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let column = result
            .get("col_offset")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let snippet = result
            .get("code")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| message.clone());
        let severity = bandit_severity_to_internal(
            result
                .get("issue_severity")
                .and_then(Value::as_str)
                .unwrap_or("medium"),
        );

        findings.push(Finding {
            id: format!("SAST-BANDIT-{}", sanitize_bridge_id(test_id)),
            title: message,
            severity,
            file: display_path_for_finding(target, file),
            line,
            column,
            snippet,
            ai_confidence: 30.0,
            risk_score: bridge_risk_score(severity),
            category: Some("sast-bridge".to_string()),
            cwe_id: None,
            owasp_category: None,
            tags: vec!["sast-bridge".to_string(), "bandit".to_string()],
            ai_tendency: None,
            fix_suggestion: None,
        });
    }

    Ok(findings)
}

fn run_eslint_bridge(target: &Path) -> Result<Vec<Finding>, String> {
    let output = Command::new("eslint")
        .args(["-f", "json", &target.display().to_string()])
        .output()
        .map_err(|err| format!("failed to execute eslint: {err}"))?;

    if !(output.status.success() || output.status.code() == Some(1)) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            format!("eslint exited with status {}", output.status)
        } else {
            stderr.trim().to_string()
        });
    }

    let payload: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid eslint JSON output: {err}"))?;
    let file_results = payload.as_array().cloned().unwrap_or_default();

    let mut findings = Vec::new();
    for file_result in file_results {
        let file_path = file_result
            .get("filePath")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let messages = file_result
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for message in messages {
            let rule_id = message
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN");
            let title = message
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or(rule_id)
                .to_string();
            let line = message.get("line").and_then(Value::as_u64).unwrap_or(1) as usize;
            let column = message.get("column").and_then(Value::as_u64).unwrap_or(1) as usize;
            let severity = eslint_severity_to_internal(
                message.get("severity").and_then(Value::as_i64).unwrap_or(1),
            );
            let snippet = message
                .get("source")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| title.clone());

            findings.push(Finding {
                id: format!("SAST-ESLINT-{}", sanitize_bridge_id(rule_id)),
                title,
                severity,
                file: display_path_for_finding(target, file_path),
                line,
                column,
                snippet,
                ai_confidence: 30.0,
                risk_score: bridge_risk_score(severity),
                category: Some("sast-bridge".to_string()),
                cwe_id: None,
                owasp_category: None,
                tags: vec!["sast-bridge".to_string(), "eslint".to_string()],
                ai_tendency: None,
                fix_suggestion: None,
            });
        }
    }

    Ok(findings)
}

fn sanitize_bridge_id(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn display_path_for_finding(target: &Path, raw_path: &str) -> String {
    let candidate = PathBuf::from(raw_path);
    if path_matches_target(&candidate, target) {
        return relative_to_target(target, &candidate);
    }

    if let Ok(cwd) = env::current_dir() {
        let joined = cwd.join(&candidate);
        if path_matches_target(&joined, target) {
            return relative_to_target(target, &joined);
        }
    }

    raw_path.to_string()
}

fn relative_to_target(target: &Path, path: &Path) -> String {
    if target == Path::new(".") {
        return path.display().to_string();
    }

    if target.is_file() {
        return path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());
    }

    path.strip_prefix(target)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn semgrep_severity_to_internal(raw: &str) -> Severity {
    match raw.to_ascii_lowercase().as_str() {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "info" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn bandit_severity_to_internal(raw: &str) -> Severity {
    match raw.to_ascii_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn eslint_severity_to_internal(raw: i64) -> Severity {
    match raw {
        2 => Severity::High,
        1 => Severity::Medium,
        _ => Severity::Low,
    }
}

fn bridge_risk_score(severity: Severity) -> f32 {
    match severity {
        Severity::Critical => 90.0,
        Severity::High => 80.0,
        Severity::Medium => 65.0,
        Severity::Low => 45.0,
        Severity::Info => 30.0,
    }
}

fn path_matches_target(candidate: &Path, target: &Path) -> bool {
    if target == Path::new(".") {
        return true;
    }
    if target.is_file() {
        return candidate == target;
    }
    candidate.starts_with(target)
}

fn analyze_targets(
    analyzer: &Analyzer,
    options: &AnalysisOptions,
    targets: &[PathBuf],
    rules_count: usize,
) -> Result<ScanResult, String> {
    if targets.is_empty() {
        return Ok(ScanResult {
            findings: Vec::new(),
            summary: empty_summary(0, rules_count),
        });
    }

    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for target in targets {
        let partial = analyzer
            .analyze_path(target, options)
            .map_err(|err| format!("failed to scan {}: {err}", target.display()))?;
        scanned_files += partial.summary.scanned_files;
        findings.extend(partial.findings);
    }

    findings.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let summary = summarize_findings(&findings, scanned_files, rules_count);
    Ok(ScanResult { findings, summary })
}

fn run_bench(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("bench requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);
    let mut rules_dir_override = None;
    let mut bridge_engines_override = None::<Vec<BridgeEngine>>;
    let mut categories_override = None;
    let mut exclude_paths_override = None;
    let mut ai_only_flag = false;
    let mut cross_file_flag = false;
    let mut ai_model_override = None::<AiClassifierMode>;
    let mut onnx_model_override = None::<PathBuf>;
    let mut onnx_manifest_override = None::<PathBuf>;
    let mut ai_calibration_override = None::<AiCalibrationProfile>;
    let mut min_ai_confidence_override = None;
    let mut iterations = 5usize;
    let mut warmup = 1usize;
    let mut format = BenchOutputFormat::Table;
    let mut config_path = PathBuf::from(".aishield.yml");
    let mut use_config = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir_override = Some(PathBuf::from(
                    args.get(i).ok_or("--rules-dir requires a value")?,
                ));
            }
            "--bridge" => {
                i += 1;
                bridge_engines_override = Some(parse_bridge_engines(
                    args.get(i).ok_or("--bridge requires a value")?,
                )?);
            }
            "--rules" => {
                i += 1;
                let raw = args.get(i).ok_or("--rules requires a value")?;
                categories_override = Some(parse_list_like(raw));
            }
            "--exclude" => {
                i += 1;
                let raw = args.get(i).ok_or("--exclude requires a value")?;
                exclude_paths_override = Some(parse_list_like(raw));
            }
            "--ai-only" => ai_only_flag = true,
            "--cross-file" => cross_file_flag = true,
            "--ai-model" => {
                i += 1;
                ai_model_override = Some(AiClassifierMode::parse(
                    args.get(i).ok_or("--ai-model requires a value")?,
                )?);
            }
            "--onnx-model" => {
                i += 1;
                onnx_model_override = Some(PathBuf::from(
                    args.get(i).ok_or("--onnx-model requires a value")?,
                ));
            }
            "--onnx-manifest" => {
                i += 1;
                onnx_manifest_override = Some(PathBuf::from(
                    args.get(i).ok_or("--onnx-manifest requires a value")?,
                ));
            }
            "--ai-calibration" => {
                i += 1;
                ai_calibration_override = Some(AiCalibrationProfile::parse(
                    args.get(i).ok_or("--ai-calibration requires a value")?,
                )?);
            }
            "--min-ai-confidence" => {
                i += 1;
                let raw = args.get(i).ok_or("--min-ai-confidence requires a value")?;
                min_ai_confidence_override = Some(
                    raw.parse::<f32>()
                        .map_err(|_| "invalid --min-ai-confidence value".to_string())?,
                );
            }
            "--iterations" => {
                i += 1;
                let raw = args.get(i).ok_or("--iterations requires a value")?;
                iterations = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid --iterations value".to_string())?;
                if iterations == 0 {
                    return Err("--iterations must be greater than zero".to_string());
                }
            }
            "--warmup" => {
                i += 1;
                let raw = args.get(i).ok_or("--warmup requires a value")?;
                warmup = raw
                    .parse::<usize>()
                    .map_err(|_| "invalid --warmup value".to_string())?;
            }
            "--format" => {
                i += 1;
                format = BenchOutputFormat::parse(args.get(i).ok_or("--format requires a value")?)?;
            }
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or("--config requires a value")?);
            }
            "--no-config" => use_config = false,
            other => return Err(format!("unknown bench option `{other}`")),
        }
        i += 1;
    }

    let config = if use_config {
        AppConfig::load_if_exists(&config_path)?
    } else {
        AppConfig::default()
    };

    let rules_dir = rules_dir_override.unwrap_or_else(|| config.rules_dir.clone());
    let bridge_engines = bridge_engines_override.unwrap_or_else(|| config.bridge_engines.clone());
    let categories = categories_override.unwrap_or_else(|| config.rules.clone());
    let mut exclude_paths = config.exclude_paths.clone();
    if let Some(extra) = exclude_paths_override {
        exclude_paths.extend(extra);
    }
    let ai_only = ai_only_flag || config.ai_only;
    let cross_file = cross_file_flag || config.cross_file;
    let ai_model = ai_model_override
        .or_else(|| onnx_model_override.as_ref().map(|_| AiClassifierMode::Onnx))
        .or_else(|| {
            onnx_manifest_override
                .as_ref()
                .map(|_| AiClassifierMode::Onnx)
        })
        .unwrap_or(config.ai_model);
    let onnx_model_path = onnx_model_override.or_else(|| config.onnx_model_path.clone());
    let onnx_manifest_path = onnx_manifest_override.or_else(|| config.onnx_manifest_path.clone());
    let ai_calibration = ai_calibration_override.unwrap_or(config.ai_calibration);
    let min_ai_confidence = min_ai_confidence_override.or(config.min_ai_confidence);

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;
    if ruleset.rules.is_empty() {
        return Err(format!("no rules found in {}", rules_dir.display()));
    }

    let analyzer = Analyzer::new(ruleset);
    let ai_classifier = resolve_ai_classifier(
        ai_model,
        onnx_model_path,
        onnx_manifest_path.as_deref(),
        ai_calibration,
    );
    let options = AnalysisOptions {
        ai_only,
        cross_file,
        ai_classifier,
        min_ai_confidence,
        categories,
        exclude_paths,
    };

    let total_runs = warmup + iterations;
    let mut samples_ms = Vec::with_capacity(iterations);
    let mut final_result = None::<ScanResult>;
    let mut bridge_warnings_seen = HashSet::new();

    for run_idx in 0..total_runs {
        let started = Instant::now();
        let mut result = analyzer
            .analyze_path(&target, &options)
            .map_err(|err| format!("failed to scan {}: {err}", target.display()))?;

        if !bridge_engines.is_empty() {
            let bridge_result = collect_bridge_findings(&target, &bridge_engines);
            for warning in bridge_result.warnings {
                if bridge_warnings_seen.insert(warning.clone()) {
                    eprintln!("warning: {warning}");
                }
            }
            if !bridge_result.findings.is_empty() {
                result.findings.extend(bridge_result.findings);
                result = dedup_machine_output(&result, DedupMode::Normalized);
                result.summary = recompute_summary(&result);
            }
        }

        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        if run_idx >= warmup {
            samples_ms.push(elapsed_ms);
            final_result = Some(result);
        }
    }

    let final_result = final_result.ok_or("benchmark did not execute measured runs")?;
    let metrics = BenchMetrics::from_samples(&samples_ms)?;
    let rendered = match format {
        BenchOutputFormat::Table => render_bench_table(
            &target,
            iterations,
            warmup,
            &metrics,
            &final_result,
            &bridge_engines,
        ),
        BenchOutputFormat::Json => render_bench_json(
            &target,
            iterations,
            warmup,
            &metrics,
            &final_result,
            &bridge_engines,
        ),
    };

    write_stdout(&rendered)
}

fn resolve_ai_classifier(
    requested_mode: AiClassifierMode,
    requested_model_path: Option<PathBuf>,
    requested_manifest_path: Option<&Path>,
    requested_calibration: AiCalibrationProfile,
) -> AiClassifierOptions {
    let mut resolved_model_path = requested_model_path;
    let mut calibration = AiCalibrationSettings::from_profile(requested_calibration);

    if let Some(manifest_path) = requested_manifest_path {
        match load_onnx_manifest(manifest_path) {
            Ok(manifest) => {
                if resolved_model_path.is_none() {
                    resolved_model_path = manifest.model_path.clone();
                }
                if requested_calibration == AiCalibrationProfile::Balanced {
                    if let Some(profile) = manifest.calibration_profile {
                        calibration = AiCalibrationSettings::from_profile(profile);
                    }
                }
                calibration = apply_manifest_calibration_overrides(calibration, &manifest);
            }
            Err(err) => {
                eprintln!(
                    "warning: failed to load ONNX manifest {}: {err}",
                    manifest_path.display()
                )
            }
        }
    }

    if requested_mode != AiClassifierMode::Onnx {
        return AiClassifierOptions {
            mode: requested_mode,
            onnx_model_path: resolved_model_path,
            calibration,
        };
    }

    if !cfg!(feature = "onnx") {
        eprintln!(
            "warning: --ai-model onnx requested but this binary was built without `onnx` feature; falling back to heuristic scoring"
        );
        return AiClassifierOptions {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
            calibration,
        };
    }

    let Some(model_path) = resolved_model_path else {
        eprintln!(
            "warning: --ai-model onnx requested but no model path was provided (--onnx-model or manifest); falling back to heuristic scoring"
        );
        return AiClassifierOptions {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
            calibration,
        };
    };

    if !model_path.exists() {
        eprintln!(
            "warning: ONNX model path {} does not exist; falling back to heuristic scoring",
            model_path.display()
        );
        return AiClassifierOptions {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
            calibration,
        };
    }

    AiClassifierOptions {
        mode: AiClassifierMode::Onnx,
        onnx_model_path: Some(model_path),
        calibration,
    }
}

#[derive(Debug, Default)]
struct OnnxManifest {
    model_path: Option<PathBuf>,
    calibration_profile: Option<AiCalibrationProfile>,
    onnx_weight: Option<f32>,
    heuristic_weight: Option<f32>,
    probability_scale: Option<f32>,
    probability_bias: Option<f32>,
    min_probability: Option<f32>,
    max_probability: Option<f32>,
}

fn load_onnx_manifest(path: &Path) -> Result<OnnxManifest, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed reading {}: {err}", path.display()))?;
    let value: Value =
        serde_json::from_str(&content).map_err(|err| format!("invalid JSON: {err}"))?;

    let mut manifest = OnnxManifest::default();
    if let Some(model_path) = value
        .get("model")
        .and_then(|model| model.get("path"))
        .and_then(Value::as_str)
    {
        let candidate = PathBuf::from(model_path.trim());
        if !candidate.as_os_str().is_empty() {
            manifest.model_path = Some(if candidate.is_relative() {
                path.parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(candidate)
            } else {
                candidate
            });
        }
    }

    if let Some(calibration) = value.get("calibration") {
        if let Some(profile_raw) = calibration.get("profile").and_then(Value::as_str) {
            manifest.calibration_profile = Some(AiCalibrationProfile::parse(profile_raw)?);
        }

        manifest.onnx_weight = calibration
            .get("onnx_weight")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
        manifest.heuristic_weight = calibration
            .get("heuristic_weight")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
        manifest.probability_scale = calibration
            .get("probability_scale")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
        manifest.probability_bias = calibration
            .get("probability_bias")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
        manifest.min_probability = calibration
            .get("min_probability")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
        manifest.max_probability = calibration
            .get("max_probability")
            .and_then(Value::as_f64)
            .map(|v| v as f32);
    }

    Ok(manifest)
}

fn apply_manifest_calibration_overrides(
    base: AiCalibrationSettings,
    manifest: &OnnxManifest,
) -> AiCalibrationSettings {
    let mut tuned = base;
    if let Some(weight) = manifest.onnx_weight {
        tuned.onnx_weight = weight;
    }
    if let Some(weight) = manifest.heuristic_weight {
        tuned.heuristic_weight = weight;
    }
    if let Some(scale) = manifest.probability_scale {
        tuned.probability_scale = scale;
    }
    if let Some(bias) = manifest.probability_bias {
        tuned.probability_bias = bias;
    }
    if let Some(min_probability) = manifest.min_probability {
        tuned.min_probability = min_probability;
    }
    if let Some(max_probability) = manifest.max_probability {
        tuned.max_probability = max_probability;
    }

    tuned.min_probability = tuned.min_probability.clamp(0.0, 1.0);
    tuned.max_probability = tuned.max_probability.clamp(tuned.min_probability, 1.0);
    tuned.onnx_weight = tuned.onnx_weight.max(0.0);
    tuned.heuristic_weight = tuned.heuristic_weight.max(0.0);
    tuned.probability_scale = tuned.probability_scale.clamp(0.2, 2.0);
    tuned.probability_bias = tuned.probability_bias.clamp(-0.5, 0.5);

    tuned
}

struct BenchMetrics {
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    stddev_ms: f64,
}

impl BenchMetrics {
    fn from_samples(samples_ms: &[f64]) -> Result<Self, String> {
        if samples_ms.is_empty() {
            return Err("benchmark samples are empty".to_string());
        }

        let min_ms = samples_ms
            .iter()
            .copied()
            .reduce(f64::min)
            .ok_or("missing min sample")?;
        let max_ms = samples_ms
            .iter()
            .copied()
            .reduce(f64::max)
            .ok_or("missing max sample")?;
        let mean_ms = samples_ms.iter().sum::<f64>() / samples_ms.len() as f64;
        let variance = samples_ms
            .iter()
            .map(|sample| {
                let delta = sample - mean_ms;
                delta * delta
            })
            .sum::<f64>()
            / samples_ms.len() as f64;
        let stddev_ms = variance.sqrt();

        Ok(Self {
            min_ms,
            max_ms,
            mean_ms,
            median_ms: percentile(samples_ms, 0.50),
            p95_ms: percentile(samples_ms, 0.95),
            stddev_ms,
        })
    }
}

fn percentile(samples_ms: &[f64], percentile: f64) -> f64 {
    if samples_ms.is_empty() {
        return 0.0;
    }
    if samples_ms.len() == 1 {
        return samples_ms[0];
    }

    let mut sorted = samples_ms.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let clamped = percentile.clamp(0.0, 1.0);
    let rank = clamped * (sorted.len() as f64 - 1.0);
    let lower_idx = rank.floor() as usize;
    let upper_idx = rank.ceil() as usize;
    if lower_idx == upper_idx {
        return sorted[lower_idx];
    }

    let weight = rank - lower_idx as f64;
    sorted[lower_idx] + (sorted[upper_idx] - sorted[lower_idx]) * weight
}

fn render_bench_table(
    target: &Path,
    iterations: usize,
    warmup: usize,
    metrics: &BenchMetrics,
    result: &ScanResult,
    bridge_engines: &[BridgeEngine],
) -> String {
    let mut out = String::new();
    let bridge_display = if bridge_engines.is_empty() {
        "none".to_string()
    } else {
        bridge_engines
            .iter()
            .map(|engine| engine.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };

    let _ = writeln!(out, "AIShield benchmark");
    let _ = writeln!(out, "Target: {}", target.display());
    let _ = writeln!(out, "Iterations: {} (warmup {})", iterations, warmup);
    let _ = writeln!(out, "Bridge engines: {}", bridge_display);
    let _ = writeln!(out, "Mean:   {:.2} ms", metrics.mean_ms);
    let _ = writeln!(out, "Median: {:.2} ms", metrics.median_ms);
    let _ = writeln!(out, "P95:    {:.2} ms", metrics.p95_ms);
    let _ = writeln!(out, "Min:    {:.2} ms", metrics.min_ms);
    let _ = writeln!(out, "Max:    {:.2} ms", metrics.max_ms);
    let _ = writeln!(out, "Stddev: {:.2} ms", metrics.stddev_ms);
    let _ = writeln!(
        out,
        "Throughput: {:.2} scans/sec",
        1000.0 / metrics.mean_ms.max(0.0001)
    );
    let _ = writeln!(
        out,
        "Result snapshot: findings={} scanned_files={} matched_rules={}",
        result.summary.total, result.summary.scanned_files, result.summary.matched_rules
    );
    let target_status = if metrics.mean_ms <= 2000.0 {
        "PASS"
    } else {
        "FAIL"
    };
    let _ = writeln!(out, "Phase-2 speed target (<2s mean): {}", target_status);
    out
}

fn render_bench_json(
    target: &Path,
    iterations: usize,
    warmup: usize,
    metrics: &BenchMetrics,
    result: &ScanResult,
    bridge_engines: &[BridgeEngine],
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(
        out,
        "  \"target\": \"{}\",",
        escape_json(target.to_string_lossy().as_ref())
    );
    let _ = writeln!(out, "  \"iterations\": {},", iterations);
    let _ = writeln!(out, "  \"warmup\": {},", warmup);
    out.push_str("  \"bridge_engines\": [");
    for (idx, engine) in bridge_engines.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "\"{}\"", engine.as_str());
    }
    out.push_str("],\n");
    out.push_str("  \"timing_ms\": {\n");
    let _ = writeln!(out, "    \"mean\": {:.3},", metrics.mean_ms);
    let _ = writeln!(out, "    \"median\": {:.3},", metrics.median_ms);
    let _ = writeln!(out, "    \"p95\": {:.3},", metrics.p95_ms);
    let _ = writeln!(out, "    \"min\": {:.3},", metrics.min_ms);
    let _ = writeln!(out, "    \"max\": {:.3},", metrics.max_ms);
    let _ = writeln!(out, "    \"stddev\": {:.3}", metrics.stddev_ms);
    out.push_str("  },\n");
    let _ = writeln!(
        out,
        "  \"throughput_scans_per_sec\": {:.3},",
        1000.0 / metrics.mean_ms.max(0.0001)
    );
    out.push_str("  \"result_snapshot\": {\n");
    let _ = writeln!(out, "    \"findings\": {},", result.summary.total);
    let _ = writeln!(
        out,
        "    \"scanned_files\": {},",
        result.summary.scanned_files
    );
    let _ = writeln!(
        out,
        "    \"matched_rules\": {}",
        result.summary.matched_rules
    );
    out.push_str("  },\n");
    let _ = writeln!(
        out,
        "  \"target_under_2s_mean\": {}",
        if metrics.mean_ms <= 2000.0 {
            "true"
        } else {
            "false"
        }
    );
    out.push_str("}\n");
    out
}

fn run_fix(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("fix requires a target path".to_string());
    }

    let target_spec = parse_fix_target_spec(&args[0])?;
    let target = target_spec.scan_path.clone();
    let mut rules_dir_override = None;
    let mut write_changes = false;
    let mut dry_run = false;
    let mut interactive = false;
    let mut config_path = PathBuf::from(".aishield.yml");
    let mut use_config = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir_override = Some(PathBuf::from(
                    args.get(i).ok_or("--rules-dir requires a value")?,
                ));
            }
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or("--config requires a value")?);
            }
            "--write" => write_changes = true,
            "--dry-run" => dry_run = true,
            "--interactive" => interactive = true,
            "--no-config" => use_config = false,
            other => return Err(format!("unknown fix option `{other}`")),
        }
        i += 1;
    }

    if write_changes && dry_run {
        return Err("use either --write or --dry-run, not both".to_string());
    }
    if interactive && write_changes {
        return Err("use either --interactive or --write, not both".to_string());
    }
    if interactive && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err("interactive mode requires a terminal (use --write or --dry-run)".to_string());
    }

    let config = if use_config {
        AppConfig::load_if_exists(&config_path)?
    } else {
        AppConfig::default()
    };

    let rules_dir = rules_dir_override.unwrap_or_else(|| config.rules_dir.clone());

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;
    let analyzer = Analyzer::new(ruleset);
    let mut result = analyzer.analyze_path(&target, &AnalysisOptions::default())?;

    if target_spec.line.is_some() {
        result.findings = result
            .findings
            .into_iter()
            .filter(|finding| fix_location_matches(finding, &target_spec))
            .collect::<Vec<_>>();
        result.summary = recompute_summary(&result);
    }

    if result.findings.is_empty() {
        if let Some(line) = target_spec.line {
            if let Some(column) = target_spec.column {
                println!(
                    "No findings detected at {}:{}:{}.",
                    target.display(),
                    line,
                    column
                );
            } else {
                println!("No findings detected at {}:{}.", target.display(), line);
            }
        } else {
            println!("No findings detected. Nothing to remediate.");
        }
        return Ok(());
    }

    if interactive {
        run_fix_interactive(&target, &result, dry_run)?;
    } else if write_changes || dry_run {
        apply_autofixes(&target, &result, write_changes, dry_run)?;
    } else {
        print_suggested_remediations(&result);
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixTargetSpec {
    scan_path: PathBuf,
    line: Option<usize>,
    column: Option<usize>,
}

fn parse_fix_target_spec(raw: &str) -> Result<FixTargetSpec, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("fix requires a target path".to_string());
    }

    let segments = raw.split(':').collect::<Vec<_>>();
    if segments.len() >= 3 {
        let maybe_column = segments[segments.len() - 1].parse::<usize>();
        let maybe_line = segments[segments.len() - 2].parse::<usize>();
        if let (Ok(line), Ok(column)) = (maybe_line, maybe_column) {
            if line == 0 || column == 0 {
                return Err("fix location must be 1-based (line/column > 0)".to_string());
            }
            let path = segments[..segments.len() - 2].join(":");
            if path.is_empty() {
                return Err("fix requires a target path".to_string());
            }
            return Ok(FixTargetSpec {
                scan_path: PathBuf::from(path),
                line: Some(line),
                column: Some(column),
            });
        }
    }

    if segments.len() >= 2 {
        if let Ok(line) = segments[segments.len() - 1].parse::<usize>() {
            if line == 0 {
                return Err("fix location line must be 1-based (> 0)".to_string());
            }
            let path = segments[..segments.len() - 1].join(":");
            if path.is_empty() {
                return Err("fix requires a target path".to_string());
            }
            return Ok(FixTargetSpec {
                scan_path: PathBuf::from(path),
                line: Some(line),
                column: None,
            });
        }
    }

    Ok(FixTargetSpec {
        scan_path: PathBuf::from(raw),
        line: None,
        column: None,
    })
}

fn fix_location_matches(finding: &Finding, target: &FixTargetSpec) -> bool {
    let Some(line) = target.line else {
        return true;
    };
    if finding.line != line {
        return false;
    }

    match target.column {
        Some(column) => finding.column == column,
        None => true,
    }
}

#[derive(Clone)]
struct InteractiveAutofixCandidate {
    file_path: PathBuf,
    file_display: String,
    rule_id: String,
    title: String,
    severity: Severity,
    line: usize,
    column: usize,
    fix_suggestion: Option<String>,
    proposed_replacements: usize,
}

fn run_fix_interactive(target: &Path, result: &ScanResult, dry_run: bool) -> Result<(), String> {
    let raw_candidates = collect_interactive_candidates(target, result);
    let mut file_contents = BTreeMap::<PathBuf, String>::new();
    let mut candidates = Vec::new();

    for mut candidate in raw_candidates {
        if !file_contents.contains_key(&candidate.file_path) {
            let content = match fs::read_to_string(&candidate.file_path) {
                Ok(content) => content,
                Err(err) => {
                    eprintln!(
                        "warning: skipping {}: failed to read: {}",
                        candidate.file_path.display(),
                        err
                    );
                    continue;
                }
            };
            file_contents.insert(candidate.file_path.clone(), content);
        }

        let Some(content) = file_contents.get(&candidate.file_path) else {
            continue;
        };
        let replacements = autofix_replacements(&candidate.rule_id);
        candidate.proposed_replacements = count_replacements(content, &replacements);
        if candidate.proposed_replacements > 0 {
            candidates.push(candidate);
        }
    }

    if candidates.is_empty() {
        println!("No safe autofixes are available for these findings.");
        print_suggested_remediations(result);
        return Ok(());
    }

    let selection = run_fix_tui(&candidates, &file_contents, dry_run)?;
    let Some(selected_indices) = selection else {
        println!("No autofix changes selected.");
        return Ok(());
    };

    let mut changed_files = std::collections::BTreeSet::<PathBuf>::new();
    let mut total_replacements = 0usize;

    for idx in selected_indices {
        let Some(candidate) = candidates.get(idx) else {
            continue;
        };
        let Some(content) = file_contents.get_mut(&candidate.file_path) else {
            continue;
        };
        let replacements = autofix_replacements(&candidate.rule_id);
        let applied = apply_replacements(content, &replacements);
        if applied > 0 {
            changed_files.insert(candidate.file_path.clone());
            total_replacements += applied;
        }
    }

    if total_replacements == 0 {
        println!("No autofix changes selected.");
        return Ok(());
    }

    if dry_run {
        println!(
            "Interactive dry-run: {} file(s) would change with {} replacement(s).",
            changed_files.len(),
            total_replacements
        );
        return Ok(());
    }

    for path in &changed_files {
        let Some(content) = file_contents.get(path) else {
            continue;
        };
        fs::write(path, content)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }

    println!(
        "Interactive autofix applied: {} file(s) changed with {} replacement(s).",
        changed_files.len(),
        total_replacements
    );
    Ok(())
}

fn collect_interactive_candidates(
    target: &Path,
    result: &ScanResult,
) -> Vec<InteractiveAutofixCandidate> {
    let mut keyed = BTreeMap::<(String, String), InteractiveAutofixCandidate>::new();
    for finding in &result.findings {
        if autofix_replacements(&finding.id).is_empty() {
            continue;
        }

        let file_path = resolve_finding_path(target, &finding.file);
        let key = (file_path.display().to_string(), finding.id.clone());
        keyed
            .entry(key)
            .or_insert_with(|| InteractiveAutofixCandidate {
                file_path,
                file_display: finding.file.clone(),
                rule_id: finding.id.clone(),
                title: finding.title.clone(),
                severity: finding.severity,
                line: finding.line,
                column: finding.column,
                fix_suggestion: finding.fix_suggestion.clone(),
                proposed_replacements: 0,
            });
    }

    keyed.into_values().collect::<Vec<_>>()
}

fn run_fix_tui(
    candidates: &[InteractiveAutofixCandidate],
    file_contents: &BTreeMap<PathBuf, String>,
    dry_run: bool,
) -> Result<Option<Vec<usize>>, String> {
    enable_raw_mode().map_err(|err| format!("failed to enable raw mode: {err}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|err| format!("failed to enter alternate screen: {err}"))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|err| format!("failed to initialize terminal UI: {err}"))?;
    let ui_result = run_fix_tui_loop(&mut terminal, candidates, file_contents, dry_run);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    ui_result
}

fn run_fix_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    candidates: &[InteractiveAutofixCandidate],
    file_contents: &BTreeMap<PathBuf, String>,
    dry_run: bool,
) -> Result<Option<Vec<usize>>, String> {
    let mut cursor = 0usize;
    let mut search_query = String::new();
    let mut search_mode = false;
    let mut selected = vec![false; candidates.len()];
    let mut list_state = ListState::default();

    loop {
        let visible_indices = filtered_candidate_indices(candidates, &search_query);
        if visible_indices.is_empty() {
            cursor = 0;
            list_state.select(None);
        } else {
            if cursor >= visible_indices.len() {
                cursor = visible_indices.len().saturating_sub(1);
            }
            list_state.select(Some(cursor));
        }

        let active_index = visible_indices.get(cursor).copied();

        terminal
            .draw(|frame| {
                let chunks = Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(12),
                    Constraint::Length(4),
                ])
                .split(frame.area());

                let title = if dry_run {
                    "AIShield Fix TUI (Dry Run)"
                } else {
                    "AIShield Fix TUI"
                };
                let header = Paragraph::new(vec![
                    Line::from(Span::styled(
                        title,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Line::from(format!(
                        "Candidates: {} | Filtered: {} | Selected: {}",
                        candidates.len(),
                        visible_indices.len(),
                        selected.iter().filter(|v| **v).count()
                    )),
                ])
                .block(Block::default().borders(Borders::ALL).title("Summary"));
                frame.render_widget(header, chunks[0]);

                let search = Paragraph::new(vec![Line::from(format!(
                    "Search: {}{}",
                    search_query,
                    if search_mode { "█" } else { "" }
                ))])
                .block(Block::default().borders(Borders::ALL).title("Filter (/ to edit, esc to exit)"));
                frame.render_widget(search, chunks[1]);

                let body = Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)])
                    .split(chunks[2]);
                let right = Layout::vertical([Constraint::Length(7), Constraint::Min(5)]).split(body[1]);

                let items = visible_indices
                    .iter()
                    .map(|idx| {
                        let candidate = &candidates[*idx];
                        let mark = if selected[*idx] { 'x' } else { ' ' };
                        let sev_badge = severity_badge(candidate.severity);
                        let sev_style = Style::default().fg(severity_color(candidate.severity));
                        ListItem::new(Line::from(vec![
                            Span::raw(format!("[{}] ", mark)),
                            Span::styled(
                                format!("[{}] ", sev_badge),
                                sev_style.add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                format!("[{}] ", candidate.rule_id),
                                Style::default().fg(Color::Yellow),
                            ),
                            Span::raw(format!(
                                "{}:{}:{} (+{})",
                                candidate.file_display,
                                candidate.line,
                                candidate.column,
                                candidate.proposed_replacements
                            )),
                        ]))
                    })
                    .collect::<Vec<_>>();

                let list = List::new(items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Autofix Candidates"),
                    )
                    .highlight_style(
                        Style::default()
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("> ");
                frame.render_stateful_widget(list, body[0], &mut list_state);

                let details = active_index.map(|idx| &candidates[idx]).map(|candidate| {
                    let suggestion = candidate
                        .fix_suggestion
                        .as_deref()
                        .unwrap_or("Review this path and apply secure defaults.");
                    vec![
                        Line::from(Span::styled(
                            &candidate.title,
                            Style::default().add_modifier(Modifier::BOLD),
                        )),
                        Line::from(format!(
                            "Location: {}:{}:{}",
                            candidate.file_display, candidate.line, candidate.column
                        )),
                        Line::from(format!(
                            "Rule: {} [{}] | Proposed replacements: {}",
                            candidate.rule_id,
                            candidate.severity.as_str(),
                            candidate.proposed_replacements
                        )),
                        Line::from(""),
                        Line::from(format!("Fix: {suggestion}")),
                    ]
                });
                let detail_text =
                    details.unwrap_or_else(|| vec![Line::from("No candidate selected.")]);
                let detail = Paragraph::new(detail_text)
                    .wrap(Wrap { trim: true })
                    .block(Block::default().borders(Borders::ALL).title("Details"));
                frame.render_widget(detail, right[0]);

                let preview = if let Some(idx) = active_index {
                    build_preview_diff(&candidates[idx], file_contents)
                } else {
                    "No candidate selected.".to_string()
                };
                let preview_widget = Paragraph::new(preview)
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL).title("Preview Diff"));
                frame.render_widget(preview_widget, right[1]);

                let footer = Paragraph::new(vec![
                    Line::from(
                        "Keys: ↑/↓ move  space toggle  a select-all  c clear  / search  enter apply  q cancel",
                    ),
                    Line::from(
                        "Search mode: type to filter, backspace delete, enter/esc leave search",
                    ),
                ])
                .block(Block::default().borders(Borders::ALL).title("Controls"));
                frame.render_widget(footer, chunks[3]);
            })
            .map_err(|err| format!("failed to draw fix UI: {err}"))?;

        if !event::poll(Duration::from_millis(200))
            .map_err(|err| format!("failed reading keyboard events: {err}"))?
        {
            continue;
        }

        let Event::Key(key) =
            event::read().map_err(|err| format!("failed to read keyboard event: {err}"))?
        else {
            continue;
        };

        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }

        if search_mode {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    search_mode = false;
                }
                KeyCode::Backspace => {
                    search_query.pop();
                }
                KeyCode::Char(ch) => {
                    if !ch.is_control() {
                        search_query.push(ch);
                        cursor = 0;
                    }
                }
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                cursor = cursor.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = visible_indices.len();
                if cursor + 1 < max {
                    cursor += 1;
                }
            }
            KeyCode::Char('g') => {
                cursor = 0;
            }
            KeyCode::Char('G') => {
                cursor = visible_indices.len().saturating_sub(1);
            }
            KeyCode::Char(' ') => {
                if let Some(active) = active_index.and_then(|idx| selected.get_mut(idx)) {
                    *active = !*active;
                }
            }
            KeyCode::Char('a') => {
                for idx in &visible_indices {
                    if let Some(slot) = selected.get_mut(*idx) {
                        *slot = true;
                    }
                }
            }
            KeyCode::Char('c') => {
                for idx in &visible_indices {
                    if let Some(slot) = selected.get_mut(*idx) {
                        *slot = false;
                    }
                }
            }
            KeyCode::Char('/') => {
                search_mode = true;
            }
            KeyCode::Enter => {
                return Ok(Some(resolve_selected_indices(&selected, active_index)));
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                return Ok(None);
            }
            _ => {}
        }
    }
}

fn filtered_candidate_indices(
    candidates: &[InteractiveAutofixCandidate],
    query: &str,
) -> Vec<usize> {
    let terms = query
        .split_whitespace()
        .map(|part| part.to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if terms.is_empty() {
        return (0..candidates.len()).collect::<Vec<_>>();
    }

    candidates
        .iter()
        .enumerate()
        .filter_map(|(idx, candidate)| {
            let haystack = format!(
                "{} {} {} {}:{}:{} {}",
                candidate.rule_id,
                candidate.title,
                candidate.file_display,
                candidate.file_path.display(),
                candidate.line,
                candidate.column,
                candidate.severity.as_str()
            )
            .to_ascii_lowercase();
            let matched = terms.iter().all(|term| haystack.contains(term));
            if matched {
                Some(idx)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

fn build_preview_diff(
    candidate: &InteractiveAutofixCandidate,
    file_contents: &BTreeMap<PathBuf, String>,
) -> String {
    let Some(content) = file_contents.get(&candidate.file_path) else {
        return "No preview available for this file.".to_string();
    };

    let replacements = autofix_replacements(&candidate.rule_id);
    if replacements.is_empty() {
        return "No autofix replacement template found for this rule.".to_string();
    }

    let mut out = String::new();
    let mut shown = 0usize;

    'outer: for (from, to) in replacements {
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains(from) {
                let replaced = line.replace(from, to);
                let _ = writeln!(out, "@@ line {} @@", line_idx + 1);
                let _ = writeln!(out, "- {}", truncate(line.trim(), 110));
                let _ = writeln!(out, "+ {}", truncate(replaced.trim(), 110));
                out.push('\n');
                shown += 1;
                if shown >= 4 {
                    break 'outer;
                }
            }
        }
    }

    if shown == 0 {
        out.push_str("No line-level preview available for current file content.");
    }
    out
}

fn severity_badge(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::Gray,
    }
}

fn resolve_selected_indices(selected: &[bool], fallback: Option<usize>) -> Vec<usize> {
    let mut indices = selected
        .iter()
        .enumerate()
        .filter_map(|(idx, is_selected)| if *is_selected { Some(idx) } else { None })
        .collect::<Vec<_>>();
    if indices.is_empty() {
        if let Some(idx) = fallback {
            indices.push(idx);
        }
    }
    indices
}

fn count_replacements(content: &str, replacements: &[(&str, &str)]) -> usize {
    replacements
        .iter()
        .map(|(from, _)| content.match_indices(from).count())
        .sum()
}

fn apply_replacements(content: &mut String, replacements: &[(&str, &str)]) -> usize {
    let mut count = 0usize;
    for (from, to) in replacements {
        let matches = content.match_indices(from).count();
        if matches == 0 {
            continue;
        }
        *content = content.replace(from, to);
        count += matches;
    }
    count
}

fn print_suggested_remediations(result: &ScanResult) {
    println!("Suggested remediations:");
    for finding in &result.findings {
        println!(
            "- [{}] {}:{}:{}",
            finding.id, finding.file, finding.line, finding.column
        );
        if let Some(suggestion) = &finding.fix_suggestion {
            println!("  Fix: {suggestion}");
        } else {
            println!("  Fix: Review this code path and apply secure defaults.");
        }
        if let Some(ai_tendency) = &finding.ai_tendency {
            println!("  Why AI gets this wrong: {ai_tendency}");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitTemplate {
    Config,
    GithubActions,
    GitlabCi,
    BitbucketPipelines,
    CircleCi,
    Jenkins,
    VsCode,
    PreCommit,
}

impl InitTemplate {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "config" => Ok(Self::Config),
            "github-actions" | "github" => Ok(Self::GithubActions),
            "gitlab-ci" | "gitlab" => Ok(Self::GitlabCi),
            "bitbucket-pipelines" | "bitbucket" => Ok(Self::BitbucketPipelines),
            "circleci" | "circle-ci" => Ok(Self::CircleCi),
            "jenkins" | "jenkinsfile" => Ok(Self::Jenkins),
            "vscode" => Ok(Self::VsCode),
            "pre-commit" | "precommit" => Ok(Self::PreCommit),
            _ => Err(format!(
                "unknown init template `{raw}` (supported: config, github-actions, gitlab-ci, bitbucket-pipelines, circleci, jenkins, vscode, pre-commit, all)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::GithubActions => "github-actions",
            Self::GitlabCi => "gitlab-ci",
            Self::BitbucketPipelines => "bitbucket-pipelines",
            Self::CircleCi => "circleci",
            Self::Jenkins => "jenkins",
            Self::VsCode => "vscode",
            Self::PreCommit => "pre-commit",
        }
    }
}

fn parse_init_templates(raw: &str) -> Result<Vec<InitTemplate>, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("--templates requires at least one template".to_string());
    }

    if normalized == "all" {
        return Ok(vec![
            InitTemplate::Config,
            InitTemplate::GithubActions,
            InitTemplate::GitlabCi,
            InitTemplate::BitbucketPipelines,
            InitTemplate::CircleCi,
            InitTemplate::Jenkins,
            InitTemplate::VsCode,
            InitTemplate::PreCommit,
        ]);
    }

    let entries = parse_list_like(raw);
    if entries.is_empty() {
        return Err("--templates requires at least one template".to_string());
    }

    let mut templates = Vec::new();
    for entry in entries {
        if entry == "all" {
            return Ok(vec![
                InitTemplate::Config,
                InitTemplate::GithubActions,
                InitTemplate::GitlabCi,
                InitTemplate::BitbucketPipelines,
                InitTemplate::CircleCi,
                InitTemplate::Jenkins,
                InitTemplate::VsCode,
                InitTemplate::PreCommit,
            ]);
        }
        let template = InitTemplate::parse(&entry)?;
        if !templates.contains(&template) {
            templates.push(template);
        }
    }
    Ok(templates)
}

fn init_template_writes(
    templates: &[InitTemplate],
    config_output: &Path,
) -> Vec<(PathBuf, String)> {
    let mut writes = Vec::<(PathBuf, String)>::new();
    for template in templates {
        match template {
            InitTemplate::Config => {
                writes.push((config_output.to_path_buf(), init_config_template()))
            }
            InitTemplate::GithubActions => writes.push((
                PathBuf::from(".github/workflows/aishield.yml"),
                init_github_actions_template(),
            )),
            InitTemplate::GitlabCi => {
                writes.push((PathBuf::from(".gitlab-ci.yml"), init_gitlab_ci_template()))
            }
            InitTemplate::BitbucketPipelines => writes.push((
                PathBuf::from("bitbucket-pipelines.yml"),
                init_bitbucket_pipelines_template(),
            )),
            InitTemplate::CircleCi => writes.push((
                PathBuf::from(".circleci/config.yml"),
                init_circleci_template(),
            )),
            InitTemplate::Jenkins => {
                writes.push((PathBuf::from("Jenkinsfile"), init_jenkinsfile_template()))
            }
            InitTemplate::VsCode => {
                writes.push((
                    PathBuf::from(".vscode/extensions.json"),
                    init_vscode_extensions_template(),
                ));
                writes.push((
                    PathBuf::from(".vscode/tasks.json"),
                    init_vscode_tasks_template(),
                ));
            }
            InitTemplate::PreCommit => writes.push((
                PathBuf::from(".pre-commit-config.yaml"),
                init_precommit_template(),
            )),
        }
    }
    writes
}

fn init_config_template() -> String {
    "version: 1\nrules_dir: rules\nformat: table\ndedup_mode: normalized\nbridge_engines: []\nrules: []\nexclude_paths: []\nai_only: false\ncross_file: false\nai_model: heuristic\nonnx_model_path: \"\"\nonnx_manifest_path: \"\"\nai_calibration: balanced\nmin_ai_confidence: 0.70\nseverity_threshold: medium\nfail_on_findings: false\nhistory_file: .aishield-history.log\nrecord_history: true\nnotify_webhook_url: \"\"\nnotify_min_severity: high\n".to_string()
}

fn init_github_actions_template() -> String {
    r#"name: AIShield Security Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: aishield-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  AISHIELD_ENABLE_SAST_BRIDGE: ${{ vars.AISHIELD_ENABLE_SAST_BRIDGE || 'true' }}
  AISHIELD_BRIDGE_ENGINES: ${{ vars.AISHIELD_BRIDGE_ENGINES || 'all' }}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Set bridge args
        run: |
          if [ "${AISHIELD_ENABLE_SAST_BRIDGE}" = "true" ]; then
            echo "AISHIELD_BRIDGE_ARGS=--bridge ${AISHIELD_BRIDGE_ENGINES}" >> "$GITHUB_ENV"
          else
            echo "AISHIELD_BRIDGE_ARGS=" >> "$GITHUB_ENV"
          fi

      - name: Set up Python
        if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Install Semgrep and Bandit
        if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        run: |
          python -m pip install --upgrade pip
          pip install semgrep bandit

      - name: Set up Node.js
        if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install ESLint
        if: env.AISHIELD_ENABLE_SAST_BRIDGE == 'true'
        run: npm install -g eslint

      - name: Build and scan
        run: cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif ${AISHIELD_BRIDGE_ARGS}

      - name: PR annotations
        if: github.event_name == 'pull_request'
        run: |
          BASE_SHA="${{ github.event.pull_request.base.sha }}"
          if [ -z "${BASE_SHA}" ]; then
            BASE_SHA="origin/main"
          fi
          cargo run -p aishield-cli -- scan . --format github --dedup normalized --changed-from "${BASE_SHA}" ${AISHIELD_BRIDGE_ARGS}

      - name: Upload SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aishield-sarif
          path: aishield.sarif
          if-no-files-found: error
          retention-days: 7

  upload-sarif:
    if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    steps:
      - name: Download SARIF artifact
        uses: actions/download-artifact@v4
        with:
          name: aishield-sarif
          path: .

      - name: Upload SARIF to code scanning
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: aishield.sarif
          category: aishield
"#
    .to_string()
}

fn init_gitlab_ci_template() -> String {
    r#"stages:
  - scan

variables:
  CARGO_TERM_COLOR: always
  AISHIELD_ENABLE_BRIDGE: "false"
  AISHIELD_BRIDGE_ENGINES: "all"
  AISHIELD_FAIL_ON_FINDINGS: "true"
  AISHIELD_SEVERITY: "high"

.aishield-cache: &aishield-cache
  cache:
    key: aishield-${CI_COMMIT_REF_SLUG}
    paths:
      - target/

scan:aishield:
  stage: scan
  image: rust:1.84
  <<: *aishield-cache
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  before_script:
    - apt-get update -qq && apt-get install -y -qq python3 python3-pip nodejs npm > /dev/null
    - |
      if [ "${AISHIELD_ENABLE_BRIDGE}" = "true" ]; then
        python3 -m pip install --upgrade pip -q
        pip3 install semgrep bandit -q
        npm install -g eslint --silent
        export BRIDGE_ARGS="--bridge ${AISHIELD_BRIDGE_ENGINES}"
      else
        export BRIDGE_ARGS=""
      fi
  script:
    - cargo build --workspace -q
    # Full SARIF scan
    - >-
      cargo run -q -p aishield-cli -- scan .
      --format sarif --dedup normalized
      --severity "${AISHIELD_SEVERITY}"
      --output aishield.sarif
      ${BRIDGE_ARGS}
    # MR diff-only scan with fail gate
    - |
      if [ -n "${CI_MERGE_REQUEST_DIFF_BASE_SHA}" ]; then
        FAIL_FLAG=""
        if [ "${AISHIELD_FAIL_ON_FINDINGS}" = "true" ]; then
          FAIL_FLAG="--fail-on-findings"
        fi
        cargo run -q -p aishield-cli -- scan . \
          --format table --dedup normalized \
          --severity "${AISHIELD_SEVERITY}" \
          --changed-from "${CI_MERGE_REQUEST_DIFF_BASE_SHA}" \
          ${FAIL_FLAG} ${BRIDGE_ARGS}
      fi
  artifacts:
    when: always
    paths:
      - aishield.sarif
    reports:
      sast: aishield.sarif
    expire_in: 1 week
"#
    .to_string()
}

fn init_bitbucket_pipelines_template() -> String {
    r#"image: rust:1.84

definitions:
  caches:
    cargo: target/
  steps:
    - step: &install-bridge
        name: Install bridge tools
        script:
          - apt-get update -qq && apt-get install -y -qq python3 python3-pip nodejs npm > /dev/null
          - python3 -m pip install --upgrade pip -q
          - pip3 install semgrep bandit -q
          - npm install -g eslint --silent

pipelines:
  pull-requests:
    '**':
      - step:
          name: AIShield PR scan
          caches:
            - cargo
          script:
            - apt-get update -qq && apt-get install -y -qq python3 python3-pip nodejs npm > /dev/null
            - cargo build --workspace -q
            # Diff-only scan against PR target branch
            - >-
              cargo run -q -p aishield-cli -- scan .
              --format table --dedup normalized
              --severity high --fail-on-findings
              --changed-from "origin/${BITBUCKET_PR_DESTINATION_BRANCH}"
            # Full SARIF for artifact
            - >-
              cargo run -q -p aishield-cli -- scan .
              --format sarif --dedup normalized
              --output aishield.sarif
          artifacts:
            - aishield.sarif
  branches:
    main:
      - step:
          name: AIShield full scan
          caches:
            - cargo
          script:
            - apt-get update -qq && apt-get install -y -qq python3 python3-pip nodejs npm > /dev/null
            - cargo build --workspace -q
            - >-
              cargo run -q -p aishield-cli -- scan .
              --format sarif --dedup normalized
              --severity high
              --output aishield.sarif
          artifacts:
            - aishield.sarif

  # Manual bridge-enabled pipeline (set AISHIELD_ENABLE_BRIDGE=true in repo vars)
  custom:
    bridge-scan:
      - step:
          <<: *install-bridge
      - step:
          name: AIShield bridge scan
          caches:
            - cargo
          script:
            - cargo build --workspace -q
            - >-
              cargo run -q -p aishield-cli -- scan .
              --format sarif --dedup normalized
              --severity high --bridge all
              --output aishield.sarif
          artifacts:
            - aishield.sarif
"#
    .to_string()
}

fn init_circleci_template() -> String {
    r#"version: 2.1

jobs:
  scan:
    docker:
      - image: cimg/rust:1.84
    steps:
      - checkout
      - run:
          name: Install bridge dependencies
          command: |
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip nodejs npm
      - run:
          name: Build workspace
          command: cargo build --workspace
      - run:
          name: AIShield scan (SARIF)
          command: cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
      - store_artifacts:
          path: aishield.sarif

workflows:
  security:
    jobs:
      - scan
"#
    .to_string()
}

fn init_jenkinsfile_template() -> String {
    r#"pipeline {
  agent any

  stages {
    stage('Setup') {
      steps {
        sh 'rustc --version || true'
        sh 'cargo --version'
      }
    }

    stage('Scan') {
      steps {
        sh 'cargo build --workspace'
        sh 'cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif'
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'aishield.sarif', allowEmptyArchive: true
    }
  }
}
"#
    .to_string()
}

fn init_vscode_extensions_template() -> String {
    r#"{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "tamasfe.even-better-toml",
    "redhat.vscode-yaml",
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode"
  ]
}
"#
    .to_string()
}

fn init_vscode_tasks_template() -> String {
    r#"{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "AIShield: test",
      "type": "shell",
      "command": "cargo test",
      "group": "test",
      "problemMatcher": []
    },
    {
      "label": "AIShield: scan workspace",
      "type": "shell",
      "command": "cargo run -p aishield-cli -- scan .",
      "group": "build",
      "problemMatcher": []
    },
    {
      "label": "AIShield: build docs",
      "type": "shell",
      "command": "npm run docs:build",
      "group": "build",
      "problemMatcher": []
    },
    {
      "label": "AIShield: docs dev server",
      "type": "shell",
      "command": "npm run docs:dev",
      "problemMatcher": []
    }
  ]
}
"#
    .to_string()
}

fn init_precommit_template() -> String {
    r#"repos:
  - repo: local
    hooks:
      - id: aishield-scan
        name: aishield scan (staged, high+)
        entry: cargo run -p aishield-cli -- scan . --staged --severity high --fail-on-findings
        language: system
        pass_filenames: false
"#
    .to_string()
}

fn run_init(args: &[String]) -> Result<(), String> {
    let mut output = PathBuf::from(".aishield.yml");
    let mut templates = vec![InitTemplate::Config];
    let mut force = false;
    let mut wizard = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wizard" => wizard = true,
            "--output" => {
                i += 1;
                output = PathBuf::from(args.get(i).ok_or("--output requires a value")?);
            }
            "--templates" => {
                i += 1;
                templates =
                    parse_init_templates(args.get(i).ok_or("--templates requires a value")?)?;
            }
            "--force" => force = true,
            other => return Err(format!("unknown init option `{other}`")),
        }
        i += 1;
    }

    if wizard {
        return run_init_wizard();
    }

    if output != PathBuf::from(".aishield.yml") && !templates.contains(&InitTemplate::Config) {
        return Err("--output requires templates to include `config`".to_string());
    }

    let writes = init_template_writes(&templates, &output);
    for (path, _) in &writes {
        if path.exists() && !force {
            return Err(format!(
                "{} already exists (use --force to overwrite)",
                path.display()
            ));
        }
    }

    for (path, content) in writes {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!("failed to create directory {}: {err}", parent.display())
                })?;
            }
        }
        let existed = path.exists();
        let mut file = File::create(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        println!(
            "{} {}",
            if existed { "Updated" } else { "Created" },
            path.display()
        );
    }

    if !templates.is_empty() {
        println!(
            "Initialized templates: {}",
            templates
                .iter()
                .map(|template| template.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn run_init_wizard() -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err(
            "interactive wizard requires a terminal (stdin is not a TTY)".to_string(),
        );
    }

    println!();
    println!("=== AIShield Configuration Wizard ===");
    println!();

    // ---------------------------------------------------------------
    // Step 1: Detect project languages/frameworks by checking markers
    // ---------------------------------------------------------------
    println!("Detecting project structure...");

    let marker_to_language: &[(&str, &str)] = &[
        ("package.json", "JavaScript/TypeScript"),
        ("Cargo.toml", "Rust"),
        ("go.mod", "Go"),
        ("requirements.txt", "Python"),
        ("pyproject.toml", "Python"),
        ("Dockerfile", "Docker"),
    ];

    // Glob-based markers (need a directory walk)
    let glob_marker_to_language: &[(&str, &str)] = &[
        ("*.tf", "Terraform/IaC"),
        ("*.java", "Java"),
        ("*.cs", "C#/.NET"),
        ("*.rb", "Ruby"),
        ("*.php", "PHP"),
        ("*.kt", "Kotlin"),
        ("*.swift", "Swift"),
    ];

    let mut detected: Vec<String> = Vec::new();

    // Check file-based markers in the current directory
    for (marker, lang) in marker_to_language {
        if Path::new(marker).exists() && !detected.contains(&lang.to_string()) {
            detected.push(lang.to_string());
        }
    }

    // Check glob-based markers with a shallow walk (max depth 3 to stay fast)
    for (pattern, lang) in glob_marker_to_language {
        if detected.contains(&lang.to_string()) {
            continue;
        }
        let ext = pattern.trim_start_matches("*.");
        let found = walkdir::WalkDir::new(".")
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|e| e == ext)
                    .unwrap_or(false)
            });
        if found {
            detected.push(lang.to_string());
        }
    }

    if detected.is_empty() {
        println!("  No known project markers found.");
    } else {
        println!("  Detected: {}", detected.join(", "));
    }
    println!();

    // Full list of selectable languages
    let all_languages = &[
        "JavaScript/TypeScript",
        "Rust",
        "Go",
        "Python",
        "Java",
        "C#/.NET",
        "Ruby",
        "PHP",
        "Kotlin",
        "Swift",
        "Terraform/IaC",
        "Docker",
    ];

    // Pre-select detected languages
    let defaults: Vec<bool> = all_languages
        .iter()
        .map(|lang| detected.contains(&lang.to_string()))
        .collect();

    let lang_selections = MultiSelect::new()
        .with_prompt("Select languages/frameworks to scan (Space to toggle, Enter to confirm)")
        .items(all_languages)
        .defaults(&defaults)
        .interact()
        .map_err(|e| format!("language selection failed: {e}"))?;

    let selected_languages: Vec<&str> = lang_selections
        .iter()
        .map(|&idx| all_languages[idx])
        .collect();

    if selected_languages.is_empty() {
        println!("  No languages selected; config will use default rules.");
    } else {
        println!("  Selected: {}", selected_languages.join(", "));
    }
    println!();

    // ---------------------------------------------------------------
    // Step 2: CI platform
    // ---------------------------------------------------------------
    let ci_options = &[
        "GitHub Actions",
        "GitLab CI",
        "Bitbucket Pipelines",
        "None",
    ];

    let ci_idx = Select::new()
        .with_prompt("Select CI platform")
        .items(ci_options)
        .default(0)
        .interact()
        .map_err(|e| format!("CI selection failed: {e}"))?;

    let ci_platform = ci_options[ci_idx];
    println!();

    // ---------------------------------------------------------------
    // Step 3: Severity threshold
    // ---------------------------------------------------------------
    let severity_options = &[
        "Critical only",
        "Critical + High",
        "Critical + High + Medium",
        "All (including Low and Info)",
    ];
    let severity_thresholds = &["critical", "high", "medium", "info"];

    let sev_idx = Select::new()
        .with_prompt("Minimum severity threshold for findings")
        .items(severity_options)
        .default(2) // default to Critical+High+Medium
        .interact()
        .map_err(|e| format!("severity selection failed: {e}"))?;

    let severity_threshold = severity_thresholds[sev_idx];
    println!();

    // ---------------------------------------------------------------
    // Step 4: Output format
    // ---------------------------------------------------------------
    let format_options = &["table", "json", "sarif"];

    let fmt_idx = Select::new()
        .with_prompt("Default output format")
        .items(format_options)
        .default(0)
        .interact()
        .map_err(|e| format!("format selection failed: {e}"))?;

    let output_format = format_options[fmt_idx];
    println!();

    // ---------------------------------------------------------------
    // Step 5: Scan profile
    // ---------------------------------------------------------------
    let profile_options = &[
        "strict  -- flag everything, zero false-negative tolerance",
        "pragmatic -- balanced noise vs. coverage (recommended)",
        "ai-focus -- only AI-generated code patterns",
        "none    -- no profile, use raw rule defaults",
    ];
    let profile_values = &["strict", "pragmatic", "ai-focus", ""];

    let prof_idx = Select::new()
        .with_prompt("Scan profile")
        .items(profile_options)
        .default(1) // default to pragmatic
        .interact()
        .map_err(|e| format!("profile selection failed: {e}"))?;

    let scan_profile = profile_values[prof_idx];
    println!();

    // ---------------------------------------------------------------
    // Step 6: Generate .aishield.toml
    // ---------------------------------------------------------------
    let config_path = PathBuf::from(".aishield.toml");

    if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()
            .map_err(|e| format!("confirmation failed: {e}"))?;

        if !overwrite {
            println!("Aborted -- existing config left unchanged.");
            return Ok(());
        }
    }

    // Map selected languages to rule language keys used by the scanner
    let rule_languages: Vec<&str> = selected_languages
        .iter()
        .filter_map(|lang| match *lang {
            "JavaScript/TypeScript" => Some("javascript"),
            "Rust" => Some("rust"),
            "Go" => Some("go"),
            "Python" => Some("python"),
            "Java" => Some("java"),
            "C#/.NET" => Some("csharp"),
            "Ruby" => Some("ruby"),
            "PHP" => Some("php"),
            "Kotlin" => Some("kotlin"),
            "Swift" => Some("swift"),
            "Terraform/IaC" => Some("terraform"),
            "Docker" => Some("docker"),
            _ => None,
        })
        .collect();

    let languages_toml = if rule_languages.is_empty() {
        "[]".to_string()
    } else {
        let quoted: Vec<String> = rule_languages
            .iter()
            .map(|l| format!("\"{}\"", l))
            .collect();
        format!("[{}]", quoted.join(", "))
    };

    let profile_line = if scan_profile.is_empty() {
        "# profile = \"\"  # no profile selected".to_string()
    } else {
        format!("profile = \"{}\"", scan_profile)
    };

    let ai_only = scan_profile == "ai-focus";

    let toml_content = format!(
        r#"# AIShield configuration -- generated by `aishield init --wizard`
# Documentation: https://github.com/antigravity/AIShield#configuration

[scan]
rules_dir = "rules"
languages = {languages}
format = "{format}"
severity_threshold = "{severity}"
{profile}
ai_only = {ai_only}
fail_on_findings = false
dedup_mode = "normalized"

[scan.ai]
model = "heuristic"
calibration = "balanced"
min_confidence = 0.70

[history]
enabled = true
file = ".aishield-history.log"

[notifications]
# webhook_url = ""
# min_severity = "high"
"#,
        languages = languages_toml,
        format = output_format,
        severity = severity_threshold,
        profile = profile_line,
        ai_only = ai_only,
    );

    let mut file = File::create(&config_path)
        .map_err(|err| format!("failed to create {}: {err}", config_path.display()))?;
    file.write_all(toml_content.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", config_path.display()))?;

    println!("Created {}", config_path.display());

    // ---------------------------------------------------------------
    // Step 7: Optionally generate CI template
    // ---------------------------------------------------------------
    if ci_platform != "None" {
        let generate_ci = Confirm::new()
            .with_prompt(format!("Generate {} CI template?", ci_platform))
            .default(true)
            .interact()
            .map_err(|e| format!("CI confirmation failed: {e}"))?;

        if generate_ci {
            let (ci_path, ci_content) = match ci_platform {
                "GitHub Actions" => (
                    PathBuf::from(".github/workflows/aishield.yml"),
                    init_github_actions_template(),
                ),
                "GitLab CI" => (
                    PathBuf::from(".gitlab-ci.yml"),
                    init_gitlab_ci_template(),
                ),
                "Bitbucket Pipelines" => (
                    PathBuf::from("bitbucket-pipelines.yml"),
                    init_bitbucket_pipelines_template(),
                ),
                _ => unreachable!(),
            };

            if let Some(parent) = ci_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|err| {
                        format!("failed to create directory {}: {err}", parent.display())
                    })?;
                }
            }

            let existed = ci_path.exists();
            if existed {
                let overwrite_ci = Confirm::new()
                    .with_prompt(format!(
                        "{} already exists. Overwrite?",
                        ci_path.display()
                    ))
                    .default(false)
                    .interact()
                    .map_err(|e| format!("CI overwrite confirmation failed: {e}"))?;

                if !overwrite_ci {
                    println!("Skipped CI template (existing file kept).");
                    println!();
                    println!("Setup complete. Run `aishield scan .` to start scanning.");
                    return Ok(());
                }
            }

            let mut ci_file = File::create(&ci_path)
                .map_err(|err| format!("failed to create {}: {err}", ci_path.display()))?;
            ci_file
                .write_all(ci_content.as_bytes())
                .map_err(|err| format!("failed to write {}: {err}", ci_path.display()))?;

            println!(
                "{} {}",
                if existed { "Updated" } else { "Created" },
                ci_path.display()
            );
        }
    }

    println!();
    println!("Setup complete. Run `aishield scan .` to start scanning.");
    Ok(())
}

fn run_create_rule(args: &[String]) -> Result<(), String> {
    let mut id = None::<String>;
    let mut title = None::<String>;
    let mut severity = "medium".to_string();
    let mut language = None::<String>;
    let mut category = None::<String>;
    let mut ai_tendency = None::<String>;
    let mut confidence = "0.75".to_string();
    let mut pattern_any = Vec::<String>::new();
    let mut pattern_all = Vec::<String>::new();
    let mut pattern_not = Vec::<String>::new();
    let mut tags = Vec::<String>::new();
    let mut suggestion = None::<String>;
    let mut out_dir = None::<PathBuf>;
    let mut force = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => {
                i += 1;
                id = Some(args.get(i).ok_or("--id requires a value")?.to_string());
            }
            "--title" => {
                i += 1;
                title = Some(args.get(i).ok_or("--title requires a value")?.to_string());
            }
            "--severity" => {
                i += 1;
                severity = parse_severity_value(args.get(i).ok_or("--severity requires a value")?)?
                    .to_string();
            }
            "--language" => {
                i += 1;
                language = Some(
                    args.get(i)
                        .ok_or("--language requires a value")?
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
            "--category" => {
                i += 1;
                category = Some(
                    args.get(i)
                        .ok_or("--category requires a value")?
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
            "--ai-tendency" => {
                i += 1;
                ai_tendency = Some(
                    args.get(i)
                        .ok_or("--ai-tendency requires a value")?
                        .to_string(),
                );
            }
            "--confidence" => {
                i += 1;
                let raw = args.get(i).ok_or("--confidence requires a value")?;
                let parsed = raw
                    .parse::<f32>()
                    .map_err(|_| "--confidence must be numeric (0.0-1.0)".to_string())?;
                if !(0.0..=1.0).contains(&parsed) {
                    return Err("--confidence must be between 0.0 and 1.0".to_string());
                }
                confidence = format!("{parsed:.2}");
            }
            "--pattern-any" => {
                i += 1;
                pattern_any.push(
                    args.get(i)
                        .ok_or("--pattern-any requires a value")?
                        .to_string(),
                );
            }
            "--pattern-all" => {
                i += 1;
                pattern_all.push(
                    args.get(i)
                        .ok_or("--pattern-all requires a value")?
                        .to_string(),
                );
            }
            "--pattern-not" => {
                i += 1;
                pattern_not.push(
                    args.get(i)
                        .ok_or("--pattern-not requires a value")?
                        .to_string(),
                );
            }
            "--tags" => {
                i += 1;
                tags.extend(parse_list_like(
                    args.get(i).ok_or("--tags requires a value")?,
                ));
            }
            "--suggestion" => {
                i += 1;
                suggestion = Some(
                    args.get(i)
                        .ok_or("--suggestion requires a value")?
                        .to_string(),
                );
            }
            "--out-dir" => {
                i += 1;
                out_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--out-dir requires a value")?,
                ));
            }
            "--force" => force = true,
            other => return Err(format!("unknown create-rule option `{other}`")),
        }
        i += 1;
    }

    let id = id.ok_or("--id is required")?;
    let title = title.ok_or("--title is required")?;
    let language = language.ok_or("--language is required")?;
    let category = category.ok_or("--category is required")?;

    if pattern_any.is_empty() && pattern_all.is_empty() {
        return Err("at least one of --pattern-any or --pattern-all is required".to_string());
    }

    let rule_dir = out_dir.unwrap_or_else(|| PathBuf::from(format!("rules/{language}/{category}")));
    fs::create_dir_all(&rule_dir)
        .map_err(|err| format!("failed to create {}: {err}", rule_dir.display()))?;

    let file_stem = slugify_rule_filename(&title);
    let file_path = rule_dir.join(format!("{file_stem}.yaml"));
    if file_path.exists() && !force {
        return Err(format!(
            "{} already exists (use --force to overwrite)",
            file_path.display()
        ));
    }

    let mut yaml = String::new();
    let _ = writeln!(yaml, "id: {}", id);
    let _ = writeln!(yaml, "title: {}", title);
    let _ = writeln!(yaml, "severity: {}", severity);
    let _ = writeln!(yaml, "confidence_that_ai_generated: {}", confidence);
    let _ = writeln!(yaml, "languages: [{}]", language);
    let _ = writeln!(yaml, "category: {}", category);
    if let Some(ai_tendency) = ai_tendency {
        let _ = writeln!(yaml, "ai_tendency: {}", ai_tendency);
    } else {
        let _ = writeln!(
            yaml,
            "ai_tendency: TODO describe why AI tends to generate this pattern."
        );
    }
    yaml.push_str("pattern:\n");
    if !pattern_any.is_empty() {
        yaml.push_str("  any:\n");
        for p in pattern_any {
            let _ = writeln!(yaml, "    - \"{}\"", escape_rule_yaml(&p));
        }
    }
    if !pattern_all.is_empty() {
        yaml.push_str("  all:\n");
        for p in pattern_all {
            let _ = writeln!(yaml, "    - \"{}\"", escape_rule_yaml(&p));
        }
    }
    if !pattern_not.is_empty() {
        yaml.push_str("  not:\n");
        for p in pattern_not {
            let _ = writeln!(yaml, "    - \"{}\"", escape_rule_yaml(&p));
        }
    }
    yaml.push_str("fix:\n");
    if let Some(suggestion) = suggestion {
        let _ = writeln!(yaml, "  suggestion: {}", suggestion);
    } else {
        yaml.push_str("  suggestion: TODO add secure remediation guidance.\n");
    }
    if tags.is_empty() {
        yaml.push_str("tags: [todo]\n");
    } else {
        let _ = writeln!(yaml, "tags: [{}]", tags.join(", "));
    }

    fs::write(&file_path, yaml)
        .map_err(|err| format!("failed to write {}: {err}", file_path.display()))?;

    println!("Created rule scaffold at {}", file_path.display());
    Ok(())
}

fn run_rules(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("rules requires a subcommand: install\nUsage: aishield rules install <url>".to_string());
    }

    match args[0].as_str() {
        "install" => run_rules_install(&args[1..]),
        other => Err(format!("unknown rules subcommand `{other}`")),
    }
}

fn run_rules_install(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("rules install requires a URL".to_string());
    }

    let url = &args[0];
    let mut dest_dir = PathBuf::from("rules/imported");
    let mut force = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dest" => {
                i += 1;
                dest_dir = PathBuf::from(args.get(i).ok_or("--dest requires a value")?);
            }
            "--force" => force = true,
            other => return Err(format!("unknown rules install option `{other}`")),
        }
        i += 1;
    }

    // Basic URL validation
    if !url.starts_with("http") {
        return Err("URL must start with http:// or https://".to_string());
    }

    // For now, only support downloading single YAML files or zip archives
    // If it ends in .yaml/.yml, treat as single file
    // If it ends in .zip, treat as archive
    let is_yaml = url.ends_with(".yaml") || url.ends_with(".yml");
    let is_zip = url.ends_with(".zip");

    if !is_yaml && !is_zip {
        return Err("URL must end in .yaml, .yml, or .zip".to_string());
    }

    fs::create_dir_all(&dest_dir)
        .map_err(|err| format!("failed to create destination {}: {err}", dest_dir.display()))?;

    println!("Downloading rules from {}...", url);
    let response = reqwest::blocking::get(url)
        .map_err(|err| format!("failed to download rules: {err}"))?;

    if !response.status().is_success() {
        return Err(format!("download failed with status {}", response.status()));
    }

    let content = response
        .bytes()
        .map_err(|err| format!("failed to read response body: {err}"))?;

    if is_yaml {
        let filename = url.split('/').last().unwrap_or("imported-rule.yaml");
        let dest_path = dest_dir.join(filename);
        if dest_path.exists() && !force {
            return Err(format!(
                "{} already exists (use --force to overwrite)",
                dest_path.display()
            ));
        }
        fs::write(&dest_path, content)
            .map_err(|err| format!("failed to write {}: {err}", dest_path.display()))?;
        println!("✓ Installed rule to {}", dest_path.display());
    } else if is_zip {
        let cursor = std::io::Cursor::new(content);
        let mut zip = zip::ZipArchive::new(cursor)
            .map_err(|err| format!("failed to open zip archive: {err}"))?;
        
        let mut count = 0;
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| e.to_string())?;
            let name = file.name().to_string();
            
            // Security: Prevent zip slip
            if name.contains("..") {
                eprintln!("warning: skipping unsafe path in zip: {}", name);
                continue;
            }
            
            if name.ends_with('/') {
                continue;
            }
            
            if !name.ends_with(".yaml") && !name.ends_with(".yml") {
                continue;
            }

            let dest_path = dest_dir.join(&name);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            
            let mut outfile = File::create(&dest_path).map_err(|e| e.to_string())?;
            io::copy(&mut file, &mut outfile).map_err(|e| e.to_string())?;
            count += 1;
        }
        println!("✓ Installed {} rules to {}", count, dest_dir.display());
    }

    Ok(())
}

fn run_config(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("config requires a subcommand: set, get, or show\nUsage:\n  aishield config set analytics.url <url>\n  aishield config get analytics.url\n  aishield config show".to_string());
    }

    match args[0].as_str() {
        "set" => {
            if args.len() < 3 {
                return Err("config set requires a key and value\nUsage: aishield config set <key> <value>\nExample: aishield config set analytics.url http://localhost:8080".to_string());
            }

            let key = &args[1];
            let value = &args[2];

            let mut config = config::Config::load().unwrap_or_default();
            config.set(key, value)?;
            config.save()?;

            println!(
                "✓ Set {} = {}",
                key,
                if key.contains("api_key") {
                    "***"
                } else {
                    value
                }
            );
            Ok(())
        }
        "get" => {
            if args.len() < 2 {
                return Err("config get requires a key\nUsage: aishield config get <key>\nExample: aishield config get analytics.url".to_string());
            }

            let key = &args[1];
            let config = config::Config::load().unwrap_or_default().merge_with_env();

            match config.get(key) {
                Some(value) => {
                    println!("{}", value);
                    Ok(())
                }
                None => Err(format!("config key '{}' not set", key)),
            }
        }
        "show" => {
            let config = config::Config::load().unwrap_or_default().merge_with_env();

            println!("Analytics Configuration:");
            println!("  enabled:  {}", config.analytics.enabled);
            println!(
                "  url:      {}",
                config.analytics.url.as_deref().unwrap_or("<not set>")
            );
            println!(
                "  api_key:  {}",
                if config.analytics.api_key.is_some() {
                    "***"
                } else {
                    "<not set>"
                }
            );
            println!(
                "  org_id:   {}",
                config.analytics.org_id.as_deref().unwrap_or("<not set>")
            );
            println!(
                "  team_id:  {}",
                config.analytics.team_id.as_deref().unwrap_or("<not set>")
            );
            println!();
            println!(
                "Config file: {}",
                config::Config::get_config_path()?.display()
            );
            Ok(())
        }
        other => Err(format!(
            "unknown config subcommand `{}`\nAvailable: set, get, show",
            other
        )),
    }
}

fn run_analytics(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("analytics requires a subcommand: migrate-history, summary\nUsage:\n  aishield analytics migrate-history [--dry-run] [--history-file <path>]\n  aishield analytics summary [--days N] [--limit N] [--org-id ID] [--team-id ID] [--repo-id ID] [--format table|json] [--probes N] [--probe-interval-ms N] [--max-error-rate-pct N] [--max-summary-p95-ms N] [--max-compliance-p95-ms N] [--min-coverage-pct N] [--fail-on-threshold]".to_string());
    }

    match args[0].as_str() {
        "migrate-history" => {
            let mut dry_run = false;
            let mut history_file = PathBuf::from(".aishield-history.log");

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--dry-run" => dry_run = true,
                    "--history-file" => {
                        i += 1;
                        history_file =
                            PathBuf::from(args.get(i).ok_or("--history-file requires a value")?);
                    }
                    other => return Err(format!("unknown option `{}`", other)),
                }
                i += 1;
            }

            // Load config
            let config = config::Config::load()
                .map_err(|e| format!("Failed to load config: {}", e))?
                .merge_with_env();

            // Check if analytics is configured
            if config.analytics.url.is_none() {
                return Err(
                    "Analytics URL not configured\nRun: aishield config set analytics.url <url>"
                        .to_string(),
                );
            }

            if config.analytics.api_key.is_none() {
                return Err("Analytics API key not configured\nRun: aishield config set analytics.api_key <key>".to_string());
            }

            // Load history
            println!("Loading history from {}...", history_file.display());
            let records = load_history(&history_file)?;

            if records.is_empty() {
                println!("No history records found");
                return Ok(());
            }

            println!("Found {} history records", records.len());

            if dry_run {
                println!("\n[DRY RUN] Would migrate {} scans:", records.len());
                for (idx, record) in records.iter().take(5).enumerate() {
                    println!(
                        "  {}. {} - {} findings ({} critical, {} high)",
                        idx + 1,
                        record.target,
                        record.total,
                        record.critical,
                        record.high
                    );
                }
                if records.len() > 5 {
                    println!("  ... and {} more", records.len() - 5);
                }
                return Ok(());
            }

            // Migrate each record
            let client = analytics_client::AnalyticsClient::new(&config.analytics)?;
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create async runtime: {}", e))?;

            let mut success_count = 0;
            let mut error_count = 0;

            println!("\nMigrating history records...");
            for (idx, record) in records.iter().enumerate() {
                let target_path = PathBuf::from(&record.target);

                // Extract git metadata (best effort)
                let repo_metadata = git_utils::RepoMetadata::from_path(&target_path);

                // Create scan metadata
                let scan_metadata = analytics_client::ScanMetadata::from_repo(
                    &repo_metadata,
                    record.target.clone(),
                    &config.analytics,
                );

                // Create minimal scan summary from history record
                let scan_summary = analytics_client::ScanResultSummary {
                    total_findings: record.total,
                    critical: record.critical,
                    high: record.high,
                    medium: record.medium,
                    low: record.low,
                    info: record.info,
                    ai_estimated_count: record.ai_estimated,
                    scan_duration_ms: 0,
                    files_scanned: 0,
                    rules_loaded: 0,
                    findings: vec![], // No detailed findings from history
                };

                // Push to analytics
                match runtime.block_on(client.push_scan_result(&scan_summary, &scan_metadata)) {
                    Ok(_scan_id) => {
                        success_count += 1;
                        if (idx + 1) % 10 == 0 {
                            println!("  Migrated {}/{} scans...", idx + 1, records.len());
                        }
                    }
                    Err(e) => {
                        error_count += 1;
                        eprintln!("  Warning: Failed to migrate scan #{}: {}", idx + 1, e);
                    }
                }
            }

            println!("\n✓ Migration complete:");
            println!("  Success: {}", success_count);
            if error_count > 0 {
                println!("  Errors:  {}", error_count);
            }

            Ok(())
        }
        "summary" => {
            let mut days = 30i32;
            let mut limit = 5i32;
            let mut org_id_override = None::<String>;
            let mut team_id_override = None::<String>;
            let mut repo_id_override = None::<String>;
            let mut format = AnalyticsOutputFormat::Table;
            let mut probes: usize = 1;
            let mut probe_interval_ms: u64 = 0;
            let mut fail_on_threshold = false;
            let mut thresholds = AnalyticsThresholds::default();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--days" => {
                        i += 1;
                        days = args
                            .get(i)
                            .ok_or("--days requires a value")?
                            .parse::<i32>()
                            .map_err(|_| "--days must be a positive integer".to_string())?;
                        if days <= 0 {
                            return Err("--days must be greater than 0".to_string());
                        }
                    }
                    "--limit" => {
                        i += 1;
                        limit = args
                            .get(i)
                            .ok_or("--limit requires a value")?
                            .parse::<i32>()
                            .map_err(|_| "--limit must be a positive integer".to_string())?;
                        if limit <= 0 {
                            return Err("--limit must be greater than 0".to_string());
                        }
                    }
                    "--org-id" => {
                        i += 1;
                        org_id_override =
                            Some(args.get(i).ok_or("--org-id requires a value")?.to_string());
                    }
                    "--team-id" => {
                        i += 1;
                        team_id_override =
                            Some(args.get(i).ok_or("--team-id requires a value")?.to_string());
                    }
                    "--repo-id" => {
                        i += 1;
                        repo_id_override =
                            Some(args.get(i).ok_or("--repo-id requires a value")?.to_string());
                    }
                    "--format" => {
                        i += 1;
                        format = AnalyticsOutputFormat::parse(
                            args.get(i).ok_or("--format requires a value")?,
                        )?;
                    }
                    "--probes" => {
                        i += 1;
                        probes = args
                            .get(i)
                            .ok_or("--probes requires a value")?
                            .parse::<usize>()
                            .map_err(|_| "--probes must be a positive integer".to_string())?;
                        if probes == 0 {
                            return Err("--probes must be greater than 0".to_string());
                        }
                    }
                    "--probe-interval-ms" => {
                        i += 1;
                        probe_interval_ms = args
                            .get(i)
                            .ok_or("--probe-interval-ms requires a value")?
                            .parse::<u64>()
                            .map_err(|_| {
                                "--probe-interval-ms must be a non-negative integer".to_string()
                            })?;
                    }
                    "--max-error-rate-pct" => {
                        i += 1;
                        thresholds.max_error_rate_pct = Some(
                            args.get(i)
                                .ok_or("--max-error-rate-pct requires a value")?
                                .parse::<f64>()
                                .map_err(|_| "--max-error-rate-pct must be a number".to_string())?,
                        );
                    }
                    "--max-summary-p95-ms" => {
                        i += 1;
                        thresholds.max_summary_p95_ms = Some(
                            args.get(i)
                                .ok_or("--max-summary-p95-ms requires a value")?
                                .parse::<f64>()
                                .map_err(|_| "--max-summary-p95-ms must be a number".to_string())?,
                        );
                    }
                    "--max-compliance-p95-ms" => {
                        i += 1;
                        thresholds.max_compliance_p95_ms = Some(
                            args.get(i)
                                .ok_or("--max-compliance-p95-ms requires a value")?
                                .parse::<f64>()
                                .map_err(|_| {
                                    "--max-compliance-p95-ms must be a number".to_string()
                                })?,
                        );
                    }
                    "--min-coverage-pct" => {
                        i += 1;
                        thresholds.min_coverage_pct = Some(
                            args.get(i)
                                .ok_or("--min-coverage-pct requires a value")?
                                .parse::<f64>()
                                .map_err(|_| "--min-coverage-pct must be a number".to_string())?,
                        );
                    }
                    "--fail-on-threshold" => fail_on_threshold = true,
                    other => return Err(format!("unknown option `{}`", other)),
                }
                i += 1;
            }

            if fail_on_threshold && !thresholds.has_any_threshold() {
                return Err(
                    "--fail-on-threshold requires at least one threshold option".to_string()
                );
            }

            let config = config::Config::load()
                .map_err(|e| format!("Failed to load config: {}", e))?
                .merge_with_env();

            if config.analytics.url.is_none() {
                return Err(
                    "Analytics URL not configured\nRun: aishield config set analytics.url <url>"
                        .to_string(),
                );
            }

            if config.analytics.api_key.is_none() {
                return Err("Analytics API key not configured\nRun: aishield config set analytics.api_key <key>".to_string());
            }

            let query = analytics_client::AnalyticsQuery {
                org_id: org_id_override.or(config.analytics.org_id.clone()),
                team_id: team_id_override.or(config.analytics.team_id.clone()),
                repo_id: repo_id_override,
                days,
                limit,
            };

            let client = analytics_client::AnalyticsClient::new(&config.analytics)?;
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create async runtime: {}", e))?;

            let (summary, compliance_gaps, probe_metrics) = runtime.block_on(
                fetch_analytics_probe_metrics(&client, &query, probes, probe_interval_ms),
            )?;

            let rendered = match format {
                AnalyticsOutputFormat::Table => render_analytics_summary_table(
                    &summary,
                    &compliance_gaps,
                    &query,
                    &probe_metrics,
                    &thresholds,
                ),
                AnalyticsOutputFormat::Json => render_analytics_summary_json(
                    &summary,
                    &compliance_gaps,
                    &query,
                    &probe_metrics,
                    &thresholds,
                ),
            };

            write_stdout(&rendered)?;

            if fail_on_threshold {
                let violations =
                    evaluate_analytics_thresholds(&probe_metrics, &compliance_gaps, &thresholds);
                if !violations.is_empty() {
                    return Err(format!(
                        "analytics thresholds failed: {}",
                        violations.join("; ")
                    ));
                }
            }

            Ok(())
        }
        other => Err(format!(
            "unknown analytics subcommand `{}`\nAvailable: migrate-history, summary",
            other
        )),
    }
}

fn run_stats(args: &[String]) -> Result<(), String> {
    let mut days: u64 = 30;
    let mut history_file = PathBuf::from(".aishield-history.log");
    let mut format = StatsOutputFormat::Table;
    let mut config_path = PathBuf::from(".aishield.yml");
    let mut use_config = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--last" => {
                i += 1;
                days = parse_last_days(args.get(i).ok_or("--last requires a value")?)?;
            }
            "--history-file" => {
                i += 1;
                history_file = PathBuf::from(args.get(i).ok_or("--history-file requires a value")?);
            }
            "--format" => {
                i += 1;
                format = StatsOutputFormat::parse(args.get(i).ok_or("--format requires a value")?)?;
            }
            "--config" => {
                i += 1;
                config_path = PathBuf::from(args.get(i).ok_or("--config requires a value")?);
            }
            "--no-config" => use_config = false,
            other => return Err(format!("unknown stats option `{other}`")),
        }
        i += 1;
    }

    if use_config && !args.iter().any(|a| a == "--history-file") {
        let config = AppConfig::load_if_exists(&config_path)?;
        history_file = config.history_file;
    }

    let records = load_history(&history_file)?;
    let cutoff = current_epoch_seconds().saturating_sub(days.saturating_mul(86_400));
    let filtered = records
        .into_iter()
        .filter(|record| record.timestamp >= cutoff)
        .collect::<Vec<_>>();

    let aggregate = StatsAggregate::from_records(&filtered);
    let rendered = match format {
        StatsOutputFormat::Table => render_stats_table(&aggregate, days, &history_file),
        StatsOutputFormat::Json => render_stats_json(&aggregate, days, &history_file),
    };

    write_stdout(&rendered)
}

#[derive(Debug, Default, Clone)]
struct AnalyticsThresholds {
    max_error_rate_pct: Option<f64>,
    max_summary_p95_ms: Option<f64>,
    max_compliance_p95_ms: Option<f64>,
    min_coverage_pct: Option<f64>,
}

impl AnalyticsThresholds {
    fn has_any_threshold(&self) -> bool {
        self.max_error_rate_pct.is_some()
            || self.max_summary_p95_ms.is_some()
            || self.max_compliance_p95_ms.is_some()
            || self.min_coverage_pct.is_some()
    }
}

#[derive(Debug, Clone)]
struct AnalyticsProbeMetrics {
    probe_count: usize,
    total_requests: usize,
    failed_requests: usize,
    error_rate_pct: f64,
    summary_p95_ms: Option<f64>,
    compliance_p95_ms: Option<f64>,
}

async fn fetch_analytics_probe_metrics(
    client: &analytics_client::AnalyticsClient,
    query: &analytics_client::AnalyticsQuery,
    probes: usize,
    probe_interval_ms: u64,
) -> Result<(Value, Value, AnalyticsProbeMetrics), String> {
    let mut summary_last = None::<Value>;
    let mut compliance_last = None::<Value>;
    let mut summary_latencies = Vec::<f64>::new();
    let mut compliance_latencies = Vec::<f64>::new();
    let mut failed_requests = 0usize;
    let total_requests = probes.saturating_mul(2);
    let mut last_summary_err = None::<String>;
    let mut last_compliance_err = None::<String>;

    for probe_idx in 0..probes {
        let summary_started = Instant::now();
        match client.fetch_summary(query).await {
            Ok(payload) => {
                summary_latencies.push(summary_started.elapsed().as_secs_f64() * 1000.0);
                summary_last = Some(payload);
            }
            Err(err) => {
                failed_requests += 1;
                last_summary_err = Some(err);
            }
        }

        let compliance_started = Instant::now();
        match client.fetch_compliance_gaps(query).await {
            Ok(payload) => {
                compliance_latencies.push(compliance_started.elapsed().as_secs_f64() * 1000.0);
                compliance_last = Some(payload);
            }
            Err(err) => {
                failed_requests += 1;
                last_compliance_err = Some(err);
            }
        }

        if probe_idx + 1 < probes && probe_interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(probe_interval_ms)).await;
        }
    }

    let summary = summary_last.ok_or_else(|| {
        format!(
            "failed to fetch analytics summary from API across {} probe(s): {}",
            probes,
            last_summary_err.unwrap_or_else(|| "unknown error".to_string())
        )
    })?;

    let compliance_gaps = compliance_last.ok_or_else(|| {
        format!(
            "failed to fetch analytics compliance-gaps from API across {} probe(s): {}",
            probes,
            last_compliance_err.unwrap_or_else(|| "unknown error".to_string())
        )
    })?;

    let error_rate_pct = if total_requests == 0 {
        0.0
    } else {
        (failed_requests as f64 / total_requests as f64) * 100.0
    };

    let summary_p95_ms = if summary_latencies.is_empty() {
        None
    } else {
        Some(percentile(&summary_latencies, 0.95))
    };
    let compliance_p95_ms = if compliance_latencies.is_empty() {
        None
    } else {
        Some(percentile(&compliance_latencies, 0.95))
    };

    Ok((
        summary,
        compliance_gaps,
        AnalyticsProbeMetrics {
            probe_count: probes,
            total_requests,
            failed_requests,
            error_rate_pct,
            summary_p95_ms,
            compliance_p95_ms,
        },
    ))
}

fn evaluate_analytics_thresholds(
    probe_metrics: &AnalyticsProbeMetrics,
    compliance_gaps: &Value,
    thresholds: &AnalyticsThresholds,
) -> Vec<String> {
    let mut violations = Vec::<String>::new();

    if let Some(max_error_rate_pct) = thresholds.max_error_rate_pct {
        if probe_metrics.error_rate_pct > max_error_rate_pct {
            violations.push(format!(
                "error_rate_pct {:.2}% > max_error_rate_pct {:.2}%",
                probe_metrics.error_rate_pct, max_error_rate_pct
            ));
        }
    }

    if let Some(max_summary_p95_ms) = thresholds.max_summary_p95_ms {
        match probe_metrics.summary_p95_ms {
            Some(observed) if observed > max_summary_p95_ms => violations.push(format!(
                "summary_p95_ms {:.3} > max_summary_p95_ms {:.3}",
                observed, max_summary_p95_ms
            )),
            None => violations
                .push("summary_p95_ms is unavailable (no successful summary probe)".to_string()),
            _ => {}
        }
    }

    if let Some(max_compliance_p95_ms) = thresholds.max_compliance_p95_ms {
        match probe_metrics.compliance_p95_ms {
            Some(observed) if observed > max_compliance_p95_ms => violations.push(format!(
                "compliance_p95_ms {:.3} > max_compliance_p95_ms {:.3}",
                observed, max_compliance_p95_ms
            )),
            None => violations.push(
                "compliance_p95_ms is unavailable (no successful compliance probe)".to_string(),
            ),
            _ => {}
        }
    }

    if let Some(min_coverage_pct) = thresholds.min_coverage_pct {
        let observed_coverage = compliance_gaps
            .pointer("/summary/coverage_pct")
            .and_then(Value::as_f64);

        match observed_coverage {
            Some(observed) if observed < min_coverage_pct => violations.push(format!(
                "coverage_pct {:.2}% < min_coverage_pct {:.2}%",
                observed, min_coverage_pct
            )),
            None => violations
                .push("coverage_pct is unavailable in compliance-gaps response".to_string()),
            _ => {}
        }
    }

    violations
}

fn run_hook(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("hook requires a subcommand (install)".to_string());
    }

    match args[0].as_str() {
        "install" => run_hook_install(&args[1..]),
        other => Err(format!("unknown hook subcommand `{other}`")),
    }
}

fn apply_autofixes(
    target: &Path,
    result: &ScanResult,
    write_changes: bool,
    dry_run: bool,
) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut file_rules = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    for finding in &result.findings {
        let path = resolve_finding_path(target, &finding.file);
        file_rules
            .entry(path)
            .or_default()
            .insert(finding.id.clone());
    }

    let mut touched_files = 0usize;
    let mut total_replacements = 0usize;

    for (file_path, rule_ids) in file_rules {
        let mut content = match fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(_) => continue,
        };

        let mut replacements_in_file = 0usize;
        for rule_id in rule_ids {
            for (from, to) in autofix_replacements(&rule_id) {
                let count = content.match_indices(from).count();
                if count == 0 {
                    continue;
                }
                content = content.replace(from, to);
                replacements_in_file += count;
            }
        }

        if replacements_in_file == 0 {
            continue;
        }

        touched_files += 1;
        total_replacements += replacements_in_file;
        if write_changes && !dry_run {
            fs::write(&file_path, content)
                .map_err(|err| format!("failed to write {}: {err}", file_path.display()))?;
        }
    }

    if dry_run {
        println!(
            "Autofix dry-run: {} file(s) would change with {} replacement(s).",
            touched_files, total_replacements
        );
    } else if write_changes {
        println!(
            "Autofix applied: {} file(s) changed with {} replacement(s).",
            touched_files, total_replacements
        );
    } else {
        println!(
            "Autofix preview: {} file(s) eligible with {} replacement(s).",
            touched_files, total_replacements
        );
    }

    Ok(())
}

fn resolve_finding_path(target: &Path, finding_file: &str) -> PathBuf {
    if target.is_file() {
        return target.to_path_buf();
    }
    let relative = PathBuf::from(finding_file);
    if relative.is_absolute() {
        relative
    } else {
        target.join(relative)
    }
}

fn autofix_replacements(rule_id: &str) -> Vec<(&'static str, &'static str)> {
    match rule_id {
        "AISHIELD-PY-AUTH-002" => vec![
            ("\"verify_signature\": False", "\"verify_signature\": True"),
            ("'verify_signature': False", "'verify_signature': True"),
        ],
        "AISHIELD-PY-CRYPTO-001" => vec![
            ("hashlib.md5(", "hashlib.sha256("),
            ("hashlib.sha1(", "hashlib.sha256("),
        ],
        "AISHIELD-PY-CRYPTO-002" => vec![
            ("algorithm=\"none\"", "algorithm=\"HS256\""),
            ("algorithm='none'", "algorithm='HS256'"),
            ("algorithm = \"none\"", "algorithm = \"HS256\""),
        ],
        "AISHIELD-PY-CRYPTO-003" => {
            vec![(
                "base64.b64encode(password.encode())",
                "bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            )]
        }
        "AISHIELD-PY-CRYPTO-004" => vec![("random.random()", "random.SystemRandom().random()")],
        "AISHIELD-PY-MISC-001" => vec![
            ("DEBUG = True", "DEBUG = False"),
            ("debug=True", "debug=False"),
            ("debug = True", "debug = False"),
        ],
        "AISHIELD-PY-MISC-002" => vec![
            ("\"origins\": \"*\"", "\"origins\": \"https://example.com\""),
            ("'origins': '*'", "'origins': 'https://example.com'"),
        ],
        "AISHIELD-PY-MISC-003" => vec![("host=\"0.0.0.0\"", "host=\"127.0.0.1\"")],
        "AISHIELD-PY-CRYPTO-006" => vec![
            ("verify=False", "verify=True"),
            ("verify = False", "verify = True"),
        ],
        "AISHIELD-PY-INJ-002" => vec![("os.system(", "subprocess.run(")],
        "AISHIELD-PY-INJ-003" => vec![
            ("shell=True", "shell=False"),
            ("shell = True", "shell = False"),
        ],
        "AISHIELD-PY-INJ-004" => vec![("eval(", "ast.literal_eval(")],
        "AISHIELD-JS-INJ-004" => vec![
            ("innerHTML =", "textContent ="),
            ("innerHTML=", "textContent="),
        ],
        "AISHIELD-JS-AUTH-002" => vec![
            ("ignoreExpiration: true", "ignoreExpiration: false"),
            ("ignoreExpiration:true", "ignoreExpiration:false"),
        ],
        "AISHIELD-JS-CRYPTO-001" => vec![
            ("createHash('md5')", "createHash('sha256')"),
            ("createHash(\"md5\")", "createHash(\"sha256\")"),
            ("createHash('sha1')", "createHash('sha256')"),
            ("createHash(\"sha1\")", "createHash(\"sha256\")"),
        ],
        "AISHIELD-JS-CRYPTO-002" => vec![("createCipher(", "createCipheriv(")],
        "AISHIELD-JS-CRYPTO-003" => vec![(
            "Math.random().toString(36).slice(2)",
            "crypto.randomBytes(32).toString('hex')",
        )],
        "AISHIELD-JS-INJ-002" => vec![("eval(", "JSON.parse(")],
        "AISHIELD-JS-INJ-003" => vec![("exec(", "execFile(")],
        "AISHIELD-JS-MISC-001" => vec![("origin: \"*\"", "origin: \"https://example.com\"")],
        "AISHIELD-JAVA-CRYPTO-001" => vec![(
            "MessageDigest.getInstance(\"MD5\")",
            "MessageDigest.getInstance(\"SHA-256\")",
        )],
        "AISHIELD-JAVA-CRYPTO-002" => vec![("new Random()", "new java.security.SecureRandom()")],
        "AISHIELD-JAVA-AUTH-001" => vec![
            ("if (secret == provided)", "if (secret.equals(provided))"),
            ("if(secret == provided)", "if(secret.equals(provided))"),
        ],
        "AISHIELD-GO-CRYPTO-001" => vec![("md5.Sum(", "sha256.Sum256(")],
        "AISHIELD-GO-INJ-001" => vec![(
            "exec.Command(\"sh\", \"-c\", \"cat \"+userInput)",
            "exec.Command(\"cat\", userInput)",
        )],
        "AISHIELD-GO-AUTH-001" => vec![(
            "if secret == incoming",
            "if subtle.ConstantTimeCompare([]byte(token), []byte(incoming)) == 1",
        )],
        "AISHIELD-JS-MISC-002" => vec![
            ("debug: true", "debug: false"),
            ("debug:true", "debug:false"),
        ],
        _ => Vec::new(),
    }
}

fn run_hook_install(args: &[String]) -> Result<(), String> {
    let mut severity = SeverityThreshold::High;
    let mut scan_path = ".".to_string();
    let mut all_files = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--severity" => {
                i += 1;
                severity =
                    SeverityThreshold::parse(args.get(i).ok_or("--severity requires a value")?)?;
            }
            "--path" => {
                i += 1;
                scan_path = args.get(i).ok_or("--path requires a value")?.to_string();
            }
            "--all-files" => all_files = true,
            other => return Err(format!("unknown hook install option `{other}`")),
        }
        i += 1;
    }

    let hooks_dir = PathBuf::from(".git/hooks");
    if !hooks_dir.exists() {
        return Err(".git/hooks not found; run this inside a git repository".to_string());
    }

    let staged_arg = if all_files { "" } else { "--staged " };
    let hook_path = hooks_dir.join("pre-commit");
    let script = format!(
        "#!/usr/bin/env sh\nset -e\n\nif command -v aishield >/dev/null 2>&1; then\n  aishield scan {scan_path} {staged_arg}--severity {} --fail-on-findings\nelse\n  cargo run -q -p aishield-cli -- scan {scan_path} {staged_arg}--severity {} --fail-on-findings\nfi\n",
        severity.as_str(),
        severity.as_str()
    );

    fs::write(&hook_path, script)
        .map_err(|err| format!("failed to write {}: {err}", hook_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)
            .map_err(|err| err.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms).map_err(|err| err.to_string())?;
    }

    println!("Installed pre-commit hook at {}", hook_path.display());
    Ok(())
}

#[derive(Debug, Clone)]
struct HistoryRecord {
    timestamp: u64,
    target: String,
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    ai_estimated: usize,
    top_rule: String,
}

impl HistoryRecord {
    fn to_line(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            self.timestamp,
            escape_history_field(&self.target),
            self.total,
            self.critical,
            self.high,
            self.medium,
            self.low,
            self.info,
            self.ai_estimated,
            escape_history_field(&self.top_rule)
        )
    }

    fn from_line(line: &str) -> Option<Self> {
        let parts = line.trim().split('|').collect::<Vec<_>>();
        if parts.len() != 10 {
            return None;
        }

        Some(Self {
            timestamp: parts[0].parse().ok()?,
            target: unescape_history_field(parts[1]),
            total: parts[2].parse().ok()?,
            critical: parts[3].parse().ok()?,
            high: parts[4].parse().ok()?,
            medium: parts[5].parse().ok()?,
            low: parts[6].parse().ok()?,
            info: parts[7].parse().ok()?,
            ai_estimated: parts[8].parse().ok()?,
            top_rule: unescape_history_field(parts[9]),
        })
    }
}

struct StatsAggregate {
    scans: usize,
    findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    ai_estimated: usize,
    top_rules: Vec<(String, usize)>,
}

impl StatsAggregate {
    fn from_records(records: &[HistoryRecord]) -> Self {
        let mut top_rule_counts = BTreeMap::new();
        let mut aggregate = Self {
            scans: records.len(),
            findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            ai_estimated: 0,
            top_rules: Vec::new(),
        };

        for record in records {
            aggregate.findings += record.total;
            aggregate.critical += record.critical;
            aggregate.high += record.high;
            aggregate.medium += record.medium;
            aggregate.low += record.low;
            aggregate.info += record.info;
            aggregate.ai_estimated += record.ai_estimated;

            if !record.top_rule.is_empty() && record.top_rule != "-" {
                *top_rule_counts.entry(record.top_rule.clone()).or_insert(0) += 1;
            }
        }

        aggregate.top_rules = top_rule_counts.into_iter().collect::<Vec<_>>();
        aggregate
            .top_rules
            .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        aggregate
    }
}

fn append_history(history_file: &Path, target: &Path, result: &ScanResult) -> Result<(), String> {
    if let Some(parent) = history_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed creating {}: {err}", parent.display()))?;
        }
    }

    let top_rule = most_frequent_rule_id(result).unwrap_or_else(|| "-".to_string());
    let record = HistoryRecord {
        timestamp: current_epoch_seconds(),
        target: target.display().to_string(),
        total: result.summary.total,
        critical: *result.summary.by_severity.get("critical").unwrap_or(&0),
        high: *result.summary.by_severity.get("high").unwrap_or(&0),
        medium: *result.summary.by_severity.get("medium").unwrap_or(&0),
        low: *result.summary.by_severity.get("low").unwrap_or(&0),
        info: *result.summary.by_severity.get("info").unwrap_or(&0),
        ai_estimated: result
            .findings
            .iter()
            .filter(|finding| finding.ai_confidence >= 70.0)
            .count(),
        top_rule,
    };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_file)
        .map_err(|err| format!("failed opening {}: {err}", history_file.display()))?;
    file.write_all(record.to_line().as_bytes())
        .map_err(|err| format!("failed writing {}: {err}", history_file.display()))?;
    Ok(())
}

fn enrich_finding_compliance_metadata(finding: &Finding) -> (Option<String>, Option<String>) {
    let mut cwe_id = finding.cwe_id.clone();
    let mut owasp_category = finding.owasp_category.clone();

    for tag in &finding.tags {
        let normalized = tag.trim().to_ascii_lowercase();
        apply_compliance_mapping(
            &mut cwe_id,
            &mut owasp_category,
            match normalized.as_str() {
                "sql-injection" => (
                    Some("CWE-89".to_string()),
                    Some("A03:2021 - Injection".to_string()),
                ),
                "nosql" => (
                    Some("CWE-943".to_string()),
                    Some("A03:2021 - Injection".to_string()),
                ),
                "command-injection" | "command" => (
                    Some("CWE-78".to_string()),
                    Some("A03:2021 - Injection".to_string()),
                ),
                "path-traversal" => (
                    Some("CWE-22".to_string()),
                    Some("A01:2021 - Broken Access Control".to_string()),
                ),
                "code-execution" => (
                    Some("CWE-94".to_string()),
                    Some("A03:2021 - Injection".to_string()),
                ),
                "timing-attack" => (
                    Some("CWE-208".to_string()),
                    Some("A07:2021 - Identification and Authentication Failures".to_string()),
                ),
                "weak-hash" | "crypto" | "key-management" => (
                    Some("CWE-327".to_string()),
                    Some("A02:2021 - Cryptographic Failures".to_string()),
                ),
                "secrets" => (
                    Some("CWE-798".to_string()),
                    Some("A07:2021 - Identification and Authentication Failures".to_string()),
                ),
                "cors" => (
                    Some("CWE-942".to_string()),
                    Some("A05:2021 - Security Misconfiguration".to_string()),
                ),
                "debug" => (
                    Some("CWE-489".to_string()),
                    Some("A05:2021 - Security Misconfiguration".to_string()),
                ),
                "supply-chain" => (
                    Some("CWE-1104".to_string()),
                    Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
                ),
                "auth" | "token" | "identity" => (
                    Some("CWE-287".to_string()),
                    Some("A07:2021 - Identification and Authentication Failures".to_string()),
                ),
                "misconfig" | "hardening" | "network" => (
                    Some("CWE-16".to_string()),
                    Some("A05:2021 - Security Misconfiguration".to_string()),
                ),
                _ => (None, None),
            },
        );
    }

    let category = finding
        .category
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    apply_compliance_mapping(
        &mut cwe_id,
        &mut owasp_category,
        match category.as_str() {
            "auth" => (
                Some("CWE-287".to_string()),
                Some("A07:2021 - Identification and Authentication Failures".to_string()),
            ),
            "crypto" => (
                Some("CWE-327".to_string()),
                Some("A02:2021 - Cryptographic Failures".to_string()),
            ),
            "injection" => (
                Some("CWE-74".to_string()),
                Some("A03:2021 - Injection".to_string()),
            ),
            "misconfig" => (
                Some("CWE-16".to_string()),
                Some("A05:2021 - Security Misconfiguration".to_string()),
            ),
            _ => (None, None),
        },
    );

    let rule_id = finding.id.to_ascii_uppercase();
    apply_compliance_mapping(
        &mut cwe_id,
        &mut owasp_category,
        if rule_id.contains("-AUTH-") {
            (
                Some("CWE-287".to_string()),
                Some("A07:2021 - Identification and Authentication Failures".to_string()),
            )
        } else if rule_id.contains("-CRYPTO-") {
            (
                Some("CWE-327".to_string()),
                Some("A02:2021 - Cryptographic Failures".to_string()),
            )
        } else if rule_id.contains("-INJ-") {
            (
                Some("CWE-74".to_string()),
                Some("A03:2021 - Injection".to_string()),
            )
        } else if rule_id.contains("-MISC-") || rule_id.contains("-MISCONFIG-") {
            (
                Some("CWE-16".to_string()),
                Some("A05:2021 - Security Misconfiguration".to_string()),
            )
        } else {
            (None, None)
        },
    );

    (cwe_id, owasp_category)
}

fn apply_compliance_mapping(
    cwe_id: &mut Option<String>,
    owasp_category: &mut Option<String>,
    candidate: (Option<String>, Option<String>),
) {
    if cwe_id.is_none() {
        *cwe_id = candidate.0;
    }
    if owasp_category.is_none() {
        *owasp_category = candidate.1;
    }
}

fn push_to_analytics(
    target: &Path,
    result: &ScanResult,
    org_id: Option<String>,
    team_id: Option<String>,
    repo_id: Option<String>,
) -> Result<(), String> {
    // Load config and merge with env vars
    let config = config::Config::load()
        .map_err(|e| format!("Failed to load config: {}", e))?
        .merge_with_env();

    // Check if analytics is configured
    if config.analytics.url.is_none() {
        return Err("Analytics URL not configured (use 'aishield config set analytics.url <url>' or set AISHIELD_ANALYTICS_URL)".to_string());
    }

    if config.analytics.api_key.is_none() {
        return Err("Analytics API key not configured (use 'aishield config set analytics.api_key <key>' or set AISHIELD_API_KEY)".to_string());
    }

    // Extract repository metadata
    let mut repo_metadata = git_utils::RepoMetadata::from_path(target);
    if let Some(rid) = repo_id {
        repo_metadata.repo_id = rid;
    }

    // Create scan metadata
    let mut scan_metadata = analytics_client::ScanMetadata::from_repo(
        &repo_metadata,
        target.display().to_string(),
        &config.analytics,
    );

    if let Some(oid) = org_id {
        scan_metadata.org_id = Some(oid);
    }
    if let Some(tid) = team_id {
        scan_metadata.team_id = Some(tid);
    }

    // Convert scan result to analytics format
    let scan_summary = analytics_client::ScanResultSummary {
        total_findings: result.summary.total,
        critical: *result.summary.by_severity.get("critical").unwrap_or(&0),
        high: *result.summary.by_severity.get("high").unwrap_or(&0),
        medium: *result.summary.by_severity.get("medium").unwrap_or(&0),
        low: *result.summary.by_severity.get("low").unwrap_or(&0),
        info: *result.summary.by_severity.get("info").unwrap_or(&0),
        ai_estimated_count: result
            .findings
            .iter()
            .filter(|f| f.ai_confidence >= 70.0)
            .count(),
        scan_duration_ms: 0, // Not tracked in current ScanResult
        files_scanned: result.summary.scanned_files,
        rules_loaded: result.summary.matched_rules,
        findings: result
            .findings
            .iter()
            .map(|f| {
                let (cwe_id, owasp_category) = enrich_finding_compliance_metadata(f);
                analytics_client::FindingDetail {
                    rule_id: f.id.clone(),
                    rule_title: f.title.clone(),
                    severity: match f.severity {
                        Severity::Critical => "Critical",
                        Severity::High => "High",
                        Severity::Medium => "Medium",
                        Severity::Low => "Low",
                        Severity::Info => "Info",
                    }
                    .to_string(),
                    file_path: f.file.clone(),
                    line_number: Some(f.line),
                    snippet: Some(f.snippet.clone()), // Skip snippet to reduce payload size
                    ai_confidence: if f.ai_confidence > 0.0 {
                        Some(f.ai_confidence)
                    } else {
                        None
                    },
                    ai_tendency: f.ai_tendency.clone(),
                    fix_suggestion: f.fix_suggestion.clone(),
                    cwe_id,
                    owasp_category,
                }
            })
            .collect(),
    };

    // Create analytics client
    let client = analytics_client::AnalyticsClient::new(&config.analytics)?;

    // Create tokio runtime for async operation
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create async runtime: {}", e))?;

    // Validate endpoint before attempting push for clearer operator feedback.
    let is_healthy = runtime
        .block_on(client.health_check())
        .map_err(|e| format!("Analytics health check failed: {}", e))?;
    if !is_healthy {
        return Err("Analytics API is unreachable or unhealthy".to_string());
    }

    // Push to analytics API
    let scan_id = runtime
        .block_on(client.push_scan_result(&scan_summary, &scan_metadata))
        .map_err(|e| format!("API error: {}", e))?;

    println!("✓ Scan pushed to analytics (ID: {})", scan_id);
    Ok(())
}

fn load_history(history_file: &Path) -> Result<Vec<HistoryRecord>, String> {
    if !history_file.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(history_file)
        .map_err(|err| format!("failed reading {}: {err}", history_file.display()))?;

    Ok(content
        .lines()
        .filter_map(HistoryRecord::from_line)
        .collect::<Vec<_>>())
}

fn most_frequent_rule_id(result: &ScanResult) -> Option<String> {
    let mut counts = BTreeMap::new();
    for finding in &result.findings {
        *counts.entry(finding.id.clone()).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
        .map(|entry| entry.0)
}

fn maybe_send_webhook_notification(
    webhook_url: &str,
    min_severity: SeverityThreshold,
    target: &Path,
    result: &ScanResult,
) -> Result<(), String> {
    let matching_findings = result
        .findings
        .iter()
        .filter(|finding| min_severity.includes(finding.severity))
        .cloned()
        .collect::<Vec<_>>();

    if matching_findings.is_empty() {
        eprintln!(
            "info: webhook notification skipped (no findings at/above {}).",
            min_severity.as_str()
        );
        return Ok(());
    }

    let payload = build_webhook_payload(target, min_severity, result, &matching_findings);
    send_webhook_notification(webhook_url, &payload)
}

fn build_webhook_payload(
    target: &Path,
    min_severity: SeverityThreshold,
    result: &ScanResult,
    matching_findings: &[Finding],
) -> Value {
    let top_findings = matching_findings
        .iter()
        .take(20)
        .map(|finding| {
            serde_json::json!({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.as_str(),
                "file": finding.file,
                "line": finding.line,
                "column": finding.column,
                "risk_score": finding.risk_score,
                "ai_confidence": finding.ai_confidence,
                "category": finding.category,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "event": "aishield.scan.completed",
        "timestamp": current_epoch_seconds(),
        "target": target.display().to_string(),
        "notify_min_severity": min_severity.as_str(),
        "summary": {
            "total_findings": result.summary.total,
            "critical": result.summary.by_severity.get("critical").copied().unwrap_or(0),
            "high": result.summary.by_severity.get("high").copied().unwrap_or(0),
            "medium": result.summary.by_severity.get("medium").copied().unwrap_or(0),
            "low": result.summary.by_severity.get("low").copied().unwrap_or(0),
            "info": result.summary.by_severity.get("info").copied().unwrap_or(0),
            "scanned_files": result.summary.scanned_files,
            "matched_rules": result.summary.matched_rules,
            "alert_findings": matching_findings.len(),
        },
        "top_findings": top_findings,
    })
}

fn send_webhook_notification(webhook_url: &str, payload: &Value) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .post(webhook_url)
        .json(payload)
        .send()
        .map_err(|err| format!("request error: {err}"))?;

    if !response.status().is_success() {
        return Err(format!("webhook returned HTTP {}", response.status()));
    }

    Ok(())
}

fn parse_last_days(raw: &str) -> Result<u64, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    let number = if let Some(days) = normalized.strip_suffix('d') {
        days
    } else {
        normalized.as_str()
    };

    let parsed = number
        .parse::<u64>()
        .map_err(|_| format!("invalid --last value `{raw}`; expected e.g. 30d"))?;

    if parsed == 0 {
        return Err("--last must be greater than zero".to_string());
    }
    Ok(parsed)
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn escape_history_field(input: &str) -> String {
    input.replace('%', "%25").replace('|', "%7C")
}

fn unescape_history_field(input: &str) -> String {
    input.replace("%7C", "|").replace("%25", "%")
}

fn render_stats_table(aggregate: &StatsAggregate, days: u64, history_file: &Path) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "AIShield stats for last {} day(s) from {}",
        days,
        history_file.display()
    );
    let _ = writeln!(out, "Scans: {}", aggregate.scans);
    let _ = writeln!(out, "Findings: {}", aggregate.findings);
    let _ = writeln!(
        out,
        "Severity totals: critical={} high={} medium={} low={} info={}",
        aggregate.critical, aggregate.high, aggregate.medium, aggregate.low, aggregate.info
    );
    let _ = writeln!(
        out,
        "AI-generated (estimated): {} of {} findings",
        aggregate.ai_estimated, aggregate.findings
    );

    if aggregate.top_rules.is_empty() {
        out.push_str("Top patterns: none\n");
        return out;
    }

    out.push_str("Top patterns:\n");
    for (idx, (rule_id, count)) in aggregate.top_rules.iter().take(5).enumerate() {
        let _ = writeln!(out, "  {}. {} ({})", idx + 1, rule_id, count);
    }
    out
}

fn render_stats_json(aggregate: &StatsAggregate, days: u64, history_file: &Path) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"days\": {},", days);
    let _ = writeln!(
        out,
        "  \"history_file\": \"{}\",",
        escape_json(history_file.to_string_lossy().as_ref())
    );
    let _ = writeln!(out, "  \"scans\": {},", aggregate.scans);
    let _ = writeln!(out, "  \"findings\": {},", aggregate.findings);
    out.push_str("  \"severity_totals\": {\n");
    let _ = writeln!(out, "    \"critical\": {},", aggregate.critical);
    let _ = writeln!(out, "    \"high\": {},", aggregate.high);
    let _ = writeln!(out, "    \"medium\": {},", aggregate.medium);
    let _ = writeln!(out, "    \"low\": {},", aggregate.low);
    let _ = writeln!(out, "    \"info\": {}", aggregate.info);
    out.push_str("  },\n");
    let _ = writeln!(out, "  \"ai_estimated\": {},", aggregate.ai_estimated);
    out.push_str("  \"top_patterns\": [\n");
    for (idx, (rule_id, count)) in aggregate.top_rules.iter().take(10).enumerate() {
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"id\": \"{}\",", escape_json(rule_id));
        let _ = writeln!(out, "      \"count\": {}", count);
        if idx + 1 == aggregate.top_rules.len().min(10) {
            out.push_str("    }\n");
        } else {
            out.push_str("    },\n");
        }
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn render_analytics_summary_table(
    summary: &Value,
    compliance_gaps: &Value,
    query: &analytics_client::AnalyticsQuery,
    probe_metrics: &AnalyticsProbeMetrics,
    thresholds: &AnalyticsThresholds,
) -> String {
    let mut out = String::new();

    let total_scans = summary
        .pointer("/summary/total_scans")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let total_findings = summary
        .pointer("/summary/total_findings")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let critical = summary
        .pointer("/summary/critical")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let high = summary
        .pointer("/summary/high")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let medium = summary
        .pointer("/summary/medium")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let low = summary
        .pointer("/summary/low")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let ai_ratio = summary
        .pointer("/summary/ai_ratio")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        * 100.0;

    let findings_delta = format_optional_delta(
        summary
            .pointer("/trend/findings_delta_pct")
            .and_then(Value::as_f64),
    );
    let ai_ratio_delta = format_optional_delta(
        summary
            .pointer("/trend/ai_ratio_delta_pct")
            .and_then(Value::as_f64),
    );
    let scans_delta = format_optional_delta(
        summary
            .pointer("/trend/scans_delta_pct")
            .and_then(Value::as_f64),
    );

    let top_rule_id = summary
        .pointer("/top_rules/0/rule_id")
        .and_then(Value::as_str)
        .unwrap_or("n/a");
    let top_rule_count = summary
        .pointer("/top_rules/0/count")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let coverage_pct = compliance_gaps
        .pointer("/summary/coverage_pct")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let classified_findings = compliance_gaps
        .pointer("/summary/classified_findings")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let gap_total_findings = compliance_gaps
        .pointer("/summary/total_findings")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let top_cwe = compliance_gaps
        .pointer("/top_cwe/0/key")
        .and_then(Value::as_str)
        .unwrap_or("n/a");
    let top_cwe_count = compliance_gaps
        .pointer("/top_cwe/0/count")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let top_owasp = compliance_gaps
        .pointer("/top_owasp/0/key")
        .and_then(Value::as_str)
        .unwrap_or("n/a");
    let top_owasp_count = compliance_gaps
        .pointer("/top_owasp/0/count")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let org_scope = query.org_id.as_deref().unwrap_or("all");
    let team_scope = query.team_id.as_deref().unwrap_or("all");
    let repo_scope = query.repo_id.as_deref().unwrap_or("all");
    let threshold_violations =
        evaluate_analytics_thresholds(probe_metrics, compliance_gaps, thresholds);

    let _ = writeln!(
        out,
        "AIShield analytics summary for last {} day(s)",
        query.days
    );
    let _ = writeln!(
        out,
        "Scope: org={} team={} repo={}",
        org_scope, team_scope, repo_scope
    );
    out.push('\n');

    let _ = writeln!(out, "Scans:          {}", total_scans);
    let _ = writeln!(
        out,
        "Findings:       {} (critical={}, high={}, medium={}, low={})",
        total_findings, critical, high, medium, low
    );
    let _ = writeln!(out, "AI ratio:       {:.1}%", ai_ratio);
    let _ = writeln!(
        out,
        "Trend deltas:   findings={} scans={} ai_ratio={}",
        findings_delta, scans_delta, ai_ratio_delta
    );
    let _ = writeln!(
        out,
        "Top rule:       {} ({} finding(s))",
        top_rule_id, top_rule_count
    );
    let _ = writeln!(
        out,
        "Coverage:       {:.1}% ({}/{}) classified",
        coverage_pct, classified_findings, gap_total_findings
    );
    let _ = writeln!(
        out,
        "Top CWE:        {} ({} finding(s))",
        top_cwe, top_cwe_count
    );
    let _ = writeln!(
        out,
        "Top OWASP:      {} ({} finding(s))",
        top_owasp, top_owasp_count
    );
    let _ = writeln!(
        out,
        "Probe metrics:  probes={} requests={} failed={} error_rate={:.2}% summary_p95={}ms compliance_p95={}ms",
        probe_metrics.probe_count,
        probe_metrics.total_requests,
        probe_metrics.failed_requests,
        probe_metrics.error_rate_pct,
        format_optional_ms(probe_metrics.summary_p95_ms),
        format_optional_ms(probe_metrics.compliance_p95_ms)
    );

    if thresholds.has_any_threshold() {
        out.push('\n');
        let _ = writeln!(out, "Thresholds:");
        if let Some(max_error_rate_pct) = thresholds.max_error_rate_pct {
            let _ = writeln!(
                out,
                "  max_error_rate_pct: <= {:.2}% (observed {:.2}%)",
                max_error_rate_pct, probe_metrics.error_rate_pct
            );
        }
        if let Some(max_summary_p95_ms) = thresholds.max_summary_p95_ms {
            let _ = writeln!(
                out,
                "  max_summary_p95_ms: <= {:.2} (observed {} ms)",
                max_summary_p95_ms,
                format_optional_ms(probe_metrics.summary_p95_ms)
            );
        }
        if let Some(max_compliance_p95_ms) = thresholds.max_compliance_p95_ms {
            let _ = writeln!(
                out,
                "  max_compliance_p95_ms: <= {:.2} (observed {} ms)",
                max_compliance_p95_ms,
                format_optional_ms(probe_metrics.compliance_p95_ms)
            );
        }
        if let Some(min_coverage_pct) = thresholds.min_coverage_pct {
            let _ = writeln!(
                out,
                "  min_coverage_pct: >= {:.2}% (observed {:.2}%)",
                min_coverage_pct, coverage_pct
            );
        }
        if threshold_violations.is_empty() {
            out.push_str("  result: PASS\n");
        } else {
            out.push_str("  result: FAIL\n");
            for violation in threshold_violations {
                let _ = writeln!(out, "    - {}", violation);
            }
        }
    }
    out
}

fn render_analytics_summary_json(
    summary: &Value,
    compliance_gaps: &Value,
    query: &analytics_client::AnalyticsQuery,
    probe_metrics: &AnalyticsProbeMetrics,
    thresholds: &AnalyticsThresholds,
) -> String {
    let threshold_violations =
        evaluate_analytics_thresholds(probe_metrics, compliance_gaps, thresholds);
    let payload = serde_json::json!({
        "query": {
            "org_id": query.org_id,
            "team_id": query.team_id,
            "repo_id": query.repo_id,
            "days": query.days,
            "limit": query.limit,
        },
        "probe_metrics": {
            "probe_count": probe_metrics.probe_count,
            "total_requests": probe_metrics.total_requests,
            "failed_requests": probe_metrics.failed_requests,
            "error_rate_pct": probe_metrics.error_rate_pct,
            "summary_p95_ms": probe_metrics.summary_p95_ms,
            "compliance_p95_ms": probe_metrics.compliance_p95_ms,
        },
        "thresholds": {
            "max_error_rate_pct": thresholds.max_error_rate_pct,
            "max_summary_p95_ms": thresholds.max_summary_p95_ms,
            "max_compliance_p95_ms": thresholds.max_compliance_p95_ms,
            "min_coverage_pct": thresholds.min_coverage_pct,
            "result": if threshold_violations.is_empty() { "pass" } else { "fail" },
            "violations": threshold_violations,
        },
        "summary": summary,
        "compliance_gaps": compliance_gaps,
    });

    match serde_json::to_string_pretty(&payload) {
        Ok(serialized) => format!("{serialized}\n"),
        Err(_) => "{\"error\":\"failed to serialize analytics summary\"}\n".to_string(),
    }
}

fn format_optional_delta(delta: Option<f64>) -> String {
    match delta {
        Some(value) => format!("{:+.1}%", value),
        None => "n/a".to_string(),
    }
}

fn format_optional_ms(ms: Option<f64>) -> String {
    match ms {
        Some(value) => format!("{:.3}", value),
        None => "n/a".to_string(),
    }
}

fn run_watch(args: &[String]) -> Result<(), String> {
    use notify::RecursiveMode;
    use notify_debouncer_mini::new_debouncer;
    use std::sync::mpsc;

    if args.is_empty() {
        return Err("watch requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);
    let mut rules_dir = PathBuf::from("rules");
    let mut debounce_ms: u64 = 500;
    let mut severity_threshold = None::<SeverityThreshold>;
    let mut profile_override = None::<ScanProfile>;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir = PathBuf::from(args.get(i).ok_or("--rules-dir requires a value")?);
            }
            "--severity" => {
                i += 1;
                severity_threshold = Some(SeverityThreshold::parse(
                    args.get(i).ok_or("--severity requires a value")?,
                )?);
            }
            "--profile" => {
                i += 1;
                profile_override = Some(ScanProfile::parse(
                    args.get(i).ok_or("--profile requires a value")?,
                )?);
            }
            "--debounce-ms" => {
                i += 1;
                debounce_ms = args
                    .get(i)
                    .ok_or("--debounce-ms requires a value")?
                    .parse::<u64>()
                    .map_err(|_| "invalid --debounce-ms value".to_string())?;
            }
            other => return Err(format!("unknown watch option `{other}`")),
        }
        i += 1;
    }

    // Apply profile
    let profile_severity = match profile_override {
        Some(ScanProfile::Pragmatic) => Some(SeverityThreshold::High),
        _ => None,
    };
    let effective_severity = severity_threshold.or(profile_severity);

    let profile_ai_only = matches!(
        profile_override,
        Some(ScanProfile::Pragmatic) | Some(ScanProfile::AiFocus)
    );
    let profile_min_ai = match profile_override {
        Some(ScanProfile::Pragmatic) => Some(0.50_f32),
        Some(ScanProfile::AiFocus) => Some(0.75_f32),
        _ => None,
    };

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;
    let rules_count = ruleset.rules.len();
    let analyzer = Analyzer::new(ruleset);

    let ai_classifier = AiClassifierOptions::default();
    let options = AnalysisOptions {
        ai_only: profile_ai_only,
        min_ai_confidence: profile_min_ai,
        ai_classifier,
        ..AnalysisOptions::default()
    };

    // Initial scan
    eprintln!(
        "AIShield watching {} ({} rules loaded, debounce {}ms)",
        target.display(),
        rules_count,
        debounce_ms
    );
    eprintln!("Press Ctrl+C to stop.\n");

    let do_scan = |analyzer: &Analyzer, options: &AnalysisOptions, target: &Path| {
        match analyzer.analyze_path(target, options) {
            Ok(mut result) => {
                if let Some(threshold) = effective_severity {
                    result.findings = result
                        .findings
                        .into_iter()
                        .filter(|f| threshold.includes(f.severity))
                        .collect();
                    result.summary = recompute_summary(&result);
                }
                let critical = result.summary.by_severity.get("critical").copied().unwrap_or(0);
                let high = result.summary.by_severity.get("high").copied().unwrap_or(0);
                let medium = result.summary.by_severity.get("medium").copied().unwrap_or(0);
                let now = chrono::Local::now().format("%H:%M:%S");
                eprintln!(
                    "[{now}] {} findings (critical={critical} high={high} medium={medium}) across {} files",
                    result.summary.total,
                    result.summary.scanned_files
                );
            }
            Err(err) => {
                eprintln!("scan error: {err}");
            }
        }
    };

    do_scan(&analyzer, &options, &target);

    let (tx, rx) = mpsc::channel();
    let mut debouncer = new_debouncer(Duration::from_millis(debounce_ms), tx)
        .map_err(|err| format!("failed to create file watcher: {err}"))?;

    debouncer
        .watcher()
        .watch(&target, RecursiveMode::Recursive)
        .map_err(|err| format!("failed to watch {}: {err}", target.display()))?;

    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                // Check if any event involves a supported source file
                let has_source_change = events.iter().any(|event| {
                    let path = &event.path;
                    let ext = path
                        .extension()
                        .map(|e| e.to_string_lossy().to_ascii_lowercase());
                    matches!(
                        ext.as_deref(),
                        Some("py")
                            | Some("js")
                            | Some("ts")
                            | Some("jsx")
                            | Some("tsx")
                            | Some("go")
                            | Some("rs")
                            | Some("java")
                            | Some("cs")
                            | Some("rb")
                            | Some("php")
                            | Some("kt")
                            | Some("swift")
                            | Some("tf")
                            | Some("yaml")
                            | Some("yml")
                    )
                });
                if has_source_change {
                    do_scan(&analyzer, &options, &target);
                }
            }
            Ok(Err(err)) => {
                eprintln!("watch error: {err:?}");
            }
            Err(_) => {
                // Channel closed, watcher dropped
                break;
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("AIShield CLI (foundation)\n");
    println!("Usage:");
    println!("  aishield scan <path> [--rules-dir DIR] [--format table|json|sarif|github] [--dedup none|normalized] [--bridge semgrep,bandit,eslint|all] [--rules c1,c2] [--exclude p1,p2] [--ai-only] [--cross-file] [--ai-model heuristic|onnx] [--onnx-model FILE] [--onnx-manifest FILE] [--ai-calibration conservative|balanced|aggressive] [--min-ai-confidence N] [--severity LEVEL] [--profile strict|pragmatic|ai-focus] [--badge] [--vibe] [--fail-on-findings] [--staged|--changed-from REF] [--output FILE] [--baseline FILE] [--notify-webhook URL] [--notify-min-severity LEVEL] [--history-file FILE] [--no-history] [--config FILE] [--no-config]");
    println!("  aishield fix <path[:line[:col]]> [--rules-dir DIR] [--write|--interactive] [--dry-run] [--config FILE] [--no-config]");
    println!("  aishield bench <path> [--rules-dir DIR] [--iterations N] [--warmup N] [--format table|json] [--bridge semgrep,bandit,eslint|all] [--rules c1,c2] [--exclude p1,p2] [--ai-only] [--cross-file] [--ai-model heuristic|onnx] [--onnx-model FILE] [--onnx-manifest FILE] [--ai-calibration conservative|balanced|aggressive] [--min-ai-confidence N] [--config FILE] [--no-config]");
    println!("  aishield init [--wizard] [--output PATH] [--templates config,github-actions,gitlab-ci,bitbucket-pipelines,circleci,jenkins,vscode,pre-commit|all] [--force]");
    println!("  aishield create-rule --id ID --title TITLE --language LANG --category CAT [--severity LEVEL] [--pattern-any P] [--pattern-all P] [--pattern-not P] [--tags t1,t2] [--suggestion TEXT] [--out-dir DIR] [--force]");
    println!("  aishield stats [--last Nd] [--history-file FILE] [--format table|json] [--config FILE] [--no-config]");
    println!("  aishield watch <path> [--rules-dir DIR] [--severity LEVEL] [--profile strict|pragmatic|ai-focus] [--debounce-ms N]");
    println!("  aishield hook install [--severity LEVEL] [--path TARGET] [--all-files]");
    println!("  aishield analytics migrate-history [--dry-run] [--history-file FILE]");
    println!("  aishield analytics summary [--days N] [--limit N] [--org-id ID] [--team-id ID] [--repo-id ID] [--format table|json] [--probes N] [--probe-interval-ms N] [--max-error-rate-pct N] [--max-summary-p95-ms N] [--max-compliance-p95-ms N] [--min-coverage-pct N] [--fail-on-threshold]");
    println!("  aishield deps <path> [--format table|json]");
    println!("  aishield sbom <path> [--format spdx|cyclonedx] [--output FILE]");
    println!("  aishield keys generate");
    println!("  aishield verify <report.json> [--key <pubkey-path>]");
    println!("  aishield config set|get|show ...");
}

fn recompute_summary(result: &ScanResult) -> aishield_core::ScanSummary {
    summarize_findings(
        &result.findings,
        result.summary.scanned_files,
        result.summary.matched_rules,
    )
}

fn summarize_findings(
    findings: &[Finding],
    scanned_files: usize,
    matched_rules: usize,
) -> ScanSummary {
    let mut summary = empty_summary(scanned_files, matched_rules);
    summary.total = findings.len();
    for finding in findings {
        *summary
            .by_severity
            .entry(finding.severity.as_str().to_string())
            .or_insert(0) += 1;
    }
    summary
}

fn empty_summary(scanned_files: usize, matched_rules: usize) -> ScanSummary {
    let mut by_severity = BTreeMap::new();
    by_severity.insert("critical".to_string(), 0);
    by_severity.insert("high".to_string(), 0);
    by_severity.insert("medium".to_string(), 0);
    by_severity.insert("low".to_string(), 0);
    by_severity.insert("info".to_string(), 0);

    ScanSummary {
        total: 0,
        by_severity,
        scanned_files,
        matched_rules,
    }
}

struct OutputSummary {
    dedup_mode: DedupMode,
    original_total: usize,
    deduped_total: usize,
}

fn build_output_summary(
    original: &ScanResult,
    rendered: &ScanResult,
    dedup_mode: DedupMode,
) -> OutputSummary {
    OutputSummary {
        dedup_mode,
        original_total: original.findings.len(),
        deduped_total: rendered.findings.len(),
    }
}

fn dedup_machine_output(result: &ScanResult, dedup_mode: DedupMode) -> ScanResult {
    if dedup_mode == DedupMode::None {
        return result.clone();
    }

    let mut deduped = BTreeMap::<String, Finding>::new();
    for finding in &result.findings {
        let key = normalized_finding_key(finding);
        match deduped.get(&key) {
            Some(existing) => {
                if should_replace_dedup_finding(existing, finding) {
                    deduped.insert(key, finding.clone());
                }
            }
            None => {
                deduped.insert(key, finding.clone());
            }
        }
    }

    let mut findings = deduped.into_values().collect::<Vec<_>>();
    findings.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.id.cmp(&b.id))
    });

    ScanResult {
        summary: summarize_findings(
            &findings,
            result.summary.scanned_files,
            result.summary.matched_rules,
        ),
        findings,
    }
}

fn should_replace_dedup_finding(existing: &Finding, candidate: &Finding) -> bool {
    if candidate.risk_score > existing.risk_score {
        return true;
    }
    if candidate.risk_score < existing.risk_score {
        return false;
    }

    let candidate_rank = candidate.severity.rank();
    let existing_rank = existing.severity.rank();
    if candidate_rank > existing_rank {
        return true;
    }
    if candidate_rank < existing_rank {
        return false;
    }

    if candidate.ai_confidence > existing.ai_confidence {
        return true;
    }
    if candidate.ai_confidence < existing.ai_confidence {
        return false;
    }

    candidate.id < existing.id
}

fn normalized_finding_key(finding: &Finding) -> String {
    let category = finding.category.as_deref().unwrap_or("uncategorized");
    let snippet = normalize_snippet(&finding.snippet);
    format!(
        "{}:{}:{}:{}",
        finding.file.to_ascii_lowercase(),
        finding.line,
        category.to_ascii_lowercase(),
        snippet
    )
}

fn normalize_snippet(snippet: &str) -> String {
    snippet
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn baseline_key_for_finding(finding: &Finding) -> String {
    let category = finding.category.as_deref().unwrap_or("uncategorized");
    format!(
        "{}:{}:{}",
        finding.file.to_ascii_lowercase(),
        finding.line,
        category.to_ascii_lowercase()
    )
}

fn filter_findings_against_baseline(
    result: &ScanResult,
    baseline_keys: &HashSet<String>,
) -> (ScanResult, usize) {
    if baseline_keys.is_empty() {
        return (result.clone(), 0);
    }

    let original_total = result.findings.len();
    let findings = result
        .findings
        .iter()
        .filter(|finding| !baseline_keys.contains(&baseline_key_for_finding(finding)))
        .cloned()
        .collect::<Vec<_>>();
    let suppressed = original_total.saturating_sub(findings.len());

    (
        ScanResult {
            summary: summarize_findings(
                &findings,
                result.summary.scanned_files,
                result.summary.matched_rules,
            ),
            findings,
        },
        suppressed,
    )
}

fn load_baseline_keys(path: &Path) -> Result<HashSet<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|err| format!("failed to read baseline {}: {err}", path.display()))?;
    let value: Value = serde_json::from_str(&payload)
        .map_err(|err| format!("invalid baseline JSON {}: {err}", path.display()))?;

    let mut keys = HashSet::new();
    if try_collect_baseline_keys_from_aishield_json(&value, &mut keys) {
        return Ok(keys);
    }
    if try_collect_baseline_keys_from_sarif(&value, &mut keys) {
        return Ok(keys);
    }

    Err(format!(
        "unsupported baseline format in {} (expected AIShield json with `findings` or SARIF with `runs[].results`)",
        path.display()
    ))
}

fn try_collect_baseline_keys_from_aishield_json(value: &Value, out: &mut HashSet<String>) -> bool {
    let Some(findings) = value.get("findings").and_then(Value::as_array) else {
        return false;
    };

    for finding in findings {
        let file = finding
            .get("file")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let line = finding.get("line").and_then(Value::as_u64).unwrap_or(1) as usize;
        let category = finding
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("uncategorized");

        out.insert(format!(
            "{}:{}:{}",
            file.to_ascii_lowercase(),
            line,
            category.to_ascii_lowercase()
        ));
    }

    true
}

fn try_collect_baseline_keys_from_sarif(value: &Value, out: &mut HashSet<String>) -> bool {
    let Some(runs) = value.get("runs").and_then(Value::as_array) else {
        return false;
    };

    let mut saw_result = false;
    for run in runs {
        let results = run
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for result in results {
            saw_result = true;
            let file = result
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|locations| locations.first())
                .and_then(|location| location.get("physicalLocation"))
                .and_then(|physical| physical.get("artifactLocation"))
                .and_then(|artifact| artifact.get("uri"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let line = result
                .get("locations")
                .and_then(Value::as_array)
                .and_then(|locations| locations.first())
                .and_then(|location| location.get("physicalLocation"))
                .and_then(|physical| physical.get("region"))
                .and_then(|region| region.get("startLine"))
                .and_then(Value::as_u64)
                .unwrap_or(1) as usize;
            let category = result
                .get("properties")
                .and_then(|props| props.get("category"))
                .and_then(Value::as_str)
                .unwrap_or("uncategorized");
            out.insert(format!(
                "{}:{}:{}",
                file.to_ascii_lowercase(),
                line,
                category.to_ascii_lowercase()
            ));
        }
    }

    saw_result
}

fn render_table(result: &ScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "AIShield scan complete: {} findings across {} files ({} rules loaded)",
        result.summary.total, result.summary.scanned_files, result.summary.matched_rules
    );

    if result.findings.is_empty() {
        out.push_str("No vulnerabilities detected.\n");
        return out;
    }

    let _ = writeln!(
        out,
        "{:<10} {:<30} {:<32} {:<8} {:<8} {}",
        "Severity", "Rule", "Location", "AI %", "Risk", "Snippet"
    );
    let _ = writeln!(out, "{}", "-".repeat(130));

    for finding in &result.findings {
        let location = format!("{}:{}:{}", finding.file, finding.line, finding.column);
        let _ = writeln!(
            out,
            "{:<10} {:<30} {:<32} {:<8.1} {:<8.1} {}",
            finding.severity.as_str(),
            truncate(&finding.id, 30),
            truncate(&location, 32),
            finding.ai_confidence,
            finding.risk_score,
            truncate(&finding.snippet, 40)
        );
    }

    let _ = writeln!(
        out,
        "Summary: critical={} high={} medium={} low={} info={}",
        result
            .summary
            .by_severity
            .get("critical")
            .copied()
            .unwrap_or(0),
        result.summary.by_severity.get("high").copied().unwrap_or(0),
        result
            .summary
            .by_severity
            .get("medium")
            .copied()
            .unwrap_or(0),
        result.summary.by_severity.get("low").copied().unwrap_or(0),
        result.summary.by_severity.get("info").copied().unwrap_or(0),
    );

    let ai_estimated = result
        .findings
        .iter()
        .filter(|finding| finding.ai_confidence >= 70.0)
        .count();
    let _ = writeln!(
        out,
        "AI-Generated (estimated): {} of {} findings",
        ai_estimated, result.summary.total
    );
    let top_pattern = most_frequent_rule_id(result).unwrap_or_else(|| "none".to_string());
    let _ = writeln!(out, "Top pattern: {}", top_pattern);

    out
}

fn render_github_annotations(result: &ScanResult, output_summary: &OutputSummary) -> String {
    let mut out = String::new();
    if result.findings.is_empty() {
        out.push_str("No vulnerabilities detected.\n");
        return out;
    }

    const GITHUB_ANNOTATION_LIMIT: usize = 200;
    for finding in result.findings.iter().take(GITHUB_ANNOTATION_LIMIT) {
        let level = severity_to_github_annotation_level(finding.severity);
        let title = format!("[{}] {}", finding.id, finding.title);
        let message = format!(
            "{} (AI confidence {:.1}%, risk {:.1})",
            finding.title, finding.ai_confidence, finding.risk_score
        );
        let line = finding.line.max(1);
        let column = finding.column.max(1);

        let _ = writeln!(
            out,
            "::{} file={},line={},col={},title={}::{}",
            level,
            escape_github_annotation_property(&finding.file),
            line,
            column,
            escape_github_annotation_property(&title),
            escape_github_annotation_message(&message)
        );
    }

    if result.findings.len() > GITHUB_ANNOTATION_LIMIT {
        let _ = writeln!(
            out,
            "::notice::AIShield truncated annotations to first {} findings (of {}).",
            GITHUB_ANNOTATION_LIMIT,
            result.findings.len()
        );
    }

    let _ = writeln!(
        out,
        "AIShield summary: total={} dedup_mode={} original_total={} deduped_total={}",
        result.summary.total,
        output_summary.dedup_mode.as_str(),
        output_summary.original_total,
        output_summary.deduped_total
    );

    out
}

fn truncate(input: &str, width: usize) -> String {
    if input.len() <= width {
        return input.to_string();
    }
    format!("{}...", &input[..width.saturating_sub(3)])
}

fn render_json(result: &ScanResult, output_summary: &OutputSummary) -> String {
    let ai_estimated = result
        .findings
        .iter()
        .filter(|finding| finding.ai_confidence >= 70.0)
        .count();
    let top_pattern = most_frequent_rule_id(result).unwrap_or_else(|| "none".to_string());

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"summary\": {\n");
    let _ = writeln!(out, "    \"total\": {},", result.summary.total);
    let _ = writeln!(
        out,
        "    \"scanned_files\": {},",
        result.summary.scanned_files
    );
    let _ = writeln!(
        out,
        "    \"matched_rules\": {},",
        result.summary.matched_rules
    );
    let _ = writeln!(
        out,
        "    \"dedup_mode\": \"{}\",",
        output_summary.dedup_mode.as_str()
    );
    let _ = writeln!(
        out,
        "    \"original_total\": {},",
        output_summary.original_total
    );
    let _ = writeln!(
        out,
        "    \"deduped_total\": {},",
        output_summary.deduped_total
    );
    let _ = writeln!(out, "    \"ai_estimated\": {},", ai_estimated);
    let _ = writeln!(
        out,
        "    \"top_pattern\": \"{}\",",
        escape_json(&top_pattern)
    );
    out.push_str("    \"by_severity\": {\n");

    for (idx, (k, v)) in result.summary.by_severity.iter().enumerate() {
        let suffix = if idx + 1 == result.summary.by_severity.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(out, "      \"{}\": {}{}", escape_json(k), v, suffix);
    }

    out.push_str("    }\n");
    out.push_str("  },\n");
    out.push_str("  \"findings\": [\n");

    for (idx, finding) in result.findings.iter().enumerate() {
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"id\": \"{}\",", escape_json(&finding.id));
        let _ = writeln!(out, "      \"title\": \"{}\",", escape_json(&finding.title));
        let _ = writeln!(
            out,
            "      \"severity\": \"{}\",",
            finding.severity.as_str()
        );
        let _ = writeln!(out, "      \"file\": \"{}\",", escape_json(&finding.file));
        let _ = writeln!(out, "      \"line\": {},", finding.line);
        let _ = writeln!(out, "      \"column\": {},", finding.column);
        let _ = writeln!(
            out,
            "      \"snippet\": \"{}\",",
            escape_json(&finding.snippet)
        );
        let _ = writeln!(
            out,
            "      \"ai_confidence\": {:.1},",
            finding.ai_confidence
        );
        let _ = writeln!(out, "      \"risk_score\": {:.1},", finding.risk_score);
        let _ = writeln!(
            out,
            "      \"category\": {},",
            opt_json_string(finding.category.as_deref())
        );
        let _ = writeln!(
            out,
            "      \"ai_tendency\": {},",
            opt_json_string(finding.ai_tendency.as_deref())
        );
        let _ = writeln!(
            out,
            "      \"fix_suggestion\": {},",
            opt_json_string(finding.fix_suggestion.as_deref())
        );

        out.push_str("      \"tags\": [");
        for (tag_idx, tag) in finding.tags.iter().enumerate() {
            if tag_idx > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "\"{}\"", escape_json(tag));
        }
        out.push_str("]\n");

        if idx + 1 == result.findings.len() {
            out.push_str("    }\n");
        } else {
            out.push_str("    },\n");
        }
    }

    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn render_sarif(result: &ScanResult, output_summary: &OutputSummary) -> String {
    let mut out = String::new();

    let mut rules = BTreeMap::new();
    for finding in &result.findings {
        rules
            .entry(finding.id.clone())
            .or_insert((finding.title.clone(), finding.severity));
    }

    out.push_str("{\n");
    out.push_str("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    out.push_str("  \"version\": \"2.1.0\",\n");
    out.push_str("  \"runs\": [\n");
    out.push_str("    {\n");
    out.push_str("      \"tool\": {\n");
    out.push_str("        \"driver\": {\n");
    out.push_str("          \"name\": \"AIShield\",\n");
    let _ = writeln!(
        out,
        "          \"version\": \"{}\",",
        env!("CARGO_PKG_VERSION")
    );
    out.push_str("          \"informationUri\": \"https://github.com/mackeh/AIShield\",\n");
    out.push_str("          \"rules\": [\n");

    for (idx, (rule_id, (title, severity))) in rules.iter().enumerate() {
        out.push_str("            {\n");
        let _ = writeln!(out, "              \"id\": \"{}\",", escape_json(rule_id));
        let _ = writeln!(out, "              \"name\": \"{}\",", escape_json(rule_id));
        let _ = writeln!(
            out,
            "              \"shortDescription\": {{ \"text\": \"{}\" }},",
            escape_json(title)
        );
        let _ = writeln!(
            out,
            "              \"defaultConfiguration\": {{ \"level\": \"{}\" }}",
            severity_to_sarif_level(*severity)
        );
        if idx + 1 == rules.len() {
            out.push_str("            }\n");
        } else {
            out.push_str("            },\n");
        }
    }

    out.push_str("          ]\n");
    out.push_str("        }\n");
    out.push_str("      },\n");
    out.push_str("      \"properties\": {\n");
    let _ = writeln!(
        out,
        "        \"dedupMode\": \"{}\",",
        output_summary.dedup_mode.as_str()
    );
    let _ = writeln!(
        out,
        "        \"originalTotal\": {},",
        output_summary.original_total
    );
    let _ = writeln!(
        out,
        "        \"dedupedTotal\": {}",
        output_summary.deduped_total
    );
    out.push_str("      },\n");
    out.push_str("      \"results\": [\n");

    for (idx, finding) in result.findings.iter().enumerate() {
        let message = format!(
            "{} (AI confidence {:.1}%, risk {:.1})",
            finding.title, finding.ai_confidence, finding.risk_score
        );

        out.push_str("        {\n");
        let _ = writeln!(
            out,
            "          \"ruleId\": \"{}\",",
            escape_json(&finding.id)
        );
        let _ = writeln!(
            out,
            "          \"level\": \"{}\",",
            severity_to_sarif_level(finding.severity)
        );
        let _ = writeln!(
            out,
            "          \"message\": {{ \"text\": \"{}\" }},",
            escape_json(&message)
        );
        out.push_str("          \"locations\": [\n");
        out.push_str("            {\n");
        out.push_str("              \"physicalLocation\": {\n");
        let _ = writeln!(
            out,
            "                \"artifactLocation\": {{ \"uri\": \"{}\" }},",
            escape_json(&finding.file)
        );
        let _ = writeln!(
            out,
            "                \"region\": {{ \"startLine\": {}, \"startColumn\": {} }}",
            finding.line.max(1),
            finding.column.max(1)
        );
        out.push_str("              }\n");
        out.push_str("            }\n");
        out.push_str("          ],\n");
        out.push_str("          \"properties\": {\n");
        let _ = writeln!(
            out,
            "            \"aiConfidence\": {:.1},",
            finding.ai_confidence
        );
        let _ = writeln!(out, "            \"riskScore\": {:.1},", finding.risk_score);
        let _ = writeln!(
            out,
            "            \"category\": {},",
            opt_json_string(finding.category.as_deref())
        );
        out.push_str("            \"tags\": [");
        for (tag_idx, tag) in finding.tags.iter().enumerate() {
            if tag_idx > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "\"{}\"", escape_json(tag));
        }
        out.push_str("]\n");
        out.push_str("          }\n");
        if idx + 1 == result.findings.len() {
            out.push_str("        }\n");
        } else {
            out.push_str("        },\n");
        }
    }

    out.push_str("      ]\n");
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");

    out
}

fn opt_json_string(value: Option<&str>) -> String {
    match value {
        Some(v) => format!("\"{}\"", escape_json(v)),
        None => "null".to_string(),
    }
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn escape_github_annotation_message(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_github_annotation_property(input: &str) -> String {
    input
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn severity_to_github_annotation_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "notice",
    }
}

fn write_stdout(payload: &str) -> Result<(), String> {
    let mut stdout = io::stdout();
    if let Err(err) = stdout.write_all(payload.as_bytes()) {
        if err.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        return Err(format!("failed writing to stdout: {err}"));
    }
    Ok(())
}

fn parse_list_like(raw: &str) -> Vec<String> {
    let text = raw.trim();
    let inner = if text.starts_with('[') && text.ends_with(']') {
        &text[1..text.len() - 1]
    } else {
        text
    };

    inner
        .split(',')
        .map(strip_quotes)
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
}

fn strip_quotes(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    value
}

fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid bool value `{raw}`")),
    }
}

fn parse_severity_value(raw: &str) -> Result<&'static str, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok("critical"),
        "high" => Ok("high"),
        "medium" => Ok("medium"),
        "low" => Ok("low"),
        "info" => Ok("info"),
        _ => Err("severity must be critical|high|medium|low|info".to_string()),
    }
}

fn slugify_rule_filename(title: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "new-rule".to_string()
    } else {
        trimmed.to_string()
    }
}

fn escape_rule_yaml(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Clone)]
struct AppConfig {
    rules_dir: PathBuf,
    format: OutputFormat,
    dedup_mode: Option<DedupMode>,
    bridge_engines: Vec<BridgeEngine>,
    rules: Vec<String>,
    exclude_paths: Vec<String>,
    ai_only: bool,
    cross_file: bool,
    ai_model: AiClassifierMode,
    onnx_model_path: Option<PathBuf>,
    onnx_manifest_path: Option<PathBuf>,
    ai_calibration: AiCalibrationProfile,
    min_ai_confidence: Option<f32>,
    severity_threshold: Option<SeverityThreshold>,
    fail_on_findings: bool,
    history_file: PathBuf,
    record_history: bool,
    notify_webhook_url: Option<String>,
    notify_min_severity: Option<SeverityThreshold>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::from("rules"),
            format: OutputFormat::Table,
            dedup_mode: None,
            bridge_engines: Vec::new(),
            rules: Vec::new(),
            exclude_paths: Vec::new(),
            ai_only: false,
            cross_file: false,
            ai_model: AiClassifierMode::Heuristic,
            onnx_model_path: None,
            onnx_manifest_path: None,
            ai_calibration: AiCalibrationProfile::Balanced,
            min_ai_confidence: None,
            severity_threshold: None,
            fail_on_findings: false,
            history_file: PathBuf::from(".aishield-history.log"),
            record_history: true,
            notify_webhook_url: None,
            notify_min_severity: None,
        }
    }
}

impl AppConfig {
    fn load_if_exists(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .map_err(|err| format!("failed reading {}: {err}", path.display()))?;
        Self::parse(&content).map_err(|err| format!("invalid config {}: {err}", path.display()))
    }

    fn parse(content: &str) -> Result<Self, String> {
        let mut config = Self::default();

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value_raw)) = line.split_once(':') else {
                continue;
            };

            let key = key.trim();
            let value = value_raw.trim();

            match key {
                "version" => {}
                "rules_dir" => config.rules_dir = PathBuf::from(strip_quotes(value)),
                "format" => config.format = OutputFormat::parse(value)?,
                "dedup_mode" => config.dedup_mode = Some(DedupMode::parse(value)?),
                "bridge_engines" => config.bridge_engines = parse_bridge_engines(value)?,
                "rules" => config.rules = parse_list_like(value),
                "exclude_paths" => config.exclude_paths = parse_list_like(value),
                "ai_only" => config.ai_only = parse_bool(value)?,
                "cross_file" => config.cross_file = parse_bool(value)?,
                "ai_model" => config.ai_model = AiClassifierMode::parse(value)?,
                "onnx_model_path" => {
                    let parsed = strip_quotes(value);
                    if !parsed.trim().is_empty() {
                        config.onnx_model_path = Some(PathBuf::from(parsed));
                    }
                }
                "onnx_manifest_path" => {
                    let parsed = strip_quotes(value);
                    if !parsed.trim().is_empty() {
                        config.onnx_manifest_path = Some(PathBuf::from(parsed));
                    }
                }
                "ai_calibration" => config.ai_calibration = AiCalibrationProfile::parse(value)?,
                "min_ai_confidence" => {
                    config.min_ai_confidence = Some(
                        value
                            .parse::<f32>()
                            .map_err(|_| "invalid min_ai_confidence".to_string())?,
                    )
                }
                "severity_threshold" => {
                    config.severity_threshold = Some(SeverityThreshold::parse(value)?)
                }
                "fail_on_findings" => config.fail_on_findings = parse_bool(value)?,
                "history_file" => config.history_file = PathBuf::from(strip_quotes(value)),
                "record_history" => config.record_history = parse_bool(value)?,
                "notify_webhook_url" => {
                    let parsed = strip_quotes(value);
                    if !parsed.trim().is_empty() {
                        config.notify_webhook_url = Some(parsed);
                    }
                }
                "notify_min_severity" => {
                    config.notify_min_severity = Some(SeverityThreshold::parse(value)?)
                }
                _ => {}
            }
        }

        Ok(config)
    }
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
    Github,
}

impl OutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "github" => Ok(Self::Github),
            _ => Err("format must be table, json, sarif, or github".to_string()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DedupMode {
    None,
    Normalized,
}

impl DedupMode {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "normalized" => Ok(Self::Normalized),
            _ => Err("dedup must be none or normalized".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            DedupMode::None => "none",
            DedupMode::Normalized => "normalized",
        }
    }

    fn default_for_format(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Table => Self::None,
            OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Github => Self::Normalized,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BridgeEngine {
    Semgrep,
    Bandit,
    Eslint,
}

impl BridgeEngine {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "semgrep" => Ok(Self::Semgrep),
            "bandit" => Ok(Self::Bandit),
            "eslint" => Ok(Self::Eslint),
            _ => Err("bridge engine must be semgrep, bandit, eslint, or all".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            BridgeEngine::Semgrep => "semgrep",
            BridgeEngine::Bandit => "bandit",
            BridgeEngine::Eslint => "eslint",
        }
    }
}

#[derive(Clone, Copy)]
enum StatsOutputFormat {
    Table,
    Json,
}

impl StatsOutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            _ => Err("stats format must be table or json".to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum AnalyticsOutputFormat {
    Table,
    Json,
}

impl AnalyticsOutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            _ => Err("analytics format must be table or json".to_string()),
        }
    }
}

#[derive(Clone, Copy)]
enum BenchOutputFormat {
    Table,
    Json,
}

impl BenchOutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            _ => Err("bench format must be table or json".to_string()),
        }
    }
}

#[derive(Clone, Copy)]
enum SeverityThreshold {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityThreshold {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => Err("severity must be critical|high|medium|low|info".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            SeverityThreshold::Critical => "critical",
            SeverityThreshold::High => "high",
            SeverityThreshold::Medium => "medium",
            SeverityThreshold::Low => "low",
            SeverityThreshold::Info => "info",
        }
    }

    fn includes(self, severity: Severity) -> bool {
        severity.rank() >= self.into_severity().rank()
    }

    fn into_severity(self) -> Severity {
        match self {
            SeverityThreshold::Critical => Severity::Critical,
            SeverityThreshold::High => Severity::High,
            SeverityThreshold::Medium => Severity::Medium,
            SeverityThreshold::Low => Severity::Low,
            SeverityThreshold::Info => Severity::Info,
        }
    }
}

#[derive(Clone, Copy)]
enum ScanProfile {
    Strict,
    Pragmatic,
    AiFocus,
}

impl ScanProfile {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "strict" => Ok(Self::Strict),
            "pragmatic" => Ok(Self::Pragmatic),
            "ai_focus" | "ai-focus" | "aifocus" => Ok(Self::AiFocus),
            _ => Err("profile must be strict, pragmatic, or ai-focus".to_string()),
        }
    }
}

fn render_badge(result: &ScanResult) -> String {
    let critical = result.summary.by_severity.get("critical").copied().unwrap_or(0);
    let high = result.summary.by_severity.get("high").copied().unwrap_or(0);
    let medium = result.summary.by_severity.get("medium").copied().unwrap_or(0);
    let low = result.summary.by_severity.get("low").copied().unwrap_or(0);

    let raw_score: i64 =
        100 - (critical as i64 * 25 + high as i64 * 10 + medium as i64 * 3 + low as i64);
    let score = raw_score.clamp(0, 100);

    let (grade, color) = match score {
        95..=100 => ("A+", "brightgreen"),
        85..=94 => ("A", "green"),
        70..=84 => ("B", "yellowgreen"),
        50..=69 => ("C", "yellow"),
        25..=49 => ("D", "orange"),
        _ => ("F", "red"),
    };

    let label = format!("{grade} ({score})");
    let encoded = label.replace(' ', "%20").replace('+', "%2B");
    format!(
        "![AIShield Score](https://img.shields.io/badge/AIShield-{encoded}-{color})"
    )
}

fn render_vibe(result: &ScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n  ___  _____ _____ _     _     _   _ ");
    let _ = writeln!(out, " / _ \\|_   _/  ___| |   (_)   | | | |");
    let _ = writeln!(out, "/ /_\\ \\ | | \\ `--.| |__  _  __| |_| |");
    let _ = writeln!(out, "|  _  | | |  `--. \\ '_ \\| |/ _ \\ | |_| |");
    let _ = writeln!(out, "| | | |_| |_/\\__/ / | | | |  __/ | |_| |");
    let _ = writeln!(out, "\\_| |_/\\___/\\____/|_| |_|_|\\___|_|\\___/ ");
    let _ = writeln!(out, "         VIBE CHECK");
    let _ = writeln!(out);

    let critical = result.summary.by_severity.get("critical").copied().unwrap_or(0);
    let high = result.summary.by_severity.get("high").copied().unwrap_or(0);
    let medium = result.summary.by_severity.get("medium").copied().unwrap_or(0);
    let total = result.summary.total;

    let ai_estimated = result
        .findings
        .iter()
        .filter(|f| f.ai_confidence >= 70.0)
        .count();
    let ai_pct = if total > 0 {
        (ai_estimated as f64 / total as f64 * 100.0) as u64
    } else {
        0
    };

    let message = match (critical, high, total, ai_pct) {
        (0, 0, 0, _) => {
            "Your code is immaculate. Not a single finding. \
             Either you're a security wizard or you haven't written anything yet."
        }
        (0, 0, t, _) if t <= 3 => {
            "Looking pretty clean! Just a few minor notes. \
             Your future self will thank you for fixing them now."
        }
        (0, h, _, _) if h <= 2 => {
            "Not bad! A couple of things to look at, but nothing catastrophic. \
             You're clearly not blindly copy-pasting from ChatGPT."
        }
        (0, h, _, ai) if h <= 5 && ai < 30 => {
            "Some rough edges, but mostly human-written issues. \
             A focused review session should clean these up."
        }
        (c, _, _, ai) if c == 0 && ai > 60 => {
            "The AI wrote most of this, didn't it? No critical issues though, \
             so at least the AI has decent taste. Double-check those high findings."
        }
        (c, _, _, _) if c == 1 => {
            "One critical issue found. Just one. Fix it before you ship and \
             you'll sleep much better tonight."
        }
        (c, h, _, ai) if c >= 2 && c <= 4 && ai > 50 => {
            "Houston, we have a problem. Multiple critical issues and over half \
             look AI-generated. Time for a serious security review."
        }
        (c, _, _, ai) if c > 4 && ai > 50 => {
            "Yikes. Your codebase looks like it was written by GPT-3.5 at 2am \
             after a prompt injection. Drop everything and fix these critical issues."
        }
        (c, h, _, _) if c > 4 => {
            "This is a five-alarm fire. Multiple critical vulnerabilities detected. \
             Do not merge this. Do not pass Go. Do not collect $200."
        }
        _ => {
            "Mixed bag. Some things to fix, some things that are fine. \
             Prioritize the critical and high findings, ignore the rest for now."
        }
    };

    let _ = writeln!(out, "  {message}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  Findings: {} total | {} critical | {} high | {} medium",
        total, critical, high, medium
    );
    let _ = writeln!(
        out,
        "  AI-generated (est.): {}% ({} of {} findings)",
        ai_pct, ai_estimated, total
    );
    let _ = writeln!(
        out,
        "  Files scanned: {} | Rules loaded: {}",
        result.summary.scanned_files, result.summary.matched_rules
    );
    let _ = writeln!(out);

    if !result.findings.is_empty() {
        let _ = writeln!(out, "  Top issues:");
        for (i, f) in result.findings.iter().take(5).enumerate() {
            let ai_tag = if f.ai_confidence >= 70.0 { " [AI]" } else { "" };
            let _ = writeln!(
                out,
                "    {}. [{}] {} ({}:{}){ai_tag}",
                i + 1,
                f.severity.as_str().to_ascii_uppercase(),
                f.title,
                f.file,
                f.line,
            );
        }
        let _ = writeln!(out);
    }

    out
}

// ---------------------------------------------------------------------------
// Signed scan reports: key generation, signing, and verification
// ---------------------------------------------------------------------------

fn run_keys(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    if sub != "generate" {
        return Err("usage: aishield keys generate".to_string());
    }

    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    let key_dir = home.join(".aishield");
    fs::create_dir_all(&key_dir)
        .map_err(|e| format!("failed to create {}: {e}", key_dir.display()))?;

    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let b64 = base64::engine::general_purpose::STANDARD;

    let private_path = key_dir.join("signing-key.pem");
    fs::write(&private_path, b64.encode(signing_key.to_bytes()))
        .map_err(|e| format!("failed to write private key: {e}"))?;

    let public_path = key_dir.join("public-key.pem");
    fs::write(&public_path, b64.encode(verifying_key.to_bytes()))
        .map_err(|e| format!("failed to write public key: {e}"))?;

    // Restrict private key permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&private_path, perms)
            .map_err(|e| format!("failed to set permissions on private key: {e}"))?;
    }

    println!("Signing keypair generated successfully.");
    println!("  Private key: {}", private_path.display());
    println!("  Public key:  {}", public_path.display());
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: aishield verify <report.json> [--key <pubkey-path>]".to_string());
    }

    let report_path = PathBuf::from(&args[0]);

    // Parse optional --key flag
    let mut pubkey_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                pubkey_path = Some(PathBuf::from(
                    args.get(i).ok_or("--key requires a path")?,
                ));
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    let pubkey_path = pubkey_path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".aishield/public-key.pem")
    });

    // Read and parse the report
    let report_raw =
        fs::read_to_string(&report_path).map_err(|e| format!("cannot read report: {e}"))?;
    let mut report: serde_json::Map<String, Value> =
        serde_json::from_str(&report_raw).map_err(|e| format!("invalid JSON report: {e}"))?;

    // Extract the _signature block
    let sig_value = report
        .remove("_signature")
        .ok_or("report does not contain a _signature field")?;
    let sig_obj = sig_value
        .as_object()
        .ok_or("_signature is not a JSON object")?;

    let sig_b64 = sig_obj
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("_signature.signature missing")?;
    let pubkey_b64_from_report = sig_obj
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or("_signature.public_key missing")?;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Decode the signature
    let sig_bytes = b64
        .decode(sig_b64)
        .map_err(|e| format!("invalid base64 signature: {e}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid Ed25519 signature: {e}"))?;

    // Read and decode the public key from file
    let pubkey_pem =
        fs::read_to_string(&pubkey_path).map_err(|e| format!("cannot read public key: {e}"))?;
    let pubkey_bytes = b64
        .decode(pubkey_pem.trim())
        .map_err(|e| format!("invalid base64 public key: {e}"))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("invalid public key: {e}"))?;

    // Verify that the embedded public key matches the file
    let embedded_pubkey_bytes = b64
        .decode(pubkey_b64_from_report)
        .map_err(|e| format!("invalid base64 embedded public key: {e}"))?;
    if embedded_pubkey_bytes != verifying_key.to_bytes() {
        return Err(
            "embedded public key in report does not match the provided key file".to_string(),
        );
    }

    // Recompute the digest over the report body (without _signature)
    let canonical =
        serde_json::to_string(&report).map_err(|e| format!("failed to serialise body: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();

    // Verify
    match verifying_key.verify(&digest, &signature) {
        Ok(()) => {
            println!("Signature verification: PASSED");
            if let Some(ts) = sig_obj.get("timestamp").and_then(|v| v.as_str()) {
                println!("  Signed at: {ts}");
            }
            if let Some(algo) = sig_obj.get("algorithm").and_then(|v| v.as_str()) {
                println!("  Algorithm: {algo}");
            }
            println!("  Public key: {}", pubkey_path.display());
            Ok(())
        }
        Err(e) => Err(format!("Signature verification: FAILED ({e})")),
    }
}

fn sign_scan_output(json_output: &str) -> Result<String, String> {
    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    let private_path = home.join(".aishield/signing-key.pem");

    let b64 = base64::engine::general_purpose::STANDARD;

    // Read and decode the private key
    let key_pem =
        fs::read_to_string(&private_path).map_err(|e| format!("cannot read signing key: {e}"))?;
    let key_bytes = b64
        .decode(key_pem.trim())
        .map_err(|e| format!("invalid base64 signing key: {e}"))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "signing key must be 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    // Compute SHA-256 digest of the original JSON
    let mut hasher = Sha256::new();
    hasher.update(json_output.as_bytes());
    let digest = hasher.finalize();

    // Sign the digest
    let signature = signing_key.sign(&digest);

    // Build the signed output by appending _signature to the existing JSON object
    let mut report: serde_json::Map<String, Value> =
        serde_json::from_str(json_output).map_err(|e| format!("invalid JSON: {e}"))?;

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let sig_obj = serde_json::json!({
        "algorithm": "Ed25519",
        "public_key": b64.encode(verifying_key.to_bytes()),
        "signature": b64.encode(signature.to_bytes()),
        "timestamp": timestamp,
    });

    report.insert("_signature".to_string(), sig_obj);

    serde_json::to_string_pretty(&report).map_err(|e| format!("failed to serialise output: {e}"))
}

// ---------------------------------------------------------------------------
// SBOM (Software Bill of Materials) generation
// ---------------------------------------------------------------------------

struct SbomPackage {
    name: String,
    version: String,
    ecosystem: String,
    manifest_file: String,
}

#[derive(Clone, Copy)]
enum SbomFormat {
    Spdx,
    CycloneDx,
}

impl SbomFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "spdx" => Ok(Self::Spdx),
            "cyclonedx" => Ok(Self::CycloneDx),
            _ => Err("sbom format must be spdx or cyclonedx".to_string()),
        }
    }
}

fn run_sbom(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("sbom requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);
    if !target.exists() {
        return Err(format!("target path does not exist: {}", target.display()));
    }

    let mut sbom_format = SbomFormat::Spdx;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                sbom_format = SbomFormat::parse(
                    args.get(i).ok_or("--format requires a value")?,
                )?;
            }
            "--output" => {
                i += 1;
                output_path = Some(PathBuf::from(
                    args.get(i).ok_or("--output requires a value")?,
                ));
            }
            other => return Err(format!("unknown sbom flag: {other}")),
        }
        i += 1;
    }

    let packages = collect_all_packages(&target);

    if packages.is_empty() {
        eprintln!("No dependency manifests found in {}", target.display());
    }

    let json_output = match sbom_format {
        SbomFormat::Spdx => generate_spdx_json(&packages),
        SbomFormat::CycloneDx => generate_cyclonedx_json(&packages),
    };

    let formatted = serde_json::to_string_pretty(
        &serde_json::from_str::<Value>(&json_output)
            .map_err(|e| format!("internal serialization error: {e}"))?,
    )
    .map_err(|e| format!("internal serialization error: {e}"))?;

    match output_path {
        Some(ref path) => {
            fs::write(path, &formatted)
                .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
            println!("SBOM written to {}", path.display());
        }
        None => {
            write_stdout(&formatted)?;
        }
    }

    println!(
        "\nSBOM generation complete: {} packages from {} manifests",
        packages.len(),
        packages
            .iter()
            .map(|p| p.manifest_file.as_str())
            .collect::<HashSet<_>>()
            .len(),
    );

    Ok(())
}

/// Walk the target directory recursively and collect packages from all recognized
/// dependency manifest files.
fn collect_all_packages(target: &Path) -> Vec<SbomPackage> {
    let manifest_names: &[&str] = &[
        "requirements.txt",
        "package.json",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
    ];

    let mut packages = Vec::new();

    let walker = walkdir::WalkDir::new(target)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walker {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if !manifest_names.contains(&file_name) {
            continue;
        }

        // Skip node_modules, .git, target directories
        let path_str = path.to_string_lossy();
        if path_str.contains("node_modules")
            || path_str.contains("/.git/")
            || path_str.contains("/target/")
        {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = path
            .strip_prefix(target)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let parsed: Vec<(String, String)> = match file_name {
            "requirements.txt" => sbom_parse_requirements_txt(&content),
            "package.json" => sbom_parse_package_json(&content),
            "go.mod" => sbom_parse_go_mod(&content),
            "Cargo.toml" => sbom_parse_cargo_toml_deps(&content),
            "pom.xml" => sbom_parse_pom_xml(&content),
            "build.gradle" => sbom_parse_build_gradle(&content),
            _ => continue,
        };

        let ecosystem = match file_name {
            "requirements.txt" => "pypi",
            "package.json" => "npm",
            "go.mod" => "golang",
            "Cargo.toml" => "cargo",
            "pom.xml" => "maven",
            "build.gradle" => "maven",
            _ => "generic",
        };

        for (name, version) in parsed {
            packages.push(SbomPackage {
                name,
                version,
                ecosystem: ecosystem.to_string(),
                manifest_file: rel_path.clone(),
            });
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// Manifest parsers for SBOM collection
// ---------------------------------------------------------------------------

fn sbom_parse_requirements_txt(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Handle ==, >=, <=, ~=, != version specifiers
        let (name, version) = if let Some(idx) = line.find("==") {
            (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
        } else if let Some(idx) = line.find(">=") {
            (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
        } else if let Some(idx) = line.find("<=") {
            (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
        } else if let Some(idx) = line.find("~=") {
            (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
        } else if let Some(idx) = line.find("!=") {
            (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
        } else {
            // No version constraint -- bare package name
            (line.to_string(), "*".to_string())
        };
        // Strip extras like [security] from package name
        let name = if let Some(bracket) = name.find('[') {
            name[..bracket].trim().to_string()
        } else {
            name
        };
        // Strip environment markers and comments from version
        let version = version
            .split(';')
            .next()
            .unwrap_or(&version)
            .split('#')
            .next()
            .unwrap_or(&version)
            .split(',')
            .next()
            .unwrap_or(&version)
            .trim()
            .to_string();
        if !name.is_empty() {
            packages.push((name, version));
        }
    }
    packages
}

fn sbom_parse_package_json(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let parsed: Result<Value, _> = serde_json::from_str(content);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => return packages,
    };

    for dep_key in &[
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(deps) = value.get(dep_key).and_then(|v| v.as_object()) {
            for (name, version_val) in deps {
                let version = version_val.as_str().unwrap_or("*").to_string();
                // Strip semver range prefixes for a cleaner version
                let version = version
                    .trim_start_matches('^')
                    .trim_start_matches('~')
                    .trim_start_matches(">=")
                    .trim_start_matches("<=")
                    .trim_start_matches('>')
                    .trim_start_matches('<')
                    .trim_start_matches('=')
                    .trim()
                    .to_string();
                packages.push((name.clone(), version));
            }
        }
    }

    packages
}

fn sbom_parse_go_mod(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("require (") || line == "require (" {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }

        let dep_line = if in_require {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };

        // Strip comments
        let dep_line = dep_line.split("//").next().unwrap_or(dep_line).trim();
        let parts: Vec<&str> = dep_line.split_whitespace().collect();
        if parts.len() >= 2 {
            let module = parts[0].to_string();
            let version = parts[1].trim_start_matches('v').to_string();
            packages.push((module, version));
        }
    }

    packages
}

fn sbom_parse_cargo_toml_deps(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();

    let parsed: Result<Value, _> = content.parse::<toml::Value>().map(|v| {
        let s = serde_json::to_string(&v).unwrap_or_default();
        serde_json::from_str(&s).unwrap_or(Value::Null)
    });

    let value = match parsed {
        Ok(v) => v,
        Err(_) => return packages,
    };

    for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = value.get(section).and_then(|v| v.as_object()) {
            for (name, dep_val) in deps {
                let version = if let Some(v) = dep_val.as_str() {
                    v.to_string()
                } else if let Some(obj) = dep_val.as_object() {
                    obj.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_string()
                } else {
                    "*".to_string()
                };
                packages.push((name.clone(), version));
            }
        }
    }

    packages
}

fn sbom_parse_pom_xml(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();

    let mut i = 0;
    let len = content.len();

    while i < len {
        if let Some(dep_start) = content[i..].find("<dependency>") {
            let abs_start = i + dep_start;
            if let Some(dep_end) = content[abs_start..].find("</dependency>") {
                let block = &content[abs_start..abs_start + dep_end + "</dependency>".len()];

                let group_id = sbom_extract_xml_tag(block, "groupId").unwrap_or_default();
                let artifact_id =
                    sbom_extract_xml_tag(block, "artifactId").unwrap_or_default();
                let version =
                    sbom_extract_xml_tag(block, "version").unwrap_or_else(|| "*".to_string());

                if !artifact_id.is_empty() {
                    let name = if group_id.is_empty() {
                        artifact_id
                    } else {
                        format!("{group_id}:{artifact_id}")
                    };
                    packages.push((name, version));
                }

                i = abs_start + dep_end + "</dependency>".len();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    packages
}

fn sbom_extract_xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)?;
    let end = block.find(&close)?;
    if start + open.len() <= end {
        Some(block[start + open.len()..end].trim().to_string())
    } else {
        None
    }
}

fn sbom_parse_build_gradle(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with("//") || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }

        // Common Gradle dependency configurations
        let dep_configs = [
            "implementation",
            "api",
            "compile",
            "testImplementation",
            "testCompile",
            "androidTestImplementation",
            "compileOnly",
            "runtimeOnly",
            "annotationProcessor",
            "kapt",
        ];

        for config in &dep_configs {
            if let Some(rest) = line.strip_prefix(config) {
                let rest = rest.trim();
                // Handle single-quote and double-quote strings, with or without parens
                let dep_str =
                    if (rest.starts_with('\'') || rest.starts_with('"')) && rest.len() > 1 {
                        let quote = rest.as_bytes()[0] as char;
                        let inner = &rest[1..];
                        if let Some(end) = inner.find(quote) {
                            &inner[..end]
                        } else {
                            continue;
                        }
                    } else if (rest.starts_with("(\"") || rest.starts_with("('"))
                        && rest.len() > 2
                    {
                        let quote = rest.as_bytes()[1] as char;
                        let inner = &rest[2..];
                        if let Some(end) = inner.find(quote) {
                            &inner[..end]
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                let parts: Vec<&str> = dep_str.split(':').collect();
                match parts.len() {
                    3 => {
                        let name = format!("{}:{}", parts[0], parts[1]);
                        let version = parts[2].to_string();
                        packages.push((name, version));
                    }
                    2 => {
                        let name = format!("{}:{}", parts[0], parts[1]);
                        packages.push((name, "*".to_string()));
                    }
                    _ => {}
                }
                break;
            }
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON generation
// ---------------------------------------------------------------------------

fn generate_spdx_json(packages: &[SbomPackage]) -> String {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let namespace = format!("https://aishield.dev/sbom/{timestamp_ns}");

    let mut spdx_packages = Vec::new();
    for pkg in packages {
        let spdx_id = format!(
            "SPDXRef-Package-{}-{}",
            sanitize_spdx_id(&pkg.name),
            sanitize_spdx_id(&pkg.version),
        );

        let purl = format!(
            "pkg:{}/{}@{}",
            pkg.ecosystem,
            purl_encode_name(&pkg.name),
            pkg.version,
        );

        let pkg_json = serde_json::json!({
            "SPDXID": spdx_id,
            "name": pkg.name,
            "versionInfo": pkg.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        });

        spdx_packages.push(pkg_json);
    }

    let doc = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "aishield-sbom",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": now,
            "creators": ["Tool: aishield"],
            "licenseListVersion": "3.19"
        },
        "packages": spdx_packages,
    });

    doc.to_string()
}

// ---------------------------------------------------------------------------
// CycloneDX 1.5 JSON generation
// ---------------------------------------------------------------------------

fn generate_cyclonedx_json(packages: &[SbomPackage]) -> String {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut components = Vec::new();
    for pkg in packages {
        let purl = format!(
            "pkg:{}/{}@{}",
            pkg.ecosystem,
            purl_encode_name(&pkg.name),
            pkg.version,
        );

        let comp = serde_json::json!({
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": purl,
        });

        components.push(comp);
    }

    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "AIShield",
                    "name": "aishield",
                    "version": "0.7.0",
                }
            ]
        },
        "components": components,
    });

    doc.to_string()
}

/// Sanitize a string for use as an SPDX identifier (only letters, digits, ., -).
fn sanitize_spdx_id(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Encode a package name for use in a Package URL (purl).
/// For npm scoped packages like @scope/pkg, purl uses %40scope/pkg.
fn purl_encode_name(name: &str) -> String {
    if name.starts_with('@') {
        return name.replacen('@', "%40", 1);
    }
    name.to_string()
}

// ---------------------------------------------------------------------------
// Supply-chain / dependency scanning
// ---------------------------------------------------------------------------

/// A single vulnerability finding tied to a dependency.
#[derive(Clone, Debug)]
struct DepFinding {
    package: String,
    version: String,
    ecosystem: String,
    vuln_id: String,
    summary: String,
    severity: String,
    fixed_version: Option<String>,
    manifest_file: String,
}

/// Deserialized subset of an OSV vulnerability entry.
#[derive(Clone, Debug)]
struct OsvVulnerability {
    id: String,
    summary: String,
    severity: String,
    fixed_version: Option<String>,
}

/// Lightweight client that queries the OSV.dev API.
struct OsvClient {
    http: Client,
    endpoint: String,
}

impl OsvClient {
    fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_else(|_| Client::new()),
            endpoint: "https://api.osv.dev/v1/query".to_string(),
        }
    }

    /// Query OSV for known vulnerabilities affecting `pkg` at `version` in
    /// the given `ecosystem` (e.g. "PyPI", "npm", "Go", "crates.io", "Maven").
    fn query(
        &self,
        pkg: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<OsvVulnerability>, String> {
        let body = serde_json::json!({
            "package": {
                "name": pkg,
                "ecosystem": ecosystem,
            },
            "version": version,
        });

        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .map_err(|e| format!("OSV request failed for {pkg}@{version}: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "OSV returned HTTP {} for {pkg}@{version}",
                resp.status()
            ));
        }

        let json: Value = resp
            .json()
            .map_err(|e| format!("failed to parse OSV response for {pkg}@{version}: {e}"))?;

        let vulns = json
            .get("vulns")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut results = Vec::new();
        for entry in &vulns {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();

            let summary = entry
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Extract severity -- OSV stores it in database_specific or severity array.
            let severity = extract_osv_severity(entry);

            // Try to find a fixed version from the affected[].ranges[].events[].
            let fixed_version = extract_osv_fixed_version(entry);

            results.push(OsvVulnerability {
                id,
                summary,
                severity,
                fixed_version,
            });
        }

        Ok(results)
    }
}

/// Best-effort extraction of a human-readable severity string from an OSV entry.
fn extract_osv_severity(entry: &Value) -> String {
    // First try the top-level severity array (CVSS).
    if let Some(sev_arr) = entry.get("severity").and_then(|v| v.as_array()) {
        for s in sev_arr {
            if let Some(score_str) = s.get("score").and_then(|v| v.as_str()) {
                if let Some(numeric) = parse_cvss_score(score_str) {
                    return cvss_to_label(numeric);
                }
            }
        }
    }
    // Fallback: database_specific.severity
    if let Some(db) = entry.get("database_specific") {
        if let Some(sev) = db.get("severity").and_then(|v| v.as_str()) {
            return sev.to_string();
        }
    }
    "UNKNOWN".to_string()
}

fn parse_cvss_score(vector: &str) -> Option<f64> {
    // Some OSV entries include a separate numeric score. Try parsing as f64.
    vector.parse::<f64>().ok()
}

fn cvss_to_label(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".to_string()
    } else if score >= 7.0 {
        "HIGH".to_string()
    } else if score >= 4.0 {
        "MEDIUM".to_string()
    } else if score > 0.0 {
        "LOW".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

/// Try to extract a "fixed" version from `affected[].ranges[].events[]`.
fn extract_osv_fixed_version(entry: &Value) -> Option<String> {
    let affected = entry.get("affected")?.as_array()?;
    for aff in affected {
        if let Some(ranges) = aff.get("ranges").and_then(|r| r.as_array()) {
            for range in ranges {
                if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                    for event in events {
                        if let Some(fixed) = event.get("fixed").and_then(|v| v.as_str()) {
                            return Some(fixed.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Lockfile / manifest parsers
// ---------------------------------------------------------------------------

/// Map a manifest filename to the OSV ecosystem identifier.
fn ecosystem_for_file(filename: &str) -> &'static str {
    match filename {
        "requirements.txt" | "Pipfile" | "pyproject.toml" => "PyPI",
        "package.json" | "package-lock.json" => "npm",
        "go.mod" => "Go",
        "Cargo.toml" => "crates.io",
        "pom.xml" | "build.gradle" => "Maven",
        _ => "Unknown",
    }
}

/// Parse `requirements.txt` lines of the form `package==version` (or `>=`, `~=`).
fn parse_requirements_txt(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Remove inline comments.
        let line = if let Some(idx) = line.find(" #") {
            line[..idx].trim()
        } else {
            line
        };
        if let Some((name, ver)) = split_requirement(line) {
            deps.push((name.to_lowercase(), ver));
        }
    }
    deps
}

fn split_requirement(line: &str) -> Option<(String, String)> {
    for delim in &["==", ">=", "~=", "<=", "!="] {
        if let Some(idx) = line.find(delim) {
            let name = line[..idx].trim().to_string();
            let ver = line[idx + delim.len()..].trim().to_string();
            // Strip extras e.g. `requests[security]==2.25.0`
            let name = name
                .split('[')
                .next()
                .unwrap_or(&name)
                .trim()
                .to_string();
            if !name.is_empty() && !ver.is_empty() {
                let ver = ver.split(',').next().unwrap_or("").trim().to_string();
                return Some((name, ver));
            }
        }
    }
    None
}

/// Parse `package.json` -- extract from `dependencies` and `devDependencies`.
fn parse_package_json(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    let json: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return deps,
    };
    for section in &["dependencies", "devDependencies"] {
        if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
            for (name, ver_val) in obj {
                if let Some(ver_raw) = ver_val.as_str() {
                    let ver = ver_raw
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim_start_matches(">=")
                        .trim_start_matches('=')
                        .trim()
                        .to_string();
                    if !ver.is_empty() && ver.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                        deps.push((name.clone(), ver));
                    }
                }
            }
        }
    }
    deps
}

/// Parse `go.mod` require blocks.
fn parse_go_mod(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    let mut in_require = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }
        if in_require {
            if trimmed == ")" {
                in_require = false;
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let ver = parts[1]
                    .trim_start_matches('v')
                    .split('+')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() && !ver.is_empty() {
                    deps.push((name, ver));
                }
            }
        } else if trimmed.starts_with("require ") && !trimmed.contains('(') {
            let rest = trimmed.strip_prefix("require ").unwrap_or("").trim();
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let ver = parts[1]
                    .trim_start_matches('v')
                    .split('+')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() && !ver.is_empty() {
                    deps.push((name, ver));
                }
            }
        }
    }
    deps
}

/// Parse `Cargo.toml` [dependencies] (and [dev-dependencies], [build-dependencies]).
fn parse_cargo_toml_deps(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();

    // Try proper TOML parsing first.
    if let Ok(doc) = content.parse::<toml::Value>() {
        for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(table) = doc.get(section).and_then(|v| v.as_table()) {
                for (name, val) in table {
                    let ver = match val {
                        toml::Value::String(s) => s.clone(),
                        toml::Value::Table(t) => t
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        _ => String::new(),
                    };
                    if !ver.is_empty() {
                        let ver = ver
                            .trim_start_matches('^')
                            .trim_start_matches('~')
                            .trim_start_matches(">=")
                            .trim_start_matches('=')
                            .trim()
                            .to_string();
                        deps.push((name.clone(), ver));
                    }
                }
            }
        }
        return deps;
    }

    // Fallback: simple line-based parsing when TOML is malformed.
    let mut in_deps = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[dependencies]")
            || trimmed.starts_with("[dev-dependencies]")
            || trimmed.starts_with("[build-dependencies]")
        {
            in_deps = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_deps = false;
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_idx) = trimmed.find('=') {
            let name = trimmed[..eq_idx].trim().to_string();
            let rest = trimmed[eq_idx + 1..].trim();
            if rest.starts_with('{') {
                if let Some(ver_start) = rest.find("version") {
                    let after = &rest[ver_start..];
                    if let Some(q1) = after.find('"') {
                        let after_q1 = &after[q1 + 1..];
                        if let Some(q2) = after_q1.find('"') {
                            let ver = after_q1[..q2].to_string();
                            let ver = ver
                                .trim_start_matches('^')
                                .trim_start_matches('~')
                                .trim()
                                .to_string();
                            if !ver.is_empty() {
                                deps.push((name, ver));
                            }
                        }
                    }
                }
            } else {
                let ver = rest.trim_matches('"').to_string();
                let ver = ver
                    .trim_start_matches('^')
                    .trim_start_matches('~')
                    .trim()
                    .to_string();
                if !ver.is_empty() && !name.is_empty() {
                    deps.push((name, ver));
                }
            }
        }
    }

    deps
}

/// Parse a `Pipfile` to extract [packages] and [dev-packages].
fn parse_pipfile(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    let mut in_packages = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[packages]" || trimmed == "[dev-packages]" {
            in_packages = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_packages = false;
            continue;
        }
        if !in_packages || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_idx) = trimmed.find('=') {
            let name = trimmed[..eq_idx].trim().to_string();
            let rest = trimmed[eq_idx + 1..].trim();
            let ver = rest
                .trim_matches('"')
                .trim_start_matches("==")
                .trim_start_matches(">=")
                .trim_start_matches("~=")
                .trim_start_matches('*')
                .trim()
                .to_string();
            if !name.is_empty() && !ver.is_empty() && ver != "*" {
                deps.push((name, ver));
            }
        }
    }
    deps
}

/// Parse `pyproject.toml` project.dependencies list.
fn parse_pyproject_toml(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    if let Ok(doc) = content.parse::<toml::Value>() {
        // PEP 621: [project] dependencies = [...]
        if let Some(arr) = doc
            .get("project")
            .and_then(|p| p.get("dependencies"))
            .and_then(|d| d.as_array())
        {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if let Some((name, ver)) = split_requirement(s) {
                        deps.push((name, ver));
                    }
                }
            }
        }
        // Poetry: [tool.poetry.dependencies]
        if let Some(table) = doc
            .get("tool")
            .and_then(|t| t.get("poetry"))
            .and_then(|p| p.get("dependencies"))
            .and_then(|d| d.as_table())
        {
            for (name, val) in table {
                if name == "python" {
                    continue;
                }
                let ver = match val {
                    toml::Value::String(s) => s
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim()
                        .to_string(),
                    toml::Value::Table(t) => t
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim()
                        .to_string(),
                    _ => String::new(),
                };
                if !ver.is_empty() {
                    deps.push((name.clone(), ver));
                }
            }
        }
    }
    deps
}

/// Simple pom.xml parser for <dependency> blocks.
fn parse_pom_xml(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    let mut group_id = String::new();
    let mut artifact_id = String::new();
    let mut version = String::new();
    let mut in_dependency = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<dependency>") {
            in_dependency = true;
            group_id.clear();
            artifact_id.clear();
            version.clear();
            continue;
        }
        if trimmed.contains("</dependency>") {
            if in_dependency && !artifact_id.is_empty() && !version.is_empty() {
                let name = if group_id.is_empty() {
                    artifact_id.clone()
                } else {
                    format!("{}:{}", group_id, artifact_id)
                };
                if !version.starts_with('$') {
                    deps.push((name, version.clone()));
                }
            }
            in_dependency = false;
            continue;
        }
        if in_dependency {
            if let Some(val) = extract_xml_tag_value(trimmed, "groupId") {
                group_id = val;
            }
            if let Some(val) = extract_xml_tag_value(trimmed, "artifactId") {
                artifact_id = val;
            }
            if let Some(val) = extract_xml_tag_value(trimmed, "version") {
                version = val;
            }
        }
    }
    deps
}

fn extract_xml_tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = line.find(&open) {
        let after = &line[start + open.len()..];
        if let Some(end) = after.find(&close) {
            let val = after[..end].trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Simple build.gradle parser for dependency declarations.
fn parse_build_gradle(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();
    let configs = [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testRuntimeOnly",
    ];
    for line in content.lines() {
        let trimmed = line.trim();
        for cfg in &configs {
            if trimmed.starts_with(cfg) {
                let rest = trimmed[cfg.len()..].trim();
                let rest = rest
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim_matches('\'')
                    .trim_matches('"')
                    .trim();
                let parts: Vec<&str> = rest.split(':').collect();
                if parts.len() == 3 {
                    let name = format!("{}:{}", parts[0], parts[1]);
                    let ver = parts[2].to_string();
                    if !ver.is_empty() && !ver.starts_with('$') {
                        deps.push((name, ver));
                    }
                }
            }
        }
    }
    deps
}

// ---------------------------------------------------------------------------
// Core dependency scanning logic
// ---------------------------------------------------------------------------

const MANIFEST_FILES: &[&str] = &[
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
];

/// Scan `target` directory for dependency manifests and query OSV for each package.
fn scan_dependencies(target: &Path) -> Result<Vec<DepFinding>, String> {
    let osv = OsvClient::new();
    let mut findings: Vec<DepFinding> = Vec::new();

    for manifest in MANIFEST_FILES {
        let manifest_path = target.join(manifest);
        if !manifest_path.is_file() {
            continue;
        }

        let content = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("failed to read {}: {e}", manifest_path.display()))?;

        let packages = parse_manifest(manifest, &content);
        let ecosystem = ecosystem_for_file(manifest);

        eprintln!(
            "  [deps] {} -> {} packages (ecosystem: {})",
            manifest,
            packages.len(),
            ecosystem
        );

        for (name, version) in &packages {
            match osv.query(name, version, ecosystem) {
                Ok(vulns) => {
                    for v in vulns {
                        findings.push(DepFinding {
                            package: name.clone(),
                            version: version.clone(),
                            ecosystem: ecosystem.to_string(),
                            vuln_id: v.id,
                            summary: v.summary,
                            severity: v.severity,
                            fixed_version: v.fixed_version,
                            manifest_file: manifest.to_string(),
                        });
                    }
                }
                Err(e) => {
                    eprintln!("  [deps] warning: {e}");
                }
            }
        }
    }

    Ok(findings)
}

fn parse_manifest(filename: &str, content: &str) -> Vec<(String, String)> {
    match filename {
        "requirements.txt" => parse_requirements_txt(content),
        "Pipfile" => parse_pipfile(content),
        "pyproject.toml" => parse_pyproject_toml(content),
        "package.json" | "package-lock.json" => parse_package_json(content),
        "go.mod" => parse_go_mod(content),
        "Cargo.toml" => parse_cargo_toml_deps(content),
        "pom.xml" => parse_pom_xml(content),
        "build.gradle" => parse_build_gradle(content),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// deps CLI entry-point
// ---------------------------------------------------------------------------

fn run_deps(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "deps requires a target path\nUsage: aishield deps <path> [--format table|json]"
                .to_string(),
        );
    }

    let target = PathBuf::from(&args[0]);
    if !target.is_dir() {
        return Err(format!("{} is not a directory", target.display()));
    }

    let mut format = OutputFormat::Table;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                let raw = args.get(i).ok_or("--format requires a value")?;
                format = match raw.as_str() {
                    "table" => OutputFormat::Table,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "unsupported deps format `{other}` (use table or json)"
                        ))
                    }
                };
            }
            other => return Err(format!("unknown option `{other}`")),
        }
        i += 1;
    }

    eprintln!("Scanning dependencies in {} ...", target.display());
    let start = Instant::now();
    let findings = scan_dependencies(&target)?;
    let elapsed = start.elapsed();

    match format {
        OutputFormat::Table => print_deps_table(&findings, elapsed),
        OutputFormat::Json => print_deps_json(&findings, elapsed),
        _ => print_deps_table(&findings, elapsed),
    }

    if findings.is_empty() {
        eprintln!("\nNo known vulnerabilities found.");
    } else {
        eprintln!(
            "\nFound {} vulnerabilit{} across dependencies.",
            findings.len(),
            if findings.len() == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

fn print_deps_table(findings: &[DepFinding], elapsed: Duration) {
    if findings.is_empty() {
        println!("No vulnerabilities found ({:.2}s)", elapsed.as_secs_f64());
        return;
    }

    println!(
        "{:<30} {:<12} {:<10} {:<18} {:<10} {:<14} {}",
        "PACKAGE", "VERSION", "ECOSYSTEM", "VULN ID", "SEVERITY", "FIXED IN", "MANIFEST"
    );
    println!("{}", "-".repeat(120));

    for f in findings {
        let fixed = f.fixed_version.as_deref().unwrap_or("-");
        println!(
            "{:<30} {:<12} {:<10} {:<18} {:<10} {:<14} {}",
            deps_truncate(&f.package, 29),
            deps_truncate(&f.version, 11),
            deps_truncate(&f.ecosystem, 9),
            deps_truncate(&f.vuln_id, 17),
            deps_truncate(&f.severity, 9),
            deps_truncate(fixed, 13),
            f.manifest_file,
        );
    }

    let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings {
        *by_sev.entry(f.severity.as_str()).or_insert(0) += 1;
    }
    println!(
        "\n{} vulnerabilities found in {:.2}s",
        findings.len(),
        elapsed.as_secs_f64()
    );
    let sev_parts: Vec<String> = by_sev.iter().map(|(k, v)| format!("{v} {k}")).collect();
    println!("  Breakdown: {}", sev_parts.join(", "));
}

fn print_deps_json(findings: &[DepFinding], elapsed: Duration) {
    let entries: Vec<Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "vuln_id": f.vuln_id,
                "summary": f.summary,
                "severity": f.severity,
                "fixed_version": f.fixed_version,
                "manifest_file": f.manifest_file,
            })
        })
        .collect();

    let output = serde_json::json!({
        "vulnerabilities": entries,
        "total": findings.len(),
        "elapsed_secs": elapsed.as_secs_f64(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
    );
}

fn deps_truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use aishield_core::{AiCalibrationProfile, AiClassifierMode};
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        apply_replacements, autofix_replacements, build_webhook_payload, count_replacements,
        dedup_machine_output, empty_summary, enrich_finding_compliance_metadata,
        escape_github_annotation_message, escape_github_annotation_property,
        filter_findings_against_baseline, filtered_candidate_indices, init_template_writes,
        load_baseline_keys, load_onnx_manifest, maybe_send_webhook_notification, normalize_snippet,
        parse_fix_target_spec, parse_init_templates, percentile, render_github_annotations,
        render_sarif, resolve_ai_classifier, resolve_selected_indices, AnalyticsOutputFormat,
        DedupMode, Finding, InitTemplate, OutputSummary, ScanResult, Severity, SeverityThreshold,
    };

    fn finding(
        id: &str,
        severity: Severity,
        file: &str,
        line: usize,
        snippet: &str,
        risk_score: f32,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            title: id.to_string(),
            severity,
            file: file.to_string(),
            line,
            column: 1,
            snippet: snippet.to_string(),
            ai_confidence: 80.0,
            risk_score,
            category: Some("auth".to_string()),
            cwe_id: None,
            owasp_category: None,
            tags: vec!["auth".to_string()],
            ai_tendency: None,
            fix_suggestion: None,
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            summary: empty_summary(1, 1),
            findings,
        }
    }

    #[test]
    fn enriches_sql_injection_with_specific_cwe_and_owasp() {
        let mut candidate = finding(
            "AISHIELD-GO-INJ-003",
            Severity::High,
            "src/db.go",
            42,
            "query := \"SELECT * FROM users WHERE id = \" + userInput",
            85.0,
        );
        candidate.category = Some("injection".to_string());
        candidate.tags = vec!["injection".to_string(), "sql-injection".to_string()];

        let (cwe_id, owasp_category) = enrich_finding_compliance_metadata(&candidate);
        assert_eq!(cwe_id.as_deref(), Some("CWE-89"));
        assert_eq!(owasp_category.as_deref(), Some("A03:2021 - Injection"));
    }

    #[test]
    fn explicit_rule_metadata_takes_precedence_over_heuristics() {
        let mut candidate = finding(
            "AISHIELD-GO-INJ-003",
            Severity::High,
            "src/db.go",
            42,
            "query := \"SELECT * FROM users WHERE id = \" + userInput",
            85.0,
        );
        candidate.category = Some("injection".to_string());
        candidate.tags = vec!["injection".to_string(), "sql-injection".to_string()];
        candidate.cwe_id = Some("CWE-999".to_string());
        candidate.owasp_category = Some("A00:Custom".to_string());

        let (cwe_id, owasp_category) = enrich_finding_compliance_metadata(&candidate);
        assert_eq!(cwe_id.as_deref(), Some("CWE-999"));
        assert_eq!(owasp_category.as_deref(), Some("A00:Custom"));
    }

    #[test]
    fn enriches_from_category_when_tags_are_missing() {
        let mut candidate = finding(
            "AISHIELD-PY-MISC-001",
            Severity::Medium,
            "src/app.py",
            12,
            "app.run(debug=True)",
            70.0,
        );
        candidate.category = Some("misconfig".to_string());
        candidate.tags = vec![];

        let (cwe_id, owasp_category) = enrich_finding_compliance_metadata(&candidate);
        assert_eq!(cwe_id.as_deref(), Some("CWE-16"));
        assert_eq!(
            owasp_category.as_deref(),
            Some("A05:2021 - Security Misconfiguration")
        );
    }

    #[test]
    fn enriches_from_rule_id_when_category_is_absent() {
        let mut candidate = finding(
            "AISHIELD-JAVA-CRYPTO-001",
            Severity::High,
            "src/CryptoUtil.java",
            8,
            "MessageDigest.getInstance(\"MD5\")",
            83.0,
        );
        candidate.category = None;
        candidate.tags = vec![];

        let (cwe_id, owasp_category) = enrich_finding_compliance_metadata(&candidate);
        assert_eq!(cwe_id.as_deref(), Some("CWE-327"));
        assert_eq!(
            owasp_category.as_deref(),
            Some("A02:2021 - Cryptographic Failures")
        );
    }

    #[test]
    fn normalized_dedup_keeps_highest_risk_finding_per_key() {
        let raw = result(vec![
            finding(
                "AISHIELD-PY-AUTH-001",
                Severity::Medium,
                "src/app.py",
                10,
                "if secret == provided:",
                60.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-099",
                Severity::High,
                "src/app.py",
                10,
                "if secret==provided:",
                90.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-100",
                Severity::High,
                "src/app.py",
                11,
                "if secret == provided:",
                88.0,
            ),
        ]);

        let deduped = dedup_machine_output(&raw, DedupMode::Normalized);

        assert_eq!(deduped.findings.len(), 2);
        assert!(deduped
            .findings
            .iter()
            .any(|f| f.id == "AISHIELD-PY-AUTH-099"));
        assert!(deduped
            .findings
            .iter()
            .any(|f| f.id == "AISHIELD-PY-AUTH-100"));
        assert_eq!(deduped.summary.total, 2);
    }

    #[test]
    fn none_dedup_mode_keeps_original_findings() {
        let raw = result(vec![
            finding(
                "AISHIELD-PY-AUTH-001",
                Severity::Medium,
                "src/app.py",
                10,
                "if secret == provided:",
                60.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-099",
                Severity::High,
                "src/app.py",
                10,
                "if secret==provided:",
                90.0,
            ),
        ]);

        let deduped = dedup_machine_output(&raw, DedupMode::None);

        assert_eq!(deduped.findings.len(), raw.findings.len());
    }

    #[test]
    fn baseline_filter_removes_existing_findings() {
        let raw = result(vec![
            finding(
                "AISHIELD-PY-AUTH-001",
                Severity::High,
                "src/app.py",
                10,
                "if secret == provided:",
                80.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-002",
                Severity::High,
                "src/app.py",
                11,
                "jwt.decode(token, options={\"verify_signature\": False})",
                79.0,
            ),
        ]);

        let mut baseline = std::collections::HashSet::new();
        baseline.insert("src/app.py:10:auth".to_string());

        let (filtered, suppressed) = filter_findings_against_baseline(&raw, &baseline);
        assert_eq!(suppressed, 1);
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].id, "AISHIELD-PY-AUTH-002");
    }

    #[test]
    fn load_baseline_keys_supports_aishield_json() {
        let path = temp_path("aishield-baseline-json").with_extension("json");
        fs::write(
            &path,
            r#"{
  "summary": {"total": 1},
  "findings": [
    {
      "id": "AISHIELD-PY-AUTH-001",
      "file": "src/app.py",
      "line": 10,
      "category": "auth",
      "snippet": "if secret == provided:"
    }
  ]
}"#,
        )
        .expect("write baseline file");

        let keys = load_baseline_keys(&path).expect("load baseline keys");
        assert!(keys.contains("src/app.py:10:auth"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_baseline_keys_supports_sarif() {
        let path = temp_path("aishield-baseline-sarif").with_extension("sarif");
        fs::write(
            &path,
            r#"{
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "AISHIELD-PY-AUTH-001",
          "message": {"text": "Timing-Unsafe Secret Comparison"},
          "properties": {"category": "auth"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 10}
              }
            }
          ]
        }
      ]
    }
  ]
}"#,
        )
        .expect("write sarif baseline");

        let keys = load_baseline_keys(&path).expect("load sarif baseline keys");
        assert!(keys.contains("src/app.py:10:auth"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn webhook_payload_includes_alert_summary_fields() {
        let scan = result(vec![finding(
            "AISHIELD-PY-AUTH-001",
            Severity::High,
            "src/app.py",
            10,
            "if secret == provided:",
            88.0,
        )]);

        let payload = build_webhook_payload(
            Path::new("."),
            SeverityThreshold::High,
            &scan,
            &scan.findings,
        );

        assert_eq!(
            payload.get("event").and_then(Value::as_str),
            Some("aishield.scan.completed")
        );
        assert_eq!(
            payload
                .get("summary")
                .and_then(|s| s.get("alert_findings"))
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            payload.get("notify_min_severity").and_then(Value::as_str),
            Some("high")
        );
    }

    #[test]
    fn webhook_notification_skips_when_no_matching_severity() {
        let scan = result(vec![finding(
            "AISHIELD-PY-MISC-001",
            Severity::Low,
            "src/app.py",
            10,
            "debug = true",
            40.0,
        )]);

        let outcome = maybe_send_webhook_notification(
            "http://127.0.0.1:9",
            SeverityThreshold::High,
            Path::new("."),
            &scan,
        );

        assert!(outcome.is_ok());
    }

    #[test]
    fn snippet_normalization_collapses_whitespace_and_punctuation() {
        assert_eq!(
            normalize_snippet("if secret==provided:"),
            normalize_snippet("if   secret == provided ;")
        );
    }

    #[test]
    fn github_annotation_escape_encodes_special_characters() {
        assert_eq!(escape_github_annotation_message("a%b\r\nc"), "a%25b%0D%0Ac");
        assert_eq!(
            escape_github_annotation_property("src/a:b,c%"),
            "src/a%3Ab%2Cc%25"
        );
    }

    #[test]
    fn github_render_outputs_annotation_lines() {
        let raw = result(vec![finding(
            "AISHIELD-PY-AUTH-001",
            Severity::High,
            "src/app.py",
            10,
            "if secret == provided:",
            88.0,
        )]);
        let summary = OutputSummary {
            dedup_mode: DedupMode::Normalized,
            original_total: 1,
            deduped_total: 1,
        };

        let rendered = render_github_annotations(&raw, &summary);
        assert!(
            rendered.contains("::error file=src/app.py,line=10,col=1,title=[AISHIELD-PY-AUTH-001]")
        );
        assert!(rendered.contains("AIShield summary:"));
        assert!(rendered.contains("dedup_mode=normalized"));
    }

    #[test]
    fn bridge_engine_parser_supports_all_alias_and_empty_list() {
        let engines = super::parse_bridge_engines("all").expect("parse all");
        let values = engines.iter().map(|e| e.as_str()).collect::<Vec<_>>();
        assert_eq!(values, vec!["semgrep", "bandit", "eslint"]);

        let empty = super::parse_bridge_engines("[]").expect("parse empty list");
        assert!(empty.is_empty());
    }

    #[test]
    fn bridge_engine_parser_rejects_invalid_engine() {
        let err = super::parse_bridge_engines("foo").expect_err("should reject invalid bridge");
        assert!(err.contains("bridge engine"));
    }

    #[test]
    fn init_template_parser_supports_all_alias() {
        let templates = parse_init_templates("all").expect("parse all init templates");
        let values = templates.iter().map(|t| t.as_str()).collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                "config",
                "github-actions",
                "gitlab-ci",
                "bitbucket-pipelines",
                "circleci",
                "jenkins",
                "vscode",
                "pre-commit"
            ]
        );
    }

    #[test]
    fn init_template_parser_dedups_entries() {
        let templates = parse_init_templates("config,circleci,circleci,pre-commit")
            .expect("parse dedup init templates");
        let values = templates.iter().map(|t| t.as_str()).collect::<Vec<_>>();
        assert_eq!(values, vec!["config", "circleci", "pre-commit"]);
    }

    #[test]
    fn init_template_parser_rejects_unknown_values() {
        let err = parse_init_templates("config,unknown").expect_err("should reject unknown");
        assert!(err.contains("unknown init template"));
    }

    #[test]
    fn init_template_writes_include_expected_paths() {
        let writes = init_template_writes(
            &[
                InitTemplate::Config,
                InitTemplate::VsCode,
                InitTemplate::PreCommit,
            ],
            Path::new(".aishield-custom.yml"),
        );
        let paths = writes
            .iter()
            .map(|(path, _)| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(paths.contains(&".aishield-custom.yml".to_string()));
        assert!(paths.contains(&".vscode/extensions.json".to_string()));
        assert!(paths.contains(&".vscode/tasks.json".to_string()));
        assert!(paths.contains(&".pre-commit-config.yaml".to_string()));
    }

    #[test]
    fn init_template_writes_include_ci_ecosystem_paths() {
        let writes = init_template_writes(
            &[
                InitTemplate::BitbucketPipelines,
                InitTemplate::CircleCi,
                InitTemplate::Jenkins,
            ],
            Path::new(".aishield.yml"),
        );
        let paths = writes
            .iter()
            .map(|(path, _)| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"bitbucket-pipelines.yml".to_string()));
        assert!(paths.contains(&".circleci/config.yml".to_string()));
        assert!(paths.contains(&"Jenkinsfile".to_string()));
    }

    #[test]
    fn github_actions_template_uses_hardened_sarif_upload_flow() {
        let template = super::init_github_actions_template();
        assert!(template.contains("concurrency:"));
        assert!(template.contains("upload-sarif:"));
        assert!(template.contains("actions/upload-artifact@v4"));
        assert!(template.contains("actions/download-artifact@v4"));
        assert!(template.contains("github/codeql-action/upload-sarif@v4"));
    }

    #[test]
    fn gitlab_ci_template_has_cache_sast_report_and_mr_diff_scan() {
        let template = super::init_gitlab_ci_template();
        assert!(template.contains("aishield-cache"));
        assert!(template.contains("sast: aishield.sarif"));
        assert!(template.contains("CI_MERGE_REQUEST_DIFF_BASE_SHA"));
        assert!(template.contains("--fail-on-findings"));
        assert!(template.contains("AISHIELD_ENABLE_BRIDGE"));
    }

    #[test]
    fn bitbucket_pipelines_template_has_pr_diff_scan_and_bridge_pipeline() {
        let template = super::init_bitbucket_pipelines_template();
        assert!(template.contains("BITBUCKET_PR_DESTINATION_BRANCH"));
        assert!(template.contains("--fail-on-findings"));
        assert!(template.contains("bridge-scan:"));
        assert!(template.contains("--bridge all"));
        assert!(template.contains("cargo:"));
    }

    #[test]
    fn init_config_template_sets_cross_file_disabled_by_default() {
        let template = super::init_config_template();
        assert!(template.contains("cross_file: false"));
        assert!(template.contains("ai_model: heuristic"));
        assert!(template.contains("onnx_model_path: \"\""));
        assert!(template.contains("onnx_manifest_path: \"\""));
        assert!(template.contains("ai_calibration: balanced"));
    }

    #[test]
    fn app_config_parser_supports_cross_file_and_ai_model_flags() {
        let config = super::AppConfig::parse(
            r#"
version: 1
rules_dir: rules
format: table
cross_file: true
ai_model: onnx
onnx_model_path: models/aishield.onnx
onnx_manifest_path: models/ai-classifier/model-manifest.json
ai_calibration: aggressive
"#,
        )
        .expect("parse config");

        assert!(config.cross_file);
        assert_eq!(config.ai_model, AiClassifierMode::Onnx);
        assert_eq!(
            config.onnx_model_path,
            Some(PathBuf::from("models/aishield.onnx"))
        );
        assert_eq!(
            config.onnx_manifest_path,
            Some(PathBuf::from("models/ai-classifier/model-manifest.json"))
        );
        assert_eq!(config.ai_calibration, AiCalibrationProfile::Aggressive);
    }

    #[test]
    fn resolve_ai_classifier_keeps_heuristic_mode() {
        let resolved = resolve_ai_classifier(
            AiClassifierMode::Heuristic,
            None,
            None,
            AiCalibrationProfile::Balanced,
        );
        assert_eq!(resolved.mode, AiClassifierMode::Heuristic);
        assert_eq!(resolved.onnx_model_path, None);
    }

    #[test]
    fn resolve_ai_classifier_falls_back_on_missing_onnx_path() {
        let resolved = resolve_ai_classifier(
            AiClassifierMode::Onnx,
            None,
            None,
            AiCalibrationProfile::Balanced,
        );
        assert_eq!(resolved.mode, AiClassifierMode::Heuristic);
        assert_eq!(resolved.onnx_model_path, None);
    }

    #[test]
    fn load_onnx_manifest_parses_model_and_calibration_fields() {
        let temp = std::env::temp_dir().join("aishield-onnx-manifest-test.json");
        fs::write(
            &temp,
            r#"{
  "schema_version": 1,
  "model": { "path": "models/model.onnx" },
  "calibration": {
    "profile": "conservative",
    "onnx_weight": 0.6,
    "heuristic_weight": 0.4,
    "probability_scale": 0.95,
    "probability_bias": -0.02
  }
}"#,
        )
        .expect("write manifest");

        let parsed = load_onnx_manifest(&temp).expect("parse manifest");
        assert!(parsed.model_path.is_some());
        assert_eq!(
            parsed.calibration_profile,
            Some(AiCalibrationProfile::Conservative)
        );
        assert_eq!(parsed.onnx_weight, Some(0.6));
        assert_eq!(parsed.heuristic_weight, Some(0.4));
        assert_eq!(parsed.probability_scale, Some(0.95));
        assert_eq!(parsed.probability_bias, Some(-0.02));

        let _ = fs::remove_file(temp);
    }

    #[test]
    fn resolve_ai_classifier_uses_manifest_model_when_model_not_set() {
        let root = std::env::temp_dir().join("aishield-onnx-manifest-resolve");
        let _ = fs::create_dir_all(root.join("models"));
        let manifest = root.join("manifest.json");
        let model = root.join("models/model.onnx");
        fs::write(&model, vec![0u8; 128]).expect("write model");
        fs::write(
            &manifest,
            r#"{
  "schema_version": 1,
  "model": { "path": "models/model.onnx" },
  "calibration": { "onnx_weight": 0.8, "heuristic_weight": 0.2 }
}"#,
        )
        .expect("write manifest");

        let resolved = resolve_ai_classifier(
            AiClassifierMode::Onnx,
            None,
            Some(&manifest),
            AiCalibrationProfile::Balanced,
        );
        if cfg!(feature = "onnx") {
            assert_eq!(resolved.mode, AiClassifierMode::Onnx);
            assert_eq!(resolved.onnx_model_path, Some(model));
        } else {
            assert_eq!(resolved.mode, AiClassifierMode::Heuristic);
            assert_eq!(resolved.onnx_model_path, None);
        }
        assert!(resolved.calibration.onnx_weight >= 0.7);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sarif_region_clamps_line_and_column_to_one() {
        let raw = result(vec![Finding {
            id: "SAST-BRIDGE-TEST".to_string(),
            title: "Bridge Test".to_string(),
            severity: Severity::Medium,
            file: "src/app.py".to_string(),
            line: 0,
            column: 0,
            snippet: "print('x')".to_string(),
            ai_confidence: 30.0,
            risk_score: 65.0,
            category: Some("sast-bridge".to_string()),
            cwe_id: None,
            owasp_category: None,
            tags: vec!["sast-bridge".to_string()],
            ai_tendency: None,
            fix_suggestion: None,
        }]);
        let summary = OutputSummary {
            dedup_mode: DedupMode::Normalized,
            original_total: 1,
            deduped_total: 1,
        };

        let sarif = render_sarif(&raw, &summary);
        assert!(sarif.contains("\"startLine\": 1, \"startColumn\": 1"));
    }

    #[test]
    fn percentile_uses_linear_interpolation() {
        let samples = vec![10.0, 20.0, 30.0, 40.0];
        let p50 = percentile(&samples, 0.5);
        let p95 = percentile(&samples, 0.95);
        assert!((p50 - 25.0).abs() < f64::EPSILON);
        assert!((p95 - 38.5).abs() < 0.0001);
    }

    #[test]
    fn analytics_output_format_parser_supports_table_and_json() {
        assert!(matches!(
            AnalyticsOutputFormat::parse("table"),
            Ok(AnalyticsOutputFormat::Table)
        ));
        assert!(matches!(
            AnalyticsOutputFormat::parse("json"),
            Ok(AnalyticsOutputFormat::Json)
        ));
    }

    #[test]
    fn analytics_output_format_parser_rejects_invalid_values() {
        let err = AnalyticsOutputFormat::parse("yaml").expect_err("should reject invalid format");
        assert!(err.contains("analytics format"));
    }

    #[test]
    fn analytics_summary_table_renders_hotspot_and_coverage_fields() {
        let summary = serde_json::json!({
            "summary": {
                "total_scans": 3,
                "total_findings": 12,
                "critical": 1,
                "high": 4,
                "medium": 5,
                "low": 2,
                "ai_ratio": 0.5
            },
            "trend": {
                "findings_delta_pct": 12.0,
                "scans_delta_pct": 8.0,
                "ai_ratio_delta_pct": -2.5
            },
            "top_rules": [
                { "rule_id": "AISHIELD-PY-CRYPTO-001", "count": 4 }
            ]
        });
        let gaps = serde_json::json!({
            "summary": {
                "coverage_pct": 92.5,
                "classified_findings": 11,
                "total_findings": 12
            },
            "top_cwe": [
                { "key": "CWE-79", "count": 5 }
            ],
            "top_owasp": [
                { "key": "A03:2021 - Injection", "count": 5 }
            ]
        });
        let query = super::analytics_client::AnalyticsQuery {
            org_id: Some("acme".to_string()),
            team_id: Some("platform".to_string()),
            repo_id: None,
            days: 30,
            limit: 5,
        };
        let probe_metrics = super::AnalyticsProbeMetrics {
            probe_count: 2,
            total_requests: 4,
            failed_requests: 0,
            error_rate_pct: 0.0,
            summary_p95_ms: Some(20.0),
            compliance_p95_ms: Some(15.0),
        };
        let thresholds = super::AnalyticsThresholds {
            max_error_rate_pct: Some(1.0),
            max_summary_p95_ms: Some(100.0),
            max_compliance_p95_ms: Some(100.0),
            min_coverage_pct: Some(80.0),
        };

        let rendered = super::render_analytics_summary_table(
            &summary,
            &gaps,
            &query,
            &probe_metrics,
            &thresholds,
        );
        assert!(rendered.contains("Scope: org=acme team=platform repo=all"));
        assert!(rendered.contains("Top CWE:        CWE-79"));
        assert!(rendered.contains("Top OWASP:      A03:2021 - Injection"));
        assert!(rendered.contains("Coverage:       92.5% (11/12) classified"));
        assert!(rendered.contains("Thresholds:"));
        assert!(rendered.contains("result: PASS"));
    }

    #[test]
    fn analytics_thresholds_report_coverage_violation() {
        let gaps = serde_json::json!({
            "summary": {
                "coverage_pct": 62.0
            }
        });
        let probe_metrics = super::AnalyticsProbeMetrics {
            probe_count: 1,
            total_requests: 2,
            failed_requests: 0,
            error_rate_pct: 0.0,
            summary_p95_ms: Some(10.0),
            compliance_p95_ms: Some(12.0),
        };
        let thresholds = super::AnalyticsThresholds {
            max_error_rate_pct: Some(1.0),
            max_summary_p95_ms: Some(100.0),
            max_compliance_p95_ms: Some(100.0),
            min_coverage_pct: Some(70.0),
        };

        let violations = super::evaluate_analytics_thresholds(&probe_metrics, &gaps, &thresholds);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("coverage_pct"));
    }

    #[test]
    fn apply_replacements_updates_content_and_counts_matches() {
        let mut content = "hashlib.md5(data)\nverify=False\n".to_string();
        let replacements = vec![
            ("hashlib.md5(", "hashlib.sha256("),
            ("verify=False", "verify=True"),
        ];
        assert_eq!(count_replacements(&content, &replacements), 2);
        let applied = apply_replacements(&mut content, &replacements);
        assert_eq!(applied, 2);
        assert!(content.contains("hashlib.sha256(data)"));
        assert!(content.contains("verify=True"));
    }

    #[test]
    fn parse_fix_target_supports_file_line_and_column() {
        let path_only = parse_fix_target_spec("src/app.py").expect("path parse");
        assert_eq!(path_only.scan_path.to_string_lossy(), "src/app.py");
        assert_eq!(path_only.line, None);
        assert_eq!(path_only.column, None);

        let line = parse_fix_target_spec("src/app.py:42").expect("line parse");
        assert_eq!(line.scan_path.to_string_lossy(), "src/app.py");
        assert_eq!(line.line, Some(42));
        assert_eq!(line.column, None);

        let line_col = parse_fix_target_spec("src/app.py:42:7").expect("line/col parse");
        assert_eq!(line_col.scan_path.to_string_lossy(), "src/app.py");
        assert_eq!(line_col.line, Some(42));
        assert_eq!(line_col.column, Some(7));
    }

    #[test]
    fn parse_fix_target_rejects_zero_line_or_column() {
        let err_line = parse_fix_target_spec("src/app.py:0").expect_err("line must be > 0");
        assert!(err_line.contains("1-based"));

        let err_col = parse_fix_target_spec("src/app.py:5:0").expect_err("column must be > 0");
        assert!(err_col.contains("1-based"));
    }

    #[test]
    fn autofix_support_covers_priority_rule_set() {
        let ids = vec![
            "AISHIELD-PY-AUTH-002",
            "AISHIELD-PY-CRYPTO-001",
            "AISHIELD-PY-CRYPTO-002",
            "AISHIELD-PY-CRYPTO-003",
            "AISHIELD-PY-CRYPTO-004",
            "AISHIELD-PY-CRYPTO-006",
            "AISHIELD-PY-INJ-002",
            "AISHIELD-PY-INJ-003",
            "AISHIELD-PY-INJ-004",
            "AISHIELD-PY-MISC-001",
            "AISHIELD-PY-MISC-002",
            "AISHIELD-PY-MISC-003",
            "AISHIELD-JS-AUTH-002",
            "AISHIELD-JS-CRYPTO-001",
            "AISHIELD-JS-CRYPTO-002",
            "AISHIELD-JS-CRYPTO-003",
            "AISHIELD-JS-INJ-002",
            "AISHIELD-JS-INJ-003",
            "AISHIELD-JS-INJ-004",
            "AISHIELD-JS-MISC-001",
            "AISHIELD-JS-MISC-002",
            "AISHIELD-JAVA-AUTH-001",
            "AISHIELD-JAVA-CRYPTO-001",
            "AISHIELD-JAVA-CRYPTO-002",
            "AISHIELD-GO-AUTH-001",
            "AISHIELD-GO-CRYPTO-001",
            "AISHIELD-GO-INJ-001",
        ];

        for id in ids {
            assert!(
                !autofix_replacements(id).is_empty(),
                "expected autofix mapping for {id}"
            );
        }
    }

    #[test]
    fn resolve_selected_indices_uses_cursor_when_none_selected() {
        let selected = vec![false, false, false];
        let resolved = resolve_selected_indices(&selected, Some(1));
        assert_eq!(resolved, vec![1]);
    }

    #[test]
    fn resolve_selected_indices_prefers_explicit_selections() {
        let selected = vec![true, false, true, false];
        let resolved = resolve_selected_indices(&selected, Some(3));
        assert_eq!(resolved, vec![0, 2]);
    }

    #[test]
    fn filtered_candidate_indices_matches_rule_and_file_tokens() {
        let candidates = vec![
            super::InteractiveAutofixCandidate {
                file_path: "src/auth.py".into(),
                file_display: "src/auth.py".to_string(),
                rule_id: "AISHIELD-PY-AUTH-002".to_string(),
                title: "JWT Signature Verification Disabled".to_string(),
                severity: Severity::High,
                line: 12,
                column: 5,
                fix_suggestion: None,
                proposed_replacements: 1,
            },
            super::InteractiveAutofixCandidate {
                file_path: "src/ui.js".into(),
                file_display: "src/ui.js".to_string(),
                rule_id: "AISHIELD-JS-INJ-004".to_string(),
                title: "Unsanitized innerHTML Assignment".to_string(),
                severity: Severity::High,
                line: 22,
                column: 3,
                fix_suggestion: None,
                proposed_replacements: 1,
            },
        ];

        assert_eq!(filtered_candidate_indices(&candidates, "auth jwt"), vec![0]);
        assert_eq!(
            filtered_candidate_indices(&candidates, "ui innerhtml"),
            vec![1]
        );
        assert_eq!(
            filtered_candidate_indices(&candidates, "missing"),
            Vec::<usize>::new()
        );
    }

    fn temp_path(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{stamp}"))
    }
}
