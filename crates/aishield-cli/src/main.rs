use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aishield_core::{
    AiClassifierMode, AiClassifierOptions, AnalysisOptions, Analyzer, Finding, RuleSet, ScanResult,
    ScanSummary, Severity,
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
        "stats" => run_stats(&args[1..]),
        "hook" => run_hook(&args[1..]),
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
    let mut min_ai_confidence_override = None;
    let mut severity_override = None;
    let mut fail_on_findings_flag = false;
    let mut output_path = None;
    let mut baseline_path = None::<PathBuf>;
    let mut notify_webhook_override = None::<String>;
    let mut notify_severity_override = None::<SeverityThreshold>;
    let mut history_file_override = None;
    let mut no_history_flag = false;
    let mut staged_only = false;
    let mut changed_from = None::<String>;
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
    let ai_only = ai_only_flag || config.ai_only;
    let cross_file = cross_file_flag || config.cross_file;
    let ai_model = ai_model_override
        .or_else(|| onnx_model_override.as_ref().map(|_| AiClassifierMode::Onnx))
        .unwrap_or(config.ai_model);
    let onnx_model_path = onnx_model_override.or_else(|| config.onnx_model_path.clone());
    let min_ai_confidence = min_ai_confidence_override.or(config.min_ai_confidence);
    let severity_threshold = severity_override.or(config.severity_threshold);
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
    let ai_classifier = resolve_ai_classifier(ai_model, onnx_model_path);
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

    if let Some(webhook_url) = notify_webhook_url {
        if let Err(err) =
            maybe_send_webhook_notification(&webhook_url, notify_min_severity, &target, &result)
        {
            eprintln!("warning: failed to send webhook notification: {err}");
        }
    }

    let rendered = match format {
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
    };

    if let Some(path) = output_path {
        fs::write(&path, rendered)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        println!("Wrote report to {}", path.display());
    } else {
        write_stdout(&rendered)?;
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
        .unwrap_or(config.ai_model);
    let onnx_model_path = onnx_model_override.or_else(|| config.onnx_model_path.clone());
    let min_ai_confidence = min_ai_confidence_override.or(config.min_ai_confidence);

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;
    if ruleset.rules.is_empty() {
        return Err(format!("no rules found in {}", rules_dir.display()));
    }

    let analyzer = Analyzer::new(ruleset);
    let ai_classifier = resolve_ai_classifier(ai_model, onnx_model_path);
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
) -> AiClassifierOptions {
    if requested_mode != AiClassifierMode::Onnx {
        return AiClassifierOptions {
            mode: requested_mode,
            onnx_model_path: requested_model_path,
        };
    }

    if !cfg!(feature = "onnx") {
        eprintln!(
            "warning: --ai-model onnx requested but this binary was built without `onnx` feature; falling back to heuristic scoring"
        );
        return AiClassifierOptions {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
        };
    }

    let Some(model_path) = requested_model_path else {
        eprintln!(
            "warning: --ai-model onnx requested but no --onnx-model path was provided; falling back to heuristic scoring"
        );
        return AiClassifierOptions {
            mode: AiClassifierMode::Heuristic,
            onnx_model_path: None,
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
        };
    }

    AiClassifierOptions {
        mode: AiClassifierMode::Onnx,
        onnx_model_path: Some(model_path),
    }
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
    "version: 1\nrules_dir: rules\nformat: table\ndedup_mode: normalized\nbridge_engines: []\nrules: []\nexclude_paths: []\nai_only: false\ncross_file: false\nai_model: heuristic\nonnx_model_path: \"\"\nmin_ai_confidence: 0.70\nseverity_threshold: medium\nfail_on_findings: false\nhistory_file: .aishield-history.log\nrecord_history: true\nnotify_webhook_url: \"\"\nnotify_min_severity: high\n".to_string()
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

scan:aishield:
  stage: scan
  image: rust:1.84
  before_script:
    - apt-get update && apt-get install -y python3 python3-pip nodejs npm
  script:
    - cargo build --workspace
    - cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
  artifacts:
    when: always
    paths:
      - aishield.sarif
    expire_in: 1 week

# Optional bridge run:
#   set CI variable AISHIELD_ENABLE_BRIDGE=true
scan:aishield-bridge:
  stage: scan
  image: rust:1.84
  rules:
    - if: '$AISHIELD_ENABLE_BRIDGE == "true"'
  before_script:
    - apt-get update && apt-get install -y python3 python3-pip nodejs npm
    - python3 -m pip install --upgrade pip
    - pip3 install semgrep bandit
    - npm install -g eslint
  script:
    - cargo build --workspace
    - cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --bridge all --output aishield.sarif
  artifacts:
    when: always
    paths:
      - aishield.sarif
    expire_in: 1 week
"#
    .to_string()
}

fn init_bitbucket_pipelines_template() -> String {
    r#"image: rust:1.84

pipelines:
  pull-requests:
    '**':
      - step:
          name: AIShield scan
          caches:
            - cargo
          script:
            - apt-get update && apt-get install -y python3 python3-pip nodejs npm
            - cargo build --workspace
            - cargo run -p aishield-cli -- scan . --format json --dedup normalized --output aishield.json
          artifacts:
            - aishield.json
  branches:
    main:
      - step:
          name: AIShield SARIF
          caches:
            - cargo
          script:
            - apt-get update && apt-get install -y python3 python3-pip nodejs npm
            - cargo build --workspace
            - cargo run -p aishield-cli -- scan . --format sarif --dedup normalized --output aishield.sarif
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

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            ("if (token == provided)", "if (token.equals(provided))"),
            ("if(token == provided)", "if(token.equals(provided))"),
        ],
        "AISHIELD-GO-CRYPTO-001" => vec![("md5.Sum(", "sha256.Sum256(")],
        "AISHIELD-GO-INJ-001" => vec![(
            "exec.Command(\"sh\", \"-c\", \"cat \"+userInput)",
            "exec.Command(\"cat\", userInput)",
        )],
        "AISHIELD-GO-AUTH-001" => vec![(
            "if token == incoming",
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

fn print_help() {
    println!("AIShield CLI (foundation)\n");
    println!("Usage:");
    println!("  aishield scan <path> [--rules-dir DIR] [--format table|json|sarif|github] [--dedup none|normalized] [--bridge semgrep,bandit,eslint|all] [--rules c1,c2] [--exclude p1,p2] [--ai-only] [--cross-file] [--ai-model heuristic|onnx] [--onnx-model FILE] [--min-ai-confidence N] [--severity LEVEL] [--fail-on-findings] [--staged|--changed-from REF] [--output FILE] [--baseline FILE] [--notify-webhook URL] [--notify-min-severity LEVEL] [--history-file FILE] [--no-history] [--config FILE] [--no-config]");
    println!("  aishield fix <path[:line[:col]]> [--rules-dir DIR] [--write|--interactive] [--dry-run] [--config FILE] [--no-config]");
    println!("  aishield bench <path> [--rules-dir DIR] [--iterations N] [--warmup N] [--format table|json] [--bridge semgrep,bandit,eslint|all] [--rules c1,c2] [--exclude p1,p2] [--ai-only] [--cross-file] [--ai-model heuristic|onnx] [--onnx-model FILE] [--min-ai-confidence N] [--config FILE] [--no-config]");
    println!("  aishield init [--output PATH] [--templates config,github-actions,gitlab-ci,bitbucket-pipelines,circleci,jenkins,vscode,pre-commit|all] [--force]");
    println!("  aishield create-rule --id ID --title TITLE --language LANG --category CAT [--severity LEVEL] [--pattern-any P] [--pattern-all P] [--pattern-not P] [--tags t1,t2] [--suggestion TEXT] [--out-dir DIR] [--force]");
    println!("  aishield stats [--last Nd] [--history-file FILE] [--format table|json] [--config FILE] [--no-config]");
    println!("  aishield hook install [--severity LEVEL] [--path TARGET] [--all-files]");
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

#[cfg(test)]
mod tests {
    use aishield_core::AiClassifierMode;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        apply_replacements, autofix_replacements, build_webhook_payload, count_replacements,
        dedup_machine_output, empty_summary, escape_github_annotation_message,
        escape_github_annotation_property, filter_findings_against_baseline,
        filtered_candidate_indices, init_template_writes, load_baseline_keys,
        maybe_send_webhook_notification, normalize_snippet, parse_fix_target_spec,
        parse_init_templates, percentile, render_github_annotations, render_sarif,
        resolve_ai_classifier, resolve_selected_indices, DedupMode, Finding, InitTemplate,
        OutputSummary, ScanResult, Severity, SeverityThreshold,
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
    fn normalized_dedup_keeps_highest_risk_finding_per_key() {
        let raw = result(vec![
            finding(
                "AISHIELD-PY-AUTH-001",
                Severity::Medium,
                "src/app.py",
                10,
                "if token == provided:",
                60.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-099",
                Severity::High,
                "src/app.py",
                10,
                "if token==provided:",
                90.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-100",
                Severity::High,
                "src/app.py",
                11,
                "if token == provided:",
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
                "if token == provided:",
                60.0,
            ),
            finding(
                "AISHIELD-PY-AUTH-099",
                Severity::High,
                "src/app.py",
                10,
                "if token==provided:",
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
                "if token == provided:",
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
      "snippet": "if token == provided:"
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
            "if token == provided:",
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
            normalize_snippet("if token==provided:"),
            normalize_snippet("if   token == provided ;")
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
            "if token == provided:",
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
    fn init_config_template_sets_cross_file_disabled_by_default() {
        let template = super::init_config_template();
        assert!(template.contains("cross_file: false"));
        assert!(template.contains("ai_model: heuristic"));
        assert!(template.contains("onnx_model_path: \"\""));
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
"#,
        )
        .expect("parse config");

        assert!(config.cross_file);
        assert_eq!(config.ai_model, AiClassifierMode::Onnx);
        assert_eq!(
            config.onnx_model_path,
            Some(PathBuf::from("models/aishield.onnx"))
        );
    }

    #[test]
    fn resolve_ai_classifier_keeps_heuristic_mode() {
        let resolved = resolve_ai_classifier(AiClassifierMode::Heuristic, None);
        assert_eq!(resolved.mode, AiClassifierMode::Heuristic);
        assert_eq!(resolved.onnx_model_path, None);
    }

    #[test]
    fn resolve_ai_classifier_falls_back_on_missing_onnx_path() {
        let resolved = resolve_ai_classifier(AiClassifierMode::Onnx, None);
        assert_eq!(resolved.mode, AiClassifierMode::Heuristic);
        assert_eq!(resolved.onnx_model_path, None);
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
