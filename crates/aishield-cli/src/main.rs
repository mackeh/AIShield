use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aishield_core::{
    AnalysisOptions, Analyzer, Finding, RuleSet, ScanResult, ScanSummary, Severity,
};

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
    let mut categories_override = None;
    let mut exclude_paths_override = None;
    let mut ai_only_flag = false;
    let mut min_ai_confidence_override = None;
    let mut severity_override = None;
    let mut fail_on_findings_flag = false;
    let mut output_path = None;
    let mut history_file_override = None;
    let mut no_history_flag = false;
    let mut staged_only = false;
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
            "--history-file" => {
                i += 1;
                history_file_override = Some(PathBuf::from(
                    args.get(i).ok_or("--history-file requires a value")?,
                ));
            }
            "--no-history" => no_history_flag = true,
            "--staged" => staged_only = true,
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
    let categories = categories_override.unwrap_or_else(|| config.rules.clone());
    let mut exclude_paths = config.exclude_paths.clone();
    if let Some(extra) = exclude_paths_override {
        exclude_paths.extend(extra);
    }
    let ai_only = ai_only_flag || config.ai_only;
    let min_ai_confidence = min_ai_confidence_override.or(config.min_ai_confidence);
    let severity_threshold = severity_override.or(config.severity_threshold);
    let fail_on_findings = fail_on_findings_flag || config.fail_on_findings;
    let history_file = history_file_override.unwrap_or_else(|| config.history_file.clone());
    let record_history = if no_history_flag {
        false
    } else {
        config.record_history
    };

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;

    if ruleset.rules.is_empty() {
        return Err(format!("no rules found in {}", rules_dir.display()));
    }

    let rules_count = ruleset.rules.len();
    let analyzer = Analyzer::new(ruleset);
    let options = AnalysisOptions {
        ai_only,
        min_ai_confidence,
        categories,
        exclude_paths,
    };
    let mut result = if staged_only {
        let staged_targets = collect_staged_targets(&target)?;
        analyze_targets(&analyzer, &options, &staged_targets, rules_count)?
    } else {
        analyzer
            .analyze_path(&target, &options)
            .map_err(|err| format!("failed to scan {}: {err}", target.display()))?
    };

    if let Some(threshold) = severity_threshold {
        result.findings = result
            .findings
            .into_iter()
            .filter(|f| threshold.includes(f.severity))
            .collect::<Vec<_>>();
        result.summary = recompute_summary(&result);
    }

    if record_history {
        if let Err(err) = append_history(&history_file, &target, &result) {
            eprintln!("warning: failed to append scan history: {err}");
        }
    }

    let rendered = match format {
        OutputFormat::Table => render_table(&result),
        OutputFormat::Json => render_json(&result),
        OutputFormat::Sarif => render_sarif(&result),
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

fn run_fix(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("fix requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);
    let mut rules_dir_override = None;
    let mut write_changes = false;
    let mut dry_run = false;
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
            "--no-config" => use_config = false,
            other => return Err(format!("unknown fix option `{other}`")),
        }
        i += 1;
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
    let result = analyzer.analyze_path(&target, &AnalysisOptions::default())?;

    if result.findings.is_empty() {
        println!("No findings detected. Nothing to remediate.");
        return Ok(());
    }

    if write_changes || dry_run {
        apply_autofixes(&target, &result, write_changes, dry_run)?;
    } else {
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

    Ok(())
}

fn run_init(args: &[String]) -> Result<(), String> {
    let mut output = PathBuf::from(".aishield.yml");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                i += 1;
                output = PathBuf::from(args.get(i).ok_or("--output requires a value")?);
            }
            other => return Err(format!("unknown init option `{other}`")),
        }
        i += 1;
    }

    if output.exists() {
        return Err(format!("{} already exists", output.display()));
    }

    let config = "version: 1\nrules_dir: rules\nformat: table\nrules: []\nexclude_paths: []\nai_only: false\nmin_ai_confidence: 0.70\nseverity_threshold: medium\nfail_on_findings: false\nhistory_file: .aishield-history.log\nrecord_history: true\n";

    let mut file = File::create(&output).map_err(|err| err.to_string())?;
    file.write_all(config.as_bytes())
        .map_err(|err| err.to_string())?;
    println!("Created {}", output.display());
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
        "AISHIELD-PY-CRYPTO-001" => vec![
            ("hashlib.md5(", "hashlib.sha256("),
            ("hashlib.sha1(", "hashlib.sha256("),
        ],
        "AISHIELD-PY-MISC-001" => vec![
            ("DEBUG = True", "DEBUG = False"),
            ("debug=True", "debug=False"),
            ("debug = True", "debug = False"),
        ],
        "AISHIELD-PY-CRYPTO-006" => vec![
            ("verify=False", "verify=True"),
            ("verify = False", "verify = True"),
        ],
        "AISHIELD-PY-INJ-003" => vec![
            ("shell=True", "shell=False"),
            ("shell = True", "shell = False"),
        ],
        "AISHIELD-JS-INJ-004" => vec![
            ("innerHTML =", "textContent ="),
            ("innerHTML=", "textContent="),
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
    println!("  aishield scan <path> [--rules-dir DIR] [--format table|json|sarif] [--rules c1,c2] [--exclude p1,p2] [--ai-only] [--min-ai-confidence N] [--severity LEVEL] [--fail-on-findings] [--staged] [--output FILE] [--history-file FILE] [--no-history] [--config FILE] [--no-config]");
    println!("  aishield fix <path> [--rules-dir DIR] [--write] [--dry-run] [--config FILE] [--no-config]");
    println!("  aishield init [--output PATH]");
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

fn truncate(input: &str, width: usize) -> String {
    if input.len() <= width {
        return input.to_string();
    }
    format!("{}...", &input[..width.saturating_sub(3)])
}

fn render_json(result: &ScanResult) -> String {
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

fn render_sarif(result: &ScanResult) -> String {
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
            finding.line, finding.column
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

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
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
    rules: Vec<String>,
    exclude_paths: Vec<String>,
    ai_only: bool,
    min_ai_confidence: Option<f32>,
    severity_threshold: Option<SeverityThreshold>,
    fail_on_findings: bool,
    history_file: PathBuf,
    record_history: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::from("rules"),
            format: OutputFormat::Table,
            rules: Vec::new(),
            exclude_paths: Vec::new(),
            ai_only: false,
            min_ai_confidence: None,
            severity_threshold: None,
            fail_on_findings: false,
            history_file: PathBuf::from(".aishield-history.log"),
            record_history: true,
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
                "rules" => config.rules = parse_list_like(value),
                "exclude_paths" => config.exclude_paths = parse_list_like(value),
                "ai_only" => config.ai_only = parse_bool(value)?,
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
}

impl OutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            _ => Err("format must be table, json, or sarif".to_string()),
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
