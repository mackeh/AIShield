use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use aishield_core::{AnalysisOptions, Analyzer, RuleSet, ScanResult, Severity};

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
    let mut ai_only_flag = false;
    let mut min_ai_confidence_override = None;
    let mut severity_override = None;
    let mut fail_on_findings_flag = false;
    let mut output_path = None;
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
    let ai_only = ai_only_flag || config.ai_only;
    let min_ai_confidence = min_ai_confidence_override.or(config.min_ai_confidence);
    let severity_threshold = severity_override.or(config.severity_threshold);
    let fail_on_findings = fail_on_findings_flag || config.fail_on_findings;

    let ruleset = RuleSet::load_from_dir(&rules_dir)
        .map_err(|err| format!("failed to load rules from {}: {err}", rules_dir.display()))?;

    if ruleset.rules.is_empty() {
        return Err(format!("no rules found in {}", rules_dir.display()));
    }

    let analyzer = Analyzer::new(ruleset);
    let options = AnalysisOptions {
        ai_only,
        min_ai_confidence,
        categories,
    };
    let mut result = analyzer
        .analyze_path(&target, &options)
        .map_err(|err| format!("failed to scan {}: {err}", target.display()))?;

    if let Some(threshold) = severity_threshold {
        result.findings = result
            .findings
            .into_iter()
            .filter(|f| threshold.includes(f.severity))
            .collect::<Vec<_>>();
        result.summary = recompute_summary(&result);
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

fn run_fix(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("fix requires a target path".to_string());
    }

    let target = PathBuf::from(&args[0]);
    let mut rules_dir_override = None;
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

    let config = "version: 1\nrules_dir: rules\nformat: table\nrules: []\nai_only: false\nmin_ai_confidence: 0.70\nseverity_threshold: medium\nfail_on_findings: false\n";

    let mut file = File::create(&output).map_err(|err| err.to_string())?;
    file.write_all(config.as_bytes())
        .map_err(|err| err.to_string())?;
    println!("Created {}", output.display());
    Ok(())
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

fn run_hook_install(args: &[String]) -> Result<(), String> {
    let mut severity = SeverityThreshold::High;
    let mut scan_path = ".".to_string();

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
            other => return Err(format!("unknown hook install option `{other}`")),
        }
        i += 1;
    }

    let hooks_dir = PathBuf::from(".git/hooks");
    if !hooks_dir.exists() {
        return Err(".git/hooks not found; run this inside a git repository".to_string());
    }

    let hook_path = hooks_dir.join("pre-commit");
    let script = format!(
        "#!/usr/bin/env sh\nset -e\n\nif command -v aishield >/dev/null 2>&1; then\n  aishield scan {scan_path} --severity {} --fail-on-findings\nelse\n  cargo run -q -p aishield-cli -- scan {scan_path} --severity {} --fail-on-findings\nfi\n",
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

fn print_help() {
    println!("AIShield CLI (foundation)\n");
    println!("Usage:");
    println!("  aishield scan <path> [--rules-dir DIR] [--format table|json|sarif] [--rules c1,c2] [--ai-only] [--min-ai-confidence N] [--severity LEVEL] [--fail-on-findings] [--output FILE] [--config FILE] [--no-config]");
    println!("  aishield fix <path> [--rules-dir DIR] [--config FILE] [--no-config]");
    println!("  aishield init [--output PATH]");
    println!("  aishield hook install [--severity LEVEL] [--path TARGET]");
}

fn recompute_summary(result: &ScanResult) -> aishield_core::ScanSummary {
    let mut by_severity = BTreeMap::new();
    by_severity.insert("critical".to_string(), 0);
    by_severity.insert("high".to_string(), 0);
    by_severity.insert("medium".to_string(), 0);
    by_severity.insert("low".to_string(), 0);
    by_severity.insert("info".to_string(), 0);

    for finding in &result.findings {
        *by_severity
            .entry(finding.severity.as_str().to_string())
            .or_insert(0) += 1;
    }

    aishield_core::ScanSummary {
        total: result.findings.len(),
        by_severity,
        scanned_files: result.summary.scanned_files,
        matched_rules: result.summary.matched_rules,
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

    out
}

fn truncate(input: &str, width: usize) -> String {
    if input.len() <= width {
        return input.to_string();
    }
    format!("{}...", &input[..width.saturating_sub(3)])
}

fn render_json(result: &ScanResult) -> String {
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

#[derive(Clone)]
struct AppConfig {
    rules_dir: PathBuf,
    format: OutputFormat,
    rules: Vec<String>,
    ai_only: bool,
    min_ai_confidence: Option<f32>,
    severity_threshold: Option<SeverityThreshold>,
    fail_on_findings: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::from("rules"),
            format: OutputFormat::Table,
            rules: Vec::new(),
            ai_only: false,
            min_ai_confidence: None,
            severity_threshold: None,
            fail_on_findings: false,
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
