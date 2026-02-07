use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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
    let mut rules_dir = PathBuf::from("rules");
    let mut format = OutputFormat::Table;
    let mut categories = Vec::new();
    let mut ai_only = false;
    let mut min_ai_confidence = None;
    let mut severity_threshold = None;
    let mut fail_on_findings = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir = PathBuf::from(args.get(i).ok_or("--rules-dir requires a value")?);
            }
            "--format" => {
                i += 1;
                format = OutputFormat::parse(args.get(i).ok_or("--format requires a value")?)?;
            }
            "--rules" => {
                i += 1;
                let raw = args.get(i).ok_or("--rules requires a value")?;
                categories = raw
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>();
            }
            "--ai-only" => ai_only = true,
            "--min-ai-confidence" => {
                i += 1;
                let raw = args.get(i).ok_or("--min-ai-confidence requires a value")?;
                min_ai_confidence = Some(
                    raw.parse::<f32>()
                        .map_err(|_| "invalid --min-ai-confidence value".to_string())?,
                );
            }
            "--severity" => {
                i += 1;
                severity_threshold = Some(SeverityThreshold::parse(
                    args.get(i).ok_or("--severity requires a value")?,
                )?);
            }
            "--fail-on-findings" => fail_on_findings = true,
            other => return Err(format!("unknown scan option `{other}`")),
        }
        i += 1;
    }

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

    match format {
        OutputFormat::Table => print_table(&result),
        OutputFormat::Json => print_json(&result),
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
    let mut rules_dir = PathBuf::from("rules");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules-dir" => {
                i += 1;
                rules_dir = PathBuf::from(args.get(i).ok_or("--rules-dir requires a value")?);
            }
            other => return Err(format!("unknown fix option `{other}`")),
        }
        i += 1;
    }

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

    let config = "version: 1\nrules_dir: rules\nseverity_threshold: medium\nai_only: false\nmin_ai_confidence: 0.70\nformat: table\n";

    let mut file = File::create(&output).map_err(|err| err.to_string())?;
    file.write_all(config.as_bytes())
        .map_err(|err| err.to_string())?;
    println!("Created {}", output.display());
    Ok(())
}

fn print_help() {
    println!("AIShield CLI (foundation)\n");
    println!("Usage:");
    println!("  aishield scan <path> [--rules-dir DIR] [--format table|json] [--rules c1,c2] [--ai-only] [--min-ai-confidence N] [--severity LEVEL] [--fail-on-findings]");
    println!("  aishield fix <path> [--rules-dir DIR]");
    println!("  aishield init [--output PATH]");
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

fn print_table(result: &ScanResult) {
    println!(
        "AIShield scan complete: {} findings across {} files ({} rules loaded)",
        result.summary.total, result.summary.scanned_files, result.summary.matched_rules
    );

    if result.findings.is_empty() {
        println!("No vulnerabilities detected.");
        return;
    }

    println!(
        "{:<10} {:<30} {:<32} {:<8} {:<8} {}",
        "Severity", "Rule", "Location", "AI %", "Risk", "Snippet"
    );
    println!("{}", "-".repeat(130));

    for finding in &result.findings {
        let location = format!("{}:{}:{}", finding.file, finding.line, finding.column);
        let rule = format!("{}", finding.id);
        println!(
            "{:<10} {:<30} {:<32} {:<8.1} {:<8.1} {}",
            finding.severity.as_str(),
            truncate(&rule, 30),
            truncate(&location, 32),
            finding.ai_confidence,
            finding.risk_score,
            truncate(&finding.snippet, 40)
        );
    }

    println!(
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
}

fn truncate(input: &str, width: usize) -> String {
    if input.len() <= width {
        return input.to_string();
    }
    format!("{}...", &input[..width.saturating_sub(3)])
}

fn print_json(result: &ScanResult) {
    println!("{{");
    println!("  \"summary\": {{");
    println!("    \"total\": {},", result.summary.total);
    println!("    \"scanned_files\": {},", result.summary.scanned_files);
    println!("    \"matched_rules\": {},", result.summary.matched_rules);
    println!("    \"by_severity\": {{");

    let mut first = true;
    for (k, v) in &result.summary.by_severity {
        if !first {
            println!(",");
        }
        print!("      \"{}\": {}", escape_json(k), v);
        first = false;
    }
    println!();
    println!("    }}");
    println!("  }},");
    println!("  \"findings\": [");

    for (idx, finding) in result.findings.iter().enumerate() {
        println!("    {{");
        println!("      \"id\": \"{}\",", escape_json(&finding.id));
        println!("      \"title\": \"{}\",", escape_json(&finding.title));
        println!("      \"severity\": \"{}\",", finding.severity.as_str());
        println!("      \"file\": \"{}\",", escape_json(&finding.file));
        println!("      \"line\": {},", finding.line);
        println!("      \"column\": {},", finding.column);
        println!("      \"snippet\": \"{}\",", escape_json(&finding.snippet));
        println!("      \"ai_confidence\": {:.1},", finding.ai_confidence);
        println!("      \"risk_score\": {:.1},", finding.risk_score);
        println!(
            "      \"category\": {},",
            opt_json_string(finding.category.as_deref())
        );
        println!(
            "      \"ai_tendency\": {},",
            opt_json_string(finding.ai_tendency.as_deref())
        );
        println!(
            "      \"fix_suggestion\": {},",
            opt_json_string(finding.fix_suggestion.as_deref())
        );
        print!("      \"tags\": [");
        for (i, tag) in finding.tags.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("\"{}\"", escape_json(tag));
        }
        println!("]");

        if idx + 1 == result.findings.len() {
            println!("    }}");
        } else {
            println!("    }},");
        }
    }

    println!("  ]");
    println!("}}");
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

#[derive(Clone, Copy)]
enum OutputFormat {
    Table,
    Json,
}

impl OutputFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            _ => Err("--format must be table or json".to_string()),
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
        match raw.to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => Err("--severity must be critical|high|medium|low|info".to_string()),
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
