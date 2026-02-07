use std::fs;
use std::path::{Path, PathBuf};

use crate::Severity;

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence_that_ai_generated: f32,
    pub languages: Vec<String>,
    pub ai_tendency: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub fix_suggestion: Option<String>,
    pub pattern_any: Vec<String>,
    pub pattern_all: Vec<String>,
    pub pattern_not: Vec<String>,
    pub negative_patterns: Vec<String>,
}

impl Rule {
    pub fn applies_to_language(&self, language: &str) -> bool {
        self.languages
            .iter()
            .any(|l| l.eq_ignore_ascii_case(language))
    }

    pub fn matches_line(&self, line_lower: &str) -> Option<usize> {
        if self
            .pattern_not
            .iter()
            .any(|needle| line_lower.contains(needle))
        {
            return None;
        }

        if !self.pattern_all.is_empty()
            && self
                .pattern_all
                .iter()
                .any(|needle| !line_lower.contains(needle))
        {
            return None;
        }

        if !self.pattern_any.is_empty()
            && self
                .pattern_any
                .iter()
                .all(|needle| !line_lower.contains(needle))
        {
            return None;
        }

        first_match_column(line_lower, &self.pattern_any, &self.pattern_all)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn load_from_dir(path: &Path) -> Result<Self, String> {
        let mut files = Vec::new();
        collect_rule_files(path, &mut files);

        let mut rules = Vec::new();
        for file in files {
            let content = fs::read_to_string(&file)
                .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
            let rule = parse_rule(&content, &file)?;
            rules.push(rule);
        }

        Ok(Self { rules })
    }

    pub fn for_language<'a>(&'a self, language: &'a str) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules
            .iter()
            .filter(move |rule| rule.applies_to_language(language))
    }

    pub fn with_categories(&self, categories: &[String]) -> Self {
        if categories.is_empty() {
            return self.clone();
        }

        let wanted = categories
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect::<Vec<_>>();

        let filtered = self
            .rules
            .iter()
            .filter(|rule| {
                let category_match = rule
                    .category
                    .as_ref()
                    .map(|c| wanted.contains(&c.to_ascii_lowercase()))
                    .unwrap_or(false);

                let tag_match = rule
                    .tags
                    .iter()
                    .any(|tag| wanted.contains(&tag.to_ascii_lowercase()));

                category_match || tag_match
            })
            .cloned()
            .collect::<Vec<_>>();

        Self { rules: filtered }
    }
}

#[derive(Clone, Copy)]
enum Section {
    Root,
    Pattern,
    Negative,
    Fix,
}

#[derive(Clone, Copy)]
enum PatternField {
    Any,
    All,
    Not,
}

fn collect_rule_files(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };

    if meta.is_file() {
        if path
            .extension()
            .map(|ext| {
                let ext = ext.to_string_lossy().to_ascii_lowercase();
                ext == "yaml" || ext == "yml"
            })
            .unwrap_or(false)
        {
            out.push(path.to_path_buf());
        }
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        collect_rule_files(&entry.path(), out);
    }
}

fn parse_rule(content: &str, source: &Path) -> Result<Rule, String> {
    let mut id = String::new();
    let mut title = String::new();
    let mut severity = Severity::Medium;
    let mut confidence = 0.70;
    let mut languages = Vec::new();
    let mut ai_tendency = None;
    let mut category = None;
    let mut tags = Vec::new();
    let mut fix_suggestion = None;
    let mut pattern_any = Vec::new();
    let mut pattern_all = Vec::new();
    let mut pattern_not = Vec::new();
    let mut negative_patterns = Vec::new();

    let mut section = Section::Root;
    let mut pattern_field = PatternField::Any;

    for raw_line in content.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = raw_line.chars().take_while(|c| *c == ' ').count();
        if indent == 0 {
            section = Section::Root;

            if let Some(v) = parse_kv(trimmed, "id") {
                id = v;
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "title") {
                title = v;
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "severity") {
                severity = parse_severity(&v)?;
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "confidence_that_ai_generated") {
                confidence = v.parse::<f32>().unwrap_or(0.70);
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "languages") {
                languages = parse_list(&v);
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "ai_tendency") {
                ai_tendency = Some(v);
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "category") {
                category = Some(v);
                continue;
            }
            if let Some(v) = parse_kv(trimmed, "tags") {
                tags = parse_list(&v);
                continue;
            }
            if trimmed == "pattern:" {
                section = Section::Pattern;
                pattern_field = PatternField::Any;
                continue;
            }
            if trimmed == "negative_patterns:" {
                section = Section::Negative;
                continue;
            }
            if trimmed == "fix:" {
                section = Section::Fix;
                continue;
            }
            continue;
        }

        match section {
            Section::Pattern => {
                if trimmed == "contains:" || trimmed == "any:" {
                    pattern_field = PatternField::Any;
                    continue;
                }
                if trimmed == "all:" {
                    pattern_field = PatternField::All;
                    continue;
                }
                if trimmed == "not:" {
                    pattern_field = PatternField::Not;
                    continue;
                }

                if let Some(v) = parse_kv(trimmed, "contains") {
                    pattern_any.extend(parse_list(&v));
                    pattern_field = PatternField::Any;
                    continue;
                }
                if let Some(v) = parse_kv(trimmed, "any") {
                    pattern_any.extend(parse_list(&v));
                    pattern_field = PatternField::Any;
                    continue;
                }
                if let Some(v) = parse_kv(trimmed, "all") {
                    pattern_all.extend(parse_list(&v));
                    pattern_field = PatternField::All;
                    continue;
                }
                if let Some(v) = parse_kv(trimmed, "not") {
                    pattern_not.extend(parse_list(&v));
                    pattern_field = PatternField::Not;
                    continue;
                }

                if let Some(value) = trimmed.strip_prefix("- ") {
                    let needle = strip_quotes(value).to_ascii_lowercase();
                    if needle.is_empty() {
                        continue;
                    }
                    match pattern_field {
                        PatternField::Any => pattern_any.push(needle),
                        PatternField::All => pattern_all.push(needle),
                        PatternField::Not => pattern_not.push(needle),
                    }
                }
            }
            Section::Negative => {
                if let Some(v) = parse_kv(trimmed, "contains") {
                    negative_patterns.extend(parse_list(&v));
                    continue;
                }
                if let Some(value) = trimmed.strip_prefix("- ") {
                    let needle = strip_quotes(value).to_ascii_lowercase();
                    if !needle.is_empty() {
                        negative_patterns.push(needle);
                    }
                }
            }
            Section::Fix => {
                if let Some(v) = parse_kv(trimmed, "suggestion") {
                    fix_suggestion = Some(v);
                }
            }
            Section::Root => {}
        }
    }

    if id.is_empty() {
        return Err(format!("{}: missing `id`", source.display()));
    }
    if title.is_empty() {
        return Err(format!("{}: missing `title`", source.display()));
    }
    if languages.is_empty() {
        return Err(format!("{}: missing `languages`", source.display()));
    }
    if pattern_any.is_empty() && pattern_all.is_empty() {
        return Err(format!(
            "{}: missing pattern.any/contains or pattern.all",
            source.display()
        ));
    }

    Ok(Rule {
        id,
        title,
        severity,
        confidence_that_ai_generated: confidence,
        languages,
        ai_tendency,
        category,
        tags,
        fix_suggestion,
        pattern_any,
        pattern_all,
        pattern_not,
        negative_patterns,
    })
}

fn first_match_column(
    line_lower: &str,
    pattern_any: &[String],
    pattern_all: &[String],
) -> Option<usize> {
    let mut candidates = Vec::new();

    for needle in pattern_any {
        if let Some(idx) = line_lower.find(needle) {
            candidates.push(idx + 1);
        }
    }

    for needle in pattern_all {
        if let Some(idx) = line_lower.find(needle) {
            candidates.push(idx + 1);
        }
    }

    candidates.into_iter().min()
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        other => Err(format!("unknown severity `{other}`")),
    }
}

fn parse_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    if !line.starts_with(&prefix) {
        return None;
    }
    let value = line[prefix.len()..].trim();
    Some(strip_quotes(value))
}

fn parse_list(value: &str) -> Vec<String> {
    let text = value.trim();
    if !(text.starts_with('[') && text.ends_with(']')) {
        return Vec::new();
    }

    let inner = &text[1..text.len() - 1];
    inner
        .split(',')
        .map(strip_quotes)
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
}

fn strip_quotes(input: &str) -> String {
    let mut value = input.trim().to_string();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{parse_rule, RuleSet};
    use std::path::{Path, PathBuf};

    #[test]
    fn parses_any_all_not_pattern_fields() {
        let yaml = r#"id: AISHIELD-TEST-001
title: Pattern Semantics
severity: high
languages: [python]
pattern:
  any:
    - "token == "
  all:
    - "token"
    - "=="
  not:
    - "compare_digest("
"#;

        let rule = parse_rule(yaml, Path::new("inline.yaml")).expect("parse rule");

        assert_eq!(rule.pattern_any, vec!["token == "]);
        assert_eq!(rule.pattern_all, vec!["token", "=="]);
        assert_eq!(rule.pattern_not, vec!["compare_digest("]);
        assert!(rule.matches_line("if token == provided:").is_some());
        assert!(rule
            .matches_line("return hmac.compare_digest(token, provided)")
            .is_none());
    }

    #[test]
    fn contains_alias_maps_to_any() {
        let yaml = r#"id: AISHIELD-TEST-002
title: Contains Alias
severity: medium
languages: [javascript]
pattern:
  contains:
    - "innerhtml ="
"#;

        let rule = parse_rule(yaml, Path::new("inline.yaml")).expect("parse rule");
        assert_eq!(rule.pattern_any, vec!["innerhtml ="]);
        assert!(rule.pattern_all.is_empty());
        assert!(rule.matches_line("node.innerhtml = userinput").is_some());
    }

    #[test]
    fn repository_rulepack_has_foundational_coverage() {
        let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let ruleset = RuleSet::load_from_dir(&rules_dir).expect("load repository rules");
        assert!(
            ruleset.rules.len() >= 30,
            "expected at least 30 foundational rules, found {}",
            ruleset.rules.len()
        );
    }
}
