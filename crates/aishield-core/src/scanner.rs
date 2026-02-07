use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: String,
}

pub fn collect_source_files(target: &Path) -> Vec<SourceFile> {
    let mut files = Vec::new();
    walk(target, &mut files);
    files
}

fn walk(path: &Path, out: &mut Vec<SourceFile>) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };

    if meta.is_file() {
        if let Some(language) = language_from_path(path) {
            out.push(SourceFile {
                path: path.to_path_buf(),
                language: language.to_string(),
            });
        }
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let child = entry.path();
        if should_skip(&child) {
            continue;
        }
        walk(&child, out);
    }
}

fn should_skip(path: &Path) -> bool {
    let Some(name) = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        name.as_str(),
        ".git" | "target" | "node_modules" | ".next" | "dist"
    )
}

fn language_from_path(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    match ext.as_str() {
        "py" => Some("python"),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some("javascript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::collect_source_files;

    #[test]
    fn collects_go_rust_and_java_sources() {
        let root = temp_path("aishield-scanner-lang-test");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("sample.go"), "package main\n").expect("write go");
        fs::write(root.join("sample.rs"), "fn main() {}\n").expect("write rust");
        fs::write(root.join("Sample.java"), "class Sample {}\n").expect("write java");
        fs::write(root.join("ignored.txt"), "noop\n").expect("write ignored");

        let files = collect_source_files(&root);
        let mut languages = files
            .iter()
            .map(|f| f.language.as_str())
            .collect::<Vec<_>>();
        languages.sort_unstable();

        assert_eq!(languages, vec!["go", "java", "rust"]);

        let _ = fs::remove_dir_all(root);
    }

    fn temp_path(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{stamp}"))
    }
}
