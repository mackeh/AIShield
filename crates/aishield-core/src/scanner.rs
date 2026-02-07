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
        _ => None,
    }
}
