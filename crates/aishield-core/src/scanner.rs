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
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())?;

    if file_name == "dockerfile" || file_name.starts_with("dockerfile.") {
        return Some("dockerfile");
    }

    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    match ext.as_str() {
        "py" => Some("python"),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some("javascript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        "cs" => Some("csharp"),
        "rb" => Some("ruby"),
        "php" | "phtml" => Some("php"),
        "kt" | "kts" => Some("kotlin"),
        "swift" => Some("swift"),
        "tf" | "hcl" => Some("terraform"),
        "yaml" | "yml" => {
            if looks_like_kubernetes_manifest(path) {
                Some("kubernetes")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn looks_like_kubernetes_manifest(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let hints = [
        "k8s",
        "kube",
        "kubernetes",
        "deployment",
        "daemonset",
        "statefulset",
        "service",
        "ingress",
        "pod",
        "cronjob",
        "helm",
        "manifest",
    ];
    hints.iter().any(|hint| lower.contains(hint))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::collect_source_files;

    #[test]
    fn collects_application_language_sources() {
        let root = temp_path("aishield-scanner-lang-test");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("sample.go"), "package main\n").expect("write go");
        fs::write(root.join("sample.rs"), "fn main() {}\n").expect("write rust");
        fs::write(root.join("Sample.java"), "class Sample {}\n").expect("write java");
        fs::write(root.join("Sample.cs"), "class Sample {}\n").expect("write csharp");
        fs::write(root.join("sample.rb"), "puts 'hi'\n").expect("write ruby");
        fs::write(root.join("sample.php"), "<?php echo 'hi';\n").expect("write php");
        fs::write(root.join("sample.kt"), "class Sample\n").expect("write kotlin");
        fs::write(root.join("sample.swift"), "print(\"hi\")\n").expect("write swift");
        fs::write(root.join("ignored.txt"), "noop\n").expect("write ignored");

        let files = collect_source_files(&root);
        let mut languages = files
            .iter()
            .map(|f| f.language.as_str())
            .collect::<Vec<_>>();
        languages.sort_unstable();

        assert_eq!(
            languages,
            vec!["csharp", "go", "java", "kotlin", "php", "ruby", "rust", "swift"]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn collects_infrastructure_languages() {
        let root = temp_path("aishield-scanner-infra-test");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("main.tf"),
            "resource \"aws_s3_bucket\" \"x\" {}\n",
        )
        .expect("write terraform");
        fs::write(
            root.join("Dockerfile"),
            "FROM ubuntu:latest\nRUN useradd app\n",
        )
        .expect("write dockerfile");
        fs::write(
            root.join("k8s-deployment.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\n",
        )
        .expect("write kubernetes yaml");
        fs::write(root.join("app-config.yaml"), "name: app\n").expect("write generic yaml");

        let files = collect_source_files(&root);
        let mut languages = files
            .iter()
            .map(|f| f.language.as_str())
            .collect::<Vec<_>>();
        languages.sort_unstable();

        assert_eq!(languages, vec!["dockerfile", "kubernetes", "terraform"]);

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
