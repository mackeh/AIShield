use std::path::Path;
use std::process::Command;

/// Get the git remote URL for a repository
pub fn get_git_remote_url(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(&["-C", path.to_str()?, "remote", "get-url", "origin"])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

/// Get the current git branch
pub fn get_git_branch(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(&["-C", path.to_str()?, "rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

/// Get the current git commit SHA
pub fn get_git_commit_sha(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(&["-C", path.to_str()?, "rev-parse", "HEAD"])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

/// Extract repository ID from git remote URL
/// Examples:
/// - "https://github.com/acme/repo.git" → "github.com/acme/repo"
/// - "git@github.com:acme/repo.git" → "github.com/acme/repo"  
/// - "/local/path" → "local/path"
pub fn extract_repo_id(remote_url: &str) -> String {
    // Remove .git suffix
    let url = remote_url.trim_end_matches(".git");

    // Handle git@github.com:user/repo format
    if url.starts_with("git@") {
        if let Some(colon_pos) = url.find(':') {
            let host_part = &url[4..colon_pos]; // Skip "git@"
            let path_part = &url[colon_pos + 1..];
            return format!("{}/{}", host_part, path_part);
        }
    }

    // Handle https://github.com/user/repo format
    if url.starts_with("http://") || url.starts_with("https://") {
        if let Some(domain_start) = url.find("://") {
            return url[domain_start + 3..].to_string();
        }
    }

    // Fallback: return as-is
    url.to_string()
}

/// Get repository name from path
pub fn get_repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Get full repository metadata
pub struct RepoMetadata {
    pub repo_id: String,
    pub repo_name: String,
    pub branch: String,
    pub commit_sha: String,
}

impl RepoMetadata {
    pub fn from_path(path: &Path) -> Self {
        let repo_name = get_repo_name(path);

        let remote_url = get_git_remote_url(path);
        let repo_id = match &remote_url {
            Some(url) => extract_repo_id(url),
            None => format!("local/{}", repo_name),
        };

        let branch = get_git_branch(path).unwrap_or_else(|| "unknown".to_string());
        let commit_sha = get_git_commit_sha(path).unwrap_or_else(|| "unknown".to_string());

        Self {
            repo_id,
            repo_name,
            branch,
            commit_sha,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_repo_id() {
        assert_eq!(
            extract_repo_id("https://github.com/acme/repo.git"),
            "github.com/acme/repo"
        );

        assert_eq!(
            extract_repo_id("git@github.com:acme/repo.git"),
            "github.com/acme/repo"
        );

        assert_eq!(
            extract_repo_id("https://gitlab.com/group/project"),
            "gitlab.com/group/project"
        );
    }
}
