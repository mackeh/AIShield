use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Analytics configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyticsConfig {
    /// Enable analytics push
    #[serde(default)]
    pub enabled: bool,

    /// Analytics API URL
    #[serde(default)]
    pub url: Option<String>,

    /// API key for authentication
    #[serde(default)]
    pub api_key: Option<String>,

    /// Organization ID
    #[serde(default)]
    pub org_id: Option<String>,

    /// Team ID
    #[serde(default)]
    pub team_id: Option<String>,
}

/// Root configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub analytics: AnalyticsConfig,
}

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self, String> {
        let config_path = Self::get_config_path()?;

        if !config_path.exists() {
            return Ok(Config::default());
        }

        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse config file: {}", e))
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<(), String> {
        let config_path = Self::get_config_path()?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        fs::write(&config_path, content).map_err(|e| format!("Failed to write config file: {}", e))
    }

    /// Get the config file path
    pub fn get_config_path() -> Result<PathBuf, String> {
        let config_dir =
            dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;

        Ok(config_dir.join("aishield").join("config.toml"))
    }

    /// Merge with environment variables (env vars take precedence)
    pub fn merge_with_env(mut self) -> Self {
        if let Ok(url) = std::env::var("AISHIELD_ANALYTICS_URL") {
            self.analytics.url = Some(url);
        }

        if let Ok(api_key) = std::env::var("AISHIELD_API_KEY") {
            self.analytics.api_key = Some(api_key);
        }

        if let Ok(org_id) = std::env::var("AISHIELD_ORG_ID") {
            self.analytics.org_id = Some(org_id);
        }

        if let Ok(team_id) = std::env::var("AISHIELD_TEAM_ID") {
            self.analytics.team_id = Some(team_id);
        }

        if let Ok(enabled) = std::env::var("AISHIELD_ANALYTICS_ENABLED") {
            self.analytics.enabled = enabled.to_lowercase() == "true" || enabled == "1";
        }

        self
    }

    /// Set a configuration value by dot-notation key
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "analytics.enabled" => {
                self.analytics.enabled = value.to_lowercase() == "true" || value == "1";
            }
            "analytics.url" => {
                self.analytics.url = Some(value.to_string());
            }
            "analytics.api_key" => {
                self.analytics.api_key = Some(value.to_string());
            }
            "analytics.org_id" => {
                self.analytics.org_id = Some(value.to_string());
            }
            "analytics.team_id" => {
                self.analytics.team_id = Some(value.to_string());
            }
            _ => return Err(format!("Unknown config key: {}", key)),
        }
        Ok(())
    }

    /// Get a configuration value by dot-notation key
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "analytics.enabled" => Some(self.analytics.enabled.to_string()),
            "analytics.url" => self.analytics.url.clone(),
            "analytics.api_key" => self
                .analytics
                .api_key
                .clone()
                .map(|_| "***hidden***".to_string()),
            "analytics.org_id" => self.analytics.org_id.clone(),
            "analytics.team_id" => self.analytics.team_id.clone(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_set_get() {
        let mut config = Config::default();

        config.set("analytics.enabled", "true").unwrap();
        assert_eq!(config.analytics.enabled, true);

        config
            .set("analytics.url", "http://localhost:8080")
            .unwrap();
        assert_eq!(
            config.analytics.url,
            Some("http://localhost:8080".to_string())
        );

        assert_eq!(config.get("analytics.enabled"), Some("true".to_string()));
        assert_eq!(
            config.get("analytics.url"),
            Some("http://localhost:8080".to_string())
        );
    }

    #[test]
    fn test_merge_with_env() {
        std::env::set_var("AISHIELD_ANALYTICS_URL", "http://env:8080");
        std::env::set_var("AISHIELD_ORG_ID", "test/org");

        let mut config = Config::default();
        config.analytics.url = Some("http://config:8080".to_string());

        let merged = config.merge_with_env();

        // Env var should override config
        assert_eq!(merged.analytics.url, Some("http://env:8080".to_string()));
        assert_eq!(merged.analytics.org_id, Some("test/org".to_string()));

        std::env::remove_var("AISHIELD_ANALYTICS_URL");
        std::env::remove_var("AISHIELD_ORG_ID");
    }
}
