use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use regex::Regex;
use crate::types::{Ecosystem, Vulnerability};
use anyhow::Result;

pub mod scheduler;
pub mod git_monitor;
pub mod webhooks;
pub mod policy;

/// Main automation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationConfig {
    pub repositories: Vec<Repository>,
    pub schedule: Schedule,
    pub notifications: NotificationConfig,
    pub policies: Vec<ScanPolicy>,
    pub storage: StorageConfig,
}

/// Repository configuration for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    pub url: String,
    pub branches: Option<Vec<String>>, // None means monitor default branch only
    pub local_path: Option<PathBuf>,
    pub credentials: Option<Credentials>,
    pub ecosystems: Option<Vec<Ecosystem>>, // Filter specific ecosystems for this repo
}

/// Git credentials for private repositories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: Option<String>,
    pub token: Option<String>, // GitHub/GitLab token
    pub ssh_key_path: Option<PathBuf>,
}

/// Scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub frequency: ScheduleFrequency,
    pub time: Option<String>, // For daily/weekly: "14:30", for hourly: ignored
    pub timezone: Option<String>, // Default: UTC
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleFrequency {
    Hourly,
    Daily,
    Weekly,
    Custom(String), // Cron expression
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub webhooks: Vec<Webhook>,
    pub filters: NotificationFilters,
}

/// Webhook configuration for Discord/Slack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub name: String,
    pub url: String,
    pub webhook_type: WebhookType,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookType {
    Discord,
    Slack,
    Generic, // For custom webhook formats
}

impl std::fmt::Display for WebhookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookType::Discord => write!(f, "Discord"),
            WebhookType::Slack => write!(f, "Slack"),
            WebhookType::Generic => write!(f, "Generic"),
        }
    }
}

/// Notification filtering options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFilters {
    pub min_severity: Option<String>, // "high", "medium", "low"
    pub only_new_vulnerabilities: bool,
    pub repositories: Option<Vec<String>>, // Only notify for specific repos
}

/// Scan policy for filtering vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPolicy {
    pub name: String,
    pub enabled: bool,
    pub conditions: PolicyConditions,
    pub actions: PolicyActions,
}

/// Policy conditions for matching vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConditions {
    pub title_contains: Option<Vec<String>>, // Keywords like "unauth", "xss"
    pub severity: Option<Vec<String>>, // "critical", "high", "medium", "low"
    pub ecosystems: Option<Vec<Ecosystem>>,
    pub cve_pattern: Option<String>, // Regex pattern for CVE IDs
    pub packages: Option<Vec<String>>, // Specific package names
}

/// Policy actions when conditions are met
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyActions {
    pub notify: bool,
    pub priority: PolicyPriority,
    pub custom_message: Option<String>,
    pub ignore: bool, // Ignore vulnerabilities matching this policy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Storage configuration for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_path: Option<PathBuf>,
    pub retain_days: u32, // How long to keep scan history
    pub export_format: Option<String>, // "json", "csv", "sarif"
    pub export_path: Option<PathBuf>,
}

/// Scan result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub repository: String,
    pub branch: String,
    pub timestamp: DateTime<Utc>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub total_packages: usize,
    pub scan_duration_ms: u64,
    pub policies_applied: Vec<String>,
}

/// Notification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationMessage {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub repository: String,
    pub branch: String,
    pub vulnerability_count: usize,
    pub new_vulnerabilities: usize,
    pub scan_url: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl AutomationConfig {
    /// Load configuration from file
    pub async fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: AutomationConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub async fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }

    /// Create a default configuration
    pub fn default_config() -> Self {
        Self {
            repositories: vec![],
            schedule: Schedule {
                frequency: ScheduleFrequency::Daily,
                time: Some("02:00".to_string()),
                timezone: Some("UTC".to_string()),
            },
            notifications: NotificationConfig {
                enabled: true,
                webhooks: vec![],
                filters: NotificationFilters {
                    min_severity: Some("medium".to_string()),
                    only_new_vulnerabilities: true,
                    repositories: None,
                },
            },
            policies: vec![],
            storage: StorageConfig {
                database_path: Some(PathBuf::from("vulfy_automation.db")),
                retain_days: 30,
                export_format: Some("json".to_string()),
                export_path: Some(PathBuf::from("vulfy_exports")),
            },
        }
    }
}

impl ScanPolicy {
    /// Check if a vulnerability matches this policy
    pub fn matches(&self, vulnerability: &Vulnerability) -> bool {
        if !self.enabled {
            return false;
        }

        let conditions = &self.conditions;

        // Check title contains keywords
        if let Some(keywords) = &conditions.title_contains {
            let title_lower = vulnerability.summary.to_lowercase();
            let has_keyword = keywords.iter().any(|keyword| {
                title_lower.contains(&keyword.to_lowercase())
            });
            if !has_keyword {
                return false;
            }
        }

        // Check severity
        if let Some(severities) = &conditions.severity {
            if let Some(vuln_severity) = &vulnerability.severity {
                let vuln_severity_lower = vuln_severity.to_lowercase();
                if !severities.iter().any(|s| vuln_severity_lower.contains(&s.to_lowercase())) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check CVE pattern
        if let Some(pattern) = &conditions.cve_pattern {
            if let Ok(regex) = Regex::new(pattern) {
                if !regex.is_match(&vulnerability.id) {
                    return false;
                }
            }
        }

        // Check packages
        if let Some(_packages) = &conditions.packages {
            // This would need to be checked against the package name from scan context
            // For now, we'll skip this check as we don't have package context in Vulnerability
        }

        true
    }
} 