use serde_json::{json, Value};
use reqwest::Client;
use tracing::{info, error};
use anyhow::Result;
use super::{ScanResult, NotificationMessage, Webhook, WebhookType};

pub struct WebhookNotifier {
    client: Client,
}

impl WebhookNotifier {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Send notification to all enabled webhooks
    pub async fn send_notifications(&self, webhooks: &[Webhook], message: &NotificationMessage) -> Result<()> {
        let mut results = Vec::new();
        
        for webhook in webhooks.iter().filter(|w| w.enabled) {
            let result = self.send_webhook_notification(webhook, message).await;
            if let Err(ref e) = result {
                error!("Failed to send notification to {}: {}", webhook.name, e);
            } else {
                info!("Successfully sent notification to {}", webhook.name);
            }
            results.push(result);
        }

        // Return error if all webhooks failed
        if results.iter().all(|r| r.is_err()) && !results.is_empty() {
            return Err(anyhow::anyhow!("All webhook notifications failed"));
        }

        Ok(())
    }

    /// Send notification to a specific webhook
    async fn send_webhook_notification(&self, webhook: &Webhook, message: &NotificationMessage) -> Result<()> {
        let payload = match webhook.webhook_type {
            WebhookType::Discord => self.create_discord_payload(message),
            WebhookType::Slack => self.create_slack_payload(message),
            WebhookType::Generic => self.create_generic_payload(message),
        };

        let response = self.client
            .post(&webhook.url)
            .json(&payload)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Webhook request failed with status {}: {}", status, body))
        }
    }

    /// Create Discord webhook payload
    fn create_discord_payload(&self, message: &NotificationMessage) -> Value {
        let color = match message.severity.as_str() {
            "critical" => 0xFF0000, // Red
            "high" => 0xFF6600,     // Orange
            "medium" => 0xFFFF00,   // Yellow
            "low" => 0x00FF00,      // Green
            _ => 0x808080,          // Gray
        };

        let severity_emoji = match message.severity.as_str() {
            "critical" => "🚨",
            "high" => "🔥",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪",
        };

        json!({
            "embeds": [{
                "title": format!("{} {}", severity_emoji, message.title),
                "description": message.description,
                "color": color,
                "fields": [
                    {
                        "name": "Repository",
                        "value": format!("`{}`", message.repository),
                        "inline": true
                    },
                    {
                        "name": "Branch",
                        "value": format!("`{}`", message.branch),
                        "inline": true
                    },
                    {
                        "name": "Severity",
                        "value": format!("{} {}", severity_emoji, message.severity.to_uppercase()),
                        "inline": true
                    },
                    {
                        "name": "Total Vulnerabilities",
                        "value": message.vulnerability_count.to_string(),
                        "inline": true
                    },
                    {
                        "name": "New Vulnerabilities",
                        "value": message.new_vulnerabilities.to_string(),
                        "inline": true
                    },
                    {
                        "name": "Scan Time",
                        "value": format!("<t:{}:R>", message.timestamp.timestamp()),
                        "inline": true
                    }
                ],
                "footer": {
                    "text": "Vulfy Security Scanner",
                    "icon_url": "https://github.com/mindPatch/vulfy/raw/main/assets/main_logo.png"
                },
                "timestamp": message.timestamp.to_rfc3339()
            }]
        })
    }

    /// Create Slack webhook payload
    fn create_slack_payload(&self, message: &NotificationMessage) -> Value {
        let severity_emoji = match message.severity.as_str() {
            "critical" => ":rotating_light:",
            "high" => ":fire:",
            "medium" => ":warning:",
            "low" => ":large_green_circle:",
            _ => ":white_circle:",
        };

        let color = match message.severity.as_str() {
            "critical" => "#FF0000",
            "high" => "#FF6600", 
            "medium" => "#FFFF00",
            "low" => "#00FF00",
            _ => "#808080",
        };

        json!({
            "attachments": [{
                "color": color,
                "title": format!("{} {}", severity_emoji, message.title),
                "text": message.description,
                "fields": [
                    {
                        "title": "Repository",
                        "value": format!("`{}`", message.repository),
                        "short": true
                    },
                    {
                        "title": "Branch", 
                        "value": format!("`{}`", message.branch),
                        "short": true
                    },
                    {
                        "title": "Severity",
                        "value": format!("{} {}", severity_emoji, message.severity.to_uppercase()),
                        "short": true
                    },
                    {
                        "title": "Total Vulnerabilities",
                        "value": message.vulnerability_count.to_string(),
                        "short": true
                    },
                    {
                        "title": "New Vulnerabilities", 
                        "value": message.new_vulnerabilities.to_string(),
                        "short": true
                    },
                    {
                        "title": "Scan Time",
                        "value": format!("<!date^{}^{{date_short_pretty}} at {{time}}|{}>", 
                               message.timestamp.timestamp(), 
                               message.timestamp.format("%Y-%m-%d %H:%M:%S UTC")),
                        "short": true
                    }
                ],
                "footer": "Vulfy Security Scanner",
                "footer_icon": "https://github.com/mindPatch/vulfy/raw/main/assets/main_logo.png",
                "ts": message.timestamp.timestamp()
            }]
        })
    }

    /// Create generic webhook payload (JSON format)
    fn create_generic_payload(&self, message: &NotificationMessage) -> Value {
        json!({
            "title": message.title,
            "description": message.description,
            "severity": message.severity,
            "repository": message.repository,
            "branch": message.branch,
            "vulnerability_count": message.vulnerability_count,
            "new_vulnerabilities": message.new_vulnerabilities,
            "scan_url": message.scan_url,
            "timestamp": message.timestamp,
            "source": "vulfy-security-scanner"
        })
    }

    /// Create notification message from scan results
    pub fn create_notification_from_scan(&self, current_scan: &ScanResult, previous_scan: Option<&ScanResult>) -> NotificationMessage {
        let total_vulns = current_scan.vulnerabilities.len();
        
        // Calculate new vulnerabilities by comparing with previous scan
        let new_vulns = if let Some(prev) = previous_scan {
            let prev_ids: std::collections::HashSet<_> = prev.vulnerabilities.iter()
                .map(|v| &v.id)
                .collect();
            
            current_scan.vulnerabilities.iter()
                .filter(|v| !prev_ids.contains(&v.id))
                .count()
        } else {
            total_vulns // All vulnerabilities are "new" if no previous scan
        };

        // Determine overall severity - use severity field directly
        let severity = if current_scan.vulnerabilities.iter().any(|v| 
            v.severity.as_ref().map_or(false, |s| s.to_lowercase().contains("critical"))
        ) {
            "critical"
        } else if current_scan.vulnerabilities.iter().any(|v| 
            v.severity.as_ref().map_or(false, |s| s.to_lowercase().contains("high"))
        ) {
            "high"
        } else if current_scan.vulnerabilities.iter().any(|v| 
            v.severity.as_ref().map_or(false, |s| s.to_lowercase().contains("medium"))
        ) {
            "medium"
        } else {
            "low"
        };

        let title = if new_vulns > 0 {
            format!("Security Alert: {} New Vulnerabilities Found", new_vulns)
        } else {
            "Security Scan Completed".to_string()
        };

        let description = if total_vulns > 0 {
            format!(
                "Found {} vulnerabilities in repository `{}` on branch `{}`. {} are newly discovered.",
                total_vulns, current_scan.repository, current_scan.branch, new_vulns
            )
        } else {
            format!(
                "No vulnerabilities found in repository `{}` on branch `{}`. Great job! 🎉",
                current_scan.repository, current_scan.branch
            )
        };

        NotificationMessage {
            title,
            description,
            severity: severity.to_string(),
            repository: current_scan.repository.clone(),
            branch: current_scan.branch.clone(),
            vulnerability_count: total_vulns,
            new_vulnerabilities: new_vulns,
            scan_url: None, // Could be populated with a link to detailed results
            timestamp: current_scan.timestamp,
        }
    }
}

impl Default for WebhookNotifier {
    fn default() -> Self {
        Self::new()
    }
} 