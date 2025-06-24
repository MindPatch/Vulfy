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
        // Validate webhook URL before attempting to send
        if webhook.url.contains("YOUR_WEBHOOK_ID") || webhook.url.contains("YOUR_WEBHOOK_TOKEN") {
            return Err(anyhow::anyhow!(
                "Webhook '{}' has placeholder URL. Please update with actual webhook URL from Discord/Slack.", 
                webhook.name
            ));
        }

        let payload = match webhook.webhook_type {
            WebhookType::Discord => self.create_discord_payload(message),
            WebhookType::Slack => self.create_slack_payload(message),
            WebhookType::Generic => self.create_generic_payload(message),
        };

        info!("Sending notification to {}: {}", webhook.name, message.title);
        
        let response = self.client
            .post(&webhook.url)
            .json(&payload)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if response.status().is_success() {
            info!("Successfully sent notification to {}", webhook.name);
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Webhook request failed for {}: status {}, body: {}", webhook.name, status, body);
            Err(anyhow::anyhow!("Webhook request failed with status {}: {}", status, body))
        }
    }

    /// Create Discord webhook payload
    fn create_discord_payload(&self, message: &NotificationMessage) -> Value {
        let color = match message.severity.as_str() {
            "critical" => 0xDC143C, // Crimson Red
            "high" => 0xFF4500,     // Orange Red
            "medium" => 0xFFD700,   // Gold
            "low" => 0x32CD32,      // Lime Green
            _ => 0x808080,          // Gray
        };

        let severity_emoji = match message.severity.as_str() {
            "critical" => "🔥",
            "high" => "🟠",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪",
        };

        // Truncate description if too long for Discord (max 4096 characters)
        let description = if message.description.len() > 4000 {
            format!("{}...\n\n*Message truncated due to length*", &message.description[..3950])
        } else {
            message.description.clone()
        };

        json!({
            "embeds": [{
                "title": format!("{} {}", severity_emoji, message.title),
                "description": description,
                "color": color,
                "fields": [
                    {
                        "name": "📊 Summary",
                        "value": format!("**Total:** {} vulnerabilities\n**New:** {} vulnerabilities", 
                                       message.vulnerability_count, message.new_vulnerabilities),
                        "inline": true
                    },
                    {
                        "name": "🎯 Target",
                        "value": format!("**Repository:** `{}`\n**Branch:** `{}`", 
                                       message.repository, message.branch),
                        "inline": true
                    },
                    {
                        "name": "⏰ Scan Time",
                        "value": format!("<t:{}:R>", message.timestamp.timestamp()),
                        "inline": true
                    }
                ],
                "footer": {
                    "text": "Vulfy Security Scanner",
                    "icon_url": "https://raw.githubusercontent.com/MindPatch/Vulfy/refs/heads/master/assets/main_logo.png"
                },
                "timestamp": message.timestamp.to_rfc3339()
            }]
        })
    }

    /// Create Slack webhook payload
    fn create_slack_payload(&self, message: &NotificationMessage) -> Value {
        let severity_emoji = match message.severity.as_str() {
            "critical" => ":fire:",
            "high" => ":large_orange_circle:",
            "medium" => ":large_yellow_circle:",
            "low" => ":large_green_circle:",
            _ => ":white_circle:",
        };

        let color = match message.severity.as_str() {
            "critical" => "#DC143C",
            "high" => "#FF4500", 
            "medium" => "#FFD700",
            "low" => "#32CD32",
            _ => "#808080",
        };

        // Truncate description if too long for Slack
        let description = if message.description.len() > 3000 {
            format!("{}...\n\n_Message truncated due to length_", &message.description[..2950])
        } else {
            message.description.clone()
        };

        json!({
            "attachments": [{
                "color": color,
                "title": format!("{} {}", severity_emoji, message.title),
                "text": description,
                "fields": [
                    {
                        "title": "📊 Summary",
                        "value": format!("*Total:* {} vulnerabilities\n*New:* {} vulnerabilities", 
                                       message.vulnerability_count, message.new_vulnerabilities),
                        "short": true
                    },
                    {
                        "title": "🎯 Target", 
                        "value": format!("*Repository:* `{}`\n*Branch:* `{}`", 
                                       message.repository, message.branch),
                        "short": true
                    },
                    {
                        "title": "⏰ Scan Time",
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

        // IMPROVED: Better severity determination with proper CVSS parsing
        let (severity, severity_counts) = self.analyze_vulnerability_severity(&current_scan.vulnerabilities);

        // ENHANCED: Create detailed title and description with vulnerability info
        let title = if total_vulns == 0 {
            "✅ Security Scan Clean".to_string()
        } else {
            format!("🚨 {} {} Vulnerabilities Found", 
                    if new_vulns > 0 { "New" } else { "Total" },
                    severity_counts.iter()
                        .filter(|(_, &count)| count > 0)
                        .map(|(sev, count)| format!("{} {}", count, sev))
                        .collect::<Vec<_>>()
                        .join(", "))
        };

        let description = if total_vulns > 0 {
            let mut desc = format!(
                "🔍 **Repository:** `{}`\n📋 **Branch:** `{}`\n\n",
                current_scan.repository, current_scan.branch
            );

            // Add severity breakdown
            desc.push_str("**📊 Severity Breakdown:**\n");
            for (sev_name, &count) in &severity_counts {
                if count > 0 {
                    let emoji = match sev_name.as_str() {
                        "Critical" => "🔥",
                        "High" => "🟠", 
                        "Medium" => "🟡",
                        "Low" => "🟢",
                        _ => "⚪",
                    };
                    desc.push_str(&format!("{} **{}:** {} vulnerabilities\n", emoji, sev_name, count));
                }
            }

            // Add top vulnerabilities (up to 5 most severe)
            let mut sorted_vulns = current_scan.vulnerabilities.clone();
            sorted_vulns.sort_by(|a, b| {
                let a_level = self.get_severity_level(a.severity.as_deref());
                let b_level = self.get_severity_level(b.severity.as_deref());
                b_level.cmp(&a_level) // Descending order (highest severity first)
            });

            if !sorted_vulns.is_empty() {
                desc.push_str("\n**🎯 Top Vulnerabilities:**\n");
                for (i, vuln) in sorted_vulns.iter().take(5).enumerate() {
                    let severity_emoji = match self.get_severity_level(vuln.severity.as_deref()) {
                        4 => "🔥",
                        3 => "🟠",
                        2 => "🟡", 
                        1 => "🟢",
                        _ => "⚪",
                    };
                    
                    let title = if vuln.summary.len() > 60 {
                        format!("{}...", &vuln.summary[..57])
                    } else {
                        vuln.summary.clone()
                    };
                    
                    desc.push_str(&format!("{}. {} **{}**\n", i + 1, severity_emoji, title));
                }
                
                if sorted_vulns.len() > 5 {
                    desc.push_str(&format!("... and {} more vulnerabilities\n", sorted_vulns.len() - 5));
                }
            }

            if new_vulns > 0 {
                desc.push_str(&format!("\n💡 **{}** are newly discovered since last scan", new_vulns));
            }

            desc
        } else {
            format!(
                "✅ No vulnerabilities found in repository `{}` on branch `{}`. Great job! 🎉",
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

    /// Analyze vulnerability severity and return overall severity + counts
    fn analyze_vulnerability_severity(&self, vulnerabilities: &[crate::automation::Vulnerability]) -> (String, std::collections::HashMap<String, usize>) {
        let mut severity_counts = std::collections::HashMap::new();
        severity_counts.insert("Critical".to_string(), 0);
        severity_counts.insert("High".to_string(), 0);
        severity_counts.insert("Medium".to_string(), 0);
        severity_counts.insert("Low".to_string(), 0);
        severity_counts.insert("Unknown".to_string(), 0);

        let mut max_severity_level = 0;
        let mut overall_severity = "low".to_string();

        for vuln in vulnerabilities {
            let level = self.get_severity_level(vuln.severity.as_deref());
            
            let severity_name = match level {
                4 => "Critical",
                3 => "High", 
                2 => "Medium",
                1 => "Low",
                _ => "Unknown",
            };
            
            *severity_counts.get_mut(severity_name).unwrap() += 1;
            
            if level > max_severity_level {
                max_severity_level = level;
                overall_severity = match level {
                    4 => "critical",
                    3 => "high",
                    2 => "medium", 
                    1 => "low",
                    _ => "unknown",
                }.to_string();
            }
        }

        (overall_severity, severity_counts)
    }

    /// Get severity level from severity string (same logic as scheduler)
    fn get_severity_level(&self, severity: Option<&str>) -> u8 {
        match severity {
            Some(s) => {
                let severity_lower = s.to_lowercase();
                
                // Handle CVSS format
                if severity_lower.starts_with("cvss:") {
                    // Extract base score if present
                    if let Some(score_start) = s.find("/AV:") {
                        let score_part = &s[..score_start];
                        if let Some(version_end) = score_part.rfind('/') {
                            if let Ok(base_score) = score_part[version_end + 1..].parse::<f32>() {
                                return match base_score {
                                    score if score >= 9.0 => 4, // Critical (9.0-10.0)
                                    score if score >= 7.0 => 3, // High (7.0-8.9)
                                    score if score >= 4.0 => 2, // Medium (4.0-6.9)
                                    score if score >= 0.1 => 1, // Low (0.1-3.9)
                                    _ => 0,
                                };
                            }
                        }
                    }
                    
                    // Fallback: analyze impact scores
                    let high_impact_count = ["C:H", "I:H", "A:H"].iter()
                        .filter(|&impact| s.contains(impact))
                        .count();
                    
                    return match high_impact_count {
                        3 => 4, // Critical
                        2 => 3, // High
                        1 => 3, // High
                        _ => 2, // Medium/Low
                    };
                }
                
                // Handle simple severity strings
                match severity_lower.as_str() {
                    s if s.contains("critical") => 4,
                    s if s.contains("high") => 3,
                    s if s.contains("medium") || s.contains("moderate") => 2,
                    s if s.contains("low") => 1,
                    _ => 0,
                }
            }
            None => 0,
        }
    }
}

impl Default for WebhookNotifier {
    fn default() -> Self {
        Self::new()
    }
} 
