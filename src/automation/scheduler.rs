use tokio_cron_scheduler::{JobScheduler, Job};
use tracing::{info, error, warn};
use std::sync::Arc;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::str::FromStr;
use cron::Schedule;
use anyhow::Result;
use chrono::Timelike;
use crate::automation::{
    AutomationConfig, ScheduleFrequency, ScanResult,
    git_monitor::GitMonitor, webhooks::WebhookNotifier, policy::PolicyEngine,
};

pub struct AutomationScheduler {
    scheduler: JobScheduler,
    config: Arc<AutomationConfig>,
    git_monitor: Arc<GitMonitor>,
    webhook_notifier: Arc<WebhookNotifier>,
    policy_engine: Arc<PolicyEngine>,
    is_running: Arc<AtomicBool>,
}

impl AutomationScheduler {
    pub async fn new(config: AutomationConfig, workspace_dir: PathBuf) -> Result<Self> {
        let scheduler = JobScheduler::new().await?;
        let git_monitor = Arc::new(GitMonitor::new(workspace_dir));
        let webhook_notifier = Arc::new(WebhookNotifier::new());
        let policy_engine = Arc::new(PolicyEngine::new(config.policies.clone()));
        
        // Initialize the workspace
        git_monitor.init_workspace().await?;
        
        Ok(Self {
            scheduler,
            config: Arc::new(config),
            git_monitor,
            webhook_notifier,
            policy_engine,
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the scheduler with the configured schedule
    pub async fn start(&mut self) -> Result<()> {
        let cron_expression = self.build_cron_expression();
        info!("Starting automation scheduler with cron expression: {}", cron_expression);

        // Clone the necessary data for the job closure
        let config = Arc::clone(&self.config);
        let git_monitor = Arc::clone(&self.git_monitor);
        let webhook_notifier = Arc::clone(&self.webhook_notifier);
        let policy_engine = Arc::clone(&self.policy_engine);

        let job = Job::new_async(cron_expression.as_str(), move |_uuid, _l| {
            let config = Arc::clone(&config);
            let git_monitor = Arc::clone(&git_monitor);
            let webhook_notifier = Arc::clone(&webhook_notifier);
            let policy_engine = Arc::clone(&policy_engine);

            Box::pin(async move {
                info!("Starting scheduled vulnerability scan");
                
                if let Err(e) = run_scheduled_scan(config, git_monitor, webhook_notifier, policy_engine).await {
                    error!("Scheduled scan failed: {}", e);
                } else {
                    info!("Scheduled scan completed successfully");
                }
            })
        })?;

        self.scheduler.add(job).await?;
        self.scheduler.start().await?;
        self.is_running.store(true, Ordering::Relaxed);
        
        info!("Automation scheduler started successfully");
        Ok(())
    }

    /// Stop the scheduler
    pub async fn stop(&mut self) -> Result<()> {
        self.scheduler.shutdown().await?;
        self.is_running.store(false, Ordering::Relaxed);
        info!("Automation scheduler stopped");
        Ok(())
    }

    /// Run a manual scan (outside of the schedule)
    pub async fn run_manual_scan(&self) -> Result<Vec<ScanResult>> {
        info!("Starting manual vulnerability scan");
        
        let results = run_scheduled_scan(
            Arc::clone(&self.config),
            Arc::clone(&self.git_monitor),
            Arc::clone(&self.webhook_notifier),
            Arc::clone(&self.policy_engine),
        ).await?;

        info!("Manual scan completed successfully");
        Ok(results)
    }

    /// Build cron expression from schedule configuration
    fn build_cron_expression(&self) -> String {
        let schedule = &self.config.schedule;
        
        match &schedule.frequency {
            ScheduleFrequency::Hourly => {
                // Run every hour from the current time (e.g., if started at 14:35, run at 15:35, 16:35, etc.)
                let now = chrono::Utc::now();
                let minute = now.minute();
                let second = now.second();
                format!("{} {} * * * *", second, minute)
            }
            ScheduleFrequency::Daily => {
                if let Some(time) = &schedule.time {
                    if let Some((hour, minute)) = parse_time(time) {
                        format!("0 {} {} * * *", minute, hour)
                    } else {
                        warn!("Invalid time format '{}', using default 02:00", time);
                        "0 0 2 * * *".to_string() // 2:00 AM daily
                    }
                } else {
                    "0 0 2 * * *".to_string() // 2:00 AM daily
                }
            }
            ScheduleFrequency::Weekly => {
                if let Some(time) = &schedule.time {
                    if let Some((hour, minute)) = parse_time(time) {
                        format!("0 {} {} * * 1", minute, hour) // Monday
                    } else {
                        warn!("Invalid time format '{}', using default 02:00", time);
                        "0 0 2 * * 1".to_string() // 2:00 AM on Monday
                    }
                } else {
                    "0 0 2 * * 1".to_string() // 2:00 AM on Monday
                }
            }
            ScheduleFrequency::Custom(cron) => {
                cron.clone()
            }
        }
    }

    /// Check if scheduler is running
    pub async fn is_running(&self) -> bool {
        // For tokio-cron-scheduler, we'll just return true if we have a scheduler
        // A more sophisticated implementation would track the running state
        self.is_running.load(Ordering::Relaxed)
    }

    /// Get next scheduled run time
    pub async fn next_run_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        // Calculate the next run time based on the cron expression
        let cron_expression = self.build_cron_expression();
        
        // Use cron crate to parse and calculate next occurrence
        if let Ok(schedule) = Schedule::from_str(&cron_expression) {
            schedule.upcoming(chrono::Utc).next()
        } else {
            warn!("Invalid cron expression: {}", cron_expression);
            None
        }
    }
}

/// Run a complete scan cycle for all configured repositories
async fn run_scheduled_scan(
    config: Arc<AutomationConfig>,
    git_monitor: Arc<GitMonitor>,
    webhook_notifier: Arc<WebhookNotifier>,
    policy_engine: Arc<PolicyEngine>,
) -> Result<Vec<ScanResult>> {
    let mut all_results = Vec::new();

    for repository in &config.repositories {
        info!("Processing repository: {}", repository.name);
        
        match git_monitor.scan_repository(repository).await {
            Ok(results) => {
                for (result, packages) in results {
                    // Store the original scan result BEFORE policy filtering
                    all_results.push(result.clone());
                    
                    // Apply policies to filter results for notifications
                    let mut filtered_result = policy_engine.apply_policies(&result, &packages);
                    
                    // CRITICAL FIX: Filter vulnerabilities by minimum severity BEFORE creating notification
                    if let Some(min_severity) = &config.notifications.filters.min_severity {
                        let min_level = severity_level(min_severity);
                        filtered_result.scan_result.vulnerabilities.retain(|v| {
                            if let Some(severity) = &v.severity {
                                let level = severity_level(severity);
                                level >= min_level
                            } else {
                                false // Exclude vulnerabilities with no severity info
                            }
                        });
                        
                        info!("Policy filtering: {} original -> {} filtered vulnerabilities (min_severity: '{}')", 
                              result.vulnerabilities.len(),
                              filtered_result.scan_result.vulnerabilities.len(), 
                              min_severity);
                    }
                    
                    // Send notifications if enabled and conditions are met
                    if config.notifications.enabled && should_notify(&filtered_result, &config.notifications.filters) {
                        let notification = webhook_notifier.create_notification_from_scan(&filtered_result.scan_result, None);
                        
                        if let Err(e) = webhook_notifier.send_notifications(&config.notifications.webhooks, &notification).await {
                            error!("Failed to send notifications for {}/{}: {}", 
                                   result.repository, result.branch, e);
                        } else {
                            info!("Sent notifications for {}/{} - {} vulnerabilities after policy filtering", 
                                  result.repository, result.branch, filtered_result.scan_result.vulnerabilities.len());
                        }
                    } else {
                        info!("No notifications sent for {}/{} - {} vulnerabilities found but filtered out by policies", 
                              result.repository, result.branch, result.vulnerabilities.len());
                    }
                }
            }
            Err(e) => {
                error!("Failed to scan repository {}: {}", repository.name, e);
                
                // Send error notification
                if config.notifications.enabled {
                    let error_notification = create_error_notification(&repository.name, &e.to_string());
                    if let Err(e) = webhook_notifier.send_notifications(&config.notifications.webhooks, &error_notification).await {
                        error!("Failed to send error notification: {}", e);
                    }
                }
            }
        }
    }

    Ok(all_results)
}

/// Check if a notification should be sent based on filters
fn should_notify(
    filtered_result: &crate::automation::policy::FilteredScanResult,
    filters: &crate::automation::NotificationFilters,
) -> bool {
    let result = &filtered_result.scan_result;
    
    // Check if there are any vulnerabilities first
    if result.vulnerabilities.is_empty() {
        info!("No vulnerabilities found, skipping notification");
        return false;
    }

    // Check minimum severity - FIXED: Better CVSS and severity parsing
    if let Some(min_severity) = &filters.min_severity {
        let qualifying_vulnerabilities: Vec<_> = result.vulnerabilities.iter()
            .filter(|v| {
                if let Some(severity) = &v.severity {
                    let level = severity_level(severity);
                    let min_level = severity_level(min_severity);
                    level >= min_level
                } else {
                    false
                }
            })
            .collect();
        
        if qualifying_vulnerabilities.is_empty() {
            info!("No vulnerabilities meet minimum severity requirement of '{}'. Found {} total vulnerabilities but none qualify.", 
                  min_severity, result.vulnerabilities.len());
            return false;
        } else {
            info!("Found {} vulnerabilities meeting minimum severity '{}' out of {} total", 
                  qualifying_vulnerabilities.len(), min_severity, result.vulnerabilities.len());
        }
    }

    // Check repository filter
    if let Some(repos) = &filters.repositories {
        if !repos.contains(&result.repository) {
            info!("Repository '{}' not in notification filter list", result.repository);
            return false;
        }
    }

    // For only_new_vulnerabilities filter:
    // If we don't have persistent storage to compare against previous scans,
    // we'll be more lenient and allow notifications for significant findings
    if filters.only_new_vulnerabilities {
        // Note: In a full implementation, this would compare against stored previous scan results
        // For now, we'll allow notifications if there are any vulnerabilities, since we can't
        // reliably determine what's "new" without persistent storage
        info!("only_new_vulnerabilities=true, but no previous scan data available. Allowing notification for {} vulnerabilities.", result.vulnerabilities.len());
    }

    info!("Notification criteria met: {} vulnerabilities found", result.vulnerabilities.len());
    true
}

/// Convert severity string to numeric level for comparison - IMPROVED CVSS parsing
fn severity_level(severity: &str) -> u8 {
    let severity_lower = severity.to_lowercase();
    
    // Handle CVSS format (e.g., "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if severity_lower.starts_with("cvss:") {
        // Extract base score if present (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:L/MI:L/MA:L")
        if let Some(score_start) = severity.find("/AV:") {
            let score_part = &severity[..score_start];
            if let Some(version_end) = score_part.rfind('/') {
                if let Ok(base_score) = score_part[version_end + 1..].parse::<f32>() {
                    return match base_score {
                        s if s >= 9.0 => 4, // Critical (9.0-10.0)
                        s if s >= 7.0 => 3, // High (7.0-8.9)
                        s if s >= 4.0 => 2, // Medium (4.0-6.9)
                        s if s >= 0.1 => 1, // Low (0.1-3.9)
                        _ => 0,
                    };
                }
            }
        }
        
        // Fallback: analyze impact scores for CVSS without base score
        let high_impact_count = ["C:H", "I:H", "A:H"].iter()
            .filter(|&impact| severity.contains(impact))
            .count();
        
        let medium_impact_count = ["C:M", "I:M", "A:M"].iter()
            .filter(|&impact| severity.contains(impact))
            .count();
            
        return match high_impact_count {
            3 => 4, // Critical - High impact on all three (Confidentiality, Integrity, Availability)
            2 => 3, // High - High impact on two categories
            1 => 3, // High - High impact on at least one category
            0 if medium_impact_count >= 2 => 2, // Medium - Medium impact on multiple categories
            0 if medium_impact_count >= 1 => 2, // Medium - Medium impact on at least one category
            _ => 1, // Low - Low or no significant impact
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

/// Parse time string in format "HH:MM" to (hour, minute)
fn parse_time(time_str: &str) -> Option<(u8, u8)> {
    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() == 2 {
        if let (Ok(hour), Ok(minute)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
            if hour < 24 && minute < 60 {
                return Some((hour, minute));
            }
        }
    }
    None
}

/// Create error notification message
fn create_error_notification(repository_name: &str, error_message: &str) -> crate::automation::NotificationMessage {
    crate::automation::NotificationMessage {
        title: "Repository Scan Failed".to_string(),
        description: format!("Failed to scan repository `{}`: {}", repository_name, error_message),
        severity: "high".to_string(),
        repository: repository_name.to_string(),
        branch: "unknown".to_string(),
        vulnerability_count: 0,
        new_vulnerabilities: 0,
        scan_url: None,
        timestamp: chrono::Utc::now(),
    }
} 