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
                    // Apply policies to filter results
                    let filtered_result = policy_engine.apply_policies(&result, &packages);
                    
                    // Send notifications if enabled and conditions are met
                    if config.notifications.enabled && should_notify(&filtered_result, &config.notifications.filters) {
                        let notification = webhook_notifier.create_notification_from_scan(&filtered_result.scan_result, None);
                        
                        if let Err(e) = webhook_notifier.send_notifications(&config.notifications.webhooks, &notification).await {
                            error!("Failed to send notifications for {}/{}: {}", 
                                   result.repository, result.branch, e);
                        } else {
                            info!("Sent notifications for {}/{}", result.repository, result.branch);
                        }
                    }
                    
                    all_results.push(filtered_result.scan_result);
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

    // Check minimum severity
    if let Some(min_severity) = &filters.min_severity {
        let has_qualifying_severity = result.vulnerabilities.iter().any(|v| {
            if let Some(severity) = &v.severity {
                let level = severity_level(severity);
                let min_level = severity_level(min_severity);
                info!("Checking severity: '{}' (level {}) >= '{}' (level {})", 
                     severity, level, min_severity, min_level);
                level >= min_level
            } else {
                false
            }
        });
        
        if !has_qualifying_severity {
            info!("No vulnerabilities meet minimum severity requirement of '{}'", min_severity);
            return false;
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

/// Convert severity string to numeric level for comparison
fn severity_level(severity: &str) -> u8 {
    let severity_lower = severity.to_lowercase();
    
    // Handle CVSS format (e.g., "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if severity_lower.starts_with("cvss:") {
        // For CVSS format, determine severity based on the score components
        // C:H/I:H/A:H indicates High impact across all three categories
        if severity.contains("C:H") && severity.contains("I:H") && severity.contains("A:H") {
            return 4; // Critical - High impact on all three (Confidentiality, Integrity, Availability)
        } else if severity.contains("C:H") || severity.contains("I:H") || severity.contains("A:H") {
            return 3; // High - High impact on at least one category
        } else if severity.contains("C:M") || severity.contains("I:M") || severity.contains("A:M") {
            return 2; // Medium - Medium impact
        } else {
            return 1; // Low - Low or no significant impact
        }
    }
    
    // Handle simple severity strings
    match severity_lower.as_str() {
        s if s.contains("critical") => 4,
        s if s.contains("high") => 3,
        s if s.contains("medium") => 2,
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