use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::error::{VulfyError, VulfyResult};
use crate::types::{Ecosystem, ScanConfig, ReportFormat};
use crate::scanner::Scanner;
use crate::matcher::VulnerabilityMatcher;
use crate::reporter::Reporter;
use crate::automation::{AutomationConfig, scheduler::AutomationScheduler};

#[derive(Parser)]
#[command(name = "vulfy")]
#[command(about = "A cross-language CLI-based package version scanner for detecting known vulnerabilities")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan packages for vulnerabilities
    #[command(name = "scan")]
    Scan {
        #[command(subcommand)]
        scan_type: ScanType,
    },
    /// Automation and monitoring commands
    #[command(name = "automation")]
    Automation {
        #[command(subcommand)]
        automation_command: AutomationCommand,
    },
}

#[derive(Subcommand)]
pub enum ScanType {
    /// Scan all supported package files
    #[command(name = "packages")]
    Packages {
        /// Target directory or file to scan
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// Report format (table is default, shows beautiful CLI output)
        #[arg(short = 'f', long, default_value = "table")]
        format: ReportFormat,

        /// Output file (optional - defaults to stdout for table, required for json/csv)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable recursive scanning
        #[arg(long)]
        no_recursive: bool,

        /// Only scan specific ecosystems (comma-separated: npm,pypi,crates.io,maven,go,rubygems,vcpkg,packagist,nuget)
        /// Aliases supported: cargo→crates.io, composer→packagist
        #[arg(short, long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,

        /// Exclude development dependencies
        #[arg(long)]
        no_dev_deps: bool,

        /// Quiet mode - suppress scan progress info
        #[arg(short, long)]
        quiet: bool,

        /// Show only high severity vulnerabilities
        #[arg(long)]
        high_only: bool,
    },
}

#[derive(Subcommand)]
pub enum AutomationCommand {
    /// Initialize automation configuration
    #[command(name = "init")]
    Init {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
        
        /// Create with example repositories and policies
        #[arg(long)]
        with_examples: bool,
    },
    /// Start the automation scheduler
    #[command(name = "start")]
    Start {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
        
        /// Workspace directory for cloning repositories
        #[arg(short, long, default_value = "vulfy-workspace")]
        workspace: PathBuf,
        
        /// Run in foreground (default runs as daemon)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the automation scheduler
    #[command(name = "stop")]
    Stop {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
    },
    /// Run a manual scan using automation config
    #[command(name = "run")]
    Run {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
        
        /// Workspace directory for cloning repositories
        #[arg(short, long, default_value = "vulfy-workspace")]
        workspace: PathBuf,
        
        /// Specific repository to scan (optional)
        #[arg(short, long)]
        repository: Option<String>,

        /// Report format (table is default, shows beautiful CLI output)
        #[arg(short = 'f', long, default_value = "table")]
        format: ReportFormat,

        /// Output file (optional - save results to file)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show only vulnerabilities (skip summary)
        #[arg(long)]
        vulnerabilities_only: bool,
    },
    /// Show automation status and next scheduled run
    #[command(name = "status")]
    Status {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
    },
    /// Validate automation configuration
    #[command(name = "validate")]
    Validate {
        /// Configuration file path
        #[arg(short, long, default_value = "vulfy-automation.toml")]
        config: PathBuf,
    },
}

impl Cli {
    pub async fn execute(self) -> VulfyResult<()> {
        match self.command {
            Commands::Scan { scan_type } => {
                match scan_type {
                    ScanType::Packages {
                        path,
                        output,
                        no_recursive,
                        ecosystems,
                        no_dev_deps,
                        format,
                        quiet,
                        high_only,
                    } => {
                        // Build scan configuration
                        let config = ScanConfigBuilder::new()
                            .target_path(path)
                            .output_file(output)
                            .recursive(!no_recursive)
                            .ecosystems(ecosystems.map(parse_ecosystems).transpose()?)
                            .include_dev_dependencies(!no_dev_deps)
                            .format(format)
                            .quiet(quiet)
                            .high_only(high_only)
                            .build();

                        if !quiet {
                            info!("Starting vulnerability scan with config: {:?}", config);
                        }

                        // Execute the scan
                        execute_scan(config).await
                    }
                }
            }
            Commands::Automation { automation_command } => {
                execute_automation_command(automation_command).await
            }
        }
    }
}

/// Builder pattern for ScanConfig
pub struct ScanConfigBuilder {
    config: ScanConfig,
}

impl ScanConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: ScanConfig::default(),
        }
    }

    pub fn target_path(mut self, path: PathBuf) -> Self {
        self.config.target_path = path;
        self
    }

    pub fn output_file(mut self, output: Option<PathBuf>) -> Self {
        self.config.output_file = output;
        self
    }

    pub fn recursive(mut self, recursive: bool) -> Self {
        self.config.recursive = recursive;
        self
    }

    pub fn ecosystems(mut self, ecosystems: Option<Vec<Ecosystem>>) -> Self {
        self.config.ecosystems = ecosystems;
        self
    }

    pub fn include_dev_dependencies(mut self, include: bool) -> Self {
        self.config.include_dev_dependencies = include;
        self
    }

    pub fn format(mut self, format: ReportFormat) -> Self {
        self.config.format = format;
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.config.quiet = quiet;
        self
    }

    pub fn high_only(mut self, high_only: bool) -> Self {
        self.config.high_only = high_only;
        self
    }

    pub fn build(self) -> ScanConfig {
        self.config
    }
}

fn parse_ecosystems(ecosystem_strs: Vec<String>) -> VulfyResult<Vec<Ecosystem>> {
    let mut ecosystems = Vec::new();
    
    for eco_str in ecosystem_strs {
        let ecosystem = match eco_str.to_lowercase().as_str() {
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPI,
            "cargo" | "crates.io" => Ecosystem::Cargo,
            "maven" => Ecosystem::Maven,
            "go" => Ecosystem::Go,
            "rubygems" => Ecosystem::RubyGems,
            "vcpkg" => Ecosystem::Vcpkg,
            "composer" | "packagist" => Ecosystem::Composer,
            "nuget" => Ecosystem::NuGet,
            _ => {
                return Err(VulfyError::Config {
                    message: format!("Unsupported ecosystem: {}", eco_str),
                });
            }
        };
        ecosystems.push(ecosystem);
    }
    
    Ok(ecosystems)
}

async fn execute_scan(config: ScanConfig) -> VulfyResult<()> {
    if !config.quiet {
        info!("Scanning directory: {:?}", config.target_path);
    }

    // Initialize scanner
    let scanner = Scanner::new();
    
    // Scan for packages
    let packages = scanner.scan_directory(&config).await?;
    
    if packages.is_empty() {
        if !config.quiet {
            warn!("No packages found in the specified directory");
        }
        return Ok(());
    }

    if !config.quiet {
        info!("Found {} packages", packages.len());
    }

    // Initialize vulnerability matcher
    let matcher = VulnerabilityMatcher::new();
    
    // Check for vulnerabilities
    let scan_result = matcher.check_vulnerabilities(packages).await?;

    if !config.quiet {
        info!(
            "Scan complete: {} total packages, {} vulnerable packages, {} total vulnerabilities",
            scan_result.total_packages,
            scan_result.vulnerable_packages,
            scan_result.total_vulnerabilities
        );
    }

    // Generate report
    let reporter = Reporter::new();
    reporter.generate_report(&scan_result, &config).await?;

    Ok(())
}

async fn execute_automation_command(command: AutomationCommand) -> VulfyResult<()> {
    match command {
        AutomationCommand::Init { config, with_examples } => {
            execute_automation_init(config, with_examples).await
        }
        AutomationCommand::Start { config, workspace, foreground } => {
            execute_automation_start(config, workspace, foreground).await
        }
        AutomationCommand::Stop { config } => {
            execute_automation_stop(config).await
        }
        AutomationCommand::Run { config, workspace, repository, format, output, vulnerabilities_only } => {
            execute_automation_run(config, workspace, repository, format, output, vulnerabilities_only).await
        }
        AutomationCommand::Status { config } => {
            execute_automation_status(config).await
        }
        AutomationCommand::Validate { config } => {
            execute_automation_validate(config).await
        }
    }
}

async fn execute_automation_init(config_path: PathBuf, with_examples: bool) -> VulfyResult<()> {
    use crate::automation::{Repository, Webhook, WebhookType, Credentials};
    use crate::automation::{ScheduleFrequency, policy::PolicyEngine};

    info!("Initializing automation configuration at: {}", config_path.display());

    if config_path.exists() {
        return Err(VulfyError::Config {
            message: format!("Configuration file already exists: {}", config_path.display()),
        });
    }

    let mut automation_config = AutomationConfig::default_config();

    if with_examples {
        // Add comprehensive examples (existing complex configuration)
        automation_config.repositories = vec![
            Repository {
                name: "my-web-app".to_string(),
                url: "https://github.com/user/my-web-app.git".to_string(),
                branches: Some(vec!["main".to_string(), "develop".to_string()]),
                local_path: None,
                credentials: Some(Credentials {
                    username: Some("git".to_string()),
                    token: Some("your_github_token_here".to_string()),
                    ssh_key_path: None,
                }),
                ecosystems: Some(vec![crate::types::Ecosystem::Npm, crate::types::Ecosystem::PyPI]),
            },
            Repository {
                name: "my-api".to_string(),
                url: "https://github.com/user/my-api.git".to_string(),
                branches: None, // Only main branch
                local_path: None,
                credentials: None, // Public repository
                ecosystems: Some(vec![crate::types::Ecosystem::Cargo]),
            },
        ];

        // Add example webhooks
        automation_config.notifications.webhooks = vec![
            Webhook {
                name: "Discord Security Channel".to_string(),
                url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN".to_string(),
                webhook_type: WebhookType::Discord,
                enabled: true,
            },
            Webhook {
                name: "Slack Security Alerts".to_string(),
                url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK".to_string(),
                webhook_type: WebhookType::Slack,
                enabled: false, // Disabled by default
            },
        ];

        // Add example policies
        automation_config.policies = PolicyEngine::create_default_policies();

        // Set daily schedule at 2:00 AM
        automation_config.schedule.frequency = ScheduleFrequency::Daily;
        automation_config.schedule.time = Some("02:00".to_string());
    } else {
        // Create simple default configuration
        automation_config.repositories = vec![
            Repository {
                name: "my-project".to_string(),
                url: "https://github.com/your-username/your-repo.git".to_string(),
                branches: None, // Will scan default branch
                local_path: None,
                credentials: None, // For public repos
                ecosystems: None, // Will scan all supported ecosystems
            },
        ];

        // Simple daily schedule
        automation_config.schedule.frequency = ScheduleFrequency::Daily;
        automation_config.schedule.time = Some("02:00".to_string());

        // Minimal notifications (disabled by default)
        automation_config.notifications.enabled = false;
    }

    // Save configuration
    automation_config.save_to_file(&config_path).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to save configuration: {}", e),
        }
    })?;

    info!("✅ Automation configuration created successfully!");
    
    if with_examples {
        println!("\n📝 Comprehensive example configuration created with:");
        println!("   • 2 example repositories");
        println!("   • Discord and Slack webhook templates");
        println!("   • Default security policies");
        println!("   • Daily scan schedule at 2:00 AM");
        println!("\n🔧 Edit {} to customize your setup", config_path.display());
        println!("💡 Remember to update webhook URLs and repository credentials!");
    } else {
        println!("\n📝 Simple configuration created!");
        println!("   • 1 example repository (update the URL)");
        println!("   • Daily scans at 2:00 AM");
        println!("   • Notifications disabled (edit config to enable)");
        println!("\n🔧 Edit {} to add your repository details", config_path.display());
        println!("💡 Use --with-examples for a comprehensive configuration");
    }

    Ok(())
}

async fn execute_automation_start(config_path: PathBuf, workspace: PathBuf, foreground: bool) -> VulfyResult<()> {
    info!("Starting automation scheduler...");

    // Load configuration
    let config = AutomationConfig::load_from_file(&config_path).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to load configuration from {}: {}", config_path.display(), e),
        }
    })?;

    // Validate configuration
    validate_automation_config(&config)?;

    // Create and start scheduler
    let mut scheduler = AutomationScheduler::new(config, workspace).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to create scheduler: {}", e),
        }
    })?;

    scheduler.start().await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to start scheduler: {}", e),
        }
    })?;

    if let Some(next_run) = scheduler.next_run_time().await {
        info!("Next scheduled scan: {}", next_run.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    if foreground {
        info!("Running in foreground mode. Press Ctrl+C to stop.");
        // Keep the scheduler running
        tokio::signal::ctrl_c().await.map_err(|e| {
            VulfyError::Config {
                message: format!("Failed to listen for shutdown signal: {}", e),
            }
        })?;
        
        info!("Shutting down scheduler...");
        scheduler.stop().await.map_err(|e| {
            VulfyError::Config {
                message: format!("Failed to stop scheduler: {}", e),
            }
        })?;
    } else {
        info!("Scheduler started in background mode");
        // In a real implementation, you might want to daemonize the process here
        println!("⚠️ Background mode not fully implemented yet. Use --foreground for now.");
    }

    Ok(())
}

async fn execute_automation_stop(_config_path: PathBuf) -> VulfyResult<()> {
    info!("Stopping automation scheduler...");
    
    // In a real implementation, this would connect to a running scheduler process
    // For now, we'll just indicate the operation
    println!("⚠️ Stop command not fully implemented yet.");
    println!("💡 If running in foreground mode, use Ctrl+C to stop.");
    
    Ok(())
}

async fn execute_automation_run(config_path: PathBuf, workspace: PathBuf, repository: Option<String>, format: ReportFormat, output: Option<PathBuf>, vulnerabilities_only: bool) -> VulfyResult<()> {
    info!("Running manual automation scan...");

    // Load configuration
    let config = AutomationConfig::load_from_file(&config_path).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to load configuration from {}: {}", config_path.display(), e),
        }
    })?;

    // Filter repositories if specified
    let mut filtered_config = config.clone();
    if let Some(repo_name) = repository {
        filtered_config.repositories.retain(|r| r.name == repo_name);
        if filtered_config.repositories.is_empty() {
            return Err(VulfyError::Config {
                message: format!("Repository '{}' not found in configuration", repo_name),
            });
        }
        info!("Scanning only repository: {}", repo_name);
    }

    // Create scheduler and run manual scan
    let scheduler = AutomationScheduler::new(filtered_config, workspace.clone()).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to create scheduler: {}", e),
        }
    })?;

    let results = scheduler.run_manual_scan().await.map_err(|e| {
        VulfyError::Config {
            message: format!("Manual scan failed: {}", e),
        }
    })?;

    if !vulnerabilities_only {
        // Print summary
        let total_repos = results.len();
        let total_vulns: usize = results.iter().map(|r| r.vulnerabilities.len()).sum();
        let repos_with_vulns = results.iter().filter(|r| !r.vulnerabilities.is_empty()).count();

        println!("\n🔍 Manual Scan Results:");
        println!("📊 Scanned {} repositories", total_repos);
        println!("⚠️  Found {} vulnerabilities across {} repositories", total_vulns, repos_with_vulns);
        
        for result in &results {
            if !result.vulnerabilities.is_empty() {
                println!("   • {}/{}: {} vulnerabilities", result.repository, result.branch, result.vulnerabilities.len());
            }
        }
    }

    // Convert automation results to standard scan result format for reporting
    if !results.is_empty() && (format != crate::types::ReportFormat::Table || output.is_some()) {
        let mut all_packages = Vec::new();
        
        for scan_result in &results {
            // Group vulnerabilities by package name
            let mut vulnerabilities_by_package: std::collections::HashMap<String, Vec<crate::types::Vulnerability>> = std::collections::HashMap::new();
            
            for vulnerability in &scan_result.vulnerabilities {
                // Extract package name from vulnerability ID (often in format "package-name@version")
                let package_name = vulnerability.id.split('@').next().unwrap_or("unknown").to_string();
                
                let vuln = crate::types::Vulnerability {
                    id: vulnerability.id.clone(),
                    summary: vulnerability.summary.clone(),
                    severity: vulnerability.severity.clone(),
                    fixed_version: vulnerability.fixed_version.clone(),
                    references: vulnerability.references.clone(),
                };
                
                vulnerabilities_by_package.entry(package_name).or_default().push(vuln);
            }
            
            // Create PackageVulnerability entries
            for (package_name, vulns) in vulnerabilities_by_package {
                let package_vuln = crate::types::PackageVulnerability {
                    package: crate::types::Package {
                        name: package_name,
                        version: "unknown".to_string(), // We don't have version info from automation scan
                        ecosystem: crate::types::Ecosystem::Npm, // Default, could be improved
                        source_file: PathBuf::from(format!("{}/{}", scan_result.repository, scan_result.branch)),
                    },
                    vulnerabilities: vulns,
                };
                all_packages.push(package_vuln);
            }
        }

        let total_vulnerabilities = results.iter().map(|r| r.vulnerabilities.len()).sum();
        let vulnerable_packages = all_packages.len();
        let total_packages = results.iter().map(|r| r.total_packages).sum();

        let combined_scan_result = crate::types::ScanResult {
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            total_packages,
            vulnerable_packages,
            total_vulnerabilities,
            packages: all_packages,
            summary_by_ecosystem: std::collections::HashMap::new(), // Empty for now
        };

        // Create scan config for reporter
        let scan_config = ScanConfig {
            target_path: workspace,
            output_file: output,
            recursive: true,
            ecosystems: None,
            include_dev_dependencies: true,
            format,
            quiet: false,
            high_only: false,
        };

        // Generate report
        let reporter = Reporter::new();
        reporter.generate_report(&combined_scan_result, &scan_config).await?;
    }

    Ok(())
}

async fn execute_automation_status(config_path: PathBuf) -> VulfyResult<()> {
    info!("Checking automation status...");

    if !config_path.exists() {
        println!("❌ Configuration file not found: {}", config_path.display());
        println!("💡 Run 'vulfy automation init' to create a configuration");
        return Ok(());
    }

    // Load and validate configuration
    let config = AutomationConfig::load_from_file(&config_path).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to load configuration: {}", e),
        }
    })?;

    println!("✅ Configuration: {}", config_path.display());
    println!("\n📊 Configuration Summary:");
    println!("   • Repositories: {}", config.repositories.len());
    println!("   • Webhooks: {} ({} enabled)", 
             config.notifications.webhooks.len(),
             config.notifications.webhooks.iter().filter(|w| w.enabled).count());
    println!("   • Policies: {} ({} enabled)", 
             config.policies.len(),
             config.policies.iter().filter(|p| p.enabled).count());
    println!("   • Schedule: {:?}", config.schedule.frequency);

    // Show repository details
    if !config.repositories.is_empty() {
        println!("\n📂 Repositories:");
        for repo in &config.repositories {
            let branch_info = if let Some(branches) = &repo.branches {
                format!("{} branches", branches.len())
            } else {
                "default branch".to_string()
            };
            println!("   • {} - {} ({})", repo.name, repo.url, branch_info);
        }
    }

    // Show webhook details
    if !config.notifications.webhooks.is_empty() {
        println!("\n🔔 Webhooks:");
        for webhook in &config.notifications.webhooks {
            let status = if webhook.enabled { "✅" } else { "❌" };
            println!("   {} {} ({})", status, webhook.name, webhook.webhook_type);
        }
    }

    // Show policy details  
    if !config.policies.is_empty() {
        println!("\n📋 Policies:");
        for policy in &config.policies {
            let status = if policy.enabled { "✅" } else { "❌" };
            println!("   {} {}", status, policy.name);
        }
    }

    // Check scheduler status by trying to create a scheduler instance
    println!("\n🤖 Scheduler Status:");
    
    // Try to create a scheduler to check configuration validity
    let workspace = PathBuf::from("vulfy-workspace");
    match AutomationScheduler::new(config.clone(), workspace).await {
        Ok(scheduler) => {
            // Show next run time if available
            if let Some(next_run) = scheduler.next_run_time().await {
                println!("   📅 Next scheduled run: {}", next_run.format("%Y-%m-%d %H:%M:%S UTC"));
            } else {
                println!("   ⚠️  Unable to calculate next run time");
            }
            
            println!("   ✅ Scheduler configuration is valid");
            println!("   ℹ️  Use 'vulfy automation start' to begin monitoring");
        }
        Err(e) => {
            println!("   ❌ Scheduler configuration error: {}", e);
        }
    }

    Ok(())
}

async fn execute_automation_validate(config_path: PathBuf) -> VulfyResult<()> {
    info!("Validating automation configuration...");

    if !config_path.exists() {
        return Err(VulfyError::Config {
            message: format!("Configuration file not found: {}", config_path.display()),
        });
    }

    // Load configuration
    let config = AutomationConfig::load_from_file(&config_path).await.map_err(|e| {
        VulfyError::Config {
            message: format!("Failed to load configuration: {}", e),
        }
    })?;

    // Validate configuration
    validate_automation_config(&config)?;

    println!("✅ Configuration is valid!");
    println!("📊 {} repositories, {} webhooks, {} policies configured", 
             config.repositories.len(),
             config.notifications.webhooks.len(),
             config.policies.len());

    Ok(())
}

fn validate_automation_config(config: &AutomationConfig) -> VulfyResult<()> {
    // Validate repositories
    if config.repositories.is_empty() {
        return Err(VulfyError::Config {
            message: "No repositories configured".to_string(),
        });
    }

    for repo in &config.repositories {
        if repo.name.is_empty() {
            return Err(VulfyError::Config {
                message: "Repository name cannot be empty".to_string(),
            });
        }
        if repo.url.is_empty() {
            return Err(VulfyError::Config {
                message: format!("Repository '{}' has empty URL", repo.name),
            });
        }
        // Basic URL validation
        if !repo.url.starts_with("http") && !repo.url.starts_with("git@") {
            return Err(VulfyError::Config {
                message: format!("Repository '{}' has invalid URL format", repo.name),
            });
        }
    }

    // Validate webhooks
    for webhook in &config.notifications.webhooks {
        if webhook.enabled && webhook.url.is_empty() {
            return Err(VulfyError::Config {
                message: format!("Enabled webhook '{}' has empty URL", webhook.name),
            });
        }
        if webhook.enabled && !webhook.url.starts_with("http") {
            return Err(VulfyError::Config {
                message: format!("Webhook '{}' has invalid URL format", webhook.name),
            });
        }
    }

    // Validate schedule time format
    if let Some(time) = &config.schedule.time {
        let parts: Vec<&str> = time.split(':').collect();
        if parts.len() != 2 {
            return Err(VulfyError::Config {
                message: format!("Invalid time format '{}'. Use HH:MM format", time),
            });
        }
        
        if let (Ok(hour), Ok(minute)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
            if hour >= 24 || minute >= 60 {
                return Err(VulfyError::Config {
                    message: format!("Invalid time '{}'. Hour must be 0-23, minute 0-59", time),
                });
            }
        } else {
            return Err(VulfyError::Config {
                message: format!("Invalid time format '{}'. Use HH:MM format", time),
            });
        }
    }

    Ok(())
} 