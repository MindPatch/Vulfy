use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::error::{VulfyError, VulfyResult};
use crate::types::{Ecosystem, ScanConfig};
use crate::scanner::Scanner;
use crate::matcher::VulnerabilityMatcher;
use crate::reporter::Reporter;

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
}

#[derive(Subcommand)]
pub enum ScanType {
    /// Scan all supported package files
    #[command(name = "packages")]
    Packages {
        /// Target directory or file to scan
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// Output file for the JSON report
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable recursive scanning
        #[arg(long)]
        no_recursive: bool,

        /// Only scan specific ecosystems (comma-separated: npm,pypi,cargo,maven,go,rubygems)
        #[arg(short, long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,

        /// Exclude development dependencies
        #[arg(long)]
        no_dev_deps: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
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
                        verbose,
                    } => {
                        // Build scan configuration
                        let config = ScanConfigBuilder::new()
                            .target_path(path)
                            .output_file(output)
                            .recursive(!no_recursive)
                            .ecosystems(ecosystems.map(|e| parse_ecosystems(e)).transpose()?)
                            .include_dev_dependencies(!no_dev_deps)
                            .build();

                        if verbose {
                            info!("Starting vulnerability scan with config: {:?}", config);
                        }

                        // Execute the scan
                        execute_scan(config).await
                    }
                }
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
    info!("Scanning directory: {:?}", config.target_path);

    // Initialize scanner
    let scanner = Scanner::new();
    
    // Scan for packages
    let packages = scanner.scan_directory(&config).await?;
    
    if packages.is_empty() {
        warn!("No packages found in the specified directory");
        return Ok(());
    }

    info!("Found {} packages", packages.len());

    // Initialize vulnerability matcher
    let matcher = VulnerabilityMatcher::new();
    
    // Check for vulnerabilities
    let scan_result = matcher.check_vulnerabilities(packages).await?;

    info!(
        "Scan complete: {} total packages, {} vulnerable packages, {} total vulnerabilities",
        scan_result.total_packages,
        scan_result.vulnerable_packages,
        scan_result.total_vulnerabilities
    );

    // Generate report
    let reporter = Reporter::new();
    reporter.generate_report(&scan_result, &config).await?;

    Ok(())
} 