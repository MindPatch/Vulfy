use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use clap::ValueEnum;

/// Represents a software package dependency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source_file: PathBuf,
}

/// Report output formats
#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum ReportFormat {
    /// Beautiful ASCII table with emojis (default)
    #[value(name = "table")]
    Table,
    /// JSON format for programmatic use
    #[value(name = "json")]
    Json,
    /// CSV format for spreadsheet analysis
    #[value(name = "csv")]
    Csv,
    /// Summary only - just statistics
    #[value(name = "summary")]
    Summary,
    /// SARIF format for static analysis tools
    #[value(name = "sarif")]
    Sarif,
}

impl Default for ReportFormat {
    fn default() -> Self {
        ReportFormat::Table
    }
}

/// Supported package ecosystems
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "pypi")]
    PyPI,
    #[serde(rename = "crates.io")]
    Cargo,
    #[serde(rename = "maven")]
    Maven,
    #[serde(rename = "go")]
    Go,
    #[serde(rename = "rubygems")]
    RubyGems,
    #[serde(rename = "vcpkg")]
    Vcpkg,
    #[serde(rename = "packagist")]
    Composer,
    #[serde(rename = "nuget")]
    NuGet,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Maven => "Maven",
            Ecosystem::Go => "Go",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Vcpkg => "vcpkg",
            Ecosystem::Composer => "Packagist",
            Ecosystem::NuGet => "NuGet",
        }
    }
}

/// Represents a vulnerability (CVE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
}

/// A package with its associated vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerability {
    #[serde(flatten)]
    pub package: Package,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Complete scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_timestamp: String,
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
    pub packages: Vec<PackageVulnerability>,
    pub summary_by_ecosystem: HashMap<Ecosystem, EcosystemSummary>,
}

/// Summary statistics per ecosystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemSummary {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
}

/// Configuration for scanning
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target_path: PathBuf,
    pub output_file: Option<PathBuf>,
    pub recursive: bool,
    pub ecosystems: Option<Vec<Ecosystem>>,
    pub include_dev_dependencies: bool,
    pub format: ReportFormat,
    pub quiet: bool,
    pub high_only: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_path: PathBuf::from("."),
            output_file: None,
            recursive: true,
            ecosystems: None,
            include_dev_dependencies: true,
            format: ReportFormat::default(),
            quiet: false,
            high_only: false,
        }
    }
}

/// OSV.dev API request/response types
#[derive(Debug, Serialize, Deserialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub affected: Option<Vec<OsvAffected>>,
    pub references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvPackage>,
    pub ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

/// SARIF (Static Analysis Results Interchange Format) structures
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<SarifArtifact>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifResultProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResultProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<SarifMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: i32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<SarifMessage>,
} 