use std::io::Write;
use tracing::info;
use serde_json;
use std::collections::HashMap;

use crate::error::{VulfyError, VulfyResult};
use crate::types::{ScanConfig, ScanResult, ReportFormat, Ecosystem};

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        match config.format {
            ReportFormat::Table => self.generate_table_report(scan_result, config).await,
            ReportFormat::Json => self.generate_json_report(scan_result, config).await,
            ReportFormat::Csv => self.generate_csv_report(scan_result, config).await,
            ReportFormat::Summary => self.generate_summary_report(scan_result, config).await,
        }
    }

    async fn generate_table_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        let table_output = self.format_table_report(scan_result, config).await?;
        
        if let Some(ref output_file) = config.output_file {
            self.write_to_file(&table_output, output_file).await?;
            if !config.quiet {
                info!("Table report written to {}", output_file.display());
            }
        } else {
            // Output directly to stdout
            print!("{}", table_output);
            std::io::stdout().flush().map_err(|e| VulfyError::Io(e))?;
        }
        
        Ok(())
    }

    async fn generate_json_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        let json_report = self.format_json_report(scan_result).await?;

        if let Some(ref output_file) = config.output_file {
            self.write_to_file(&json_report, output_file).await?;
            if !config.quiet {
                info!("JSON report written to {}", output_file.display());
            }
        } else {
            print!("{}", json_report);
            std::io::stdout().flush().map_err(|e| VulfyError::Io(e))?;
        }

        Ok(())
    }

    async fn generate_csv_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        let csv_report = self.format_csv_report(scan_result).await?;

        if let Some(ref output_file) = config.output_file {
            self.write_to_file(&csv_report, output_file).await?;
            if !config.quiet {
                info!("CSV report written to {}", output_file.display());
            }
        } else {
            print!("{}", csv_report);
            std::io::stdout().flush().map_err(|e| VulfyError::Io(e))?;
        }

        Ok(())
    }

    async fn generate_summary_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        let summary_output = self.format_summary_report(scan_result).await?;
        
        if let Some(ref output_file) = config.output_file {
            self.write_to_file(&summary_output, output_file).await?;
            if !config.quiet {
                info!("Summary report written to {}", output_file.display());
            }
        } else {
            print!("{}", summary_output);
            std::io::stdout().flush().map_err(|e| VulfyError::Io(e))?;
        }
        
        Ok(())
    }

    async fn format_table_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<String> {
        let mut output = String::new();
        
        // Filter vulnerabilities by severity if high_only is set
        let mut vulnerabilities = Vec::new();
        
        for package_vuln in &scan_result.packages {
            let package_name = &package_vuln.package.name;
            let package_version = &package_vuln.package.version;
            let ecosystem = &package_vuln.package.ecosystem;
            
            for vuln in &package_vuln.vulnerabilities {
                // Skip vulnerabilities with no meaningful summary
                if vuln.summary.trim().is_empty() || 
                   vuln.summary.trim() == "No summary available" ||
                   vuln.summary.trim() == "No description available" {
                    continue;
                }
                
                // Filter high severity only if requested
                if config.high_only {
                    let is_high_severity = vuln.severity.as_ref()
                        .map(|s| s.contains("HIGH") || s.contains("CRITICAL") || s.contains("/A:H") || s.contains("/I:H") || s.contains("/C:H"))
                        .unwrap_or(false);
                    if !is_high_severity {
                        continue;
                    }
                }
                
                let cve_id = self.extract_cve_from_references(&vuln.references)
                    .unwrap_or_else(|| vuln.id.clone());
                
                let (severity_level, severity_emoji) = self.parse_severity(vuln.severity.as_deref());
                let pub_year = self.get_publish_year(&vuln.references, &cve_id);
                
                vulnerabilities.push((
                    &vuln.summary,
                    cve_id,
                    severity_level,
                    severity_emoji,
                    format!("{}@{}", package_name, package_version),
                    pub_year,
                    ecosystem,
                ));
            }
        }
        
        if vulnerabilities.is_empty() {
            if config.high_only {
                output.push_str("✅ No high severity vulnerabilities found!\n");
            } else {
                output.push_str("✅ No vulnerabilities found! Your system looks secure.\n");
            }
            return Ok(output);
        }
        
        // Sort by severity (High -> Medium -> Low -> Unknown)
        vulnerabilities.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "High" => 0,
                "Medium" => 1,
                "Low" => 2,
                _ => 3,
            };
            severity_order(&a.2).cmp(&severity_order(&b.2))
        });
        
        // Header
        output.push_str(&format!("\n🛡️  SECURITY VULNERABILITY REPORT\n"));
        output.push_str(&format!("{}\n", "=".repeat(80)));
        output.push_str(&format!("📅 Scan Date: {}\n", scan_result.scan_timestamp));
        output.push_str(&format!("📦 Total Packages: {}\n", scan_result.total_packages));
        output.push_str(&format!("⚠️  Vulnerable Packages: {}\n", scan_result.vulnerable_packages));
        output.push_str(&format!("🚨 Total Vulnerabilities: {}\n", scan_result.total_vulnerabilities));
        if config.high_only {
            output.push_str(&format!("🔥 Showing: High severity only\n"));
        }
        output.push_str(&format!("{}\n", "=".repeat(80)));
        
        // Table headers
        output.push_str(&format!("\n{:<45} {:<17} {:<12} {:<25} {:<6}\n", 
            "TITLE", "CVE ID", "SEVERITY", "PACKAGE", "YEAR"));
        output.push_str(&format!("{} {} {} {} {}\n", 
            "─".repeat(45), "─".repeat(17), "─".repeat(12), "─".repeat(25), "─".repeat(6)));
        
        // Display vulnerabilities
        for (title, cve_id, severity_level, severity_emoji, package, pub_year, _ecosystem) in vulnerabilities.iter() {
            let title_truncated = self.truncate_text(title, 44);
            let cve_truncated = if cve_id.len() > 16 { &cve_id[..16] } else { cve_id };
            let severity_display = format!("{} {}", severity_emoji, severity_level);
            let package_truncated = self.truncate_text(package, 24);
            
            output.push_str(&format!("{:<45} {:<17} {:<12} {:<25} {:<6}\n",
                title_truncated, cve_truncated, severity_display, package_truncated, pub_year));
        }
        
        // Summary by severity
        let mut severity_counts = HashMap::new();
        for (_, _, severity, _, _, _, _) in &vulnerabilities {
            *severity_counts.entry(severity.as_str()).or_insert(0) += 1;
        }
        
        output.push_str(&format!("\n{}\n", "=".repeat(80)));
        output.push_str("📊 SEVERITY BREAKDOWN:\n");
        for severity in &["High", "Medium", "Low", "Unknown"] {
            if let Some(&count) = severity_counts.get(severity) {
                let emoji = match *severity {
                    "High" => "🔥",
                    "Medium" => "🟡", 
                    "Low" => "🟢",
                    _ => "⚪",
                };
                output.push_str(&format!("   {} {}: {} vulnerabilities\n", emoji, severity, count));
            }
        }
        
        // Top vulnerable packages
        let mut package_counts = HashMap::new();
        for (_, _, _, _, package, _, _) in &vulnerabilities {
            *package_counts.entry(package).or_insert(0) += 1;
        }
        
        let mut top_packages: Vec<_> = package_counts.into_iter().collect();
        top_packages.sort_by(|a, b| b.1.cmp(&a.1));
        top_packages.truncate(5);
        
        if !top_packages.is_empty() {
            output.push_str("\n🎯 TOP VULNERABLE PACKAGES:\n");
            for (package, count) in top_packages {
                output.push_str(&format!("   📦 {}: {} vulnerabilities\n", package, count));
            }
        }
        
        output.push_str("\n💡 RECOMMENDATION: Update vulnerable packages to their fixed versions\n");
        output.push_str("🔗 For detailed info, check CVE references at https://nvd.nist.gov/\n");
        output.push_str(&format!("{}\n\n", "=".repeat(80)));
        
        Ok(output)
    }

    async fn format_json_report(&self, scan_result: &ScanResult) -> VulfyResult<String> {
        serde_json::to_string_pretty(scan_result)
            .map_err(|e| VulfyError::Json(e))
    }

    async fn format_csv_report(&self, scan_result: &ScanResult) -> VulfyResult<String> {
        let mut csv_content = String::new();
        csv_content.push_str("package_name,version,ecosystem,vulnerability_id,cve_id,severity,summary,fixed_version,source_file\n");

        for package_vuln in &scan_result.packages {
            if package_vuln.vulnerabilities.is_empty() {
                // Include packages with no vulnerabilities
                csv_content.push_str(&format!(
                    "{},{},{},,,,,{}\n",
                    self.escape_csv_field(&package_vuln.package.name),
                    self.escape_csv_field(&package_vuln.package.version),
                    package_vuln.package.ecosystem.as_str(),
                    package_vuln.package.source_file.display()
                ));
            } else {
                for vuln in &package_vuln.vulnerabilities {
                    let cve_id = self.extract_cve_from_references(&vuln.references)
                        .unwrap_or_else(|| vuln.id.clone());
                    
                    csv_content.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        self.escape_csv_field(&package_vuln.package.name),
                        self.escape_csv_field(&package_vuln.package.version),
                        package_vuln.package.ecosystem.as_str(),
                        self.escape_csv_field(&vuln.id),
                        self.escape_csv_field(&cve_id),
                        self.escape_csv_field(&vuln.severity.as_deref().unwrap_or("Unknown")),
                        self.escape_csv_field(&vuln.summary),
                        self.escape_csv_field(&vuln.fixed_version.as_deref().unwrap_or("")),
                        package_vuln.package.source_file.display()
                    ));
                }
            }
        }

        Ok(csv_content)
    }

    async fn format_summary_report(&self, scan_result: &ScanResult) -> VulfyResult<String> {
        let mut output = String::new();
        
        output.push_str(&format!("🛡️  SECURITY SCAN SUMMARY\n"));
        output.push_str(&format!("{}\n", "=".repeat(40)));
        output.push_str(&format!("📅 Scan Date: {}\n", scan_result.scan_timestamp));
        output.push_str(&format!("📦 Total Packages: {}\n", scan_result.total_packages));
        output.push_str(&format!("⚠️  Vulnerable Packages: {}\n", scan_result.vulnerable_packages));
        output.push_str(&format!("🚨 Total Vulnerabilities: {}\n", scan_result.total_vulnerabilities));
        
        // Summary by ecosystem
        if !scan_result.summary_by_ecosystem.is_empty() {
            output.push_str("\n📊 By Ecosystem:\n");
            for (ecosystem, summary) in &scan_result.summary_by_ecosystem {
                let emoji = self.ecosystem_emoji(ecosystem);
                output.push_str(&format!("  {} {}: {}/{} packages vulnerable, {} vulnerabilities\n",
                    emoji, ecosystem.as_str(), summary.vulnerable_packages, 
                    summary.total_packages, summary.total_vulnerabilities));
            }
        }
        
        if scan_result.vulnerable_packages == 0 {
            output.push_str("\n✅ No vulnerabilities found! Your packages are secure.\n");
        } else {
            output.push_str("\n💡 Run with --format=table for detailed vulnerability information.\n");
        }
        
        Ok(output)
    }

    async fn write_to_file(&self, content: &str, file_path: &std::path::Path) -> VulfyResult<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(file_path, content).await?;
        Ok(())
    }

    fn truncate_text(&self, text: &str, max_length: usize) -> String {
        if text.len() <= max_length {
            text.to_string()
        } else {
            format!("{}...", &text[..max_length-3])
        }
    }

    fn extract_cve_from_references(&self, references: &[String]) -> Option<String> {
        for reference in references {
            if reference.contains("CVE-") {
                // Extract CVE pattern using regex
                if let Some(start) = reference.find("CVE-") {
                    let cve_part = &reference[start..];
                    if let Some(end) = cve_part.find(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
                        return Some(cve_part[..end].to_string());
                    } else {
                        return Some(cve_part.to_string());
                    }
                }
            }
        }
        None
    }

    fn parse_severity(&self, severity_str: Option<&str>) -> (String, String) {
        match severity_str {
            Some(s) if s.contains("CVSS:") => {
                if s.contains("AV:N") {  // Network accessible
                    if s.contains("/A:H") || s.contains("/I:H") || s.contains("/C:H") {
                        ("High".to_string(), "🔥".to_string())
                    } else {
                        ("Medium".to_string(), "🟡".to_string())
                    }
                } else {
                    ("Low".to_string(), "🟢".to_string())
                }
            }
            Some(_) => ("Unknown".to_string(), "⚪".to_string()),
            None => ("Unknown".to_string(), "⚪".to_string()),
        }
    }

    fn get_publish_year(&self, references: &[String], cve_id: &str) -> String {
        // First try to extract from NVD references
        for reference in references {
            if reference.contains("nvd.nist.gov") {
                if let Some(cve) = self.extract_cve_from_references(&[reference.clone()]) {
                    if let Some(year_start) = cve.find("CVE-") {
                        let year_part = &cve[year_start + 4..];
                        if let Some(year_end) = year_part.find('-') {
                            return year_part[..year_end].to_string();
                        }
                    }
                }
            }
        }
        
        // If no luck with references, try to extract year from any ID format: <ANYTHING>-<YEAR>-<ID>
        // This handles CVE-2020-1234, RUSTSEC-2020-006, GHSA-xxxx-2021-xxxx, etc.
        let parts: Vec<&str> = cve_id.split('-').collect();
        for part in &parts {
            if part.len() == 4 && part.chars().all(|c| c.is_ascii_digit()) {
                let year: i32 = part.parse().unwrap_or(0);
                // Validate it's a reasonable year (between 1990 and current year + 5)
                if year >= 1990 && year <= 2030 {
                    return part.to_string();
                }
            }
        }
        
        // Try to extract year from any reference URLs that might contain CVE or date info
        for reference in references {
            // Look for 4-digit years in URLs
            let ref_parts: Vec<&str> = reference.split(|c: char| !c.is_ascii_alphanumeric()).collect();
            for part in ref_parts {
                if part.len() == 4 && part.chars().all(|c| c.is_ascii_digit()) {
                    let year: i32 = part.parse().unwrap_or(0);
                    if year >= 1990 && year <= 2030 {
                        return part.to_string();
                    }
                }
            }
        }
        
        "—".to_string()
    }

    fn escape_csv_field(&self, field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }

    fn ecosystem_emoji(&self, ecosystem: &Ecosystem) -> &'static str {
        match ecosystem {
            Ecosystem::Npm => "📦",
            Ecosystem::PyPI => "🐍",
            Ecosystem::Cargo => "🦀",
            Ecosystem::Maven => "☕",
            Ecosystem::Go => "🐹",
            Ecosystem::RubyGems => "💎",
        }
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
} 