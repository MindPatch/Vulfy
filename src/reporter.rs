use std::io::Write;
use tracing::info;
use serde_json;

use crate::error::{VulfyError, VulfyResult};
use crate::types::{ScanConfig, ScanResult};

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate_report(&self, scan_result: &ScanResult, config: &ScanConfig) -> VulfyResult<()> {
        // Generate JSON report
        let json_report = self.format_json_report(scan_result).await?;

        // Output to file or stdout
        if let Some(ref output_file) = config.output_file {
            self.write_to_file(&json_report, output_file).await?;
            info!("Report written to {}", output_file.display());
        } else {
            self.write_to_stdout(&json_report).await?;
        }

        // Print summary to stderr for visibility
        self.print_summary(scan_result).await;

        Ok(())
    }

    async fn format_json_report(&self, scan_result: &ScanResult) -> VulfyResult<String> {
        serde_json::to_string_pretty(scan_result)
            .map_err(|e| VulfyError::Json(e))
    }

    async fn write_to_file(&self, content: &str, file_path: &std::path::Path) -> VulfyResult<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(file_path, content).await?;
        Ok(())
    }

    async fn write_to_stdout(&self, content: &str) -> VulfyResult<()> {
        print!("{}", content);
        std::io::stdout().flush().map_err(|e| VulfyError::Io(e))?;
        Ok(())
    }

    async fn print_summary(&self, scan_result: &ScanResult) {
        eprintln!("\n🔍 Vulnerability Scan Summary");
        eprintln!("═══════════════════════════════");
        eprintln!("📦 Total packages scanned: {}", scan_result.total_packages);
        eprintln!("⚠️  Vulnerable packages: {}", scan_result.vulnerable_packages);
        eprintln!("🚨 Total vulnerabilities: {}", scan_result.total_vulnerabilities);
        eprintln!("📅 Scan timestamp: {}", scan_result.scan_timestamp);

        if !scan_result.summary_by_ecosystem.is_empty() {
            eprintln!("\n📊 By Ecosystem:");
            eprintln!("─────────────────");
            for (ecosystem, summary) in &scan_result.summary_by_ecosystem {
                eprintln!(
                    "  {} {} - {}/{} packages vulnerable, {} vulnerabilities",
                    Self::ecosystem_emoji(ecosystem),
                    ecosystem.as_str(),
                    summary.vulnerable_packages,
                    summary.total_packages,
                    summary.total_vulnerabilities
                );
            }
        }

        // Show most critical vulnerabilities
        let mut high_severity_count = 0;
        let mut medium_severity_count = 0;
        let mut low_severity_count = 0;
        let mut unknown_severity_count = 0;

        for package_vuln in &scan_result.packages {
            for vuln in &package_vuln.vulnerabilities {
                match vuln.severity.as_deref() {
                    Some(severity) if severity.contains("HIGH") || severity.contains("CRITICAL") => {
                        high_severity_count += 1;
                    }
                    Some(severity) if severity.contains("MEDIUM") || severity.contains("MODERATE") => {
                        medium_severity_count += 1;
                    }
                    Some(severity) if severity.contains("LOW") => {
                        low_severity_count += 1;
                    }
                    _ => {
                        unknown_severity_count += 1;
                    }
                }
            }
        }

        if scan_result.total_vulnerabilities > 0 {
            eprintln!("\n🎯 Severity Breakdown:");
            eprintln!("──────────────────────");
            if high_severity_count > 0 {
                eprintln!("  🔴 High/Critical: {}", high_severity_count);
            }
            if medium_severity_count > 0 {
                eprintln!("  🟡 Medium: {}", medium_severity_count);
            }
            if low_severity_count > 0 {
                eprintln!("  🟢 Low: {}", low_severity_count);
            }
            if unknown_severity_count > 0 {
                eprintln!("  ⚪ Unknown: {}", unknown_severity_count);
            }
        }

        // Show top vulnerable packages
        if scan_result.vulnerable_packages > 0 {
            eprintln!("\n🚨 Most Vulnerable Packages:");
            eprintln!("────────────────────────────");
            
            let mut package_counts: Vec<_> = scan_result
                .packages
                .iter()
                .filter(|pv| !pv.vulnerabilities.is_empty())
                .map(|pv| (pv, pv.vulnerabilities.len()))
                .collect();
            
            package_counts.sort_by(|a, b| b.1.cmp(&a.1));
            
            for (package_vuln, vuln_count) in package_counts.iter().take(5) {
                eprintln!(
                    "  {} {}@{} ({} vulnerabilities)",
                    Self::ecosystem_emoji(&package_vuln.package.ecosystem),
                    package_vuln.package.name,
                    package_vuln.package.version,
                    vuln_count
                );
            }

            if package_counts.len() > 5 {
                eprintln!("  ... and {} more", package_counts.len() - 5);
            }
        }

        if scan_result.vulnerable_packages == 0 {
            eprintln!("\n✅ No vulnerabilities found! Your packages are secure.");
        } else {
            eprintln!("\n💡 Recommendation: Review the detailed JSON report and update vulnerable packages.");
        }
    }

    fn ecosystem_emoji(ecosystem: &crate::types::Ecosystem) -> &'static str {
        match ecosystem {
            crate::types::Ecosystem::Npm => "📦",
            crate::types::Ecosystem::PyPI => "🐍",
            crate::types::Ecosystem::Cargo => "🦀",
            crate::types::Ecosystem::Maven => "☕",
            crate::types::Ecosystem::Go => "🐹",
            crate::types::Ecosystem::RubyGems => "💎",
        }
    }

    /// Generate a compact CSV report for further analysis
    pub async fn generate_csv_report(&self, scan_result: &ScanResult) -> VulfyResult<String> {
        let mut csv_content = String::new();
        csv_content.push_str("package_name,version,ecosystem,vulnerability_id,severity,summary,fixed_version,source_file\n");

        for package_vuln in &scan_result.packages {
            if package_vuln.vulnerabilities.is_empty() {
                // Include packages with no vulnerabilities
                csv_content.push_str(&format!(
                    "{},{},{},,,,,{}\n",
                    Self::escape_csv_field(&package_vuln.package.name),
                    Self::escape_csv_field(&package_vuln.package.version),
                    package_vuln.package.ecosystem.as_str(),
                    package_vuln.package.source_file.display()
                ));
            } else {
                for vuln in &package_vuln.vulnerabilities {
                    csv_content.push_str(&format!(
                        "{},{},{},{},{},{},{},{}\n",
                        Self::escape_csv_field(&package_vuln.package.name),
                        Self::escape_csv_field(&package_vuln.package.version),
                        package_vuln.package.ecosystem.as_str(),
                        Self::escape_csv_field(&vuln.id),
                        Self::escape_csv_field(&vuln.severity.as_deref().unwrap_or("Unknown")),
                        Self::escape_csv_field(&vuln.summary),
                        Self::escape_csv_field(&vuln.fixed_version.as_deref().unwrap_or("")),
                        package_vuln.package.source_file.display()
                    ));
                }
            }
        }

        Ok(csv_content)
    }

    fn escape_csv_field(field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
} 