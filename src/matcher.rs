use std::collections::HashMap;
use tracing::{debug, info, warn};
use reqwest::Client;

use crate::error::{VulfyError, VulfyResult};
use crate::types::{
    Ecosystem, EcosystemSummary, OsvQuery, OsvPackage, OsvResponse, OsvVulnerability,
    Package, PackageVulnerability, ScanResult, Vulnerability,
};

const OSV_API_URL: &str = "https://api.osv.dev/v1";
const MAX_CONCURRENT_REQUESTS: usize = 10;

pub struct VulnerabilityMatcher {
    client: Client,
}

impl VulnerabilityMatcher {
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("vulfy/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    pub async fn check_vulnerabilities(&self, packages: Vec<Package>) -> VulfyResult<ScanResult> {
        let total_packages = packages.len();
        info!("Checking {} packages for vulnerabilities", total_packages);

        // Process packages in chunks to avoid overwhelming the API
        let mut all_package_vulnerabilities = Vec::new();
        let chunks: Vec<_> = packages.chunks(MAX_CONCURRENT_REQUESTS).collect();

        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            debug!("Processing chunk {} of {}", chunk_idx + 1, chunks.len());
            
            let chunk_results = self.process_package_chunk(chunk).await?;
            all_package_vulnerabilities.extend(chunk_results);

            // Small delay between chunks to be respectful to the API
            if chunk_idx < chunks.len() - 1 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        // Generate scan result statistics
        let scan_result = self.generate_scan_result(all_package_vulnerabilities).await;
        
        info!(
            "Vulnerability check complete: {}/{} packages have vulnerabilities",
            scan_result.vulnerable_packages,
            scan_result.total_packages
        );

        Ok(scan_result)
    }

    async fn process_package_chunk(&self, packages: &[Package]) -> VulfyResult<Vec<PackageVulnerability>> {
        let mut tasks = Vec::new();

        for package in packages {
            let task = self.check_package_vulnerabilities(package.clone());
            tasks.push(task);
        }

        // Execute all requests concurrently
        let results = futures::future::join_all(tasks).await;
        
        let mut package_vulnerabilities = Vec::new();
        for (package, result) in packages.iter().zip(results) {
            match result {
                Ok(vulnerabilities) => {
                    package_vulnerabilities.push(PackageVulnerability {
                        package: package.clone(),
                        vulnerabilities,
                    });
                }
                Err(e) => {
                    warn!("Failed to check vulnerabilities for {}: {}", package.name, e);
                    // Include package with empty vulnerabilities list on error
                    package_vulnerabilities.push(PackageVulnerability {
                        package: package.clone(),
                        vulnerabilities: Vec::new(),
                    });
                }
            }
        }

        Ok(package_vulnerabilities)
    }

    async fn check_package_vulnerabilities(&self, package: Package) -> VulfyResult<Vec<Vulnerability>> {
        debug!("Checking vulnerabilities for {}@{}", package.name, package.version);

        let query = OsvQuery {
            package: OsvPackage {
                name: package.name.clone(),
                ecosystem: package.ecosystem.as_str().to_string(),
            },
        };

        let url = format!("{}/query", OSV_API_URL);
        let response = self
            .client
            .post(&url)
            .json(&query)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VulfyError::OsvApi {
                message: format!(
                    "OSV API request failed with status: {} for package {}",
                    response.status(),
                    package.name
                ),
            });
        }

        let osv_response: OsvResponse = response.json().await?;
        
        let vulnerabilities = self.convert_osv_vulnerabilities(osv_response.vulns, &package).await;
        
        if !vulnerabilities.is_empty() {
            debug!("Found {} vulnerabilities for {}", vulnerabilities.len(), package.name);
        }

        Ok(vulnerabilities)
    }

    async fn convert_osv_vulnerabilities(
        &self,
        osv_vulns: Vec<OsvVulnerability>,
        package: &Package,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for osv_vuln in osv_vulns {
            // Check if this vulnerability affects the current package version
            if self.is_version_affected(&osv_vuln, &package.version) {
                let severity = osv_vuln
                    .severity
                    .as_ref()
                    .and_then(|severities| severities.first())
                    .map(|s| s.score.clone());

                let fixed_version = self.find_fixed_version(&osv_vuln);

                let references = osv_vuln
                    .references
                    .as_ref()
                    .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
                    .unwrap_or_default();

                vulnerabilities.push(Vulnerability {
                    id: osv_vuln.id,
                    summary: osv_vuln.summary.unwrap_or_else(|| "No summary available".to_string()),
                    severity,
                    fixed_version,
                    references,
                });
            }
        }

        vulnerabilities
    }

    fn is_version_affected(&self, osv_vuln: &OsvVulnerability, version: &str) -> bool {
        // Simplified version checking - in a real implementation, this would need
        // to handle complex version range semantics for different ecosystems
        if let Some(affected) = &osv_vuln.affected {
            for affected_entry in affected {
                if let Some(ranges) = &affected_entry.ranges {
                    for range in ranges {
                        // Simple check - assume version is affected if it's mentioned
                        // A proper implementation would use semver parsing and range checking
                        if range.range_type == "ECOSYSTEM" || range.range_type == "SEMVER" {
                            for event in &range.events {
                                if let Some(introduced) = &event.introduced {
                                    if introduced == "0" || version >= introduced.as_str() {
                                        if let Some(fixed) = &event.fixed {
                                            if version < fixed.as_str() {
                                                return true;
                                            }
                                        } else {
                                            return true; // No fixed version yet
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If we can't determine from ranges, assume it might be affected
        true
    }

    fn find_fixed_version(&self, osv_vuln: &OsvVulnerability) -> Option<String> {
        if let Some(affected) = &osv_vuln.affected {
            for affected_entry in affected {
                if let Some(ranges) = &affected_entry.ranges {
                    for range in ranges {
                        for event in &range.events {
                            if let Some(fixed) = &event.fixed {
                                return Some(fixed.clone());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    async fn generate_scan_result(&self, package_vulnerabilities: Vec<PackageVulnerability>) -> ScanResult {
        let total_packages = package_vulnerabilities.len();
        let vulnerable_packages = package_vulnerabilities
            .iter()
            .filter(|pv| !pv.vulnerabilities.is_empty())
            .count();
        
        let total_vulnerabilities: usize = package_vulnerabilities
            .iter()
            .map(|pv| pv.vulnerabilities.len())
            .sum();

        // Generate summary by ecosystem
        let mut summary_by_ecosystem: HashMap<Ecosystem, EcosystemSummary> = HashMap::new();
        
        for package_vuln in &package_vulnerabilities {
            let ecosystem = &package_vuln.package.ecosystem;
            let entry = summary_by_ecosystem.entry(ecosystem.clone()).or_insert(EcosystemSummary {
                total_packages: 0,
                vulnerable_packages: 0,
                total_vulnerabilities: 0,
            });
            
            entry.total_packages += 1;
            if !package_vuln.vulnerabilities.is_empty() {
                entry.vulnerable_packages += 1;
                entry.total_vulnerabilities += package_vuln.vulnerabilities.len();
            }
        }

        ScanResult {
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            total_packages,
            vulnerable_packages,
            total_vulnerabilities,
            packages: package_vulnerabilities,
            summary_by_ecosystem,
        }
    }
}

impl Default for VulnerabilityMatcher {
    fn default() -> Self {
        Self::new()
    }
} 