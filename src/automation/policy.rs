use crate::automation::{ScanPolicy, ScanResult, PolicyConditions, PolicyActions};
use crate::types::{Vulnerability, Package};
use tracing::{info, debug, warn};
use regex::Regex;
use std::collections::HashMap;

pub struct PolicyEngine {
    policies: Vec<ScanPolicy>,
}

#[derive(Debug, Clone)]
pub struct PolicyMatch {
    pub policy_name: String,
    pub vulnerability_id: String,
    pub package_name: String,
    pub actions: PolicyActions,
}

#[derive(Debug, Clone)]
pub struct FilteredScanResult {
    pub scan_result: ScanResult,
    pub policy_matches: Vec<PolicyMatch>,
    pub ignored_vulnerabilities: Vec<String>,
    pub prioritized_vulnerabilities: Vec<String>,
}

impl PolicyEngine {
    pub fn new(policies: Vec<ScanPolicy>) -> Self {
        Self { policies }
    }

    /// Apply policies to scan results
    pub fn apply_policies(&self, scan_result: &ScanResult, packages: &[Package]) -> FilteredScanResult {
        let mut policy_matches = Vec::new();
        let mut ignored_vulnerabilities = Vec::new();
        let mut prioritized_vulnerabilities = Vec::new();
        
        // Create a package lookup map for vulnerability context
        let package_map: HashMap<String, &Package> = packages
            .iter()
            .map(|p| (format!("{}@{}", p.name, p.version), p))
            .collect();

        // Apply each policy to each vulnerability
        for vulnerability in &scan_result.vulnerabilities {
            for policy in &self.policies {
                if policy.enabled {
                    // Find the package associated with this vulnerability
                    let package_name = self.find_package_for_vulnerability(vulnerability, &package_map);
                    
                    if self.vulnerability_matches_policy(vulnerability, policy, package_name.as_deref()) {
                        let policy_match = PolicyMatch {
                            policy_name: policy.name.clone(),
                            vulnerability_id: vulnerability.id.clone(),
                            package_name: package_name.clone().unwrap_or_else(|| "unknown".to_string()),
                            actions: policy.actions.clone(),
                        };

                        policy_matches.push(policy_match.clone());

                        // Apply policy actions
                        if policy.actions.ignore {
                            ignored_vulnerabilities.push(vulnerability.id.clone());
                            debug!("Policy '{}' ignored vulnerability: {}", policy.name, vulnerability.id);
                        }

                        if policy.actions.notify {
                            prioritized_vulnerabilities.push(vulnerability.id.clone());
                            info!("Policy '{}' prioritized vulnerability: {} ({})", 
                                  policy.name, vulnerability.id, policy.actions.priority.as_str());
                        }
                    }
                }
            }
        }

        // Remove ignored vulnerabilities from the result
        let filtered_vulnerabilities: Vec<Vulnerability> = scan_result
            .vulnerabilities
            .iter()
            .filter(|v| !ignored_vulnerabilities.contains(&v.id))
            .cloned()
            .collect();

        let mut filtered_scan_result = scan_result.clone();
        filtered_scan_result.vulnerabilities = filtered_vulnerabilities;
        filtered_scan_result.policies_applied = self.policies.iter().map(|p| p.name.clone()).collect();

        FilteredScanResult {
            scan_result: filtered_scan_result,
            policy_matches,
            ignored_vulnerabilities,
            prioritized_vulnerabilities,
        }
    }

    /// Check if a vulnerability matches a policy
    fn vulnerability_matches_policy(&self, vulnerability: &Vulnerability, policy: &ScanPolicy, package_name: Option<&str>) -> bool {
        let conditions = &policy.conditions;

        // Check title contains keywords (case-insensitive)
        if let Some(keywords) = &conditions.title_contains {
            let title_lower = vulnerability.summary.to_lowercase();
            
            let has_keyword = keywords.iter().any(|keyword| {
                let keyword_lower = keyword.to_lowercase();
                title_lower.contains(&keyword_lower)
            });
            
            if !has_keyword {
                return false;
            }
        }

        // Check severity levels
        if let Some(severities) = &conditions.severity {
            if let Some(vuln_severity) = &vulnerability.severity {
                let vuln_severity_lower = vuln_severity.to_lowercase();
                let severity_matches = severities.iter().any(|s| vuln_severity_lower.contains(&s.to_lowercase()));
                
                if !severity_matches {
                    return false;
                }
            } else {
                // No severity info available, skip this condition
                return false;
            }
        }

        // Check CVE pattern
        if let Some(pattern) = &conditions.cve_pattern {
            if let Ok(regex) = Regex::new(pattern) {
                // Check against the vulnerability ID
                let has_match = regex.is_match(&vulnerability.id);
                
                if !has_match {
                    return false;
                }
            } else {
                warn!("Invalid regex pattern in policy '{}': {}", policy.name, pattern);
                return false;
            }
        }

        // Check package names
        if let Some(packages) = &conditions.packages {
            if let Some(pkg_name) = package_name {
                let package_matches = packages.iter().any(|p| {
                    // Support wildcard matching
                    if p.contains('*') {
                        let pattern = p.replace('*', ".*");
                        if let Ok(regex) = Regex::new(&pattern) {
                            regex.is_match(pkg_name)
                        } else {
                            false
                        }
                    } else {
                        pkg_name.contains(p)
                    }
                });
                
                if !package_matches {
                    return false;
                }
            } else {
                // No package name available, can't match package condition
                return false;
            }
        }

        // Check ecosystems
        if let Some(_ecosystems) = &conditions.ecosystems {
            // This would need ecosystem context from the scan
            // For now, we'll skip this check as we don't have ecosystem info in Vulnerability
        }

        true
    }

    /// Find the package associated with a vulnerability
    fn find_package_for_vulnerability(&self, vulnerability: &Vulnerability, package_map: &HashMap<String, &Package>) -> Option<String> {
        // This is a best-effort approach since vulnerability doesn't directly reference packages
        // We'll try to match based on package names mentioned in the vulnerability
        
        for package in package_map.values() {
            // Check if package name is mentioned in vulnerability summary
            let package_name = &package.name;
            
            if vulnerability.summary.to_lowercase().contains(&package_name.to_lowercase()) {
                return Some(package_name.clone());
            }
        }
        
        None
    }

    /// Create a default set of policies for common security issues
    pub fn create_default_policies() -> Vec<ScanPolicy> {
        vec![
            ScanPolicy {
                name: "Critical Authentication Issues".to_string(),
                enabled: true,
                conditions: PolicyConditions {
                    title_contains: Some(vec![
                        "unauth".to_string(),
                        "authentication".to_string(),
                        "bypass".to_string(),
                        "privilege".to_string(),
                        "escalation".to_string(),
                    ]),
                    severity: Some(vec!["high".to_string(), "critical".to_string()]),
                    ecosystems: None,
                    cve_pattern: None,
                    packages: None,
                },
                actions: PolicyActions {
                    notify: true,
                    priority: crate::automation::PolicyPriority::Critical,
                    custom_message: Some("🚨 Critical authentication vulnerability detected!".to_string()),
                    ignore: false,
                },
            },
            ScanPolicy {
                name: "XSS Vulnerabilities".to_string(),
                enabled: true,
                conditions: PolicyConditions {
                    title_contains: Some(vec![
                        "xss".to_string(),
                        "cross-site scripting".to_string(),
                        "script injection".to_string(),
                    ]),
                    severity: Some(vec!["medium".to_string(), "high".to_string(), "critical".to_string()]),
                    ecosystems: None,
                    cve_pattern: None,
                    packages: None,
                },
                actions: PolicyActions {
                    notify: true,
                    priority: crate::automation::PolicyPriority::High,
                    custom_message: Some("⚠️ XSS vulnerability requires attention".to_string()),
                    ignore: false,
                },
            },
            ScanPolicy {
                name: "SQL Injection".to_string(),
                enabled: true,
                conditions: PolicyConditions {
                    title_contains: Some(vec![
                        "sql injection".to_string(),
                        "sqli".to_string(),
                        "sql".to_string(),
                    ]),
                    severity: Some(vec!["medium".to_string(), "high".to_string(), "critical".to_string()]),
                    ecosystems: None,
                    cve_pattern: None,
                    packages: None,
                },
                actions: PolicyActions {
                    notify: true,
                    priority: crate::automation::PolicyPriority::High,
                    custom_message: Some("💉 SQL injection vulnerability detected".to_string()),
                    ignore: false,
                },
            },
            ScanPolicy {
                name: "Low Priority Development Dependencies".to_string(),
                enabled: true,
                conditions: PolicyConditions {
                    title_contains: None,
                    severity: Some(vec!["low".to_string()]),
                    ecosystems: None,
                    cve_pattern: None,
                    packages: Some(vec![
                        "test*".to_string(),
                        "dev*".to_string(),
                        "*dev".to_string(),
                        "*test".to_string(),
                    ]),
                },
                actions: PolicyActions {
                    notify: false,
                    priority: crate::automation::PolicyPriority::Low,
                    custom_message: None,
                    ignore: true, // Ignore low-severity issues in dev dependencies
                },
            },
        ]
    }

    /// Get summary statistics for policy application
    pub fn get_policy_stats(&self, filtered_result: &FilteredScanResult) -> PolicyStats {
        let total_policies = self.policies.len();
        let active_policies = self.policies.iter().filter(|p| p.enabled).count();
        
        let policy_matches_by_name: HashMap<String, usize> = filtered_result
            .policy_matches
            .iter()
            .fold(HashMap::new(), |mut acc, m| {
                *acc.entry(m.policy_name.clone()).or_insert(0) += 1;
                acc
            });

        PolicyStats {
            total_policies,
            active_policies,
            total_matches: filtered_result.policy_matches.len(),
            ignored_vulnerabilities: filtered_result.ignored_vulnerabilities.len(),
            prioritized_vulnerabilities: filtered_result.prioritized_vulnerabilities.len(),
            policy_matches_by_name,
        }
    }
}

#[derive(Debug)]
pub struct PolicyStats {
    pub total_policies: usize,
    pub active_policies: usize,
    pub total_matches: usize,
    pub ignored_vulnerabilities: usize,
    pub prioritized_vulnerabilities: usize,
    pub policy_matches_by_name: HashMap<String, usize>,
}

impl crate::automation::PolicyPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            crate::automation::PolicyPriority::Critical => "critical",
            crate::automation::PolicyPriority::High => "high",
            crate::automation::PolicyPriority::Medium => "medium",
            crate::automation::PolicyPriority::Low => "low",
        }
    }
} 