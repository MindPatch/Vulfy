use std::path::Path;
use serde_json::Value;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct NpmParser;

impl PackageParser for NpmParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("package-lock.json") | Some("yarn.lock") | Some("package.json")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "package-lock.json" => self.parse_package_lock(file_path).await,
            "yarn.lock" => self.parse_yarn_lock(file_path).await,
            "package.json" => self.parse_package_json(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
}

impl NpmParser {
    async fn parse_package_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let lock_file: Value = serde_json::from_str(&content)?;

        let mut packages = Vec::new();

        // Parse lockfileVersion 2 and 3 format
        if let Some(packages_obj) = lock_file.get("packages") {
            if let Some(packages_map) = packages_obj.as_object() {
                for (path, package_info) in packages_map {
                    if path.is_empty() {
                        continue; // Skip root package
                    }

                    if let (Some(name), Some(version)) = (
                        package_info.get("name").and_then(|v| v.as_str()),
                        package_info.get("version").and_then(|v| v.as_str()),
                    ) {
                        packages.push(Package {
                            name: name.to_string(),
                            version: version.to_string(),
                            ecosystem: Ecosystem::Npm,
                            source_file: file_path.to_path_buf(),
                        });
                    }
                }
            }
        }
        // Fallback to dependencies format (lockfileVersion 1)
        else if let Some(dependencies) = lock_file.get("dependencies") {
            if let Some(deps_map) = dependencies.as_object() {
                for (name, dep_info) in deps_map {
                    if let Some(version) = dep_info.get("version").and_then(|v| v.as_str()) {
                        packages.push(Package {
                            name: name.clone(),
                            version: version.to_string(),
                            ecosystem: Ecosystem::Npm,
                            source_file: file_path.to_path_buf(),
                        });
                    }
                }
            }
        }

        Ok(packages)
    }

    async fn parse_yarn_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple yarn.lock parser
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('"') && line.contains('@') && line.ends_with(':') {
                // Package line format: "package@version", "package@^version":
                let package_spec = line.trim_end_matches(':').trim_matches('"');
                if let Some(at_pos) = package_spec.rfind('@') {
                    let name = &package_spec[..at_pos];
                    let version_spec = &package_spec[at_pos + 1..];
                    
                    // Skip if it's a scoped package name (contains / after @)
                    if name.contains('/') && !name.starts_with('@') {
                        continue;
                    }

                    // Try to parse version from spec
                    let version = version_spec
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim_start_matches(">=")
                        .trim_start_matches("<=")
                        .trim_start_matches('>')
                        .trim_start_matches('<')
                        .to_string();

                    packages.push(Package {
                        name: name.to_string(),
                        version,
                        ecosystem: Ecosystem::Npm,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_package_json(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let package_json: Value = serde_json::from_str(&content)?;

        let mut packages = Vec::new();

        // Parse dependencies
        if let Some(deps) = package_json.get("dependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                if let Some(version_str) = version.as_str() {
                    packages.push(Package {
                        name: name.clone(),
                        version: version_str.to_string(),
                        ecosystem: Ecosystem::Npm,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse devDependencies
        if let Some(dev_deps) = package_json.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, version) in dev_deps {
                if let Some(version_str) = version.as_str() {
                    packages.push(Package {
                        name: name.clone(),
                        version: version_str.to_string(),
                        ecosystem: Ecosystem::Npm,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }
} 