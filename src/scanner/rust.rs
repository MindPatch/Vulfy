use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct RustParser;

impl PackageParser for RustParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("Cargo.lock") | Some("Cargo.toml")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let cargo_data: toml::Value = toml::from_str(&content)?;

        let mut packages = Vec::new();

        match file_path.file_name().and_then(|n| n.to_str()) {
            Some("Cargo.lock") => {
                packages.extend(self.parse_cargo_lock(&cargo_data, file_path)?);
            }
            Some("Cargo.toml") => {
                packages.extend(self.parse_cargo_toml(&cargo_data, file_path)?);
            }
            _ => {} // Should not happen due to can_parse check
        }

        Ok(packages)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }
}

impl RustParser {
    fn parse_cargo_lock(&self, cargo_lock: &toml::Value, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut packages = Vec::new();

        if let Some(package_array) = cargo_lock.get("package").and_then(|v| v.as_array()) {
            for package in package_array {
                if let (Some(name), Some(version)) = (
                    package.get("name").and_then(|v| v.as_str()),
                    package.get("version").and_then(|v| v.as_str()),
                ) {
                    packages.push(Package {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Cargo,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn parse_cargo_toml(&self, cargo_toml: &toml::Value, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut packages = Vec::new();

        // Parse [dependencies] section
        if let Some(deps) = cargo_toml.get("dependencies").and_then(|v| v.as_table()) {
            for (name, dep_info) in deps {
                let version = self.extract_version_from_dependency(dep_info);
                if let Some(version) = version {
                    packages.push(Package {
                        name: name.clone(),
                        version,
                        ecosystem: Ecosystem::Cargo,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse [dev-dependencies] section
        if let Some(dev_deps) = cargo_toml.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (name, dep_info) in dev_deps {
                let version = self.extract_version_from_dependency(dep_info);
                if let Some(version) = version {
                    packages.push(Package {
                        name: name.clone(),
                        version,
                        ecosystem: Ecosystem::Cargo,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse [build-dependencies] section
        if let Some(build_deps) = cargo_toml.get("build-dependencies").and_then(|v| v.as_table()) {
            for (name, dep_info) in build_deps {
                let version = self.extract_version_from_dependency(dep_info);
                if let Some(version) = version {
                    packages.push(Package {
                        name: name.clone(),
                        version,
                        ecosystem: Ecosystem::Cargo,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn extract_version_from_dependency(&self, dep_info: &toml::Value) -> Option<String> {
        match dep_info {
            // Simple version string: serde = "1.0"
            toml::Value::String(version) => Some(version.clone()),
            
            // Table format: serde = { version = "1.0", features = ["derive"] }
            toml::Value::Table(table) => {
                table.get("version").and_then(|v| v.as_str()).map(|s| s.to_string())
            }
            
            _ => None,
        }
    }
} 