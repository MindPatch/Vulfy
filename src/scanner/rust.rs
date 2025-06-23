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
            Some("Cargo.lock")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let cargo_lock: toml::Value = toml::from_str(&content)?;

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

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }
} 