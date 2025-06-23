use std::path::Path;
use serde_json::Value;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct PhpParser;

impl PackageParser for PhpParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        matches!(
            filename,
            "composer.json" | "composer.lock" | "phpunit.xml" | "phpunit.xml.dist"
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "composer.json" => self.parse_composer_json(file_path).await,
            "composer.lock" => self.parse_composer_lock(file_path).await,
            "phpunit.xml" | "phpunit.xml.dist" => self.parse_phpunit_xml(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Composer
    }
}

impl PhpParser {
    async fn parse_composer_json(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let composer_json: Value = serde_json::from_str(&content)?;
        let mut packages = Vec::new();

        // Parse require dependencies
        if let Some(require) = composer_json.get("require").and_then(|r| r.as_object()) {
            for (name, version) in require {
                // Skip PHP version requirement
                if name == "php" {
                    continue;
                }
                
                if let Some(version_str) = version.as_str() {
                    packages.push(Package {
                        name: name.clone(),
                        version: version_str.to_string(),
                        ecosystem: Ecosystem::Composer,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse require-dev dependencies
        if let Some(require_dev) = composer_json.get("require-dev").and_then(|r| r.as_object()) {
            for (name, version) in require_dev {
                if let Some(version_str) = version.as_str() {
                    packages.push(Package {
                        name: name.clone(),
                        version: version_str.to_string(),
                        ecosystem: Ecosystem::Composer,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_composer_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let composer_lock: Value = serde_json::from_str(&content)?;
        let mut packages = Vec::new();

        // Parse packages array (main dependencies)
        if let Some(packages_array) = composer_lock.get("packages").and_then(|p| p.as_array()) {
            for package in packages_array {
                if let (Some(name), Some(version)) = (
                    package.get("name").and_then(|n| n.as_str()),
                    package.get("version").and_then(|v| v.as_str()),
                ) {
                    packages.push(Package {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Composer,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse packages-dev array (development dependencies)
        if let Some(dev_packages) = composer_lock.get("packages-dev").and_then(|p| p.as_array()) {
            for package in dev_packages {
                if let (Some(name), Some(version)) = (
                    package.get("name").and_then(|n| n.as_str()),
                    package.get("version").and_then(|v| v.as_str()),
                ) {
                    packages.push(Package {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Composer,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_phpunit_xml(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        // PHPUnit XML files don't typically contain dependency information
        // but might reference test dependencies - we'll skip for now
        // Could be extended to parse custom extensions or test suites
        let _content = tokio::fs::read_to_string(file_path).await?;
        Ok(Vec::new())
    }
} 