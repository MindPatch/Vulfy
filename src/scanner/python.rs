use std::path::Path;
use serde_json::Value;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct PythonParser;

impl PackageParser for PythonParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("requirements.txt") | Some("Pipfile.lock") | Some("poetry.lock")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "requirements.txt" => self.parse_requirements_txt(file_path).await,
            "Pipfile.lock" => self.parse_pipfile_lock(file_path).await,
            "poetry.lock" => self.parse_poetry_lock(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
}

impl PythonParser {
    async fn parse_requirements_txt(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            // Parse package==version or package>=version etc.
            if let Some(package_info) = self.parse_requirement_line(line) {
                packages.push(Package {
                    name: package_info.0,
                    version: package_info.1,
                    ecosystem: Ecosystem::PyPI,
                    source_file: file_path.to_path_buf(),
                });
            }
        }

        Ok(packages)
    }

    async fn parse_pipfile_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let pipfile_lock: Value = serde_json::from_str(&content)?;

        let mut packages = Vec::new();

        // Parse default dependencies
        if let Some(default_deps) = pipfile_lock.get("default").and_then(|v| v.as_object()) {
            for (name, dep_info) in default_deps {
                if let Some(version) = dep_info.get("version").and_then(|v| v.as_str()) {
                    packages.push(Package {
                        name: name.clone(),
                        version: version.trim_start_matches("==").to_string(),
                        ecosystem: Ecosystem::PyPI,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        // Parse develop dependencies
        if let Some(develop_deps) = pipfile_lock.get("develop").and_then(|v| v.as_object()) {
            for (name, dep_info) in develop_deps {
                if let Some(version) = dep_info.get("version").and_then(|v| v.as_str()) {
                    packages.push(Package {
                        name: name.clone(),
                        version: version.trim_start_matches("==").to_string(),
                        ecosystem: Ecosystem::PyPI,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_poetry_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple TOML-like parsing for poetry.lock
        let mut current_package: Option<(String, String)> = None;
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("[[package]]") {
                if let Some((name, version)) = current_package.take() {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::PyPI,
                        source_file: file_path.to_path_buf(),
                    });
                }
            } else if line.starts_with("name = ") {
                if let Some(name) = line.split("=").nth(1) {
                    let name = name.trim().trim_matches('"');
                    if let Some((_, version)) = current_package.as_ref() {
                        current_package = Some((name.to_string(), version.clone()));
                    } else {
                        current_package = Some((name.to_string(), String::new()));
                    }
                }
            } else if line.starts_with("version = ") {
                if let Some(version) = line.split("=").nth(1) {
                    let version = version.trim().trim_matches('"');
                    if let Some((name, _)) = current_package.as_ref() {
                        current_package = Some((name.clone(), version.to_string()));
                    } else {
                        current_package = Some((String::new(), version.to_string()));
                    }
                }
            }
        }

        // Don't forget the last package
        if let Some((name, version)) = current_package {
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package {
                    name,
                    version,
                    ecosystem: Ecosystem::PyPI,
                    source_file: file_path.to_path_buf(),
                });
            }
        }

        Ok(packages)
    }

    fn parse_requirement_line(&self, line: &str) -> Option<(String, String)> {
        // Handle various requirement formats: package==1.0.0, package>=1.0.0, etc.
        let operators = ["==", ">=", "<=", "!=", "~=", ">", "<"];
        
        for op in &operators {
            if let Some(pos) = line.find(op) {
                let name = line[..pos].trim().to_string();
                let version = line[pos + op.len()..].trim()
                    .split(&[';', '#'][..]) // Remove comments and environment markers
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                
                if !name.is_empty() && !version.is_empty() {
                    return Some((name, version));
                }
            }
        }

        // Handle package without version specifier
        if !line.contains(&['=', '>', '<', '!', '~'][..]) {
            let name = line.split(&[';', '#'][..])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            
            if !name.is_empty() {
                return Some((name, "latest".to_string()));
            }
        }

        None
    }
} 