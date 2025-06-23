use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct GoParser;

impl PackageParser for GoParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("go.mod") | Some("go.sum")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "go.mod" => self.parse_go_mod(file_path).await,
            "go.sum" => self.parse_go_sum(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }
}

impl GoParser {
    async fn parse_go_mod(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        
        let mut in_require_block = false;
        let mut in_replace_block = false;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            
            // Check for require block
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            } else if line.starts_with("replace (") {
                in_replace_block = true;
                continue;
            } else if line == ")" {
                in_require_block = false;
                in_replace_block = false;
                continue;
            }
            
            // Parse single-line require
            if line.starts_with("require ") && !in_require_block {
                if let Some(package) = self.parse_go_dependency(&line[8..]) {
                    packages.push(Package {
                        name: package.0,
                        version: package.1,
                        ecosystem: Ecosystem::Go,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
            // Parse dependencies in require block
            else if in_require_block && !in_replace_block {
                if let Some(package) = self.parse_go_dependency(line) {
                    packages.push(Package {
                        name: package.0,
                        version: package.1,
                        ecosystem: Ecosystem::Go,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }
        
        Ok(packages)
    }

    async fn parse_go_sum(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.is_empty() {
                continue;
            }
            
            // go.sum format: module version hash
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let module = parts[0];
                let version = parts[1];
                
                // Skip /go.mod entries
                if version.ends_with("/go.mod") {
                    continue;
                }
                
                packages.push(Package {
                    name: module.to_string(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Go,
                    source_file: file_path.to_path_buf(),
                });
            }
        }
        
        Ok(packages)
    }

    fn parse_go_dependency(&self, line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() >= 2 {
            let module = parts[0].to_string();
            let version = parts[1].to_string();
            
            // Remove 'indirect' comment if present
            let version = if parts.len() > 2 && parts[2] == "//indirect" {
                version
            } else {
                version
            };
            
            Some((module, version))
        } else {
            None
        }
    }
} 