use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct GoParser;

impl PackageParser for GoParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        matches!(
            filename,
            "go.mod" | "go.sum" | "go.work" | "go.work.sum"
        ) || (filename == "modules.txt" && file_path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()) == Some("vendor"))
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "go.mod" => self.parse_go_mod(file_path).await,
            "go.sum" => self.parse_go_sum(file_path).await,
            "go.work" => self.parse_go_work(file_path).await,
            "go.work.sum" => self.parse_go_sum(file_path).await, // Same format as go.sum
            "modules.txt" => self.parse_vendor_modules(file_path).await,
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
            
            // Parse version, handle indirect dependencies
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let version = parts[1];
                
                // Remove 'v' prefix if present
                let clean_version = version.trim_start_matches('v');

                packages.push(Package {
                    name: name.to_string(),
                    version: clean_version.to_string(),
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

    async fn parse_go_work(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // go.work files mainly contain module paths, not direct dependencies
        // But we can scan for use directives that point to local modules
        for line in content.lines() {
            let line = line.trim();
            
            if let Some(stripped) = line.strip_prefix("use ") {
                let _module_path = stripped.trim();
                // Handle 'use' directive if needed
            }

            // Parse require statement
            if let Some(stripped) = line.strip_prefix("require ") {
                if let Some((name, version)) = self.parse_require_line(stripped) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::Go,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_vendor_modules(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // vendor/modules.txt format:
        // # module_name version
        // ## explicit; go 1.18
        // module_name/subpackage
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("# ") && !line.starts_with("## ") {
                let module_info = &line[2..];
                let parts: Vec<&str> = module_info.split_whitespace().collect();
                
                if parts.len() >= 2 {
                    let name = parts[0].to_string();
                    let version = parts[1].to_string();
                    
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::Go,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn parse_require_line(&self, line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let version = parts[1].to_string();
            Some((name, version))
        } else {
            None
        }
    }
} 