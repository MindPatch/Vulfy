use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct RubyParser;

impl PackageParser for RubyParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("Gemfile.lock")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        self.parse_gemfile_lock(&content, file_path).await
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }
}

impl RubyParser {
    async fn parse_gemfile_lock(&self, content: &str, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut packages = Vec::new();
        let mut in_gems_section = false;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Look for GEM section
            if line == "GEM" {
                in_gems_section = true;
                continue;
            }
            
            // Exit GEM section on new section
            if in_gems_section && line.starts_with(char::is_uppercase) && line.ends_with(':') {
                in_gems_section = false;
                continue;
            }
            
            // Skip source lines
            if line.starts_with("remote:") || line.starts_with("specs:") {
                continue;
            }
            
            // Parse gem entries
            if in_gems_section && line.starts_with("    ") && !line.starts_with("      ") {
                // Gem entry format: "    gem_name (version)"
                let gem_line = line.trim();
                
                if let Some(open_paren) = gem_line.find('(') {
                    if let Some(close_paren) = gem_line.find(')') {
                        let name = gem_line[..open_paren].trim().to_string();
                        let version = gem_line[open_paren + 1..close_paren].trim().to_string();
                        
                        if !name.is_empty() && !version.is_empty() {
                            packages.push(Package {
                                name,
                                version,
                                ecosystem: Ecosystem::RubyGems,
                                source_file: file_path.to_path_buf(),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(packages)
    }
} 