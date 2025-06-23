use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct RubyParser;

impl PackageParser for RubyParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        matches!(filename, "Gemfile.lock" | "Gemfile" | "gems.rb") ||
        filename.ends_with(".gemspec")
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "Gemfile.lock" => self.parse_gemfile_lock(file_path).await,
            "Gemfile" | "gems.rb" => self.parse_gemfile(file_path).await,
            name if name.ends_with(".gemspec") => self.parse_gemspec(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }
}

impl RubyParser {
    async fn parse_gemfile_lock(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        self.parse_gemfile_lock_content(&content, file_path).await
    }

    async fn parse_gemfile_lock_content(&self, content: &str, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut packages = Vec::new();
        let mut in_gems_section = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line == "GEM" {
                in_gems_section = true;
                continue;
            } else if line.starts_with("PLATFORMS") || line.starts_with("DEPENDENCIES") || line.starts_with("BUNDLED") {
                in_gems_section = false;
                continue;
            }

            if in_gems_section && line.contains('(') && line.contains(')') {
                // Parse gem line like: "    rails (7.0.0)"
                if let Some(open_paren) = line.find('(') {
                    if let Some(close_paren) = line.find(')') {
                        let name = line[..open_paren].trim().to_string();
                        let version = line[open_paren + 1..close_paren].trim().to_string();
                        
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

    async fn parse_gemfile(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Parse Gemfile for gem declarations
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse gem lines: gem 'name', 'version' or gem "name", "version"
            if line.starts_with("gem ") {
                if let Some((name, version)) = self.parse_gem_declaration(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::RubyGems,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_gemspec(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Parse gemspec for add_dependency calls
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments
            if line.starts_with('#') {
                continue;
            }

            // Parse dependency lines: s.add_dependency 'name', 'version'
            if line.contains("add_dependency") || line.contains("add_runtime_dependency") || line.contains("add_development_dependency") {
                if let Some((name, version)) = self.parse_gemspec_dependency(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::RubyGems,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn parse_gem_declaration(&self, line: &str) -> Option<(String, String)> {
        // Parse: gem 'name', 'version' or gem "name", "version"
        let line = line.trim_start_matches("gem").trim();
        
        // Extract quoted strings
        let parts = self.extract_quoted_parts(line);
        if parts.len() >= 2 {
            Some((parts[0].clone(), parts[1].clone()))
        } else if parts.len() == 1 {
            // No version specified
            Some((parts[0].clone(), "latest".to_string()))
        } else {
            None
        }
    }

    fn parse_gemspec_dependency(&self, line: &str) -> Option<(String, String)> {
        // Parse: s.add_dependency 'name', 'version'
        let parts = self.extract_quoted_parts(line);
        if parts.len() >= 2 {
            Some((parts[0].clone(), parts[1].clone()))
        } else if parts.len() == 1 {
            Some((parts[0].clone(), "latest".to_string()))
        } else {
            None
        }
    }

    fn extract_quoted_parts(&self, line: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut chars = line.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\'' || c == '"' {
                let quote_char = c;
                let mut content = String::new();
                
                while let Some(inner_c) = chars.next() {
                    if inner_c == quote_char {
                        break;
                    }
                    content.push(inner_c);
                }
                
                if !content.is_empty() {
                    parts.push(content);
                }
            }
        }
        
        parts
    }
} 