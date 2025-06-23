use std::path::Path;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct CSharpParser;

impl PackageParser for CSharpParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let extension = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        
        matches!(filename, "packages.config" | "Directory.Build.props" | "Directory.Packages.props") ||
        matches!(extension, "csproj" | "vbproj" | "fsproj") ||
        filename.ends_with(".nuspec")
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let extension = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match (filename, extension) {
            ("packages.config", _) => self.parse_packages_config(file_path).await,
            ("Directory.Build.props", _) | ("Directory.Packages.props", _) => {
                self.parse_directory_props(file_path).await
            }
            (_, "csproj") | (_, "vbproj") | (_, "fsproj") => {
                self.parse_project_file(file_path).await
            }
            (name, _) if name.ends_with(".nuspec") => {
                self.parse_nuspec(file_path).await
            }
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }
}

impl CSharpParser {
    async fn parse_packages_config(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple XML parsing for packages.config
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("<package ") && line.contains("id=") && line.contains("version=") {
                if let Some((id, version)) = self.extract_package_info(line) {
                    packages.push(Package {
                        name: id,
                        version,
                        ecosystem: Ecosystem::NuGet,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_project_file(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Parse PackageReference elements
        for line in content.lines() {
            let line = line.trim();
            
            // Format: <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
            if line.contains("<PackageReference") && line.contains("Include=") {
                if let Some((name, version)) = self.extract_package_reference(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::NuGet,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_directory_props(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Parse centralized package management
        for line in content.lines() {
            let line = line.trim();
            
            // Format: <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
            if line.contains("<PackageVersion") && line.contains("Include=") {
                if let Some((name, version)) = self.extract_package_version(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::NuGet,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_nuspec(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        let mut in_dependencies = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line.contains("<dependencies>") {
                in_dependencies = true;
                continue;
            } else if line.contains("</dependencies>") {
                in_dependencies = false;
                continue;
            }

            if in_dependencies && line.contains("<dependency") && line.contains("id=") {
                if let Some((id, version)) = self.extract_dependency_info(line) {
                    packages.push(Package {
                        name: id,
                        version,
                        ecosystem: Ecosystem::NuGet,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn extract_package_info(&self, line: &str) -> Option<(String, String)> {
        // Parse: <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
        let id = self.extract_xml_attribute(line, "id")?;
        let version = self.extract_xml_attribute(line, "version")?;
        Some((id, version))
    }

    fn extract_package_reference(&self, line: &str) -> Option<(String, String)> {
        // Parse: <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
        let name = self.extract_xml_attribute(line, "Include")?;
        let version = self.extract_xml_attribute(line, "Version").unwrap_or_else(|| "latest".to_string());
        Some((name, version))
    }

    fn extract_package_version(&self, line: &str) -> Option<(String, String)> {
        // Parse: <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
        let name = self.extract_xml_attribute(line, "Include")?;
        let version = self.extract_xml_attribute(line, "Version")?;
        Some((name, version))
    }

    fn extract_dependency_info(&self, line: &str) -> Option<(String, String)> {
        // Parse: <dependency id="Newtonsoft.Json" version="13.0.1" />
        let id = self.extract_xml_attribute(line, "id")?;
        let version = self.extract_xml_attribute(line, "version").unwrap_or_else(|| "latest".to_string());
        Some((id, version))
    }

    fn extract_xml_attribute(&self, line: &str, attr: &str) -> Option<String> {
        let pattern = format!("{}=\"", attr);
        if let Some(start) = line.find(&pattern) {
            let start_pos = start + pattern.len();
            if let Some(end) = line[start_pos..].find('"') {
                return Some(line[start_pos..start_pos + end].to_string());
            }
        }
        None
    }
} 