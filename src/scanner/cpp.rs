use std::path::Path;
use serde_json::Value;

use crate::error::VulfyResult;
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct CppParser;

impl PackageParser for CppParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        matches!(
            filename,
            "vcpkg.json" | "CMakeLists.txt" | "conanfile.txt" | "conanfile.py"
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "vcpkg.json" => self.parse_vcpkg_json(file_path).await,
            "CMakeLists.txt" => self.parse_cmake(file_path).await,
            "conanfile.txt" => self.parse_conanfile_txt(file_path).await,
            "conanfile.py" => self.parse_conanfile_py(file_path).await,
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Vcpkg
    }
}

impl CppParser {
    async fn parse_vcpkg_json(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let vcpkg_manifest: Value = serde_json::from_str(&content)?;
        let mut packages = Vec::new();

        // Parse dependencies array
        if let Some(deps) = vcpkg_manifest.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps {
                match dep {
                    // Simple string dependency: "boost"
                    Value::String(name) => {
                        packages.push(Package {
                            name: name.clone(),
                            version: "latest".to_string(),
                            ecosystem: Ecosystem::Vcpkg,
                            source_file: file_path.to_path_buf(),
                        });
                    }
                    // Object dependency: {"name": "boost", "version>=": "1.70.0"}
                    Value::Object(dep_obj) => {
                        if let Some(name) = dep_obj.get("name").and_then(|n| n.as_str()) {
                            let version = dep_obj
                                .get("version>=")
                                .or_else(|| dep_obj.get("version"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("latest")
                                .to_string();

                            packages.push(Package {
                                name: name.to_string(),
                                version,
                                ecosystem: Ecosystem::Vcpkg,
                                source_file: file_path.to_path_buf(),
                            });
                        }
                    }
                    _ => continue,
                }
            }
        }

        Ok(packages)
    }

    async fn parse_cmake(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Look for find_package() calls
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("find_package(") && line.contains(')') {
                if let Some(package_name) = self.extract_cmake_package(line) {
                    packages.push(Package {
                        name: package_name,
                        version: "latest".to_string(),
                        ecosystem: Ecosystem::Vcpkg,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_conanfile_txt(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        let mut in_requires = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line == "[requires]" {
                in_requires = true;
                continue;
            } else if line.starts_with('[') {
                in_requires = false;
                continue;
            }

            if in_requires && !line.is_empty() && !line.starts_with('#') {
                if let Some((name, version)) = self.parse_conan_requirement(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::Vcpkg, // Conan packages often overlap with vcpkg
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_conanfile_py(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Look for self.requires() calls
        for line in content.lines() {
            let line = line.trim();
            
            if line.contains("self.requires(") {
                if let Some((name, version)) = self.extract_conan_py_requirement(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::Vcpkg,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn extract_cmake_package(&self, line: &str) -> Option<String> {
        // Extract package name from find_package(PackageName ...)
        if let Some(start) = line.find('(') {
            if let Some(end) = line[start..].find(')') {
                let params = &line[start + 1..start + end];
                let parts: Vec<&str> = params.split_whitespace().collect();
                if !parts.is_empty() {
                    return Some(parts[0].to_string());
                }
            }
        }
        None
    }

    fn parse_conan_requirement(&self, line: &str) -> Option<(String, String)> {
        // Parse format: boost/1.70.0@conan/stable or boost/1.70.0
        if let Some(slash_pos) = line.find('/') {
            let name = line[..slash_pos].trim().to_string();
            let rest = &line[slash_pos + 1..];
            
            // Extract version (before @ if present)
            let version = if let Some(at_pos) = rest.find('@') {
                rest[..at_pos].trim().to_string()
            } else {
                rest.trim().to_string()
            };
            
            Some((name, version))
        } else {
            // Just package name without version
            Some((line.trim().to_string(), "latest".to_string()))
        }
    }

    fn extract_conan_py_requirement(&self, line: &str) -> Option<(String, String)> {
        // Extract from self.requires("boost/1.70.0@conan/stable")
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                let requirement = &line[start + 1..start + 1 + end];
                return self.parse_conan_requirement(requirement);
            }
        }
        // Try single quotes
        if let Some(start) = line.find('\'') {
            if let Some(end) = line[start + 1..].find('\'') {
                let requirement = &line[start + 1..start + 1 + end];
                return self.parse_conan_requirement(requirement);
            }
        }
        None
    }
} 