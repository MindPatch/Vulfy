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
            Some("requirements.txt") | Some("Pipfile.lock") | Some("poetry.lock") |
            Some("Pipfile") | Some("pyproject.toml") | Some("setup.py") |
            Some("setup.cfg") | Some("environment.yml") | Some("environment.yaml") |
            Some("conda.yaml") | Some("conda.yml")
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
            "Pipfile" => self.parse_pipfile(file_path).await,
            "pyproject.toml" => self.parse_pyproject_toml(file_path).await,
            "setup.py" => self.parse_setup_py(file_path).await,
            "setup.cfg" => self.parse_setup_cfg(file_path).await,
            "environment.yml" | "environment.yaml" | "conda.yaml" | "conda.yml" => {
                self.parse_conda_env(file_path).await
            }
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

    async fn parse_pipfile(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple TOML-like parsing for Pipfile [packages] and [dev-packages] sections
        let mut in_packages = false;
        let mut in_dev_packages = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line == "[packages]" {
                in_packages = true;
                in_dev_packages = false;
                continue;
            } else if line == "[dev-packages]" {
                in_packages = false;
                in_dev_packages = true;
                continue;
            } else if line.starts_with('[') {
                in_packages = false;
                in_dev_packages = false;
                continue;
            }

            if (in_packages || in_dev_packages) && line.contains('=') {
                if let Some((name, version)) = self.parse_pipfile_dependency(line) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::PyPI,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_pyproject_toml(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let pyproject: toml::Value = toml::from_str(&content)?;
        let mut packages = Vec::new();

        // Parse poetry dependencies
        if let Some(poetry) = pyproject.get("tool").and_then(|t| t.get("poetry")) {
            if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
                for (name, version_info) in deps {
                    if name != "python" { // Skip python version
                        if let Some(version) = self.extract_poetry_version(version_info) {
                            packages.push(Package {
                                name: name.clone(),
                                version,
                                ecosystem: Ecosystem::PyPI,
                                source_file: file_path.to_path_buf(),
                            });
                        }
                    }
                }
            }

            if let Some(dev_deps) = poetry.get("group").and_then(|g| g.get("dev")).and_then(|d| d.get("dependencies")).and_then(|d| d.as_table()) {
                for (name, version_info) in dev_deps {
                    if let Some(version) = self.extract_poetry_version(version_info) {
                        packages.push(Package {
                            name: name.clone(),
                            version,
                            ecosystem: Ecosystem::PyPI,
                            source_file: file_path.to_path_buf(),
                        });
                    }
                }
            }
        }

        // Parse PEP 621 project dependencies
        if let Some(project) = pyproject.get("project") {
            if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    if let Some(dep_str) = dep.as_str() {
                        if let Some((name, version)) = self.parse_requirement_line(dep_str) {
                            packages.push(Package {
                                name,
                                version,
                                ecosystem: Ecosystem::PyPI,
                                source_file: file_path.to_path_buf(),
                            });
                        }
                    }
                }
            }
        }

        Ok(packages)
    }

    async fn parse_setup_py(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple regex-like parsing for install_requires and extras_require
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            
            if line.contains("install_requires") || line.contains("extras_require") {
                // Look for dependencies in the next lines
                let mut j = i;
                while j < lines.len() {
                    let dep_line = lines[j].trim();
                    
                    // Extract quoted dependencies
                    if dep_line.contains('"') || dep_line.contains('\'') {
                        if let Some(dep) = self.extract_quoted_dependency(dep_line) {
                            if let Some((name, version)) = self.parse_requirement_line(&dep) {
                                packages.push(Package {
                                    name,
                                    version,
                                    ecosystem: Ecosystem::PyPI,
                                    source_file: file_path.to_path_buf(),
                                });
                            }
                        }
                    }
                    
                    if dep_line.contains(']') || dep_line.contains(')') {
                        break;
                    }
                    j += 1;
                }
                i = j;
            } else {
                i += 1;
            }
        }

        Ok(packages)
    }

    async fn parse_setup_cfg(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        let mut in_options = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line == "[options]" {
                in_options = true;
                continue;
            } else if line.starts_with('[') {
                in_options = false;
                continue;
            }

            if in_options && line.starts_with("install_requires") {
                // Handle multi-line install_requires
                let deps_part = line.split('=').nth(1).unwrap_or("").trim();
                if !deps_part.is_empty() {
                    for dep in deps_part.split(',') {
                        if let Some((name, version)) = self.parse_requirement_line(dep.trim()) {
                            packages.push(Package {
                                name,
                                version,
                                ecosystem: Ecosystem::PyPI,
                                source_file: file_path.to_path_buf(),
                            });
                        }
                    }
                }
            }
        }

        Ok(packages)
    }

    async fn parse_conda_env(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();
        let mut in_dependencies = false;

        for line in content.lines() {
            let line = line.trim();
            
            if line == "dependencies:" {
                in_dependencies = true;
                continue;
            } else if line.starts_with("name:") || line.starts_with("channels:") || !line.starts_with('-') {
                if !line.is_empty() && !line.starts_with('#') {
                    in_dependencies = false;
                }
                continue;
            }

            if in_dependencies && line.starts_with('-') {
                let dep = line.trim_start_matches('-').trim();
                
                // Skip conda-specific packages and pip sections
                if dep.starts_with("pip:") || dep.contains("conda") {
                    continue;
                }

                if let Some((name, version)) = self.parse_conda_dependency(dep) {
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::PyPI, // Most conda packages are also on PyPI
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn parse_pipfile_dependency(&self, line: &str) -> Option<(String, String)> {
        if let Some(eq_pos) = line.find('=') {
            let name = line[..eq_pos].trim().trim_matches('"').to_string();
            let version_part = line[eq_pos + 1..].trim().trim_matches('"');
            
            // Handle simple version strings
            if !version_part.starts_with('{') {
                return Some((name, version_part.to_string()));
            }
        }
        None
    }

    fn extract_poetry_version(&self, version_info: &toml::Value) -> Option<String> {
        match version_info {
            toml::Value::String(version) => Some(version.clone()),
            toml::Value::Table(table) => {
                table.get("version").and_then(|v| v.as_str()).map(|s| s.to_string())
            }
            _ => None,
        }
    }

    fn extract_quoted_dependency(&self, line: &str) -> Option<String> {
        // Extract content between quotes
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        if let Some(start) = line.find('\'') {
            if let Some(end) = line[start + 1..].find('\'') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    fn parse_conda_dependency(&self, dep: &str) -> Option<(String, String)> {
        // Handle conda dependencies like: numpy=1.21.0, scipy>=1.7.0
        let operators = ["==", ">=", "<=", "!=", "=", ">", "<"];
        
        for op in &operators {
            if let Some(pos) = dep.find(op) {
                let name = dep[..pos].trim().to_string();
                let version = dep[pos + op.len()..].trim().to_string();
                
                if !name.is_empty() && !version.is_empty() {
                    return Some((name, version));
                }
            }
        }

        // Package without version
        if !dep.contains(&['=', '>', '<'][..]) && !dep.is_empty() {
            return Some((dep.trim().to_string(), "latest".to_string()));
        }

        None
    }
} 