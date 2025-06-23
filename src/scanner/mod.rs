use std::path::Path;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::error::{VulfyError, VulfyResult};
use crate::types::{Ecosystem, Package, ScanConfig};

mod npm;
mod python;
mod rust;
mod java;
mod go;
mod ruby;
mod cpp;
mod php;
mod csharp;

pub use npm::NpmParser;
pub use python::PythonParser;
pub use rust::RustParser;
pub use java::JavaParser;
pub use go::GoParser;
pub use ruby::RubyParser;
pub use cpp::CppParser;
pub use php::PhpParser;
pub use csharp::CSharpParser;

/// Strategy pattern for parsing different package file formats
pub trait PackageParser {
    fn can_parse(&self, file_path: &Path) -> bool;
    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>>;
    fn ecosystem(&self) -> Ecosystem;
}

/// Enum-based parser to handle async trait object limitations
#[derive(Debug)]
pub enum Parser {
    Npm(NpmParser),
    Python(PythonParser),
    Rust(RustParser),
    Java(JavaParser),
    Go(GoParser),
    Ruby(RubyParser),
    Cpp(CppParser),
    Php(PhpParser),
    Csharp(CSharpParser),
}

impl Parser {
    pub fn can_parse(&self, file_path: &Path) -> bool {
        match self {
            Parser::Npm(p) => p.can_parse(file_path),
            Parser::Python(p) => p.can_parse(file_path),
            Parser::Rust(p) => p.can_parse(file_path),
            Parser::Java(p) => p.can_parse(file_path),
            Parser::Go(p) => p.can_parse(file_path),
            Parser::Ruby(p) => p.can_parse(file_path),
            Parser::Cpp(p) => p.can_parse(file_path),
            Parser::Php(p) => p.can_parse(file_path),
            Parser::Csharp(p) => p.can_parse(file_path),
        }
    }

    pub async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        match self {
            Parser::Npm(p) => p.parse(file_path).await,
            Parser::Python(p) => p.parse(file_path).await,
            Parser::Rust(p) => p.parse(file_path).await,
            Parser::Java(p) => p.parse(file_path).await,
            Parser::Go(p) => p.parse(file_path).await,
            Parser::Ruby(p) => p.parse(file_path).await,
            Parser::Cpp(p) => p.parse(file_path).await,
            Parser::Php(p) => p.parse(file_path).await,
            Parser::Csharp(p) => p.parse(file_path).await,
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            Parser::Npm(p) => p.ecosystem(),
            Parser::Python(p) => p.ecosystem(),
            Parser::Rust(p) => p.ecosystem(),
            Parser::Java(p) => p.ecosystem(),
            Parser::Go(p) => p.ecosystem(),
            Parser::Ruby(p) => p.ecosystem(),
            Parser::Cpp(p) => p.ecosystem(),
            Parser::Php(p) => p.ecosystem(),
            Parser::Csharp(p) => p.ecosystem(),
        }
    }
}

pub struct Scanner {
    parsers: Vec<Parser>,
}

impl Scanner {
    pub fn new() -> Self {
        let parsers = vec![
            Parser::Npm(NpmParser),
            Parser::Python(PythonParser),
            Parser::Rust(RustParser),
            Parser::Java(JavaParser),
            Parser::Go(GoParser),
            Parser::Ruby(RubyParser),
            Parser::Cpp(CppParser),
            Parser::Php(PhpParser),
            Parser::Csharp(CSharpParser),
        ];

        Self { parsers }
    }

    pub async fn scan_directory(&self, config: &ScanConfig) -> VulfyResult<Vec<Package>> {
        let mut all_packages = Vec::new();

        if config.target_path.is_file() {
            // Single file scan
            all_packages.extend(self.scan_file(&config.target_path).await?);
        } else if config.target_path.is_dir() {
            // Directory scan with prioritization
            let discovered_files = if config.recursive {
                self.discover_files_recursive(&config.target_path)?
            } else {
                self.discover_files_flat(&config.target_path)?
            };

            // Group files by ecosystem and prioritize manifest files over lock files
            let prioritized_files = self.prioritize_files(discovered_files);
            
            // Process prioritized files
            for file_path in prioritized_files {
                if let Some(parser) = self.find_parser(&file_path) {
                    match self.scan_file_with_parser(&file_path, parser).await {
                        Ok(mut packages) => {
                            all_packages.append(&mut packages);
                        }
                        Err(e) => {
                            warn!("Failed to parse {}: {}", file_path.display(), e);
                        }
                    }
                }
            }
        } else {
            return Err(VulfyError::FileNotFound {
                path: config.target_path.display().to_string(),
            });
        }

        // Filter by ecosystems if specified
        if let Some(ref ecosystems) = config.ecosystems {
            all_packages.retain(|pkg| ecosystems.contains(&pkg.ecosystem));
        }

        info!("Collected {} packages from scan", all_packages.len());
        Ok(all_packages)
    }

    fn discover_files_recursive(&self, dir_path: &Path) -> VulfyResult<Vec<std::path::PathBuf>> {
        let mut files = Vec::new();

        for entry in WalkDir::new(dir_path) {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if path.is_file() && self.find_parser(path).is_some() {
                        files.push(path.to_path_buf());
                    }
                }
                Err(e) => {
                    warn!("Error accessing directory entry: {}", e);
                }
            }
        }

        Ok(files)
    }

    fn discover_files_flat(&self, dir_path: &Path) -> VulfyResult<Vec<std::path::PathBuf>> {
        let mut files = Vec::new();

        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| VulfyError::Io(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| VulfyError::Io(e))?;
            let path = entry.path();
            
            if path.is_file() && self.find_parser(&path).is_some() {
                files.push(path);
            }
        }

        Ok(files)
    }

    fn prioritize_files(&self, files: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
        use std::collections::HashMap;
        
        // Group files by ecosystem
        let mut ecosystem_files: HashMap<Ecosystem, Vec<std::path::PathBuf>> = HashMap::new();
        
        for file in files {
            if let Some(parser) = self.find_parser(&file) {
                let ecosystem = parser.ecosystem();
                ecosystem_files.entry(ecosystem).or_default().push(file);
            }
        }

        let mut prioritized_files = Vec::new();

        // For each ecosystem, prioritize manifest files over lock files
        for (ecosystem, files) in ecosystem_files {
            let (manifest_files, lock_files) = self.separate_manifest_and_lock_files(&ecosystem, files);
            
            if !manifest_files.is_empty() {
                // Prefer manifest files
                debug!("Using {} manifest files for ecosystem {}", manifest_files.len(), ecosystem.as_str());
                prioritized_files.extend(manifest_files);
            } else {
                // Fall back to lock files if no manifest files found
                debug!("Using {} lock files for ecosystem {} (no manifest files found)", lock_files.len(), ecosystem.as_str());
                prioritized_files.extend(lock_files);
            }
        }

        prioritized_files
    }

    fn separate_manifest_and_lock_files(&self, ecosystem: &Ecosystem, files: Vec<std::path::PathBuf>) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
        let mut manifest_files = Vec::new();
        let mut lock_files = Vec::new();

        for file in files {
            if self.is_lock_file(ecosystem, &file) {
                lock_files.push(file);
            } else {
                manifest_files.push(file);
            }
        }

        (manifest_files, lock_files)
    }

    fn is_lock_file(&self, ecosystem: &Ecosystem, file_path: &Path) -> bool {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        
        match ecosystem {
            Ecosystem::Npm => matches!(filename, "package-lock.json" | "yarn.lock" | "npm-shrinkwrap.json" | "pnpm-lock.yaml"),
            Ecosystem::PyPI => matches!(filename, "Pipfile.lock" | "poetry.lock"),
            Ecosystem::Cargo => matches!(filename, "Cargo.lock"),
            Ecosystem::Go => matches!(filename, "go.sum" | "go.work.sum"),
            Ecosystem::Composer => matches!(filename, "composer.lock"),
            // Java, Ruby, Vcpkg, NuGet don't have traditional lock files in our current implementation
            _ => false,
        }
    }

    async fn scan_file(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        if let Some(parser) = self.find_parser(file_path) {
            self.scan_file_with_parser(file_path, parser).await
        } else {
            Err(VulfyError::UnsupportedFileType {
                file_type: file_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
            })
        }
    }

    async fn scan_file_with_parser(&self, file_path: &Path, parser: &Parser) -> VulfyResult<Vec<Package>> {
        debug!("Parsing {} with {} parser", file_path.display(), parser.ecosystem().as_str());
        parser.parse(file_path).await
    }

    fn find_parser(&self, file_path: &Path) -> Option<&Parser> {
        self.parsers
            .iter()
            .find(|parser| parser.can_parse(file_path))
    }

    async fn scan_directory_recursive(&self, dir_path: &Path, _config: &ScanConfig) -> VulfyResult<Vec<Package>> {
        // This method is no longer used - keeping for backward compatibility
        let mut all_packages = Vec::new();

        for entry in WalkDir::new(dir_path) {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(parser) = self.find_parser(path) {
                            debug!("Found parseable file: {:?}", path);
                            match self.scan_file_with_parser(path, parser).await {
                                Ok(mut packages) => {
                                    all_packages.append(&mut packages);
                                }
                                Err(e) => {
                                    warn!("Failed to parse {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Error accessing directory entry: {}", e);
                }
            }
        }

        Ok(all_packages)
    }

    async fn scan_directory_flat(&self, dir_path: &Path) -> VulfyResult<Vec<Package>> {
        // This method is no longer used - keeping for backward compatibility
        let mut all_packages = Vec::new();

        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| VulfyError::Io(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| VulfyError::Io(e))?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(parser) = self.find_parser(&path) {
                    debug!("Found parseable file: {:?}", path);
                    match self.scan_file_with_parser(&path, parser).await {
                        Ok(mut packages) => {
                            all_packages.append(&mut packages);
                        }
                        Err(e) => {
                            warn!("Failed to parse {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(all_packages)
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
} 