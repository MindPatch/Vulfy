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

pub use npm::NpmParser;
pub use python::PythonParser;
pub use rust::RustParser;
pub use java::JavaParser;
pub use go::GoParser;
pub use ruby::RubyParser;

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
        ];

        Self { parsers }
    }

    pub async fn scan_directory(&self, config: &ScanConfig) -> VulfyResult<Vec<Package>> {
        let mut all_packages = Vec::new();

        if config.target_path.is_file() {
            // Single file scan
            all_packages.extend(self.scan_file(&config.target_path).await?);
        } else if config.target_path.is_dir() {
            // Directory scan
            if config.recursive {
                all_packages.extend(self.scan_directory_recursive(&config.target_path, config).await?);
            } else {
                all_packages.extend(self.scan_directory_flat(&config.target_path).await?);
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

    async fn scan_directory_recursive(&self, dir_path: &Path, _config: &ScanConfig) -> VulfyResult<Vec<Package>> {
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
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
} 