use thiserror::Error;

pub type VulfyResult<T> = Result<T, VulfyError>;

#[derive(Error, Debug)]
pub enum VulfyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("XML parsing error: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Unsupported file type: {file_type}")]
    UnsupportedFileType { file_type: String },

    #[error("Package parsing error: {message}")]
    PackageParsing { message: String },

    #[error("Version parsing error: {message}")]
    VersionParsing { message: String },

    #[error("OSV API error: {message}")]
    OsvApi { message: String },

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Generic error: {0}")]
    Generic(#[from] anyhow::Error),
} 