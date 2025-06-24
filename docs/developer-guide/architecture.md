# Architecture Overview

Vulfy is built with a modular, async-first architecture designed for performance, reliability, and extensibility.

## High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Layer     │───▶│  Core Scanner    │───▶│  OSV.dev API    │
│  (clap-based)   │    │   (async Rust)   │    │   (HTTP/JSON)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │
         │                       ▼
         │              ┌──────────────────┐
         │              │  Package Parsers │
         │              │  (9 ecosystems)  │
         │              └──────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌──────────────────┐
│   Automation    │    │    Reporters     │
│   System        │    │ (Table/JSON/CSV) │
└─────────────────┘    └──────────────────┘
         │
         ▼
┌─────────────────┐
│  Notifications  │
│ (Discord/Slack) │
└─────────────────┘
```

## Core Components

### 1. CLI Layer (`src/cli.rs`)

**Responsibility**: Command-line interface and argument parsing

- Built with `clap` for robust argument parsing
- Supports nested subcommands (`scan packages`, `automation start`)
- Handles configuration loading and validation
- Manages output formatting and file operations

**Key Features**:
- Type-safe argument parsing with `clap` derive macros
- Builder pattern for configuration construction
- Comprehensive error handling and user feedback

### 2. Scanner Core (`src/scanner/mod.rs`)

**Responsibility**: Orchestrates the scanning process

- Discovers package files across supported ecosystems
- Manages concurrent scanning with rate limiting
- Coordinates between parsers and vulnerability matching
- Handles recursive directory traversal

**Architecture**:
```rust
pub struct Scanner {
    parsers: HashMap<Ecosystem, Box<dyn PackageParser>>,
    api_client: OsvClient,
    config: ScanConfig,
}
```

### 3. Package Parsers (`src/scanner/*.rs`)

**Responsibility**: Extract package information from manifest files

Each ecosystem has a dedicated parser implementing the `PackageParser` trait:

```rust
pub trait PackageParser: Send + Sync {
    async fn parse(&self, file_path: &Path) -> Result<Vec<Package>>;
    fn supported_files(&self) -> &[&str];
}
```

**Parsers**:
- **NPM** (`npm.rs`): package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- **Python** (`python.rs`): requirements.txt, Pipfile.lock, poetry.lock, pyproject.toml
- **Rust** (`rust.rs`): Cargo.lock, Cargo.toml
- **Java** (`java.rs`): pom.xml, build.gradle, build.gradle.kts
- **Go** (`go.rs`): go.mod, go.sum, go.work
- **Ruby** (`ruby.rs`): Gemfile.lock, Gemfile, *.gemspec
- **C++** (`cpp.rs`): vcpkg.json, CMakeLists.txt, conanfile.txt
- **PHP** (`php.rs`): composer.json, composer.lock
- **C#** (`csharp.rs`): *.csproj, packages.config, *.nuspec

### 4. Vulnerability Matcher (`src/matcher.rs`)

**Responsibility**: Match packages against vulnerability database

- Queries OSV.dev API for vulnerability information
- Implements semantic version comparison using `semver` crate
- Handles rate limiting and retry logic
- Filters vulnerabilities based on severity and policies

**Key Features**:
- Proper semantic version parsing and comparison
- Concurrent API requests with backoff
- CVSS severity parsing and normalization
- Comprehensive error handling

### 5. Reporter (`src/reporter.rs`)

**Responsibility**: Format and output scan results

Supports multiple output formats:
- **Table**: Beautiful ASCII tables with color coding
- **JSON**: Structured data for programmatic use
- **CSV**: Spreadsheet-compatible format
- **SARIF**: Static Analysis Results Interchange Format
- **Summary**: Condensed statistics only

### 6. Automation System (`src/automation/`)

**Responsibility**: Continuous monitoring and scheduling

#### Components:

**Scheduler** (`scheduler.rs`):
- Cron-based job scheduling using `tokio-cron-scheduler`
- Supports hourly, daily, weekly, and custom schedules
- Manages background task execution

**Git Monitor** (`git_monitor.rs`):
- Repository cloning and updates using `git2`
- Branch-specific monitoring
- Credential management for private repositories

**Policy Engine** (`policy.rs`):
- Advanced vulnerability filtering
- Regex-based pattern matching
- Severity and ecosystem targeting
- Custom notification rules

**Webhooks** (`webhooks.rs`):
- Discord, Slack, and generic webhook support
- Rich notification formatting
- Retry logic and error handling

## Data Flow

### 1. Scan Process

```
1. CLI parses arguments → ScanConfig
2. Scanner discovers package files
3. Parsers extract package information
4. Matcher queries OSV.dev API
5. Vulnerabilities are filtered and matched
6. Reporter formats and outputs results
```

### 2. Automation Process

```
1. Scheduler triggers scan job
2. Git Monitor clones/updates repositories
3. Scanner processes each repository
4. Policy Engine filters vulnerabilities
5. Webhooks send notifications
6. Results are stored/exported
```

## Key Design Decisions

### Async-First Architecture

- Built on `tokio` for maximum concurrency
- Non-blocking I/O operations throughout
- Efficient handling of multiple API requests
- Background task management for automation

### Strategy Pattern for Parsers

- Each ecosystem has a dedicated parser
- Common interface via `PackageParser` trait
- Easy to add new ecosystems
- Isolated parsing logic per ecosystem

### Semantic Version Handling

- Uses `semver` crate for proper version comparison
- Handles complex version ranges and constraints
- Fixes critical version comparison bugs from string-based comparison

### Error Handling Strategy

- Custom error types with `thiserror`
- Comprehensive error context
- Graceful degradation on parsing failures
- Detailed logging with `tracing`

### Configuration Management

- TOML-based configuration files
- Environment variable overrides
- Validation at load time
- Type-safe configuration structs

## Performance Optimizations

### Concurrent Processing

- Parallel package file discovery
- Concurrent API requests with rate limiting
- Async I/O operations throughout
- Background automation tasks

### Memory Efficiency

- Streaming parsers for large files
- Lazy loading of package information
- Efficient data structures
- Proper resource cleanup

### API Rate Limiting

- Configurable concurrent request limits
- Exponential backoff on failures
- Request batching where possible
- Respectful API usage patterns

## Security Considerations

### Credential Management

- Environment variable support for tokens
- SSH key authentication for Git
- Secure credential storage
- No credentials in configuration files

### Input Validation

- Comprehensive parsing validation
- Regex pattern validation
- URL validation for webhooks
- Path traversal protection

### Network Security

- HTTPS-only API communication
- Certificate validation
- Timeout handling
- Secure webhook delivery

## Extensibility Points

### Adding New Ecosystems

1. Create new parser in `src/scanner/`
2. Implement `PackageParser` trait
3. Register parser in scanner module
4. Add ecosystem to `types.rs`
5. Update CLI documentation

### Custom Output Formats

1. Add format variant to `ReportFormat` enum
2. Implement formatting logic in `reporter.rs`
3. Update CLI options
4. Add tests and documentation

### New Notification Channels

1. Add webhook type to `WebhookType` enum
2. Implement formatting in `webhooks.rs`
3. Add configuration options
4. Update validation logic

## Testing Strategy

### Unit Tests

- Parser validation with sample files
- Version comparison edge cases
- Configuration validation
- Error handling scenarios

### Integration Tests

- End-to-end scan workflows
- API integration testing
- Automation system testing
- Output format validation

### Performance Tests

- Large project scanning
- Concurrent request handling
- Memory usage validation
- API rate limiting compliance

## Dependencies

### Core Dependencies

- **tokio**: Async runtime and utilities
- **reqwest**: HTTP client for OSV.dev API
- **serde**: Serialization/deserialization
- **clap**: Command-line argument parsing
- **semver**: Semantic version parsing and comparison

### Parsing Dependencies

- **toml**: TOML configuration parsing
- **quick-xml**: XML parsing for Maven files
- **regex**: Pattern matching for policies
- **walkdir**: Recursive directory traversal

### Automation Dependencies

- **git2**: Git operations
- **tokio-cron-scheduler**: Job scheduling
- **chrono**: Date/time handling
- **uuid**: Unique identifier generation

## Future Architecture Considerations

### Scalability

- Database backend for large-scale deployments
- Distributed scanning capabilities
- Caching layer for vulnerability data
- Horizontal scaling support

### Plugin System

- Dynamic parser loading
- Custom notification handlers
- Third-party integrations
- Configuration extensions

### Performance Enhancements

- Local vulnerability database
- Incremental scanning
- Result caching
- Parallel repository processing

---

**Next**: [Adding Ecosystems](adding-ecosystems.md) - Guide for supporting new package managers 