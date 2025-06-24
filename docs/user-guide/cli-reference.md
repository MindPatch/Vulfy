# CLI Reference

Complete reference for all Vulfy command-line options and subcommands.

## Global Usage

```bash
vulfy [COMMAND]
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `scan` | Scan packages for vulnerabilities |
| `automation` | Automation and monitoring commands |

---

## Scan Commands

### `vulfy scan packages`

Scan all supported package files for vulnerabilities.

#### Usage

```bash
vulfy scan packages [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--path <PATH>` | `-p` | Target directory or file to scan | `.` (current directory) |
| `--format <FORMAT>` | `-f` | Report format | `table` |
| `--output <FILE>` | `-o` | Output file (optional - defaults to stdout) | stdout |
| `--no-recursive` | | Disable recursive scanning | false |
| `--ecosystems <LIST>` | `-e` | Only scan specific ecosystems (comma-separated) | all |
| `--no-dev-deps` | | Exclude development dependencies | false |
| `--quiet` | `-q` | Quiet mode - suppress scan progress info | false |
| `--high-only` | | Show only high severity vulnerabilities | false |

#### Supported Formats

- `table` - Beautiful ASCII table with emojis (default)
- `json` - JSON format for programmatic use
- `csv` - CSV format for spreadsheet analysis
- `summary` - Summary only - just statistics
- `sarif` - SARIF format for static analysis tools

#### Supported Ecosystems

- `npm` - Node.js packages
- `pypi` - Python packages  
- `crates.io` - Rust packages (alias: `cargo`)
- `maven` - Java packages
- `go` - Go modules
- `rubygems` - Ruby gems
- `vcpkg` - C/C++ packages
- `packagist` - PHP packages (alias: `composer`)
- `nuget` - .NET packages

#### Examples

```bash
# Basic scan with table output
vulfy scan packages

# Scan specific directory
vulfy scan packages --path /path/to/project

# JSON output to file
vulfy scan packages --format json --output report.json

# Only high-severity vulnerabilities
vulfy scan packages --high-only --quiet

# Scan only npm and Python packages
vulfy scan packages --ecosystems npm,pypi

# Skip development dependencies
vulfy scan packages --no-dev-deps

# Non-recursive scan
vulfy scan packages --no-recursive
```

---

## Automation Commands

### `vulfy automation init`

Initialize automation configuration with optional examples.

#### Usage

```bash
vulfy automation init [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |
| `--with-examples` | | Create with example repositories and policies | false |

#### Examples

```bash
# Create basic configuration
vulfy automation init

# Create with example policies and repositories
vulfy automation init --with-examples

# Custom config file location
vulfy automation init --config /path/to/config.toml
```

### `vulfy automation start`

Start the automation scheduler for continuous monitoring.

#### Usage

```bash
vulfy automation start [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |
| `--workspace <PATH>` | `-w` | Workspace directory for cloning repositories | `vulfy-workspace` |
| `--foreground` | | Run in foreground (default runs as daemon) | false |

#### Examples

```bash
# Start scheduler as daemon
vulfy automation start

# Run in foreground for debugging
vulfy automation start --foreground

# Custom workspace directory
vulfy automation start --workspace /tmp/vulfy-repos
```

### `vulfy automation stop`

Stop the automation scheduler.

#### Usage

```bash
vulfy automation stop [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |

### `vulfy automation run`

Run a manual scan using automation configuration.

#### Usage

```bash
vulfy automation run [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |
| `--workspace <PATH>` | `-w` | Workspace directory for cloning repositories | `vulfy-workspace` |
| `--repository <NAME>` | `-r` | Specific repository to scan (optional) | all |
| `--format <FORMAT>` | `-f` | Report format | `table` |
| `--output <FILE>` | `-o` | Output file (optional - save results to file) | stdout |
| `--vulnerabilities-only` | | Show only vulnerabilities (skip summary) | false |

#### Examples

```bash
# Run manual scan for all repositories
vulfy automation run

# Scan specific repository
vulfy automation run --repository my-web-app

# Output to JSON file
vulfy automation run --format json --output scan-results.json

# Show only vulnerabilities
vulfy automation run --vulnerabilities-only
```

### `vulfy automation status`

Show automation status and next scheduled run.

#### Usage

```bash
vulfy automation status [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |

### `vulfy automation validate`

Validate automation configuration file.

#### Usage

```bash
vulfy automation validate [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <PATH>` | `-c` | Configuration file path | `vulfy-automation.toml` |

---

## Global Options

### Help

```bash
# General help
vulfy --help

# Command-specific help
vulfy scan --help
vulfy automation --help
vulfy automation init --help
```

### Version

```bash
vulfy --version
```

---

## Exit Codes

Vulfy uses standard exit codes for CI/CD integration:

| Code | Meaning |
|------|---------|
| `0` | Success - no vulnerabilities found |
| `1` | Vulnerabilities found or scan error |
| `2` | Invalid command line arguments |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULFY_LOG` | Log level (error, warn, info, debug, trace) | `info` |
| `VULFY_CONFIG` | Default configuration file path | `vulfy-automation.toml` |
| `VULFY_WORKSPACE` | Default workspace directory | `vulfy-workspace` |

### Examples

```bash
# Enable debug logging
VULFY_LOG=debug vulfy scan packages

# Use custom config location
VULFY_CONFIG=/path/to/config.toml vulfy automation status
```

---

## Configuration Files

### Scan Configuration

Create a `.vulfy.toml` file in your project root:

```toml
[scan]
ecosystems = ["npm", "pypi", "crates.io"]
min_severity = "medium"
skip_dev_deps = true
ignore_paths = ["node_modules", "vendor", ".git"]

[output]
format = "table"
color = "auto"

[api]
timeout = 30
max_concurrent = 10
retry_attempts = 3
```

### Automation Configuration

See [Configuration Guide](configuration.md) for complete automation configuration reference.

---

## Tips and Best Practices

### Performance

- Use `--ecosystems` to limit scanning to relevant package managers
- Use `--no-dev-deps` to skip development dependencies in production scans
- Use `--quiet` in CI/CD pipelines to reduce output noise

### CI/CD Integration

```bash
# Fail build if high-severity vulnerabilities found
vulfy scan packages --high-only --quiet || exit 1

# Generate SARIF report for GitHub Security tab
vulfy scan packages --format sarif --output vulfy.sarif
```

### Output Management

- Use `--output` to save results to files
- Use `--format json` for programmatic processing
- Use `--format summary` for quick overview

---

**Next**: [Configuration Guide](configuration.md) - Detailed configuration options 