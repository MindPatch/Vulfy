# Getting Started with Vulfy

Welcome to Vulfy! This guide will help you install and run your first vulnerability scan in just a few minutes.

## What is Vulfy?

Vulfy is a lightning-fast, cross-language vulnerability scanner that checks your project dependencies for known security issues. Built with Rust for maximum performance, it integrates with the OSV.dev database to provide accurate, up-to-date vulnerability information across 9 programming language ecosystems.

## Installation

### Option 1: Pre-built Binaries (Recommended)

Download the latest release for your platform:

```bash
# Linux x86_64
curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
tar -xzf vulfy-linux-x86_64.tar.gz
sudo mv vulfy /usr/local/bin/

# macOS (Intel)
curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-macos-x86_64.tar.gz
tar -xzf vulfy-macos-x86_64.tar.gz
sudo mv vulfy /usr/local/bin/

# macOS (Apple Silicon)
curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-macos-aarch64.tar.gz
tar -xzf vulfy-macos-aarch64.tar.gz
sudo mv vulfy /usr/local/bin/

# Windows
# Download vulfy-windows-x86_64.zip from releases page and extract to PATH
```

### Option 2: Install with Cargo

If you have Rust installed:

```bash
cargo install vulfy
```

### Option 3: Build from Source

```bash
git clone https://github.com/mindPatch/vulfy.git
cd vulfy
cargo build --release
sudo cp target/release/vulfy /usr/local/bin/
```

## Verify Installation

```bash
vulfy --version
# Should output: vulfy 0.1.0
```

## Your First Scan

### Basic Scan

Navigate to any project directory and run:

```bash
vulfy scan packages
```

This will:
- 🔍 Recursively scan for package files
- 📦 Detect dependencies across all supported ecosystems
- 🛡️ Check for vulnerabilities using OSV.dev
- 📊 Display results in a beautiful table format

### Example Output

```
🔍 Scanning for package files...
📦 Found 6 package files across 4 ecosystems

🛡️  VULNERABILITY REPORT
┌─────────────────────────────────────────┬──────────────┬──────────┬─────────────────┬──────┐
│ Title                                   │ CVE ID       │ Severity │ Package         │ Year │
├─────────────────────────────────────────┼──────────────┼──────────┼─────────────────┼──────┤
│ Remote Code Execution in lodash        │ CVE-2021-123 │ 🔥 High  │ lodash@4.17.0   │ 2021 │
│ Path Traversal in express              │ CVE-2022-456 │ 🟡 Medium│ express@4.16.0  │ 2022 │
│ SQL Injection in sequelize             │ CVE-2020-789 │ 🔥 High  │ sequelize@5.0.0 │ 2020 │
└─────────────────────────────────────────┴──────────────┴──────────┴─────────────────┴──────┘

📊 SCAN SUMMARY
• Total packages scanned: 42
• Vulnerable packages: 8
• Total vulnerabilities: 12
• 🔥 High severity: 4
• 🟡 Medium severity: 6
• 🟢 Low severity: 2
```

## Supported Ecosystems

Vulfy automatically detects and scans the following package managers:

| Ecosystem | Package Files | Status |
|-----------|---------------|--------|
| **npm** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` | ✅ |
| **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` | ✅ |
| **Rust** | `Cargo.lock`, `Cargo.toml` | ✅ |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | ✅ |
| **Go** | `go.mod`, `go.sum`, `go.work` | ✅ |
| **Ruby** | `Gemfile.lock`, `Gemfile`, `*.gemspec` | ✅ |
| **C/C++** | `vcpkg.json`, `CMakeLists.txt`, `conanfile.txt` | ✅ |
| **PHP** | `composer.json`, `composer.lock` | ✅ |
| **.NET** | `*.csproj`, `packages.config`, `*.nuspec` | ✅ |

## Common Use Cases

### Scan Specific Directory

```bash
vulfy scan packages --path /path/to/project
```

### Save Results to File

```bash
# JSON format for programmatic use
vulfy scan packages --format json --output security-report.json

# CSV format for spreadsheet analysis
vulfy scan packages --format csv --output vulnerabilities.csv

# SARIF format for GitHub Security tab
vulfy scan packages --format sarif --output vulfy.sarif
```

### Filter by Severity

```bash
# Only show high-severity vulnerabilities
vulfy scan packages --high-only

# Quiet mode (suppress progress info)
vulfy scan packages --quiet
```

### Target Specific Ecosystems

```bash
# Only scan npm and Python packages
vulfy scan packages --ecosystems npm,pypi

# Scan only Rust projects
vulfy scan packages --ecosystems crates.io
```

### Skip Development Dependencies

```bash
vulfy scan packages --no-dev-deps
```

## Exit Codes

Vulfy uses standard exit codes for CI/CD integration:

- `0`: Scan completed successfully, no vulnerabilities found
- `1`: Vulnerabilities found or scan error occurred
- `2`: Invalid command line arguments

## Next Steps

Now that you've run your first scan, you might want to:

1. **[Configure Output Formats](output-formats.md)** - Learn about JSON, CSV, and SARIF formats
2. **[Set Up Automation](automation-overview.md)** - Monitor repositories continuously
3. **[Integrate with CI/CD](../tutorials/ci-cd-integration.md)** - Add Vulfy to your pipelines
4. **[Customize with Policies](security-policies.md)** - Create advanced filtering rules

## Troubleshooting

### Common Issues

**"No package files found"**
- Ensure you're in a project directory with supported package files
- Use `--path` to specify the correct directory
- Check that package files aren't in ignored directories

**"Network connection failed"**
- Vulfy requires internet access to query OSV.dev
- Check your firewall and proxy settings
- The OSV.dev API may be temporarily unavailable

**"Permission denied"**
- Make sure the `vulfy` binary is executable: `chmod +x vulfy`
- On macOS, you may need to allow the binary in Security & Privacy settings

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/mindPatch/vulfy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mindPatch/vulfy/discussions)
- **CLI Help**: Run `vulfy --help` or `vulfy scan packages --help`

---

**Next**: [CLI Reference](cli-reference.md) - Complete command documentation 