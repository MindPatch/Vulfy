<div align="center">
  <img src="assets/main_logo.png" alt="Vulfy Logo" width="200"/>
  
  # 🐺 Vulfy
  
  **Fast, cross-language vulnerability scanner that doesn't mess around.**
  
  [![Release](https://img.shields.io/github/v/release/mindPatch/vulfy)](https://github.com/mindPatch/vulfy/releases)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
  [![CI](https://img.shields.io/github/actions/workflow/status/mindPatch/vulfy/ci.yml)](https://github.com/mindPatch/vulfy/actions)
</div>

---

## 🚀 What is Vulfy?

Vulfy is a lightning-fast vulnerability scanner that checks your project dependencies for known security issues across **9 programming languages**. Built with Rust for maximum performance, it integrates with the OSV.dev database to provide accurate, up-to-date vulnerability information.

### ✨ Key Features

- 🔥 **Lightning Fast** - Async Rust performance with concurrent scanning
- 🌍 **Multi-Ecosystem Support** - npm, Python, Rust, Java, Go, Ruby, C/C++, PHP, .NET
- 📊 **Multiple Output Formats** - Table, JSON, CSV, SARIF for different use cases
- 🎯 **OSV.dev Integration** - Real vulnerability data from Google's Open Source Vulnerabilities database
- ⚡ **Zero Configuration** - Works out of the box, configure only what you need
- 🔄 **CI/CD Ready** - Perfect exit codes and formats for automated pipelines
- 🤖 **Automation & Monitoring** - Continuous Git repository monitoring with smart notifications
- 📋 **Advanced Policy Engine** - Custom vulnerability filtering and security policies
- 🔔 **Multi-Platform Notifications** - Discord, Slack, and webhook integrations

---

## 📚 Documentation

**[📖 Complete Documentation](docs/README.md)** - Comprehensive guides, tutorials, and API reference

### Quick Navigation
- **[🚀 5-Minute Quick Start](docs/tutorials/quick-start.md)** - Get scanning immediately
- **[⚙️ Installation Guide](docs/user-guide/getting-started.md)** - All installation methods
- **[📋 CLI Reference](docs/user-guide/cli-reference.md)** - Complete command documentation
- **[🤖 Automation Setup](docs/user-guide/automation-overview.md)** - Continuous monitoring
- **[🔧 Configuration Schema](docs/api-reference/configuration-schema.md)** - Full configuration reference

---

## 📦 Installation

### Option 1: Pre-built Binaries (Recommended)
```bash
# Linux/WSL
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
```

### Option 2: Using Cargo
```bash
cargo install vulfy
```

### Option 3: From Source
```bash
git clone https://github.com/mindPatch/vulfy.git
cd vulfy
cargo build --release
sudo cp target/release/vulfy /usr/local/bin/
```

**Verify Installation:**
```bash
vulfy --version
# Should output: vulfy 0.1.0
```

---

## 🏃‍♂️ Quick Start

### Basic Vulnerability Scan
```bash
# Scan current directory
vulfy scan packages

# Scan specific directory
vulfy scan packages --path /path/to/project

# Only show high-severity vulnerabilities
vulfy scan packages --high-only
```

### Generate Reports
```bash
# JSON for automation/CI
vulfy scan packages --format json --output security-report.json

# CSV for spreadsheet analysis
vulfy scan packages --format csv --output vulnerabilities.csv

# SARIF for GitHub Security tab
vulfy scan packages --format sarif --output vulfy.sarif
```

### CI/CD Integration
```bash
# Fail build if high-severity vulnerabilities found
vulfy scan packages --high-only --quiet || exit 1

# Scan specific ecosystems only
vulfy scan packages --ecosystems npm,pypi --no-dev-deps
```

---

## 🎯 Supported Ecosystems

| Ecosystem | Package Files | Status |
|-----------|---------------|--------|
| 📦 **npm** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` | ✅ |
| 🐍 **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` | ✅ |
| 🦀 **Rust** | `Cargo.lock`, `Cargo.toml` | ✅ |
| ☕ **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | ✅ |
| 🐹 **Go** | `go.mod`, `go.sum`, `go.work` | ✅ |
| 💎 **Ruby** | `Gemfile.lock`, `Gemfile`, `*.gemspec` | ✅ |
| ⚙️ **C/C++** | `vcpkg.json`, `CMakeLists.txt`, `conanfile.txt` | 🆕 **NEW!** |
| 🐘 **PHP** | `composer.json`, `composer.lock` | 🆕 **NEW!** |
| 🔷 **.NET** | `*.csproj`, `packages.config`, `*.nuspec` | 🆕 **NEW!** |

---

## 📋 Example Output

### Beautiful Table Format (Default)
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

**[📖 See All Output Formats](docs/user-guide/output-formats.md)** - JSON, CSV, SARIF examples

---

## 🤖 Automation & Monitoring

Vulfy includes a powerful automation system for continuous security monitoring of Git repositories.

### Key Automation Features

- 📂 **Multi-Repository Monitoring** - Track multiple Git repos with branch-specific scanning
- ⏰ **Flexible Scheduling** - Hourly, daily, weekly, or custom cron expressions
- 🔔 **Smart Notifications** - Rich Discord/Slack alerts with severity-based filtering
- 📋 **Advanced Policy Engine** - Custom vulnerability filtering with keyword matching
- 🔐 **Authentication Support** - GitHub tokens, SSH keys, private repository access
- 🏗️ **Ecosystem Filtering** - Per-repository ecosystem targeting for focused scans

### Quick Automation Setup

```bash
# Initialize automation with example configuration
vulfy automation init --with-examples

# Validate configuration
vulfy automation validate

# Run manual scan using automation config
vulfy automation run

# Start continuous monitoring
vulfy automation start --foreground
```

### Example Configuration

```toml
# Monitor multiple repositories
[[repositories]]
name = "my-web-app"
url = "https://github.com/user/my-web-app.git"
branches = ["main", "develop"]
ecosystems = ["npm", "pypi"]

[repositories.credentials]
username = "git"
token = "your_github_token_here"

# Schedule daily scans at 2:00 AM UTC
[schedule]
frequency = "daily"
time = "02:00"
timezone = "UTC"

# Discord webhook notifications
[[notifications.webhooks]]
name = "Security Alerts"
url = "https://discord.com/api/webhooks/..."
webhook_type = "discord"
enabled = true

# Advanced security policies
[[policies]]
name = "Critical Authentication Issues"
enabled = true

[policies.conditions]
title_contains = ["authentication", "auth", "bypass"]
severity = ["high", "critical"]

[policies.actions]
notify = true
priority = "critical"
custom_message = "🚨 Critical auth vulnerability detected!"
```

**[📖 Complete Automation Guide](docs/user-guide/automation-overview.md)** - Detailed setup and configuration

---

## 🛠️ Usage & Configuration

### Command Line Options

```bash
vulfy scan packages [OPTIONS]

OPTIONS:
    -p, --path <PATH>              Directory to scan [default: current directory]
    -f, --format <FORMAT>          Output format: table, json, csv, summary, sarif
    -o, --output <FILE>            Save results to file
    -e, --ecosystems <LIST>        Only scan specific ecosystems (comma-separated)
    -q, --quiet                    Suppress progress output
    --high-only                    Show only high/critical severity vulnerabilities
    --no-recursive                 Don't scan subdirectories
    --no-dev-deps                  Skip development dependencies
```

### Project Configuration

Create `.vulfy.toml` in your project root:

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

**[📖 Full Configuration Reference](docs/api-reference/configuration-schema.md)** - Complete schema documentation

---

## 🚀 Roadmap

### ✅ Recently Added
- 🤖 **Complete Automation System** - Git repository monitoring with scheduling
- 🔔 **Multi-Platform Notifications** - Discord, Slack, and webhook integrations
- 📋 **Advanced Policy Engine** - Custom vulnerability filtering and security policies
- 🆕 **3 New Ecosystems** - C/C++, PHP, and .NET support

### 🔄 Coming Soon
- 🔧 **Fix Mode** - Automatically update vulnerable packages to safe versions
- 📈 **Trend Analysis** - Track vulnerability trends over time
- ⚡ **Watch Mode** - Real-time monitoring for new vulnerabilities
- 💾 **Database Storage** - Historical scan data and analytics

### 🔮 Future Plans
- 🐳 **Container Scanning** - Docker image vulnerability detection
- 🌐 **Web Dashboard** - Centralized security monitoring interface
- 🔌 **Plugin System** - Extensible architecture for custom integrations

**Have feature requests?** [Open an issue](https://github.com/mindPatch/vulfy/issues/new) and let's discuss!

---

## 🏗️ Architecture & Performance

Vulfy is built with performance and reliability as core principles:

- **⚡ Async-First Design** - Built on Tokio for maximum concurrency
- **🔧 Strategy Pattern** - Pluggable parsers for different package managers  
- **🚦 Rate Limiting** - Respectful API usage with configurable limits
- **💾 Memory Efficient** - Streaming parsers for large projects
- **🛡️ Error Resilient** - Graceful handling of network and parsing errors
- **🔍 Semantic Versioning** - Proper version comparison using semver crate

**[📖 Architecture Deep Dive](docs/developer-guide/architecture.md)** - Technical implementation details

---

## 🤝 Contributing

We welcome contributions! Whether it's bug fixes, new features, or ecosystem support.

### Quick Start
```bash
git clone https://github.com/mindPatch/vulfy.git
cd vulfy
cargo build
cargo test
```

### Contribution Guidelines
- Follow Rust best practices and run `cargo clippy`
- Add tests for new features
- Update documentation for user-facing changes
- Keep commit messages clear and descriptive

**[📖 Contributing Guide](docs/developer-guide/contributing.md)** - Detailed contribution instructions

---

## 🆘 Support & Community

### Getting Help
- **🐛 Bug Reports**: [Create an issue](https://github.com/mindPatch/vulfy/issues/new?template=bug_report.md)
- **💡 Feature Requests**: [Start a discussion](https://github.com/mindPatch/vulfy/discussions/new?category=ideas)
- **❓ Questions**: [GitHub Discussions](https://github.com/mindPatch/vulfy/discussions)
- **📖 Documentation**: [Complete docs](docs/README.md)

### Quick Troubleshooting
- **"No package files found"** - Ensure you're in a project directory with supported package files
- **"Network connection failed"** - Check internet connectivity; Vulfy needs access to OSV.dev API
- **"Permission denied"** - Make sure `vulfy` binary is executable: `chmod +x vulfy`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[OSV.dev](https://osv.dev/)** - Comprehensive vulnerability database
- **Rust Community** - Amazing crates and tooling ecosystem
- **Contributors** - Everyone who makes Vulfy better

---

<div align="center">
  <strong>Made with ❤️ and ☕ by mindpatch</strong>
  <br><br>
  <a href="https://github.com/mindPatch/vulfy">⭐ Star us on GitHub</a> |
  <a href="https://github.com/mindPatch/vulfy/issues">🐛 Report Issues</a> |
  <a href="https://github.com/mindPatch/vulfy/discussions">💬 Discussions</a>
</div>
