# Quick Start Tutorial

Get Vulfy up and running in 5 minutes! This tutorial will walk you through installation, your first scan, and basic automation setup.

## Prerequisites

- A project with package files (npm, Python, Rust, Java, Go, Ruby, C++, PHP, or .NET)
- Internet connection (for OSV.dev API access)
- Command line access

## Step 1: Install Vulfy (2 minutes)

### Option A: Download Binary (Recommended)

```bash
# Linux/WSL
curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
tar -xzf vulfy-linux-x86_64.tar.gz
sudo mv vulfy /usr/local/bin/

# macOS
curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-macos-x86_64.tar.gz
tar -xzf vulfy-macos-x86_64.tar.gz
sudo mv vulfy /usr/local/bin/
```

### Option B: Install with Cargo

```bash
cargo install vulfy
```

### Verify Installation

```bash
vulfy --version
# Should output: vulfy 0.1.0
```

## Step 2: Your First Scan (1 minute)

Navigate to any project directory and run:

```bash
vulfy scan packages
```

**Example Output:**
```
🔍 Scanning for package files...
📦 Found 3 package files across 2 ecosystems

🛡️  VULNERABILITY REPORT
┌─────────────────────────────────────────┬──────────────┬──────────┬─────────────────┬──────┐
│ Title                                   │ CVE ID       │ Severity │ Package         │ Year │
├─────────────────────────────────────────┼──────────────┼──────────┼─────────────────┼──────┤
│ Prototype Pollution in lodash          │ CVE-2021-123 │ 🔥 High  │ lodash@4.17.0   │ 2021 │
│ SQL Injection in sequelize             │ CVE-2020-789 │ 🟡 Medium│ sequelize@5.0.0 │ 2020 │
└─────────────────────────────────────────┴──────────────┴──────────┴─────────────────┴──────┘

📊 SCAN SUMMARY
• Total packages scanned: 42
• Vulnerable packages: 2
• Total vulnerabilities: 2
• 🔥 High severity: 1
• 🟡 Medium severity: 1
```

**Congratulations!** 🎉 You've just completed your first vulnerability scan!

## Step 3: Try Different Formats (30 seconds)

### JSON Output
```bash
vulfy scan packages --format json --output security-report.json
```

### CSV for Spreadsheets
```bash
vulfy scan packages --format csv --output vulnerabilities.csv
```

### SARIF for GitHub Security Tab
```bash
vulfy scan packages --format sarif --output vulfy.sarif
```

## Step 4: Filter Results (30 seconds)

### Show Only High-Severity Issues
```bash
vulfy scan packages --high-only
```

### Scan Specific Ecosystems
```bash
# Only scan npm and Python packages
vulfy scan packages --ecosystems npm,pypi
```

### Skip Development Dependencies
```bash
vulfy scan packages --no-dev-deps
```

## Step 5: Set Up Basic Automation (1 minute)

### Initialize Automation Config
```bash
vulfy automation init --with-examples
```

This creates `vulfy-automation.toml` with example configuration.

### Quick Edit for Your Repository
Edit the generated file to monitor your own repository:

```toml
[[repositories]]
name = "my-project"
url = "https://github.com/username/my-project.git"
branches = ["main"]
ecosystems = ["npm", "pypi"]  # Adjust for your project

[schedule]
frequency = "daily"
time = "02:00"
timezone = "UTC"

[notifications]
enabled = false  # Enable after setting up webhook
```

### Test the Configuration
```bash
# Validate config
vulfy automation validate

# Run manual scan
vulfy automation run
```

## What You've Accomplished

In just 5 minutes, you've:

✅ **Installed Vulfy** and verified it works  
✅ **Scanned your first project** for vulnerabilities  
✅ **Tried different output formats** (JSON, CSV, SARIF)  
✅ **Learned filtering options** for focused scanning  
✅ **Set up basic automation** configuration  

## Next Steps

### Immediate Actions

1. **Review vulnerabilities found** - Check if any need immediate attention
2. **Set up CI/CD integration** - Add Vulfy to your build pipeline
3. **Configure notifications** - Set up Discord/Slack alerts

### Deeper Integration

1. **[Set Up Automation](automation-setup.md)** - Complete automation guide
2. **[CI/CD Integration](ci-cd-integration.md)** - Add to your pipelines
3. **[Custom Policies](custom-policies.md)** - Create advanced filtering rules

## Common Project Types

### Node.js Project
```bash
# Scan npm dependencies
vulfy scan packages --ecosystems npm --no-dev-deps

# Focus on production dependencies
vulfy scan packages --ecosystems npm --no-dev-deps --high-only
```

### Python Project
```bash
# Scan Python packages
vulfy scan packages --ecosystems pypi

# Include conda environments
vulfy scan packages --ecosystems pypi --path ./environment.yml
```

### Multi-Language Project
```bash
# Scan all supported ecosystems
vulfy scan packages

# Target specific combinations
vulfy scan packages --ecosystems npm,pypi,go
```

### Rust Project
```bash
# Scan Cargo dependencies
vulfy scan packages --ecosystems crates.io

# Quick check for high-severity issues
vulfy scan packages --ecosystems crates.io --high-only --quiet
```

## Troubleshooting

### "No package files found"
- Make sure you're in a project directory
- Check supported file names in the [Getting Started Guide](../user-guide/getting-started.md#supported-ecosystems)
- Use `--path` to specify a different directory

### "Network connection failed"
- Ensure internet connectivity
- Check if your firewall blocks HTTPS requests
- OSV.dev API might be temporarily unavailable

### "Permission denied"
- Make sure `vulfy` binary is executable: `chmod +x vulfy`
- On macOS, allow the binary in Security & Privacy settings

## Quick Reference

### Essential Commands
```bash
# Basic scan
vulfy scan packages

# Scan with output file
vulfy scan packages --format json --output report.json

# High-severity only
vulfy scan packages --high-only --quiet

# Initialize automation
vulfy automation init --with-examples

# Manual automation scan
vulfy automation run
```

### Key Options
- `--path` - Specify directory to scan
- `--format` - Output format (table, json, csv, sarif)
- `--output` - Save to file
- `--ecosystems` - Filter package managers
- `--high-only` - Show only high-severity vulnerabilities
- `--quiet` - Suppress progress output

## Success! 🚀

You're now ready to use Vulfy for vulnerability scanning! The tool will help you:

- **Identify security issues** in your dependencies
- **Monitor projects continuously** with automation
- **Integrate security scanning** into your development workflow
- **Stay informed** about new vulnerabilities

For more advanced features, check out the complete [User Guide](../user-guide/getting-started.md) and [Automation Documentation](../user-guide/automation-overview.md).

---

**Next**: [CI/CD Integration](ci-cd-integration.md) - Add Vulfy to your build pipelines 